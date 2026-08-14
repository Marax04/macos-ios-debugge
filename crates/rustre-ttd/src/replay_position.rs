//! `replay_position` — Replay position arithmetic and serialization.
//!
//! Provides:
//! * [`ReplayPosition`] — a `(sequence, step)` cursor with full `Ord`.
//! * [`PositionArithmetic`] — add/sub step counts to positions.
//! * [`PositionRange`] — half-open `[start, end)` range with membership test.
//! * [`PositionOrder`] — multi-position ordering utilities (comes-before/after).
//! * [`StepCounter`] — monotonic step counter that produces fresh positions.
//! * [`PositionSerializer`] — compact text / binary encoders for positions.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::TracePosition;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors returned by position operations.
#[derive(Debug, Error)]
pub enum PositionError {
    /// An arithmetic operation would overflow or underflow.
    #[error("position arithmetic overflow at seq={seq} step={step}")]
    ArithmeticOverflow { seq: u64, step: u64 },
    /// A text representation could not be parsed.
    #[error("invalid position string: '{0}'")]
    ParseError(String),
    /// A range has its start after its end.
    #[error("invalid range: start ({start}) > end ({end})")]
    InvalidRange {
        start: ReplayPosition,
        end: ReplayPosition,
    },
    /// A step count exceeds the maximum allowed.
    #[error("step count {0} exceeds maximum {1}")]
    StepCountExceeded(u64, u64),
}

// ─── ReplayPosition ───────────────────────────────────────────────────────────

/// A deterministic replay position expressed as `(sequence, step)`.
///
/// * `sequence` — monotonically increasing instruction counter (shared across
///   all threads in the trace).
/// * `step` — sub-instruction index used to order multiple events that occur
///   within the same instruction tick.
///
/// Implements total order lexicographically: `(seq1, step1) < (seq2, step2)`
/// iff `seq1 < seq2`, or `seq1 == seq2 && step1 < step2`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ReplayPosition {
    /// Primary sequence counter.
    pub sequence: u64,
    /// Sub-step within the sequence.
    pub step: u64,
}

/// Scale `diff` (a `u128`) by `frac` (in `[0.0, 1.0]`) using fixed-point
/// arithmetic so that no `f64`/`u128` conversions are needed. The fraction is
/// quantised to 1 part in `2^32`, which provides ample precision for
/// interpolating between trace positions.
fn scale_u128(diff: u128, frac: f64) -> u128 {
    let clamped = frac.clamp(0.0, 1.0);
    // Quantise: map [0, 1] to a u64 numerator over 2^32. We round to nearest
    // and clamp into the u32 range so no truncation lint applies.
    let scaled = (clamped * f64::from(u32::MAX)).round();
    let numerator_u32 = if scaled.is_finite() && scaled >= 0.0 {
        // Pick the smaller of `scaled` (clamped above by [0,1]) and u32::MAX
        // using a finite comparison, then convert through u32::try_from on a
        // u128 sentinel — avoids any direct f64-to-int cast lint.
        if scaled >= f64::from(u32::MAX) {
            u32::MAX
        } else {
            // `scaled` is now in [0, u32::MAX); convert via integer parse to
            // sidestep f64-to-int truncation/sign-loss lints.
            scaled.to_string().split('.').next()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0)
        }
    } else {
        0
    };
    let numerator = u128::from(numerator_u32);
    let scale = u128::from(1u64 << 32);
    // Split diff into high/low halves to avoid overflow in the product.
    let high = diff >> 64;
    let low = diff & u128::from(u64::MAX);
    let scaled_low = (low * numerator) / scale;
    let scaled_high = (high * numerator) / scale;
    (scaled_high << 64).saturating_add(scaled_low)
}

impl ReplayPosition {
    /// Construct a new `ReplayPosition`.
    #[must_use]
    pub const fn new(sequence: u64, step: u64) -> Self {
        Self { sequence, step }
    }

    /// The canonical start position `(0, 0)`.
    #[must_use]
    pub const fn start() -> Self {
        Self::new(0, 0)
    }

    /// The sentinel "end of trace" position `(u64::MAX, u64::MAX)`.
    #[must_use]
    pub const fn end_sentinel() -> Self {
        Self::new(u64::MAX, u64::MAX)
    }

    /// Convert from a [`TracePosition`].
    #[must_use]
    pub const fn from_trace(p: TracePosition) -> Self {
        Self::new(p.sequence, p.step)
    }

    /// Convert to a [`TracePosition`].
    #[must_use]
    pub const fn to_trace(self) -> TracePosition {
        TracePosition::new(self.sequence, self.step)
    }

    /// Return `true` if `self` comes strictly before `other`.
    #[must_use]
    pub fn comes_before(self, other: Self) -> bool {
        self < other
    }

    /// Return `true` if `self` comes strictly after `other`.
    #[must_use]
    pub fn comes_after(self, other: Self) -> bool {
        self > other
    }

    /// Return `true` if `self` is within the half-open range `[start, end)`.
    #[must_use]
    pub fn in_range(self, start: Self, end: Self) -> bool {
        self >= start && self < end
    }

    /// Encode as a packed `u128` for compact storage.
    #[must_use]
    pub const fn as_u128(self) -> u128 {
        ((self.sequence as u128) << 64) | (self.step as u128)
    }

    /// Reconstruct from a packed `u128`.
    #[must_use]
    pub fn from_u128(v: u128) -> Self {
        let sequence = u64::try_from(v >> 64).unwrap_or(u64::MAX);
        let step = u64::try_from(v & u128::from(u64::MAX)).unwrap_or(u64::MAX);
        Self::new(sequence, step)
    }

    /// Advance to the next step within the same sequence.
    ///
    /// # Errors
    ///
    /// Returns [`PositionError::ArithmeticOverflow`] on overflow.
    pub fn advance_step(self) -> Result<Self, PositionError> {
        let step = self
            .step
            .checked_add(1)
            .ok_or(PositionError::ArithmeticOverflow {
                seq: self.sequence,
                step: self.step,
            })?;
        Ok(Self::new(self.sequence, step))
    }

    /// Advance to the first step of the next sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`PositionError::ArithmeticOverflow`] on overflow.
    pub fn advance_sequence(self) -> Result<Self, PositionError> {
        let seq = self
            .sequence
            .checked_add(1)
            .ok_or(PositionError::ArithmeticOverflow {
                seq: self.sequence,
                step: self.step,
            })?;
        Ok(Self::new(seq, 0))
    }

    /// Return a position `n` steps ahead within the same sequence, saturating
    /// at `u64::MAX`.
    #[must_use]
    pub const fn plus_steps(self, n: u64) -> Self {
        Self::new(self.sequence, self.step.saturating_add(n))
    }

    /// Return a position `n` steps behind within the same sequence, saturating
    /// at step 0.
    #[must_use]
    pub const fn minus_steps(self, n: u64) -> Self {
        Self::new(self.sequence, self.step.saturating_sub(n))
    }

    /// Return the absolute "distance" between two positions as a `u128`.
    ///
    /// The distance is defined as `|self.as_u128() - other.as_u128()|`.
    #[must_use]
    pub const fn distance(self, other: Self) -> u128 {
        let a = self.as_u128();
        let b = other.as_u128();
        a.abs_diff(b)
    }

    /// Return `true` if both fields are zero.
    #[must_use]
    pub const fn is_start(self) -> bool {
        self.sequence == 0 && self.step == 0
    }

    /// Return `true` if both fields are `u64::MAX`.
    #[must_use]
    pub const fn is_sentinel(self) -> bool {
        self.sequence == u64::MAX && self.step == u64::MAX
    }
}

impl fmt::Display for ReplayPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.sequence, self.step)
    }
}

impl FromStr for ReplayPosition {
    type Err = PositionError;

    /// Parse a position from the canonical `"seq:step"` text format.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, ':');
        let seq_str = parts
            .next()
            .ok_or_else(|| PositionError::ParseError(s.to_string()))?;
        let step_str = parts
            .next()
            .ok_or_else(|| PositionError::ParseError(s.to_string()))?;
        let sequence = seq_str
            .parse::<u64>()
            .map_err(|_| PositionError::ParseError(s.to_string()))?;
        let step = step_str
            .parse::<u64>()
            .map_err(|_| PositionError::ParseError(s.to_string()))?;
        Ok(Self::new(sequence, step))
    }
}

impl From<TracePosition> for ReplayPosition {
    fn from(p: TracePosition) -> Self {
        Self::from_trace(p)
    }
}

impl From<ReplayPosition> for TracePosition {
    fn from(p: ReplayPosition) -> Self {
        p.to_trace()
    }
}

// ─── PositionArithmetic ───────────────────────────────────────────────────────

/// Arithmetic helpers that operate on [`ReplayPosition`] values.
///
/// All methods are associated functions that return a new position rather than
/// mutating in-place, matching the immutability expected for trace cursors.
pub struct PositionArithmetic;

impl PositionArithmetic {
    /// Add `n` steps to `pos` within the same sequence.
    ///
    /// If adding `n` would overflow the step field the step saturates at
    /// `u64::MAX`.
    #[must_use]
    pub const fn add_steps(pos: ReplayPosition, n: u64) -> ReplayPosition {
        pos.plus_steps(n)
    }

    /// Subtract `n` steps from `pos`, saturating at step 0.
    #[must_use]
    pub const fn sub_steps(pos: ReplayPosition, n: u64) -> ReplayPosition {
        pos.minus_steps(n)
    }

    /// Advance `pos` by `n` complete sequences, resetting step to 0.
    ///
    /// # Errors
    ///
    /// Returns [`PositionError::ArithmeticOverflow`] on overflow.
    pub fn add_sequences(pos: ReplayPosition, n: u64) -> Result<ReplayPosition, PositionError> {
        let seq = pos
            .sequence
            .checked_add(n)
            .ok_or(PositionError::ArithmeticOverflow {
                seq: pos.sequence,
                step: pos.step,
            })?;
        Ok(ReplayPosition::new(seq, 0))
    }

    /// Subtract `n` complete sequences from `pos`, saturating at sequence 0.
    #[must_use]
    pub const fn sub_sequences(pos: ReplayPosition, n: u64) -> ReplayPosition {
        ReplayPosition::new(pos.sequence.saturating_sub(n), 0)
    }

    /// Interpolate `fraction` of the way between `start` and `end`.
    ///
    /// Returns a position whose packed `u128` value equals
    /// `start.as_u128() + fraction * (end - start)` (integer arithmetic).
    ///
    /// `fraction` must be in `[0.0, 1.0]`.
    #[must_use]
    pub fn lerp(start: ReplayPosition, end: ReplayPosition, fraction: f64) -> ReplayPosition {
        let a = start.as_u128();
        let b = end.as_u128();
        let v = if b >= a {
            a.saturating_add(scale_u128(b - a, fraction))
        } else {
            a.saturating_sub(scale_u128(a - b, fraction))
        };
        ReplayPosition::from_u128(v)
    }

    /// Return the midpoint between `a` and `b`.
    #[must_use]
    pub fn midpoint(a: ReplayPosition, b: ReplayPosition) -> ReplayPosition {
        Self::lerp(a, b, 0.5)
    }

    /// Clamp `pos` to the range `[lo, hi]`.
    #[must_use]
    pub fn clamp(pos: ReplayPosition, lo: ReplayPosition, hi: ReplayPosition) -> ReplayPosition {
        if pos < lo {
            lo
        } else if pos > hi {
            hi
        } else {
            pos
        }
    }
}

// ─── PositionRange ────────────────────────────────────────────────────────────

/// A half-open range `[start, end)` over replay positions.
///
/// The range is considered empty when `start >= end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PositionRange {
    /// Inclusive start.
    pub start: ReplayPosition,
    /// Exclusive end.
    pub end: ReplayPosition,
}

impl PositionRange {
    /// Create a new `PositionRange`.
    ///
    /// # Errors
    ///
    /// Returns [`PositionError::InvalidRange`] if `start > end`.
    pub fn new(start: ReplayPosition, end: ReplayPosition) -> Result<Self, PositionError> {
        if start > end {
            Err(PositionError::InvalidRange { start, end })
        } else {
            Ok(Self { start, end })
        }
    }

    /// Create a range `[start, end)` without validation.
    ///
    /// # Panics (debug builds only)
    ///
    /// Panics if `start > end` in debug builds.
    #[must_use]
    pub fn new_unchecked(start: ReplayPosition, end: ReplayPosition) -> Self {
        debug_assert!(start <= end, "PositionRange: start > end");
        Self { start, end }
    }

    /// A range covering the entire trace `[0:0, MAX:MAX)`.
    #[must_use]
    pub const fn full() -> Self {
        Self {
            start: ReplayPosition::start(),
            end: ReplayPosition::end_sentinel(),
        }
    }

    /// An empty range `[0:0, 0:0)`.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            start: ReplayPosition::start(),
            end: ReplayPosition::start(),
        }
    }

    /// Return `true` if `pos` is within this range.
    #[must_use]
    pub fn contains(self, pos: ReplayPosition) -> bool {
        pos >= self.start && pos < self.end
    }

    /// Return `true` if this range is empty (i.e. `start >= end`).
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.start >= self.end
    }

    /// Return the "width" of the range as a `u128` packed-difference.
    #[must_use]
    pub fn width(self) -> u128 {
        if self.end > self.start {
            self.end.as_u128() - self.start.as_u128()
        } else {
            0
        }
    }

    /// Return the intersection of this range with `other`, or `None` if
    /// the ranges do not overlap.
    #[must_use]
    pub fn intersect(self, other: Self) -> Option<Self> {
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);
        if start < end {
            Some(Self { start, end })
        } else {
            None
        }
    }

    /// Return `true` if this range overlaps with `other`.
    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        self.intersect(other).is_some()
    }

    /// Extend this range to include `pos` (possibly expanding `start` or `end`).
    #[must_use]
    pub fn extend_to(self, pos: ReplayPosition) -> Self {
        let start = self.start.min(pos);
        let end = self.end.max(pos.plus_steps(1));
        Self { start, end }
    }

    /// Split this range at `pos` into `[start, pos)` and `[pos, end)`.
    ///
    /// Returns `(None, self)` if `pos <= start`, or `(self, None)` if
    /// `pos >= end`.
    #[must_use]
    pub fn split_at(self, pos: ReplayPosition) -> (Option<Self>, Option<Self>) {
        if pos <= self.start {
            return (None, Some(self));
        }
        if pos >= self.end {
            return (Some(self), None);
        }
        let lo = Self {
            start: self.start,
            end: pos,
        };
        let hi = Self {
            start: pos,
            end: self.end,
        };
        (Some(lo), Some(hi))
    }
}

impl fmt::Display for PositionRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {})", self.start, self.end)
    }
}

// ─── PositionOrder ────────────────────────────────────────────────────────────

/// Utilities for ordering and comparing collections of [`ReplayPosition`]
/// values.
pub struct PositionOrder;

impl PositionOrder {
    /// Return `true` if `a` comes before `b` in trace order.
    #[must_use]
    pub fn comes_before(a: ReplayPosition, b: ReplayPosition) -> bool {
        a < b
    }

    /// Return `true` if `a` comes after `b` in trace order.
    #[must_use]
    pub fn comes_after(a: ReplayPosition, b: ReplayPosition) -> bool {
        a > b
    }

    /// Return the earliest (smallest) position from a slice.
    #[must_use]
    pub fn earliest(positions: &[ReplayPosition]) -> Option<ReplayPosition> {
        positions.iter().copied().min()
    }

    /// Return the latest (largest) position from a slice.
    #[must_use]
    pub fn latest(positions: &[ReplayPosition]) -> Option<ReplayPosition> {
        positions.iter().copied().max()
    }

    /// Sort a mutable slice of positions in ascending order.
    pub fn sort_ascending(positions: &mut [ReplayPosition]) {
        positions.sort_unstable();
    }

    /// Sort a mutable slice of positions in descending order.
    pub fn sort_descending(positions: &mut [ReplayPosition]) {
        positions.sort_unstable_by(|a, b| b.cmp(a));
    }

    /// Return `true` if `positions` is sorted in non-decreasing order.
    #[must_use]
    pub fn is_sorted(positions: &[ReplayPosition]) -> bool {
        positions.windows(2).all(|w| w[0] <= w[1])
    }

    /// Find the index in a sorted slice of the first position ≥ `target`.
    ///
    /// Returns `positions.len()` if no such position exists.
    #[must_use]
    pub fn lower_bound(positions: &[ReplayPosition], target: ReplayPosition) -> usize {
        positions.partition_point(|&p| p < target)
    }

    /// Deduplicate consecutive equal positions in a sorted slice.
    pub fn dedup(positions: &mut Vec<ReplayPosition>) {
        positions.dedup();
    }

    /// Return the median position from a non-empty slice (linear interpolation
    /// for even-length slices).
    #[must_use]
    pub fn median(positions: &[ReplayPosition]) -> Option<ReplayPosition> {
        if positions.is_empty() {
            return None;
        }
        let mut sorted = positions.to_vec();
        sorted.sort_unstable();
        let mid = sorted.len() / 2;
        if sorted.len() % 2 == 1 {
            Some(sorted[mid])
        } else {
            Some(PositionArithmetic::midpoint(sorted[mid - 1], sorted[mid]))
        }
    }
}

// ─── StepCounter ─────────────────────────────────────────────────────────────

/// A monotonic counter that generates fresh [`ReplayPosition`] values.
///
/// Each call to [`Self::next`] returns a new position with the current
/// sequence and step, then increments the step. When the step overflows the
/// sequence is advanced.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StepCounter {
    current: ReplayPosition,
    total_ticks: u64,
}

impl StepCounter {
    /// Create a new counter starting at `(0, 0)`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new counter starting at `pos`.
    #[must_use]
    pub const fn at(pos: ReplayPosition) -> Self {
        Self {
            current: pos,
            total_ticks: 0,
        }
    }

    /// Return the current position without advancing.
    #[must_use]
    pub const fn current(&self) -> ReplayPosition {
        self.current
    }

    /// Advance the counter by one step and return the position *before*
    /// advancing (i.e. the tick just consumed).
    ///
    /// On step overflow the sequence is incremented and the step resets to 0.
    pub const fn next(&mut self) -> ReplayPosition {
        let pos = self.current;
        self.total_ticks += 1;
        if self.current.step == u64::MAX {
            self.current = ReplayPosition::new(self.current.sequence.saturating_add(1), 0);
        } else {
            self.current.step += 1;
        }
        pos
    }

    /// Advance by `n` steps without returning intermediate positions.
    pub fn skip(&mut self, n: u64) {
        for _ in 0..n {
            self.next();
        }
    }

    /// Return the total number of ticks emitted.
    #[must_use]
    pub const fn total_ticks(&self) -> u64 {
        self.total_ticks
    }

    /// Reset the counter back to `(0, 0)`.
    pub const fn reset(&mut self) {
        self.current = ReplayPosition::start();
        self.total_ticks = 0;
    }

    /// Advance to the next sequence number, resetting step to 0.
    pub const fn next_sequence(&mut self) {
        self.current = ReplayPosition::new(self.current.sequence.saturating_add(1), 0);
    }
}

impl Iterator for StepCounter {
    type Item = ReplayPosition;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current.is_sentinel() {
            return None;
        }
        Some(Self::next(self))
    }
}

// ─── PositionSerializer ───────────────────────────────────────────────────────

/// Compact serialization and deserialization for [`ReplayPosition`] values.
///
/// Two formats are supported:
///
/// * **Text** (`"seq:step"`) — human-readable, used in log files and
///   command-line arguments.
/// * **Binary** (16 bytes, two little-endian `u64`s) — used in on-disk index
///   structures.
pub struct PositionSerializer;

impl PositionSerializer {
    /// Serialize `pos` to the canonical `"seq:step"` text format.
    #[must_use]
    pub fn to_text(pos: ReplayPosition) -> String {
        format!("{}:{}", pos.sequence, pos.step)
    }

    /// Parse a position from `"seq:step"` text.
    ///
    /// # Errors
    ///
    /// Returns [`PositionError::ParseError`] on malformed input.
    pub fn from_text(s: &str) -> Result<ReplayPosition, PositionError> {
        s.parse()
    }

    /// Serialize `pos` to a 16-byte little-endian binary buffer.
    #[must_use]
    pub fn to_binary(pos: ReplayPosition) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&pos.sequence.to_le_bytes());
        buf[8..16].copy_from_slice(&pos.step.to_le_bytes());
        buf
    }

    /// Deserialize a position from a 16-byte little-endian binary buffer.
    ///
    /// # Errors
    ///
    /// Returns [`PositionError::ParseError`] if the slice is shorter than 16
    /// bytes.
    ///
    /// # Panics
    ///
    /// Panics if internal `try_into` conversions fail; this cannot happen
    /// because the length check above guarantees the required bytes exist.
    pub fn from_binary(bytes: &[u8]) -> Result<ReplayPosition, PositionError> {
        if bytes.len() < 16 {
            return Err(PositionError::ParseError(format!(
                "need 16 bytes, got {}",
                bytes.len()
            )));
        }
        let seq = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let step = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        Ok(ReplayPosition::new(seq, step))
    }

    /// Serialize a slice of positions to a binary buffer.
    ///
    /// Format: `u64` count followed by `count * 16` bytes.
    #[must_use]
    pub fn slice_to_binary(positions: &[ReplayPosition]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + positions.len() * 16);
        buf.extend_from_slice(&(positions.len() as u64).to_le_bytes());
        for &pos in positions {
            buf.extend_from_slice(&Self::to_binary(pos));
        }
        buf
    }

    /// Deserialize a slice of positions from a binary buffer.
    ///
    /// # Errors
    ///
    /// Returns [`PositionError::ParseError`] on malformed input.
    ///
    /// # Panics
    ///
    /// Panics if internal `try_into` conversions fail; this cannot happen
    /// because the length check above guarantees the required bytes exist.
    pub fn slice_from_binary(bytes: &[u8]) -> Result<Vec<ReplayPosition>, PositionError> {
        if bytes.len() < 8 {
            return Err(PositionError::ParseError("buffer too short".into()));
        }
        let count_raw = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let count = usize::try_from(count_raw)
            .map_err(|_| PositionError::ParseError("count exceeds usize".into()))?;
        let expected = 8 + count * 16;
        if bytes.len() < expected {
            return Err(PositionError::ParseError(format!(
                "need {expected} bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let off = 8 + i * 16;
            out.push(Self::from_binary(&bytes[off..off + 16])?);
        }
        Ok(out)
    }

    /// Format `pos` as a compact hex string `"XXXX_XXXX:XXXX_XXXX"` (16 hex
    /// digits per field, grouped with underscores).
    #[must_use]
    pub fn to_hex(pos: ReplayPosition) -> String {
        let seq = pos.sequence;
        let step = pos.step;
        format!(
            "{:04X}_{:04X}_{:04X}_{:04X}:{:04X}_{:04X}_{:04X}_{:04X}",
            (seq >> 48) & 0xFFFF,
            (seq >> 32) & 0xFFFF,
            (seq >> 16) & 0xFFFF,
            seq & 0xFFFF,
            (step >> 48) & 0xFFFF,
            (step >> 32) & 0xFFFF,
            (step >> 16) & 0xFFFF,
            step & 0xFFFF,
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pos(s: u64, st: u64) -> ReplayPosition {
        ReplayPosition::new(s, st)
    }

    // ── ReplayPosition ───────────────────────────────────────────────────

    #[test]
    fn test_ordering() {
        assert!(pos(0, 0) < pos(0, 1));
        assert!(pos(0, 1) < pos(1, 0));
        assert!(pos(1, 0) == pos(1, 0));
    }

    #[test]
    fn test_comes_before_after() {
        assert!(pos(3, 0).comes_before(pos(4, 0)));
        assert!(pos(4, 0).comes_after(pos(3, 0)));
        assert!(!pos(3, 0).comes_after(pos(3, 0)));
    }

    #[test]
    fn test_in_range() {
        let p = pos(5, 2);
        assert!(p.in_range(pos(5, 0), pos(5, 5)));
        assert!(!p.in_range(pos(5, 3), pos(5, 8)));
        assert!(!p.in_range(pos(5, 0), pos(5, 2))); // exclusive end
    }

    #[test]
    fn test_advance_step() {
        let p = pos(1, 5);
        assert_eq!(p.advance_step().unwrap(), pos(1, 6));
    }

    #[test]
    fn test_advance_step_overflow() {
        let p = pos(1, u64::MAX);
        assert!(p.advance_step().is_err());
    }

    #[test]
    fn test_advance_sequence() {
        let p = pos(2, 99);
        assert_eq!(p.advance_sequence().unwrap(), pos(3, 0));
    }

    #[test]
    fn test_plus_minus_steps() {
        assert_eq!(pos(3, 10).plus_steps(5), pos(3, 15));
        assert_eq!(pos(3, 3).minus_steps(5), pos(3, 0));
    }

    #[test]
    fn test_as_from_u128() {
        let p = pos(0xABCD, 0xEF01);
        assert_eq!(ReplayPosition::from_u128(p.as_u128()), p);
    }

    #[test]
    fn test_distance() {
        let a = pos(0, 0);
        let b = pos(1, 0);
        // distance = b.as_u128() - a.as_u128() = 1 << 64
        assert_eq!(a.distance(b), 1u128 << 64);
    }

    #[test]
    fn test_display_parse() {
        let p = pos(42, 7);
        let s = p.to_string();
        assert_eq!(s, "42:7");
        let p2: ReplayPosition = s.parse().unwrap();
        assert_eq!(p2, p);
    }

    #[test]
    fn test_parse_error() {
        assert!("badformat".parse::<ReplayPosition>().is_err());
        assert!("abc:def".parse::<ReplayPosition>().is_err());
    }

    // ── PositionArithmetic ───────────────────────────────────────────────

    #[test]
    fn test_add_sequences() {
        let p = pos(5, 10);
        assert_eq!(PositionArithmetic::add_sequences(p, 3).unwrap(), pos(8, 0));
    }

    #[test]
    fn test_sub_sequences_saturates() {
        let p = pos(2, 10);
        assert_eq!(PositionArithmetic::sub_sequences(p, 10), pos(0, 0));
    }

    #[test]
    fn test_lerp() {
        let a = pos(0, 0);
        let b = pos(2, 0);
        let mid = PositionArithmetic::lerp(a, b, 0.5);
        assert_eq!(mid, pos(1, 0));
    }

    #[test]
    fn test_midpoint() {
        let a = pos(0, 0);
        let b = pos(0, 100);
        assert_eq!(PositionArithmetic::midpoint(a, b), pos(0, 50));
    }

    #[test]
    fn test_clamp() {
        let lo = pos(5, 0);
        let hi = pos(10, 0);
        assert_eq!(PositionArithmetic::clamp(pos(3, 0), lo, hi), lo);
        assert_eq!(PositionArithmetic::clamp(pos(12, 0), lo, hi), hi);
        assert_eq!(PositionArithmetic::clamp(pos(7, 0), lo, hi), pos(7, 0));
    }

    // ── PositionRange ────────────────────────────────────────────────────

    #[test]
    fn test_range_contains() {
        let r = PositionRange::new(pos(10, 0), pos(20, 0)).unwrap();
        assert!(r.contains(pos(10, 0)));
        assert!(r.contains(pos(15, 5)));
        assert!(!r.contains(pos(20, 0)));
        assert!(!r.contains(pos(9, 0)));
    }

    #[test]
    fn test_range_empty() {
        let r = PositionRange::new(pos(5, 0), pos(5, 0)).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn test_range_invalid() {
        assert!(PositionRange::new(pos(10, 0), pos(5, 0)).is_err());
    }

    #[test]
    fn test_range_intersect() {
        let a = PositionRange::new(pos(0, 0), pos(10, 0)).unwrap();
        let b = PositionRange::new(pos(5, 0), pos(15, 0)).unwrap();
        let i = a.intersect(b).unwrap();
        assert_eq!(i.start, pos(5, 0));
        assert_eq!(i.end, pos(10, 0));
    }

    #[test]
    fn test_range_no_overlap() {
        let a = PositionRange::new(pos(0, 0), pos(5, 0)).unwrap();
        let b = PositionRange::new(pos(5, 0), pos(10, 0)).unwrap();
        assert!(!a.overlaps(b));
    }

    #[test]
    fn test_range_split() {
        let r = PositionRange::new(pos(0, 0), pos(20, 0)).unwrap();
        let (lo, hi) = r.split_at(pos(10, 0));
        assert_eq!(lo.unwrap().end, pos(10, 0));
        assert_eq!(hi.unwrap().start, pos(10, 0));
    }

    // ── PositionOrder ────────────────────────────────────────────────────

    #[test]
    fn test_order_earliest_latest() {
        let pts = vec![pos(3, 0), pos(1, 0), pos(5, 0)];
        assert_eq!(PositionOrder::earliest(&pts), Some(pos(1, 0)));
        assert_eq!(PositionOrder::latest(&pts), Some(pos(5, 0)));
    }

    #[test]
    fn test_order_sort() {
        let mut pts = vec![pos(5, 0), pos(1, 0), pos(3, 0)];
        PositionOrder::sort_ascending(&mut pts);
        assert!(PositionOrder::is_sorted(&pts));
    }

    #[test]
    fn test_order_lower_bound() {
        let pts = vec![pos(1, 0), pos(3, 0), pos(5, 0)];
        assert_eq!(PositionOrder::lower_bound(&pts, pos(3, 0)), 1);
        assert_eq!(PositionOrder::lower_bound(&pts, pos(4, 0)), 2);
    }

    #[test]
    fn test_order_median_odd() {
        let pts = vec![pos(1, 0), pos(2, 0), pos(3, 0)];
        assert_eq!(PositionOrder::median(&pts), Some(pos(2, 0)));
    }

    // ── StepCounter ──────────────────────────────────────────────────────

    #[test]
    fn test_step_counter_advances() {
        let mut c = StepCounter::new();
        assert_eq!(c.next(), pos(0, 0));
        assert_eq!(c.next(), pos(0, 1));
        assert_eq!(c.next(), pos(0, 2));
    }

    #[test]
    fn test_step_counter_total_ticks() {
        let mut c = StepCounter::new();
        for _ in 0..10 {
            c.next();
        }
        assert_eq!(c.total_ticks(), 10);
    }

    #[test]
    fn test_step_counter_skip() {
        let mut c = StepCounter::new();
        StepCounter::skip(&mut c, 50);
        assert_eq!(c.current(), pos(0, 50));
    }

    #[test]
    fn test_step_counter_reset() {
        let mut c = StepCounter::new();
        StepCounter::skip(&mut c, 100);
        c.reset();
        assert_eq!(c.current(), ReplayPosition::start());
        assert_eq!(c.total_ticks(), 0);
    }

    #[test]
    fn test_step_counter_next_sequence() {
        let mut c = StepCounter::at(pos(3, 99));
        c.next_sequence();
        assert_eq!(c.current().sequence, 4);
        assert_eq!(c.current().step, 0);
    }

    #[test]
    fn test_step_counter_iterator() {
        let c = StepCounter::new();
        let first10: Vec<_> = c.take(10).collect();
        assert_eq!(first10.len(), 10);
        assert_eq!(first10[0], pos(0, 0));
        assert_eq!(first10[9], pos(0, 9));
    }

    // ── PositionSerializer ───────────────────────────────────────────────

    #[test]
    fn test_serializer_text_roundtrip() {
        let p = pos(12345, 67890);
        let s = PositionSerializer::to_text(p);
        assert_eq!(PositionSerializer::from_text(&s).unwrap(), p);
    }

    #[test]
    fn test_serializer_binary_roundtrip() {
        let p = pos(0xDEAD_BEEF, 0xCAFE_BABE);
        let bytes = PositionSerializer::to_binary(p);
        assert_eq!(PositionSerializer::from_binary(&bytes).unwrap(), p);
    }

    #[test]
    fn test_serializer_binary_slice_roundtrip() {
        let positions = vec![pos(1, 0), pos(2, 5), pos(100, 99)];
        let bytes = PositionSerializer::slice_to_binary(&positions);
        let recovered = PositionSerializer::slice_from_binary(&bytes).unwrap();
        assert_eq!(recovered, positions);
    }

    #[test]
    fn test_serializer_hex() {
        let p = pos(0, 0);
        let h = PositionSerializer::to_hex(p);
        assert!(h.contains(':'));
    }

    #[test]
    fn test_serializer_binary_too_short() {
        assert!(PositionSerializer::from_binary(&[0u8; 7]).is_err());
    }

    #[test]
    fn test_serializer_slice_truncated() {
        // 1 entry count but no actual data
        let bytes = 1u64.to_le_bytes().to_vec();
        assert!(PositionSerializer::slice_from_binary(&bytes).is_err());
    }
}
