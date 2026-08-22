//! Strided Interval Arithmetic
//!
//! A *strided interval* `SI[stride; lo, hi]` represents every value
//! `v = lo + k * stride` for non-negative integer `k` such that `v <= hi`.
//!
//! This module provides:
//! * Signed and unsigned interpretations of the same bit-vector.
//! * All arithmetic and bitwise operations with sound over-approximation.
//! * Widening and narrowing operators for fixpoint convergence.
//! * `join` (least upper bound) and `meet` (greatest lower bound).
//! * Bit-vector `extract` and `concat` (for sub-word and word-building ops).
//! * A complement operator (useful for negation / bitwise NOT).
//!
//! ## Representation invariants
//! * `stride >= 1` always.
//! * `lo <= hi` (modulo the bit-width, for wrap-around intervals).
//! * If `stride == 0` the interval is a singleton: `lo == hi`.
//! * `Top` == `SI[1; 0, u64::MAX]` for 64-bit.
//! * `Bottom` represents the empty set (no values).
//!
//! References:
//! * Balakrishnan & Reps, "WYSINWYX: What You See Is Not What You eXecute", TOPLAS 2010.
//! * Seladji & Bouhoula, "Strided Intervals for Abstract Interpretation", 2015.

use std::fmt;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Core type
// ─────────────────────────────────────────────────────────────────────────────

/// A strided interval over unsigned 64-bit integers.
///
/// `SI { stride, lo, hi }` denotes `{ lo + k*stride | k ∈ ℕ, lo + k*stride ≤ hi }`.
///
/// Special cases:
/// * `Bottom` — empty set (unreachable).
/// * `stride == 0` — singleton `{lo}` (lo must equal hi).
/// * `stride == 1`, `lo == 0`, `hi == u64::MAX` — Top (all values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StridedInterval {
    /// Empty set: no concrete values.
    Bottom,
    /// Non-empty strided interval `[lo, hi] / stride`.
    Interval {
        /// Stride (step between consecutive values). 0 means singleton.
        stride: u64,
        /// Inclusive lower bound.
        lo: u64,
        /// Inclusive upper bound (lo + k*stride for some k).
        hi: u64,
        /// Bit-width of the underlying type (8, 16, 32, 64, …).
        bits: u8,
    },
}

impl StridedInterval {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// The empty interval (Bottom).
    #[inline]
    #[must_use]
    pub const fn bottom() -> Self {
        Self::Bottom
    }

    /// Top for the given bit-width (all values).
    #[inline]
    #[must_use]
    pub const fn top(bits: u8) -> Self {
        let hi = width_mask(bits);
        Self::Interval { stride: 1, lo: 0, hi, bits }
    }

    /// Singleton interval `{v}` with the given bit-width.
    #[inline]
    #[must_use]
    pub const fn singleton(v: u64, bits: u8) -> Self {
        let v = v & width_mask(bits);
        Self::Interval { stride: 1, lo: v, hi: v, bits }
    }

    /// Construct a strided interval, normalising the inputs.
    ///
    /// Returns `Bottom` if `lo > hi` for an unsigned interpretation.
    #[must_use]
    pub fn new(stride: u64, lo: u64, hi: u64, bits: u8) -> Self {
        let mask = width_mask(bits);
        let lo = lo & mask;
        let mut hi = hi & mask;
        if lo > hi {
            return Self::Bottom;
        }
        let mut stride = if lo == hi { 1 } else { stride.max(1) };
        // Clamp stride so that we don't step past hi.
        if stride == 0 {
            stride = 1;
        }
        // Align `hi` onto `lo + k*stride`, which the representation invariant
        // requires and this constructor's contract promises. Leaving it
        // unaligned is not cosmetic: `hi` is then a value the interval does not
        // denote, and every operation that reasons from the bounds inherits the
        // error. `SI[2;1,2]` denotes `{1}`, but subtracting `SI[2;0,1]` (i.e.
        // `{0}`) from it produced `SI[2;0,2]` = `{0,2}` — an abstract result
        // that excludes the only concrete result, 1. An analysis consuming that
        // concludes a reachable value is impossible.
        if stride > 1 {
            hi = lo + ((hi - lo) / stride) * stride;
            if lo == hi {
                stride = 1;
            }
        }
        Self::Interval { stride, lo, hi, bits }
    }

    /// Construct from a contiguous range `[lo, hi]` (stride = 1).
    #[must_use]
    pub fn range(lo: u64, hi: u64, bits: u8) -> Self {
        Self::new(1, lo, hi, bits)
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// Returns `true` if this is the Bottom element.
    #[inline]
    #[must_use]
    pub const fn is_bottom(&self) -> bool {
        matches!(self, Self::Bottom)
    }

    /// Returns `true` if this is the Top element for its bit-width.
    #[must_use]
    pub const fn is_top(&self) -> bool {
        match self {
            Self::Bottom => false,
            Self::Interval { stride, lo, hi, bits } => {
                *stride == 1 && *lo == 0 && *hi == width_mask(*bits)
            }
        }
    }

    /// Returns `true` if this is a singleton (exactly one value).
    #[must_use]
    pub fn is_singleton(&self) -> bool {
        match self {
            Self::Bottom => false,
            Self::Interval { lo, hi, .. } => lo == hi,
        }
    }

    /// Extract the single concrete value if this is a singleton.
    #[must_use]
    pub fn as_singleton(&self) -> Option<u64> {
        if let Self::Interval { lo, hi, .. } = self && lo == hi {
            return Some(*lo);
        }
        None
    }

    /// The bit-width, or `None` for Bottom.
    #[must_use]
    pub const fn bits(&self) -> Option<u8> {
        match self {
            Self::Bottom => None,
            Self::Interval { bits, .. } => Some(*bits),
        }
    }

    /// Returns the number of elements in the set (capped at `u64::MAX`).
    #[must_use]
    pub fn cardinality(&self) -> Option<u64> {
        match self {
            Self::Bottom => Some(0),
            Self::Interval { stride, lo, hi, .. } => {
                if lo == hi {
                    return Some(1);
                }
                let range = hi.wrapping_sub(*lo);
                // `stride` is normally >= 1 (enforced by `new`), but this enum's
                // fields are public and it derives `Deserialize`, so a
                // struct-literal or deserialized value can carry `stride == 0`
                // without ever going through `new`'s normalization. Guard
                // against that here rather than panicking on division by zero.
                Some(range / (*stride).max(1) + 1)
            }
        }
    }

    /// Returns `true` if `v` is a member of this interval.
    #[must_use]
    pub fn contains(&self, v: u64) -> bool {
        match self {
            Self::Bottom => false,
            Self::Interval { stride, lo, hi, bits } => {
                let v = v & width_mask(*bits);
                if v < *lo || v > *hi {
                    return false;
                }
                if v == *lo {
                    return true;
                }
                (v - lo).is_multiple_of(*stride)
            }
        }
    }

    // ── Lattice operations ────────────────────────────────────────────────────

    /// Least upper bound (join / union over-approximation).
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => *x,
            (
                Self::Interval { stride: s1, lo: lo1, hi: hi1, bits: b1 },
                Self::Interval { stride: s2, lo: lo2, hi: hi2, bits: b2 },
            ) => {
                debug_assert_eq!(b1, b2, "join: bit-width mismatch");
                let lo = (*lo1).min(*lo2);
                let hi = (*hi1).max(*hi2);
                let stride = gcd(*s1, *s2);
                // Stride must also divide the gap between the two lo values.
                // Use the true absolute difference: `wrapping_sub` would feed
                // a wrapped ~2^64 value into `gcd` when lo2 < lo1, yielding a
                // stride that does not divide the offset from the new (min)
                // lower bound — dropping real elements of the operand whose lo
                // is larger. (e.g. join(SI[3;128,..], SI[3;67,..]) must be
                // stride 1, since 128-67=61 is not a multiple of 3.)
                let stride = gcd(stride, lo1.abs_diff(*lo2));
                Self::new(stride.max(1), lo, hi, *b1)
            }
        }
    }

    /// Greatest lower bound (meet / intersection).
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (
                Self::Interval { stride: s1, lo: lo1, hi: hi1, bits: b1 },
                Self::Interval { stride: s2, lo: lo2, hi: hi2, bits: b2 },
            ) => {
                debug_assert_eq!(b1, b2, "meet: bit-width mismatch");
                let lo = (*lo1).max(*lo2);
                let hi = (*hi1).min(*hi2);
                if lo > hi {
                    return Self::Bottom;
                }
                // Stride of intersection: lcm of the two strides, if they share an element.
                let stride = lcm(*s1, *s2);
                // Find the first value in both: Chinese Remainder Theorem approximation.
                let start = align_up(lo, stride, *lo1, *s1, *lo2, *s2);
                match start {
                    None => Self::Bottom,
                    Some(v) if v > hi => Self::Bottom,
                    Some(v) => Self::new(stride, v, hi, *b1),
                }
            }
        }
    }

    /// Widening operator for fixpoint convergence.
    ///
    /// If `self ⊑ other` already holds, return `other` unchanged.  Otherwise,
    /// extrapolate by expanding bounds to the nearest power-of-two boundary.
    #[must_use]
    pub fn widen(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => *x,
            (
                Self::Interval { stride: s1, lo: lo1, hi: hi1, bits: b1 },
                Self::Interval { stride: s2, lo: lo2, hi: hi2, bits: b2 },
            ) => {
                debug_assert_eq!(b1, b2, "widen: bit-width mismatch");
                // Widening must be an upper bound of BOTH operands
                // (widen(a,b) ⊒ a ⊔ b). The previous `else` arms kept `lo2`/
                // `hi2`, which DROPPED members of `self` whenever `b` was not
                // ⊒ `a` (e.g. widen([5,10],[7,10]) returned [7,10], losing 5
                // and 6 ∈ a) — unsound when the caller passes an incoming
                // state that has not already been joined with the old one.
                let lo = if lo2 < lo1 { 0 } else { *lo1 };
                let hi = if hi2 > hi1 { width_mask(*b1) } else { *hi1 };
                // Stride must keep every member of both operands reachable
                // from the final `lo`: gcd of BOTH strides (ignoring `s1`
                // dropped members of `a`, e.g. widen(SI[3;0,9], SI[6;0,12]))
                // and both lo offsets. abs_diff, not wrapping_sub: see `join`.
                let stride = gcd(
                    gcd(*s1, *s2),
                    gcd(lo1.abs_diff(lo), lo2.abs_diff(lo)),
                );
                Self::new(stride.max(1), lo, hi, *b1)
            }
        }
    }

    /// Narrowing operator (refine after widening, maintaining convergence).
    #[must_use]
    pub fn narrow(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (
                Self::Interval { stride: s1, lo: lo1, hi: hi1, bits: b1 },
                Self::Interval { stride: s2, lo: lo2, hi: hi2, bits: b2 },
            ) => {
                debug_assert_eq!(b1, b2, "narrow: bit-width mismatch");
                let _ = s2;
                // Tighten bounds if the other is more precise (classic interval
                // narrowing: only refine bounds sitting at the extremes).
                let lo = if *lo1 == 0 { *lo2 } else { *lo1 };
                let hi = if *hi1 == width_mask(*b1) { *hi2 } else { *hi1 };
                // Keep `self`'s stride. Taking `max(s1, s2)` was UNSOUND: when
                // `b ⊑ a` holds, `b`'s stride `s2` is a multiple of `a`'s stride
                // `s1`, but `b`'s base need not be congruent to the narrowed
                // `lo` modulo `s2`, so a coarser residue class could drop real
                // members of `b`. E.g. a=SI[1;1,100], b=SI[2;4,10]: max-stride
                // gives SI[2;1,100] = {1,3,5,…}, which excludes 4,6,8,10 ∈ b.
                // Using `s1` keeps `b ⊑ result ⊑ a` (since `s2 % s1 == 0` and the
                // bases stay congruent mod `s1`).
                let stride = *s1;
                Self::new(stride, lo, hi, *b1)
            }
        }
    }

    /// Partial-order check: `self ⊑ other`.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bottom, _) => true,
            (_, Self::Bottom) => false,
            (
                Self::Interval { stride: s1, lo: lo1, hi: hi1, bits: b1 },
                Self::Interval { stride: s2, lo: lo2, hi: hi2, bits: b2 },
            ) => {
                // Same defensive note as `cardinality`: `s2` can be 0 if this
                // value was built via struct literal or `Deserialize` rather
                // than `new`, which would otherwise panic on `%`.
                let s2 = (*s2).max(1);
                // A singleton normalizes to stride 1 (see `new`), so the
                // stride-divisibility requirement `s1 % s2 == 0` is wrong for
                // it: {33} IS a subset of SI[2; 9, 241] even though 1 % 2 != 0.
                // Membership of the single element is the exact condition.
                if lo1 == hi1 {
                    return b1 == b2 && other.contains(*lo1);
                }
                b1 == b2 && lo1 >= lo2 && hi1 <= hi2 && s1 % s2 == 0 && lo1.wrapping_sub(*lo2) % s2 == 0
            }
        }
    }

    // ── Arithmetic operations ─────────────────────────────────────────────────

    /// Unsigned addition.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        apply_binop(self, other, |a_lo, a_hi, a_s, b_lo, b_hi, b_s, bits| {
            let mask = width_mask(bits);
            let lo = a_lo.wrapping_add(b_lo) & mask;
            let hi = a_hi.wrapping_add(b_hi) & mask;
            let stride = gcd(a_s, b_s).max(1);
            // If overflow wrapped, return Top.
            if a_hi.checked_add(b_hi).is_none_or(|s| s > mask) {
                Self::top(bits)
            } else {
                Self::new(stride, lo, hi, bits)
            }
        })
    }

    /// Unsigned subtraction.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        apply_binop(self, other, |a_lo, a_hi, a_s, b_lo, b_hi, b_s, bits| {
            let mask = width_mask(bits);
            if b_hi > a_lo {
                // Potential underflow — be conservative.
                return Self::top(bits);
            }
            let lo = a_lo.wrapping_sub(b_hi) & mask;
            let hi = a_hi.wrapping_sub(b_lo) & mask;
            let stride = gcd(a_s, b_s).max(1);
            Self::new(stride, lo, hi, bits)
        })
    }

    /// Unsigned multiplication.
    #[must_use]
    pub fn mul(&self, other: &Self) -> Self {
        apply_binop(self, other, |a_lo, a_hi, a_s, b_lo, b_hi, b_s, bits| {
            let mask = width_mask(bits);
            // Use u128 to detect overflow.
            let lo128 = u128::from(a_lo).wrapping_mul(u128::from(b_lo));
            let hi128 = u128::from(a_hi).wrapping_mul(u128::from(b_hi));
            if hi128 > u128::from(mask) {
                return Self::top(bits);
            }
            let lo = u64::try_from(lo128).unwrap_or(u64::MAX) & mask;
            let hi = u64::try_from(hi128).unwrap_or(u64::MAX) & mask;
            // Products expand as
            //   (a + s·i)(c + t·j) = a·c + s·c·i + t·a·j + s·t·i·j,
            // so the achievable increments are integer combinations of s·c,
            // t·a AND the cross term s·t. Omitting `a_s * b_s` produced a
            // stride too large, which DROPPED real products — unsound for an
            // abstract domain, where widening is safe but narrowing is not.
            // This mirrors the struct implementation in lib.rs, where the same
            // term was already added with a correcting comment.
            let stride = gcd(
                gcd(
                    gcd(a_s.saturating_mul(b_lo), a_s.saturating_mul(b_hi)),
                    gcd(b_s.saturating_mul(a_lo), b_s.saturating_mul(a_hi)),
                ),
                a_s.saturating_mul(b_s),
            )
            .max(1);
            Self::new(stride, lo, hi, bits)
        })
    }

    /// Unsigned division (truncated toward zero).
    #[must_use]
    pub fn udiv(&self, other: &Self) -> Self {
        apply_binop(self, other, |a_lo, a_hi, _a_s, b_lo, b_hi, _b_s, bits| {
            if b_lo == 0 {
                // Possible division by zero — Top.
                return Self::top(bits);
            }
            let lo = a_lo / b_hi;
            let hi = a_hi / b_lo;
            Self::new(1, lo, hi, bits)
        })
    }

    /// Unsigned remainder.
    #[must_use]
    pub fn urem(&self, other: &Self) -> Self {
        apply_binop(self, other, |_a_lo, a_hi, _a_s, b_lo, b_hi, _b_s, bits| {
            if b_lo == 0 {
                return Self::top(bits);
            }
            // Result ∈ [0, min(a_hi, b_hi - 1)].
            let hi = a_hi.min(b_hi.saturating_sub(1));
            Self::new(1, 0, hi, bits)
        })
    }

    /// Signed addition (reinterpret as signed i64).
    #[must_use]
    pub fn sadd(&self, other: &Self) -> Self {
        // For signed arithmetic, work in the signed domain then convert back.
        self.signed_binop(other, i64::wrapping_add)
    }

    /// Signed subtraction.
    #[must_use]
    pub fn ssub(&self, other: &Self) -> Self {
        self.signed_binop(other, i64::wrapping_sub)
    }

    /// Signed multiplication.
    #[must_use]
    pub fn smul(&self, other: &Self) -> Self {
        self.signed_binop(other, i64::wrapping_mul)
    }

    /// Signed division (truncated toward zero).
    ///
    /// # Panics
    ///
    /// Panics in debug builds if the two operands have mismatched bit-widths.
    #[must_use]
    pub fn sdiv(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Interval { bits: b1, .. }, Self::Interval { bits: b2, .. }) => {
                debug_assert_eq!(b1, b2);
                let bits = *b1;
                if let Some(d) = other.as_singleton() && d == 0 {
                    return Self::top(bits);
                }
                // Enumerate quotients over contiguous signed pieces of each
                // operand (a single `signed_bounds()` pair is invalid when an
                // operand straddles the sign boundary). For the divisor, the
                // extreme quotient magnitudes come from the endpoints AND from
                // the nonzero value of smallest magnitude in each piece (a
                // divisor near ±1 maximizes |x/y|), so those must be candidates
                // too — plain corners are not enough.
                let mut divisors: Vec<i64> = Vec::new();
                for &(blo, bhi) in &other.signed_pieces() {
                    for d in [blo, bhi] {
                        if d != 0 {
                            divisors.push(d);
                        }
                    }
                    if bhi >= 1 {
                        divisors.push(if blo > 0 { blo } else { 1 }); // smallest positive
                    }
                    if blo <= -1 {
                        divisors.push(if bhi < 0 { bhi } else { -1 }); // smallest negative
                    }
                }
                if divisors.is_empty() {
                    // Divisor is exactly {0}.
                    return Self::top(bits);
                }
                let mut slo = i64::MAX;
                let mut shi = i64::MIN;
                for &(alo, ahi) in &self.signed_pieces() {
                    for &x in &[alo, ahi] {
                        for &y in &divisors {
                            if let Some(q) = checked_sdiv(x, y) {
                                slo = slo.min(q);
                                shi = shi.max(q);
                            }
                        }
                    }
                }
                if slo > shi {
                    return Self::top(bits);
                }
                signed_range_to_interval(slo, shi, bits)
            }
        }
    }

    // ── Bitwise operations ────────────────────────────────────────────────────

    /// Bitwise AND.
    #[must_use]
    pub fn band(&self, other: &Self) -> Self {
        apply_binop(self, other, |a_lo, a_hi, _a_s, b_lo, b_hi, _b_s, bits| {
            // Conservative approximation: result ∈ [0, min(a_hi, b_hi)].
            if a_lo == a_hi && b_lo == b_hi {
                // Both are singletons — exact result.
                let v = a_lo & b_lo;
                return Self::singleton(v, bits);
            }
            let hi = a_hi.min(b_hi);
            Self::new(1, 0, hi, bits)
        })
    }

    /// Bitwise OR.
    #[must_use]
    pub fn bor(&self, other: &Self) -> Self {
        apply_binop(self, other, |a_lo, a_hi, _a_s, b_lo, b_hi, _b_s, bits| {
            if a_lo == a_hi && b_lo == b_hi {
                let v = a_lo | b_lo;
                return Self::singleton(v, bits);
            }
            // Sound lower bound: x|y >= x >= a_lo and x|y >= y >= b_lo, so
            // x|y >= max(a_lo, b_lo). (a_lo|b_lo is NOT sound — e.g. a=[1,2],
            // b=[2,2] can produce 2|2=2 < 1|2=3.)
            let lo = a_lo.max(b_lo);
            // Sound upper bound: a value <= a_hi may set any bits below a_hi's
            // MSB, so the OR can reach every bit up to msb(a_hi|b_hi). Fill the
            // low bits (a_hi|b_hi alone is NOT sound).
            let hi = fill_below_msb(a_hi | b_hi).min(width_mask(bits));
            Self::new(1, lo, hi, bits)
        })
    }

    /// Bitwise XOR.
    #[must_use]
    pub fn bxor(&self, other: &Self) -> Self {
        apply_binop(self, other, |a_lo, a_hi, _a_s, b_lo, b_hi, _b_s, bits| {
            if a_lo == a_hi && b_lo == b_hi {
                let v = a_lo ^ b_lo;
                return Self::singleton(v, bits);
            }
            // Same reasoning as `bor`'s upper bound: XOR can reach any bit up
            // to msb(a_hi|b_hi), so the raw `a_hi|b_hi` is not a sound bound.
            let hi = fill_below_msb(a_hi | b_hi).min(width_mask(bits));
            Self::new(1, 0, hi, bits)
        })
    }

    /// Bitwise NOT / complement.
    #[must_use]
    pub fn bnot(&self) -> Self {
        match self {
            Self::Bottom => Self::Bottom,
            Self::Interval { stride, lo, hi, bits } => {
                let mask = width_mask(*bits);
                let new_lo = (!hi) & mask;
                let new_hi = (!lo) & mask;
                Self::new(*stride, new_lo, new_hi, *bits)
            }
        }
    }

    /// Arithmetic negation (two's complement).
    #[must_use]
    pub fn neg(&self) -> Self {
        match self {
            Self::Bottom => Self::Bottom,
            Self::Interval { stride, lo, hi, bits } => {
                let mask = width_mask(*bits);
                // -x wraps: -lo becomes (mask+1-lo)&mask.
                let new_lo = (mask.wrapping_add(1).wrapping_sub(*hi)) & mask;
                let new_hi = (mask.wrapping_add(1).wrapping_sub(*lo)) & mask;
                Self::new(*stride, new_lo.min(new_hi), new_lo.max(new_hi), *bits)
            }
        }
    }

    // ── Shift operations ──────────────────────────────────────────────────────

    /// Logical left shift.
    #[must_use]
    pub fn shl(&self, shift: &Self) -> Self {
        apply_binop(self, shift, |a_lo, a_hi, _a_s, b_lo, b_hi, _b_s, bits| {
            if b_hi >= u64::from(bits) {
                // Shift amount ≥ bit-width: result is 0 or Top.
                return if a_lo == 0 && a_hi == 0 {
                    Self::singleton(0, bits)
                } else {
                    Self::top(bits)
                };
            }
            let mask = width_mask(bits);
            let lo = (a_lo << b_lo) & mask;
            let hi_shifted = (a_hi << b_hi) & mask;
            // Check for overflow.
            if b_hi > 0 && a_hi >> (u64::from(bits) - b_hi) != 0 {
                return Self::top(bits);
            }
            Self::new(1, lo.min(hi_shifted), lo.max(hi_shifted), bits)
        })
    }

    /// Logical right shift.
    #[must_use]
    pub fn shr(&self, shift: &Self) -> Self {
        apply_binop(self, shift, |a_lo, a_hi, _a_s, b_lo, b_hi, _b_s, bits| {
            // A shift amount >= bits yields 0, but the shift RANGE may also
            // include smaller amounts that yield nonzero results — returning
            // singleton(0) whenever `b_hi >= bits` is unsound when `b_lo <
            // bits`. Compute each bound against its own effective shift: the
            // largest value uses the smallest shift (b_lo), the smallest value
            // uses the largest shift (b_hi, saturating to 0 past the width).
            let w = u64::from(bits);
            let lo = if b_hi >= w { 0 } else { a_lo >> b_hi };
            let hi = if b_lo >= w { 0 } else { a_hi >> b_lo };
            Self::new(1, lo, hi, bits)
        })
    }

    /// Arithmetic right shift (sign-extending).
    #[must_use]
    pub fn sar(&self, shift: &Self) -> Self {
        match (self, shift) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Interval { bits: b1, .. }, Self::Interval { bits: b2, .. }) => {
                let bits = *b1;
                let _ = b2;
                let shift_lo = if let Self::Interval { lo, .. } = shift { *lo } else { 0 };
                let shift_hi = if let Self::Interval { hi, .. } = shift { *hi } else { 0 };
                // Arithmetic shift is monotonic in both the (signed) value and
                // the shift amount, so extremes lie at corners — but only over
                // a contiguous signed piece: a straddling interval's
                // `signed_bounds()` is a (pos, neg) pair with min>max and would
                // corrupt the corner set.
                let mut slo = i64::MAX;
                let mut shi = i64::MIN;
                for &(alo, ahi) in &self.signed_pieces() {
                    for &x in &[alo, ahi] {
                        for &s in &[shift_lo.min(63), shift_hi.min(63)] {
                            let q = x >> s;
                            slo = slo.min(q);
                            shi = shi.max(q);
                        }
                    }
                }
                signed_range_to_interval(slo, shi, bits)
            }
        }
    }

    // ── Bit-vector operations ─────────────────────────────────────────────────

    /// Extract bits `[from_bit, to_bit]` (inclusive, 0-indexed from LSB).
    #[must_use]
    pub fn extract(&self, from_bit: u8, to_bit: u8) -> Self {
        match self {
            Self::Bottom => Self::Bottom,
            Self::Interval { lo, hi, .. } => {
                if from_bit > to_bit {
                    return Self::Bottom;
                }
                // Bit positions beyond 63 don't exist in the u64 backing
                // store. Clamp before doing u8 arithmetic on `to_bit -
                // from_bit + 1` and before shifting by `from_bit`: without
                // this, a malformed (from_bit, to_bit) pair from untrusted
                // IR (e.g. from_bit=200, to_bit=255) overflows the u8
                // subtraction and shifts a u64 by >= 64 bits, panicking in
                // debug builds.
                if from_bit >= 64 {
                    return Self::singleton(0, 1);
                }
                let to_bit = to_bit.min(63);
                let result_bits = to_bit - from_bit + 1;
                let shift = u64::from(from_bit);
                let mask = width_mask(result_bits);
                let slo = lo >> shift;
                let shi = hi >> shift;
                // If the shifted range wraps the extracted width, every value is
                // possible: masking only the endpoints would drop intermediates.
                if shi.wrapping_sub(slo) > mask || (slo & mask) > (shi & mask) {
                    return Self::top(result_bits);
                }
                Self::range(slo & mask, shi & mask, result_bits)
            }
        }
    }

    /// Concatenate two intervals: `self` occupies the high bits, `other` the low bits.
    #[must_use]
    pub fn concat(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (
                Self::Interval { lo: alo, hi: ahi, bits: ab, .. },
                Self::Interval { lo: blo, hi: bhi, bits: bb, .. },
            ) => {
                // Widen to u16 first: `bits` is a plain `pub` field, so a
                // malformed pair (e.g. both near 255, from a struct literal
                // or deserialized value) could otherwise overflow the u8
                // addition before the `> 64` guard ever runs.
                let result_bits_wide = u16::from(*ab) + u16::from(*bb);
                if result_bits_wide > 64 {
                    return Self::top(64);
                }
                // The `return Self::top(64)` guard above bounds this to 64, so
                // the conversion cannot fail; `try_from` states that instead of
                // asserting it in a comment, and falls back to the same 64 the
                // guard would have produced if the bound ever moves.
                let result_bits = u8::try_from(result_bits_wide).unwrap_or(64);
                let lo = (alo << bb) | blo;
                let hi = (ahi << bb) | bhi;
                Self::range(lo.min(hi), lo.max(hi), result_bits)
            }
        }
    }

    /// Zero-extend from the current bit-width to `target_bits`.
    ///
    /// # Panics
    ///
    /// Panics if `target_bits` is narrower than the source bit-width.
    #[must_use]
    pub fn zero_extend(&self, target_bits: u8) -> Self {
        match self {
            Self::Bottom => Self::Bottom,
            Self::Interval { stride, lo, hi, bits } => {
                assert!(target_bits >= *bits, "zero_extend: target narrower than source");
                Self::new(*stride, *lo, *hi, target_bits)
            }
        }
    }

    /// Sign-extend from the current bit-width to `target_bits`.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if the bit-widths are mismatched in signed-binop.
    #[must_use]
    pub fn sign_extend(&self, target_bits: u8) -> Self {
        match self {
            Self::Bottom => Self::Bottom,
            Self::Interval { .. } => {
                let (slo, shi) = self.signed_bounds();
                let lo = to_unsigned(slo, target_bits);
                let hi = to_unsigned(shi, target_bits);
                Self::range(lo.min(hi), lo.max(hi), target_bits)
            }
        }
    }

    /// Truncate to `target_bits` (take the low `target_bits` of the value).
    ///
    /// # Panics
    ///
    /// Panics if `target_bits` is wider than the source bit-width.
    #[must_use]
    pub fn truncate(&self, target_bits: u8) -> Self {
        match self {
            Self::Bottom => Self::Bottom,
            Self::Interval { lo, hi, bits, stride } => {
                assert!(target_bits <= *bits, "truncate: target wider than source");
                let mask = width_mask(target_bits);
                let new_lo = lo & mask;
                let new_hi = hi & mask;
                if hi.wrapping_sub(*lo) <= mask && new_lo <= new_hi {
                    Self::new(*stride, new_lo, new_hi, target_bits)
                } else {
                    // Truncation wrapped — be conservative.
                    Self::top(target_bits)
                }
            }
        }
    }

    // ── Signed interpretation helpers ─────────────────────────────────────────

    /// Interpret the unsigned bounds as signed `i64` values.
    #[must_use]
    pub const fn signed_bounds(&self) -> (i64, i64) {
        match self {
            Self::Bottom => (0, 0),
            Self::Interval { lo, hi, bits, .. } => {
                (to_signed(*lo, *bits), to_signed(*hi, *bits))
            }
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Decompose the unsigned interval into contiguous *signed* `(min, max)`
    /// pieces. An interval that straddles the sign boundary (contains both
    /// values `< 2^(bits-1)` and `>= 2^(bits-1)`) is NOT a single contiguous
    /// signed range — its `signed_bounds()` would return a `(pos, neg)` pair
    /// with min > max. Split it into a positive piece and a negative piece so
    /// that corner-based reasoning stays sound.
    fn signed_pieces(&self) -> Vec<(i64, i64)> {
        match self {
            Self::Bottom => Vec::new(),
            Self::Interval { lo, hi, bits, .. } => {
                let b = (*bits).clamp(1, 64);
                let mask = width_mask(b);
                let lo = *lo & mask;
                let hi = *hi & mask;
                let thr = 1u64 << (b - 1); // first value with the sign bit set
                if hi < thr || lo >= thr {
                    // Entirely non-negative or entirely negative: contiguous.
                    vec![(to_signed(lo, b), to_signed(hi, b))]
                } else {
                    // Straddles: [lo, thr-1] non-negative, [thr, hi] negative.
                    vec![
                        (to_signed(lo, b), to_signed(thr - 1, b)),
                        (to_signed(thr, b), to_signed(hi, b)),
                    ]
                }
            }
        }
    }

    fn signed_binop<F>(&self, other: &Self, op: F) -> Self
    where
        F: Fn(i64, i64) -> i64,
    {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Interval { bits: b1, .. }, Self::Interval { bits: b2, .. }) => {
                let bits = *b1;
                debug_assert_eq!(b1, b2, "signed_binop: bit-width mismatch");
                // Enumerate corners over every contiguous signed piece of each
                // operand — a single (alo, ahi) pair is invalid when the
                // operand straddles the sign boundary.
                let mut slo = i64::MAX;
                let mut shi = i64::MIN;
                for &(alo, ahi) in &self.signed_pieces() {
                    for &(blo, bhi) in &other.signed_pieces() {
                        for r in [op(alo, blo), op(alo, bhi), op(ahi, blo), op(ahi, bhi)] {
                            slo = slo.min(r);
                            shi = shi.max(r);
                        }
                    }
                }
                signed_range_to_interval(slo, shi, bits)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Display
// ─────────────────────────────────────────────────────────────────────────────

impl fmt::Display for StridedInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bottom => write!(f, "⊥"),
            Self::Interval { stride, lo, hi, bits } => {
                if lo == hi {
                    write!(f, "{{{lo}}}:{bits}")
                } else {
                    write!(f, "SI[{stride}; {lo:#x}, {hi:#x}]:{bits}")
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility functions
// ─────────────────────────────────────────────────────────────────────────────

/// Mask for `bits`-wide unsigned value.
#[inline]
#[must_use]
pub const fn width_mask(bits: u8) -> u64 {
    if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 }
}

/// Interpret a `bits`-wide unsigned value as a signed `i64`.
#[inline]
#[must_use]
pub const fn to_signed(v: u64, bits: u8) -> i64 {
    if bits == 0 {
        return 0;
    }
    // Clamp: a `bits` value above 64 is malformed (no such integer width
    // exists), but since `bits` is a plain `pub` field it can arrive this
    // way via a struct literal or deserialized `StridedInterval`. Without
    // the clamp, `1u64 << (bits - 1)` shifts by up to 254, panicking in
    // debug builds.
    let bits = if bits > 64 { 64 } else { bits };
    let sign_bit = 1u64 << (bits - 1);
    if v & sign_bit != 0 {
        // Negative: sign-extend.
        let extended = v | !width_mask(bits);
        extended.cast_signed()
    } else {
        v.cast_signed()
    }
}

/// Convert a signed `i64` back to an unsigned `u64` for the given bit-width.
#[inline]
#[must_use]
pub const fn to_unsigned(v: i64, bits: u8) -> u64 {
    v.cast_unsigned() & width_mask(bits)
}

/// Set every bit below the most-significant set bit of `x` (i.e. round `x`
/// up to `2^k - 1` where `2^k` is the smallest power of two strictly greater
/// than `x`). Returns 0 for input 0. Used as a sound upper bound for OR/XOR
/// over intervals: any value `<= x` may set arbitrary bits below x's MSB.
#[inline]
#[must_use]
pub const fn fill_below_msb(mut x: u64) -> u64 {
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
    x
}

/// Greatest common divisor (Euclidean).
#[must_use]
pub const fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Least common multiple.
#[must_use]
pub const fn lcm(a: u64, b: u64) -> u64 {
    if a == 0 || b == 0 {
        return 0;
    }
    // Use saturating_mul to avoid overflow when a/gcd(a,b) * b wraps u64.
    (a / gcd(a, b)).saturating_mul(b)
}

/// Apply a binary operation, handling Bottom cases.
fn apply_binop<F>(a: &StridedInterval, b: &StridedInterval, op: F) -> StridedInterval
where
    F: Fn(u64, u64, u64, u64, u64, u64, u8) -> StridedInterval,
{
    use StridedInterval::{Bottom, Interval};
    match (a, b) {
        (Bottom, _) | (_, Bottom) => Bottom,
        (
            Interval { stride: sa, lo: la, hi: ha, bits: ba },
            Interval { stride: sb, lo: lb, hi: hb, bits: bb },
        ) => {
            debug_assert_eq!(ba, bb, "apply_binop: bit-width mismatch");
            op(*la, *ha, *sa, *lb, *hb, *sb, *ba)
        }
    }
}

/// Attempt to find the first value ≥ `lo` that satisfies both congruences
/// (x ≡ lo1 mod s1) and (x ≡ lo2 mod s2). Returns None if incompatible.
fn align_up(lo: u64, stride: u64, lo1: u64, s1: u64, lo2: u64, s2: u64) -> Option<u64> {
    // Simple conservative fallback: just return lo if it satisfies both.
    if s1 != 0 && lo.wrapping_sub(lo1).is_multiple_of(s1)
        && s2 != 0 && lo.wrapping_sub(lo2).is_multiple_of(s2)
    {
        return Some(lo);
    }
    // Search value-by-value (step 1), NOT by `stride`: the first value
    // satisfying both congruences may be at any residue, so stepping by the
    // combined stride (lcm) from `lo` would only ever probe one residue class
    // and could skip the real aligned value entirely — e.g. lo=55, stride=2
    // steps 55,57,59,… (all odd) and never reaches the valid even 56.
    // The aligned value, if any, lies within one full period (lcm == stride)
    // of `lo`, so bound the scan by that (capped for pathological strides).
    let period = stride.max(1).min(1 << 20);
    for k in 0u64..=period {
        let v = lo.wrapping_add(k);
        if (s1 == 0 || v.wrapping_sub(lo1).is_multiple_of(s1))
            && (s2 == 0 || v.wrapping_sub(lo2).is_multiple_of(s2))
        {
            return Some(v);
        }
    }
    None // Give up — over-approximate to Bottom at call site.
}

/// Map a signed result range `[slo, shi]` back to an unsigned `bits`-wide
/// strided interval. Returns `Top` when the range is wider than the bit-width
/// or when it wraps around the unsigned boundary once masked (either case
/// would otherwise be mis-collapsed into a bogus contiguous interval).
fn signed_range_to_interval(slo: i64, shi: i64, bits: u8) -> StridedInterval {
    if slo > shi {
        return StridedInterval::Bottom;
    }
    // Range wider than the representable value space ⇒ every value possible.
    if i128::from(shi) - i128::from(slo) >= (1i128 << bits.min(63)) {
        return StridedInterval::top(bits);
    }
    let lo = to_unsigned(slo, bits);
    let hi = to_unsigned(shi, bits);
    if lo <= hi {
        StridedInterval::range(lo, hi, bits)
    } else {
        // Wrapped across the unsigned boundary — not representable as a single
        // non-wrapping interval, so conservatively return Top.
        StridedInterval::top(bits)
    }
}

const fn checked_sdiv(a: i64, b: i64) -> Option<i64> {
    if b == 0 { None } else { Some(a.wrapping_div(b)) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Widening with threshold (for loop analysis)
// ─────────────────────────────────────────────────────────────────────────────

/// A set of thresholds used during widening to delay divergence to the
/// nearest "natural" bound (e.g., array sizes, loop bounds).
#[derive(Debug, Clone)]
pub struct WideningThresholds {
    /// Sorted list of threshold values.
    pub thresholds: Vec<u64>,
}

impl WideningThresholds {
    /// Default thresholds: powers of two and common loop bounds.
    #[must_use]
    pub fn default_thresholds(bits: u8) -> Self {
        let mask = width_mask(bits);
        let mut t = vec![0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
                          511, 512, 1023, 1024, 2047, 2048, 4095, 4096, 65535, 65536];
        t.push(mask);
        t.dedup();
        t.sort_unstable();
        t.retain(|&v| v <= mask);
        Self { thresholds: t }
    }

    /// Find the smallest threshold ≥ `v`, or `u64::MAX`.
    #[must_use]
    pub fn next_threshold(&self, v: u64) -> u64 {
        match self.thresholds.partition_point(|&t| t < v) {
            i if i < self.thresholds.len() => self.thresholds[i],
            _ => u64::MAX,
        }
    }

    /// Find the largest threshold ≤ `v`, or `0`.
    #[must_use]
    pub fn prev_threshold(&self, v: u64) -> u64 {
        let i = self.thresholds.partition_point(|&t| t <= v);
        if i > 0 { self.thresholds[i - 1] } else { 0 }
    }
}

impl StridedInterval {
    /// Widening with threshold hints.
    ///
    /// Instead of jumping directly to `[0, u64::MAX]`, the bounds are relaxed
    /// to the nearest threshold value, delaying divergence.
    #[must_use]
    pub fn widen_with_thresholds(&self, other: &Self, thresholds: &WideningThresholds) -> Self {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => *x,
            (
                Self::Interval { lo: lo1, hi: hi1, stride: s1, bits: b1 },
                Self::Interval { lo: lo2, hi: hi2, stride: s2, bits: _b2 },
            ) => {
                let bits = *b1;
                // Same soundness requirements as `widen`: the result must be
                // ⊒ both operands, so the non-extrapolating arms keep `self`'s
                // (already-extremal) bound, not `other`'s, and the stride must
                // divide both lo offsets from the final `lo` (a threshold `lo`
                // need not be congruent to either operand's base).
                let lo = if lo2 < lo1 {
                    thresholds.prev_threshold(*lo2)
                } else {
                    *lo1
                };
                let hi = if hi2 > hi1 {
                    thresholds.next_threshold(*hi2).min(width_mask(bits))
                } else {
                    *hi1
                };
                let stride = gcd(
                    gcd(*s1, *s2),
                    gcd(lo1.abs_diff(lo), lo2.abs_diff(lo)),
                )
                .max(1);
                Self::new(stride, lo, hi, bits)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cardinality_does_not_panic_on_zero_stride_struct_literal() {
        // `Interval`'s fields are public and the type derives `Deserialize`,
        // so a struct literal (or a deserialized value) can carry
        // `stride == 0` without ever going through `new`'s normalization.
        // `cardinality` must not divide by zero in that case.
        let si = StridedInterval::Interval { stride: 0, lo: 0, hi: 10, bits: 64 };
        assert_eq!(si.cardinality(), Some(11));
    }

    #[test]
    fn is_subset_of_does_not_panic_on_zero_stride_struct_literal() {
        let a = StridedInterval::Interval { stride: 1, lo: 0, hi: 4, bits: 64 };
        let b = StridedInterval::Interval { stride: 0, lo: 0, hi: 10, bits: 64 };
        // Should not panic; result value isn't the point, just that it returns.
        let _ = a.is_subset_of(&b);
    }

    #[test]
    fn test_singleton_contains() {
        let si = StridedInterval::singleton(42, 64);
        assert!(si.contains(42));
        assert!(!si.contains(43));
    }

    #[test]
    fn test_range_contains() {
        let si = StridedInterval::new(2, 0, 10, 64); // evens 0..=10
        assert!(si.contains(0));
        assert!(si.contains(2));
        assert!(si.contains(10));
        assert!(!si.contains(1));
        assert!(!si.contains(11));
    }

    #[test]
    fn test_join_intervals() {
        let a = StridedInterval::new(1, 0, 5, 8);
        let b = StridedInterval::new(1, 3, 10, 8);
        let c = a.join(&b);
        assert!(c.contains(0));
        assert!(c.contains(10));
    }

    #[test]
    fn test_meet_intervals() {
        let a = StridedInterval::new(1, 0, 10, 8);
        let b = StridedInterval::new(1, 5, 15, 8);
        let c = a.meet(&b);
        assert!(c.contains(5));
        assert!(!c.contains(4));
    }

    #[test]
    fn test_add_intervals() {
        let a = StridedInterval::new(1, 1, 3, 8);
        let b = StridedInterval::new(1, 2, 4, 8);
        let c = a.add(&b);
        assert!(c.contains(3));
        assert!(c.contains(7));
    }

    #[test]
    fn test_band_singletons() {
        let a = StridedInterval::singleton(0xFF, 8);
        let b = StridedInterval::singleton(0x0F, 8);
        let c = a.band(&b);
        assert_eq!(c.as_singleton(), Some(0x0F));
    }

    // ── Hardening: malformed (from_bit, to_bit, bits) inputs from untrusted
    // struct literals / deserialized values must not panic. ──────────────────

    #[test]
    fn extract_does_not_panic_on_out_of_range_bits() {
        let a = StridedInterval::new(1, 0, 0xFF, 32);
        // to_bit=255 would overflow `to_bit - from_bit + 1` as u8 arithmetic
        // if not clamped, and `from_bit >= 64` would shift a u64 out of range.
        let r = a.extract(0, 255);
        assert!(!r.is_bottom());
        let r2 = a.extract(200, 255);
        assert_eq!(r2.as_singleton(), Some(0));
    }

    #[test]
    fn to_signed_does_not_panic_on_oversized_bits() {
        // `bits` is a plain pub field; a value above 64 is malformed but
        // must be handled gracefully rather than overflow-shifting.
        assert_eq!(to_signed(1, 255), 1);
        assert_eq!(to_signed(0, 100), 0);
    }

    #[test]
    fn concat_does_not_panic_on_oversized_bit_widths() {
        let a = StridedInterval::new(1, 0, 1, 200);
        let b = StridedInterval::new(1, 0, 1, 200);
        // ab + bb = 400 would overflow a u8 addition before the `> 64`
        // guard could run; result should conservatively fall back to Top.
        let c = a.concat(&b);
        assert!(c.is_top());
    }

    #[test]
    fn test_bnot() {
        let a = StridedInterval::singleton(0x00, 8);
        let b = a.bnot();
        assert_eq!(b.as_singleton(), Some(0xFF));
    }

    #[test]
    fn test_extract() {
        let a = StridedInterval::singleton(0b10110100u64, 8);
        let b = a.extract(2, 5); // bits 2..5 = 0b1101 = 13
        assert_eq!(b.as_singleton(), Some(0b1101));
    }

    #[test]
    fn test_concat() {
        let hi = StridedInterval::singleton(0xAB, 8);
        let lo = StridedInterval::singleton(0xCD, 8);
        let c = hi.concat(&lo);
        assert_eq!(c.as_singleton(), Some(0xABCD));
    }

    #[test]
    fn test_zero_extend() {
        let a = StridedInterval::singleton(0xFF, 8);
        let b = a.zero_extend(16);
        assert_eq!(b.as_singleton(), Some(0x00FF));
    }

    #[test]
    fn test_sign_extend_negative() {
        let a = StridedInterval::singleton(0xFF, 8); // -1 in i8
        let b = a.sign_extend(16);
        assert_eq!(b.as_singleton(), Some(0xFFFF));
    }

    #[test]
    fn test_widen_diverges() {
        let a = StridedInterval::new(1, 0, 5, 8);
        let b = StridedInterval::new(1, 0, 10, 8);
        let c = a.widen(&b);
        // hi should have expanded.
        match c {
            StridedInterval::Interval { hi, .. } => assert!(hi >= 10),
            _ => panic!("expected Interval"),
        }
    }

    #[test]
    fn test_widen_with_thresholds() {
        let thresholds = WideningThresholds::default_thresholds(8);
        let a = StridedInterval::new(1, 0, 5, 8);
        let b = StridedInterval::new(1, 0, 10, 8);
        let c = a.widen_with_thresholds(&b, &thresholds);
        match c {
            StridedInterval::Interval { hi, .. } => assert!(hi >= 10 && hi <= 15),
            _ => panic!("expected Interval"),
        }
    }

    #[test]
    fn test_is_subset() {
        let a = StridedInterval::new(2, 2, 8, 8);
        let b = StridedInterval::new(1, 0, 10, 8);
        assert!(a.is_subset_of(&b));
        assert!(!b.is_subset_of(&a));
    }

    #[test]
    fn test_bottom_lattice() {
        let bot = StridedInterval::bottom();
        let top = StridedInterval::top(8);
        assert!(bot.is_subset_of(&top));
        assert!(bot.is_subset_of(&bot));
        assert_eq!(bot.join(&top), top);
        assert_eq!(bot.meet(&top), bot);
    }

    #[test]
    fn test_top_is_top() {
        let t = StridedInterval::top(8);
        assert!(t.is_top());
        assert!(!t.is_bottom());
    }

    // ── Additional edge-case tests ───────────────────────────────────────────

    #[test]
    fn test_new_lo_greater_than_hi_returns_bottom() {
        let si = StridedInterval::new(1, 10, 5, 8);
        assert!(si.is_bottom());
    }

    #[test]
    fn test_singleton_masks_to_bitwidth() {
        let si = StridedInterval::singleton(0xFFFF, 8);
        assert_eq!(si.as_singleton(), Some(0xFF));
    }

    #[test]
    fn test_bottom_meet_join_with_bottom() {
        let bot = StridedInterval::bottom();
        let other = StridedInterval::singleton(5, 8);
        assert_eq!(bot.meet(&other), bot);
        assert_eq!(bot.join(&other), other);
    }

    #[test]
    fn test_contains_bottom_is_false() {
        let bot = StridedInterval::bottom();
        assert!(!bot.contains(0));
        assert!(!bot.contains(u64::MAX));
    }

    #[test]
    fn test_width_mask_boundaries() {
        assert_eq!(width_mask(8), 0xFF);
        assert_eq!(width_mask(16), 0xFFFF);
        assert_eq!(width_mask(32), 0xFFFF_FFFF);
        assert_eq!(width_mask(64), u64::MAX);
    }

    #[test]
    fn test_gcd_and_lcm_basics() {
        assert_eq!(gcd(0, 5), 5);
        assert_eq!(gcd(12, 18), 6);
        assert_eq!(gcd(7, 13), 1);
        assert_eq!(lcm(4, 6), 12);
    }

    #[test]
    fn test_to_signed_and_back() {
        // 0xFF in 8 bits is -1 signed.
        assert_eq!(to_signed(0xFF, 8), -1);
        assert_eq!(to_unsigned(-1, 8), 0xFF);
        assert_eq!(to_signed(0x80, 8), -128);
        assert_eq!(to_signed(0x7F, 8), 127);
    }

    #[test]
    fn test_truncate_to_8_bits() {
        let si = StridedInterval::singleton(0x1234, 16);
        let t = si.truncate(8);
        assert_eq!(t.as_singleton(), Some(0x34));
    }

    #[test]
    fn test_cardinality_singleton_and_range() {
        let s = StridedInterval::singleton(42, 8);
        assert_eq!(s.cardinality(), Some(1));
        let r = StridedInterval::new(2, 0, 10, 8);
        // 0, 2, 4, 6, 8, 10 → 6 values.
        assert_eq!(r.cardinality(), Some(6));
    }

    #[test]
    fn test_is_singleton_vs_range() {
        assert!(StridedInterval::singleton(5, 8).is_singleton());
        assert!(!StridedInterval::range(0, 10, 8).is_singleton());
        assert!(!StridedInterval::bottom().is_singleton());
    }

    // ── Randomized soundness (over-approximation) properties ──────────────────
    //
    // The abstract domain must never *under*-approximate: every concrete result
    // of an operation on concrete inputs drawn from the operand intervals must
    // be a member of the abstract result. We check this exhaustively over 8-bit
    // intervals (only 256 concrete values, so enumeration is cheap), on many
    // random operand pairs driven by a deterministic xorshift PRNG.

    use crate::test_prng::xorshift;

    /// All concrete 8-bit values in an interval.
    fn elements8(si: &StridedInterval) -> Vec<u64> {
        (0u64..=0xFF).filter(|&v| si.contains(v)).collect()
    }

    /// A random non-Bottom 8-bit interval.
    fn rand_si8(state: &mut u64) -> StridedInterval {
        let lo = xorshift(state) & 0xFF;
        let hi = xorshift(state) & 0xFF;
        let stride = (xorshift(state) % 5) + 1; // 1..=5
        StridedInterval::new(stride, lo.min(hi), lo.max(hi), 8)
    }

    #[test]
    fn prop_join_over_approximates_both_operands() {
        let mut state = 0x1234_5678_9abc_def0;
        for _ in 0..4000 {
            let a = rand_si8(&mut state);
            let b = rand_si8(&mut state);
            let j = a.join(&b);
            for v in elements8(&a) {
                assert!(j.contains(v), "join lost element {v} of a={a} b={b} -> {j}");
            }
            for v in elements8(&b) {
                assert!(j.contains(v), "join lost element {v} of b in a={a} b={b} -> {j}");
            }
        }
    }

    #[test]
    fn prop_meet_contains_all_common_elements() {
        let mut state = 0x0fed_cba9_8765_4321;
        for _ in 0..4000 {
            let a = rand_si8(&mut state);
            let b = rand_si8(&mut state);
            let m = a.meet(&b);
            let ea = elements8(&a);
            for v in ea {
                if b.contains(v) {
                    assert!(
                        m.contains(v),
                        "meet dropped common element {v} of a={a} b={b} -> {m}"
                    );
                }
            }
        }
    }

    #[test]
    fn prop_signed_ops_over_approximate() {
        // Signed ops interpret the 8-bit values as i8. The abstract result
        // must contain the (masked) concrete result for every operand pair.
        let mut state = 0xa5a5_5a5a_1122_3344;
        let mask = 0xFFu64;
        for _ in 0..2000 {
            let a = rand_si8(&mut state);
            let b = rand_si8(&mut state);
            let ea = elements8(&a);
            let eb = elements8(&b);
            let sadd = a.sadd(&b);
            let ssub = a.ssub(&b);
            let smul = a.smul(&b);
            let sdiv = a.sdiv(&b);
            for &x in &ea {
                let xs = i64::from(x as u8 as i8);
                for &y in &eb {
                    let ys = i64::from(y as u8 as i8);
                    let add = (xs.wrapping_add(ys) as u64) & mask;
                    assert!(sadd.contains(add), "sadd missed {xs}+{ys}: a={a} b={b} -> {sadd}");
                    let sub = (xs.wrapping_sub(ys) as u64) & mask;
                    assert!(ssub.contains(sub), "ssub missed {xs}-{ys}: a={a} b={b} -> {ssub}");
                    let mul = (xs.wrapping_mul(ys) as u64) & mask;
                    assert!(smul.contains(mul), "smul missed {xs}*{ys}: a={a} b={b} -> {smul}");
                    if ys != 0 {
                        let dv = (xs.wrapping_div(ys) as u64) & mask;
                        assert!(sdiv.contains(dv), "sdiv missed {xs}/{ys}: a={a} b={b} -> {sdiv}");
                    }
                }
            }
        }
    }

    #[test]
    fn prop_shift_and_udiv_ops_over_approximate() {
        let mut state = 0x1357_9bdf_2468_ace0;
        let mask = 0xFFu64;
        for _ in 0..2000 {
            let a = rand_si8(&mut state);
            // shift amount kept small so shifts stay meaningful
            let slo = xorshift(&mut state) % 9;
            let shi = xorshift(&mut state) % 9;
            let sh = StridedInterval::new(1, slo.min(shi), slo.max(shi), 8);
            let b = rand_si8(&mut state);
            let ea = elements8(&a);
            let esh = elements8(&sh);
            let eb = elements8(&b);
            let shl = a.shl(&sh);
            let shr = a.shr(&sh);
            let sar = a.sar(&sh);
            let udiv = a.udiv(&b);
            let urem = a.urem(&b);
            for &x in &ea {
                for &s in &esh {
                    let l = (x << s) & mask;
                    assert!(shl.contains(l), "shl missed {x}<<{s}={l}: a={a} sh={sh} -> {shl}");
                    let r = (x >> s) & mask;
                    assert!(shr.contains(r), "shr missed {x}>>{s}={r}: a={a} sh={sh} -> {shr}");
                    let ar = ((i64::from(x as u8 as i8) >> s) as u64) & mask;
                    assert!(sar.contains(ar), "sar missed {x} sar {s}={ar}: a={a} sh={sh} -> {sar}");
                }
                for &y in &eb {
                    if y != 0 {
                        assert!(udiv.contains(x / y), "udiv missed {x}/{y}: -> {udiv}");
                        assert!(urem.contains(x % y), "urem missed {x}%{y}: -> {urem}");
                    }
                }
            }
        }
    }

    #[test]
    fn prop_arithmetic_ops_over_approximate() {
        let mut state = 0xdead_beef_cafe_babe;
        let mask = 0xFFu64;
        for _ in 0..2000 {
            let a = rand_si8(&mut state);
            let b = rand_si8(&mut state);
            let ea = elements8(&a);
            let eb = elements8(&b);
            let add = a.add(&b);
            let mul = a.mul(&b);
            let band = a.band(&b);
            let bor = a.bor(&b);
            let bxor = a.bxor(&b);
            for &x in &ea {
                for &y in &eb {
                    let s = x.wrapping_add(y) & mask;
                    assert!(add.contains(s), "add missed {x}+{y}={s}: a={a} b={b} -> {add}");
                    let p = x.wrapping_mul(y) & mask;
                    assert!(mul.contains(p), "mul missed {x}*{y}={p}: a={a} b={b} -> {mul}");
                    assert!(band.contains(x & y), "band missed {x}&{y}: -> {band}");
                    assert!(bor.contains(x | y), "bor missed {x}|{y}: -> {bor}");
                    assert!(bxor.contains(x ^ y), "bxor missed {x}^{y}: -> {bxor}");
                }
            }
        }
    }

    // ── sar (arithmetic right shift) over-approximation ─────────────────────
    // For every concrete value x in `a` and every concrete shift s in `shift`,
    // the arithmetic (sign-extending) right shift result must be a member of
    // `a.sar(shift)`. Reference: interpret x as signed within `bits`, shift, and
    // re-mask to `bits`. The abstract clamps the shift to 63; mirror that.
    #[test]
    fn prop_sar_over_approximates() {
        let mut state = 0x5ADD_1E55_0F17_u64 | 1;
        for _ in 0..6000 {
            let a = rand_si8(&mut state);
            // Small shift interval so the shift stays meaningful for 8-bit.
            let s_lo = xorshift(&mut state) % 10;
            let s_hi = s_lo + xorshift(&mut state) % 6;
            let shift = StridedInterval::new(1, s_lo, s_hi, 8);
            let res = a.sar(&shift);
            for x in elements8(&a) {
                let sx = to_signed(x, 8);
                for s in elements8(&shift) {
                    let sh = s.min(63) as u32;
                    let q = sx >> sh; // arithmetic (i64) shift
                    let masked = (q as u64) & 0xFF;
                    assert!(
                        res.contains(masked),
                        "sar missed x={x}(s={sx})>>{s} = {masked}: a={a} shift={shift} -> {res}"
                    );
                }
            }
        }
    }

    // ── narrow: standard narrowing spec `b ⊑ (a △ b) ⊑ a` when `b ⊑ a` ───────
    // Narrowing refines a widened (over-approximating) value `a` using a more
    // precise recomputation `b ⊑ a`. It must never drop a member of `b` (which
    // is itself a sound over-approximation of the concrete fixpoint) and must
    // never grow beyond `a`.
    #[test]
    fn prop_narrow_between_meet_and_self() {
        let mut state = 0x9A22_0FEE_1234_u64 | 1;
        let mut checked = 0u64;
        for _ in 0..20000 {
            let a = rand_si8(&mut state);
            let b = rand_si8(&mut state);
            // Only the precondition `b ⊑ a` gives the narrowing spec meaning.
            if !b.is_subset_of(&a) {
                continue;
            }
            checked += 1;
            let n = a.narrow(&b);
            assert!(
                b.is_subset_of(&n),
                "narrow dropped members of b: a={a} b={b} -> narrow={n}"
            );
            assert!(
                n.is_subset_of(&a),
                "narrow grew beyond a: a={a} b={b} -> narrow={n}"
            );
            // Element-level soundness cross-check.
            for v in elements8(&b) {
                assert!(n.contains(v), "narrow lost element {v}: a={a} b={b} -> {n}");
            }
        }
        assert!(checked > 100, "too few b⊑a cases exercised ({checked})");
    }

    // ── Lattice-law property tests (randomized, deterministic seeds) ─────────

    #[test]
    fn prop_join_commutative() {
        let mut state = 0xC077_u64 ^ 0x1111_2222_3333_4444;
        for _ in 0..4000 {
            let a = rand_si8(&mut state);
            let b = rand_si8(&mut state);
            assert_eq!(a.join(&b), b.join(&a), "join not commutative: a={a} b={b}");
        }
    }

    #[test]
    fn prop_join_associative_sound() {
        // Exact associativity may fail for over-approximating joins; the sound
        // requirement is that both associations contain every element of a, b, c.
        let mut state = 0xA550_C1A7_1234_5678;
        for _ in 0..3000 {
            let a = rand_si8(&mut state);
            let b = rand_si8(&mut state);
            let c = rand_si8(&mut state);
            let l = a.join(&b).join(&c);
            let r = a.join(&b.join(&c));
            for si in [&a, &b, &c] {
                for v in elements8(si) {
                    assert!(l.contains(v), "(a⊔b)⊔c lost {v}: a={a} b={b} c={c} -> {l}");
                    assert!(r.contains(v), "a⊔(b⊔c) lost {v}: a={a} b={b} c={c} -> {r}");
                }
            }
        }
    }

    #[test]
    fn prop_meet_is_lower_bound() {
        let mut state = 0x3E37_10EE_u64 ^ 0xdead_0000_beef_0000;
        for _ in 0..4000 {
            let a = rand_si8(&mut state);
            let b = rand_si8(&mut state);
            let m = a.meet(&b);
            assert!(m.is_subset_of(&a), "meet not ⊑ a: a={a} b={b} -> {m}");
            assert!(m.is_subset_of(&b), "meet not ⊑ b: a={a} b={b} -> {m}");
        }
    }

    #[test]
    fn prop_widen_over_approximates_join() {
        // widen(a, b) ⊒ a ⊔ b: every element of both operands is retained.
        // Seed 0x51DE_CA5E: caught the old `else *lo2` / `else *hi2` arms
        // (widen([5,10],[7,10]) = [7,10], losing 5,6) and the `gcd(s2, ..)`
        // stride that ignored s1 (widen(SI[3;0,9], SI[6;0,12]) missing 3).
        let mut state = 0x51DE_CA5E_0000_0001;
        for _ in 0..6000 {
            let a = rand_si8(&mut state);
            let b = rand_si8(&mut state);
            let w = a.widen(&b);
            for si in [&a, &b] {
                for v in elements8(si) {
                    assert!(w.contains(v), "widen lost {v}: a={a} b={b} -> {w}");
                }
            }
            let thr = WideningThresholds::default_thresholds(8);
            let wt = a.widen_with_thresholds(&b, &thr);
            for si in [&a, &b] {
                for v in elements8(si) {
                    assert!(wt.contains(v), "widen_with_thresholds lost {v}: a={a} b={b} -> {wt}");
                }
            }
        }
    }

    #[test]
    fn is_subset_of_regression_singleton_in_strided() {
        // Found by prop_meet_is_lower_bound (seed 0x3E37_10EE ^ 0xdead_0000_beef_0000):
        // {33} is a member-wise subset of SI[2; 9, 0xf1], but singletons
        // normalize to stride 1 and the old `s1 % s2 == 0` check rejected it.
        let a = StridedInterval::new(2, 0x9, 0xf1, 8);
        let s = StridedInterval::singleton(33, 8);
        assert!(s.is_subset_of(&a));
        assert!(!StridedInterval::singleton(34, 8).is_subset_of(&a));
    }

    #[test]
    fn widen_regression_else_arm_kept_other_bound() {
        // Direct regression for the widen unsoundness found by
        // prop_widen_over_approximates_join.
        let a = StridedInterval::new(1, 5, 10, 8);
        let b = StridedInterval::new(1, 7, 10, 8);
        let w = a.widen(&b);
        assert!(w.contains(5) && w.contains(6), "widen must retain a's members: {w}");
        let a2 = StridedInterval::new(3, 0, 9, 8);
        let b2 = StridedInterval::new(6, 0, 12, 8);
        let w2 = a2.widen(&b2);
        for v in [0u64, 3, 6, 9] {
            assert!(w2.contains(v), "widen stride must divide a's stride: {w2} missing {v}");
        }
    }

    #[test]
    fn prop_widening_terminates() {
        // Repeated widening against arbitrary new values must reach a fixpoint
        // in a small bounded number of steps (bounds hit extremes, stride only
        // divides downward).
        let mut state = 0x7E10_11AA_22BB_33CC;
        for _ in 0..1000 {
            let mut cur = rand_si8(&mut state);
            let mut steps = 0usize;
            loop {
                let next_in = rand_si8(&mut state);
                let w = cur.widen(&next_in);
                assert!(
                    cur.is_subset_of(&w) || cur == w,
                    "widen not increasing: cur={cur} in={next_in} -> {w}"
                );
                if w == cur {
                    break;
                }
                cur = w;
                steps += 1;
                assert!(steps <= 80, "widening chain did not stabilise: cur={cur}");
            }
        }
    }
}
