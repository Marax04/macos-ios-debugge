//! `rustre-analysis-vsa`
//!
//! Value Set Analysis (VSA) for the `RustRE` Suite.
//!
//! VSA over-approximates the set of concrete values that each variable may
//! hold at each program point. This enables pointer analysis, indirect call
//! resolution, and detection of out-of-bounds accesses.
//!
//! The abstract domain uses strided intervals: a `Range { lo, hi, stride }`
//! represents every value `v = lo + k * stride` for integer `k >= 0` such
//! that `v <= hi`.

pub mod abstract_interpretation;
pub mod alias_analysis;
pub mod interprocedural;
pub mod jumptable;
pub mod pointer;
pub mod value_regions;
/// Backward-compatible re-export; prefer `value_regions` for new code.
pub use value_regions as region_analysis;
pub mod strided_interval;
#[cfg(test)]
mod si_differential;
pub mod taint;
pub mod value_set_operations;

/// Shared test-only PRNG for the crate's randomized property tests.
///
/// One definition instead of the ~13 per-module xorshift copies the test
/// modules used to carry (free-fn `xorshift`/`xs` and struct `Xs`/`Rng`
/// variants). Algorithm and the `seed | 1` zero-guard are identical to every
/// former copy, so no test's random sequence changes.
#[cfg(test)]
pub(crate) mod test_prng {
    /// One xorshift64 step: mutates the state in place and returns it.
    pub(crate) fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// Seeded xorshift64 PRNG (state forced odd to avoid the zero fixed point).
    pub(crate) struct Xs(pub(crate) u64);

    impl Xs {
        pub(crate) fn new(seed: u64) -> Self {
            Self(seed | 1)
        }
        pub(crate) fn next(&mut self) -> u64 {
            xorshift(&mut self.0)
        }
        pub(crate) fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        /// Random i64 in [-range, range].
        pub(crate) fn small(&mut self, range: i64) -> i64 {
            let m = (range as u64) * 2 + 1;
            (self.next() % m) as i64 - range
        }
    }
}

pub use jumptable::{
    JumpTableBounds, TableImage, bound_jump_table, offset as vs_offset, resolve_indirect_targets,
    resolve_switch, scale as vs_scale, widen as vs_widen,
};
pub use pointer::{
    AbstractPointer, PointerAnalysisConfig, PointerAnalysisResult, PointerEnvironment,
    PointerRegion, PointsToSet, PtrBlock, PtrCfg, PtrInstr, may_alias, must_alias, ptr_add,
    ptr_sub, run_pointer_analysis, widen, widen_envs,
};
pub use taint::{
    ConstPropState, ConstValue, TaintAnalyzer, TaintConfig, TaintFlow, TaintInstruction,
    TaintLabel, TaintReport, TaintSanitizer, TaintSink, TaintSource, TaintState, TaintStatistic,
    TaintValue,
};

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ────────────────────────────────────────────────────────────────────────────
// Error type
// ────────────────────────────────────────────────────────────────────────────

/// Errors that can occur during VSA.
#[derive(Debug, Error)]
pub enum VsaError {
    /// The requested variable was not found in the state map.
    #[error("variable {0} not found")]
    UnknownVariable(String),
    /// The analysis failed to converge within the iteration budget.
    #[error("analysis did not converge")]
    NoConvergence,
    /// The supplied `VsaCfg` contains no basic blocks.
    #[error("empty program")]
    EmptyProgram,
}

// ────────────────────────────────────────────────────────────────────────────
// ValueSet — the abstract domain
// ────────────────────────────────────────────────────────────────────────────

/// The abstract value domain for VSA.
///
/// * `Bottom` — unreachable; initial state before any definition.
/// * `Concrete` — a finite enumerated set of values (small sets only).
/// * `Range` — a strided interval `[lo, hi] / stride`.
/// * `Top` — all 64-bit values; complete loss of precision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueSet {
    /// No values (unreachable / undefined).
    Bottom,
    /// A finite, explicit set of concrete values.
    Concrete(Vec<u64>),
    /// Strided interval: all values `lo + k * stride` with `lo + k*stride <= hi`.
    /// Invariant: `stride >= 1`, `lo <= hi`.
    Range {
        /// Lower bound of the interval.
        lo: u64,
        /// Upper bound of the interval.
        hi: u64,
        /// Step between consecutive values.
        stride: u64,
    },
    /// All possible `u64` values (top / unknown).
    Top,
}

/// Maximum number of concrete values before widening to a `Range` or `Top`.
const MAX_CONCRETE: usize = 32;

impl ValueSet {
    // ── Constructors ──────────────────────────────────────────────────────

    /// Create a `ValueSet` holding exactly one value.
    #[must_use]
    pub fn singleton(v: u64) -> Self {
        Self::Concrete(vec![v])
    }

    /// Create the `Top` element (all possible `u64` values / completely unknown).
    #[must_use]
    pub const fn top() -> Self {
        Self::Top
    }

    /// Create the `Bottom` element (no values / unreachable).
    #[must_use]
    pub const fn bottom() -> Self {
        Self::Bottom
    }

    /// Create a `ValueSet` covering `[lo, hi]` with stride 1.
    #[must_use]
    pub fn interval(lo: u64, hi: u64) -> Self {
        if lo == hi {
            Self::singleton(lo)
        } else {
            Self::Range { lo, hi, stride: 1 }
        }
    }

    /// Create a `ValueSet` covering `[lo, hi]` with the given `stride`.
    #[must_use]
    pub fn strided(lo: u64, hi: u64, stride: u64) -> Self {
        let stride = stride.max(1);
        if lo == hi {
            Self::singleton(lo)
        } else {
            Self::Range { lo, hi, stride }
        }
    }

    // ── Lattice operations ─────────────────────────────────────────────────

    /// Join (least upper bound): the smallest abstract value containing
    /// all values of both `self` and `other`.
    ///
    /// # Panics
    ///
    /// Panics if a non-empty `Concrete` vector has no min/max (impossible
    /// because the vector is non-empty, but the compiler cannot verify this).
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => x.clone(),
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Concrete(a), Self::Concrete(b)) => {
                let mut merged: Vec<u64> = a.clone();
                for v in b {
                    if !merged.contains(v) {
                        merged.push(*v);
                    }
                }
                if merged.len() > MAX_CONCRETE {
                    let lo = *merged.iter().min().expect("non-empty");
                    let hi = *merged.iter().max().expect("non-empty");
                    Self::Range { lo, hi, stride: 1 }
                } else {
                    merged.sort_unstable();
                    Self::Concrete(merged)
                }
            }
            (Self::Concrete(vals), Self::Range { lo, hi, stride })
            | (Self::Range { lo, hi, stride }, Self::Concrete(vals)) => {
                let min_v = vals.iter().copied().min().unwrap_or(u64::MAX);
                let max_v = vals.iter().copied().max().unwrap_or(0);
                let new_lo = (*lo).min(min_v);
                let new_hi = (*hi).max(max_v);
                Self::Range {
                    lo: new_lo,
                    hi: new_hi,
                    stride: gcd(*stride, 1),
                }
            }
            (
                Self::Range {
                    lo: lo1,
                    hi: hi1,
                    stride: s1,
                },
                Self::Range {
                    lo: lo2,
                    hi: hi2,
                    stride: s2,
                },
            ) => {
                let lo = (*lo1).min(*lo2);
                let hi = (*hi1).max(*hi2);
                // The stride must also divide the offset between the two
                // interval start points, otherwise values of the interval whose
                // `lo` is larger become misaligned to `lo` and are dropped.
                let stride = gcd(gcd(*s1, *s2), lo1.abs_diff(*lo2));
                Self::Range { lo, hi, stride: stride.max(1) }
            }
        }
    }

    /// Meet (greatest lower bound).
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, x) | (x, Self::Top) => x.clone(),
            (Self::Concrete(a), Self::Concrete(b)) => {
                let intersection: Vec<u64> = a.iter().filter(|v| b.contains(v)).copied().collect();
                if intersection.is_empty() {
                    Self::Bottom
                } else {
                    Self::Concrete(intersection)
                }
            }
            (Self::Concrete(vals), Self::Range { lo, hi, stride })
            | (Self::Range { lo, hi, stride }, Self::Concrete(vals)) => {
                let filtered: Vec<u64> = vals
                    .iter()
                    .copied()
                    .filter(|v| *v >= *lo && *v <= *hi && (*v - lo) % stride == 0)
                    .collect();
                if filtered.is_empty() {
                    Self::Bottom
                } else {
                    Self::Concrete(filtered)
                }
            }
            (
                Self::Range {
                    lo: lo1,
                    hi: hi1,
                    stride: s1,
                },
                Self::Range {
                    lo: lo2,
                    hi: hi2,
                    stride: s2,
                },
            ) => {
                let lo = (*lo1).max(*lo2);
                let hi = (*hi1).min(*hi2);
                if lo > hi {
                    return Self::Bottom;
                }
                let stride = lcm(*s1, *s2);
                // Find the first value >= lo satisfying BOTH congruences
                // (x ≡ lo1 mod s1 and x ≡ lo2 mod s2). The old code only aligned
                // to s1 and checked s2 once, which incorrectly dropped values
                // whose true common residue sits further up. Residues repeat with
                // period `stride == lcm(s1,s2)`, so scanning one period suffices.
                // Cap the scan to avoid pathological loops for huge strides; on
                // overflow fall back to a sound (coarser) enclosing range.
                const SCAN_CAP: u64 = 8192;
                if stride <= SCAN_CAP {
                    let mut start = None;
                    let mut v = lo;
                    let window_end = lo.saturating_add(stride);
                    while v <= hi && v < window_end {
                        if (v - lo1) % s1 == 0 && (v - lo2) % s2 == 0 {
                            start = Some(v);
                            break;
                        }
                        v += 1;
                    }
                    match start {
                        Some(s) => {
                            let hi2 = s + ((hi - s) / stride) * stride;
                            Self::strided(s, hi2, stride)
                        }
                        None => Self::Bottom,
                    }
                } else {
                    // Coarse but sound over-approximation of the intersection:
                    // every common value lies in [lo, hi] and is a multiple of
                    // gcd(s1,s2) away from `lo` (since gcd | s1 | (x-lo1) and
                    // gcd | s2 | (x-lo2), and lo is one of lo1/lo2).
                    Self::strided(lo, hi, gcd(*s1, *s2).max(1))
                }
            }
        }
    }

    // ── Arithmetic transfer functions ──────────────────────────────────────

    /// `self + rhs` (wrapping `u64`).
    ///
    /// # Panics
    ///
    /// Panics if a non-empty `Concrete` result vector has no min/max
    /// (impossible in practice, but required by the type system).
    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        match (self, rhs) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Concrete(a), Self::Concrete(b)) => {
                let mut result = Vec::new();
                for x in a {
                    for y in b {
                        result.push(x.wrapping_add(*y));
                    }
                }
                result.sort_unstable();
                result.dedup();
                if result.len() > MAX_CONCRETE {
                    let lo = *result.iter().min().expect("non-empty");
                    let hi = *result.iter().max().expect("non-empty");
                    Self::Range { lo, hi, stride: 1 }
                } else {
                    Self::Concrete(result)
                }
            }
            (
                Self::Range {
                    lo: lo1,
                    hi: hi1,
                    stride: s1,
                },
                Self::Range {
                    lo: lo2,
                    hi: hi2,
                    stride: s2,
                },
            ) => {
                let lo = lo1.wrapping_add(*lo2);
                let hi = hi1.wrapping_add(*hi2);
                // Wrapping overflow: an inverted range represents nothing, so
                // conservatively return Top rather than an unsound empty range.
                if hi < lo {
                    return Self::Top;
                }
                let stride = gcd(*s1, *s2);
                Self::Range { lo, hi, stride: stride.max(1) }
            }
            (Self::Concrete(vals), Self::Range { lo, hi, stride })
            | (Self::Range { lo, hi, stride }, Self::Concrete(vals)) => {
                let min_v = vals.iter().copied().min().unwrap_or(0);
                let max_v = vals.iter().copied().max().unwrap_or(0);
                // The result stride must also divide the spread among the
                // concrete addends, otherwise sums like `v_i + lo` become
                // misaligned to `lo + min_v`. Fold in gcd of `(v - min_v)`.
                // Skip zero diffs: `gcd(0, 0)` collapses to 1 in our helper,
                // which would spuriously force stride 1. A `spread` of 0 means
                // all addends are equal (no extra stride constraint).
                let spread = vals
                    .iter()
                    .filter(|&&v| v != min_v)
                    .fold(0u64, |g, &v| gcd(g, v - min_v));
                let new_lo = lo.wrapping_add(min_v);
                let new_hi = hi.wrapping_add(max_v);
                if new_hi < new_lo {
                    return Self::Top;
                }
                Self::Range {
                    lo: new_lo,
                    hi: new_hi,
                    stride: gcd(*stride, spread).max(1),
                }
            }
        }
    }

    /// `self - rhs` (wrapping `u64`).
    ///
    /// # Panics
    ///
    /// Panics if a non-empty `Concrete` result vector has no min/max
    /// (impossible in practice, but required by the type system).
    #[must_use]
    pub fn sub(&self, rhs: &Self) -> Self {
        match (self, rhs) {
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Concrete(a), Self::Concrete(b)) => {
                let mut result = Vec::new();
                for x in a {
                    for y in b {
                        result.push(x.wrapping_sub(*y));
                    }
                }
                result.sort_unstable();
                result.dedup();
                if result.len() > MAX_CONCRETE {
                    let lo = *result.iter().min().expect("non-empty");
                    let hi = *result.iter().max().expect("non-empty");
                    Self::Range { lo, hi, stride: 1 }
                } else {
                    Self::Concrete(result)
                }
            }
            (
                Self::Range {
                    lo: lo1,
                    hi: hi1,
                    stride: s1,
                },
                Self::Range {
                    lo: lo2,
                    hi: hi2,
                    stride: s2,
                },
            ) => {
                let lo = lo1.wrapping_sub(*hi2);
                let hi = hi1.wrapping_sub(*lo2);
                // Wrapping underflow (lo1 < hi2) inverts the range; return Top
                // rather than an unsound empty interval.
                if hi < lo {
                    return Self::Top;
                }
                let stride = gcd(*s1, *s2);
                Self::Range { lo, hi, stride: stride.max(1) }
            }
            _ => Self::Top,
        }
    }

    /// Bitwise AND.
    #[must_use]
    pub fn bitwise_and(&self, rhs: &Self) -> Self {
        match (self, rhs) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Concrete(a), Self::Concrete(b)) => {
                let mut result: Vec<u64> = a
                    .iter()
                    .flat_map(|x| b.iter().map(move |y| x & y))
                    .collect();
                result.sort_unstable();
                result.dedup();
                Self::Concrete(result)
            }
            _ => Self::Top,
        }
    }

    /// Bitwise OR.
    #[must_use]
    pub fn bitwise_or(&self, rhs: &Self) -> Self {
        match (self, rhs) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Concrete(a), Self::Concrete(b)) => {
                let mut result: Vec<u64> = a
                    .iter()
                    .flat_map(|x| b.iter().map(move |y| x | y))
                    .collect();
                result.sort_unstable();
                result.dedup();
                Self::Concrete(result)
            }
            _ => Self::Top,
        }
    }

    // ── Queries ────────────────────────────────────────────────────────────

    /// Returns `true` if this value set is `Bottom` (no values / unreachable).
    #[must_use]
    pub const fn is_bottom(&self) -> bool {
        matches!(self, Self::Bottom)
    }

    /// Returns `true` if this value set is `Top` (all values / unknown).
    #[must_use]
    pub const fn is_top(&self) -> bool {
        matches!(self, Self::Top)
    }

    /// Returns `true` when `self <= other` (every concrete value of `self` is
    /// also in `other`).
    #[must_use]
    pub fn leq(&self, other: &Self) -> bool {
        self.join(other) == *other
    }

    /// Returns `true` when `v` is contained in this value set.
    #[must_use]
    pub fn contains(&self, v: u64) -> bool {
        match self {
            Self::Bottom => false,
            Self::Top => true,
            Self::Concrete(vals) => vals.contains(&v),
            Self::Range { lo, hi, stride } => v >= *lo && v <= *hi && (v - lo).is_multiple_of(*stride),
        }
    }

    /// Widening operator for `ValueSet`.
    ///
    /// Widens `self` toward `other`: if `other` introduces values outside
    /// the current bounds the corresponding bound is blown to the extreme
    /// (`0` or `u64::MAX`).  After widening, concrete sets that have grown
    /// beyond `MAX_CONCRETE` are promoted to a `Range`.
    #[must_use]
    /// # Panics
    ///
    /// Panics if a non-empty `Concrete` vector has no min/max (impossible in practice).
    pub fn widen(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => x.clone(),
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            // Concrete × Concrete: union; if still small keep concrete, else widen to range.
            (Self::Concrete(a), Self::Concrete(b)) => {
                let mut merged = a.clone();
                for v in b {
                    if !merged.contains(v) {
                        merged.push(*v);
                    }
                }
                if merged.len() > MAX_CONCRETE {
                    let lo = *merged.iter().min().expect("non-empty");
                    let hi = *merged.iter().max().expect("non-empty");
                    Self::Range { lo, hi, stride: 1 }
                } else {
                    merged.sort_unstable();
                    Self::Concrete(merged)
                }
            }
            // Everything else: promote to range and apply bound widening.
            _ => {
                let (self_lo, self_hi) = match self {
                    Self::Range { lo, hi, .. } => (*lo, *hi),
                    Self::Concrete(v) => {
                        (*v.iter().min().unwrap_or(&0), *v.iter().max().unwrap_or(&0))
                    }
                    _ => unreachable!(),
                };
                let (other_lo, other_hi) = match other {
                    Self::Range { lo, hi, .. } => (*lo, *hi),
                    Self::Concrete(v) => {
                        (*v.iter().min().unwrap_or(&0), *v.iter().max().unwrap_or(&0))
                    }
                    _ => unreachable!(),
                };
                let lo = if other_lo < self_lo { 0 } else { self_lo };
                let hi = if other_hi > self_hi {
                    u64::MAX
                } else {
                    self_hi
                };
                if lo == 0 && hi == u64::MAX {
                    Self::Top
                } else {
                    Self::Range { lo, hi, stride: 1 }
                }
            }
        }
    }

    /// Enumerate concrete values up to `limit`.
    ///
    /// Returns `None` if the set cannot be finitely enumerated within `limit`.
    #[must_use]
    pub fn concretize(&self, limit: usize) -> Option<Vec<u64>> {
        match self {
            Self::Bottom => Some(vec![]),
            Self::Concrete(v) => Some(v.clone()),
            Self::Range { lo, hi, stride } => {
                let mut vals = Vec::new();
                let mut v = *lo;
                loop {
                    vals.push(v);
                    if vals.len() > limit {
                        return None;
                    }
                    if v >= *hi {
                        break;
                    }
                    v = v.saturating_add(*stride);
                    if v > *hi {
                        break;
                    }
                }
                Some(vals)
            }
            Self::Top => None,
        }
    }
}

impl fmt::Display for ValueSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bottom => write!(f, "\u{22a5}"),
            Self::Top => write!(f, "\u{22a4}"),
            Self::Concrete(v) => write!(
                f,
                "{{{}}}",
                v.iter()
                    .map(|x| format!("{x:#x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Range { lo, hi, stride } => write!(f, "[{lo:#x}, {hi:#x}]/{stride}"),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

pub(crate) fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a.max(1) } else { gcd(b, a % b) }
}

fn lcm(a: u64, b: u64) -> u64 {
    if a == 0 || b == 0 {
        1
    } else {
        (a / gcd(a, b)).saturating_mul(b)
    }
}

/// Smallest all-ones mask covering the highest set bit of `v`
/// (e.g. `0b10010 -> 0b11111`). Returns `0` for `v == 0`.
///
/// Used as a sound upper bound for bitwise OR/XOR of ranges: for any
/// `x <= a`, `y <= b`, the result `x|y` (or `x^y`) has no set bit above the
/// highest bit of `a|b`, hence `x|y <= ones_upto(a|b)`.
pub(crate) const fn ones_upto(v: u64) -> u64 {
    if v == 0 { 0 } else { u64::MAX >> v.leading_zeros() }
}

// ────────────────────────────────────────────────────────────────────────────
// VSA instruction model
// ────────────────────────────────────────────────────────────────────────────

/// A simplified instruction for VSA transfer functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VsaInstr {
    /// `dst = constant`
    Const {
        /// Destination variable name.
        dst: String,
        /// Constant value to assign.
        value: u64,
    },
    /// `dst = src`
    Copy {
        /// Destination variable name.
        dst: String,
        /// Source variable name.
        src: String,
    },
    /// `dst = lhs + rhs`
    Add {
        /// Destination variable name.
        dst: String,
        /// Left-hand operand name.
        lhs: String,
        /// Right-hand operand name.
        rhs: String,
    },
    /// `dst = lhs - rhs`
    Sub {
        /// Destination variable name.
        dst: String,
        /// Left-hand operand name.
        lhs: String,
        /// Right-hand operand name.
        rhs: String,
    },
    /// `dst = lhs & rhs`
    And {
        /// Destination variable name.
        dst: String,
        /// Left-hand operand name.
        lhs: String,
        /// Right-hand operand name.
        rhs: String,
    },
    /// `dst = lhs | rhs`
    Or {
        /// Destination variable name.
        dst: String,
        /// Left-hand operand name.
        lhs: String,
        /// Right-hand operand name.
        rhs: String,
    },
    /// `dst = load(ptr)`
    Load {
        /// Destination variable name.
        dst: String,
        /// Pointer variable name.
        ptr: String,
    },
    /// `store(ptr, val)`
    Store {
        /// Pointer variable name.
        ptr: String,
        /// Value variable name.
        val: String,
    },
    /// `dst = phi(srcs...)`
    Phi {
        /// Destination variable name.
        dst: String,
        /// Source variable names from predecessor blocks.
        srcs: Vec<String>,
    },
    /// Indirect call via `target`.
    IndirectCall {
        /// The variable holding the call target address.
        target: String,
    },
}

// ────────────────────────────────────────────────────────────────────────────
// VsaState — per-program-point abstract state
// ────────────────────────────────────────────────────────────────────────────

/// The VSA abstract state: a map from variable name to `ValueSet`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VsaState {
    /// The per-variable abstract value map.
    pub vars: HashMap<String, ValueSet>,
}

impl VsaState {
    /// Create a new, empty `VsaState` (all variables bottom).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a variable; returns `Bottom` if not present.
    #[must_use]
    pub fn get(&self, var: &str) -> ValueSet {
        self.vars.get(var).cloned().unwrap_or(ValueSet::Bottom)
    }

    /// Set the abstract value for a variable.
    pub fn set(&mut self, var: impl Into<String>, vs: ValueSet) {
        self.vars.insert(var.into(), vs);
    }

    /// Join two states (point-wise join for each variable).
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (k, v) in &other.vars {
            let existing = result.vars.entry(k.clone()).or_insert(ValueSet::Bottom);
            *existing = existing.join(v);
        }
        result
    }

    /// Returns `true` if `self <= other` (every variable in `self` is `<=` `other`).
    #[must_use]
    pub fn leq(&self, other: &Self) -> bool {
        self.vars.iter().all(|(k, v)| v.leq(&other.get(k)))
    }

    /// Point-wise widening: for each variable, widen the previous value
    /// toward the new one to ensure termination of ascending chains.
    #[must_use]
    pub fn widen(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (k, v) in &other.vars {
            let existing = result.vars.entry(k.clone()).or_insert(ValueSet::Bottom);
            *existing = existing.widen(v);
        }
        result
    }
}

// ────────────────────────────────────────────────────────────────────────────
// AddressClassification
// ────────────────────────────────────────────────────────────────────────────

/// Classification of where a pointer value points.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AddressClass {
    /// Likely a stack address (high canonical addresses on x86-64).
    Stack,
    /// Heap-allocated (returned by `malloc` / `operator new`).
    Heap,
    /// Global / static data section.
    Global,
    /// Read-only data section.
    ReadOnly,
    /// Executable (code) section.
    Code,
    /// Cannot be classified.
    Unknown,
}

/// Classifies addresses from `ValueSet`s using section range information.
pub struct AddressClassifier {
    /// `(start, end)` address range for the stack.
    pub stack_range: Option<(u64, u64)>,
    /// Known heap allocation start addresses.
    pub heap_hints: HashSet<u64>,
    /// `(start, end)` address range for global / static data.
    pub global_range: Option<(u64, u64)>,
    /// `(start, end)` address range for read-only data.
    pub ro_range: Option<(u64, u64)>,
    /// `(start, end)` address range for executable code.
    pub code_range: Option<(u64, u64)>,
}

impl AddressClassifier {
    /// Create a new `AddressClassifier` with no ranges configured.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stack_range: None,
            heap_hints: HashSet::new(),
            global_range: None,
            ro_range: None,
            code_range: None,
        }
    }

    /// Classify a single address.
    #[must_use]
    pub fn classify_addr(&self, addr: u64) -> AddressClass {
        if let Some((lo, hi)) = self.code_range
            && addr >= lo && addr < hi {
                return AddressClass::Code;
            }
        if let Some((lo, hi)) = self.stack_range
            && addr >= lo && addr < hi {
                return AddressClass::Stack;
            }
        if self.heap_hints.contains(&addr) {
            return AddressClass::Heap;
        }
        if let Some((lo, hi)) = self.ro_range
            && addr >= lo && addr < hi {
                return AddressClass::ReadOnly;
            }
        if let Some((lo, hi)) = self.global_range
            && addr >= lo && addr < hi {
                return AddressClass::Global;
            }
        AddressClass::Unknown
    }

    /// Classify all concretizable values in a `ValueSet`.
    #[must_use]
    pub fn classify(&self, vs: &ValueSet) -> HashSet<AddressClass> {
        vs.concretize(256).map_or_else(
            || { let mut s = HashSet::new(); s.insert(AddressClass::Unknown); s },
            |vals| vals.into_iter().map(|v| self.classify_addr(v)).collect(),
        )
    }
}

impl Default for AddressClassifier {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// VsaAnalyzer — transfer functions per instruction
// ────────────────────────────────────────────────────────────────────────────

/// A basic block in a VSA CFG.
#[derive(Debug, Clone)]
pub struct VsaBlock {
    /// Block index (0-based).
    pub id: usize,
    /// Ordered list of instructions in this block.
    pub instrs: Vec<VsaInstr>,
}

/// A CFG for VSA.
#[derive(Debug, Clone)]
pub struct VsaCfg {
    /// All basic blocks (indexed by id).
    pub blocks: Vec<VsaBlock>,
    /// Successor lists (indexed by block id).
    pub successors: Vec<Vec<usize>>,
    /// Predecessor lists (indexed by block id).
    pub predecessors: Vec<Vec<usize>>,
    /// Entry block id.
    pub entry: usize,
}

impl VsaCfg {
    /// Build a `VsaCfg` from blocks, a successor list, and an entry block.
    #[must_use]
    pub fn new(blocks: Vec<VsaBlock>, successors: Vec<Vec<usize>>, entry: usize) -> Self {
        let n = blocks.len();
        let mut predecessors = vec![Vec::new(); n];
        for (src, succs) in successors.iter().enumerate() {
            for &dst in succs {
                if dst < n {
                    predecessors[dst].push(src);
                }
            }
        }
        Self {
            blocks,
            successors,
            predecessors,
            entry,
        }
    }
}

/// The per-block memory model for loads/stores (simplified).
#[derive(Debug, Clone, Default)]
pub struct MemoryModel {
    /// Abstract memory cells as `(pointer_valueset, value_valueset)` pairs.
    pub cells: Vec<(ValueSet, ValueSet)>,
}

impl MemoryModel {
    /// Maximum number of abstract memory cells to prevent memory exhaustion.
    const MAX_CELLS: usize = 65_536;

    /// Perform an abstract store: strong update for singleton pointers,
    /// weak update (join) otherwise.
    pub fn store(&mut self, ptr: &ValueSet, val: ValueSet) {
        if let ValueSet::Concrete(addrs) = ptr
            && addrs.len() == 1 {
                let addr = addrs[0];
                for (k, v) in &mut self.cells {
                    if *k == ValueSet::singleton(addr) {
                        *v = val;
                        return;
                    }
                }
                // Cap cell growth to prevent memory exhaustion from attacker-supplied programs.
                if self.cells.len() < Self::MAX_CELLS {
                    self.cells.push((ValueSet::singleton(addr), val));
                } else {
                    // Fall back to a weak update over all existing cells.
                    for (_, v) in &mut self.cells {
                        *v = v.join(&val);
                    }
                }
                return;
            }
        // Weak update: join into every overlapping cell.
        for (_, v) in &mut self.cells {
            *v = v.join(&val);
        }
    }

    /// Perform an abstract load.
    #[must_use]
    pub fn load(&self, ptr: &ValueSet) -> ValueSet {
        let mut result = ValueSet::Bottom;
        for (k, v) in &self.cells {
            if !k.meet(ptr).is_bottom() {
                result = result.join(v);
            }
        }
        if result.is_bottom() {
            ValueSet::Top
        } else {
            result
        }
    }
}

/// Runs VSA over a `VsaCfg`, returning per-block `VsaState` at block entry.
pub struct VsaAnalyzer {
    /// The initial abstract state at the entry block.
    pub initial_state: VsaState,
}

impl VsaAnalyzer {
    /// Create a new `VsaAnalyzer` with the given entry-block state.
    #[must_use]
    pub const fn new(initial_state: VsaState) -> Self {
        Self { initial_state }
    }

    /// Transfer function: apply `block`'s instructions to `state`.
    #[must_use]
    pub fn transfer(block: &VsaBlock, state: &VsaState, mem: &mut MemoryModel) -> VsaState {
        let mut s = state.clone();
        for instr in &block.instrs {
            match instr {
                VsaInstr::Const { dst, value } => {
                    s.set(dst.clone(), ValueSet::singleton(*value));
                }
                VsaInstr::Copy { dst, src } => {
                    let v = s.get(src);
                    s.set(dst.clone(), v);
                }
                VsaInstr::Add { dst, lhs, rhs } => {
                    let result = s.get(lhs).add(&s.get(rhs));
                    s.set(dst.clone(), result);
                }
                VsaInstr::Sub { dst, lhs, rhs } => {
                    let result = s.get(lhs).sub(&s.get(rhs));
                    s.set(dst.clone(), result);
                }
                VsaInstr::And { dst, lhs, rhs } => {
                    let result = s.get(lhs).bitwise_and(&s.get(rhs));
                    s.set(dst.clone(), result);
                }
                VsaInstr::Or { dst, lhs, rhs } => {
                    let result = s.get(lhs).bitwise_or(&s.get(rhs));
                    s.set(dst.clone(), result);
                }
                VsaInstr::Load { dst, ptr } => {
                    let ptr_vs = s.get(ptr);
                    let val = mem.load(&ptr_vs);
                    s.set(dst.clone(), val);
                }
                VsaInstr::Store { ptr, val } => {
                    let ptr_vs = s.get(ptr);
                    let val_vs = s.get(val);
                    mem.store(&ptr_vs, val_vs);
                }
                VsaInstr::Phi { dst, srcs } => {
                    let joined = srcs
                        .iter()
                        .map(|src| s.get(src))
                        .fold(ValueSet::Bottom, |acc, v| acc.join(&v));
                    s.set(dst.clone(), joined);
                }
                VsaInstr::IndirectCall { .. } => {
                    // No state modification for calls in this simplified model.
                }
            }
        }
        s
    }

    /// Run the worklist-based VSA fixpoint computation.
    ///
    /// Returns the per-block entry `VsaState` slice on success.
    ///
    /// # Errors
    ///
    /// Returns [`VsaError::EmptyProgram`] if `cfg` has no blocks.
    /// Returns [`VsaError::NoConvergence`] if the analysis exceeds the
    /// iteration limit (100 000 steps).
    pub fn run(&self, cfg: &VsaCfg) -> Result<Vec<VsaState>, VsaError> {
        // Cap block count to prevent memory exhaustion from attacker-supplied CFGs.
        const MAX_BLOCKS: usize = 1_000_000;
        const WIDEN_THRESHOLD: usize = 3;
        if cfg.blocks.is_empty() {
            return Err(VsaError::EmptyProgram);
        }
        let n = cfg.blocks.len();
        if n > MAX_BLOCKS {
            return Err(VsaError::NoConvergence);
        }
        let mut states: Vec<VsaState> = vec![VsaState::new(); n];
        states[cfg.entry] = self.initial_state.clone();

        let mut mem = MemoryModel::default();
        let mut worklist: VecDeque<usize> = (0..n).collect();
        let mut in_worklist = vec![true; n];
        let mut visit_count = vec![0usize; n];

        let mut iterations = 0usize;
        while let Some(bid) = worklist.pop_front() {
            in_worklist[bid] = false;
            iterations += 1;
            if iterations > 100_000 {
                return Err(VsaError::NoConvergence);
            }

            let new_out = Self::transfer(&cfg.blocks[bid], &states[bid], &mut mem);

            for &succ in &cfg.successors[bid] {
                if succ >= n {
                    continue;
                }
                visit_count[succ] += 1;
                let joined = states[succ].join(&new_out);
                // Apply widening at loop headers (after enough visits)
                // to ensure termination on ascending chains.
                let next_state = if visit_count[succ] >= WIDEN_THRESHOLD {
                    states[succ].widen(&joined)
                } else {
                    joined
                };
                if next_state != states[succ] {
                    states[succ] = next_state;
                    if !in_worklist[succ] {
                        in_worklist[succ] = true;
                        worklist.push_back(succ);
                    }
                }
            }
        }

        Ok(states)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// IndirectCallResolver
// ────────────────────────────────────────────────────────────────────────────

/// Resolves indirect call targets from VSA results.
pub struct IndirectCallResolver<'a> {
    /// Per-block entry states produced by `VsaAnalyzer::run`.
    pub states: &'a [VsaState],
    /// Address classifier used to filter code-section targets.
    pub classifier: &'a AddressClassifier,
}

/// The result of resolving an indirect call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndirectCallResolution {
    /// The block in which the indirect call appears.
    pub block_id: usize,
    /// The variable that holds the call target.
    pub target_var: String,
    /// The set of concrete code addresses this call may dispatch to.
    pub resolved_targets: Vec<u64>,
    /// `true` if the analysis could not narrow down to concrete targets.
    pub is_imprecise: bool,
}

impl<'a> IndirectCallResolver<'a> {
    /// Create a new `IndirectCallResolver`.
    #[must_use]
    pub const fn new(states: &'a [VsaState], classifier: &'a AddressClassifier) -> Self {
        Self { states, classifier }
    }

    /// Resolve all indirect calls in `cfg`.
    #[must_use]
    pub fn resolve(&self, cfg: &VsaCfg) -> Vec<IndirectCallResolution> {
        let mut results = Vec::new();

        for block in &cfg.blocks {
            for instr in &block.instrs {
                if let VsaInstr::IndirectCall { target } = instr {
                    let vs = self.states[block.id].get(target);
                    // When the classifier has no code_range configured every
                    // address classifies as Unknown.  In that case accept both
                    // Code and Unknown so that callers without section-range
                    // information still receive concretised targets (matching
                    // the documented behaviour: "all concretisable addresses
                    // are returned regardless of section membership").
                    let no_code_range = self.classifier.code_range.is_none();
                    let (resolved_targets, is_imprecise) = vs.concretize(512).map_or_else(
                        || (vec![], true),
                        |vals| {
                            let code_vals: Vec<u64> = vals
                                .into_iter()
                                .filter(|&a| {
                                    let cls = self.classifier.classify_addr(a);
                                    cls == AddressClass::Code
                                        || (no_code_range && cls == AddressClass::Unknown)
                                })
                                .collect();
                            let imprecise = code_vals.is_empty();
                            (code_vals, imprecise)
                        },
                    );

                    results.push(IndirectCallResolution {
                        block_id: block.id,
                        target_var: target.clone(),
                        resolved_targets,
                        is_imprecise,
                    });
                }
            }
        }

        results
    }
}

// ────────────────────────────────────────────────────────────────────────────
// StridedInterval — named, self-contained strided-interval type
// ────────────────────────────────────────────────────────────────────────────

/// A strided interval `[lo, hi] / stride` representing every value
/// `lo + k * stride` for non-negative integer `k` such that the value stays
/// `<= hi`.
///
/// Invariants (maintained by all constructors):
/// * `stride >= 1`
/// * `lo <= hi`
/// * `(hi - lo) % stride == 0`  (hi is reachable from lo)
///
/// `Bottom` is represented by the sentinel `lo = 1, hi = 0` (lo > hi).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StridedInterval {
    /// Lower bound.
    pub lo: u64,
    /// Upper bound.
    pub hi: u64,
    /// Step (must be >= 1; stride = `u64::MAX` signals Top).
    pub stride: u64,
}

impl StridedInterval {
    // ── Sentinel values ────────────────────────────────────────────────────

    /// The bottom element (no values / unreachable).
    pub const BOTTOM: Self = Self {
        lo: 1,
        hi: 0,
        stride: 1,
    };

    /// The top element (all u64 values).
    pub const TOP: Self = Self {
        lo: 0,
        hi: u64::MAX,
        stride: 1,
    };

    // ── Constructors ───────────────────────────────────────────────────────

    /// Construct `[lo, hi] / stride`.  Normalises the stride and clamps hi.
    #[must_use]
    pub fn new(lo: u64, hi: u64, stride: u64) -> Self {
        if lo > hi {
            return Self::BOTTOM;
        }
        let stride = stride.max(1);
        // Snap hi downward so it is actually reachable from lo.
        let span = hi - lo;
        let hi = lo + (span / stride) * stride;
        Self { lo, hi, stride }
    }

    /// Singleton interval `{v}`.
    #[must_use]
    pub const fn singleton(v: u64) -> Self {
        Self {
            lo: v,
            hi: v,
            stride: 1,
        }
    }

    /// Unit-stride interval `[lo, hi]`.
    #[must_use]
    pub fn interval(lo: u64, hi: u64) -> Self {
        Self::new(lo, hi, 1)
    }

    // ── Predicates ─────────────────────────────────────────────────────────

    /// Returns `true` when this interval is bottom (no values).
    #[must_use]
    pub const fn is_bottom(&self) -> bool {
        self.lo > self.hi
    }

    /// Returns `true` when this interval covers all u64 values.
    #[must_use]
    pub const fn is_top(&self) -> bool {
        self.lo == 0 && self.hi == u64::MAX && self.stride == 1
    }

    /// Returns `true` when this interval contains exactly one value.
    #[must_use]
    pub const fn is_singleton(&self) -> bool {
        !self.is_bottom() && self.lo == self.hi
    }

    /// Returns `true` when `v` is a member of this interval.
    #[must_use]
    pub const fn contains(&self, v: u64) -> bool {
        if self.is_bottom() {
            return false;
        }
        v >= self.lo && v <= self.hi && (v - self.lo).is_multiple_of(self.stride)
    }

    // ── Lattice operations ─────────────────────────────────────────────────

    /// Least upper bound (join / widen-free merge).
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        if self.is_bottom() {
            return *other;
        }
        if other.is_bottom() {
            return *self;
        }
        let lo = self.lo.min(other.lo);
        let hi = self.hi.max(other.hi);
        let stride = gcd(
            gcd(self.stride, other.stride),
            other.lo.abs_diff(self.lo),
        );
        Self::new(lo, hi, stride.max(1))
    }

    /// Greatest lower bound (meet / intersection).
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::BOTTOM;
        }
        let lo = self.lo.max(other.lo);
        let hi = self.hi.min(other.hi);
        if lo > hi {
            return Self::BOTTOM;
        }
        let stride = lcm(self.stride, other.stride);
        // Find the first value >= lo that satisfies both congruences.
        // For simplicity: scan from lo with the LCM stride.
        let mut v = lo;
        loop {
            if self.contains(v) && other.contains(v) {
                // Found a starting point.
                // Upper endpoint: the largest value <= hi in both intervals.
                let span = hi - v;
                let hi2 = v + (span / stride) * stride;
                if hi2 < v {
                    return Self::BOTTOM;
                }
                return Self::new(v, hi2, stride);
            }
            if v == hi {
                break;
            }
            v = v.saturating_add(1);
            // Avoid infinite loops for large ranges.
            if v > lo.saturating_add(stride.saturating_mul(2).saturating_add(1024)) {
                break;
            }
        }
        Self::BOTTOM
    }

    /// Widening operator: used to accelerate fixpoint convergence.
    ///
    /// If `self` (the previous value) is not yet >= `new` (the updated value),
    /// the widened result extends the bounds toward the extremes and doubles
    /// the stride, preventing infinite ascending chains.
    #[must_use]
    pub fn widen(&self, new: &Self) -> Self {
        if self.is_bottom() {
            return *new;
        }
        if new.is_bottom() {
            return *self;
        }
        let lo = if new.lo < self.lo { 0 } else { self.lo };
        let hi = if new.hi > self.hi { u64::MAX } else { self.hi };
        if lo == 0 && hi == u64::MAX {
            return Self::TOP;
        }
        // Stride must remain aligned to the (possibly lowered) `lo` for BOTH
        // operands' members. Doubling the stride was unsound: it dropped values
        // that were reachable at the original stride. Instead take the gcd of
        // both strides and the offsets of each operand's `lo` from the final
        // `lo` — the same construction as `join`, which keeps every member.
        // Termination still holds: bounds only move toward the extremes and the
        // stride only decreases (gcd), both monotone in a finite lattice.
        let stride = gcd(
            gcd(self.stride, new.stride),
            gcd(self.lo - lo, new.lo - lo),
        )
        .max(1);
        Self::new(lo, hi, stride)
    }

    // ── Arithmetic transfer functions ──────────────────────────────────────

    /// Addition: `[a,b]/s + [c,d]/t = [a+c, b+d] / gcd(s,t)` (wrapping).
    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        if self.is_bottom() || rhs.is_bottom() {
            return Self::BOTTOM;
        }
        if self.is_top() || rhs.is_top() {
            return Self::TOP;
        }
        let lo = self.lo.wrapping_add(rhs.lo);
        let hi = self.hi.wrapping_add(rhs.hi);
        // Wrapping overflow: if the sum range wraps around, the result covers all u64.
        if hi < lo {
            return Self::TOP;
        }
        let stride = gcd(self.stride, rhs.stride).max(1);
        Self::new(lo, hi, stride)
    }

    /// Subtraction: `[a,b]/s - [c,d]/t = [a-d, b-c] / gcd(s,t)` (wrapping).
    #[must_use]
    pub fn sub(&self, rhs: &Self) -> Self {
        if self.is_bottom() || rhs.is_bottom() {
            return Self::BOTTOM;
        }
        let lo = self.lo.wrapping_sub(rhs.hi);
        let hi = self.hi.wrapping_sub(rhs.lo);
        if hi < lo {
            return Self::TOP;
        }
        let stride = gcd(self.stride, rhs.stride).max(1);
        Self::new(lo, hi, stride)
    }

    /// Bitwise AND: conservatively returns `[0, min(hi_a, hi_b)] / 1`.
    #[must_use]
    pub fn bitwise_and(&self, rhs: &Self) -> Self {
        if self.is_bottom() || rhs.is_bottom() {
            return Self::BOTTOM;
        }
        if self.is_singleton() && rhs.is_singleton() {
            return Self::singleton(self.lo & rhs.lo);
        }
        // Conservative: result is in [0, min(hi_a, hi_b)].
        let hi = self.hi.min(rhs.hi);
        Self::new(0, hi, 1)
    }

    /// Bitwise OR: conservatively returns `[max(lo_a, lo_b), lo_a | hi_b OR hi_a | lo_b]`.
    #[must_use]
    pub fn bitwise_or(&self, rhs: &Self) -> Self {
        if self.is_bottom() || rhs.is_bottom() {
            return Self::BOTTOM;
        }
        if self.is_singleton() && rhs.is_singleton() {
            return Self::singleton(self.lo | rhs.lo);
        }
        // Conservative upper bound. `hi_a | hi_b` is NOT a valid bound: e.g.
        // hi_a = 0x10 admits x = 0x0F, so x|y can set low bits absent from
        // hi_a|hi_b. The sound bound saturates every bit below the top set bit.
        let lo = self.lo.max(rhs.lo);
        let hi = ones_upto(self.hi | rhs.hi);
        Self::new(lo, hi, 1)
    }

    /// Enumerate up to `limit` concrete values. Returns `None` when the set is
    /// too large.
    #[must_use]
    pub fn concretize(&self, limit: usize) -> Option<Vec<u64>> {
        if self.is_bottom() {
            return Some(vec![]);
        }
        if self.is_top() {
            return None;
        }
        // `stride` is normally guaranteed >= 1 by the `new()` constructor, but
        // `StridedInterval` has public fields and derives `Deserialize`, so a
        // value built directly or read from untrusted/malformed data can carry
        // `stride == 0`. Clamp defensively to avoid a division-by-zero panic
        // and an infinite (`saturating_add(0)`) loop below.
        let stride = self.stride.max(1);
        let count_u64 = (self.hi - self.lo) / stride + 1;
        let count = usize::try_from(count_u64).unwrap_or(usize::MAX);
        if count > limit {
            return None;
        }
        let mut v = self.lo;
        let mut out = Vec::with_capacity(count);
        loop {
            out.push(v);
            if v == self.hi {
                break;
            }
            v = v.saturating_add(stride);
            if v > self.hi {
                break;
            }
        }
        Some(out)
    }
}

impl fmt::Display for StridedInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_bottom() {
            write!(f, "\u{22a5}")
        } else if self.is_top() {
            write!(f, "\u{22a4}")
        } else if self.is_singleton() {
            write!(f, "{{{:#x}}}", self.lo)
        } else {
            write!(f, "[{:#x}, {:#x}]/{}", self.lo, self.hi, self.stride)
        }
    }
}

// ── Null / bounds helpers ──────────────────────────────────────────────────

/// Returns `true` when `vs` definitely contains only the value 0 (null).
#[must_use]
pub const fn is_definitely_null(vs: &StridedInterval) -> bool {
    vs.is_singleton() && vs.lo == 0
}

/// Returns `true` when `vs` may contain a value outside `[bounds.0, bounds.1)`.
///
/// If `vs` is `Top` or its range overlaps the exterior of `bounds`, this
/// returns `true`.
#[must_use]
pub const fn may_be_out_of_bounds(vs: &StridedInterval, bounds: (u64, u64)) -> bool {
    let (base, limit) = bounds;
    if vs.is_bottom() {
        return false;
    }
    if vs.is_top() {
        return true;
    }
    // Out of bounds if any part of the interval is outside [base, limit).
    vs.lo < base || vs.hi >= limit
}

// ────────────────────────────────────────────────────────────────────────────
// MemoryAbstraction — abstract memory map keyed by address intervals
// ────────────────────────────────────────────────────────────────────────────

/// An abstract memory map from address ranges to abstract values.
///
/// Internally backed by a sorted list of `(address_key, value)` entries.
/// The address key is a `StridedInterval` describing which concrete addresses
/// that cell may cover.  Stores perform a strong update when the key is a
/// singleton, or a weak update (join) otherwise.
#[derive(Debug, Clone, Default)]
pub struct MemoryAbstraction {
    /// Sorted (by `lo`) list of `(address_interval, abstract_value)` cells.
    pub cells: Vec<(StridedInterval, StridedInterval)>,
}

impl MemoryAbstraction {
    /// Create an empty `MemoryAbstraction`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Maximum number of cells to prevent memory exhaustion from attacker-supplied programs.
    const MAX_CELLS: usize = 65_536;

    /// Store `val` at `addr`.
    ///
    /// * Singleton `addr` → strong update of the matching cell (or insertion).
    /// * Range `addr` → weak update (join) of every potentially-aliased cell.
    pub fn store(&mut self, addr: StridedInterval, val: StridedInterval) {
        if addr.is_bottom() {
            return;
        }
        if addr.is_singleton() {
            // Strong update.
            for (k, v) in &mut self.cells {
                if *k == addr {
                    *v = val;
                    return;
                }
            }
            // Cap cell count to prevent memory exhaustion.
            if self.cells.len() < Self::MAX_CELLS {
                self.cells.push((addr, val));
            } else {
                // Conservatively join into all existing cells.
                for (_, v) in &mut self.cells {
                    *v = v.join(&val);
                }
            }
            return;
        }
        // Weak update: the store MAY hit any address in `addr`, so weaken every
        // aliasing cell by joining `val` in.
        //
        // Joining into aliasing cells ALONE is unsound: when `addr` only
        // *partially* overlaps the existing cells (e.g. cell [5,7] and store
        // [7,11]), the shared point makes `matched` true, yet addresses in
        // `addr` outside every aliasing cell (8,9,10,11) are left with no cell
        // covering them — a later load there would miss `val` and return
        // Bottom. So we additionally guarantee a cell keyed *exactly* by `addr`
        // exists, covering the whole stored range. Keying on the exact range
        // (rather than always pushing) keeps the cell set deduplicated by key,
        // so `join`/`store` stay idempotent and the dataflow fixpoint still
        // terminates.
        let mut covered = false;
        for (k, v) in &mut self.cells {
            if !k.meet(&addr).is_bottom() {
                *v = v.join(&val);
            }
            if *k == addr {
                *v = v.join(&val);
                covered = true;
            }
        }
        if !covered {
            if self.cells.len() < Self::MAX_CELLS {
                self.cells.push((addr, val));
            } else {
                // At capacity: fold the value into every cell so it is never
                // dropped (conservative, still sound).
                for (_, v) in &mut self.cells {
                    *v = v.join(&val);
                }
            }
        }
    }

    /// Load the abstract value stored at `addr`.
    ///
    /// Returns `Bottom` when no cell aliases `addr`, or the join of all
    /// aliased cells otherwise.
    #[must_use]
    pub fn load(&self, addr: &StridedInterval) -> StridedInterval {
        if addr.is_bottom() {
            return StridedInterval::BOTTOM;
        }
        let mut result = StridedInterval::BOTTOM;
        for (k, v) in &self.cells {
            if !k.meet(addr).is_bottom() {
                result = result.join(v);
            }
        }
        result
    }

    /// Join two memory abstractions (for merging states at join points).
    ///
    /// This must *merge* the values of cells shared by both operands. The
    /// previous implementation delegated to [`store`], whose singleton path is
    /// a **strong update** (overwrite): joining `{@8:[0,10]}` with `{@8:[0,5]}`
    /// overwrote the left cell, yielding `{@8:[0,5]}` and dropping value `10`.
    /// That makes `join` right-biased and unsound (a join point could lose
    /// values flowing in from one predecessor). We instead merge cells sharing
    /// an identical key with the value-lattice `join`, and carry over cells that
    /// exist in only one operand.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        let mut out = self.clone();
        for (addr, val) in &other.cells {
            if let Some((_, v)) = out.cells.iter_mut().find(|(k, _)| k == addr) {
                *v = v.join(val);
            } else if out.cells.len() < Self::MAX_CELLS {
                out.cells.push((*addr, *val));
            } else {
                // At capacity: fold into every cell so no value is dropped.
                for (_, v) in &mut out.cells {
                    *v = v.join(val);
                }
            }
        }
        out
    }

    /// Returns `true` when `self` is a fixpoint with respect to `other`
    /// (every cell in `other` is subsumed by `self`, i.e. `self ⊒ other`),
    /// matching the `leq`-means-"self subsumes" convention used by
    /// `RegisterState::leq` and `VsaStateV2::leq` elsewhere in this crate.
    ///
    /// The previous implementation compared only cell *counts*
    /// (`self.join(other).cells.len() == self.cells.len()`), which is neither
    /// necessary nor sufficient: two abstractions with identical keys but
    /// differing values (e.g. `[0,10]` in `self` vs `[0,5]` in `other` at the
    /// same address) have the same cell count regardless of whether `self`
    /// actually subsumes `other`. A consumer using that predicate to detect a
    /// dataflow fixpoint could stop early on a state whose values are still
    /// ascending, reporting an under-approximation (unsound). We now check the
    /// values directly: for every cell in `other`, the value `self` yields at
    /// that address must subsume `other`'s value.
    #[must_use]
    pub fn leq(&self, other: &Self) -> bool {
        other.cells.iter().all(|(addr, val)| {
            let mine = self.load(addr);
            mine.join(val) == mine
        })
    }

    /// Total number of abstract cells stored.
    #[must_use]
    pub const fn cell_count(&self) -> usize {
        self.cells.len()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// VsaEngine — iterative dataflow engine with widening
// ────────────────────────────────────────────────────────────────────────────

/// Per-register abstract state used by `VsaEngine`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterState {
    /// Map from register name to strided interval.
    pub regs: HashMap<String, StridedInterval>,
}

impl RegisterState {
    /// Get the abstract value for `reg` (returns `Bottom` if unknown).
    #[must_use]
    pub fn get(&self, reg: &str) -> StridedInterval {
        self.regs
            .get(reg)
            .copied()
            .unwrap_or(StridedInterval::BOTTOM)
    }

    /// Set the abstract value for `reg`.
    pub fn set(&mut self, reg: impl Into<String>, val: StridedInterval) {
        self.regs.insert(reg.into(), val);
    }

    /// Point-wise join of two register states.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        let mut out = self.clone();
        for (k, v) in &other.regs {
            let e = out.regs.entry(k.clone()).or_insert(StridedInterval::BOTTOM);
            *e = e.join(v);
        }
        out
    }

    /// Point-wise widening.
    #[must_use]
    pub fn widen(&self, new: &Self) -> Self {
        let mut out = self.clone();
        for (k, v) in &new.regs {
            let e = out.regs.entry(k.clone()).or_insert(StridedInterval::BOTTOM);
            *e = e.widen(v);
        }
        out
    }

    /// Returns `true` when `self` subsumes `new` (fixpoint reached).
    #[must_use]
    pub fn leq(&self, new: &Self) -> bool {
        new.regs.iter().all(|(k, v)| {
            let s = self.get(k);
            // s >= v means join(s,v) == s
            s.join(v) == s
        })
    }
}

/// The per-location result of the VSA engine.
#[derive(Debug, Clone, Default)]
pub struct ValueSetResult {
    /// Per-block entry register states.
    pub register_states: Vec<RegisterState>,
    /// The final memory abstraction at function exit (approximated).
    pub memory: MemoryAbstraction,
    /// Number of iterations until convergence.
    pub iterations: usize,
    /// Whether the analysis converged within the budget.
    pub converged: bool,
}

impl ValueSetResult {
    /// Get the abstract value of `reg` at block entry `block_id`.
    #[must_use]
    pub fn reg_at(&self, block_id: usize, reg: &str) -> Option<StridedInterval> {
        self.register_states.get(block_id).map(|s| s.get(reg))
    }

    /// Returns `true` when `reg` at `block_id` is definitely null.
    #[must_use]
    pub fn is_null_at(&self, block_id: usize, reg: &str) -> bool {
        self.reg_at(block_id, reg)
            .is_some_and(|v| is_definitely_null(&v))
    }

    /// Returns `true` when `reg` at `block_id` may be outside `bounds`.
    #[must_use]
    pub fn may_oob_at(&self, block_id: usize, reg: &str, bounds: (u64, u64)) -> bool {
        self.reg_at(block_id, reg)
            .is_some_and(|v| may_be_out_of_bounds(&v, bounds))
    }
}

/// A simplified VSA instruction operating on named registers and memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VsaEngineInstr {
    /// `dst = constant`
    Const { dst: String, value: u64 },
    /// `dst = src`
    Move { dst: String, src: String },
    /// `dst = lhs + rhs`
    Add {
        dst: String,
        lhs: String,
        rhs: String,
    },
    /// `dst = lhs - rhs`
    Sub {
        dst: String,
        lhs: String,
        rhs: String,
    },
    /// `dst = lhs & rhs`
    And {
        dst: String,
        lhs: String,
        rhs: String,
    },
    /// `dst = lhs | rhs`
    Or {
        dst: String,
        lhs: String,
        rhs: String,
    },
    /// `dst = lhs + constant`
    AddConst { dst: String, src: String, imm: u64 },
    /// `dst = mem[ptr]`
    Load { dst: String, ptr: String },
    /// `mem[ptr] = src`
    Store { ptr: String, src: String },
    /// `dst = phi(srcs...)`
    Phi { dst: String, srcs: Vec<String> },
    /// Indirect call through `target`.
    IndirectCall { target: String },
    /// Any instruction not modelled (does nothing to state).
    Nop,
}

/// A basic block for the `VsaEngine`.
#[derive(Debug, Clone)]
pub struct VsaEngineBlock {
    /// Block index.
    pub id: usize,
    /// Ordered instructions.
    pub instrs: Vec<VsaEngineInstr>,
}

/// A CFG for `VsaEngine`.
#[derive(Debug, Clone)]
pub struct VsaEngineCfg {
    /// All blocks, indexed by id.
    pub blocks: Vec<VsaEngineBlock>,
    /// Successor edges.
    pub succs: Vec<Vec<usize>>,
    /// Predecessor edges.
    pub preds: Vec<Vec<usize>>,
    /// Entry block.
    pub entry: usize,
}

impl VsaEngineCfg {
    /// Construct a `VsaEngineCfg` from blocks, successors, and entry.
    #[must_use]
    pub fn new(blocks: Vec<VsaEngineBlock>, succs: Vec<Vec<usize>>, entry: usize) -> Self {
        let n = blocks.len();
        let mut preds = vec![Vec::new(); n];
        for (src, ss) in succs.iter().enumerate() {
            for &dst in ss {
                if dst < n {
                    preds[dst].push(src);
                }
            }
        }
        Self {
            blocks,
            succs,
            preds,
            entry,
        }
    }
}

/// Iterative dataflow engine for Value-Set Analysis with widening.
///
/// Runs a worklist algorithm over a `VsaEngineCfg`, applying transfer
/// functions per instruction and widening after `WIDEN_THRESHOLD` iterations
/// at each join point to guarantee termination.
pub struct VsaEngine {
    /// Initial register state injected at the entry block.
    pub entry_state: RegisterState,
    /// After how many passes to start widening at a block.
    pub widen_threshold: usize,
    /// Maximum total iterations before giving up.
    pub iteration_budget: usize,
}

impl VsaEngine {
    /// Create a `VsaEngine` with default thresholds.
    #[must_use]
    pub const fn new(entry_state: RegisterState) -> Self {
        Self {
            entry_state,
            widen_threshold: 3,
            iteration_budget: 50_000,
        }
    }

    /// Apply one block's instructions to `state`, updating `mem` in place.
    #[must_use]
    pub fn transfer(
        block: &VsaEngineBlock,
        state: &RegisterState,
        mem: &mut MemoryAbstraction,
    ) -> RegisterState {
        let mut s = state.clone();
        for instr in &block.instrs {
            match instr {
                VsaEngineInstr::Const { dst, value } => {
                    s.set(dst.clone(), StridedInterval::singleton(*value));
                }
                VsaEngineInstr::Move { dst, src } => {
                    let v = s.get(src);
                    s.set(dst.clone(), v);
                }
                VsaEngineInstr::Add { dst, lhs, rhs } => {
                    let v = s.get(lhs).add(&s.get(rhs));
                    s.set(dst.clone(), v);
                }
                VsaEngineInstr::Sub { dst, lhs, rhs } => {
                    let v = s.get(lhs).sub(&s.get(rhs));
                    s.set(dst.clone(), v);
                }
                VsaEngineInstr::And { dst, lhs, rhs } => {
                    let v = s.get(lhs).bitwise_and(&s.get(rhs));
                    s.set(dst.clone(), v);
                }
                VsaEngineInstr::Or { dst, lhs, rhs } => {
                    let v = s.get(lhs).bitwise_or(&s.get(rhs));
                    s.set(dst.clone(), v);
                }
                VsaEngineInstr::AddConst { dst, src, imm } => {
                    let v = s.get(src).add(&StridedInterval::singleton(*imm));
                    s.set(dst.clone(), v);
                }
                VsaEngineInstr::Load { dst, ptr } => {
                    let ptr_v = s.get(ptr);
                    let val = mem.load(&ptr_v);
                    // If nothing is stored there, assume Top (unknown).
                    let val = if val.is_bottom() {
                        StridedInterval::TOP
                    } else {
                        val
                    };
                    s.set(dst.clone(), val);
                }
                VsaEngineInstr::Store { ptr, src } => {
                    let ptr_v = s.get(ptr);
                    let src_v = s.get(src);
                    mem.store(ptr_v, src_v);
                }
                VsaEngineInstr::Phi { dst, srcs } => {
                    let joined = srcs
                        .iter()
                        .map(|r| s.get(r))
                        .fold(StridedInterval::BOTTOM, |acc, v| acc.join(&v));
                    s.set(dst.clone(), joined);
                }
                VsaEngineInstr::IndirectCall { .. } | VsaEngineInstr::Nop => {}
            }
        }
        s
    }

    /// Run the VSA fixpoint over `cfg`.
    ///
    /// Returns a `ValueSetResult` on success, or a `VsaError` if the analysis
    /// fails to converge within the iteration budget.
    ///
    /// # Errors
    ///
    /// * `VsaError::EmptyProgram` — `cfg` has no blocks.
    /// * `VsaError::NoConvergence` — iteration budget exhausted.
    pub fn analyze_function(&self, cfg: &VsaEngineCfg) -> Result<ValueSetResult, VsaError> {
        if cfg.blocks.is_empty() {
            return Err(VsaError::EmptyProgram);
        }
        let n = cfg.blocks.len();
        let mut states: Vec<RegisterState> = vec![RegisterState::default(); n];
        states[cfg.entry] = self.entry_state.clone();

        // Track how many times each block has been visited (for widening).
        let mut visit_count = vec![0usize; n];

        let mut mem = MemoryAbstraction::new();
        let mut worklist: VecDeque<usize> = VecDeque::new();
        let mut in_wl = vec![false; n];
        worklist.push_back(cfg.entry);
        in_wl[cfg.entry] = true;

        let mut total_iters = 0usize;
        let mut converged = true;

        while let Some(bid) = worklist.pop_front() {
            in_wl[bid] = false;
            total_iters += 1;
            if total_iters > self.iteration_budget {
                converged = false;
                break;
            }

            visit_count[bid] += 1;
            let out = Self::transfer(&cfg.blocks[bid], &states[bid], &mut mem);

            for &succ in &cfg.succs[bid] {
                if succ >= n {
                    continue;
                }
                let joined = states[succ].join(&out);
                // Apply widening once we have visited this successor enough times.
                let new_state = if visit_count[succ] >= self.widen_threshold {
                    states[succ].widen(&joined)
                } else {
                    joined
                };

                if !states[succ].leq(&new_state) {
                    states[succ] = new_state;
                    if !in_wl[succ] {
                        in_wl[succ] = true;
                        worklist.push_back(succ);
                    }
                }
            }
        }

        Ok(ValueSetResult {
            register_states: states,
            memory: mem,
            iterations: total_iters,
            converged,
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// VsaAnalysisPass — AnalysisPass implementation
// ────────────────────────────────────────────────────────────────────────────

/// An [`rustre_analysis::AnalysisPass`] that runs Value-Set Analysis over all
/// executable segments of the binary.
///
/// For each executable segment the pass builds a minimal single-block
/// [`VsaEngineCfg`] and drives the [`VsaEngine`] over it, accumulating the
/// number of blocks that converged.
#[derive(Debug, Default)]
pub struct VsaAnalysisPass;

impl VsaAnalysisPass {
    /// Create a new `VsaAnalysisPass`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl rustre_analysis::AnalysisPass for VsaAnalysisPass {
    fn name(&self) -> &'static str {
        "vsa_analysis"
    }

    fn kind(&self) -> rustre_analysis::AnalysisKind {
        rustre_analysis::AnalysisKind::VsaAnalysis
    }

    fn description(&self) -> &'static str {
        "Value-Set Analysis: over-approximates concrete values held by \
         variables at each program point using strided-interval abstract domains"
    }

    async fn run(
        &self,
        view: &rustre_core::binary_view::BinaryView,
        _config: &rustre_analysis::AnalysisConfig,
    ) -> Result<rustre_analysis::AnalysisResult, rustre_analysis::AnalysisError> {
        use std::time::Instant;
        let start = Instant::now();

        let exec_segs: Vec<_> = {
            let mem_guard = view.mem.read();
            mem_guard.segments.iter()
                .filter(|s| s.permissions.contains(rustre_core::permissions::Permissions::EXECUTE))
                .cloned()
                .collect()
        };
        let mut functions_found = 0usize;

        for _seg in &exec_segs {
            // Build a trivial single-block CFG representing this segment so the
            // engine has something concrete to iterate over.
            let block = VsaEngineBlock {
                id: 0,
                instrs: vec![],
            };
            let cfg = VsaEngineCfg::new(vec![block], vec![vec![]], 0);
            let engine = VsaEngine::new(RegisterState::default());

            if let Ok(_result) = engine.analyze_function(&cfg) {
                functions_found += 1;
            }
        }

        Ok(rustre_analysis::AnalysisResult {
            kind: rustre_analysis::AnalysisKind::VsaAnalysis,
            functions_found,
            data_refs_found: 0,
            strings_found: 0,
            duration_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            warnings: Vec::new(),
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// VsaResult — per-address, per-register query interface
// ────────────────────────────────────────────────────────────────────────────

/// VSA results keyed by program address.
///
/// Wraps a `ValueSetResult` (which is block-indexed) and provides an
/// address-indexed query API.  The address↔block mapping is built once at
/// construction and queried in O(1) thereafter.
#[derive(Debug, Clone)]
pub struct VsaResult {
    /// The underlying block-indexed result from `VsaEngine`.
    pub inner: ValueSetResult,
    /// Map from program address to the block whose *entry* covers that address.
    pub addr_to_block: HashMap<u64, usize>,
    /// Wideness threshold: when a register's interval spans more than this many
    /// values, the concrete fallback evaluator is used instead of the abstract result.
    pub concrete_fallback_limit: usize,
}

impl VsaResult {
    /// Create a `VsaResult` wrapping `inner`.  The `addr_to_block` map must
    /// map each program address of interest to the block-id whose entry state
    /// describes the values at that address.
    #[must_use]
    pub const fn new(inner: ValueSetResult, addr_to_block: HashMap<u64, usize>) -> Self {
        Self {
            inner,
            addr_to_block,
            concrete_fallback_limit: 1024,
        }
    }

    /// Serialize the address-to-block map to a JSON string for diagnostics or
    /// inter-process communication.
    ///
    /// # Errors
    ///
    /// Returns a `serde_json::Error` if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.addr_to_block)
    }

    /// Look up the abstract value of `reg` at program address `addr`.
    ///
    /// Returns `ValueSet::Top` when the address is unknown or the block has no
    /// state for `reg`.
    #[must_use]
    pub fn possible_values(&self, addr: u64, reg: &str) -> ValueSet {
        let Some(&block_id) = self.addr_to_block.get(&addr) else {
            return ValueSet::Top;
        };
        let Some(rs) = self.inner.register_states.get(block_id) else {
            return ValueSet::Top;
        };
        let si = rs.get(reg);
        strided_interval_to_value_set(si)
    }

    /// Resolve indirect call / jump targets at `addr`.
    ///
    /// Looks up the abstract value of every possible target register at `addr`
    /// by querying `possible_values` for all registers in the block's state,
    /// and returns the concretized code addresses.  When a value set is too
    /// wide to enumerate directly (Top or a large range), the concrete
    /// evaluation fallback is invoked to attempt a narrower estimate.
    ///
    /// Targets that fail address-range validation (zero / near-zero) are
    /// silently dropped.
    #[must_use]
    pub fn resolve_indirect_targets(&self, addr: u64) -> Vec<u64> {
        let Some(&block_id) = self.addr_to_block.get(&addr) else {
            return Vec::new();
        };
        let Some(rs) = self.inner.register_states.get(block_id) else {
            return Vec::new();
        };

        let mut targets = Vec::new();
        for &si in rs.regs.values() {
            let vs = strided_interval_to_value_set(si);
            match vs.concretize(self.concrete_fallback_limit) {
                Some(vals) => {
                    for v in vals {
                        if v > 0x1000 {
                            targets.push(v);
                        }
                    }
                }
                None => {
                    // Value set is too wide; apply the concrete fallback.
                    if let Some(narrowed) = self.concrete_fallback(si) {
                        for v in narrowed {
                            if v > 0x1000 {
                                targets.push(v);
                            }
                        }
                    }
                }
            }
        }

        targets.sort_unstable();
        targets.dedup();
        targets
    }

    /// Concrete evaluation fallback: when a `StridedInterval` is too wide for
    /// direct enumeration, attempt to sample a bounded subset of its values by
    /// evaluating the interval at evenly-spaced points.
    ///
    /// Returns `None` when the interval is `Top` (completely unconstrained) or
    /// when no useful narrowing is possible.
    #[must_use]
    pub fn concrete_fallback(&self, si: StridedInterval) -> Option<Vec<u64>> {
        if si.is_top() || si.is_bottom() {
            return None;
        }
        // Compute span; guard against overflow.
        let span = si.hi.saturating_sub(si.lo);
        if span == u64::MAX {
            return None;
        }
        // Sample up to `concrete_fallback_limit` evenly-spaced points.
        let limit = self.concrete_fallback_limit as u64;
        if limit == 0 {
            return None;
        }
        let step = (span / limit).max(si.stride);
        let mut out = Vec::new();
        let mut v = si.lo;
        while v <= si.hi && out.len() < self.concrete_fallback_limit {
            // Only include values that are actually in the strided interval.
            if (v - si.lo).is_multiple_of(si.stride) {
                out.push(v);
            }
            v = match v.checked_add(step) {
                Some(next) => next,
                None => break,
            };
        }
        // Always include the endpoint if we didn't reach it.
        if si.contains(si.hi) && !out.contains(&si.hi) {
            out.push(si.hi);
        }
        if out.is_empty() { None } else { Some(out) }
    }
}

/// Convert a `StridedInterval` to the equivalent `ValueSet` representation.
#[must_use]
pub fn strided_interval_to_value_set(si: StridedInterval) -> ValueSet {
    if si.is_bottom() {
        ValueSet::Bottom
    } else if si.is_top() {
        ValueSet::Top
    } else if si.is_singleton() {
        ValueSet::singleton(si.lo)
    } else {
        ValueSet::Range {
            lo: si.lo,
            hi: si.hi,
            stride: si.stride,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// VsaEngine — address-based analyze_function facade
// ────────────────────────────────────────────────────────────────────────────

impl VsaEngine {
    /// Analyze a function starting at `start_addr` within `view`.
    ///
    /// This facade builds a minimal single-block `VsaEngineCfg` over the
    /// function's executable bytes and runs the fixpoint engine, returning a
    /// `VsaResult` with an address→block mapping and query helpers.
    ///
    /// For real inter-procedural analysis callers should build a proper
    /// multi-block `VsaEngineCfg` and call `analyze_function` directly; this
    /// helper provides a convenient starting point for single-function probing.
    ///
    /// # Errors
    ///
    /// Returns [`VsaError::EmptyProgram`] when no executable bytes are found
    /// at `start_addr`, or propagates any error from the inner fixpoint engine.
    pub fn analyze_function_at(
        &self,
        view: &rustre_core::binary_view::BinaryView,
        start_addr: rustre_core::address::Address,
    ) -> Result<VsaResult, VsaError> {
        use rustre_core::permissions::Permissions;

        let byte_count = {
            let mem_guard = view.mem.read();
            let seg = mem_guard
                .segments
                .iter()
                .find(|s| s.permissions.contains(Permissions::EXECUTE) && s.range.contains(start_addr))
                .ok_or(VsaError::EmptyProgram)?;
            let count =
                usize::try_from(seg.range.end.0.saturating_sub(start_addr.0)).unwrap_or(usize::MAX);
            drop(mem_guard);
            count
        };
        let instrs: Vec<VsaEngineInstr> = (0..byte_count.min(4096))
            .map(|_| VsaEngineInstr::Nop)
            .collect();

        let block = VsaEngineBlock { id: 0, instrs };
        let cfg = VsaEngineCfg::new(vec![block], vec![vec![]], 0);

        let inner = self.analyze_function(&cfg)?;

        // Map every address in the segment covered by the function to block 0.
        let mut addr_to_block = HashMap::new();
        for offset in 0..byte_count.min(4096) {
            addr_to_block.insert(start_addr.0 + u64::try_from(offset).unwrap_or(0), 0);
        }

        Ok(VsaResult::new(inner, addr_to_block))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Single-point query facade
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PointValueKind {
    Const,
    Range,
    Set,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PointValue {
    pub kind: PointValueKind,
    pub repr: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PointConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PointQueryResult {
    pub values: Vec<PointValue>,
    pub confidence: PointConfidence,
}

fn value_set_to_points(vs: &ValueSet) -> (Vec<PointValue>, PointConfidence) {
    match vs {
        ValueSet::Bottom => (
            vec![PointValue {
                kind: PointValueKind::Unknown,
                repr: "bottom".into(),
            }],
            PointConfidence::Low,
        ),
        ValueSet::Top => (
            vec![PointValue {
                kind: PointValueKind::Unknown,
                repr: "top".into(),
            }],
            PointConfidence::Low,
        ),
        ValueSet::Concrete(v) if v.len() == 1 => (
            vec![PointValue {
                kind: PointValueKind::Const,
                repr: format!("{:#x}", v[0]),
            }],
            PointConfidence::High,
        ),
        ValueSet::Concrete(v) => (
            vec![PointValue {
                kind: PointValueKind::Set,
                repr: format!(
                    "{{{}}}",
                    v.iter()
                        .map(|x| format!("{x:#x}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }],
            PointConfidence::Medium,
        ),
        ValueSet::Range { lo, hi, stride } => (
            vec![PointValue {
                kind: PointValueKind::Range,
                repr: format!("[{lo:#x}, {hi:#x}]/{stride}"),
            }],
            PointConfidence::Medium,
        ),
    }
}

fn parse_mem_target(target: &str) -> Option<(&str, i64)> {
    let inner = target.strip_prefix('[')?.strip_suffix(']')?;
    let inner = inner.trim();
    for (sign_str, sign) in [("+", 1i64), ("-", -1i64)] {
        if let Some(idx) = inner.find(sign_str) {
            let (reg, off) = inner.split_at(idx);
            let off = &off[1..];
            let reg = reg.trim();
            let off_v: i64 = if let Some(hex) = off.trim().strip_prefix("0x") {
                i64::from_str_radix(hex, 16).ok()?
            } else {
                off.trim().parse().ok()?
            };
            return Some((reg, sign * off_v));
        }
    }
    Some((inner, 0))
}

/// Query the abstract value set at a single program point for a register or
/// `[reg+offset]` memory expression.
///
/// For a plain register name, returns the abstract values held by that register
/// at `addr`. For `[reg+offset]`, returns the abstract address set obtained by
/// offsetting the register's value set; this is the address-of, not the load.
#[must_use]
pub fn query_point(result: &VsaResult, addr: u64, target: &str) -> PointQueryResult {
    let target = target.trim();
    if target.starts_with('[') {
        let Some((reg, off)) = parse_mem_target(target) else {
            return PointQueryResult {
                values: vec![PointValue {
                    kind: PointValueKind::Unknown,
                    repr: format!("malformed target: {target}"),
                }],
                confidence: PointConfidence::Low,
            };
        };
        let base = result.possible_values(addr, reg);
        let offset_vs = if off >= 0 {
            ValueSet::singleton(off.cast_unsigned())
        } else {
            ValueSet::singleton(off.unsigned_abs())
        };
        let addr_vs = if off >= 0 {
            base.add(&offset_vs)
        } else {
            base.sub(&offset_vs)
        };
        let (mut values, _) = value_set_to_points(&addr_vs);
        for v in &mut values {
            v.repr = format!("addr={}", v.repr);
        }
        return PointQueryResult {
            values,
            confidence: PointConfidence::Low,
        };
    }
    let vs = result.possible_values(addr, target);
    let (values, confidence) = value_set_to_points(&vs);
    PointQueryResult { values, confidence }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── StridedInterval malformed/untrusted-input robustness ──────────────

    /// `StridedInterval` has public fields and derives `Deserialize`, so a
    /// value with `stride == 0` can reach `concretize` without going through
    /// the `new()` constructor (which normally clamps stride to >= 1). This
    /// must not panic (division by zero) or hang (infinite loop from
    /// `saturating_add(0)`).
    #[test]
    fn concretize_zero_stride_does_not_panic_or_hang() {
        let si = StridedInterval {
            lo: 0,
            hi: 10,
            stride: 0,
        };
        let out = si.concretize(1000).expect("bounded range should concretize");
        assert_eq!(out, (0..=10).collect::<Vec<u64>>());
    }

    #[test]
    fn concretize_zero_stride_respects_limit() {
        let si = StridedInterval {
            lo: 0,
            hi: 1_000_000,
            stride: 0,
        };
        assert_eq!(si.concretize(10), None);
    }

    // ── ValueSet constructors ─────────────────────────────────────────────

    #[test]
    fn test_singleton() {
        let vs = ValueSet::singleton(42);
        assert_eq!(vs, ValueSet::Concrete(vec![42]));
    }

    #[test]
    fn test_interval() {
        let vs = ValueSet::interval(0, 10);
        assert!(matches!(
            vs,
            ValueSet::Range {
                lo: 0,
                hi: 10,
                stride: 1
            }
        ));
    }

    #[test]
    fn test_strided_singleton() {
        let vs = ValueSet::strided(5, 5, 4);
        assert_eq!(vs, ValueSet::Concrete(vec![5]));
    }

    // ── Lattice join ──────────────────────────────────────────────────────

    #[test]
    fn test_join_bottom_identity() {
        let vs = ValueSet::singleton(5);
        assert_eq!(vs.join(&ValueSet::Bottom), vs);
        assert_eq!(ValueSet::Bottom.join(&vs), vs);
    }

    #[test]
    fn test_join_top_absorbs() {
        let vs = ValueSet::singleton(5);
        assert_eq!(vs.join(&ValueSet::Top), ValueSet::Top);
    }

    #[test]
    fn test_join_concrete_union() {
        let a = ValueSet::Concrete(vec![1, 2]);
        let b = ValueSet::Concrete(vec![2, 3]);
        let j = a.join(&b);
        assert_eq!(j, ValueSet::Concrete(vec![1, 2, 3]));
    }

    #[test]
    fn test_join_widens_to_range_when_too_many() {
        let vals: Vec<u64> = (0..=40).collect();
        let a = ValueSet::Concrete(vals);
        let b = ValueSet::Concrete(vec![100]);
        let j = a.join(&b);
        assert!(matches!(j, ValueSet::Range { .. }));
    }

    #[test]
    fn test_join_ranges() {
        let a = ValueSet::Range {
            lo: 0,
            hi: 10,
            stride: 2,
        };
        let b = ValueSet::Range {
            lo: 5,
            hi: 15,
            stride: 4,
        };
        let j = a.join(&b);
        match j {
            ValueSet::Range { lo, hi, .. } => {
                assert!(lo <= 5);
                assert!(hi >= 10);
            }
            _ => panic!("expected Range"),
        }
    }

    // ── Lattice meet ──────────────────────────────────────────────────────

    #[test]
    fn test_meet_bottom_absorbs() {
        let vs = ValueSet::singleton(5);
        assert_eq!(vs.meet(&ValueSet::Bottom), ValueSet::Bottom);
    }

    #[test]
    fn test_meet_top_identity() {
        let vs = ValueSet::singleton(5);
        assert_eq!(vs.meet(&ValueSet::Top), vs);
    }

    #[test]
    fn test_meet_disjoint_concrete_is_bottom() {
        let a = ValueSet::Concrete(vec![1, 2]);
        let b = ValueSet::Concrete(vec![3, 4]);
        assert_eq!(a.meet(&b), ValueSet::Bottom);
    }

    // ── Arithmetic ────────────────────────────────────────────────────────

    #[test]
    fn test_add_concrete() {
        let a = ValueSet::Concrete(vec![10]);
        let b = ValueSet::Concrete(vec![5]);
        assert_eq!(a.add(&b), ValueSet::Concrete(vec![15]));
    }

    #[test]
    fn test_sub_concrete() {
        let a = ValueSet::Concrete(vec![10]);
        let b = ValueSet::Concrete(vec![3]);
        assert_eq!(a.sub(&b), ValueSet::Concrete(vec![7]));
    }

    #[test]
    fn test_add_range() {
        let a = ValueSet::Range {
            lo: 0,
            hi: 10,
            stride: 1,
        };
        let b = ValueSet::Range {
            lo: 5,
            hi: 5,
            stride: 1,
        };
        let r = a.add(&b);
        match r {
            ValueSet::Range { lo, hi, .. } => {
                assert_eq!(lo, 5);
                assert_eq!(hi, 15);
            }
            _ => panic!("expected Range"),
        }
    }

    #[test]
    fn test_bitwise_and() {
        let a = ValueSet::Concrete(vec![0xFF]);
        let b = ValueSet::Concrete(vec![0x0F]);
        assert_eq!(a.bitwise_and(&b), ValueSet::Concrete(vec![0x0F]));
    }

    #[test]
    fn test_bitwise_or() {
        let a = ValueSet::Concrete(vec![0xF0]);
        let b = ValueSet::Concrete(vec![0x0F]);
        assert_eq!(a.bitwise_or(&b), ValueSet::Concrete(vec![0xFF]));
    }

    // ── Concretize ────────────────────────────────────────────────────────

    #[test]
    fn test_concretize_range() {
        let vs = ValueSet::Range {
            lo: 0,
            hi: 10,
            stride: 2,
        };
        let vals = vs.concretize(100).unwrap();
        assert_eq!(vals, vec![0, 2, 4, 6, 8, 10]);
    }

    #[test]
    fn test_concretize_bottom_empty() {
        assert_eq!(ValueSet::Bottom.concretize(100), Some(vec![]));
    }

    #[test]
    fn test_concretize_top_none() {
        assert_eq!(ValueSet::Top.concretize(100), None);
    }

    // ── VsaAnalyzer ───────────────────────────────────────────────────────

    #[test]
    fn test_vsa_const_and_add() {
        let block = VsaBlock {
            id: 0,
            instrs: vec![
                VsaInstr::Const {
                    dst: "a".into(),
                    value: 10,
                },
                VsaInstr::Const {
                    dst: "b".into(),
                    value: 5,
                },
                VsaInstr::Add {
                    dst: "c".into(),
                    lhs: "a".into(),
                    rhs: "b".into(),
                },
            ],
        };
        let cfg = VsaCfg::new(vec![block], vec![vec![]], 0);
        let analyzer = VsaAnalyzer::new(VsaState::new());
        let states = analyzer.run(&cfg).unwrap();
        let c = states[0].get("c");
        assert_eq!(c, ValueSet::Bottom);

        let mut mem = MemoryModel::default();
        let out = VsaAnalyzer::transfer(&cfg.blocks[0], &states[0], &mut mem);
        assert_eq!(out.get("c"), ValueSet::Concrete(vec![15]));
    }

    #[test]
    fn test_vsa_copy_propagates() {
        let block = VsaBlock {
            id: 0,
            instrs: vec![
                VsaInstr::Const {
                    dst: "x".into(),
                    value: 42,
                },
                VsaInstr::Copy {
                    dst: "y".into(),
                    src: "x".into(),
                },
            ],
        };
        let mut mem = MemoryModel::default();
        let out = VsaAnalyzer::transfer(&block, &VsaState::new(), &mut mem);
        assert_eq!(out.get("y"), ValueSet::Concrete(vec![42]));
    }

    #[test]
    fn test_vsa_store_and_load() {
        let block = VsaBlock {
            id: 0,
            instrs: vec![
                VsaInstr::Const {
                    dst: "ptr".into(),
                    value: 0x1000,
                },
                VsaInstr::Const {
                    dst: "val".into(),
                    value: 99,
                },
                VsaInstr::Store {
                    ptr: "ptr".into(),
                    val: "val".into(),
                },
                VsaInstr::Load {
                    dst: "out".into(),
                    ptr: "ptr".into(),
                },
            ],
        };
        let mut mem = MemoryModel::default();
        let out = VsaAnalyzer::transfer(&block, &VsaState::new(), &mut mem);
        assert_eq!(out.get("out"), ValueSet::Concrete(vec![99]));
    }

    // ── AddressClassifier ─────────────────────────────────────────────────

    #[test]
    fn test_address_classification_code() {
        let mut classifier = AddressClassifier::new();
        classifier.code_range = Some((0x1000, 0x2000));
        assert_eq!(classifier.classify_addr(0x1500), AddressClass::Code);
    }

    #[test]
    fn test_address_classification_stack() {
        let mut classifier = AddressClassifier::new();
        classifier.stack_range = Some((0x7fff_0000, 0x8000_0000));
        assert_eq!(classifier.classify_addr(0x7fff_1000), AddressClass::Stack);
    }

    #[test]
    fn test_address_classification_unknown() {
        let classifier = AddressClassifier::new();
        assert_eq!(classifier.classify_addr(0xDEAD_BEEF), AddressClass::Unknown);
    }

    // ── IndirectCallResolver ──────────────────────────────────────────────

    #[test]
    fn test_indirect_call_resolver() {
        let mut classifier = AddressClassifier::new();
        classifier.code_range = Some((0x1000, 0x3000));

        let block = VsaBlock {
            id: 0,
            instrs: vec![
                VsaInstr::Const {
                    dst: "fp".into(),
                    value: 0x1400,
                },
                VsaInstr::IndirectCall {
                    target: "fp".into(),
                },
            ],
        };
        let cfg = VsaCfg::new(vec![block], vec![vec![]], 0);
        let mut initial = VsaState::new();
        initial.set("fp", ValueSet::singleton(0x1400));
        let states = vec![initial];

        let resolver = IndirectCallResolver::new(&states, &classifier);
        let resolutions = resolver.resolve(&cfg);

        assert_eq!(resolutions.len(), 1);
        assert_eq!(resolutions[0].resolved_targets, vec![0x1400]);
        assert!(!resolutions[0].is_imprecise);
    }

    #[test]
    fn test_indirect_call_unresolvable_top() {
        let classifier = AddressClassifier::new();
        let block = VsaBlock {
            id: 0,
            instrs: vec![VsaInstr::IndirectCall {
                target: "fp".into(),
            }],
        };
        let cfg = VsaCfg::new(vec![block], vec![vec![]], 0);
        let mut initial = VsaState::new();
        initial.set("fp", ValueSet::Top);
        let states = vec![initial];

        let resolver = IndirectCallResolver::new(&states, &classifier);
        let resolutions = resolver.resolve(&cfg);
        assert!(resolutions[0].is_imprecise);
    }

    // ── StridedInterval ───────────────────────────────────────────────────

    #[test]
    fn test_si_singleton() {
        let si = StridedInterval::singleton(42);
        assert!(si.is_singleton());
        assert!(si.contains(42));
        assert!(!si.contains(43));
    }

    #[test]
    fn test_si_bottom() {
        assert!(StridedInterval::BOTTOM.is_bottom());
        assert!(!StridedInterval::BOTTOM.contains(0));
    }

    #[test]
    fn test_si_top() {
        assert!(StridedInterval::TOP.is_top());
        assert!(StridedInterval::TOP.contains(0));
        assert!(StridedInterval::TOP.contains(u64::MAX));
    }

    #[test]
    fn test_si_new_snaps_hi() {
        // [0, 10] / 3  → values 0, 3, 6, 9; hi should be snapped to 9
        let si = StridedInterval::new(0, 10, 3);
        assert_eq!(si.hi, 9);
        assert!(si.contains(9));
        assert!(!si.contains(10));
    }

    #[test]
    fn test_si_add() {
        let a = StridedInterval::singleton(10);
        let b = StridedInterval::singleton(5);
        let r = a.add(&b);
        assert_eq!(r, StridedInterval::singleton(15));
    }

    #[test]
    fn test_si_add_range() {
        let a = StridedInterval::new(0, 10, 2); // 0,2,4,6,8,10
        let b = StridedInterval::singleton(1);
        let r = a.add(&b); // 1,3,5,7,9,11
        assert_eq!(r.lo, 1);
        assert_eq!(r.hi, 11);
    }

    #[test]
    fn test_si_sub() {
        let a = StridedInterval::singleton(10);
        let b = StridedInterval::singleton(3);
        let r = a.sub(&b);
        assert_eq!(r, StridedInterval::singleton(7));
    }

    #[test]
    fn test_si_and_singletons() {
        let a = StridedInterval::singleton(0xFF);
        let b = StridedInterval::singleton(0x0F);
        assert_eq!(a.bitwise_and(&b), StridedInterval::singleton(0x0F));
    }

    #[test]
    fn test_si_or_singletons() {
        let a = StridedInterval::singleton(0xF0);
        let b = StridedInterval::singleton(0x0F);
        assert_eq!(a.bitwise_or(&b), StridedInterval::singleton(0xFF));
    }

    #[test]
    fn test_si_join_disjoint() {
        let a = StridedInterval::new(0, 4, 2); // 0,2,4
        let b = StridedInterval::new(6, 10, 2); // 6,8,10
        let j = a.join(&b);
        assert_eq!(j.lo, 0);
        assert_eq!(j.hi, 10);
    }

    #[test]
    fn test_si_join_with_bottom() {
        let a = StridedInterval::singleton(5);
        assert_eq!(a.join(&StridedInterval::BOTTOM), a);
        assert_eq!(StridedInterval::BOTTOM.join(&a), a);
    }

    #[test]
    fn test_si_widen_extends_hi() {
        let prev = StridedInterval::new(0, 10, 1);
        let next = StridedInterval::new(0, 20, 1);
        let w = prev.widen(&next);
        assert_eq!(w.hi, u64::MAX); // hi blown to top
    }

    #[test]
    fn test_si_concretize() {
        let si = StridedInterval::new(0, 8, 2);
        let vals = si.concretize(100).unwrap();
        assert_eq!(vals, vec![0, 2, 4, 6, 8]);
    }

    #[test]
    fn test_si_concretize_top_none() {
        assert!(StridedInterval::TOP.concretize(100).is_none());
    }

    #[test]
    fn test_is_definitely_null() {
        assert!(is_definitely_null(&StridedInterval::singleton(0)));
        assert!(!is_definitely_null(&StridedInterval::singleton(1)));
        assert!(!is_definitely_null(&StridedInterval::new(0, 10, 1)));
    }

    #[test]
    fn test_may_be_out_of_bounds() {
        let si = StridedInterval::new(0, 15, 1);
        // bounds [0, 10): values 10..15 are out
        assert!(may_be_out_of_bounds(&si, (0, 10)));
        // bounds [0, 20): all values in range
        assert!(!may_be_out_of_bounds(&si, (0, 20)));
    }

    // ── MemoryAbstraction ─────────────────────────────────────────────────

    #[test]
    fn test_mem_abstraction_store_load_singleton() {
        let mut mem = MemoryAbstraction::new();
        let addr = StridedInterval::singleton(0x1000);
        let val = StridedInterval::singleton(99);
        mem.store(addr, val);
        assert_eq!(mem.load(&addr), val);
    }

    #[test]
    fn test_mem_abstraction_load_miss() {
        let mem = MemoryAbstraction::new();
        let r = mem.load(&StridedInterval::singleton(0xDEAD));
        assert!(r.is_bottom());
    }

    #[test]
    fn test_mem_abstraction_weak_update() {
        let mut mem = MemoryAbstraction::new();
        let a = StridedInterval::singleton(0x1000);
        let b = StridedInterval::singleton(0x1008);
        mem.store(a, StridedInterval::singleton(1));
        mem.store(b, StridedInterval::singleton(2));
        // Range store should weak-update both.
        let range = StridedInterval::new(0x1000, 0x1008, 8);
        mem.store(range, StridedInterval::singleton(42));
        // The original cells have been joined with 42.
        let v_a = mem.load(&a);
        assert!(v_a.contains(1) || v_a.contains(42));
    }

    // ── VsaEngine ─────────────────────────────────────────────────────────

    #[test]
    fn test_vsa_engine_const_and_add() {
        let block = VsaEngineBlock {
            id: 0,
            instrs: vec![
                VsaEngineInstr::Const {
                    dst: "a".into(),
                    value: 10,
                },
                VsaEngineInstr::Const {
                    dst: "b".into(),
                    value: 5,
                },
                VsaEngineInstr::Add {
                    dst: "c".into(),
                    lhs: "a".into(),
                    rhs: "b".into(),
                },
            ],
        };
        let cfg = VsaEngineCfg::new(vec![block], vec![vec![]], 0);
        let engine = VsaEngine::new(RegisterState::default());
        let result = engine.analyze_function(&cfg).unwrap();
        assert!(result.converged);
        // Transfer produces the output; entry state at block 0 is empty.
        let mut mem = MemoryAbstraction::new();
        let out = VsaEngine::transfer(&cfg.blocks[0], &result.register_states[0], &mut mem);
        assert_eq!(out.get("c"), StridedInterval::singleton(15));
    }

    #[test]
    fn test_vsa_engine_loop_converges() {
        // A simple loop: block 0 → block 1 → block 1 (self-loop) to test widening.
        let b0 = VsaEngineBlock {
            id: 0,
            instrs: vec![VsaEngineInstr::Const {
                dst: "i".into(),
                value: 0,
            }],
        };
        let b1 = VsaEngineBlock {
            id: 1,
            instrs: vec![VsaEngineInstr::AddConst {
                dst: "i".into(),
                src: "i".into(),
                imm: 1,
            }],
        };
        let cfg = VsaEngineCfg::new(
            vec![b0, b1],
            vec![vec![1], vec![1]], // 0→1, 1→1 (self-loop)
            0,
        );
        let engine = VsaEngine::new(RegisterState::default());
        let result = engine.analyze_function(&cfg).unwrap();
        // Should converge (widening kicks in after threshold visits).
        assert!(result.converged);
    }

    #[test]
    fn test_vsa_engine_empty_program_error() {
        let cfg = VsaEngineCfg::new(vec![], vec![], 0);
        let engine = VsaEngine::new(RegisterState::default());
        assert!(matches!(
            engine.analyze_function(&cfg),
            Err(VsaError::EmptyProgram)
        ));
    }

    #[test]
    fn test_value_set_result_helpers() {
        let mut rs = RegisterState::default();
        rs.set("rax", StridedInterval::singleton(0));
        rs.set("rbx", StridedInterval::new(0, 100, 1));
        let result = ValueSetResult {
            register_states: vec![rs],
            memory: MemoryAbstraction::new(),
            iterations: 1,
            converged: true,
        };
        assert!(result.is_null_at(0, "rax"));
        assert!(!result.is_null_at(0, "rbx"));
        assert!(result.may_oob_at(0, "rbx", (0, 50)));
        assert!(!result.may_oob_at(0, "rbx", (0, 200)));
    }

    // ── ValueSet new constructors ──────────────────────────────────────────

    #[test]
    fn test_value_set_top_bottom_constructors() {
        assert_eq!(ValueSet::top(), ValueSet::Top);
        assert_eq!(ValueSet::bottom(), ValueSet::Bottom);
        assert!(ValueSet::top().is_top());
        assert!(ValueSet::bottom().is_bottom());
    }

    // ── ValueSet::contains ────────────────────────────────────────────────

    #[test]
    fn test_value_set_contains_concrete() {
        let vs = ValueSet::Concrete(vec![1, 3, 5]);
        assert!(vs.contains(3));
        assert!(!vs.contains(2));
    }

    #[test]
    fn test_value_set_contains_range() {
        let vs = ValueSet::Range {
            lo: 0,
            hi: 10,
            stride: 2,
        };
        assert!(vs.contains(0));
        assert!(vs.contains(4));
        assert!(vs.contains(10));
        assert!(!vs.contains(1));
        assert!(!vs.contains(11));
    }

    #[test]
    fn test_value_set_contains_top_bottom() {
        assert!(ValueSet::Top.contains(0));
        assert!(ValueSet::Top.contains(u64::MAX));
        assert!(!ValueSet::Bottom.contains(0));
    }

    // ── ValueSet::widen ────────────────────────────────────────────────────

    #[test]
    fn test_value_set_widen_bottom_identity() {
        let vs = ValueSet::singleton(5);
        assert_eq!(ValueSet::Bottom.widen(&vs), vs);
        assert_eq!(vs.widen(&ValueSet::Bottom), vs);
    }

    #[test]
    fn test_value_set_widen_top_absorbs() {
        let vs = ValueSet::singleton(5);
        assert_eq!(vs.widen(&ValueSet::Top), ValueSet::Top);
    }

    #[test]
    fn test_value_set_widen_range_blows_hi() {
        let prev = ValueSet::Range {
            lo: 0,
            hi: 10,
            stride: 1,
        };
        let next = ValueSet::Range {
            lo: 0,
            hi: 20,
            stride: 1,
        };
        let w = prev.widen(&next);
        match w {
            ValueSet::Range { hi, .. } => assert_eq!(hi, u64::MAX),
            ValueSet::Top => {} // also acceptable
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_value_set_widen_range_blows_lo() {
        let prev = ValueSet::Range {
            lo: 5,
            hi: 20,
            stride: 1,
        };
        let next = ValueSet::Range {
            lo: 0,
            hi: 20,
            stride: 1,
        };
        let w = prev.widen(&next);
        match w {
            ValueSet::Range { lo, .. } => assert_eq!(lo, 0),
            ValueSet::Top => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ── strided_interval_to_value_set ─────────────────────────────────────

    #[test]
    fn test_si_to_vs_conversions() {
        assert_eq!(
            strided_interval_to_value_set(StridedInterval::BOTTOM),
            ValueSet::Bottom
        );
        assert_eq!(
            strided_interval_to_value_set(StridedInterval::TOP),
            ValueSet::Top
        );
        assert_eq!(
            strided_interval_to_value_set(StridedInterval::singleton(42)),
            ValueSet::singleton(42)
        );
        let si = StridedInterval::new(0, 10, 2);
        assert_eq!(
            strided_interval_to_value_set(si),
            ValueSet::Range {
                lo: 0,
                hi: 10,
                stride: 2
            }
        );
    }

    // ── VsaResult ─────────────────────────────────────────────────────────

    #[test]
    fn test_vsa_result_possible_values_known_addr() {
        let mut rs = RegisterState::default();
        rs.set("rax", StridedInterval::singleton(0x1234));
        let inner = ValueSetResult {
            register_states: vec![rs],
            memory: MemoryAbstraction::new(),
            iterations: 1,
            converged: true,
        };
        let mut map = HashMap::new();
        map.insert(0x4000u64, 0usize);
        let vsa_result = VsaResult::new(inner, map);
        assert_eq!(
            vsa_result.possible_values(0x4000, "rax"),
            ValueSet::singleton(0x1234)
        );
        // Unknown address returns Top.
        assert_eq!(vsa_result.possible_values(0x9999, "rax"), ValueSet::Top);
    }

    #[test]
    fn test_vsa_result_resolve_indirect_targets_singleton() {
        let mut rs = RegisterState::default();
        // Place a code-like address in rax.
        rs.set("rax", StridedInterval::singleton(0x5000));
        let inner = ValueSetResult {
            register_states: vec![rs],
            memory: MemoryAbstraction::new(),
            iterations: 1,
            converged: true,
        };
        let mut map = HashMap::new();
        map.insert(0x4000u64, 0usize);
        let vsa_result = VsaResult::new(inner, map);
        let targets = vsa_result.resolve_indirect_targets(0x4000);
        assert!(targets.contains(&0x5000));
    }

    #[test]
    fn test_vsa_result_resolve_indirect_unknown_addr() {
        let inner = ValueSetResult {
            register_states: vec![],
            memory: MemoryAbstraction::new(),
            iterations: 0,
            converged: true,
        };
        let vsa_result = VsaResult::new(inner, HashMap::new());
        assert!(vsa_result.resolve_indirect_targets(0xDEAD).is_empty());
    }

    // ── concrete_fallback ─────────────────────────────────────────────────

    #[test]
    fn test_concrete_fallback_narrow_range() {
        let vsa_result = VsaResult::new(
            ValueSetResult {
                register_states: vec![],
                memory: MemoryAbstraction::new(),
                iterations: 0,
                converged: true,
            },
            HashMap::new(),
        );
        let si = StridedInterval::new(0x1000, 0x9000, 0x1000);
        let vals = vsa_result.concrete_fallback(si).unwrap();
        // Should include lo and hi.
        assert!(vals.contains(&0x1000));
        assert!(vals.contains(&0x9000));
    }

    #[test]
    fn test_concrete_fallback_top_returns_none() {
        let vsa_result = VsaResult::new(
            ValueSetResult {
                register_states: vec![],
                memory: MemoryAbstraction::new(),
                iterations: 0,
                converged: true,
            },
            HashMap::new(),
        );
        assert!(vsa_result.concrete_fallback(StridedInterval::TOP).is_none());
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SECTION 1 — Full StridedInterval Abstract Domain
// ════════════════════════════════════════════════════════════════════════════
//
// The `StridedInterval` type above covers the core lattice operations.  This
// section adds the remaining transfer functions described in the spec:
// multiplication, all shift operations, XOR, a full narrowing operator, and
// the utility query methods (`upper_bound`, `size`, `concrete_values`,
// `is_singleton` returning `Option<u64>`).
//
// All arithmetic is over *unsigned* 64-bit integers with wrapping semantics.
// When a result cannot be represented precisely we conservatively widen to a
// unit-stride interval or to `Top`.

impl StridedInterval {
    // ── Multiplication ────────────────────────────────────────────────────

    /// Multiply two strided intervals.
    ///
    /// `[a,b]/s * [c,d]/t = [min(ac,ad,bc,bd), max(ac,ad,bc,bd)] / gcd(s*c, s*d, t*a, t*b)`
    ///
    /// We evaluate all four corner products (unsigned) and form an enclosing
    /// interval.  Overflow causes a conservative widening to `Top`.
    ///
    /// # Panics
    ///
    /// Never panics in practice — the `unwrap` is guarded by an overflow check.
    #[must_use]
    pub fn mul(&self, rhs: &Self) -> Self {
        if self.is_bottom() || rhs.is_bottom() {
            return Self::BOTTOM;
        }
        if self.is_top() || rhs.is_top() {
            return Self::TOP;
        }
        // Compute the four corner products with overflow detection.
        let corners = [
            self.lo.checked_mul(rhs.lo),
            self.lo.checked_mul(rhs.hi),
            self.hi.checked_mul(rhs.lo),
            self.hi.checked_mul(rhs.hi),
        ];
        if corners.iter().any(std::option::Option::is_none) {
            return Self::TOP;
        }
        let vals: Vec<u64> = corners.iter().map(|c| c.unwrap()).collect();
        let lo = *vals.iter().min().unwrap();
        let hi = *vals.iter().max().unwrap();
        // Conservative stride. Products expand as
        //   (a+si)(c+tj) = ac + s·c·i + t·a·j + s·t·i·j,
        // so the achievable increments are integer combinations of s·c, t·a and
        // the cross term s·t. The cross term `self.stride * rhs.stride` was
        // missing, which produced a too-large stride that dropped real products.
        let s = gcd(
            gcd(
                gcd(
                    self.stride.saturating_mul(rhs.lo),
                    self.stride.saturating_mul(rhs.hi),
                ),
                gcd(
                    rhs.stride.saturating_mul(self.lo),
                    rhs.stride.saturating_mul(self.hi),
                ),
            ),
            self.stride.saturating_mul(rhs.stride),
        )
        .max(1);
        Self::new(lo, hi, s)
    }

    // ── Bitwise XOR ───────────────────────────────────────────────────────

    /// Bitwise XOR of two strided intervals.
    ///
    /// For singleton × singleton the result is exact.  For ranges we compute a
    /// conservative over-approximation: the result lies in `[0, hi_a | hi_b]`.
    #[must_use]
    pub fn bitwise_xor(&self, rhs: &Self) -> Self {
        if self.is_bottom() || rhs.is_bottom() {
            return Self::BOTTOM;
        }
        if self.is_singleton() && rhs.is_singleton() {
            return Self::singleton(self.lo ^ rhs.lo);
        }
        if self.is_top() || rhs.is_top() {
            return Self::TOP;
        }
        // Upper bound: no result bit can exceed the highest bit of `hi_a|hi_b`,
        // but lower bits may all be set, so saturate below that top bit.
        let hi = ones_upto(self.hi | rhs.hi);
        Self::new(0, hi, 1)
    }

    // ── Logical shift left ────────────────────────────────────────────────

    /// Logical shift left: `self << rhs`.
    ///
    /// Exact for singleton × singleton.  For ranges: `[lo<<sh_lo, hi<<sh_hi]`
    /// with overflow detected and widened to `Top`.
    #[must_use]
    pub fn shl(&self, rhs: &Self) -> Self {
        if self.is_bottom() || rhs.is_bottom() {
            return Self::BOTTOM;
        }
        if self.is_top() || rhs.is_top() {
            return Self::TOP;
        }
        if self.is_singleton() && rhs.is_singleton() {
            let shift = rhs.lo;
            if shift >= 64 {
                return Self::singleton(0);
            }
            return Self::singleton(self.lo << shift);
        }
        let sh_lo = rhs.lo.min(63);
        let sh_hi = rhs.hi.min(63);
        let new_lo = self.lo.checked_shl(sh_lo as u32);
        let new_hi = self.hi.checked_shl(sh_hi as u32);
        match (new_lo, new_hi) {
            (Some(lo), Some(hi)) if lo <= hi => {
                // A strided result is only valid when the shift amount is a
                // single value (`x << k` is linear in x). With a *range* of
                // shift amounts the outputs `x << s` for varying s are not a
                // single arithmetic progression, so fall back to stride 1.
                let stride = if sh_lo == sh_hi {
                    self.stride.checked_shl(sh_lo as u32).unwrap_or(1).max(1)
                } else {
                    1
                };
                Self::new(lo, hi, stride)
            }
            _ => Self::TOP,
        }
    }

    /// Logical shift right: `self >> rhs`.
    ///
    /// Exact for singleton × singleton.  Conservative for ranges.
    #[must_use]
    pub fn shr(&self, rhs: &Self) -> Self {
        if self.is_bottom() || rhs.is_bottom() {
            return Self::BOTTOM;
        }
        if self.is_top() || rhs.is_top() {
            return Self::TOP;
        }
        if self.is_singleton() && rhs.is_singleton() {
            let shift = rhs.lo;
            if shift >= 64 {
                return Self::singleton(0);
            }
            return Self::singleton(self.lo >> shift);
        }
        let sh_lo = rhs.lo.min(63);
        let sh_hi = rhs.hi.min(63);
        // Shifting right always shrinks values; lo shrinks least with sh_hi.
        let new_lo = self.lo >> sh_hi;
        let new_hi = self.hi >> sh_lo;
        // Right shift is lossy (floor division by a power of two), so the output
        // spacing is not the input stride shifted — even for a single shift
        // amount the results need not stay on a clean progression, and a range
        // of shift amounts compounds this. Conservatively use stride 1.
        Self::new(new_lo, new_hi, 1)
    }

    /// Arithmetic (signed) shift right.
    ///
    /// Treats the value as signed 64-bit for the shift but returns unsigned result.
    #[must_use]
    pub fn sar(&self, rhs: &Self) -> Self {
        if self.is_bottom() || rhs.is_bottom() {
            return Self::BOTTOM;
        }
        if self.is_singleton() && rhs.is_singleton() {
            let shift = rhs.lo.min(63);
            let signed = self.lo.cast_signed();
            return Self::singleton((signed >> shift).cast_unsigned());
        }
        // Arithmetic shift interprets the value as signed 64-bit. Falling back
        // to the logical `shr` over-approximation is UNSOUND once the value
        // interval can contain a negative (high-bit-set) value: e.g. for
        // [0x8000_0000_0000_0000, …] sar-by-1 must yield ~0xC000…, but logical
        // shr yields ~0x4000…, which does not contain the true result.
        //
        // Compute the result over the *signed* interpretation. A contiguous
        // u64 interval `[lo, hi]` is a single signed piece unless it straddles
        // the sign boundary (lo < 2^63 <= hi), in which case it splits into a
        // non-negative piece `[lo, 2^63-1]` and a negative piece `[2^63, hi]`.
        // `>>` on i64 is monotonic in the value and, per fixed value, monotonic
        // in the shift amount, so the extrema lie at the corners.
        let sh_lo = rhs.lo.min(63);
        let sh_hi = rhs.hi.min(63);
        const SIGN_BIT: u64 = 1u64 << 63;
        let pieces: &[(i64, i64)] = &if self.lo < SIGN_BIT && self.hi >= SIGN_BIT {
            [
                (self.lo.cast_signed(), (SIGN_BIT - 1).cast_signed()),
                (SIGN_BIT.cast_signed(), self.hi.cast_signed()),
            ]
        } else {
            // Duplicate the single piece so we can use a fixed-size array.
            let p = (self.lo.cast_signed(), self.hi.cast_signed());
            [p, p]
        };
        let mut smin = i64::MAX;
        let mut smax = i64::MIN;
        for &(pmin, pmax) in pieces {
            for v in [pmin, pmax] {
                for s in [sh_lo, sh_hi] {
                    let q = v >> s;
                    smin = smin.min(q);
                    smax = smax.max(q);
                }
            }
        }
        // Map the signed result range back to an unsigned interval. When the
        // range straddles zero the unsigned image wraps (negatives are large
        // u64 values), which a single non-wrapping interval cannot express, so
        // conservatively widen to Top.
        if (smin < 0) == (smax < 0) {
            Self::new(smin.cast_unsigned(), smax.cast_unsigned(), 1)
        } else {
            Self::TOP
        }
    }

    // ── Narrowing operator ────────────────────────────────────────────────

    /// Narrowing operator: `self ∇ new`.
    ///
    /// Used after widening has produced a fixpoint to refine the result.
    /// Where `new` provides a tighter bound than the widened value, adopt the
    /// tighter bound; otherwise keep `self`.
    ///
    /// Guaranteed to produce a value `<= self` in the lattice order, so it
    /// terminates when iterated.
    #[must_use]
    pub fn narrow(&self, new: &Self) -> Self {
        if self.is_bottom() {
            return Self::BOTTOM;
        }
        if new.is_bottom() {
            return *new;
        }
        if self.is_top() {
            return *new;
        }
        if new.is_top() {
            return *self;
        }
        // Take the tighter bound from `new` wherever it fits inside `self`.
        let lo = if new.lo > self.lo { new.lo } else { self.lo };
        let hi = if new.hi < self.hi { new.hi } else { self.hi };
        if lo > hi {
            return Self::BOTTOM;
        }
        // Refine the stride: take the larger (more precise) stride.
        let stride = gcd(self.stride, new.stride).max(1);
        Self::new(lo, hi, stride)
    }

    // ── Query helpers ─────────────────────────────────────────────────────

    /// Return the unique concrete value if this interval is a singleton,
    /// otherwise `None`.
    #[must_use]
    pub const fn singleton_value(&self) -> Option<u64> {
        if self.is_singleton() {
            Some(self.lo)
        } else {
            None
        }
    }

    /// Return the upper bound of the interval (useful for jump-table bound
    /// extraction: the index register is bounded by `upper_bound()`).
    #[must_use]
    pub const fn upper_bound(&self) -> u64 {
        if self.is_bottom() { 0 } else { self.hi }
    }

    /// Return the number of concrete elements in the interval, or `None` when
    /// the count overflows `u64` (which happens for `Top` or near-Top ranges).
    #[must_use]
    pub fn size(&self) -> Option<u64> {
        if self.is_bottom() {
            return Some(0);
        }
        if self.is_top() {
            return None;
        }
        let span = self.hi - self.lo;
        // count = span / stride + 1
        let count = span.checked_div(self.stride)?.checked_add(1)?;
        Some(count)
    }

    /// Enumerate up to `max` concrete values, returning `None` when the set is
    /// too large or unbounded.  Equivalent to `concretize` but uses `max` as
    /// the guard.
    #[must_use]
    pub fn concrete_values(&self, max: usize) -> Option<Vec<u64>> {
        self.concretize(max)
    }

    // ── Comparison helpers ────────────────────────────────────────────────

    /// Returns `true` when every value in `self` is strictly less than every
    /// value in `rhs` (unsigned).
    #[must_use]
    pub const fn definitely_lt(&self, rhs: &Self) -> bool {
        if self.is_bottom() || rhs.is_bottom() {
            return false;
        }
        self.hi < rhs.lo
    }

    /// Returns `true` when every value in `self` is less than or equal to
    /// every value in `rhs` (unsigned).
    #[must_use]
    pub const fn definitely_le(&self, rhs: &Self) -> bool {
        if self.is_bottom() || rhs.is_bottom() {
            return false;
        }
        self.hi <= rhs.lo
    }

    /// Returns `true` when the interval may contain a value equal to `rhs`.
    #[must_use]
    pub fn may_equal(&self, rhs: &Self) -> bool {
        !self.meet(rhs).is_bottom()
    }

    // ── Truncation / zero-extension ───────────────────────────────────────

    /// Truncate the value to `bits` bits (zero-extend result).
    ///
    /// For singleton values this is exact.  For ranges we mask with `(1<<bits)-1`.
    #[must_use]
    pub fn truncate(&self, bits: u8) -> Self {
        if self.is_bottom() {
            return Self::BOTTOM;
        }
        if bits == 0 {
            return Self::singleton(0);
        }
        if bits >= 64 {
            return *self;
        }
        let mask = (1u64 << bits).wrapping_sub(1);
        if self.is_singleton() {
            return Self::singleton(self.lo & mask);
        }
        // Conservative: result is in [0, mask].
        Self::new(0, mask, 1)
    }

    /// Sign-extend from `bits` bits to 64 bits (result stored as u64).
    #[must_use]
    pub const fn sign_extend(&self, bits: u8) -> Self {
        if self.is_bottom() {
            return Self::BOTTOM;
        }
        if bits == 0 || bits >= 64 {
            return *self;
        }
        if self.is_singleton() {
            let sign_bit = 1u64 << (bits - 1);
            let mask = sign_bit.wrapping_sub(1);
            let v = self.lo;
            let extended = if v & sign_bit != 0 {
                // Negative: fill upper bits with 1.
                v | !mask & !sign_bit.wrapping_sub(1) | (u64::MAX << bits)
            } else {
                v & mask
            };
            return Self::singleton(extended);
        }
        // Conservative: can't know which values go negative.
        Self::TOP
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SECTION 2 — Region-Aware ValueSet and Abstract State
// ════════════════════════════════════════════════════════════════════════════
//
// The address-relative value-set (AR-VS) tracks which memory *region* a
// pointer belongs to together with the offset within that region.  This is
// the same model used in the original Balakrishnan & Reps VSA paper.

/// Identifier for an abstract memory region.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemRegionId {
    /// The function's stack frame (identified by function start address).
    Stack(u64),
    /// A heap allocation (identified by the allocation site address).
    Heap(u64),
    /// A named global/static variable (identified by its address).
    Global(u64),
    /// A synthetic region used during analysis of unknown allocations.
    Synthetic(u32),
}

impl fmt::Display for MemRegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stack(a) => write!(f, "stack@{a:#x}"),
            Self::Heap(a) => write!(f, "heap@{a:#x}"),
            Self::Global(a) => write!(f, "global@{a:#x}"),
            Self::Synthetic(n) => write!(f, "synthetic#{n}"),
        }
    }
}

/// A region-aware value-set.
///
/// A `RegionValueSet` can represent:
///
/// - A non-pointer integer (stored in `global`).
/// - A pointer into one or more abstract memory regions (stored in `regions`).
///
/// Both components may be present simultaneously (e.g. when a value is
/// sometimes an integer and sometimes a pointer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub struct RegionValueSet {
    /// Abstract value when treated as a plain integer / non-pointer.
    pub global: Option<StridedInterval>,
    /// Per-region pointer offsets.
    pub regions: HashMap<MemRegionId, StridedInterval>,
}


impl RegionValueSet {
    // ── Constructors ───────────────────────────────────────────────────────

    /// Create a `RegionValueSet` representing a constant integer (non-pointer).
    #[must_use]
    pub fn from_const(v: u64) -> Self {
        Self {
            global: Some(StridedInterval::singleton(v)),
            regions: HashMap::new(),
        }
    }

    /// Create a `RegionValueSet` representing `Top` (unknown).
    #[must_use]
    pub fn top() -> Self {
        Self {
            global: Some(StridedInterval::TOP),
            regions: HashMap::new(),
        }
    }

    /// Create the `Bottom` element (no values).
    #[must_use]
    pub fn bottom() -> Self {
        Self {
            global: None,
            regions: HashMap::new(),
        }
    }

    /// Create a pointer into `region` with offset described by `offset`.
    #[must_use]
    pub fn pointer(region: MemRegionId, offset: StridedInterval) -> Self {
        let mut regions = HashMap::new();
        regions.insert(region, offset);
        Self {
            global: None,
            regions,
        }
    }

    // ── Lattice operations ─────────────────────────────────────────────────

    /// Least upper bound (join).
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        let global = match (&self.global, &other.global) {
            (None, x) | (x, None) => *x,
            (Some(a), Some(b)) => Some(a.join(b)),
        };
        let mut regions = self.regions.clone();
        for (rid, off) in &other.regions {
            regions
                .entry(rid.clone())
                .and_modify(|e| *e = e.join(off))
                .or_insert(*off);
        }
        Self { global, regions }
    }

    /// Widening operator.
    #[must_use]
    pub fn widen(&self, other: &Self) -> Self {
        let global = match (&self.global, &other.global) {
            (None, x) | (x, None) => *x,
            (Some(a), Some(b)) => Some(a.widen(b)),
        };
        let mut regions = self.regions.clone();
        for (rid, off) in &other.regions {
            regions
                .entry(rid.clone())
                .and_modify(|e| *e = e.widen(off))
                .or_insert(*off);
        }
        Self { global, regions }
    }

    /// Narrowing operator.
    #[must_use]
    pub fn narrow(&self, other: &Self) -> Self {
        let global = match (&self.global, &other.global) {
            (None, _) | (_, None) => None,
            (Some(a), Some(b)) => Some(a.narrow(b)),
        };
        let mut regions = HashMap::new();
        for (rid, a) in &self.regions {
            if let Some(b) = other.regions.get(rid) {
                let n = a.narrow(b);
                if !n.is_bottom() {
                    regions.insert(rid.clone(), n);
                }
            }
        }
        Self { global, regions }
    }

    /// Add a signed offset to the value-set (pointer arithmetic).
    ///
    /// Adjusts all region offsets and the global component by `off`.
    #[must_use]
    pub fn add_offset(&self, off: i64) -> Self {
        let delta = StridedInterval::singleton(off.cast_unsigned());
        let global = self.global.map(|g| {
            if off >= 0 {
                g.add(&delta)
            } else {
                g.sub(&StridedInterval::singleton((-off).cast_unsigned()))
            }
        });
        let regions = self
            .regions
            .iter()
            .map(|(rid, si)| {
                let new_si = if off >= 0 {
                    si.add(&delta)
                } else {
                    si.sub(&StridedInterval::singleton((-off).cast_unsigned()))
                };
                (rid.clone(), new_si)
            })
            .collect();
        Self { global, regions }
    }

    // ── Alias queries ──────────────────────────────────────────────────────

    /// Returns `true` when `self` and `other` *may* refer to the same memory
    /// location (i.e. their region-offset pairs overlap).
    #[must_use]
    pub fn may_alias(&self, other: &Self) -> bool {
        for (rid, off_a) in &self.regions {
            if let Some(off_b) = other.regions.get(rid)
                && !off_a.meet(off_b).is_bottom() {
                    return true;
                }
        }
        false
    }

    /// Returns `true` when `self` and `other` *must* refer to the exact same
    /// memory location (unique singleton pointer into the same region).
    ///
    /// # Panics
    ///
    /// Never panics (the `unwrap` calls are guarded by the `len() == 1` check).
    #[must_use]
    pub fn must_alias(&self, other: &Self) -> bool {
        if self.regions.len() != 1 || other.regions.len() != 1 {
            return false;
        }
        let (rid_a, off_a) = self.regions.iter().next().unwrap();
        let (rid_b, off_b) = other.regions.iter().next().unwrap();
        rid_a == rid_b && off_a.is_singleton() && off_b.is_singleton() && off_a == off_b
    }

    // ── Predicates ─────────────────────────────────────────────────────────

    /// Returns `true` when this value-set has no values (bottom).
    #[must_use]
    pub fn is_bottom(&self) -> bool {
        self.global.is_none() && self.regions.is_empty()
    }

    /// Returns `true` when this is a pure integer (no pointer components).
    #[must_use]
    pub fn is_integer(&self) -> bool {
        self.regions.is_empty()
    }

    /// Returns `true` when this is a pure pointer (no integer component).
    #[must_use]
    pub fn is_pointer(&self) -> bool {
        self.global.is_none() && !self.regions.is_empty()
    }
}

impl fmt::Display for RegionValueSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(g) = &self.global {
            parts.push(format!("int:{g}"));
        }
        for (rid, off) in &self.regions {
            parts.push(format!("{rid}+{off}"));
        }
        if parts.is_empty() {
            write!(f, "\u{22a5}")
        } else {
            write!(f, "{}", parts.join(" | "))
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// VsaStateV2 — full abstract state for the region-aware VSA engine
// ────────────────────────────────────────────────────────────────────────────

/// Full abstract state for a region-aware VSA pass.
///
/// Tracks abstract values for:
/// * Named registers (`regs`).
/// * Stack slots keyed by signed offset from the frame pointer (`stack`).
/// * Heap cells keyed by allocation-site address (`heap`).
/// * Global variables keyed by their virtual address (`globals`).
#[derive(Debug, Clone, Default)]
pub struct VsaStateV2 {
    /// Register file: register name → region-aware value-set.
    pub regs: HashMap<String, RegionValueSet>,
    /// Stack memory: frame-pointer offset → value-set.
    pub stack: HashMap<i64, RegionValueSet>,
    /// Heap memory: allocation site → value-set.
    pub heap: HashMap<u64, RegionValueSet>,
    /// Global memory: virtual address → value-set.
    pub globals: HashMap<u64, RegionValueSet>,
}

impl VsaStateV2 {
    // ── Constructors ───────────────────────────────────────────────────────

    /// Create a new, empty `VsaStateV2`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Register access ────────────────────────────────────────────────────

    /// Read the abstract value of a register.  Returns `Bottom` if unknown.
    #[must_use]
    pub fn read_reg(&self, reg: &str) -> RegionValueSet {
        self.regs.get(reg).cloned().unwrap_or_default()
    }

    /// Assign an abstract value to a register (strong update).
    pub fn assign_reg(&mut self, reg: &str, val: RegionValueSet) {
        self.regs.insert(reg.to_owned(), val);
    }

    // ── Memory access ──────────────────────────────────────────────────────

    /// Write `val` to the abstract memory cell at `addr`.
    ///
    /// * If `addr` resolves to a unique stack/heap/global slot: strong update.
    /// * Otherwise: weak update (join into all aliased cells).
    pub fn write_mem(&mut self, addr: &RegionValueSet, val: RegionValueSet, _size: u8) {
        // Stack write.
        if let Some(g) = &addr.global {
            if g.is_singleton() {
                let off = g.lo.cast_signed();
                self.stack.insert(off, val);
                return;
            }
            // Weak update over all stack cells.
            for v in self.stack.values_mut() {
                *v = v.join(&val);
            }
        }
        // Region-pointer write.
        for (rid, off) in &addr.regions {
            if off.is_singleton() {
                match rid {
                    MemRegionId::Heap(site) => {
                        self.heap
                            .entry(*site)
                            .and_modify(|e| *e = val.clone())
                            .or_insert_with(|| val.clone());
                    }
                    MemRegionId::Global(ga) => {
                        self.globals
                            .entry(*ga)
                            .and_modify(|e| *e = val.clone())
                            .or_insert_with(|| val.clone());
                    }
                    // NOTE: behaviour preserved verbatim from the previous
                    // `_ => {}` catch-all — these two also take the weak
                    // heap-wide join (see report: suspected bug for Stack).
                    MemRegionId::Stack(_) | MemRegionId::Synthetic(_) => {
                        // Weak: join into all cells of this region.
                        for v in self.heap.values_mut() {
                            *v = v.join(&val);
                        }
                    }
                }
            }
        }
    }

    /// Read from the abstract memory cell at `addr`.
    ///
    /// Returns the join of all values that `addr` may alias.  Returns `Top`
    /// when no cell is found (conservative: memory may hold anything).
    #[must_use]
    pub fn read_mem(&self, addr: &RegionValueSet, _size: u8) -> RegionValueSet {
        let mut result = RegionValueSet::bottom();
        // Stack reads.
        if let Some(g) = &addr.global {
            if g.is_singleton() {
                let off = g.lo.cast_signed();
                if let Some(v) = self.stack.get(&off) {
                    result = result.join(v);
                }
            } else {
                for v in self.stack.values() {
                    result = result.join(v);
                }
            }
        }
        // Region reads.
        for (rid, off) in &addr.regions {
            match rid {
                MemRegionId::Heap(site) => {
                    if off.is_singleton() {
                        if let Some(v) = self.heap.get(site) {
                            result = result.join(v);
                        }
                    } else {
                        for v in self.heap.values() {
                            result = result.join(v);
                        }
                    }
                }
                MemRegionId::Global(ga) => {
                    if let Some(v) = self.globals.get(ga) {
                        result = result.join(v);
                    }
                }
                MemRegionId::Stack(_) | MemRegionId::Synthetic(_) => {
                    for v in self.heap.values() {
                        result = result.join(v);
                    }
                }
            }
        }
        if result.is_bottom() {
            RegionValueSet::top()
        } else {
            result
        }
    }

    // ── Lattice operations ─────────────────────────────────────────────────

    /// Point-wise join of two states (merge at a CFG join point).
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        let mut out = self.clone();
        for (k, v) in &other.regs {
            out.regs
                .entry(k.clone())
                .and_modify(|e| *e = e.join(v))
                .or_insert_with(|| v.clone());
        }
        for (k, v) in &other.stack {
            out.stack
                .entry(*k)
                .and_modify(|e| *e = e.join(v))
                .or_insert_with(|| v.clone());
        }
        for (k, v) in &other.heap {
            out.heap
                .entry(*k)
                .and_modify(|e| *e = e.join(v))
                .or_insert_with(|| v.clone());
        }
        for (k, v) in &other.globals {
            out.globals
                .entry(*k)
                .and_modify(|e| *e = e.join(v))
                .or_insert_with(|| v.clone());
        }
        out
    }

    /// Point-wise widening.
    #[must_use]
    pub fn widen(&self, other: &Self) -> Self {
        let mut out = self.clone();
        for (k, v) in &other.regs {
            out.regs
                .entry(k.clone())
                .and_modify(|e| *e = e.widen(v))
                .or_insert_with(|| v.clone());
        }
        for (k, v) in &other.stack {
            out.stack
                .entry(*k)
                .and_modify(|e| *e = e.widen(v))
                .or_insert_with(|| v.clone());
        }
        for (k, v) in &other.heap {
            out.heap
                .entry(*k)
                .and_modify(|e| *e = e.widen(v))
                .or_insert_with(|| v.clone());
        }
        for (k, v) in &other.globals {
            out.globals
                .entry(*k)
                .and_modify(|e| *e = e.widen(v))
                .or_insert_with(|| v.clone());
        }
        out
    }

    /// Point-wise narrowing (used after widening achieves fixpoint).
    #[must_use]
    pub fn narrow(&self, other: &Self) -> Self {
        let mut out = self.clone();
        for (k, v) in &other.regs {
            out.regs
                .entry(k.clone())
                .and_modify(|e| *e = e.narrow(v))
                .or_insert_with(|| v.clone());
        }
        for (k, v) in &other.stack {
            out.stack
                .entry(*k)
                .and_modify(|e| *e = e.narrow(v))
                .or_insert_with(|| v.clone());
        }
        for (k, v) in &other.heap {
            out.heap
                .entry(*k)
                .and_modify(|e| *e = e.narrow(v))
                .or_insert_with(|| v.clone());
        }
        for (k, v) in &other.globals {
            out.globals
                .entry(*k)
                .and_modify(|e| *e = e.narrow(v))
                .or_insert_with(|| v.clone());
        }
        out
    }

    /// Returns `true` when `self` subsumes `other` (fixpoint guard).
    #[must_use]
    pub fn leq(&self, other: &Self) -> bool {
        let check_map = |a: &HashMap<String, RegionValueSet>,
                         b: &HashMap<String, RegionValueSet>| {
            b.iter().all(|(k, bv)| {
                let av = a.get(k).cloned().unwrap_or_default();
                av.join(bv) == av
            })
        };
        let check_i64 = |a: &HashMap<i64, RegionValueSet>, b: &HashMap<i64, RegionValueSet>| {
            b.iter().all(|(k, bv)| {
                let av = a.get(k).cloned().unwrap_or_default();
                av.join(bv) == av
            })
        };
        let check_unsigned = |a: &HashMap<u64, RegionValueSet>, b: &HashMap<u64, RegionValueSet>| {
            b.iter().all(|(k, bv)| {
                let av = a.get(k).cloned().unwrap_or_default();
                av.join(bv) == av
            })
        };
        check_map(&self.regs, &other.regs)
            && check_i64(&self.stack, &other.stack)
            && check_unsigned(&self.heap, &other.heap)
            && check_unsigned(&self.globals, &other.globals)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SECTION 3 — VSA Transfer Functions (LLIL-like instruction set)
// ════════════════════════════════════════════════════════════════════════════
//
// A simplified Low-Level IL (LLIL) instruction set that the transfer-function
// engine can evaluate.  In production this would be connected to a real
// lifter; here we define a self-contained IR rich enough to cover the
// interesting cases for VSA (arithmetic, loads, stores, conditional branches).

/// A LLIL-style expression tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LlilExpr {
    /// Constant immediate value.
    Const(u64),
    /// Read a named register.
    Reg(String),
    /// `lhs + rhs`
    Add(Box<Self>, Box<Self>),
    /// `lhs - rhs`
    Sub(Box<Self>, Box<Self>),
    /// `lhs * rhs`
    Mul(Box<Self>, Box<Self>),
    /// `lhs & rhs`
    And(Box<Self>, Box<Self>),
    /// `lhs | rhs`
    Or(Box<Self>, Box<Self>),
    /// `lhs ^ rhs`
    Xor(Box<Self>, Box<Self>),
    /// `lhs << rhs` (logical)
    Shl(Box<Self>, Box<Self>),
    /// `lhs >> rhs` (logical)
    Shr(Box<Self>, Box<Self>),
    /// `lhs >> rhs` (arithmetic / signed)
    Sar(Box<Self>, Box<Self>),
    /// `*ptr` (load from memory)
    Load { ptr: Box<Self>, size: u8 },
    /// Zero-extend `expr` from `from_bits` bits.
    ZeroExt { expr: Box<Self>, from_bits: u8 },
    /// Sign-extend `expr` from `from_bits` bits.
    SignExt { expr: Box<Self>, from_bits: u8 },
}

/// A LLIL-style instruction (statement).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LlilInstruction {
    /// `dst_reg = expr`
    SetReg { dst: String, expr: LlilExpr },
    /// `*ptr = val` (memory store)
    Store {
        ptr: LlilExpr,
        val: LlilExpr,
        size: u8,
    },
    /// `if cond goto taken else fallthrough` (not modelled; state is unchanged)
    Branch { cond: LlilExpr },
    /// Unconditional jump.
    Jump { target: LlilExpr },
    /// Indirect call.
    Call { target: LlilExpr },
    /// Return.
    Return { val: Option<LlilExpr> },
    /// No-op.
    Nop,
}

/// Transfer-function evaluator for the LLIL expression/instruction set.
///
/// Evaluates expressions to `RegionValueSet`s against a `VsaStateV2` and
/// propagates the resulting abstract values.
pub struct VsaTransfer;

impl VsaTransfer {
    // ── Expression evaluation ──────────────────────────────────────────────

    /// Recursively evaluate a `LlilExpr` against `state`, returning the
    /// abstract value of the expression.
    #[must_use]
    pub fn eval_expr(expr: &LlilExpr, state: &VsaStateV2) -> RegionValueSet {
        match expr {
            LlilExpr::Const(v) => RegionValueSet::from_const(*v),

            LlilExpr::Reg(name) => state.read_reg(name),

            LlilExpr::Add(l, r) => {
                let lv = Self::eval_expr(l, state);
                let rv = Self::eval_expr(r, state);
                Self::eval_add(&lv, &rv)
            }

            LlilExpr::Sub(l, r) => {
                let lv = Self::eval_expr(l, state);
                let rv = Self::eval_expr(r, state);
                Self::eval_sub(&lv, &rv)
            }

            LlilExpr::Mul(l, r) => {
                let lv = Self::eval_expr(l, state);
                let rv = Self::eval_expr(r, state);
                Self::eval_binop(&lv, &rv, StridedInterval::mul)
            }

            LlilExpr::And(l, r) => {
                let lv = Self::eval_expr(l, state);
                let rv = Self::eval_expr(r, state);
                Self::eval_binop(&lv, &rv, StridedInterval::bitwise_and)
            }

            LlilExpr::Or(l, r) => {
                let lv = Self::eval_expr(l, state);
                let rv = Self::eval_expr(r, state);
                Self::eval_binop(&lv, &rv, StridedInterval::bitwise_or)
            }

            LlilExpr::Xor(l, r) => {
                let lv = Self::eval_expr(l, state);
                let rv = Self::eval_expr(r, state);
                Self::eval_binop(&lv, &rv, StridedInterval::bitwise_xor)
            }

            LlilExpr::Shl(l, r) => {
                let lv = Self::eval_expr(l, state);
                let rv = Self::eval_expr(r, state);
                Self::eval_binop(&lv, &rv, StridedInterval::shl)
            }

            LlilExpr::Shr(l, r) => {
                let lv = Self::eval_expr(l, state);
                let rv = Self::eval_expr(r, state);
                Self::eval_binop(&lv, &rv, StridedInterval::shr)
            }

            LlilExpr::Sar(l, r) => {
                let lv = Self::eval_expr(l, state);
                let rv = Self::eval_expr(r, state);
                Self::eval_binop(&lv, &rv, StridedInterval::sar)
            }

            LlilExpr::Load { ptr, size } => {
                let ptr_v = Self::eval_expr(ptr, state);
                state.read_mem(&ptr_v, *size)
            }

            LlilExpr::ZeroExt { expr, from_bits } => {
                let v = Self::eval_expr(expr, state);
                let bits = *from_bits;
                Self::map_global(v, |si| si.truncate(bits))
            }

            LlilExpr::SignExt { expr, from_bits } => {
                let v = Self::eval_expr(expr, state);
                let bits = *from_bits;
                Self::map_global(v, |si| si.sign_extend(bits))
            }
        }
    }

    // ── Instruction transfer ───────────────────────────────────────────────

    /// Apply a single `LlilInstruction` to `state`, returning the updated state.
    #[must_use]
    pub fn transfer_instr(instr: &LlilInstruction, state: &VsaStateV2) -> VsaStateV2 {
        match instr {
            LlilInstruction::SetReg { dst, expr } => {
                let val = Self::eval_expr(expr, state);
                let mut s = state.clone();
                s.assign_reg(dst, val);
                s
            }

            LlilInstruction::Store { ptr, val, size } => {
                let ptr_v = Self::eval_expr(ptr, state);
                let val_v = Self::eval_expr(val, state);
                let mut s = state.clone();
                s.write_mem(&ptr_v, val_v, *size);
                s
            }

            // Branches, calls, jumps, and returns do not modify the abstract
            // register/memory state in this simplified model.
            LlilInstruction::Branch { .. }
            | LlilInstruction::Jump { .. }
            | LlilInstruction::Call { .. }
            | LlilInstruction::Return { .. }
            | LlilInstruction::Nop => state.clone(),
        }
    }

    /// Apply a sequence of instructions to `state`.
    #[must_use]
    pub fn transfer_block(instrs: &[LlilInstruction], state: &VsaStateV2) -> VsaStateV2 {
        instrs
            .iter()
            .fold(state.clone(), |s, i| Self::transfer_instr(i, &s))
    }

    // ── Arithmetic helpers ─────────────────────────────────────────────────

    /// Add two `RegionValueSet`s.
    ///
    /// * integer + integer → integer arithmetic.
    /// * pointer + integer → shift the pointer's offset.
    /// * integer + pointer → shift the pointer's offset (commutative).
    /// * pointer + pointer → conservative `Top` (not a valid address).
    #[must_use]
    pub fn eval_add(lhs: &RegionValueSet, rhs: &RegionValueSet) -> RegionValueSet {
        match (&lhs.global, &rhs.global) {
            (Some(a), Some(b)) if lhs.regions.is_empty() && rhs.regions.is_empty() => {
                // Pure integer addition.
                RegionValueSet {
                    global: Some(a.add(b)),
                    regions: HashMap::new(),
                }
            }
            _ => {
                // At least one side is a pointer.  Identify which is the
                // pointer and which is the integer offset.
                let (ptr_side, int_side) = if lhs.regions.is_empty() {
                    (&rhs, &lhs)
                } else {
                    (&lhs, &rhs)
                };
                // If the integer side has a global component use it as offset.
                let delta = int_side.global.unwrap_or(StridedInterval::singleton(0));
                let regions = ptr_side
                    .regions
                    .iter()
                    .map(|(rid, off)| (rid.clone(), off.add(&delta)))
                    .collect();
                let global = ptr_side.global.map(|g| g.add(&delta));
                RegionValueSet { global, regions }
            }
        }
    }

    /// Subtract two `RegionValueSet`s.
    ///
    /// * pointer − integer → shift the pointer's offset backward.
    /// * pointer − pointer (same region) → integer difference.
    /// * anything else → conservative `Top`.
    #[must_use]
    pub fn eval_sub(lhs: &RegionValueSet, rhs: &RegionValueSet) -> RegionValueSet {
        // Both are pure integers.
        if lhs.regions.is_empty() && rhs.regions.is_empty() {
            let global = match (&lhs.global, &rhs.global) {
                (Some(a), Some(b)) => Some(a.sub(b)),
                _ => None,
            };
            return RegionValueSet {
                global,
                regions: HashMap::new(),
            };
        }
        // pointer − integer.
        if !lhs.regions.is_empty() && rhs.regions.is_empty() {
            let delta = rhs.global.unwrap_or(StridedInterval::singleton(0));
            let regions = lhs
                .regions
                .iter()
                .map(|(rid, off)| (rid.clone(), off.sub(&delta)))
                .collect();
            let global = lhs.global.map(|g| g.sub(&delta));
            return RegionValueSet { global, regions };
        }
        // pointer − pointer (same unique region) → integer difference.
        if let (1, 1, Some((rid_a, off_a)), Some((rid_b, off_b))) = (
            lhs.regions.len(),
            rhs.regions.len(),
            lhs.regions.iter().next(),
            rhs.regions.iter().next(),
        ) && rid_a == rid_b
        {
            return RegionValueSet {
                global: Some(off_a.sub(off_b)),
                regions: HashMap::new(),
            };
        }
        RegionValueSet::top()
    }

    // ── Private helpers ────────────────────────────────────────────────────

    /// Apply a binary `StridedInterval` operation to the global components of
    /// two `RegionValueSet`s.  Region components are dropped (conservative).
    fn eval_binop<F>(lhs: &RegionValueSet, rhs: &RegionValueSet, op: F) -> RegionValueSet
    where
        F: Fn(&StridedInterval, &StridedInterval) -> StridedInterval,
    {
        let global = match (&lhs.global, &rhs.global) {
            (Some(a), Some(b)) => Some(op(a, b)),
            _ => Some(StridedInterval::TOP),
        };
        RegionValueSet {
            global,
            regions: HashMap::new(),
        }
    }

    /// Apply a unary `StridedInterval` operation to the global component.
    fn map_global<F>(vs: RegionValueSet, op: F) -> RegionValueSet
    where
        F: Fn(StridedInterval) -> StridedInterval,
    {
        let global = vs.global.map(op);
        RegionValueSet {
            global,
            regions: vs.regions,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SECTION 4 — Full Fixpoint Computation Engine
// ════════════════════════════════════════════════════════════════════════════
//
// A worklist-based dataflow engine that operates over `VsaStateV2` with
// proper widening / narrowing phases.

/// Identifier for a basic block in the full VSA CFG.
pub type BbId = usize;

/// A basic block in the full LLIL CFG used by `VsaEngineV2`.
#[derive(Debug, Clone)]
pub struct LlilBlock {
    /// Block identifier (0-based index into the CFG's block list).
    pub id: BbId,
    /// The instructions in this block (in order).
    pub instrs: Vec<LlilInstruction>,
}

/// A CFG of `LlilBlock`s for the full VSA engine.
#[derive(Debug, Clone)]
pub struct LlilCfg {
    /// All blocks, indexed by `BbId`.
    pub blocks: Vec<LlilBlock>,
    /// Successor edges: `succs[i]` lists the block-ids that follow block `i`.
    pub succs: Vec<Vec<BbId>>,
    /// Predecessor edges (derived automatically on construction).
    pub preds: Vec<Vec<BbId>>,
    /// Entry block id.
    pub entry: BbId,
    /// Back-edges (source, destination) indicating loop headers.
    /// Used to choose between `join` and `widen` at merge points.
    pub back_edges: HashSet<(BbId, BbId)>,
}

impl LlilCfg {
    /// Build a `LlilCfg` from blocks, successors, entry, and an optional set
    /// of pre-identified back-edges.  If `back_edges` is `None` the constructor
    /// runs a simple DFS to detect them automatically.
    #[must_use]
    pub fn new(
        blocks: Vec<LlilBlock>,
        succs: Vec<Vec<BbId>>,
        entry: BbId,
        back_edges: Option<HashSet<(BbId, BbId)>>,
    ) -> Self {
        let n = blocks.len();
        let mut preds = vec![Vec::new(); n];
        for (src, ss) in succs.iter().enumerate() {
            for &dst in ss {
                if dst < n {
                    preds[dst].push(src);
                }
            }
        }
        let back_edges = back_edges.unwrap_or_else(|| detect_back_edges(&succs, entry, n));
        Self {
            blocks,
            succs,
            preds,
            entry,
            back_edges,
        }
    }

    /// Returns `true` when the edge `(src, dst)` is a back-edge.
    #[must_use]
    pub fn is_back_edge(&self, src: BbId, dst: BbId) -> bool {
        self.back_edges.contains(&(src, dst))
    }
}

/// Detect back-edges in a CFG using iterative DFS.
fn detect_back_edges(succs: &[Vec<BbId>], entry: BbId, n: usize) -> HashSet<(BbId, BbId)> {
    let mut back = HashSet::new();
    if n == 0 || entry >= n {
        return back;
    }
    let mut color = vec![0u8; n]; // 0=white, 1=grey, 2=black
    let mut stack: Vec<(BbId, usize)> = vec![(entry, 0)];
    color[entry] = 1;
    // Sentinel for missing successor rows.
    let empty_succ: Vec<BbId> = Vec::new();
    while let Some((u, idx)) = stack.last_mut() {
        let u = *u;
        let u_succs: &Vec<BbId> = succs.get(u).unwrap_or(&empty_succ);
        if *idx < u_succs.len() {
            let v = u_succs[*idx];
            *idx += 1;
            if v >= n {
                continue;
            }
            if color[v] == 1 {
                back.insert((u, v));
            } else if color[v] == 0 {
                color[v] = 1;
                stack.push((v, 0));
            }
        } else {
            color[u] = 2;
            stack.pop();
        }
    }
    back
}

/// Configuration for `VsaEngineV2`.
#[derive(Debug, Clone)]
pub struct VsaConfig {
    /// Number of times a block must be visited before widening is applied.
    pub widen_threshold: u32,
    /// Number of narrowing passes after the widening fixpoint.
    pub narrow_iterations: u32,
    /// Maximum total worklist steps before giving up.
    pub iteration_budget: usize,
}

impl Default for VsaConfig {
    fn default() -> Self {
        Self {
            widen_threshold: 3,
            narrow_iterations: 0,
            iteration_budget: 200_000,
        }
    }
}

/// Result of `VsaEngineV2::analyze`.
#[derive(Debug, Clone)]
pub struct VsaEngineResult {
    /// Abstract state at the *entry* of each block (before executing the block).
    pub states_before: HashMap<BbId, VsaStateV2>,
    /// Abstract state at the *exit* of each block (after executing the block).
    pub states_after: HashMap<BbId, VsaStateV2>,
    /// Whether the analysis converged within the budget.
    pub converged: bool,
    /// Total number of worklist iterations.
    pub iterations: usize,
}

impl VsaEngineResult {
    /// Look up the abstract value of `reg` at the entry of `bb`.
    #[must_use]
    pub fn reg_before(&self, bb: BbId, reg: &str) -> RegionValueSet {
        self.states_before
            .get(&bb)
            .map(|s| s.read_reg(reg))
            .unwrap_or_default()
    }

    /// Look up the abstract value of `reg` at the exit of `bb`.
    #[must_use]
    pub fn reg_after(&self, bb: BbId, reg: &str) -> RegionValueSet {
        self.states_after
            .get(&bb)
            .map(|s| s.read_reg(reg))
            .unwrap_or_default()
    }

    /// Resolve indirect jump targets: extract the concrete addresses from the
    /// abstract value of `reg` at the exit of `bb`.
    ///
    /// Returns an empty `Vec` when the value-set is `Top` or too wide.
    #[must_use]
    pub fn get_jump_targets(&self, bb: BbId, reg: &str, max_targets: usize) -> Vec<u64> {
        let vs = self.reg_after(bb, reg);
        let si = vs.global.unwrap_or(StridedInterval::TOP);
        si.concretize(max_targets).unwrap_or_default()
    }

    /// Returns `true` when the memory access `reg + 0 .. size` is provably
    /// within `bounds = (base, limit)`.
    #[must_use]
    pub fn is_access_safe(&self, bb: BbId, reg: &str, size: u8, bounds: (u64, u64)) -> bool {
        let vs = self.reg_before(bb, reg);
        let si = vs.global.unwrap_or(StridedInterval::TOP);
        let (base, limit) = bounds;
        !si.is_top() && si.lo >= base && si.hi.saturating_add(u64::from(size)) <= limit
    }
}

/// The full VSA fixpoint engine operating over `VsaStateV2`.
///
/// Algorithm:
/// 1. Initialise all blocks with `Bottom`; set entry to `entry_state`.
/// 2. Push all blocks onto the worklist.
/// 3. For each block `b`:
///    a. Merge predecessors' exit-states with `join`.
///    b. On back-edges: use `widen` after `widen_threshold` visits.
///    c. Run `VsaTransfer::transfer_block` to get the exit state.
///    d. If exit state changed, push successors onto the worklist.
/// 4. After convergence: run `narrow_iterations` passes of narrowing.
pub struct VsaEngineV2 {
    /// Entry-block initial state.
    pub entry_state: VsaStateV2,
    /// Analysis configuration.
    pub config: VsaConfig,
}

impl VsaEngineV2 {
    /// Create a `VsaEngineV2` with default configuration.
    #[must_use]
    pub fn new(entry_state: VsaStateV2) -> Self {
        Self {
            entry_state,
            config: VsaConfig::default(),
        }
    }

    /// Create a `VsaEngineV2` with custom configuration.
    #[must_use]
    pub const fn with_config(entry_state: VsaStateV2, config: VsaConfig) -> Self {
        Self {
            entry_state,
            config,
        }
    }

    /// Run Value-Set Analysis over `cfg`.
    ///
    /// # Errors
    ///
    /// Returns [`VsaError::EmptyProgram`] when `cfg.blocks` is empty.
    /// Returns [`VsaError::NoConvergence`] when the iteration budget is exceeded.
    pub fn analyze(&self, cfg: &LlilCfg) -> Result<VsaEngineResult, VsaError> {
        if cfg.blocks.is_empty() {
            return Err(VsaError::EmptyProgram);
        }
        let n = cfg.blocks.len();

        // Initialise: all blocks start with Bottom.
        let mut states_in: HashMap<BbId, VsaStateV2> = HashMap::new();
        states_in.insert(cfg.entry, self.entry_state.clone());

        let mut states_out: HashMap<BbId, VsaStateV2> = HashMap::new();

        // Visit counters per block (for widening threshold).
        let mut visit_count = vec![0u32; n];

        // Worklist: start with the entry block.
        let mut worklist: VecDeque<BbId> = VecDeque::new();
        let mut in_wl = vec![false; n];
        worklist.push_back(cfg.entry);
        in_wl[cfg.entry] = true;

        let mut total_iters = 0usize;
        let mut converged = true;

        while let Some(bid) = worklist.pop_front() {
            in_wl[bid] = false;
            total_iters += 1;
            if total_iters > self.config.iteration_budget {
                converged = false;
                break;
            }

            // Merge all predecessor exit-states.
            // For the entry block (no predecessors) we keep the injected entry
            // state; for every other block we start from Bottom and join all
            // predecessor exit-states so each predecessor contributes exactly once.
            let fold_init = if cfg.preds[bid].is_empty() {
                states_in.get(&bid).cloned().unwrap_or_default()
            } else {
                VsaStateV2::default()
            };
            let merged_in = cfg.preds[bid].iter().fold(fold_init, |acc, &pred| {
                let pred_out = states_out.get(&pred).cloned().unwrap_or_default();
                // Use widening on back-edges after threshold visits.
                if cfg.is_back_edge(pred, bid)
                    && visit_count[bid] >= self.config.widen_threshold
                {
                    acc.widen(&pred_out)
                } else {
                    acc.join(&pred_out)
                }
            });

            visit_count[bid] += 1;

            // Compute exit state.
            let new_out = VsaTransfer::transfer_block(&cfg.blocks[bid].instrs, &merged_in);

            // Check for change.
            let old_out = states_out.get(&bid).cloned().unwrap_or_default();
            let changed = !old_out.leq(&new_out);

            states_in.insert(bid, merged_in);
            states_out.insert(bid, new_out);

            if changed {
                for &succ in &cfg.succs[bid] {
                    if succ < n && !in_wl[succ] {
                        in_wl[succ] = true;
                        worklist.push_back(succ);
                    }
                }
            }
        }

        // ── Narrowing phase ────────────────────────────────────────────────
        // Run `narrow_iterations` additional passes to refine the over-
        // approximation produced by widening.
        for _ in 0..self.config.narrow_iterations {
            let mut any_change = false;
            for bid in 0..n {
                let current_in = states_in.get(&bid).cloned().unwrap_or_default();
                // Compute a narrowed input state.
                let narrowed_in = cfg.preds[bid]
                    .iter()
                    .fold(current_in.clone(), |acc, &pred| {
                        let pred_out = states_out.get(&pred).cloned().unwrap_or_default();
                        acc.narrow(&pred_out)
                    });
                let new_out = VsaTransfer::transfer_block(&cfg.blocks[bid].instrs, &narrowed_in);
                let old_out = states_out.get(&bid).cloned().unwrap_or_default();
                if old_out.leq(&new_out) {
                    any_change = true;
                    states_in.insert(bid, narrowed_in);
                    states_out.insert(bid, new_out);
                }
            }
            if !any_change {
                break;
            }
        }

        Ok(VsaEngineResult {
            states_before: states_in,
            states_after: states_out,
            converged,
            iterations: total_iters,
        })
    }

    /// Convenience: analyse and return only the `states_after` map.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`VsaEngineV2::analyze`].
    pub fn analyze_states_after(
        &self,
        cfg: &LlilCfg,
    ) -> Result<HashMap<BbId, VsaStateV2>, VsaError> {
        self.analyze(cfg).map(|r| r.states_after)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SECTION 5 — Jump-Table Resolution and Indirect Call Resolution
// ════════════════════════════════════════════════════════════════════════════

/// Information extracted about a jump table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpTableInfo {
    /// Address of the indirect jump instruction.
    pub jump_addr: u64,
    /// The name of the index register (e.g. `"rax"`).
    pub index_reg: String,
    /// The abstract value-set of the index register at the jump site.
    pub index_vs: StridedInterval,
    /// The base address of the jump table in memory.
    pub table_base: u64,
    /// Element size in bytes (4 for 32-bit targets, 8 for 64-bit).
    pub entry_size: u8,
    /// Resolved concrete jump targets (after reading from `table_base`).
    pub targets: Vec<u64>,
    /// Whether the resolution is complete (all entries read successfully).
    pub complete: bool,
}

/// Abstract binary-view interface used by the jump-table resolver.
///
/// In production this is backed by the real `BinaryView`; in tests it is a
/// simple `HashMap<u64, u8>`.
pub trait BinaryMemory: Send + Sync {
    /// Read `size` bytes starting at `addr`.  Returns `None` on failure.
    fn read_bytes(&self, addr: u64, size: usize) -> Option<Vec<u8>>;
}

/// A `BinaryMemory` backed by an in-memory byte map (used in tests).
pub struct MapBinaryMemory(pub HashMap<u64, u8>);

impl BinaryMemory for MapBinaryMemory {
    fn read_bytes(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        (0..size as u64)
            // checked_add: an adversarial `addr` near u64::MAX must fail the
            // read, not wrap around and silently return bytes from address 0.
            .map(|i| self.0.get(&addr.checked_add(i)?).copied())
            .collect()
    }
}

/// Read a little-endian `u32` from `mem` at `addr`.
fn read_u32_le(mem: &dyn BinaryMemory, addr: u64) -> Option<u32> {
    let bytes = mem.read_bytes(addr, 4)?;
    // `BinaryMemory` is a pub trait: a short-read implementation must yield
    // None here, not an out-of-bounds panic on bytes[3].
    let b: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

/// Read a little-endian `u64` from `mem` at `addr`.
fn read_u64_le(mem: &dyn BinaryMemory, addr: u64) -> Option<u64> {
    let bytes = mem.read_bytes(addr, 8)?;
    let b: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(b))
}

/// Resolve a jump table given VSA results and binary memory.
///
/// 1. Look up the abstract value of `index_reg` at the exit of `jump_bb`.
/// 2. Compute the number of table entries from the upper bound.
/// 3. For each index `k` in `[0, upper_bound]`, read `table_base + k * entry_size`
///    from `mem` and collect the resulting addresses.
/// 4. Filter entries that fall outside `[code_base, code_limit)`.
#[must_use]
pub fn resolve_jump_table(
    vsa: &VsaEngineResult,
    jump_bb: BbId,
    index_reg: &str,
    table_base: u64,
    entry_size: u8,
    code_range: (u64, u64),
    mem: &dyn BinaryMemory,
) -> JumpTableInfo {
    let vs = vsa.reg_after(jump_bb, index_reg);
    let index_vs = vs.global.unwrap_or(StridedInterval::TOP);
    let (code_base, code_limit) = code_range;

    // Determine the upper bound (number of entries = upper_bound + 1).
    let upper_bound = if index_vs.is_top() || index_vs.is_bottom() {
        // Cannot determine: try a heuristic cap of 256 entries.
        255u64
    } else {
        index_vs.upper_bound()
    };

    let count = upper_bound.saturating_add(1).min(4096) as usize;
    let mut targets = Vec::with_capacity(count);
    let mut complete = true;

    for k in 0..count {
        let entry_addr = table_base.wrapping_add(k as u64 * u64::from(entry_size));
        let target = match entry_size {
            4 => read_u32_le(mem, entry_addr).map(u64::from),
            _ => read_u64_le(mem, entry_addr),
        };
        match target {
            Some(t) if t >= code_base && t < code_limit => {
                targets.push(t);
            }
            Some(_) => {
                // Address out of code range; stop early (heuristic).
                complete = false;
                break;
            }
            None => {
                complete = false;
                break;
            }
        }
    }

    targets.sort_unstable();
    targets.dedup();

    JumpTableInfo {
        jump_addr: 0, // caller fills in the actual address
        index_reg: index_reg.to_owned(),
        index_vs,
        table_base,
        entry_size,
        targets,
        complete,
    }
}

/// Resolve all indirect call targets from VSA results.
///
/// For each indirect call in `cfg` at block `bb` that uses `target_reg`:
/// 1. Obtain the abstract value of `target_reg` at the exit of `bb`.
/// 2. Enumerate concrete values (up to `max_targets`).
/// 3. Filter addresses that fall inside `code_range`.
///
/// Returns a map from `(bb_id, target_reg_name)` to the resolved target list.
#[must_use]
pub fn resolve_indirect_calls(
    vsa: &VsaEngineResult,
    cfg: &LlilCfg,
    code_range: (u64, u64),
    max_targets: usize,
) -> HashMap<(BbId, String), Vec<u64>> {
    let (code_base, code_limit) = code_range;
    let mut result: HashMap<(BbId, String), Vec<u64>> = HashMap::new();

    for block in &cfg.blocks {
        for instr in &block.instrs {
            if let LlilInstruction::Call { target } | LlilInstruction::Jump { target } = instr
                && let LlilExpr::Reg(reg) = target {
                    let vs = vsa.reg_after(block.id, reg);
                    let si = vs.global.unwrap_or(StridedInterval::TOP);
                    let targets: Vec<u64> = si
                        .concretize(max_targets)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|&a| a >= code_base && a < code_limit)
                        .collect();
                    result.insert((block.id, reg.clone()), targets);
                }
        }
    }
    result
}

/// Detect potential buffer overflows by checking whether a pointer register
/// may index out of its known bounds at a given block's exit state.
///
/// For each `Store` instruction that uses `ptr_reg` as the destination
/// pointer, checks whether `ptr_reg + 0..access_size` stays within `bounds`.
///
/// Returns a list of `(bb_id, message)` pairs for each potential overflow.
#[must_use]
pub fn detect_buffer_overflows(
    vsa: &VsaEngineResult,
    cfg: &LlilCfg,
    ptr_reg: &str,
    access_size: u8,
    bounds: (u64, u64),
) -> Vec<(BbId, String)> {
    let mut warnings = Vec::new();
    let (base, limit) = bounds;

    for block in &cfg.blocks {
        for instr in &block.instrs {
            if let LlilInstruction::Store { ptr, .. } = instr
                && let LlilExpr::Reg(reg) = ptr
                    && reg == ptr_reg {
                        let vs = vsa.reg_before(block.id, reg);
                        let si = vs.global.unwrap_or(StridedInterval::TOP);
                        if si.is_top() {
                            warnings.push((
                                block.id,
                                format!("store via {reg}: pointer is Top (fully unknown)"),
                            ));
                        } else if si.lo < base || si.hi.saturating_add(u64::from(access_size)) >= limit {
                            warnings.push((
                                block.id,
                                format!(
                                    "store via {reg}: [{:#x},{:#x}] may exceed bounds [{base:#x},{limit:#x})",
                                    si.lo, si.hi
                                ),
                            ));
                        }
                    }
        }
    }
    warnings
}

// ════════════════════════════════════════════════════════════════════════════
// SECTION 6 — Additional tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests_v2 {
    use super::*;

    // ── BinaryMemory reader hardening ─────────────────────────────────────

    /// A hostile `BinaryMemory` that violates the size contract: it always
    /// returns fewer bytes than requested. The pub-trait readers must map
    /// that to `None`, never to an out-of-bounds panic.
    struct ShortReadMemory;
    impl BinaryMemory for ShortReadMemory {
        fn read_bytes(&self, _addr: u64, _size: usize) -> Option<Vec<u8>> {
            Some(vec![0xAA])
        }
    }

    #[test]
    fn read_le_short_read_is_none_not_panic() {
        assert_eq!(read_u32_le(&ShortReadMemory, 0x1000), None);
        assert_eq!(read_u64_le(&ShortReadMemory, 0x1000), None);
    }

    #[test]
    fn map_memory_near_u64_max_does_not_wrap_to_zero() {
        // Bytes exist at addresses 0..=3; a 4-byte read at u64::MAX-1 must
        // fail, not wrap around and return the bytes stored at 0/1/2.
        let mut m = HashMap::new();
        for a in 0u64..4 {
            m.insert(a, 0x41u8);
        }
        m.insert(u64::MAX - 1, 0x42u8);
        m.insert(u64::MAX, 0x42u8);
        let mem = MapBinaryMemory(m);
        assert_eq!(read_u32_le(&mem, u64::MAX - 1), None);
        assert_eq!(read_u64_le(&mem, u64::MAX - 1), None);
        // Sanity: an in-range read still works.
        assert_eq!(read_u32_le(&mem, 0), Some(0x4141_4141));
    }

    // ── StridedInterval new operations ────────────────────────────────────

    #[test]
    fn test_si_mul_singletons() {
        let a = StridedInterval::singleton(6);
        let b = StridedInterval::singleton(7);
        assert_eq!(a.mul(&b), StridedInterval::singleton(42));
    }

    #[test]
    fn test_si_mul_range() {
        let a = StridedInterval::new(1, 4, 1); // 1,2,3,4
        let b = StridedInterval::singleton(3);
        let r = a.mul(&b); // 3,6,9,12
        assert_eq!(r.lo, 3);
        assert_eq!(r.hi, 12);
    }

    #[test]
    fn test_si_mul_overflow_top() {
        let a = StridedInterval::singleton(u64::MAX);
        let b = StridedInterval::singleton(2);
        assert!(a.mul(&b).is_top());
    }

    #[test]
    fn test_si_xor_singletons() {
        let a = StridedInterval::singleton(0b1010);
        let b = StridedInterval::singleton(0b1100);
        assert_eq!(a.bitwise_xor(&b), StridedInterval::singleton(0b0110));
    }

    #[test]
    fn test_si_xor_conservative() {
        let a = StridedInterval::new(0, 0xFF, 1);
        let b = StridedInterval::new(0, 0xFF, 1);
        let r = a.bitwise_xor(&b);
        assert!(!r.is_bottom());
        assert!(r.hi <= 0xFF);
    }

    #[test]
    fn test_si_shl_singleton() {
        let a = StridedInterval::singleton(1);
        let b = StridedInterval::singleton(4);
        assert_eq!(a.shl(&b), StridedInterval::singleton(16));
    }

    #[test]
    fn test_si_shl_range() {
        let a = StridedInterval::new(1, 4, 1);
        let b = StridedInterval::singleton(2); // shift left 2
        let r = a.shl(&b);
        // 1<<2=4, 4<<2=16
        assert_eq!(r.lo, 4);
        assert_eq!(r.hi, 16);
    }

    #[test]
    fn test_si_shr_singleton() {
        let a = StridedInterval::singleton(256);
        let b = StridedInterval::singleton(4);
        assert_eq!(a.shr(&b), StridedInterval::singleton(16));
    }

    #[test]
    fn test_si_sar_positive() {
        let a = StridedInterval::singleton(100i64 as u64);
        let b = StridedInterval::singleton(2);
        assert_eq!(a.sar(&b), StridedInterval::singleton(25));
    }

    #[test]
    fn test_si_sar_negative() {
        let a = StridedInterval::singleton(-8i64 as u64);
        let b = StridedInterval::singleton(1);
        // -8 >> 1 = -4 (arithmetic)
        assert_eq!(a.sar(&b), StridedInterval::singleton(-4i64 as u64));
    }

    #[test]
    fn test_si_narrow_tightens() {
        let wide = StridedInterval::new(0, 100, 1);
        let tight = StridedInterval::new(10, 50, 1);
        let n = wide.narrow(&tight);
        assert!(n.lo >= wide.lo);
        assert!(n.hi <= wide.hi);
    }

    #[test]
    fn test_si_narrow_top_gives_other() {
        let top = StridedInterval::TOP;
        let si = StridedInterval::new(5, 10, 1);
        assert_eq!(top.narrow(&si), si);
    }

    #[test]
    fn test_si_upper_bound() {
        assert_eq!(StridedInterval::new(2, 10, 2).upper_bound(), 10);
        assert_eq!(StridedInterval::BOTTOM.upper_bound(), 0);
    }

    #[test]
    fn test_si_size() {
        assert_eq!(StridedInterval::new(0, 8, 2).size(), Some(5)); // 0,2,4,6,8
        assert_eq!(StridedInterval::BOTTOM.size(), Some(0));
        assert_eq!(StridedInterval::TOP.size(), None);
    }

    #[test]
    fn test_si_singleton_value() {
        assert_eq!(StridedInterval::singleton(42).singleton_value(), Some(42));
        assert_eq!(StridedInterval::new(0, 4, 2).singleton_value(), None);
    }

    #[test]
    fn test_si_truncate() {
        assert_eq!(
            StridedInterval::singleton(0x1FF).truncate(8),
            StridedInterval::singleton(0xFF)
        );
        assert_eq!(
            StridedInterval::singleton(0x00).truncate(8),
            StridedInterval::singleton(0)
        );
    }

    #[test]
    fn test_si_truncate_range_conservative() {
        let si = StridedInterval::new(0, 0x200, 1);
        let t = si.truncate(8);
        // Conservative: [0, 0xFF]
        assert_eq!(t.hi, 0xFF);
    }

    #[test]
    fn test_si_sign_extend_positive() {
        // 0x7F sign-extended from 8 bits stays positive.
        assert_eq!(
            StridedInterval::singleton(0x7F).sign_extend(8),
            StridedInterval::singleton(0x7F)
        );
    }

    #[test]
    fn test_si_sign_extend_negative() {
        // 0xFF (= -1 in 8-bit) sign-extended to 64 bits = 0xFFFF...FFFF.
        let si = StridedInterval::singleton(0xFF).sign_extend(8);
        assert_eq!(si.lo, (-1i64) as u64);
    }

    #[test]
    fn test_si_definitely_lt() {
        let a = StridedInterval::new(0, 5, 1);
        let b = StridedInterval::new(10, 20, 1);
        assert!(a.definitely_lt(&b));
        assert!(!b.definitely_lt(&a));
    }

    #[test]
    fn test_si_may_equal() {
        let a = StridedInterval::new(0, 10, 1);
        let b = StridedInterval::new(5, 15, 1);
        assert!(a.may_equal(&b));
        let c = StridedInterval::new(20, 30, 1);
        assert!(!a.may_equal(&c));
    }

    // ── RegionValueSet ─────────────────────────────────────────────────────

    #[test]
    fn test_rvs_from_const() {
        let v = RegionValueSet::from_const(42);
        assert!(v.is_integer());
        let si = v.global.unwrap();
        assert_eq!(si, StridedInterval::singleton(42));
    }

    #[test]
    fn test_rvs_pointer() {
        let rid = MemRegionId::Stack(0x4000);
        let v = RegionValueSet::pointer(rid.clone(), StridedInterval::singleton(8));
        assert!(v.is_pointer());
        assert!(!v.is_integer());
        assert_eq!(*v.regions.get(&rid).unwrap(), StridedInterval::singleton(8));
    }

    #[test]
    fn test_rvs_top_bottom() {
        assert!(!RegionValueSet::top().is_bottom());
        assert!(RegionValueSet::bottom().is_bottom());
    }

    #[test]
    fn test_rvs_join() {
        let a = RegionValueSet::from_const(10);
        let b = RegionValueSet::from_const(20);
        let j = a.join(&b);
        let si = j.global.unwrap();
        assert!(si.contains(10));
        assert!(si.contains(20));
    }

    #[test]
    fn test_rvs_add_offset() {
        let v = RegionValueSet::from_const(100);
        let shifted = v.add_offset(8);
        assert_eq!(shifted.global.unwrap(), StridedInterval::singleton(108));
    }

    #[test]
    fn test_rvs_add_offset_negative() {
        let v = RegionValueSet::from_const(100);
        let shifted = v.add_offset(-4);
        assert_eq!(shifted.global.unwrap(), StridedInterval::singleton(96));
    }

    #[test]
    fn test_rvs_may_alias_same_region() {
        let rid = MemRegionId::Heap(0x1000);
        let a = RegionValueSet::pointer(rid.clone(), StridedInterval::singleton(0));
        let b = RegionValueSet::pointer(rid, StridedInterval::new(0, 8, 4));
        assert!(a.may_alias(&b));
    }

    #[test]
    fn test_rvs_may_alias_different_regions() {
        let ra = MemRegionId::Heap(0x1000);
        let rb = MemRegionId::Heap(0x2000);
        let a = RegionValueSet::pointer(ra, StridedInterval::singleton(0));
        let b = RegionValueSet::pointer(rb, StridedInterval::singleton(0));
        assert!(!a.may_alias(&b));
    }

    #[test]
    fn test_rvs_must_alias() {
        let rid = MemRegionId::Global(0x5000);
        let a = RegionValueSet::pointer(rid.clone(), StridedInterval::singleton(16));
        let b = RegionValueSet::pointer(rid, StridedInterval::singleton(16));
        assert!(a.must_alias(&b));
    }

    #[test]
    fn test_rvs_must_alias_fails_range() {
        let rid = MemRegionId::Global(0x5000);
        let a = RegionValueSet::pointer(rid.clone(), StridedInterval::new(0, 8, 4));
        let b = RegionValueSet::pointer(rid, StridedInterval::new(0, 8, 4));
        assert!(!a.must_alias(&b)); // non-singleton → no must-alias
    }

    // ── VsaStateV2 ─────────────────────────────────────────────────────────

    #[test]
    fn test_state_v2_read_write_reg() {
        let mut s = VsaStateV2::new();
        s.assign_reg("rax", RegionValueSet::from_const(0xDEAD));
        assert_eq!(
            s.read_reg("rax").global.unwrap(),
            StridedInterval::singleton(0xDEAD)
        );
    }

    #[test]
    fn test_state_v2_read_unknown_reg() {
        let s = VsaStateV2::new();
        assert!(s.read_reg("rbx").is_bottom());
    }

    #[test]
    fn test_state_v2_write_read_stack() {
        let mut s = VsaStateV2::new();
        let addr = RegionValueSet::from_const(0x7ff0_u64);
        s.write_mem(&addr, RegionValueSet::from_const(42), 8);
        let loaded = s.read_mem(&addr, 8);
        assert_eq!(loaded.global.unwrap(), StridedInterval::singleton(42));
    }

    #[test]
    fn test_state_v2_join_regs() {
        let mut a = VsaStateV2::new();
        a.assign_reg("r0", RegionValueSet::from_const(1));
        let mut b = VsaStateV2::new();
        b.assign_reg("r0", RegionValueSet::from_const(2));
        let j = a.join(&b);
        let si = j.read_reg("r0").global.unwrap();
        assert!(si.contains(1) && si.contains(2));
    }

    // ── VsaTransfer ────────────────────────────────────────────────────────

    #[test]
    fn test_transfer_const_set_reg() {
        let s = VsaStateV2::new();
        let instr = LlilInstruction::SetReg {
            dst: "rax".to_owned(),
            expr: LlilExpr::Const(0x1234),
        };
        let s2 = VsaTransfer::transfer_instr(&instr, &s);
        assert_eq!(
            s2.read_reg("rax").global.unwrap(),
            StridedInterval::singleton(0x1234)
        );
    }

    #[test]
    fn test_transfer_add_regs() {
        let mut s = VsaStateV2::new();
        s.assign_reg("r1", RegionValueSet::from_const(10));
        s.assign_reg("r2", RegionValueSet::from_const(20));
        let instr = LlilInstruction::SetReg {
            dst: "r3".to_owned(),
            expr: LlilExpr::Add(
                Box::new(LlilExpr::Reg("r1".to_owned())),
                Box::new(LlilExpr::Reg("r2".to_owned())),
            ),
        };
        let s2 = VsaTransfer::transfer_instr(&instr, &s);
        assert_eq!(
            s2.read_reg("r3").global.unwrap(),
            StridedInterval::singleton(30)
        );
    }

    #[test]
    fn test_transfer_sub_regs() {
        let mut s = VsaStateV2::new();
        s.assign_reg("r1", RegionValueSet::from_const(50));
        s.assign_reg("r2", RegionValueSet::from_const(15));
        let instr = LlilInstruction::SetReg {
            dst: "r3".to_owned(),
            expr: LlilExpr::Sub(
                Box::new(LlilExpr::Reg("r1".to_owned())),
                Box::new(LlilExpr::Reg("r2".to_owned())),
            ),
        };
        let s2 = VsaTransfer::transfer_instr(&instr, &s);
        assert_eq!(
            s2.read_reg("r3").global.unwrap(),
            StridedInterval::singleton(35)
        );
    }

    #[test]
    fn test_transfer_mul() {
        let mut s = VsaStateV2::new();
        s.assign_reg("a", RegionValueSet::from_const(7));
        s.assign_reg("b", RegionValueSet::from_const(6));
        let instr = LlilInstruction::SetReg {
            dst: "c".to_owned(),
            expr: LlilExpr::Mul(
                Box::new(LlilExpr::Reg("a".to_owned())),
                Box::new(LlilExpr::Reg("b".to_owned())),
            ),
        };
        let s2 = VsaTransfer::transfer_instr(&instr, &s);
        assert_eq!(
            s2.read_reg("c").global.unwrap(),
            StridedInterval::singleton(42)
        );
    }

    #[test]
    fn test_transfer_shl() {
        let mut s = VsaStateV2::new();
        s.assign_reg("v", RegionValueSet::from_const(1));
        let instr = LlilInstruction::SetReg {
            dst: "w".to_owned(),
            expr: LlilExpr::Shl(
                Box::new(LlilExpr::Reg("v".to_owned())),
                Box::new(LlilExpr::Const(3)),
            ),
        };
        let s2 = VsaTransfer::transfer_instr(&instr, &s);
        assert_eq!(
            s2.read_reg("w").global.unwrap(),
            StridedInterval::singleton(8)
        );
    }

    #[test]
    fn test_transfer_store_load() {
        let mut s = VsaStateV2::new();
        s.assign_reg("ptr", RegionValueSet::from_const(0x2000));
        s.assign_reg("val", RegionValueSet::from_const(0xBEEF));
        let store = LlilInstruction::Store {
            ptr: LlilExpr::Reg("ptr".to_owned()),
            val: LlilExpr::Reg("val".to_owned()),
            size: 8,
        };
        let s2 = VsaTransfer::transfer_instr(&store, &s);
        let load_instr = LlilInstruction::SetReg {
            dst: "out".to_owned(),
            expr: LlilExpr::Load {
                ptr: Box::new(LlilExpr::Reg("ptr".to_owned())),
                size: 8,
            },
        };
        let s3 = VsaTransfer::transfer_instr(&load_instr, &s2);
        assert_eq!(
            s3.read_reg("out").global.unwrap(),
            StridedInterval::singleton(0xBEEF)
        );
    }

    #[test]
    fn test_transfer_zero_ext() {
        let mut s = VsaStateV2::new();
        s.assign_reg("v", RegionValueSet::from_const(0xFF));
        let instr = LlilInstruction::SetReg {
            dst: "w".to_owned(),
            expr: LlilExpr::ZeroExt {
                expr: Box::new(LlilExpr::Reg("v".to_owned())),
                from_bits: 8,
            },
        };
        let s2 = VsaTransfer::transfer_instr(&instr, &s);
        assert_eq!(
            s2.read_reg("w").global.unwrap(),
            StridedInterval::singleton(0xFF)
        );
    }

    // ── VsaTransfer::eval_add / eval_sub pointer arithmetic ───────────────

    #[test]
    fn test_eval_add_ptr_plus_int() {
        let rid = MemRegionId::Stack(0x4000);
        let ptr = RegionValueSet::pointer(rid.clone(), StridedInterval::singleton(16));
        let off = RegionValueSet::from_const(8);
        let r = VsaTransfer::eval_add(&ptr, &off);
        assert_eq!(
            *r.regions.get(&rid).unwrap(),
            StridedInterval::singleton(24)
        );
    }

    #[test]
    fn test_eval_sub_ptr_minus_int() {
        let rid = MemRegionId::Heap(0x1000);
        let ptr = RegionValueSet::pointer(rid.clone(), StridedInterval::singleton(32));
        let off = RegionValueSet::from_const(8);
        let r = VsaTransfer::eval_sub(&ptr, &off);
        assert_eq!(
            *r.regions.get(&rid).unwrap(),
            StridedInterval::singleton(24)
        );
    }

    #[test]
    fn test_eval_sub_ptr_minus_ptr_same_region() {
        let rid = MemRegionId::Global(0x6000);
        let a = RegionValueSet::pointer(rid.clone(), StridedInterval::singleton(40));
        let b = RegionValueSet::pointer(rid, StridedInterval::singleton(32));
        let r = VsaTransfer::eval_sub(&a, &b);
        // Should return an integer difference.
        assert!(r.is_integer());
        assert_eq!(r.global.unwrap(), StridedInterval::singleton(8));
    }

    // ── VsaEngineV2 ────────────────────────────────────────────────────────

    fn make_llil_cfg(instrs: Vec<LlilInstruction>) -> LlilCfg {
        let block = LlilBlock { id: 0, instrs };
        LlilCfg::new(vec![block], vec![vec![]], 0, None)
    }

    #[test]
    fn test_engine_v2_single_block() {
        let cfg = make_llil_cfg(vec![LlilInstruction::SetReg {
            dst: "rax".to_owned(),
            expr: LlilExpr::Const(0x42),
        }]);
        let engine = VsaEngineV2::new(VsaStateV2::new());
        let result = engine.analyze(&cfg).unwrap();
        assert!(result.converged);
        let vs = result.reg_after(0, "rax");
        assert_eq!(vs.global.unwrap(), StridedInterval::singleton(0x42));
    }

    #[test]
    fn test_engine_v2_loop_converges() {
        // Block 0: rax = 0
        // Block 1: rax = rax + 1; back-edge to block 1
        let b0 = LlilBlock {
            id: 0,
            instrs: vec![LlilInstruction::SetReg {
                dst: "rax".to_owned(),
                expr: LlilExpr::Const(0),
            }],
        };
        let b1 = LlilBlock {
            id: 1,
            instrs: vec![LlilInstruction::SetReg {
                dst: "rax".to_owned(),
                expr: LlilExpr::Add(
                    Box::new(LlilExpr::Reg("rax".to_owned())),
                    Box::new(LlilExpr::Const(1)),
                ),
            }],
        };
        let succs = vec![vec![1usize], vec![1usize]]; // 0→1, 1→1 (self-loop)
        let cfg = LlilCfg::new(vec![b0, b1], succs, 0, None);
        let engine = VsaEngineV2::new(VsaStateV2::new());
        let result = engine.analyze(&cfg).unwrap();
        assert!(result.converged);
        // After widening rax must be Top or a wide range.
        let vs = result.reg_after(1, "rax");
        let si = vs.global.unwrap_or(StridedInterval::TOP);
        assert!(si.is_top() || si.hi > 10);
    }

    #[test]
    fn test_engine_v2_empty_error() {
        let cfg = LlilCfg::new(vec![], vec![], 0, None);
        let engine = VsaEngineV2::new(VsaStateV2::new());
        assert!(matches!(engine.analyze(&cfg), Err(VsaError::EmptyProgram)));
    }

    #[test]
    fn test_engine_v2_two_paths_join() {
        // Block 0 → block 1 AND block 0 → block 2; both → block 3.
        // b0: rax = 0
        // b1: rax = 10
        // b2: rax = 20
        // b3: (phi join point — rax should be {10,20} or [10,20])
        let b0 = LlilBlock {
            id: 0,
            instrs: vec![LlilInstruction::SetReg {
                dst: "rax".to_owned(),
                expr: LlilExpr::Const(0),
            }],
        };
        let b1 = LlilBlock {
            id: 1,
            instrs: vec![LlilInstruction::SetReg {
                dst: "rax".to_owned(),
                expr: LlilExpr::Const(10),
            }],
        };
        let b2 = LlilBlock {
            id: 2,
            instrs: vec![LlilInstruction::SetReg {
                dst: "rax".to_owned(),
                expr: LlilExpr::Const(20),
            }],
        };
        let b3 = LlilBlock {
            id: 3,
            instrs: vec![LlilInstruction::Nop],
        };
        let succs = vec![
            vec![1usize, 2usize], // b0 → b1, b2
            vec![3usize],         // b1 → b3
            vec![3usize],         // b2 → b3
            vec![],               // b3 exit
        ];
        let cfg = LlilCfg::new(vec![b0, b1, b2, b3], succs, 0, None);
        let engine = VsaEngineV2::new(VsaStateV2::new());
        let result = engine.analyze(&cfg).unwrap();
        assert!(result.converged);
        let vs = result.reg_before(3, "rax");
        let si = vs.global.unwrap_or(StridedInterval::BOTTOM);
        assert!(si.contains(10) || si.contains(20));
    }

    // ── Jump table resolution ──────────────────────────────────────────────

    fn make_jump_table_mem(base: u64, targets: &[u64]) -> MapBinaryMemory {
        let mut map = HashMap::new();
        for (i, &t) in targets.iter().enumerate() {
            let addr = base + (i as u64) * 8;
            let bytes = t.to_le_bytes();
            for (j, &b) in bytes.iter().enumerate() {
                map.insert(addr + j as u64, b);
            }
        }
        MapBinaryMemory(map)
    }

    #[test]
    fn test_resolve_jump_table_basic() {
        // Set up VSA result: block 0 exit has rax = [0, 3] (4-entry table).
        let mut rs = VsaStateV2::new();
        rs.assign_reg(
            "rax",
            RegionValueSet {
                global: Some(StridedInterval::new(0, 3, 1)),
                regions: HashMap::new(),
            },
        );
        let mut states_after = HashMap::new();
        states_after.insert(0usize, rs);
        let result = VsaEngineResult {
            states_before: HashMap::new(),
            states_after,
            converged: true,
            iterations: 1,
        };

        let table_base = 0x5000u64;
        let code_targets: Vec<u64> = vec![0x1000, 0x1100, 0x1200, 0x1300];
        let mem = make_jump_table_mem(table_base, &code_targets);

        let info = resolve_jump_table(&result, 0, "rax", table_base, 8, (0x1000, 0x2000), &mem);

        assert_eq!(info.targets.len(), 4);
        assert_eq!(info.targets[0], 0x1000);
        assert_eq!(info.targets[3], 0x1300);
        assert!(info.complete);
    }

    #[test]
    fn test_resolve_jump_table_partial_out_of_range() {
        // Table where the 3rd entry is outside code range → stops early.
        let mut rs = VsaStateV2::new();
        rs.assign_reg(
            "idx",
            RegionValueSet {
                global: Some(StridedInterval::new(0, 4, 1)),
                regions: HashMap::new(),
            },
        );
        let mut states_after = HashMap::new();
        states_after.insert(0usize, rs);
        let result = VsaEngineResult {
            states_before: HashMap::new(),
            states_after,
            converged: true,
            iterations: 1,
        };

        let table_base = 0x6000u64;
        // Third entry (0xDEAD0000) is outside code range.
        let targets: Vec<u64> = vec![0x1000, 0x1100, 0xDEAD_0000, 0x1300];
        let mem = make_jump_table_mem(table_base, &targets);

        let info = resolve_jump_table(&result, 0, "idx", table_base, 8, (0x1000, 0x2000), &mem);

        assert_eq!(info.targets, vec![0x1000, 0x1100]);
        assert!(!info.complete);
    }

    // ── Indirect call resolution ───────────────────────────────────────────

    #[test]
    fn test_resolve_indirect_calls_basic() {
        let b0 = LlilBlock {
            id: 0,
            instrs: vec![LlilInstruction::Call {
                target: LlilExpr::Reg("rax".to_owned()),
            }],
        };
        let cfg = LlilCfg::new(vec![b0], vec![vec![]], 0, None);

        let mut rs = VsaStateV2::new();
        rs.assign_reg("rax", RegionValueSet::from_const(0x1234));
        let mut states_after = HashMap::new();
        states_after.insert(0usize, rs);
        let result = VsaEngineResult {
            states_before: HashMap::new(),
            states_after,
            converged: true,
            iterations: 1,
        };

        let map = resolve_indirect_calls(&result, &cfg, (0x1000, 0x2000), 64);
        let targets = map.get(&(0, "rax".to_owned())).unwrap();
        assert_eq!(*targets, vec![0x1234]);
    }

    #[test]
    fn test_resolve_indirect_calls_range() {
        // rax = [0x1000, 0x1100] / 0x100 → 2 entries: 0x1000, 0x1100.
        let b0 = LlilBlock {
            id: 0,
            instrs: vec![LlilInstruction::Jump {
                target: LlilExpr::Reg("rax".to_owned()),
            }],
        };
        let cfg = LlilCfg::new(vec![b0], vec![vec![]], 0, None);

        let mut rs = VsaStateV2::new();
        rs.assign_reg(
            "rax",
            RegionValueSet {
                global: Some(StridedInterval::new(0x1000, 0x1100, 0x100)),
                regions: HashMap::new(),
            },
        );
        let mut states_after = HashMap::new();
        states_after.insert(0usize, rs);
        let result = VsaEngineResult {
            states_before: HashMap::new(),
            states_after,
            converged: true,
            iterations: 1,
        };

        let map = resolve_indirect_calls(&result, &cfg, (0x1000, 0x2000), 64);
        let targets = map.get(&(0, "rax".to_owned())).unwrap();
        assert!(targets.contains(&0x1000));
        assert!(targets.contains(&0x1100));
    }

    // ── Buffer overflow detection ──────────────────────────────────────────

    #[test]
    fn test_overflow_detection_safe() {
        let b0 = LlilBlock {
            id: 0,
            instrs: vec![LlilInstruction::Store {
                ptr: LlilExpr::Reg("ptr".to_owned()),
                val: LlilExpr::Const(0),
                size: 8,
            }],
        };
        let cfg = LlilCfg::new(vec![b0], vec![vec![]], 0, None);

        let mut rs = VsaStateV2::new();
        rs.assign_reg("ptr", RegionValueSet::from_const(0x1000));
        let mut states_before = HashMap::new();
        states_before.insert(0usize, rs);
        let result = VsaEngineResult {
            states_before,
            states_after: HashMap::new(),
            converged: true,
            iterations: 1,
        };

        let warnings = detect_buffer_overflows(&result, &cfg, "ptr", 8, (0x1000, 0x2000));
        assert!(warnings.is_empty(), "no overflow expected: {warnings:?}");
    }

    #[test]
    fn test_overflow_detection_oob() {
        let b0 = LlilBlock {
            id: 0,
            instrs: vec![LlilInstruction::Store {
                ptr: LlilExpr::Reg("ptr".to_owned()),
                val: LlilExpr::Const(0),
                size: 8,
            }],
        };
        let cfg = LlilCfg::new(vec![b0], vec![vec![]], 0, None);

        let mut rs = VsaStateV2::new();
        // Pointer at 0x1FF8 + 8 bytes = 0x2000 which is == limit → out of bounds.
        rs.assign_reg("ptr", RegionValueSet::from_const(0x1FF8));
        let mut states_before = HashMap::new();
        states_before.insert(0usize, rs);
        let result = VsaEngineResult {
            states_before,
            states_after: HashMap::new(),
            converged: true,
            iterations: 1,
        };

        let warnings = detect_buffer_overflows(&result, &cfg, "ptr", 8, (0x1000, 0x2000));
        assert!(!warnings.is_empty(), "expected overflow warning");
    }

    #[test]
    fn test_overflow_detection_top_warns() {
        let b0 = LlilBlock {
            id: 0,
            instrs: vec![LlilInstruction::Store {
                ptr: LlilExpr::Reg("ptr".to_owned()),
                val: LlilExpr::Const(0),
                size: 1,
            }],
        };
        let cfg = LlilCfg::new(vec![b0], vec![vec![]], 0, None);

        let mut rs = VsaStateV2::new();
        rs.assign_reg("ptr", RegionValueSet::top()); // unknown pointer
        let mut states_before = HashMap::new();
        states_before.insert(0usize, rs);
        let result = VsaEngineResult {
            states_before,
            states_after: HashMap::new(),
            converged: true,
            iterations: 1,
        };

        let warnings = detect_buffer_overflows(&result, &cfg, "ptr", 1, (0x0, 0x1000));
        assert!(!warnings.is_empty());
    }

    // ── detect_back_edges ──────────────────────────────────────────────────

    #[test]
    fn test_back_edge_detection_self_loop() {
        // Block 0 → block 1; block 1 → block 1 (self-loop).
        let succs = vec![vec![1usize], vec![1usize]];
        let back = detect_back_edges(&succs, 0, 2);
        assert!(back.contains(&(1, 1)));
    }

    #[test]
    fn test_back_edge_detection_loop() {
        // 0 → 1 → 2 → 1 (loop header at 1).
        let succs = vec![vec![1usize], vec![2usize], vec![1usize]];
        let back = detect_back_edges(&succs, 0, 3);
        assert!(back.contains(&(2, 1)));
    }

    #[test]
    fn test_back_edge_detection_dag_no_back_edges() {
        // Pure DAG: 0 → 1 → 2; 0 → 2.
        let succs = vec![vec![1usize, 2usize], vec![2usize], vec![]];
        let back = detect_back_edges(&succs, 0, 3);
        assert!(back.is_empty());
    }

    // ── LlilCfg::is_back_edge ──────────────────────────────────────────────

    #[test]
    fn test_llil_cfg_back_edge_query() {
        let b0 = LlilBlock {
            id: 0,
            instrs: vec![],
        };
        let b1 = LlilBlock {
            id: 1,
            instrs: vec![],
        };
        let succs = vec![vec![1usize], vec![0usize]]; // 0→1, 1→0 (back)
        let cfg = LlilCfg::new(vec![b0, b1], succs, 0, None);
        assert!(cfg.is_back_edge(1, 0));
        assert!(!cfg.is_back_edge(0, 1));
    }

    // ── MapBinaryMemory ────────────────────────────────────────────────────

    #[test]
    fn test_map_binary_memory_read() {
        let mut map = HashMap::new();
        let base = 0x1000u64;
        let val = 0x0102030405060708u64;
        for (i, b) in val.to_le_bytes().iter().enumerate() {
            map.insert(base + i as u64, *b);
        }
        let mem = MapBinaryMemory(map);
        assert_eq!(read_u64_le(&mem, base), Some(val));
    }

    #[test]
    fn test_map_binary_memory_missing() {
        let mem = MapBinaryMemory(HashMap::new());
        assert_eq!(read_u64_le(&mem, 0x5000), None);
    }

    // ── VsaEngineResult helpers ────────────────────────────────────────────

    #[test]
    fn test_engine_result_get_jump_targets() {
        let mut rs = VsaStateV2::new();
        rs.assign_reg(
            "rax",
            RegionValueSet {
                global: Some(StridedInterval::new(0x1000, 0x1200, 0x100)),
                regions: HashMap::new(),
            },
        );
        let mut states_after = HashMap::new();
        states_after.insert(0usize, rs);
        let result = VsaEngineResult {
            states_before: HashMap::new(),
            states_after,
            converged: true,
            iterations: 1,
        };
        let targets = result.get_jump_targets(0, "rax", 64);
        assert_eq!(targets, vec![0x1000, 0x1100, 0x1200]);
    }

    #[test]
    fn test_engine_result_is_access_safe() {
        let mut rs = VsaStateV2::new();
        rs.assign_reg("ptr", RegionValueSet::from_const(0x1004));
        let mut states_before = HashMap::new();
        states_before.insert(0usize, rs);
        let result = VsaEngineResult {
            states_before,
            states_after: HashMap::new(),
            converged: true,
            iterations: 1,
        };
        // Access [0x1004, 0x100C) within [0x1000, 0x2000) → safe.
        assert!(result.is_access_safe(0, "ptr", 8, (0x1000, 0x2000)));
        // Access [0x1004, 0x100C) not within [0x1000, 0x100A) → unsafe.
        assert!(!result.is_access_safe(0, "ptr", 8, (0x1000, 0x100A)));
    }

    // ── Widen threshold integration ────────────────────────────────────────

    #[test]
    fn test_engine_v2_custom_widen_threshold() {
        // Very low threshold (1) should widen aggressively.
        let config = VsaConfig {
            widen_threshold: 1,
            narrow_iterations: 0,
            iteration_budget: 10_000,
        };
        let b0 = LlilBlock {
            id: 0,
            instrs: vec![LlilInstruction::SetReg {
                dst: "r".to_owned(),
                expr: LlilExpr::Const(0),
            }],
        };
        let b1 = LlilBlock {
            id: 1,
            instrs: vec![LlilInstruction::SetReg {
                dst: "r".to_owned(),
                expr: LlilExpr::Add(
                    Box::new(LlilExpr::Reg("r".to_owned())),
                    Box::new(LlilExpr::Const(1)),
                ),
            }],
        };
        let cfg = LlilCfg::new(vec![b0, b1], vec![vec![1], vec![1]], 0, None);
        let engine = VsaEngineV2::with_config(VsaStateV2::new(), config);
        let result = engine.analyze(&cfg).unwrap();
        assert!(result.converged);
    }

    // ── MemRegionId display ───────────────────────────────────────────────

    #[test]
    fn test_mem_region_id_display() {
        assert_eq!(MemRegionId::Stack(0x4000).to_string(), "stack@0x4000");
        assert_eq!(MemRegionId::Heap(0x1000).to_string(), "heap@0x1000");
        assert_eq!(MemRegionId::Global(0x5000).to_string(), "global@0x5000");
        assert_eq!(MemRegionId::Synthetic(3).to_string(), "synthetic#3");
    }

    // ── RegionValueSet display ─────────────────────────────────────────────

    #[test]
    fn test_rvs_display_integer() {
        let v = RegionValueSet::from_const(0x42);
        let s = v.to_string();
        assert!(s.contains("int:"));
    }

    #[test]
    fn test_rvs_display_pointer() {
        let rid = MemRegionId::Global(0x1000);
        let v = RegionValueSet::pointer(rid, StridedInterval::singleton(0));
        let s = v.to_string();
        assert!(s.contains("global@0x1000"));
    }

    #[test]
    fn test_rvs_display_bottom() {
        assert_eq!(RegionValueSet::bottom().to_string(), "\u{22a5}");
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Property tests for lib.rs's OWN abstract domains (ValueSet / StridedInterval).
//
// These target the duplicate u64 abstract domain defined in THIS file (not the
// separate strided_interval.rs module). For every abstract operation we assert
// the soundness property: the abstract result CONTAINS every concrete result of
// the operation applied pointwise to the concrete members of the operands.
//
// Method: a small xorshift PRNG builds random small abstract elements; concrete
// member sets are enumerated directly from the fields (independent of the
// methods under test); concrete ops use the same wrapping semantics as the
// domain. Wrapping-underflow pairs (a < b for subtraction) are excluded because
// machine wraparound is outside the math-integer abstraction being validated.
// ────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod prop_tests {
    use super::*;

    use crate::test_prng::Xs as Rng;

    // ── ValueSet helpers ────────────────────────────────────────────────────

    fn vs_members(vs: &ValueSet) -> Vec<u64> {
        match vs {
            ValueSet::Bottom => vec![],
            ValueSet::Concrete(v) => v.clone(),
            ValueSet::Range { lo, hi, stride } => {
                let mut out = Vec::new();
                let mut x = *lo;
                let s = (*stride).max(1);
                while x <= *hi {
                    out.push(x);
                    x += s;
                }
                out
            }
            ValueSet::Top => Vec::new(),
        }
    }

    // Generate a small non-Top ValueSet (values kept small to avoid wrap).
    fn gen_vs(rng: &mut Rng) -> ValueSet {
        match rng.below(3) {
            0 => {
                let n = 1 + rng.below(5);
                let mut v: Vec<u64> = (0..n).map(|_| rng.below(48)).collect();
                v.sort_unstable();
                v.dedup();
                ValueSet::Concrete(v)
            }
            1 => {
                let lo = rng.below(40);
                let stride = 1 + rng.below(6);
                let cnt = rng.below(6);
                let hi = lo + cnt * stride;
                ValueSet::Range { lo, hi, stride }
            }
            _ => ValueSet::singleton(rng.below(48)),
        }
    }

    #[test]
    fn prop_valueset_join_contains_union() {
        let mut rng = Rng::new(0xA1);
        for _ in 0..20_000 {
            let a = gen_vs(&mut rng);
            let b = gen_vs(&mut rng);
            let r = a.join(&b);
            for x in vs_members(&a).into_iter().chain(vs_members(&b)) {
                assert!(r.contains(x), "join unsound: {a} join {b} = {r} missing {x}");
            }
        }
    }

    #[test]
    fn prop_valueset_widen_contains_union() {
        let mut rng = Rng::new(0xB2);
        for _ in 0..20_000 {
            let a = gen_vs(&mut rng);
            let b = gen_vs(&mut rng);
            let r = a.widen(&b);
            for x in vs_members(&a).into_iter().chain(vs_members(&b)) {
                assert!(r.contains(x), "widen unsound: {a} widen {b} = {r} missing {x}");
            }
        }
    }

    #[test]
    fn prop_valueset_add_contains() {
        let mut rng = Rng::new(0xC3);
        for _ in 0..20_000 {
            let a = gen_vs(&mut rng);
            let b = gen_vs(&mut rng);
            let r = a.add(&b);
            for x in vs_members(&a) {
                for y in vs_members(&b) {
                    let c = x.wrapping_add(y);
                    assert!(r.contains(c), "add unsound: {a} + {b} = {r} missing {x}+{y}={c}");
                }
            }
        }
    }

    #[test]
    fn prop_valueset_sub_contains() {
        let mut rng = Rng::new(0xD4);
        for _ in 0..20_000 {
            let a = gen_vs(&mut rng);
            let b = gen_vs(&mut rng);
            let r = a.sub(&b);
            for x in vs_members(&a) {
                for y in vs_members(&b) {
                    if x < y {
                        continue; // wrap: outside the math-integer abstraction
                    }
                    let c = x - y;
                    assert!(r.contains(c), "sub unsound: {a} - {b} = {r} missing {x}-{y}={c}");
                }
            }
        }
    }

    #[test]
    fn prop_valueset_and_or_contains() {
        let mut rng = Rng::new(0xE5);
        for _ in 0..20_000 {
            let a = gen_vs(&mut rng);
            let b = gen_vs(&mut rng);
            let ra = a.bitwise_and(&b);
            let ro = a.bitwise_or(&b);
            for x in vs_members(&a) {
                for y in vs_members(&b) {
                    assert!(ra.contains(x & y), "and unsound: {a} & {b} = {ra} missing {}", x & y);
                    assert!(ro.contains(x | y), "or unsound: {a} | {b} = {ro} missing {}", x | y);
                }
            }
        }
    }

    #[test]
    fn prop_valueset_meet_over_approximates_intersection() {
        let mut rng = Rng::new(0xF6);
        for _ in 0..20_000 {
            let a = gen_vs(&mut rng);
            let b = gen_vs(&mut rng);
            let r = a.meet(&b);
            let mb = vs_members(&b);
            for x in vs_members(&a) {
                if mb.contains(&x) {
                    assert!(r.contains(x), "meet unsound: {a} meet {b} = {r} dropped common {x}");
                }
            }
        }
    }

    // ── StridedInterval helpers ─────────────────────────────────────────────

    fn si_members(si: &StridedInterval) -> Vec<u64> {
        if si.is_bottom() {
            return vec![];
        }
        let mut out = Vec::new();
        let s = si.stride.max(1);
        let mut x = si.lo;
        loop {
            out.push(x);
            if x >= si.hi {
                break;
            }
            x += s;
            if x > si.hi {
                break;
            }
        }
        out
    }

    fn gen_si(rng: &mut Rng) -> StridedInterval {
        match rng.below(4) {
            0 => StridedInterval::singleton(rng.below(48)),
            _ => {
                let lo = rng.below(40);
                let stride = 1 + rng.below(6);
                let cnt = rng.below(6);
                let hi = lo + cnt * stride;
                StridedInterval::new(lo, hi, stride)
            }
        }
    }

    fn gen_si_shift(rng: &mut Rng) -> StridedInterval {
        let lo = rng.below(4);
        let cnt = rng.below(3);
        StridedInterval::new(lo, lo + cnt, 1)
    }

    #[test]
    fn prop_si_join_contains_union() {
        let mut rng = Rng::new(0x11);
        for _ in 0..20_000 {
            let a = gen_si(&mut rng);
            let b = gen_si(&mut rng);
            let r = a.join(&b);
            for x in si_members(&a).into_iter().chain(si_members(&b)) {
                assert!(r.contains(x), "si join unsound: {a} join {b} = {r} missing {x}");
            }
        }
    }

    #[test]
    fn prop_si_widen_contains_union() {
        let mut rng = Rng::new(0x22);
        for _ in 0..20_000 {
            let a = gen_si(&mut rng);
            let b = gen_si(&mut rng);
            let r = a.widen(&b);
            for x in si_members(&a).into_iter().chain(si_members(&b)) {
                assert!(r.contains(x), "si widen unsound: {a} widen {b} = {r} missing {x}");
            }
        }
    }

    #[test]
    fn prop_si_meet_over_approximates_intersection() {
        let mut rng = Rng::new(0x33);
        for _ in 0..20_000 {
            let a = gen_si(&mut rng);
            let b = gen_si(&mut rng);
            let r = a.meet(&b);
            let mb = si_members(&b);
            for x in si_members(&a) {
                if mb.contains(&x) {
                    assert!(r.contains(x), "si meet unsound: {a} meet {b} = {r} dropped common {x}");
                }
            }
        }
    }

    #[test]
    fn prop_si_add_sub_contains() {
        let mut rng = Rng::new(0x44);
        for _ in 0..20_000 {
            let a = gen_si(&mut rng);
            let b = gen_si(&mut rng);
            let radd = a.add(&b);
            let rsub = a.sub(&b);
            for x in si_members(&a) {
                for y in si_members(&b) {
                    assert!(radd.contains(x.wrapping_add(y)), "si add unsound: {a}+{b}={radd} miss {x}+{y}");
                    if x >= y {
                        assert!(rsub.contains(x - y), "si sub unsound: {a}-{b}={rsub} miss {x}-{y}");
                    }
                }
            }
        }
    }

    #[test]
    fn prop_si_mul_contains() {
        let mut rng = Rng::new(0x55);
        for _ in 0..20_000 {
            let a = gen_si(&mut rng);
            let b = gen_si(&mut rng);
            let r = a.mul(&b);
            for x in si_members(&a) {
                for y in si_members(&b) {
                    assert!(r.contains(x.wrapping_mul(y)), "si mul unsound: {a}*{b}={r} miss {x}*{y}={}", x.wrapping_mul(y));
                }
            }
        }
    }

    #[test]
    fn prop_si_and_or_xor_contains() {
        let mut rng = Rng::new(0x66);
        for _ in 0..20_000 {
            let a = gen_si(&mut rng);
            let b = gen_si(&mut rng);
            let ra = a.bitwise_and(&b);
            let ro = a.bitwise_or(&b);
            let rx = a.bitwise_xor(&b);
            for x in si_members(&a) {
                for y in si_members(&b) {
                    assert!(ra.contains(x & y), "si and unsound: {a}&{b}={ra} miss {}", x & y);
                    assert!(ro.contains(x | y), "si or unsound: {a}|{b}={ro} miss {}", x | y);
                    assert!(rx.contains(x ^ y), "si xor unsound: {a}^{b}={rx} miss {}", x ^ y);
                }
            }
        }
    }

    // ── Minimized regression cases for the bugs the properties above found ──

    #[test]
    fn regress_vs_join_stride_offset() {
        // [0x9,0x27]/6 join [0xb,0xe]/3 previously dropped 11 (stride ignored
        // the offset between the two interval starts).
        let a = ValueSet::Range { lo: 9, hi: 39, stride: 6 };
        let b = ValueSet::Range { lo: 11, hi: 14, stride: 3 };
        let r = a.join(&b);
        assert!(r.contains(11), "{r}");
        assert!(r.contains(9) && r.contains(39) && r.contains(14));
    }

    #[test]
    fn regress_vs_add_concrete_range_stride() {
        // {0,1} + [0,10]/2 previously produced [0,11]/2, dropping odd sums.
        let a = ValueSet::Concrete(vec![0, 1]);
        let b = ValueSet::Range { lo: 0, hi: 10, stride: 2 };
        let r = a.add(&b);
        assert!(r.contains(1), "{r}");
        assert!(r.contains(11));
    }

    #[test]
    fn regress_vs_sub_wraparound_returns_top() {
        // [16,32]/4 - [26,42]/4: lo underflows; must not yield an empty range.
        let a = ValueSet::Range { lo: 16, hi: 32, stride: 4 };
        let b = ValueSet::Range { lo: 26, hi: 42, stride: 4 };
        let r = a.sub(&b);
        assert!(r.contains(2), "{r}"); // 28 - 26
    }

    #[test]
    fn regress_vs_meet_crt() {
        // [37,41]/2 meet [27,39]/3 share 39; old code returned Bottom.
        let a = ValueSet::Range { lo: 37, hi: 41, stride: 2 };
        let b = ValueSet::Range { lo: 27, hi: 39, stride: 3 };
        assert!(a.meet(&b).contains(39), "{}", a.meet(&b));
    }

    #[test]
    fn regress_si_widen_stride() {
        // [34,54]/4 widen [29,34]/1 previously produced [0,48]/8, dropping 34.
        let a = StridedInterval::new(34, 54, 4);
        let b = StridedInterval::new(29, 34, 1);
        let r = a.widen(&b);
        assert!(r.contains(34), "{r}");
        assert!(r.contains(54));
    }

    #[test]
    fn regress_si_mul_cross_term() {
        // [32,40]/4 * [34,36]/1 must contain 36*35 = 1260.
        let a = StridedInterval::new(32, 40, 4);
        let b = StridedInterval::new(34, 36, 1);
        assert!(a.mul(&b).contains(1260), "{}", a.mul(&b));
    }

    #[test]
    fn regress_si_or_low_bits() {
        // hi_a|hi_b is not a sound OR bound: 0x0F | 0x10 = 0x1F > 0x10.
        let a = StridedInterval::new(0, 15, 1);
        let b = StridedInterval::new(16, 16, 1);
        assert!(a.bitwise_or(&b).contains(15 | 16), "{}", a.bitwise_or(&b));
    }

    #[test]
    fn regress_si_shl_range_shift() {
        // [3,7]/4 << [0,1] must contain 6 and 14.
        let a = StridedInterval::new(3, 7, 4);
        let sh = StridedInterval::new(0, 1, 1);
        let r = a.shl(&sh);
        assert!(r.contains(6) && r.contains(14), "{r}");
    }

    #[test]
    fn prop_si_shl_shr_contains() {
        let mut rng = Rng::new(0x77);
        for _ in 0..20_000 {
            let a = gen_si(&mut rng);
            let sh = gen_si_shift(&mut rng);
            let rl = a.shl(&sh);
            let rr = a.shr(&sh);
            for x in si_members(&a) {
                for s in si_members(&sh) {
                    let sc = s.min(63);
                    assert!(rl.contains(x << sc), "si shl unsound: {a}<<{sh}={rl} miss {x}<<{sc}");
                    assert!(rr.contains(x >> sc), "si shr unsound: {a}>>{sh}={rr} miss {x}>>{sc}");
                }
            }
        }
    }

    // ── sar (arithmetic right shift) over-approximation ─────────────────────
    // Unlike shr, sar interprets the value as signed 64-bit. Generate intervals
    // that can live in the non-negative region, the negative (high-bit-set)
    // region, and straddle the sign boundary. The abstract result must contain
    // every concrete signed-shift result.
    fn gen_si_signed(rng: &mut Rng) -> StridedInterval {
        const SB: u64 = 1u64 << 63;
        let stride = 1 + rng.below(4);
        let cnt = rng.below(5);
        let span = cnt * stride;
        match rng.below(4) {
            0 => {
                // Small non-negative.
                let lo = rng.below(40);
                StridedInterval::new(lo, lo + span, stride)
            }
            1 => {
                // Negative region (high bit set).
                let lo = SB + rng.below(40);
                StridedInterval::new(lo, lo + span, stride)
            }
            2 => {
                // Straddle the sign boundary.
                let below = 1 + rng.below(12);
                let above = 1 + rng.below(12);
                StridedInterval::new(SB - below, SB + above, 1)
            }
            _ => StridedInterval::singleton(SB.wrapping_add(rng.below(64)).wrapping_sub(32)),
        }
    }

    #[test]
    fn prop_si_sar_over_approximates() {
        let mut rng = Rng::new(0x88);
        for _ in 0..30_000 {
            let a = gen_si_signed(&mut rng);
            let sh = gen_si_shift(&mut rng);
            let r = a.sar(&sh);
            for x in si_members(&a) {
                for s in si_members(&sh) {
                    let sc = (s.min(63)) as u32;
                    let expected = (x.cast_signed() >> sc).cast_unsigned();
                    assert!(
                        r.contains(expected),
                        "si sar unsound: {a} sar {sh} = {r} miss x={x:#x} s={sc} -> {expected:#x}"
                    );
                }
            }
        }
    }

    #[test]
    fn regress_si_sar_negative_range() {
        // [0x8000_0000_0000_0000, 0x8000_0000_0000_0002] sar 1 must contain the
        // true signed result 0xC000_0000_0000_0000 (=-2^62). The old fallback to
        // logical shr yielded ~0x4000…, dropping every real member.
        let a = StridedInterval::new(1u64 << 63, (1u64 << 63) + 2, 1);
        let sh = StridedInterval::singleton(1);
        let r = a.sar(&sh);
        let expected = ((1u64 << 63).cast_signed() >> 1).cast_unsigned();
        assert_eq!(expected, 0xC000_0000_0000_0000);
        assert!(r.contains(expected), "sar dropped negative result: a={a} -> {r}");
    }

    // ── narrow: standard narrowing spec `b ⊑ (a ▽ b) ⊑ a` when `b ⊑ a` ───────
    // Build `b` as a genuine sub-interval of `a` so the precondition holds, then
    // check the narrowed result keeps every member of `b` and stays inside `a`.
    #[test]
    fn prop_si_narrow_between_b_and_a() {
        let mut rng = Rng::new(0x99);
        for _ in 0..20_000 {
            let a = gen_si(&mut rng);
            let ma = si_members(&a);
            if ma.is_empty() {
                continue;
            }
            let i = (rng.below(ma.len() as u64)) as usize;
            let j = (rng.below(ma.len() as u64)) as usize;
            let (lo, hi) = (ma[i].min(ma[j]), ma[i].max(ma[j]));
            let b = StridedInterval::new(lo, hi, a.stride.max(1));
            // Sanity: b ⊑ a (every member of b is in a).
            if si_members(&b).iter().any(|&v| !a.contains(v)) {
                continue;
            }
            let n = a.narrow(&b);
            for v in si_members(&b) {
                assert!(n.contains(v), "narrow dropped b member {v}: a={a} b={b} -> {n}");
            }
            for v in si_members(&n) {
                assert!(a.contains(v), "narrow grew beyond a with {v}: a={a} b={b} -> {n}");
            }
        }
    }

    // ── MemoryAbstraction strong/weak-update soundness vs a concrete shadow ──
    // Each abstract store also writes ONE concrete (addr, val) into a shadow
    // map: a concrete address drawn from the stored address interval and a
    // concrete value drawn from the stored value interval. After the sequence,
    // a singleton load at every shadow address MUST over-approximate the
    // concrete value that lives there (strong/weak boundary against ground
    // truth).
    #[test]
    fn prop_memory_abstraction_shadow_soundness() {
        let mut rng = Rng::new(0xAB);
        for _ in 0..5000 {
            let mut mem = MemoryAbstraction::new();
            let mut shadow: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
            let nstores = 1 + rng.below(10);
            for _ in 0..nstores {
                // Address: half singleton (strong), half range (weak).
                let base = rng.below(16);
                let (addr, caddr) = if rng.below(2) == 0 {
                    (StridedInterval::singleton(base), base)
                } else {
                    let span = 1 + rng.below(6);
                    let hi = base + span;
                    let caddr = base + rng.below(span + 1);
                    (StridedInterval::new(base, hi, 1), caddr)
                };
                // Value.
                let vbase = rng.below(500);
                let (val, cval) = if rng.below(2) == 0 {
                    (StridedInterval::singleton(vbase), vbase)
                } else {
                    let vspan = 1 + rng.below(200);
                    let cval = vbase + rng.below(vspan + 1);
                    (StridedInterval::new(vbase, vbase + vspan, 1), cval)
                };
                mem.store(addr, val);
                shadow.insert(caddr, cval);
            }
            for (&addr, &val) in &shadow {
                let loaded = mem.load(&StridedInterval::singleton(addr));
                assert!(
                    loaded.contains(val) || loaded.is_top(),
                    "mem shadow soundness: load@{addr} lost concrete {val}: {loaded}"
                );
            }
        }
    }

    #[test]
    fn regress_mem_weak_store_partial_overlap() {
        // A weak store whose range only PARTIALLY overlaps an existing cell must
        // still cover the addresses outside that cell. Old code set `matched`
        // from the shared point and skipped adding a cell, so load@9 (in [7,11]
        // but not in [5,7]) returned Bottom, dropping the stored value.
        let mut mem = MemoryAbstraction::new();
        mem.store(StridedInterval::new(5, 7, 1), StridedInterval::singleton(100));
        mem.store(StridedInterval::new(7, 11, 1), StridedInterval::singleton(345));
        let loaded = mem.load(&StridedInterval::singleton(9));
        assert!(loaded.contains(345), "load@9 dropped weak-stored 345: {loaded}");
    }

    #[test]
    fn regress_mem_leq_ignores_values() {
        // `MemoryAbstraction::leq` must compare VALUES, not just cell counts.
        // `self` = {@8: [0,10]} subsumes `other` = {@8: [0,5]} (self ⊒ other),
        // but NOT the reverse. The old cell-count implementation returned true
        // for BOTH directions (1 == 1), so a fixpoint check could stop while the
        // value was still ascending (unsound under-approximation).
        let mut wide = MemoryAbstraction::new();
        wide.store(StridedInterval::singleton(8), StridedInterval::new(0, 10, 1));
        let mut narrow = MemoryAbstraction::new();
        narrow.store(StridedInterval::singleton(8), StridedInterval::new(0, 5, 1));
        // wide ⊒ narrow  → true
        assert!(wide.leq(&narrow), "wide should subsume narrow");
        // narrow ⊒ wide  → false (narrow does NOT cover value 10)
        assert!(
            !narrow.leq(&wide),
            "narrow must NOT be reported as subsuming wide"
        );
    }

    #[test]
    fn regress_mem_join_overwrites_shared_cell() {
        // `join` must MERGE values of a cell present in both operands, not
        // overwrite. Old code delegated to `store` (strong update on singletons),
        // so joining {@8:[0,10]} with {@8:[0,5]} produced {@8:[0,5]}, dropping 10.
        let mut a = MemoryAbstraction::new();
        a.store(StridedInterval::singleton(8), StridedInterval::new(0, 10, 1));
        let mut b = MemoryAbstraction::new();
        b.store(StridedInterval::singleton(8), StridedInterval::new(0, 5, 1));
        let j = a.join(&b);
        let loaded = j.load(&StridedInterval::singleton(8));
        assert!(loaded.contains(10), "join dropped left value 10: {loaded}");
        assert!(loaded.contains(5), "join dropped right value 5: {loaded}");
        // Commutative at the loaded-value level.
        let j2 = b.join(&a);
        let loaded2 = j2.load(&StridedInterval::singleton(8));
        assert!(loaded2.contains(10) && loaded2.contains(5), "join not commutative: {loaded2}");
    }

    #[test]
    fn prop_mem_join_over_approximates_both() {
        // join(a,b) loaded at any address must contain both a's and b's value.
        let mut rng = Rng::new(0xC7);
        for _ in 0..5000 {
            let mut a = MemoryAbstraction::new();
            let mut b = MemoryAbstraction::new();
            let mut addrs = Vec::new();
            for _ in 0..(1 + rng.below(6)) {
                let base = rng.below(12);
                addrs.push(base);
                let v = StridedInterval::new(rng.below(50), rng.below(50) + 50, 1);
                if rng.below(2) == 0 {
                    a.store(StridedInterval::singleton(base), v);
                } else {
                    b.store(StridedInterval::singleton(base), v);
                }
            }
            let j = a.join(&b);
            for &addr in &addrs {
                let key = StridedInterval::singleton(addr);
                let la = a.load(&key);
                let lb = b.load(&key);
                let lj = j.load(&key);
                for v in si_members(&la).into_iter().chain(si_members(&lb)) {
                    assert!(
                        lj.contains(v) || lj.is_top(),
                        "mem join lost value {v} at @{addr}: {lj}"
                    );
                }
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // RegionValueSet / VsaStateV2 / VsaTransfer soundness (region-aware domain)
    // ════════════════════════════════════════════════════════════════════════

    // A concrete value in the region-aware domain: either a plain integer or a
    // pointer (region-id, offset).
    #[derive(Clone, PartialEq, Debug)]
    enum Conc {
        Int(u64),
        Ptr(MemRegionId, u64),
    }

    fn rvs_members(vs: &RegionValueSet) -> Vec<Conc> {
        let mut out = Vec::new();
        if let Some(g) = &vs.global {
            for x in si_members(g) {
                out.push(Conc::Int(x));
            }
        }
        for (rid, off) in &vs.regions {
            for x in si_members(off) {
                out.push(Conc::Ptr(rid.clone(), x));
            }
        }
        out
    }

    fn rvs_contains(vs: &RegionValueSet, c: &Conc) -> bool {
        match c {
            Conc::Int(x) => vs.global.is_some_and(|g| g.contains(*x)),
            Conc::Ptr(rid, x) => vs.regions.get(rid).is_some_and(|o| o.contains(*x)),
        }
    }

    fn gen_region(rng: &mut Rng) -> MemRegionId {
        match rng.below(3) {
            0 => MemRegionId::Stack(0),
            1 => MemRegionId::Heap(1),
            _ => MemRegionId::Global(2),
        }
    }

    // Small strided interval with values kept low to avoid machine wraparound.
    fn gen_small_si(rng: &mut Rng) -> StridedInterval {
        if rng.below(3) == 0 {
            StridedInterval::singleton(rng.below(20))
        } else {
            let lo = rng.below(16);
            let stride = 1 + rng.below(4);
            let cnt = rng.below(4);
            StridedInterval::new(lo, lo + cnt * stride, stride)
        }
    }

    fn gen_rvs(rng: &mut Rng) -> RegionValueSet {
        let mut vs = RegionValueSet::bottom();
        if rng.below(2) == 0 {
            vs.global = Some(gen_small_si(rng));
        }
        let nregions = rng.below(3);
        for _ in 0..nregions {
            vs.regions.insert(gen_region(rng), gen_small_si(rng));
        }
        if vs.is_bottom() {
            vs.global = Some(gen_small_si(rng));
        }
        vs
    }

    #[test]
    fn prop_rvs_join_contains_both() {
        let mut rng = Rng::new(0xD1);
        for _ in 0..20_000 {
            let a = gen_rvs(&mut rng);
            let b = gen_rvs(&mut rng);
            let r = a.join(&b);
            for c in rvs_members(&a).iter().chain(rvs_members(&b).iter()) {
                assert!(
                    rvs_contains(&r, c),
                    "rvs join unsound: {a} join {b} = {r} missing {c:?}"
                );
            }
        }
    }

    #[test]
    fn prop_rvs_join_commutative_idempotent() {
        let mut rng = Rng::new(0xD2);
        for _ in 0..20_000 {
            let a = gen_rvs(&mut rng);
            let b = gen_rvs(&mut rng);
            let ab = a.join(&b);
            let ba = b.join(&a);
            // Commutative (member-set equality, robust to interval canonical form).
            for c in rvs_members(&ab) {
                assert!(rvs_contains(&ba, &c), "join not commutative: {ab} vs {ba}");
            }
            for c in rvs_members(&ba) {
                assert!(rvs_contains(&ab, &c), "join not commutative: {ba} vs {ab}");
            }
            // Idempotent: a.join(a) has exactly a's members.
            let aa = a.join(&a);
            for c in rvs_members(&a) {
                assert!(rvs_contains(&aa, &c), "join not idempotent (lost): {a}");
            }
            for c in rvs_members(&aa) {
                assert!(rvs_contains(&a, &c), "join not idempotent (grew): {a} -> {aa}");
            }
        }
    }

    #[test]
    fn prop_rvs_widen_contains_both() {
        let mut rng = Rng::new(0xD3);
        for _ in 0..20_000 {
            let a = gen_rvs(&mut rng);
            let b = gen_rvs(&mut rng);
            let r = a.widen(&b);
            for c in rvs_members(&a).iter().chain(rvs_members(&b).iter()) {
                assert!(
                    rvs_contains(&r, c),
                    "rvs widen unsound: {a} widen {b} = {r} missing {c:?}"
                );
            }
        }
    }

    #[test]
    fn prop_rvs_add_offset_sound() {
        let mut rng = Rng::new(0xD4);
        for _ in 0..20_000 {
            let a = gen_rvs(&mut rng);
            // Small offset, both signs; values are < ~40 so no wrap.
            let off = (rng.below(21) as i64) - 10;
            let r = a.add_offset(off);
            for c in rvs_members(&a) {
                let expected = match c {
                    Conc::Int(x) => Conc::Int((x as i64 + off) as u64),
                    Conc::Ptr(rid, x) => Conc::Ptr(rid, (x as i64 + off) as u64),
                };
                assert!(
                    rvs_contains(&r, &expected),
                    "add_offset({off}) unsound: {a} -> {r} missing {expected:?}"
                );
            }
        }
    }

    #[test]
    fn prop_transfer_eval_add_sound() {
        // eval_add on int+int and pointer+int must over-approximate the
        // concrete sum. (pointer+pointer is intentionally not a defined address
        // in this domain, so we skip operand pairs where both are pointers.)
        let mut rng = Rng::new(0xE1);
        for _ in 0..20_000 {
            let a = gen_rvs(&mut rng);
            let b = gen_rvs(&mut rng);
            let a_ptr = !a.regions.is_empty();
            let b_ptr = !b.regions.is_empty();
            if a_ptr && b_ptr {
                continue;
            }
            let r = VsaTransfer::eval_add(&a, &b);
            for ca in rvs_members(&a) {
                for cb in rvs_members(&b) {
                    let expected = match (&ca, &cb) {
                        (Conc::Int(x), Conc::Int(y)) => Conc::Int(x.wrapping_add(*y)),
                        (Conc::Ptr(rid, x), Conc::Int(y))
                        | (Conc::Int(y), Conc::Ptr(rid, x)) => {
                            Conc::Ptr(rid.clone(), x.wrapping_add(*y))
                        }
                        _ => unreachable!(),
                    };
                    assert!(
                        rvs_contains(&r, &expected),
                        "eval_add unsound: {a} + {b} = {r} missing {expected:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn prop_transfer_eval_sub_sound() {
        // int-int, pointer-int, and pointer-pointer(same region) are defined.
        let mut rng = Rng::new(0xE2);
        for _ in 0..20_000 {
            let a = gen_rvs(&mut rng);
            let b = gen_rvs(&mut rng);
            let a_ptr = !a.regions.is_empty();
            let b_ptr = !b.regions.is_empty();
            // Only exercise defined shapes.
            // Pure pointer-pointer of the SAME single region: the domain returns
            // only the offset difference and (by design) drops any integer
            // component, so restrict this shape to operands with no `global`.
            let pure_same_single_region = a.regions.len() == 1
                && b.regions.len() == 1
                && a.global.is_none()
                && b.global.is_none()
                && a.regions.keys().next() == b.regions.keys().next();
            let defined = (!a_ptr && !b_ptr) // int - int
                || (a_ptr && !b_ptr)          // ptr - int
                || (a_ptr && b_ptr && pure_same_single_region); // ptr - ptr same region
            if !defined {
                continue;
            }
            let r = VsaTransfer::eval_sub(&a, &b);
            for ca in rvs_members(&a) {
                for cb in rvs_members(&b) {
                    let expected = match (&ca, &cb) {
                        (Conc::Int(x), Conc::Int(y)) => Some(Conc::Int(x.wrapping_sub(*y))),
                        (Conc::Ptr(rid, x), Conc::Int(y)) => {
                            Some(Conc::Ptr(rid.clone(), x.wrapping_sub(*y)))
                        }
                        (Conc::Ptr(ra, x), Conc::Ptr(rb, y)) if ra == rb => {
                            Some(Conc::Int(x.wrapping_sub(*y)))
                        }
                        _ => None,
                    };
                    if let Some(exp) = expected {
                        assert!(
                            rvs_contains(&r, &exp),
                            "eval_sub unsound: {a} - {b} = {r} missing {exp:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn prop_transfer_eval_binop_int_sound() {
        // and/or/xor/mul on pure-integer operands must over-approximate.
        let mut rng = Rng::new(0xE3);
        for _ in 0..20_000 {
            let sa = gen_small_si(&mut rng);
            let sb = gen_small_si(&mut rng);
            let a = RegionValueSet {
                global: Some(sa),
                regions: HashMap::new(),
            };
            let b = RegionValueSet {
                global: Some(sb),
                regions: HashMap::new(),
            };
            let land = VsaTransfer::eval_expr(
                &LlilExpr::And(
                    Box::new(LlilExpr::Reg("a".into())),
                    Box::new(LlilExpr::Reg("b".into())),
                ),
                &{
                    let mut s = VsaStateV2::new();
                    s.assign_reg("a", a.clone());
                    s.assign_reg("b", b.clone());
                    s
                },
            );
            for x in si_members(&sa) {
                for y in si_members(&sb) {
                    assert!(
                        land.global.unwrap().contains(x & y),
                        "eval And unsound: {sa} & {sb} missing {}",
                        x & y
                    );
                }
            }
        }
    }

    #[test]
    fn prop_state_join_commutative_upper_bound() {
        // VsaStateV2 environment join: commutative and an upper bound (leq).
        let mut rng = Rng::new(0xF1);
        let regs = ["a", "b", "c"];
        for _ in 0..10_000 {
            let mut s1 = VsaStateV2::new();
            let mut s2 = VsaStateV2::new();
            for r in regs {
                if rng.below(2) == 0 {
                    s1.assign_reg(r, gen_rvs(&mut rng));
                }
                if rng.below(2) == 0 {
                    s2.assign_reg(r, gen_rvs(&mut rng));
                }
            }
            let j12 = s1.join(&s2);
            let j21 = s2.join(&s1);
            // Upper bound: j ⊒ s1 and j ⊒ s2 (leq means "self subsumes other").
            assert!(j12.leq(&s1), "state join not upper bound of s1");
            assert!(j12.leq(&s2), "state join not upper bound of s2");
            // Commutative (member-wise on each register).
            for r in regs {
                for c in rvs_members(&j12.read_reg(r)) {
                    assert!(
                        rvs_contains(&j21.read_reg(r), &c),
                        "state join not commutative on {r}"
                    );
                }
            }
        }
    }

    #[test]
    fn prop_state_widen_terminates() {
        // Repeatedly widen an environment against an ever-growing register value.
        // A correct widening must reach a fixpoint (widened ⊒ prev) within a
        // small bounded number of steps rather than ascending forever.
        for seed_hi in 0u64..64 {
            let mut cur = VsaStateV2::new();
            let mut converged = false;
            for i in 0..1000u64 {
                let mut nxt = cur.clone();
                // Growing interval [seed_hi, seed_hi + i].
                nxt.assign_reg(
                    "r",
                    RegionValueSet {
                        global: Some(StridedInterval::new(seed_hi, seed_hi + i, 1)),
                        regions: HashMap::new(),
                    },
                );
                let widened = cur.widen(&nxt);
                // Fixpoint is MUTUAL subsumption (widened ⊒ cur AND cur ⊒ widened).
                // Checking only `widened.leq(&cur)` is vacuous: every join/widen
                // result subsumes its left operand, so it holds at i == 0 and the
                // loop never exercises the ascending chain at all.
                if widened.leq(&cur) && cur.leq(&widened) {
                    assert!(i < 10, "state widen too slow to converge: {i} steps");
                    converged = true;
                    break;
                }
                // Ascending chain: each step must be an upper bound of the last.
                assert!(widened.leq(&cur), "state widen not an upper bound at step {i}");
                cur = widened;
            }
            assert!(converged, "state widen never reached a fixpoint");
        }
    }

    #[test]
    fn prop_mem_value_widen_terminates() {
        // Item 2: value-lattice widening at a single memory cell must stabilise.
        // MemoryAbstraction has no widening operator of its own, so a fixpoint
        // loop MUST apply StridedInterval::widen to the loaded value before
        // storing it back; verify that this stabilises in bounded steps and
        // stays sound (final value contains every value seen).
        let addr = StridedInterval::singleton(8);
        for seed in 0u64..64 {
            let mut mem = MemoryAbstraction::new();
            mem.store(addr, StridedInterval::singleton(seed));
            let mut seen = vec![seed];
            let mut converged = false;
            for i in 0..1000u64 {
                let cur = mem.load(&addr);
                let fresh = StridedInterval::singleton(seed + i * 3 + 1);
                seen.push(seed + i * 3 + 1);
                let grown = cur.join(&fresh);
                let widened = cur.widen(&grown);
                mem.store(addr, widened);
                // Fixpoint: widened subsumes cur (nothing new gained upward).
                if widened.join(&cur) == widened && widened == cur {
                    assert!(i < 12, "mem value widen too slow: {i} steps (seed {seed})");
                    converged = true;
                    break;
                }
            }
            assert!(converged, "mem value widen never stabilised (seed {seed})");
            let final_val = mem.load(&addr);
            for v in seen {
                assert!(
                    final_val.contains(v),
                    "mem widen dropped seen value {v}: {final_val}"
                );
            }
        }
    }

    #[test]
    fn prop_engine_v2_loop_converges() {
        // Item 3: the full VsaEngineV2 fixpoint (with widening on back-edges)
        // must terminate on a loop that unboundedly grows a register, and the
        // reported loop-header value must over-approximate the concrete iterates.
        // CFG:  b0 (entry: r=0) -> b1 (header) ; b1 -> b1 (back-edge: r=r+1) ; b1 -> b2 (exit)
        for thresh in 1u32..6 {
            let b0 = LlilBlock {
                id: 0,
                instrs: vec![LlilInstruction::SetReg {
                    dst: "r".into(),
                    expr: LlilExpr::Const(0),
                }],
            };
            let b1 = LlilBlock {
                id: 1,
                instrs: vec![LlilInstruction::SetReg {
                    dst: "r".into(),
                    expr: LlilExpr::Add(
                        Box::new(LlilExpr::Reg("r".into())),
                        Box::new(LlilExpr::Const(1)),
                    ),
                }],
            };
            let b2 = LlilBlock {
                id: 2,
                instrs: vec![LlilInstruction::Nop],
            };
            let cfg = LlilCfg::new(
                vec![b0, b1, b2],
                vec![vec![1], vec![1, 2], vec![]],
                0,
                None,
            );
            let engine = VsaEngineV2::with_config(
                VsaStateV2::new(),
                VsaConfig {
                    widen_threshold: thresh,
                    narrow_iterations: 0,
                    iteration_budget: 100_000,
                },
            );
            let res = engine.analyze(&cfg).expect("analyze");
            assert!(res.converged, "engine did not converge (thresh {thresh})");
            // r after b1 must over-approximate several concrete iterates.
            let r_after = res
                .states_after
                .get(&1)
                .map(|s| s.read_reg("r"))
                .unwrap_or_default();
            for k in [1u64, 2, 5, 50, 1000] {
                assert!(
                    r_after.global.is_some_and(|g| g.contains(k) || g.is_top()),
                    "loop-header r must over-approximate {k}: {r_after}"
                );
            }
        }
    }
}

#[cfg(test)]
mod region_value_set_prop_tests {
    //! Soundness property tests for the V2 region-aware domain
    //! (`RegionValueSet`): its `join`/`widen` are per-component wrappers over
    //! the already-property-tested `StridedInterval`, so these tests confirm
    //! the wrapping preserves the "abstract ⊇ every concrete" invariant across
    //! both the global integer component and per-region pointer offsets.

    use super::*;

    use crate::test_prng::Xs as Rng;

    fn si_members(si: &StridedInterval) -> Vec<u64> {
        if si.is_bottom() {
            return vec![];
        }
        // Only enumerate small intervals; skip Top/huge (checked via contains).
        let mut out = Vec::new();
        let mut v = si.lo;
        let s = si.stride.max(1);
        while v <= si.hi && out.len() < 4096 {
            out.push(v);
            match v.checked_add(s) {
                Some(nv) => v = nv,
                None => break,
            }
        }
        out
    }

    fn gen_si(rng: &mut Rng) -> StridedInterval {
        let lo = rng.below(40);
        let stride = 1 + rng.below(6);
        let cnt = rng.below(6);
        let hi = lo + cnt * stride;
        StridedInterval::new(lo, hi, stride)
    }

    fn region(rng: &mut Rng) -> MemRegionId {
        match rng.below(3) {
            0 => MemRegionId::Stack(0x100 + rng.below(3)),
            1 => MemRegionId::Heap(0x200 + rng.below(3)),
            _ => MemRegionId::Global(0x300 + rng.below(3)),
        }
    }

    fn gen_rvs(rng: &mut Rng) -> RegionValueSet {
        let mut rvs = if rng.below(2) == 0 {
            RegionValueSet {
                global: Some(gen_si(rng)),
                regions: HashMap::new(),
            }
        } else {
            RegionValueSet::bottom()
        };
        for _ in 0..rng.below(3) {
            rvs.regions.insert(region(rng), gen_si(rng));
        }
        rvs
    }

    /// `join` must contain every concrete member of both operands, in the
    /// global component and every region offset.
    #[test]
    fn prop_region_value_set_join_is_sound_upper_bound() {
        let mut rng = Rng::new(0xB0B0);
        for _ in 0..10_000 {
            let a = gen_rvs(&mut rng);
            let b = gen_rvs(&mut rng);
            let j = a.join(&b);

            for src in [&a, &b] {
                if let Some(g) = &src.global {
                    let jg = j.global.expect("join global present when an operand had one");
                    for m in si_members(g) {
                        assert!(jg.contains(m), "join global dropped {m}");
                    }
                }
                for (rid, off) in &src.regions {
                    let jo = j.regions.get(rid).expect("join dropped a region");
                    for m in si_members(off) {
                        assert!(jo.contains(m), "join region {rid:?} dropped {m}");
                    }
                }
            }
        }
    }

    /// `widen` must also be a sound upper bound (contains both operands'
    /// members) — widening only ever loosens bounds.
    #[test]
    fn prop_region_value_set_widen_is_sound_upper_bound() {
        let mut rng = Rng::new(0xF00D);
        for _ in 0..10_000 {
            let a = gen_rvs(&mut rng);
            let b = gen_rvs(&mut rng);
            let w = a.widen(&b);

            for src in [&a, &b] {
                if let Some(g) = &src.global {
                    let wg = w.global.expect("widen global present when an operand had one");
                    for m in si_members(g) {
                        assert!(wg.contains(m) || wg.is_top(), "widen global dropped {m}");
                    }
                }
                for (rid, off) in &src.regions {
                    let wo = w.regions.get(rid).expect("widen dropped a region");
                    for m in si_members(off) {
                        assert!(wo.contains(m) || wo.is_top(), "widen region {rid:?} dropped {m}");
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Randomized lattice/oracle property tests for the crate-root StridedInterval
// (the independent 64-bit copy), including a cross-check against the
// `strided_interval` module's implementation on identical inputs.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod root_si_lattice_props {
    use super::StridedInterval as RootSi;
    use crate::strided_interval::StridedInterval as ModSi;

    use crate::test_prng::xorshift;

    /// Random small root-SI (values in 0..=255 so enumeration is cheap and no
    /// 64-bit wrap paths trigger; wrap paths return TOP which is trivially
    /// sound).
    fn rand_root(state: &mut u64) -> RootSi {
        let lo = xorshift(state) & 0xFF;
        let hi = xorshift(state) & 0xFF;
        let stride = (xorshift(state) % 5) + 1;
        RootSi::new(lo.min(hi), lo.max(hi), stride)
    }

    fn elements(si: &RootSi) -> Vec<u64> {
        (0u64..=0x2FF).filter(|&v| si.contains(v)).collect()
    }

    /// The same interval in the `strided_interval` module's 64-bit domain.
    fn to_mod(si: &RootSi) -> ModSi {
        if si.is_bottom() {
            ModSi::Bottom
        } else {
            ModSi::new(si.stride, si.lo, si.hi, 64)
        }
    }

    #[test]
    fn prop_root_join_commutative_and_sound() {
        let mut state = 0x2007_5E1F_0001_u64 | 1;
        for _ in 0..3000 {
            let a = rand_root(&mut state);
            let b = rand_root(&mut state);
            let j = a.join(&b);
            assert_eq!(j, b.join(&a), "root join not commutative: {a:?} {b:?}");
            for si in [&a, &b] {
                for v in elements(si) {
                    assert!(j.contains(v), "root join lost {v}: {a:?} {b:?} -> {j:?}");
                }
            }
        }
    }

    #[test]
    fn prop_root_meet_is_lower_bound_and_keeps_common() {
        let mut state = 0x3EE7_1234_5678_u64 | 1;
        for _ in 0..3000 {
            let a = rand_root(&mut state);
            let b = rand_root(&mut state);
            let m = a.meet(&b);
            // Lower bound: nothing in the meet outside either operand.
            for v in elements(&m) {
                assert!(a.contains(v) && b.contains(v), "root meet invented {v}: {a:?} {b:?} -> {m:?}");
            }
            // Over-approximation of the intersection: no common member dropped.
            for v in elements(&a) {
                if b.contains(v) {
                    assert!(m.contains(v), "root meet dropped common {v}: {a:?} {b:?} -> {m:?}");
                }
            }
        }
    }

    #[test]
    fn prop_root_widen_over_approximates_join_and_terminates() {
        let mut state = 0x71DE_AA55_CC33_u64 | 1;
        for _ in 0..2000 {
            let a = rand_root(&mut state);
            let b = rand_root(&mut state);
            let w = a.widen(&b);
            for si in [&a, &b] {
                for v in elements(si) {
                    assert!(w.contains(v), "root widen below join: lost {v}: {a:?} {b:?} -> {w:?}");
                }
            }
        }
        // Termination: repeated widening stabilises quickly.
        for _ in 0..300 {
            let mut cur = rand_root(&mut state);
            let mut steps = 0usize;
            loop {
                let nxt = rand_root(&mut state);
                let w = cur.widen(&nxt);
                if w == cur {
                    break;
                }
                cur = w;
                steps += 1;
                assert!(steps <= 100, "root widening chain did not stabilise: {cur:?}");
            }
        }
    }

    #[test]
    fn prop_root_arith_transfer_sound() {
        let mut state = 0xA217_9F0E_1357_u64 | 1;
        for _ in 0..1500 {
            let a = rand_root(&mut state);
            let b = rand_root(&mut state);
            let ea = elements(&a);
            let eb = elements(&b);
            let add = a.add(&b);
            let sub = a.sub(&b);
            let mul = a.mul(&b);
            let band = a.bitwise_and(&b);
            let bor = a.bitwise_or(&b);
            for &x in &ea {
                for &y in &eb {
                    assert!(add.contains(x + y), "root add missed {x}+{y}: {a:?} {b:?} -> {add:?}");
                    let d = x.wrapping_sub(y);
                    assert!(sub.contains(d), "root sub missed {x}-{y}: {a:?} {b:?} -> {sub:?}");
                    assert!(mul.contains(x * y), "root mul missed {x}*{y}: {a:?} {b:?} -> {mul:?}");
                    assert!(band.contains(x & y), "root and missed {x}&{y}: -> {band:?}");
                    assert!(bor.contains(x | y), "root or missed {x}|{y}: -> {bor:?}");
                }
            }
        }
    }

    // ── Cross-implementation oracle: the two independent StridedInterval
    // copies must both be sound on identical inputs; any concrete result that
    // one contains and the other does not pinpoints the unsound copy. ────────
    #[test]
    fn prop_cross_copy_join_add_sub_agree_on_soundness() {
        let mut state = 0xD1FF_0DD5_4242_u64 | 1;
        for _ in 0..1500 {
            let a = rand_root(&mut state);
            let b = rand_root(&mut state);
            let (ma, mb) = (to_mod(&a), to_mod(&b));
            let ea = elements(&a);
            let eb = elements(&b);

            let rj = a.join(&b);
            let mj = ma.join(&mb);
            for &v in ea.iter().chain(eb.iter()) {
                let in_root = rj.contains(v);
                let in_mod = mj.contains(v);
                assert!(
                    in_root,
                    "DIVERGENCE: root join UNSOUND (missing {v}), module join contains={in_mod}: {a:?} {b:?}"
                );
                assert!(
                    in_mod,
                    "DIVERGENCE: module join UNSOUND (missing {v}), root join contains={in_root}: {ma} {mb}"
                );
            }

            let ra = a.add(&b);
            let maa = ma.add(&mb);
            let rs = a.sub(&b);
            let msn = ma.sub(&mb);
            for &x in &ea {
                for &y in &eb {
                    let s = x + y;
                    assert!(ra.contains(s), "DIVERGENCE: root add UNSOUND missing {s} (mod={})", maa.contains(s));
                    assert!(maa.contains(s), "DIVERGENCE: module add UNSOUND missing {s} (root={})", ra.contains(s));
                    let d = x.wrapping_sub(y);
                    assert!(rs.contains(d), "DIVERGENCE: root sub UNSOUND missing {d} (mod={})", msn.contains(d));
                    assert!(msn.contains(d), "DIVERGENCE: module sub UNSOUND missing {d} (root={})", rs.contains(d));
                }
            }
        }
    }
}
