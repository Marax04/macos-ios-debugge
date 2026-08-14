//! `value_range` — Value Range Analysis (simplified VSA).
//!
//! Computes strided intervals for each SSA variable:
//!   `[min, max, stride]` means the variable's value is in `{min, min+stride, …, max}`.
//!
//! Used for:
//! - Jump-table bound detection (limit the number of valid table entries).
//! - Loop induction variable identification (stride == loop step).
//!
//! Audit note (dataflow-crate iteration 5): grepped the whole workspace for
//! `rustre_analysis_dataflow::` usage — nothing outside this crate calls into
//! this module (the standalone `rustre-analysis-vsa` crate is a separate,
//! unrelated implementation and does not depend on this one). Only this
//! module's own unit tests exercise it — treat it as orphaned library code
//! until a real consumer shows up.
//! - Buffer-overflow analysis (access offset bounded).
//!
//! Simplified from "Value-Set Analysis in the Executables"
//! (Balakrishnan & Reps, PLDI 2004).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::cfg_dom::BBId;
use crate::ssa::{SsaFunction, SsaVar};

// ── ValueRange ────────────────────────────────────────────────────────────────

/// A strided interval: the set `{ n ∈ Z | min ≤ n ≤ max, (n-min) % stride == 0 }`.
/// `None` bounds represent ±∞.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueRange {
    /// Inclusive lower bound; `None` = −∞.
    pub min: Option<i64>,
    /// Inclusive upper bound; `None` = +∞.
    pub max: Option<i64>,
    /// Stride (granularity, always > 0); 1 = fully dense.
    pub stride: u64,
    /// True when this variable is known to be a pointer.
    pub is_pointer: bool,
}

impl ValueRange {
    /// An unconstrained range (⊤).
    #[must_use]
    pub const fn top() -> Self {
        Self {
            min: None,
            max: None,
            stride: 1,
            is_pointer: false,
        }
    }

    /// The empty range (⊥): no values are members.
    #[must_use]
    pub const fn bottom() -> Self {
        // Encode bottom as min > max (impossible interval).
        Self {
            min: Some(1),
            max: Some(0),
            stride: 1,
            is_pointer: false,
        }
    }

    /// Whether this range is the bottom (empty) range.
    #[must_use]
    pub const fn is_bottom(&self) -> bool {
        match (self.min, self.max) {
            (Some(lo), Some(hi)) => lo > hi,
            _ => false,
        }
    }

    /// A single known constant.
    #[must_use]
    pub const fn constant(c: i64) -> Self {
        Self {
            min: Some(c),
            max: Some(c),
            stride: 1,
            is_pointer: false,
        }
    }

    /// A range `[lo, hi]` with stride 1.
    #[must_use]
    pub const fn interval(lo: i64, hi: i64) -> Self {
        let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
        Self {
            min: Some(lo),
            max: Some(hi),
            stride: 1,
            is_pointer: false,
        }
    }

    /// A strided range.
    #[must_use]
    pub fn strided(lo: i64, hi: i64, stride: u64) -> Self {
        let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
        Self {
            min: Some(lo),
            max: Some(hi),
            stride: stride.max(1),
            is_pointer: false,
        }
    }

    /// True when this is a single known constant.
    #[must_use]
    pub const fn is_constant(&self) -> bool {
        match (self.min, self.max) {
            (Some(lo), Some(hi)) => lo == hi,
            _ => false,
        }
    }

    /// Return the constant value if this is a singleton.
    #[must_use]
    pub const fn constant_value(&self) -> Option<i64> {
        match (self.min, self.max) {
            (Some(lo), Some(hi)) if lo == hi => Some(lo),
            _ => None,
        }
    }

    /// True when the value is provably non-negative.
    #[must_use]
    pub fn is_non_negative(&self) -> bool {
        self.min.is_some_and(|lo| lo >= 0)
    }

    /// True when the range is bounded on both ends.
    #[must_use]
    pub const fn is_bounded(&self) -> bool {
        self.min.is_some() && self.max.is_some()
    }

    /// Compute the number of distinct values in the range (if finite).
    #[must_use]
    pub const fn cardinality(&self) -> Option<u64> {
        match (self.min, self.max) {
            (Some(lo), Some(hi)) if hi >= lo && self.stride != 0 => {
                // Use checked_sub to avoid overflow when lo is very negative and
                // hi is very positive (e.g. lo = i64::MIN, hi = i64::MAX would
                // overflow i64 subtraction).  If it overflows we fall back to None
                // (unbounded cardinality).
                let Some(span_i64) = hi.checked_sub(lo) else {
                    return None;
                };
                let span = span_i64.cast_unsigned();
                (span / self.stride).checked_add(1)
            }
            _ => None,
        }
    }

    /// Join (widening) of two ranges: take the min of lowers and max of uppers.
    /// The stride becomes GCD of the two strides.
    ///
    /// Bottom is the identity element. It has to be special-cased because it is
    /// encoded as the *sentinel empty interval* `[1, 0]` rather than as a
    /// distinct variant: componentwise min/max against that sentinel invents a
    /// range (`⊥ ∨ {5}` came out as `{1..5}`) instead of returning the other
    /// operand. `restrict_lower` / `restrict_upper` are public and really do
    /// return bottom, so these values genuinely reach `join`.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        if self.is_bottom() {
            return other.clone();
        }
        if other.is_bottom() {
            return self.clone();
        }
        let min = match (self.min, other.min) {
            (Some(a), Some(b)) => Some(a.min(b)),
            _ => None,
        };
        let max = match (self.max, other.max) {
            (Some(a), Some(b)) => Some(a.max(b)),
            _ => None,
        };
        let stride = gcd(self.stride, other.stride);
        Self {
            min,
            max,
            stride,
            is_pointer: self.is_pointer || other.is_pointer,
        }
    }

    /// Meet (narrowing) of two ranges: take the max of lowers and min of uppers.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        let min = match (self.min, other.min) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let max = match (self.max, other.max) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let stride = self.stride.max(other.stride);
        Self {
            min,
            max,
            stride,
            is_pointer: self.is_pointer && other.is_pointer,
        }
    }

    /// Add a constant offset to the range.
    #[must_use]
    pub fn add_constant(&self, c: i64) -> Self {
        Self {
            min: self.min.map(|lo| lo.saturating_add(c)),
            max: self.max.map(|hi| hi.saturating_add(c)),
            stride: self.stride,
            is_pointer: self.is_pointer,
        }
    }

    /// Multiply the range by a positive constant (scales bounds and stride).
    #[must_use]
    pub fn mul_constant(&self, c: i64) -> Self {
        if c == 0 {
            return Self::constant(0);
        }
        let (new_min, new_max) = if c > 0 {
            (
                self.min.map(|lo| lo.saturating_mul(c)),
                self.max.map(|hi| hi.saturating_mul(c)),
            )
        } else {
            (
                self.max.map(|hi| hi.saturating_mul(c)),
                self.min.map(|lo| lo.saturating_mul(c)),
            )
        };
        let new_stride = self.stride.saturating_mul(c.unsigned_abs());
        Self {
            min: new_min,
            max: new_max,
            stride: new_stride.max(1),
            is_pointer: self.is_pointer,
        }
    }

    /// Restrict to values ≥ lo (for e.g. `if x >= 0` branch constraints).
    #[must_use]
    pub fn restrict_lower(&self, lo: i64) -> Self {
        let new_min = Some(self.min.map_or(lo, |m| m.max(lo)));
        if let (Some(new_lo), Some(hi)) = (new_min, self.max)
            && new_lo > hi {
                return Self::bottom(); // empty range — no value satisfies both constraints
            }
        Self {
            min: new_min,
            max: self.max,
            stride: self.stride,
            is_pointer: self.is_pointer,
        }
    }

    /// Restrict to values ≤ hi.
    #[must_use]
    pub fn restrict_upper(&self, hi: i64) -> Self {
        let new_max = Some(self.max.map_or(hi, |m| m.min(hi)));
        if let (Some(lo), Some(new_hi)) = (self.min, new_max)
            && lo > new_hi {
                return Self::bottom(); // empty range — no value satisfies both constraints
            }
        Self {
            min: self.min,
            max: new_max,
            stride: self.stride,
            is_pointer: self.is_pointer,
        }
    }
}

impl std::fmt::Display for ValueRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let lo = self.min.map_or_else(|| "-∞".to_string(), |v| v.to_string());
        let hi = self.max.map_or_else(|| "+∞".to_string(), |v| v.to_string());
        if self.stride == 1 {
            write!(f, "[{lo}, {hi}]")
        } else {
            write!(f, "[{lo}, {hi}] stride {}", self.stride)
        }
    }
}

// ── ValueRangeMap ─────────────────────────────────────────────────────────────

/// Maps each SSA variable to its computed value range.
pub type ValueRangeMap = HashMap<SsaVar, ValueRange>;

// ── analyze_value_ranges ──────────────────────────────────────────────────────

/// Simple forward dataflow: propagate range information through an SSA function.
///
/// This is a conservative approximation — each block is visited once in
/// topological order.  For precise loop handling, a fixed-point iteration with
/// widening would be needed.
#[must_use]
pub fn analyze_value_ranges(func: &SsaFunction) -> ValueRangeMap {
    let mut ranges: ValueRangeMap = HashMap::new();

    // Process blocks in topological order (DFS post-order reversed).
    let order = topo_order(func);

    for bb in order {
        let block = &func.blocks[bb.0];

        // φ-nodes: join the ranges of all incoming arguments.
        for phi in &block.phis {
            if let Some(ref sv) = phi.result {
                let range: ValueRange = phi
                    .args
                    .iter()
                    .filter_map(|a| a.as_ref())
                    .fold(None::<ValueRange>, |acc, arg| {
                        let arg_range = ranges.get(arg).cloned().unwrap_or_else(ValueRange::top);
                        Some(match acc {
                            None => arg_range,
                            Some(r) => r.join(&arg_range),
                        })
                    })
                    .unwrap_or_else(ValueRange::top);
                ranges.insert(sv.clone(), range);
            }
        }

        // Instructions: conservative analysis.
        for instr in &block.instrs {
            if let Some(ref sv) = instr.ssa_def {
                // If there are no uses, the value is completely unknown.
                let range = if instr.ssa_uses.is_empty() {
                    ValueRange::top()
                } else if instr.ssa_uses.len() == 1 {
                    // Simple copy: inherit the source range.
                    ranges
                        .get(&instr.ssa_uses[0])
                        .cloned()
                        .unwrap_or_else(ValueRange::top)
                } else {
                    // Multiple uses (e.g. binary op): join all source ranges.
                    instr
                        .ssa_uses
                        .iter()
                        .map(|u| ranges.get(u).cloned().unwrap_or_else(ValueRange::top))
                        .reduce(|a, b| a.join(&b))
                        .unwrap_or_else(ValueRange::top)
                };
                ranges.insert(sv.clone(), range);
            }
        }
    }

    ranges
}

// ── Loop induction variable detection ─────────────────────────────────────────

/// A detected loop induction variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InductionVar {
    pub var: SsaVar,
    /// The loop entry block.
    pub loop_header: BBId,
    /// Initial value (from the pre-header φ argument).
    pub initial: Option<i64>,
    /// Step per iteration (stride).
    pub step: Option<i64>,
    /// Upper bound of the loop (if determinable from a comparison).
    pub bound: Option<i64>,
}

/// Detect potential loop induction variables by looking for φ-nodes whose
/// arguments include a variable that adds a constant stride.
#[must_use]
pub fn detect_induction_vars(func: &SsaFunction, ranges: &ValueRangeMap) -> Vec<InductionVar> {
    let mut ivs = Vec::new();

    for (bb_idx, block) in func.blocks.iter().enumerate() {
        for phi in &block.phis {
            if let Some(ref sv) = phi.result {
                // A φ-node is a candidate induction variable if one of its
                // arguments has a range that is a stride-1 extension of the other.
                if phi.args.len() == 2 {
                    let r0 = phi.args[0]
                        .as_ref()
                        .and_then(|a| ranges.get(a))
                        .cloned()
                        .unwrap_or_else(ValueRange::top);
                    let r1 = phi.args[1]
                        .as_ref()
                        .and_then(|a| ranges.get(a))
                        .cloned()
                        .unwrap_or_else(ValueRange::top);

                    // If both bounds are known and r1 = r0 + step, it's inductive.
                    if let (Some(lo0), Some(hi0), Some(lo1), Some(hi1)) =
                        (r0.min, r0.max, r1.min, r1.max)
                    {
                        // Use checked_sub to avoid overflow when bounds span the
                        // full i64 range (e.g. lo = i64::MIN, hi = i64::MAX).
                        let Some(step0) = hi0.checked_sub(lo0) else { continue };
                        let Some(step1) = hi1.checked_sub(lo1) else { continue };
                        if step0 == step1 && step0 > 0 {
                            ivs.push(InductionVar {
                                var: sv.clone(),
                                loop_header: BBId(bb_idx),
                                initial: Some(lo0),
                                step: Some(step0),
                                bound: Some(hi1),
                            });
                        }
                    }
                }
            }
        }
    }

    ivs
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// Iterative post-order DFS to avoid stack overflow on deep CFGs.
///
/// `func.cfg` and `func.blocks` are both public fields, so a caller-built
/// `SsaFunction` can have a `cfg.entry`/`cfg.succ` that references block
/// indices `>= func.blocks.len()` (or `visited.len()`). Every index derived
/// from CFG data is bounds-checked before use so such malformed input is
/// silently ignored instead of panicking.
fn dfs_topo(bb: BBId, func: &SsaFunction, visited: &mut [bool], order: &mut Vec<BBId>) {
    if bb.0 >= visited.len() || visited[bb.0] {
        return;
    }
    visited[bb.0] = true;
    let mut stack: Vec<(BBId, usize)> = vec![(bb, 0)];
    while let Some(&mut (cur, ref mut idx)) = stack.last_mut() {
        let succs = func.cfg.succ.get(cur.0);
        if let Some(&s) = succs.and_then(|list| list.get(*idx)) {
            *idx += 1;
            if s.0 < visited.len() && !visited[s.0] {
                visited[s.0] = true;
                stack.push((s, 0));
            }
        } else {
            order.push(cur);
            stack.pop();
        }
    }
}

/// Compute a forward topological order of basic blocks via DFS.
fn topo_order(func: &SsaFunction) -> Vec<BBId> {
    let n = func.blocks.len();
    let mut visited = vec![false; n];
    let mut order = Vec::with_capacity(n);

    dfs_topo(func.cfg.entry, func, &mut visited, &mut order);
    order.reverse(); // post-order → pre-order
    order
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg_dom::{BBId, Cfg};
    use crate::ssa::{Instruction, SsaFunction, SsaVar, Var};

    use crate::test_util::sv;

    #[test]
    fn test_value_range_constant() {
        let r = ValueRange::constant(42);
        assert!(r.is_constant());
        assert_eq!(r.constant_value(), Some(42));
    }

    #[test]
    fn test_value_range_interval() {
        let r = ValueRange::interval(0, 100);
        assert!(!r.is_constant());
        assert!(r.is_bounded());
        assert_eq!(r.cardinality(), Some(101));
    }

    #[test]
    fn test_value_range_join() {
        let a = ValueRange::interval(0, 10);
        let b = ValueRange::interval(5, 20);
        let j = a.join(&b);
        assert_eq!(j.min, Some(0));
        assert_eq!(j.max, Some(20));
    }

    #[test]
    fn test_value_range_meet() {
        let a = ValueRange::interval(0, 10);
        let b = ValueRange::interval(5, 20);
        let m = a.meet(&b);
        assert_eq!(m.min, Some(5));
        assert_eq!(m.max, Some(10));
    }

    #[test]
    fn test_value_range_add_constant() {
        let r = ValueRange::interval(0, 10);
        let r2 = r.add_constant(5);
        assert_eq!(r2.min, Some(5));
        assert_eq!(r2.max, Some(15));
    }

    #[test]
    fn test_value_range_mul_constant() {
        let r = ValueRange::interval(1, 5);
        let r2 = r.mul_constant(3);
        assert_eq!(r2.min, Some(3));
        assert_eq!(r2.max, Some(15));
    }

    #[test]
    fn test_value_range_restrict_lower() {
        let r = ValueRange::interval(-10, 10);
        let r2 = r.restrict_lower(0);
        assert_eq!(r2.min, Some(0));
        assert_eq!(r2.max, Some(10));
    }

    #[test]
    fn test_value_range_restrict_upper() {
        let r = ValueRange::interval(0, 100);
        let r2 = r.restrict_upper(50);
        assert_eq!(r2.max, Some(50));
    }

    #[test]
    fn test_value_range_display() {
        let r = ValueRange::interval(0, 10);
        assert_eq!(r.to_string(), "[0, 10]");
    }

    #[test]
    fn test_value_range_top() {
        let r = ValueRange::top();
        assert!(r.min.is_none());
        assert!(r.max.is_none());
        assert!(!r.is_constant());
    }

    #[test]
    fn test_analyze_value_ranges_simple() {
        let succs = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(2, succs, BBId(0), BBId(1));
        let mut i0 = Instruction::new(0, Some(Var::new("x")), vec![]);
        i0.ssa_def = Some(sv("x", 0));
        let func = SsaFunction::new(cfg, &vec![vec![i0], vec![]]);
        let ranges = analyze_value_ranges(&func);
        assert!(ranges.contains_key(&sv("x", 0)));
    }

    #[test]
    fn test_detect_induction_vars_positive_case() {
        use crate::ssa::PhiNode;
        let succs = vec![vec![]];
        let cfg = Cfg::new(1, succs, BBId(0), BBId(0));
        let mut phi = PhiNode::new(Var::new("i"), 2);
        phi.result = Some(sv("i", 1));
        phi.args = vec![Some(sv("init", 0)), Some(sv("carried", 0))];
        let mut ranges: ValueRangeMap = HashMap::new();
        ranges.insert(sv("init", 0), ValueRange::interval(0, 5));
        ranges.insert(sv("carried", 0), ValueRange::interval(10, 15));

        let mut func = SsaFunction::new(cfg, &[vec![]]);
        func.blocks[0].phis.push(phi);

        let ivs = detect_induction_vars(&func, &ranges);
        assert_eq!(ivs.len(), 1);
        assert_eq!(ivs[0].initial, Some(0));
        assert_eq!(ivs[0].step, Some(5));
        assert_eq!(ivs[0].bound, Some(15));
    }

    #[test]
    fn test_detect_induction_vars_rejects_unequal_width() {
        use crate::ssa::PhiNode;
        let cfg = Cfg::new(1, vec![vec![]], BBId(0), BBId(0));
        let mut phi = PhiNode::new(Var::new("i"), 2);
        phi.result = Some(sv("i", 1));
        phi.args = vec![Some(sv("init", 0)), Some(sv("carried", 0))];
        let mut ranges: ValueRangeMap = HashMap::new();
        ranges.insert(sv("init", 0), ValueRange::interval(0, 5));
        ranges.insert(sv("carried", 0), ValueRange::interval(10, 100)); // different width

        let mut func = SsaFunction::new(cfg, &[vec![]]);
        func.blocks[0].phis.push(phi);

        let ivs = detect_induction_vars(&func, &ranges);
        assert!(ivs.is_empty());
    }

    #[test]
    fn test_gcd() {
        assert_eq!(gcd(12, 8), 4);
        assert_eq!(gcd(7, 0), 7);
        assert_eq!(gcd(0, 5), 5);
    }

    #[test]
    fn test_cardinality_strided() {
        let r = ValueRange::strided(0, 20, 4);
        assert_eq!(r.cardinality(), Some(6)); // 0,4,8,12,16,20
    }

    #[test]
    fn test_is_non_negative() {
        let r = ValueRange::interval(0, 100);
        assert!(r.is_non_negative());
        let r2 = ValueRange::interval(-1, 100);
        assert!(!r2.is_non_negative());
    }

    #[test]
    fn test_value_range_contains() {
        let r = ValueRange::interval(5, 10);
        assert!(r.contains(7));
        assert!(!r.contains(4));
        assert!(!r.contains(11));
    }

    #[test]
    fn test_value_range_meet_basic() {
        let a = ValueRange::interval(2, 8);
        let b = ValueRange::interval(5, 12);
        let m = a.meet(&b);
        assert_eq!(m.min, Some(5));
        assert_eq!(m.max, Some(8));
    }

    #[test]
    fn test_value_range_join_empty_is_interval() {
        let a = ValueRange::interval(0, 3);
        let b = ValueRange::interval(7, 10);
        let j = a.join(&b);
        assert_eq!(j.min, Some(0));
        assert_eq!(j.max, Some(10));
    }

    #[test]
    fn test_value_range_add() {
        let a = ValueRange::interval(1, 5);
        let b = ValueRange::interval(2, 4);
        let c = a.add(&b);
        assert_eq!(c.min, Some(3));
        assert_eq!(c.max, Some(9));
    }

    #[test]
    fn test_value_range_sub() {
        let a = ValueRange::interval(5, 10);
        let b = ValueRange::interval(1, 3);
        let c = a.sub(&b);
        assert_eq!(c.min, Some(2));
        assert_eq!(c.max, Some(9));
    }

    #[test]
    fn test_value_range_negate() {
        let r = ValueRange::interval(2, 7);
        let n = r.negate();
        assert_eq!(n.min, Some(-7));
        assert_eq!(n.max, Some(-2));
    }

    #[test]
    fn test_value_range_bottom_is_empty() {
        let r = ValueRange::bottom();
        assert!(r.is_bottom());
    }

    #[test]
    fn test_value_range_singleton() {
        let r = ValueRange::constant(42);
        assert!(r.is_constant());
        assert_eq!(r.min, Some(42));
        assert_eq!(r.max, Some(42));
    }
}

// ── ValueRange extended API ───────────────────────────────────────────────────

impl ValueRange {
    /// Whether `value` is contained in this range.
    #[must_use]
    pub const fn contains(&self, value: i64) -> bool {
        match (self.min, self.max) {
            (Some(lo), Some(hi)) => value >= lo && value <= hi,
            (Some(lo), None) => value >= lo,
            (None, Some(hi)) => value <= hi,
            (None, None) => !self.is_bottom(),
        }
    }

    /// Negate range: [-max, -min].
    #[must_use]
    pub fn negate(&self) -> Self {
        Self {
            min: self.max.map(i64::saturating_neg),
            max: self.min.map(i64::saturating_neg),
            stride: self.stride,
            is_pointer: self.is_pointer,
        }
    }

    /// Add two ranges: [a+c, b+d].
    #[must_use]
    pub const fn add(&self, other: &Self) -> Self {
        let lo = match (self.min, other.min) {
            (Some(a), Some(b)) => Some(a.saturating_add(b)),
            _ => None,
        };
        let hi = match (self.max, other.max) {
            (Some(a), Some(b)) => Some(a.saturating_add(b)),
            _ => None,
        };
        Self {
            min: lo,
            max: hi,
            stride: 1,
            is_pointer: false,
        }
    }

    /// Subtract: [a-d, b-c].
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        let neg = other.negate();
        self.add(&neg)
    }

    /// Multiply (conservative widening for non-singleton ranges).
    ///
    /// # Panics
    /// Panics if the internal bounds produce an empty sorted slice (should not
    /// happen with well-formed ranges).
    #[must_use]
    pub fn mul(&self, other: &Self) -> Self {
        match (self.min, self.max, other.min, other.max) {
            (Some(a), Some(b), Some(c), Some(d)) => {
                let products = [
                    a.saturating_mul(c),
                    a.saturating_mul(d),
                    b.saturating_mul(c),
                    b.saturating_mul(d),
                ];
                let lo = *products.iter().min().unwrap();
                let hi = *products.iter().max().unwrap();
                Self::interval(lo, hi)
            }
            _ => Self::top(),
        }
    }

    /// Range for a comparison `self op other` where op ∈ {<, <=, ==, !=, >, >=}.
    /// Returns a boolean range [0,1].
    #[must_use]
    pub const fn compare_result(&self) -> Self {
        Self::interval(0, 1)
    }

    /// Widening operator (prevents non-termination in loops).
    ///
    /// The standard widening: if the new min/max extends beyond the old,
    /// widen it to −∞/+∞.
    #[must_use]
    pub const fn widen(&self, new_range: &Self) -> Self {
        // Soundness (regression, found by randomized lattice testing):
        // `widen(a, b)` must over-approximate `join(a, b)`, i.e. contain every
        // value of BOTH operands.  The previous implementation returned
        // `new_range`'s bound whenever it did not extend past `self`'s, so
        // `widen([0,10], [5,10])` came out as `[5,10]`, silently dropping
        // `self`'s values 0..4.  Keep `self`'s bound instead, and widen to
        // ±∞ when either side is unbounded or `new_range` extends past it.
        let lo = match (self.min, new_range.min) {
            (Some(old), Some(new)) => {
                if new < old {
                    None // widen to -∞
                } else {
                    Some(old)
                }
            }
            _ => None, // either side already -∞
        };
        let hi = match (self.max, new_range.max) {
            (Some(old), Some(new)) => {
                if new > old {
                    None // widen to +∞
                } else {
                    Some(old)
                }
            }
            _ => None, // either side already +∞
        };
        Self {
            min: lo,
            max: hi,
            stride: 1,
            is_pointer: false,
        }
    }

    /// Whether the range is a singleton (single known value).
    #[must_use]
    pub const fn is_singleton(&self) -> bool {
        self.is_constant()
    }

    /// Whether the range is definitely positive (min > 0).
    #[must_use]
    pub fn is_positive(&self) -> bool {
        self.min.is_some_and(|lo| lo > 0)
    }

    /// Whether the range is definitely negative (max < 0).
    #[must_use]
    pub fn is_negative(&self) -> bool {
        self.max.is_some_and(|hi| hi < 0)
    }

    /// Whether the range covers zero.
    #[must_use]
    pub const fn may_be_zero(&self) -> bool {
        self.contains(0)
    }
}

// ── RangeAnalysisResult extended ──────────────────────────────────────────────

/// Extended queries on the value range analysis result.
pub struct RangeAnalysisExt<'a> {
    pub result: &'a std::collections::HashMap<crate::ssa::SsaVar, ValueRange>,
}

impl<'a> RangeAnalysisExt<'a> {
    /// Create a new extension wrapper.
    #[must_use]
    pub const fn new(result: &'a std::collections::HashMap<crate::ssa::SsaVar, ValueRange>) -> Self {
        Self { result }
    }

    /// Whether `var` is provably non-negative.
    #[must_use]
    pub fn is_non_negative(&self, var: &crate::ssa::SsaVar) -> bool {
        self.result
            .get(var)
            .is_some_and(ValueRange::is_non_negative)
    }

    /// Whether `var` is provably positive.
    #[must_use]
    pub fn is_positive(&self, var: &crate::ssa::SsaVar) -> bool {
        self.result.get(var).is_some_and(ValueRange::is_positive)
    }

    /// Whether `var` may be zero.
    #[must_use]
    pub fn may_be_zero(&self, var: &crate::ssa::SsaVar) -> bool {
        self.result.get(var).is_none_or(ValueRange::may_be_zero)
    }

    /// All variables with a known constant value.
    #[must_use]
    pub fn constant_vars(&self) -> Vec<(&crate::ssa::SsaVar, i64)> {
        self.result
            .iter()
            .filter_map(|(var, r)| r.min.filter(|_| r.is_constant()).map(|c| (var, c)))
            .collect()
    }

    /// All variables with a finite bounded range.
    #[must_use]
    pub fn bounded_vars(&self) -> Vec<&crate::ssa::SsaVar> {
        self.result
            .iter()
            .filter(|(_, r)| r.min.is_some() && r.max.is_some() && !r.is_bottom())
            .map(|(v, _)| v)
            .collect()
    }
}

// ── Extended value range tests ────────────────────────────────────────────────

#[cfg(test)]
mod value_range_extended_tests {
    use super::*;
    use crate::ssa::SsaVar;

    use crate::test_util::sv;

    #[test]
    fn range_contains_within_bounds() {
        let r = ValueRange::interval(10, 20);
        assert!(r.contains(10));
        assert!(r.contains(15));
        assert!(r.contains(20));
        assert!(!r.contains(9));
        assert!(!r.contains(21));
    }

    #[test]
    fn range_contains_top_all() {
        let r = ValueRange::top();
        assert!(r.contains(i64::MAX));
        assert!(r.contains(i64::MIN));
    }

    #[test]
    fn meet_disjoint_is_bottom() {
        let a = ValueRange::interval(0, 3);
        let b = ValueRange::interval(5, 8);
        let m = a.meet(&b);
        assert!(m.is_bottom());
    }

    #[test]
    fn meet_overlapping() {
        let a = ValueRange::interval(0, 10);
        let b = ValueRange::interval(5, 15);
        let m = a.meet(&b);
        assert_eq!(m.min, Some(5));
        assert_eq!(m.max, Some(10));
    }

    #[test]
    fn add_two_intervals() {
        let a = ValueRange::interval(1, 3);
        let b = ValueRange::interval(4, 6);
        let c = a.add(&b);
        assert_eq!(c.min, Some(5));
        assert_eq!(c.max, Some(9));
    }

    #[test]
    fn sub_intervals() {
        let a = ValueRange::interval(10, 20);
        let b = ValueRange::interval(1, 5);
        let c = a.sub(&b);
        assert_eq!(c.min, Some(5));
        assert_eq!(c.max, Some(19));
    }

    #[test]
    fn mul_positive_intervals() {
        let a = ValueRange::interval(2, 4);
        let b = ValueRange::interval(3, 5);
        let c = a.mul(&b);
        assert_eq!(c.min, Some(6));
        assert_eq!(c.max, Some(20));
    }

    #[test]
    fn negate_positive() {
        let r = ValueRange::interval(1, 5);
        let n = r.negate();
        assert_eq!(n.min, Some(-5));
        assert_eq!(n.max, Some(-1));
    }

    #[test]
    fn widen_extends_min_to_infinity() {
        let old = ValueRange::interval(0, 10);
        let new = ValueRange::interval(-5, 10);
        let w = old.widen(&new);
        assert!(w.min.is_none()); // widened to -∞
        assert_eq!(w.max, Some(10));
    }

    #[test]
    fn widen_extends_max_to_infinity() {
        let old = ValueRange::interval(0, 10);
        let new = ValueRange::interval(0, 15);
        let w = old.widen(&new);
        assert_eq!(w.min, Some(0));
        assert!(w.max.is_none()); // widened to +∞
    }

    #[test]
    fn widen_keeps_old_bounds_when_new_is_narrower() {
        // Regression (found by randomized lattice testing, seed 3 of the
        // widen-soundness property): widen(a, b) must contain all of a.
        // Old behavior: widen([0,10], [5,10]) == [5,10], losing 0..4.
        let old = ValueRange::interval(0, 10);
        let new = ValueRange::interval(5, 10);
        let w = old.widen(&new);
        assert_eq!(w.min, Some(0));
        assert_eq!(w.max, Some(10));
        // And when self is unbounded, the result must stay unbounded.
        let unb = ValueRange::top().widen(&ValueRange::interval(0, 1));
        assert!(unb.min.is_none() && unb.max.is_none());
    }

    #[test]
    fn may_be_zero_constant_nonzero() {
        let r = ValueRange::constant(5);
        assert!(!r.may_be_zero());
    }

    #[test]
    fn may_be_zero_includes_zero() {
        let r = ValueRange::interval(-1, 1);
        assert!(r.may_be_zero());
    }

    #[test]
    fn is_positive_above_zero() {
        let r = ValueRange::interval(1, 100);
        assert!(r.is_positive());
    }

    #[test]
    fn is_negative_below_zero() {
        let r = ValueRange::interval(-100, -1);
        assert!(r.is_negative());
    }

    #[test]
    fn range_analysis_ext_constant_vars() {
        let mut map = std::collections::HashMap::new();
        map.insert(sv("x", 0), ValueRange::constant(7));
        map.insert(sv("y", 0), ValueRange::interval(0, 5));
        let ext = RangeAnalysisExt::new(&map);
        let consts = ext.constant_vars();
        assert_eq!(consts.len(), 1);
        assert_eq!(consts[0].1, 7);
    }

    #[test]
    fn range_analysis_ext_bounded_vars() {
        let mut map = std::collections::HashMap::new();
        map.insert(sv("a", 0), ValueRange::interval(1, 10));
        map.insert(sv("b", 0), ValueRange::top());
        let ext = RangeAnalysisExt::new(&map);
        let bounded = ext.bounded_vars();
        assert_eq!(bounded.len(), 1);
    }

    // ── Additional ValueRange edge-case tests ────────────────────────────────

    #[test]
    fn vr_top_and_bottom_properties() {
        let t = ValueRange::top();
        let b = ValueRange::bottom();
        assert!(!t.is_constant());
        assert!(!t.is_bounded());
        assert!(b.is_bottom());
        assert!(!t.is_bottom());
        assert!(t.cardinality().is_none());
    }

    #[test]
    fn vr_interval_swaps_inverted_bounds() {
        let r = ValueRange::interval(10, 5);
        assert_eq!(r.min, Some(5));
        assert_eq!(r.max, Some(10));
    }

    #[test]
    fn vr_constant_value_and_predicates() {
        let c = ValueRange::constant(-3);
        assert!(c.is_constant());
        assert_eq!(c.constant_value(), Some(-3));
        assert!(!c.is_non_negative());
        let z = ValueRange::constant(0);
        assert!(z.is_non_negative());
    }

    #[test]
    fn vr_cardinality_strided_and_extreme() {
        // Strided cardinality: [0, 10] step 2 → 6 values.
        let r = ValueRange::strided(0, 10, 2);
        assert_eq!(r.cardinality(), Some(6));
        // Singleton has cardinality 1.
        assert_eq!(ValueRange::constant(42).cardinality(), Some(1));
        // Unbounded → None.
        assert!(ValueRange::top().cardinality().is_none());
        // Extreme but bounded: i64::MIN .. i64::MAX would overflow span; impl
        // returns None when span overflows i64.
        let huge = ValueRange::interval(i64::MIN, i64::MAX);
        // Either Some(very large) or None — both acceptable, just shouldn't panic.
        let _ = huge.cardinality();
    }

    #[test]
    fn vr_add_constant_saturates() {
        let r = ValueRange::interval(i64::MAX - 1, i64::MAX);
        let r2 = r.add_constant(100);
        assert_eq!(r2.max, Some(i64::MAX));
        assert_eq!(r2.min, Some(i64::MAX));
    }

    #[test]
    fn vr_mul_constant_zero_and_negative() {
        let r = ValueRange::interval(2, 5);
        assert_eq!(r.mul_constant(0), ValueRange::constant(0));
        let neg = r.mul_constant(-2);
        // Negative multiplier swaps min/max.
        assert_eq!(neg.min, Some(-10));
        assert_eq!(neg.max, Some(-4));
    }

    #[test]
    fn vr_restrict_produces_bottom_on_contradiction() {
        let r = ValueRange::interval(0, 10);
        let empty = r.restrict_lower(20);
        assert!(empty.is_bottom());
        let r2 = ValueRange::interval(0, 10);
        let empty2 = r2.restrict_upper(-1);
        assert!(empty2.is_bottom());
    }

    #[test]
    fn vr_join_meet_with_top_and_bottom() {
        let r = ValueRange::interval(1, 5);
        let joined = r.join(&ValueRange::top());
        // Join with top is unbounded on either side.
        assert!(joined.min.is_none() || joined.max.is_none());
        let met = r.meet(&ValueRange::top());
        // Meet with top should be ≈ r (bounds preserved).
        assert_eq!(met.min, Some(1));
        assert_eq!(met.max, Some(5));
    }

    #[test]
    fn vr_display_format() {
        let r = ValueRange::interval(0, 10);
        assert_eq!(format!("{r}"), "[0, 10]");
        let s = ValueRange::strided(0, 10, 2);
        assert!(format!("{s}").contains("stride 2"));
        let t = ValueRange::top();
        let out = format!("{t}");
        assert!(out.contains("-∞") && out.contains("+∞"));
    }

    #[test]
    fn analyze_value_ranges_survives_out_of_range_cfg_entry() {
        // `SsaFunction { cfg, blocks }` fields are both public, so a caller
        // can hand us a CFG whose `entry` doesn't correspond to any real
        // block. This must not panic.
        use crate::cfg_dom::Cfg;
        use crate::ssa::{Instruction, Var};
        let cfg = Cfg::new(2, vec![vec![], vec![]], BBId(99), BBId(1));
        let instrs = vec![
            vec![Instruction::new(0, Some(Var::new("x")), vec![])],
            vec![Instruction::new(1, Some(Var::new("y")), vec![])],
        ];
        let func = SsaFunction::new(cfg, &instrs);
        let ranges = analyze_value_ranges(&func);
        // Nothing reachable from the bogus entry, so no ranges computed —
        // the important thing is that we got here without panicking.
        assert!(ranges.is_empty());
    }

    #[test]
    fn analyze_value_ranges_survives_out_of_range_successor() {
        // A successor id that points past the end of `blocks`/`cfg` must be
        // ignored, not indexed into directly.
        use crate::cfg_dom::Cfg;
        use crate::ssa::{Instruction, Var};
        let mut cfg = Cfg::new(1, vec![vec![]], BBId(0), BBId(0));
        cfg.succ[0].push(BBId(77));
        let func = SsaFunction::new(cfg, &[vec![Instruction::new(0, Some(Var::new("x")), vec![])]]);
        let ranges = analyze_value_ranges(&func);
        assert!(ranges.contains_key(&sv("x", 0)) || ranges.is_empty());
    }
}
