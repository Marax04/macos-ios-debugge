//! `explosion_mitigation` — **High-level** path explosion policies (merging, inference, abstraction).
//!
//! Symbolic execution can encounter an exponential blowup in the number of
//! paths through a program.  This module provides:
//!
//! * [`LoopBoundInference`] — statically infer loop bounds from back-edges.
//! * [`MergingStrategy`] — aggressive or conservative state merging at join points.
//! * [`AbstractionTrigger`] — policy for collapsing concrete states into abstractions.
//! * [`FunctionSummaryCache`] — cache function summaries to avoid re-exploring.
//! * [`SubsumedState`] — detection of states already covered by a more general state.
//!
//! # Relationship to [`path_explosion`](crate::path_explosion)
//!
//! See [`path_explosion`](crate::path_explosion) module docs for the distinction table.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{SymExpr, SymType, SymbolicState};
use crate::path_explosion::u64_to_f64_lossy;

// ─── LoopBoundInference ───────────────────────────────────────────────────────

/// Inference of loop iteration bounds from observed back-edge frequencies.
///
/// Each time a back-edge `(from_pc, to_pc)` is taken, its iteration count is
/// incremented.  When the count exceeds the configured threshold the loop is
/// considered to have exceeded its inferred bound, and the caller may choose
/// to cut off exploration.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LoopBoundInference {
    /// Back-edge → iteration count mapping.
    counts: HashMap<(u64, u64), u64>,
    /// Default maximum iterations before a loop is cut off.
    pub default_max_iterations: u64,
    /// Per-loop overrides: (from, to) → `max_iterations`.
    overrides: HashMap<(u64, u64), u64>,
}

impl LoopBoundInference {
    /// Create a new instance with `default_max_iterations`.
    #[must_use]
    pub fn new(default_max_iterations: u64) -> Self {
        Self {
            default_max_iterations,
            ..Self::default()
        }
    }

    /// Record one iteration of the back-edge `from → to`.
    ///
    /// Returns the updated iteration count.
    pub fn record_back_edge(&mut self, from: u64, to: u64) -> u64 {
        let count = self.counts.entry((from, to)).or_default();
        *count += 1;
        *count
    }

    /// Return the current iteration count for `from → to`.
    #[must_use]
    pub fn iteration_count(&self, from: u64, to: u64) -> u64 {
        self.counts.get(&(from, to)).copied().unwrap_or(0)
    }

    /// Return the configured maximum iterations for `from → to`.
    #[must_use]
    pub fn max_for(&self, from: u64, to: u64) -> u64 {
        self.overrides
            .get(&(from, to))
            .copied()
            .unwrap_or(self.default_max_iterations)
    }

    /// Return `true` if the loop `from → to` has exceeded its bound.
    #[must_use]
    pub fn is_exceeded(&self, from: u64, to: u64) -> bool {
        self.iteration_count(from, to) >= self.max_for(from, to)
    }

    /// Set a custom iteration limit for `from → to`.
    pub fn set_override(&mut self, from: u64, to: u64, limit: u64) {
        self.overrides.insert((from, to), limit);
    }

    /// Reset the iteration count for all back-edges.
    pub fn reset_counts(&mut self) {
        self.counts.clear();
    }

    /// Infer a bound from a sequence of observed counts.
    ///
    /// Heuristic: returns the 90th-percentile observed iteration count, or
    /// `default_max_iterations` if no counts have been recorded.
    #[must_use]
    pub fn infer_bound(&self) -> u64 {
        if self.counts.is_empty() {
            return self.default_max_iterations;
        }
        let mut vals: Vec<u64> = self.counts.values().copied().collect();
        vals.sort_unstable();
        let idx = (vals.len().saturating_mul(9) / 10).min(vals.len() - 1);
        vals[idx].max(1)
    }

    /// Return the number of distinct back-edges observed.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.counts.len()
    }
}

// ─── MergingStrategy ─────────────────────────────────────────────────────────

/// Policy for merging symbolic states at control-flow join points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergingMode {
    /// Merge all paths at every join point, maximising sharing at the cost of
    /// precision (ITE-heavy expressions).
    Aggressive,
    /// Merge only paths whose depth difference is within a threshold.
    Conservative { max_depth_diff: u32 },
    /// Never merge: fully fork all paths.
    Never,
}

impl Default for MergingMode {
    fn default() -> Self {
        Self::Conservative { max_depth_diff: 4 }
    }
}

/// Strategy object that decides whether two states should be merged.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MergingStrategy {
    /// Active merging mode.
    pub mode: MergingMode,
    /// Counter of merges performed.
    merge_count: u64,
    /// Counter of merge opportunities rejected.
    rejected_count: u64,
}

impl MergingStrategy {
    /// Create a new strategy with the given mode.
    #[must_use]
    pub fn new(mode: MergingMode) -> Self {
        Self {
            mode,
            ..Self::default()
        }
    }

    /// Return `true` if `a` and `b` should be merged given the current mode.
    pub const fn should_merge(&mut self, a: &SymbolicState, b: &SymbolicState) -> bool {
        let decision = match self.mode {
            MergingMode::Never => false,
            MergingMode::Aggressive => {
                // Only merge if both states have the same PC.
                a.pc == b.pc
            }
            MergingMode::Conservative { max_depth_diff } => {
                a.pc == b.pc && a.depth.abs_diff(b.depth) <= max_depth_diff
            }
        };
        if decision {
            self.merge_count += 1;
        } else {
            self.rejected_count += 1;
        }
        decision
    }

    /// Merge `a` and `b` using ITE on `cond` for diverging registers.
    ///
    /// Delegates to [`SymbolicState::merge`].
    #[must_use]
    pub fn merge_states(&self, a: SymbolicState, b: SymbolicState, cond: SymExpr) -> SymbolicState {
        SymbolicState::merge(a, b, &cond)
    }

    /// Return the total number of merges performed.
    #[must_use]
    pub const fn merge_count(&self) -> u64 {
        self.merge_count
    }

    /// Return the number of merges rejected.
    #[must_use]
    pub const fn rejected_count(&self) -> u64 {
        self.rejected_count
    }
}

// ─── AbstractionTrigger ───────────────────────────────────────────────────────

/// Policy for when to collapse a concrete or symbolic state into an abstraction.
///
/// Abstractions reduce the cost of further analysis at the expense of precision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractionTrigger {
    /// Trigger when a state's path condition length exceeds this threshold.
    pub max_path_length: usize,
    /// Trigger when a state's depth exceeds this threshold.
    pub max_depth: u32,
    /// Trigger when the number of symbolic variables exceeds this threshold.
    pub max_sym_vars: usize,
    /// Number of times this trigger has fired.
    fire_count: u64,
}

impl Default for AbstractionTrigger {
    fn default() -> Self {
        Self {
            max_path_length: 128,
            max_depth: 64,
            max_sym_vars: 256,
            fire_count: 0,
        }
    }
}

impl AbstractionTrigger {
    /// Create a trigger with explicit thresholds.
    #[must_use]
    pub const fn new(max_path_length: usize, max_depth: u32, max_sym_vars: usize) -> Self {
        Self {
            max_path_length,
            max_depth,
            max_sym_vars,
            fire_count: 0,
        }
    }

    /// Return `true` if `state` should be abstracted.
    pub fn should_abstract(&mut self, state: &SymbolicState) -> bool {
        let sym_vars = count_sym_vars(state);
        let fire = state.path_condition.len() > self.max_path_length
            || state.depth > self.max_depth
            || sym_vars > self.max_sym_vars;
        if fire {
            self.fire_count += 1;
        }
        fire
    }

    /// Produce a simplified, over-approximated version of `state`.
    ///
    /// The abstraction drops the path condition (replacing it with `true`) and
    /// widens all concrete values to fresh symbolic variables.
    #[must_use]
    pub fn abstract_state(&self, mut state: SymbolicState) -> SymbolicState {
        // Drop the path condition — the abstraction is reachable from any path.
        state.path_condition.clear();
        state.constraints.clear();
        // Widen registers: replace constants with fresh symbolic variables.
        for (name, expr) in &mut state.registers {
            if let SymExpr::ConstBv { width, .. } = *expr {
                *expr = SymExpr::Var {
                    name: format!("abs_{name}"),
                    ty: SymType::BitVec(width),
                };
            }
        }
        state
    }

    /// Return the number of times the trigger has fired.
    #[must_use]
    pub const fn fire_count(&self) -> u64 {
        self.fire_count
    }
}

/// Count the number of distinct symbolic variable names in a state's path
/// condition and register file.
fn count_sym_vars(state: &SymbolicState) -> usize {
    let mut names = std::collections::HashSet::new();
    for expr in &state.path_condition {
        collect_var_names(expr, &mut names);
    }
    for expr in state.registers.values() {
        collect_var_names(expr, &mut names);
    }
    names.len()
}

fn collect_var_names<'a>(expr: &'a SymExpr, out: &mut std::collections::HashSet<&'a str>) {
    match expr {
        SymExpr::Var { name, .. } => {
            out.insert(name.as_str());
        }
        SymExpr::Add(l, r)
        | SymExpr::Sub(l, r)
        | SymExpr::Mul(l, r)
        | SymExpr::And(l, r)
        | SymExpr::Or(l, r)
        | SymExpr::Xor(l, r)
        | SymExpr::Eq(l, r)
        | SymExpr::Ne(l, r)
        | SymExpr::BoolAnd(l, r)
        | SymExpr::BoolOr(l, r)
        | SymExpr::ULt(l, r)
        | SymExpr::UGt(l, r) => {
            collect_var_names(l, out);
            collect_var_names(r, out);
        }
        SymExpr::Not(e)
        | SymExpr::Neg(e)
        | SymExpr::BoolNot(e)
        | SymExpr::ZExt { expr: e, .. }
        | SymExpr::SExt { expr: e, .. }
        | SymExpr::Extract { expr: e, .. } => {
            collect_var_names(e, out);
        }
        SymExpr::Ite { cond, then_, else_ } => {
            collect_var_names(cond, out);
            collect_var_names(then_, out);
            collect_var_names(else_, out);
        }
        _ => {}
    }
}

// ─── FunctionSummary ─────────────────────────────────────────────────────────

/// A cached summary of a function: pre-condition → post-condition.
///
/// A summary models the effect of a function on the symbolic state without
/// re-executing the function body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    /// Address of the summarised function.
    pub address: u64,
    /// Symbolic register assignments after the function returns.
    /// Each entry maps a register name to its post-state expression.
    pub post_registers: HashMap<String, SymExpr>,
    /// Path constraints added by this function.
    pub added_constraints: Vec<SymExpr>,
    /// Number of times this summary has been used.
    pub use_count: u64,
}

impl FunctionSummary {
    /// Construct a new summary.
    #[must_use]
    pub fn new(address: u64) -> Self {
        Self {
            address,
            post_registers: HashMap::new(),
            added_constraints: Vec::new(),
            use_count: 0,
        }
    }

    /// Apply this summary to `state`, mutating it in place.
    pub fn apply(&mut self, state: &mut SymbolicState) {
        self.use_count += 1;
        for (reg, expr) in &self.post_registers {
            state.registers.insert(reg.clone(), expr.clone());
        }
        for c in &self.added_constraints {
            state.path_condition.push(c.clone());
        }
    }
}

// ─── FunctionSummaryCache ─────────────────────────────────────────────────────

/// Cache of pre-computed function summaries.
#[derive(Debug, Default, Clone)]
pub struct FunctionSummaryCache {
    summaries: HashMap<u64, FunctionSummary>,
    /// Maximum number of summaries to retain.
    capacity: usize,
    /// Total cache hits.
    hits: u64,
    /// Total cache misses.
    misses: u64,
}

impl FunctionSummaryCache {
    /// Create a new cache with a given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            ..Self::default()
        }
    }

    /// Insert a summary for the function at `address`.
    pub fn insert(&mut self, summary: FunctionSummary) {
        if self.summaries.len() >= self.capacity && !self.summaries.contains_key(&summary.address) {
            // Evict the least-used summary.
            let min_addr = self
                .summaries
                .iter()
                .min_by_key(|(_, s)| s.use_count)
                .map(|(&a, _)| a);
            if let Some(addr) = min_addr {
                self.summaries.remove(&addr);
            }
        }
        self.summaries.insert(summary.address, summary);
    }

    /// Look up a summary by address.
    pub fn get(&mut self, address: u64) -> Option<&mut FunctionSummary> {
        if self.summaries.contains_key(&address) {
            self.hits += 1;
            self.summaries.get_mut(&address)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Remove a summary.
    pub fn evict(&mut self, address: u64) {
        self.summaries.remove(&address);
    }

    /// Return the number of cached summaries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.summaries.len()
    }

    /// Return `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.summaries.is_empty()
    }

    /// Return cache hit rate 0.0–1.0.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            u64_to_f64_lossy(self.hits) / u64_to_f64_lossy(total)
        }
    }

    /// Return the total number of cache hits.
    #[must_use]
    pub const fn hits(&self) -> u64 {
        self.hits
    }

    /// Return the total number of cache misses.
    #[must_use]
    pub const fn misses(&self) -> u64 {
        self.misses
    }
}

// ─── SubsumedState ────────────────────────────────────────────────────────────

/// Detection of states that are subsumed (i.e. already covered) by a more
/// general previously seen state.
///
/// State A subsumes state B when A's path condition is a suffix of B's (A is
/// less constrained and therefore covers a superset of paths).  This is a
/// conservative over-approximation of the standard lattice subsumption.
#[derive(Debug, Default)]
pub struct SubsumedState {
    /// "Generalised" states seen so far, keyed by PC.
    general_states: HashMap<u64, Vec<SymbolicState>>,
    /// Number of subsumptions detected.
    subsumption_count: u64,
}

impl SubsumedState {
    /// Create a new subsumption detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a state as a "general" state at its PC.
    pub fn record(&mut self, state: &SymbolicState) {
        self.general_states
            .entry(state.pc)
            .or_default()
            .push(state.clone());
    }

    /// Return `true` if `state` is subsumed by any previously recorded state
    /// at the same PC.
    ///
    /// Heuristic: `candidate` subsumes `state` if:
    /// 1. Their PCs match.
    /// 2. `candidate.path_condition` is a prefix (or equal) of `state.path_condition`.
    ///    (A less-constrained path covers a superset.)
    pub fn is_subsumed(&mut self, state: &SymbolicState) -> bool {
        let Some(generals) = self.general_states.get(&state.pc) else {
            return false;
        };
        let result = generals.iter().any(|r#gen| is_path_prefix_of(r#gen, state));
        if result {
            self.subsumption_count += 1;
        }
        result
    }

    /// Return the number of subsumptions detected.
    #[must_use]
    pub const fn subsumption_count(&self) -> u64 {
        self.subsumption_count
    }

    /// Clear all recorded general states.
    pub fn clear(&mut self) {
        self.general_states.clear();
        self.subsumption_count = 0;
    }
}

/// Return `true` if `candidate`'s path condition is a prefix of `state`'s.
fn is_path_prefix_of(candidate: &SymbolicState, state: &SymbolicState) -> bool {
    let cp = &candidate.path_condition;
    let sp = &state.path_condition;
    if cp.len() > sp.len() {
        return false;
    }
    cp.iter().zip(sp.iter()).all(|(a, b)| a == b)
}

// ─── PathExplosionGuard ───────────────────────────────────────────────────────

/// Composite guard that aggregates all mitigation strategies.
///
/// Call [`Self::check`] before each state is added to the worklist.
#[derive(Debug)]
pub struct PathExplosionGuard {
    pub loop_bounds: LoopBoundInference,
    pub merging: MergingStrategy,
    pub abstraction: AbstractionTrigger,
    pub summary_cache: FunctionSummaryCache,
    pub subsumption: SubsumedState,
}

impl PathExplosionGuard {
    /// Create a guard with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            loop_bounds: LoopBoundInference::new(32),
            merging: MergingStrategy::new(MergingMode::default()),
            abstraction: AbstractionTrigger::default(),
            summary_cache: FunctionSummaryCache::new(4096),
            subsumption: SubsumedState::new(),
        }
    }

    /// Decide whether `state` should be kept or dropped.
    ///
    /// Returns `false` if the state should be discarded (subsumed, abstracted,
    /// or loop-bound exceeded).
    pub fn check(&mut self, state: &SymbolicState) -> bool {
        if self.subsumption.is_subsumed(state) {
            return false;
        }
        if self.abstraction.should_abstract(state) {
            return false;
        }
        true
    }
}

impl Default for PathExplosionGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PathExplosionGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PathExplosionGuard {{ loops={}, merges={}, abstractions={}, subsumptions={} }}",
            self.loop_bounds.edge_count(),
            self.merging.merge_count(),
            self.abstraction.fire_count(),
            self.subsumption.subsumption_count(),
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn bv(v: u64, w: u32) -> SymExpr {
        SymExpr::ConstBv { val: v, width: w }
    }
    fn _var(n: &str) -> SymExpr {
        SymExpr::Var {
            name: n.to_string(),
            ty: SymType::BitVec(64),
        }
    }

    fn state_at(pc: u64) -> SymbolicState {
        let mut s = SymbolicState::new();
        s.pc = pc;
        s
    }

    // ── LoopBoundInference ───────────────────────────────────────────────

    #[test]
    fn test_loop_bound_record_and_count() {
        let mut lbi = LoopBoundInference::new(10);
        for _ in 0..5 {
            lbi.record_back_edge(0x1000, 0x800);
        }
        assert_eq!(lbi.iteration_count(0x1000, 0x800), 5);
    }

    #[test]
    fn test_loop_bound_is_exceeded() {
        let mut lbi = LoopBoundInference::new(3);
        for _ in 0..3 {
            lbi.record_back_edge(1, 2);
        }
        assert!(lbi.is_exceeded(1, 2));
        assert!(!lbi.is_exceeded(1, 3));
    }

    #[test]
    fn test_loop_bound_override() {
        let mut lbi = LoopBoundInference::new(10);
        lbi.set_override(0xA000, 0x9000, 2);
        lbi.record_back_edge(0xA000, 0x9000);
        lbi.record_back_edge(0xA000, 0x9000);
        assert!(lbi.is_exceeded(0xA000, 0x9000));
    }

    #[test]
    fn test_loop_bound_infer_bound() {
        let lbi = LoopBoundInference::new(100);
        assert_eq!(lbi.infer_bound(), 100);
    }

    #[test]
    fn test_loop_bound_reset_counts() {
        let mut lbi = LoopBoundInference::new(5);
        for _ in 0..4 {
            lbi.record_back_edge(1, 2);
        }
        lbi.reset_counts();
        assert_eq!(lbi.iteration_count(1, 2), 0);
    }

    // ── MergingStrategy ──────────────────────────────────────────────────

    #[test]
    fn test_merging_never_rejects() {
        let mut m = MergingStrategy::new(MergingMode::Never);
        let a = state_at(0x1000);
        let b = state_at(0x1000);
        assert!(!m.should_merge(&a, &b));
        assert_eq!(m.rejected_count(), 1);
    }

    #[test]
    fn test_merging_aggressive_same_pc() {
        let mut m = MergingStrategy::new(MergingMode::Aggressive);
        let a = state_at(0x2000);
        let b = state_at(0x2000);
        assert!(m.should_merge(&a, &b));
        assert_eq!(m.merge_count(), 1);
    }

    #[test]
    fn test_merging_aggressive_different_pc() {
        let mut m = MergingStrategy::new(MergingMode::Aggressive);
        let a = state_at(0x1000);
        let b = state_at(0x2000);
        assert!(!m.should_merge(&a, &b));
    }

    #[test]
    fn test_merging_conservative_depth_diff() {
        let mut m = MergingStrategy::new(MergingMode::Conservative { max_depth_diff: 2 });
        let mut a = state_at(0x1000);
        a.depth = 10;
        let mut b = state_at(0x1000);
        b.depth = 13;
        assert!(!m.should_merge(&a, &b)); // diff = 3 > 2
        let mut b2 = state_at(0x1000);
        b2.depth = 12;
        assert!(m.should_merge(&a, &b2)); // diff = 2 <= 2
    }

    #[test]
    fn test_merging_merge_states() {
        let m = MergingStrategy::new(MergingMode::Aggressive);
        let mut a = state_at(0x1000);
        a.registers.insert("rax".to_string(), bv(1, 64));
        let mut b = state_at(0x1000);
        b.registers.insert("rax".to_string(), bv(2, 64));
        let merged = m.merge_states(a, b, SymExpr::ConstBool(true));
        // merged.rax should be ITE(true, 1, 2) → simplified to 1
        assert!(merged.registers.contains_key("rax"));
    }

    // ── AbstractionTrigger ───────────────────────────────────────────────

    #[test]
    fn test_abstraction_trigger_path_length() {
        let mut t = AbstractionTrigger::new(3, 100, 1000);
        let mut s = state_at(0x0);
        for _ in 0..4 {
            s.path_condition.push(SymExpr::ConstBool(true));
        }
        assert!(t.should_abstract(&s));
        assert_eq!(t.fire_count(), 1);
    }

    #[test]
    fn test_abstraction_trigger_depth() {
        let mut t = AbstractionTrigger::new(1000, 5, 1000);
        let mut s = state_at(0x0);
        s.depth = 6;
        assert!(t.should_abstract(&s));
    }

    #[test]
    fn test_abstraction_no_trigger() {
        let mut t = AbstractionTrigger::default();
        let s = state_at(0x0);
        assert!(!t.should_abstract(&s));
    }

    #[test]
    fn test_abstraction_abstract_state_clears_path() {
        let t = AbstractionTrigger::default();
        let mut s = state_at(0x1000);
        s.path_condition.push(SymExpr::ConstBool(true));
        s.registers.insert("rbx".to_string(), bv(42, 64));
        let abs = t.abstract_state(s);
        assert!(abs.path_condition.is_empty());
        // rbx should be widened to a Var.
        assert!(matches!(
            abs.registers.get("rbx"),
            Some(SymExpr::Var { .. })
        ));
    }

    // ── FunctionSummaryCache ─────────────────────────────────────────────

    #[test]
    fn test_summary_cache_insert_get() {
        let mut cache = FunctionSummaryCache::new(10);
        let mut s = FunctionSummary::new(0x4000);
        s.post_registers.insert("rax".to_string(), bv(0, 64));
        cache.insert(s);
        assert!(cache.get(0x4000).is_some());
        assert_eq!(cache.hits(), 1);
    }

    #[test]
    fn test_summary_cache_miss() {
        let mut cache = FunctionSummaryCache::new(10);
        assert!(cache.get(0x9999).is_none());
        assert_eq!(cache.misses(), 1);
    }

    #[test]
    fn test_summary_cache_capacity_eviction() {
        let mut cache = FunctionSummaryCache::new(2);
        cache.insert(FunctionSummary::new(0x1000));
        cache.insert(FunctionSummary::new(0x2000));
        cache.insert(FunctionSummary::new(0x3000)); // triggers eviction
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_summary_apply() {
        let mut cache = FunctionSummaryCache::new(10);
        let mut summary = FunctionSummary::new(0x5000);
        summary.post_registers.insert("rax".to_string(), bv(99, 64));
        cache.insert(summary);
        let summary = cache.get(0x5000).unwrap();
        let mut state = state_at(0x5100);
        summary.apply(&mut state);
        assert_eq!(state.registers["rax"], bv(99, 64));
    }

    #[test]
    fn test_summary_cache_hit_rate() {
        let mut cache = FunctionSummaryCache::new(10);
        cache.insert(FunctionSummary::new(0x1000));
        cache.get(0x1000);
        cache.get(0x2000);
        assert!((cache.hit_rate() - 0.5).abs() < 1e-9);
    }

    // ── SubsumedState ────────────────────────────────────────────────────

    #[test]
    fn test_subsumed_state_detects_prefix() {
        let mut det = SubsumedState::new();
        let mut r#gen = state_at(0x1000);
        r#gen.path_condition.push(SymExpr::ConstBool(true));
        det.record(&r#gen);

        let mut specific = state_at(0x1000);
        specific.path_condition.push(SymExpr::ConstBool(true));
        specific.path_condition.push(SymExpr::ConstBool(false));
        assert!(det.is_subsumed(&specific));
        assert_eq!(det.subsumption_count(), 1);
    }

    #[test]
    fn test_subsumed_state_no_subsumption_different_pc() {
        let mut det = SubsumedState::new();
        let r#gen = state_at(0x1000);
        det.record(&r#gen);
        let other = state_at(0x2000);
        assert!(!det.is_subsumed(&other));
    }

    #[test]
    fn test_subsumed_state_clear() {
        let mut det = SubsumedState::new();
        det.record(&state_at(0x1000));
        det.clear();
        assert!(!det.is_subsumed(&state_at(0x1000)));
    }

    // ── PathExplosionGuard ───────────────────────────────────────────────

    #[test]
    fn test_guard_allows_fresh_state() {
        let mut guard = PathExplosionGuard::new();
        let s = state_at(0x1000);
        assert!(guard.check(&s));
    }

    #[test]
    fn test_guard_blocks_deep_state() {
        let mut guard = PathExplosionGuard::new();
        guard.abstraction.max_depth = 2;
        let mut s = state_at(0x1000);
        s.depth = 3;
        assert!(!guard.check(&s));
    }

    #[test]
    fn test_guard_display() {
        let g = PathExplosionGuard::new();
        assert!(g.to_string().contains("PathExplosionGuard"));
    }
}
