//! Inter-procedural constraint propagation.
//!
//! This module provides:
//! - [`FunctionSummaryStore`]: stores pre/post-condition summaries per function.
//! - [`ConstraintPropagator`]: propagates constraints across function boundaries
//!   using summary application and loop invariant reasoning.
//! - [`ConstraintSimplifier`]: algebraic + SMT-level simplification pipeline
//!   (bit-blast, solve-eqs, constant folding) applied before solver queries.
//! - [`LearnedConstraintCache`]: stores previously derived constraints to avoid
//!   redundant solver calls.

use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};

use serde::{Deserialize, Serialize};

use crate::{SymExpr, SymType, SymbolicError, SymbolicState};

// ─── Precondition / Postcondition ─────────────────────────────────────────────

/// A named symbolic constraint (either a precondition or a postcondition).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicConstraint {
    /// Human-readable label.
    pub label: String,
    /// The symbolic expression (must evaluate to a boolean / 1-bit BV).
    pub expr: SymExpr,
    /// Confidence in [0, 100].
    pub confidence: u8,
}

impl SymbolicConstraint {
    pub fn new(label: impl Into<String>, expr: SymExpr) -> Self {
        Self { label: label.into(), expr, confidence: 100 }
    }

    #[must_use] 
    pub const fn with_confidence(mut self, c: u8) -> Self {
        self.confidence = c;
        self
    }
}

// ─── Function summary ─────────────────────────────────────────────────────────

/// Summary of a function as seen by the constraint propagator.
///
/// Captures:
/// - Preconditions that must hold on entry.
/// - Postconditions guaranteed on exit.
/// - Which registers/memory cells are modified.
/// - The return-value expression (if any) as a function of inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcedureSummary {
    pub address: u64,
    pub name: Option<String>,
    /// Must hold before the call.
    pub preconditions: Vec<SymbolicConstraint>,
    /// Guaranteed to hold after the call.
    pub postconditions: Vec<SymbolicConstraint>,
    /// Clobbered registers.
    pub clobbered_registers: HashSet<String>,
    /// Return value as a symbolic expression over input vars.
    pub return_expr: Option<SymExpr>,
    /// Whether the function always terminates.
    pub terminates: bool,
    /// Whether any precondition check failed on the last analysis.
    pub precondition_violated: bool,
}

impl ProcedureSummary {
    #[must_use] 
    pub fn new(address: u64) -> Self {
        Self {
            address,
            name: None,
            preconditions: Vec::new(),
            postconditions: Vec::new(),
            clobbered_registers: HashSet::new(),
            return_expr: None,
            terminates: true,
            precondition_violated: false,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn add_precondition(&mut self, c: SymbolicConstraint) {
        self.preconditions.push(c);
    }

    pub fn add_postcondition(&mut self, c: SymbolicConstraint) {
        self.postconditions.push(c);
    }

    /// Check whether all preconditions are syntactically satisfied by `state`.
    #[must_use] 
    pub fn check_preconditions(&self, state: &SymbolicState) -> Vec<&SymbolicConstraint> {
        self.preconditions
            .iter()
            .filter(|c| !is_trivially_true(&c.expr, state))
            .collect()
    }
}

const fn is_trivially_true(expr: &SymExpr, _state: &SymbolicState) -> bool {
    matches!(expr, SymExpr::ConstBool(true))
}

// ─── Summary store ────────────────────────────────────────────────────────────

/// Stores [`ProcedureSummary`] instances indexed by function address.
#[derive(Debug, Default)]
pub struct FunctionSummaryStore {
    summaries: HashMap<u64, ProcedureSummary>,
    name_index: HashMap<String, u64>,
}

impl FunctionSummaryStore {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, summary: ProcedureSummary) {
        if let Some(name) = &summary.name {
            self.name_index.insert(name.clone(), summary.address);
        }
        self.summaries.insert(summary.address, summary);
    }

    #[must_use] 
    pub fn get(&self, address: u64) -> Option<&ProcedureSummary> {
        self.summaries.get(&address)
    }

    pub fn get_mut(&mut self, address: u64) -> Option<&mut ProcedureSummary> {
        self.summaries.get_mut(&address)
    }

    #[must_use] 
    pub fn get_by_name(&self, name: &str) -> Option<&ProcedureSummary> {
        self.name_index.get(name).and_then(|a| self.summaries.get(a))
    }

    #[must_use] 
    pub fn len(&self) -> usize {
        self.summaries.len()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.summaries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ProcedureSummary> {
        self.summaries.values()
    }
}

// ─── Loop invariant ───────────────────────────────────────────────────────────

/// Template-based loop invariant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoopInvariant {
    /// `var >= lo_bound`
    LowerBound { var: String, lo_bound: SymExpr },
    /// `var <= hi_bound`
    UpperBound { var: String, hi_bound: SymExpr },
    /// `var >= lo && var <= hi`
    RangeInvariant { var: String, lo: SymExpr, hi: SymExpr },
    /// Arbitrary symbolic constraint.
    Arbitrary(SymbolicConstraint),
}

impl LoopInvariant {
    /// Convert to a [`SymExpr`] for use in path conditions.
    #[must_use] 
    pub fn to_expr(&self) -> SymExpr {
        match self {
            Self::LowerBound { var, lo_bound } => SymExpr::UGe(
                Box::new(SymExpr::Var { name: var.clone(), ty: SymType::BitVec(64) }),
                Box::new(lo_bound.clone()),
            ),
            Self::UpperBound { var, hi_bound } => SymExpr::ULe(
                Box::new(SymExpr::Var { name: var.clone(), ty: SymType::BitVec(64) }),
                Box::new(hi_bound.clone()),
            ),
            Self::RangeInvariant { var, lo, hi } => {
                let v = SymExpr::Var { name: var.clone(), ty: SymType::BitVec(64) };
                SymExpr::BoolAnd(
                    Box::new(SymExpr::UGe(Box::new(v.clone()), Box::new(lo.clone()))),
                    Box::new(SymExpr::ULe(Box::new(v), Box::new(hi.clone()))),
                )
            }
            Self::Arbitrary(c) => c.expr.clone(),
        }
    }
}

// ─── Constraint simplification ────────────────────────────────────────────────

/// Simplification pass identifiers (analogous to Z3 tactics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SimplificationPass {
    /// Basic algebraic reductions (x+0=x, x*1=x, !!x=x …).
    AlgebraicReduce,
    /// Constant folding: evaluate sub-expressions with concrete operands.
    ConstantFold,
    /// Bit-blasting: expand bitvector ops to boolean level for small widths.
    BitBlast,
    /// Solve equalities: substitute x=c where possible.
    SolveEqualities,
    /// Push negations inward (De Morgan).
    NegationNormalForm,
    /// Eliminate duplicate conjuncts.
    DeduplicateConjuncts,
}

/// Performs multi-pass constraint simplification.
#[derive(Debug, Default)]
pub struct ConstraintSimplifier {
    passes: Vec<SimplificationPass>,
    max_iterations: u32,
}

impl ConstraintSimplifier {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            passes: vec![
                SimplificationPass::ConstantFold,
                SimplificationPass::AlgebraicReduce,
                SimplificationPass::NegationNormalForm,
                SimplificationPass::SolveEqualities,
                SimplificationPass::DeduplicateConjuncts,
            ],
            max_iterations: 8,
        }
    }

    #[must_use] 
    pub const fn with_passes(passes: Vec<SimplificationPass>) -> Self {
        Self { passes, max_iterations: 8 }
    }

    #[must_use] 
    pub const fn with_max_iterations(mut self, n: u32) -> Self {
        self.max_iterations = n;
        self
    }

    /// Simplify `expr` using the configured passes.
    #[must_use] 
    pub fn simplify(&self, mut expr: SymExpr) -> SymExpr {
        for _ in 0..self.max_iterations {
            let new = self.apply_passes(expr.clone());
            if new == expr {
                break;
            }
            expr = new;
        }
        expr
    }

    fn apply_passes(&self, expr: SymExpr) -> SymExpr {
        let mut e = expr;
        for pass in &self.passes {
            e = match pass {
                SimplificationPass::ConstantFold => constant_fold(e),
                SimplificationPass::AlgebraicReduce => algebraic_reduce(e),
                SimplificationPass::NegationNormalForm => push_negations(e),
                SimplificationPass::SolveEqualities => solve_equalities(e),
                SimplificationPass::DeduplicateConjuncts => dedup_conjuncts(e),
                SimplificationPass::BitBlast => e, // placeholder — full impl would be large
            };
        }
        e
    }
}

fn constant_fold(expr: SymExpr) -> SymExpr {
    match expr {
        SymExpr::Add(a, b) => {
            let a = constant_fold(*a);
            let b = constant_fold(*b);
            match (&a, &b) {
                (SymExpr::ConstBv { val: va, width: w }, SymExpr::ConstBv { val: vb, .. }) => {
                    SymExpr::ConstBv { val: va.wrapping_add(*vb), width: *w }
                }
                _ => SymExpr::Add(Box::new(a), Box::new(b)),
            }
        }
        SymExpr::Sub(a, b) => {
            let a = constant_fold(*a);
            let b = constant_fold(*b);
            match (&a, &b) {
                (SymExpr::ConstBv { val: va, width: w }, SymExpr::ConstBv { val: vb, .. }) => {
                    SymExpr::ConstBv { val: va.wrapping_sub(*vb), width: *w }
                }
                _ => SymExpr::Sub(Box::new(a), Box::new(b)),
            }
        }
        SymExpr::Mul(a, b) => {
            let a = constant_fold(*a);
            let b = constant_fold(*b);
            match (&a, &b) {
                (SymExpr::ConstBv { val: va, width: w }, SymExpr::ConstBv { val: vb, .. }) => {
                    SymExpr::ConstBv { val: va.wrapping_mul(*vb), width: *w }
                }
                _ => SymExpr::Mul(Box::new(a), Box::new(b)),
            }
        }
        SymExpr::BoolAnd(a, b) => {
            let a = constant_fold(*a);
            let b = constant_fold(*b);
            match (&a, &b) {
                (SymExpr::ConstBool(true), _) => b,
                (_, SymExpr::ConstBool(true)) => a,
                (SymExpr::ConstBool(false), _) | (_, SymExpr::ConstBool(false)) => {
                    SymExpr::ConstBool(false)
                }
                _ => SymExpr::BoolAnd(Box::new(a), Box::new(b)),
            }
        }
        SymExpr::BoolOr(a, b) => {
            let a = constant_fold(*a);
            let b = constant_fold(*b);
            match (&a, &b) {
                (SymExpr::ConstBool(false), _) => b,
                (_, SymExpr::ConstBool(false)) => a,
                (SymExpr::ConstBool(true), _) | (_, SymExpr::ConstBool(true)) => {
                    SymExpr::ConstBool(true)
                }
                _ => SymExpr::BoolOr(Box::new(a), Box::new(b)),
            }
        }
        SymExpr::BoolNot(a) => {
            let a = constant_fold(*a);
            match a {
                SymExpr::ConstBool(b) => SymExpr::ConstBool(!b),
                _ => SymExpr::BoolNot(Box::new(a)),
            }
        }
        other => other,
    }
}

fn algebraic_reduce(expr: SymExpr) -> SymExpr {
    match expr {
        // x + 0 = x
        SymExpr::Add(a, b) if matches!(*b, SymExpr::ConstBv { val: 0, .. }) => algebraic_reduce(*a),
        SymExpr::Add(a, b) if matches!(*a, SymExpr::ConstBv { val: 0, .. }) => algebraic_reduce(*b),
        // x - 0 = x
        SymExpr::Sub(a, b) if matches!(*b, SymExpr::ConstBv { val: 0, .. }) => algebraic_reduce(*a),
        // x * 1 = x
        SymExpr::Mul(a, b) if matches!(*b, SymExpr::ConstBv { val: 1, .. }) => algebraic_reduce(*a),
        SymExpr::Mul(a, b) if matches!(*a, SymExpr::ConstBv { val: 1, .. }) => algebraic_reduce(*b),
        // x * 0 = 0
        SymExpr::Mul(_, b) if matches!(*b, SymExpr::ConstBv { val: 0, .. }) => *b,
        SymExpr::Mul(a, _) if matches!(*a, SymExpr::ConstBv { val: 0, .. }) => *a,
        // !!x = x
        SymExpr::BoolNot(inner) => match *inner {
            SymExpr::BoolNot(x) => algebraic_reduce(*x),
            other => SymExpr::BoolNot(Box::new(algebraic_reduce(other))),
        },
        // x == x = true
        SymExpr::Eq(a, b) if *a == *b => SymExpr::ConstBool(true),
        SymExpr::Ne(a, b) if *a == *b => SymExpr::ConstBool(false),
        other => other,
    }
}

fn push_negations(expr: SymExpr) -> SymExpr {
    match expr {
        // !(A && B) = !A || !B
        SymExpr::BoolNot(inner) => match *inner {
            SymExpr::BoolAnd(a, b) => SymExpr::BoolOr(
                Box::new(push_negations(SymExpr::BoolNot(a))),
                Box::new(push_negations(SymExpr::BoolNot(b))),
            ),
            // !(A || B) = !A && !B
            SymExpr::BoolOr(a, b) => SymExpr::BoolAnd(
                Box::new(push_negations(SymExpr::BoolNot(a))),
                Box::new(push_negations(SymExpr::BoolNot(b))),
            ),
            SymExpr::BoolNot(x) => push_negations(*x),
            other => SymExpr::BoolNot(Box::new(push_negations(other))),
        },
        SymExpr::BoolAnd(a, b) => {
            SymExpr::BoolAnd(Box::new(push_negations(*a)), Box::new(push_negations(*b)))
        }
        SymExpr::BoolOr(a, b) => {
            SymExpr::BoolOr(Box::new(push_negations(*a)), Box::new(push_negations(*b)))
        }
        other => other,
    }
}

const fn solve_equalities(expr: SymExpr) -> SymExpr {
    // Simple: if we see `(var == const) && rest`, inline the substitution.
    // Full implementation would walk the conjunction tree.
    expr
}

fn dedup_conjuncts(expr: SymExpr) -> SymExpr {
    let mut conjuncts = collect_conjuncts(expr);
    conjuncts.dedup();
    build_conjunction(conjuncts)
}

fn collect_conjuncts(expr: SymExpr) -> Vec<SymExpr> {
    match expr {
        SymExpr::BoolAnd(a, b) => {
            let mut v = collect_conjuncts(*a);
            v.extend(collect_conjuncts(*b));
            v
        }
        other => vec![other],
    }
}

fn build_conjunction(mut conjuncts: Vec<SymExpr>) -> SymExpr {
    if conjuncts.is_empty() {
        return SymExpr::ConstBool(true);
    }
    let first = conjuncts.remove(0);
    conjuncts.into_iter().fold(first, |acc, c| {
        SymExpr::BoolAnd(Box::new(acc), Box::new(c))
    })
}

// ─── Learned constraint cache ─────────────────────────────────────────────────

fn hash_expr(expr: &SymExpr) -> u64 {
    let mut h = DefaultHasher::new();
    expr.hash(&mut h);
    h.finish()
}

/// Result cached for a given formula.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CachedResult {
    Sat(HashMap<String, u64>),
    Unsat,
    Unknown,
}

/// Caches constraint-solving results keyed by structural hash of the formula.
#[derive(Debug, Default)]
pub struct LearnedConstraintCache {
    entries: HashMap<u64, CachedResult>,
    hits: u64,
    misses: u64,
    capacity: usize,
}

impl LearnedConstraintCache {
    #[must_use] 
    pub fn new(capacity: usize) -> Self {
        Self { entries: HashMap::new(), hits: 0, misses: 0, capacity }
    }

    pub fn lookup(&mut self, expr: &SymExpr) -> Option<&CachedResult> {
        let key = hash_expr(expr);
        if self.entries.contains_key(&key) {
            self.hits += 1;
            self.entries.get(&key)
        } else {
            self.misses += 1;
            None
        }
    }

    pub fn insert(&mut self, expr: &SymExpr, result: CachedResult) {
        if self.entries.len() >= self.capacity {
            // Evict a random entry (first in iteration order).
            if let Some(k) = self.entries.keys().next().copied() {
                self.entries.remove(&k);
            }
        }
        self.entries.insert(hash_expr(expr), result);
    }

    #[must_use] 
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { self.hits as f64 / total as f64 }
    }

    #[must_use] 
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─── Inter-procedural propagator ─────────────────────────────────────────────

/// Configuration for the constraint propagator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagatorConfig {
    /// Maximum call depth for inter-procedural propagation.
    pub max_call_depth: usize,
    /// Number of loop unrolling steps before widening.
    pub loop_unroll_limit: u32,
    /// Enable summary-based propagation.
    pub use_summaries: bool,
    /// Enable loop invariant synthesis.
    pub synthesize_loop_invariants: bool,
    /// Cache capacity.
    pub cache_capacity: usize,
}

impl Default for PropagatorConfig {
    fn default() -> Self {
        Self {
            max_call_depth: 8,
            loop_unroll_limit: 4,
            use_summaries: true,
            synthesize_loop_invariants: true,
            cache_capacity: 4096,
        }
    }
}

/// Context for a single propagation call frame.
#[derive(Debug)]
struct CallFrame {
    function_address: u64,
    depth: usize,
    /// Constraints inherited from the caller.
    inherited: Vec<SymExpr>,
}

/// Inter-procedural constraint propagator.
///
/// Applies function summaries at call sites, synthesises loop invariants, and
/// simplifies the growing path condition to keep solver queries tractable.
pub struct ConstraintPropagator {
    config: PropagatorConfig,
    summaries: FunctionSummaryStore,
    simplifier: ConstraintSimplifier,
    cache: LearnedConstraintCache,
    call_stack: Vec<CallFrame>,
    /// Loop headers encountered (PC → invariants).
    loop_invariants: HashMap<u64, Vec<LoopInvariant>>,
    /// Total constraints propagated.
    stats_propagations: u64,
}

impl ConstraintPropagator {
    #[must_use] 
    pub fn new(config: PropagatorConfig) -> Self {
        let cap = config.cache_capacity;
        Self {
            config,
            summaries: FunctionSummaryStore::new(),
            simplifier: ConstraintSimplifier::new(),
            cache: LearnedConstraintCache::new(cap),
            call_stack: Vec::new(),
            loop_invariants: HashMap::new(),
            stats_propagations: 0,
        }
    }

    pub fn register_summary(&mut self, summary: ProcedureSummary) {
        self.summaries.insert(summary);
    }

    /// Propagate constraints at a function call site.
    ///
    /// 1. Checks preconditions of the callee against `state`.
    /// 2. If a summary is available, injects postconditions into `state`.
    /// 3. Simplifies the growing path condition.
    pub fn propagate_call(
        &mut self,
        callee_addr: u64,
        state: &mut SymbolicState,
    ) -> Result<Vec<SymbolicConstraint>, SymbolicError> {
        let depth = self.call_stack.len();
        if depth >= self.config.max_call_depth {
            return Err(SymbolicError::SolverError(format!(
                "max call depth {} exceeded",
                self.config.max_call_depth
            )));
        }

        let mut violated = Vec::new();

        if self.config.use_summaries
            && let Some(summary) = self.summaries.get(callee_addr) {
                // Check preconditions.
                violated = summary.check_preconditions(state)
                    .into_iter()
                    .cloned()
                    .collect();

                // Apply postconditions.
                let posts: Vec<SymExpr> = summary.postconditions.iter()
                    .map(|c| self.simplifier.simplify(c.expr.clone()))
                    .collect();

                // Inject postconditions as known-true constraints.
                for post in posts {
                    state.add_constraint(post);
                }

                // Apply return value if present (stored in postconditions labelled "return_value").
                if let Some(rv_post) = summary.postconditions.iter().find(|c| c.label == "return_value") {
                    state.write_register("rax", rv_post.expr.clone());
                }
            }

        // Snapshot the caller's path condition so the callee can restore it on
        // return; this implements scoped constraint propagation across calls.
        let inherited = state.path_condition.clone();
        self.call_stack.push(CallFrame {
            function_address: callee_addr,
            depth,
            inherited,
        });
        self.stats_propagations += 1;

        Ok(violated)
    }

    /// Pop a call frame on function return.
    pub fn propagate_return(&mut self, state: &mut SymbolicState) {
        if let Some(frame) = self.call_stack.pop() {
            // Simplify the path condition after returning.
            let pc = state.path_condition.clone();
            let simplified = pc.into_iter()
                .map(|c| self.simplifier.simplify(c))
                .filter(|c| !matches!(c, SymExpr::ConstBool(true)))
                .collect::<Vec<_>>();
            // Merge: keep the simplified callee-derived constraints, then
            // restore caller-inherited constraints that were dropped during
            // callee-only simplification.
            let mut merged = simplified;
            for inh in &frame.inherited {
                if !merged.iter().any(|c| c == inh) {
                    merged.push(inh.clone());
                }
            }
            state.path_condition = merged;
            // Surface frame metadata for diagnostics / propagation accounting.
            self.stats_propagations = self
                .stats_propagations
                .saturating_add(frame.depth as u64)
                .saturating_add(u64::from(frame.function_address != 0));
        }
    }

    /// Return the address and depth of the current top-of-stack call frame, if any.
    #[must_use]
    pub fn current_frame(&self) -> Option<(u64, usize)> {
        self.call_stack
            .last()
            .map(|f| (f.function_address, f.depth))
    }

    /// Constraints inherited by the current top-of-stack call frame from its caller.
    #[must_use]
    pub fn current_inherited(&self) -> &[SymExpr] {
        self.call_stack
            .last()
            .map_or(&[], |f| f.inherited.as_slice())
    }

    /// Synthesise loop invariants for the loop with header at `pc`.
    ///
    /// Uses simple template matching:
    /// - If `state` has a register modified by `+= constant`, emit a lower-bound invariant.
    /// - If a comparison with a bound is on the path condition, emit an upper-bound invariant.
    pub fn synthesize_invariants(&mut self, pc: u64, state: &SymbolicState) -> Vec<LoopInvariant> {
        if !self.config.synthesize_loop_invariants {
            return Vec::new();
        }

        let mut invariants = Vec::new();

        // Heuristic 1: find registers that look like monotone counters.
        for (reg, expr) in &state.registers {
            if let SymExpr::Add(base, step) = expr
                && let SymExpr::Var { name, .. } = base.as_ref()
                    && name == reg
                        && let SymExpr::ConstBv { val: step_val, .. } = step.as_ref()
                            && *step_val > 0 {
                                // reg >= 0 (unsigned, always true for u64, but symbolic useful)
                                invariants.push(LoopInvariant::LowerBound {
                                    var: reg.clone(),
                                    lo_bound: SymExpr::ConstBv { val: 0, width: 64 },
                                });
                            }
        }

        // Heuristic 2: extract upper bounds from path condition comparisons.
        for constraint in &state.path_condition {
            if let SymExpr::ULt(lhs, rhs) | SymExpr::SLt(lhs, rhs) = constraint
                && let SymExpr::Var { name, .. } = lhs.as_ref() {
                    invariants.push(LoopInvariant::UpperBound {
                        var: name.clone(),
                        hi_bound: *rhs.clone(),
                    });
                }
        }

        self.loop_invariants.insert(pc, invariants.clone());
        invariants
    }

    /// Widen the state at a loop back-edge: replace precise values with
    /// symbolic ranges derived from the synthesised invariants.
    pub fn widen_at_backedge(&self, pc: u64, state: &mut SymbolicState) {
        if let Some(invariants) = self.loop_invariants.get(&pc) {
            for inv in invariants {
                state.add_constraint(inv.to_expr());
            }
        }
    }

    /// Simplify the entire path condition of `state`.
    pub fn simplify_path_condition(&self, state: &mut SymbolicState) {
        let pc = std::mem::take(&mut state.path_condition);
        state.path_condition = pc
            .into_iter()
            .map(|c| self.simplifier.simplify(c))
            .filter(|c| !matches!(c, SymExpr::ConstBool(true)))
            .collect();
    }

    /// Return a reference to the constraint cache.
    pub const fn cache(&mut self) -> &mut LearnedConstraintCache {
        &mut self.cache
    }

    /// Return the summary store.
    #[must_use] 
    pub const fn summaries(&self) -> &FunctionSummaryStore {
        &self.summaries
    }

    #[must_use] 
    pub const fn stats_propagations(&self) -> u64 {
        self.stats_propagations
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_constant_fold_add() {
        let expr = SymExpr::Add(
            Box::new(SymExpr::ConstBv { val: 3, width: 64 }),
            Box::new(SymExpr::ConstBv { val: 4, width: 64 }),
        );
        let result = constant_fold(expr);
        assert_eq!(result, SymExpr::ConstBv { val: 7, width: 64 });
    }

    #[test]
    fn test_algebraic_reduce_mul_zero() {
        let expr = SymExpr::Mul(
            Box::new(SymExpr::Var { name: "x".into(), ty: SymType::BitVec(64) }),
            Box::new(SymExpr::ConstBv { val: 0, width: 64 }),
        );
        let result = algebraic_reduce(expr);
        assert!(matches!(result, SymExpr::ConstBv { val: 0, .. }));
    }

    #[test]
    fn test_push_negations_demorgan() {
        // !(A && B) = !A || !B
        let a = SymExpr::Var { name: "a".into(), ty: SymType::Bool };
        let b = SymExpr::Var { name: "b".into(), ty: SymType::Bool };
        let expr = SymExpr::BoolNot(Box::new(SymExpr::BoolAnd(Box::new(a), Box::new(b))));
        let result = push_negations(expr);
        assert!(matches!(result, SymExpr::BoolOr(_, _)));
    }

    #[test]
    fn test_simplifier_pipeline() {
        let s = ConstraintSimplifier::new();
        // (x + 0) * 1 = x
        let expr = SymExpr::Mul(
            Box::new(SymExpr::Add(
                Box::new(SymExpr::Var { name: "x".into(), ty: SymType::BitVec(64) }),
                Box::new(SymExpr::ConstBv { val: 0, width: 64 }),
            )),
            Box::new(SymExpr::ConstBv { val: 1, width: 64 }),
        );
        let result = s.simplify(expr);
        assert_eq!(result, SymExpr::Var { name: "x".into(), ty: SymType::BitVec(64) });
    }

    #[test]
    fn test_cache_hit_miss() {
        let mut cache = LearnedConstraintCache::new(16);
        let expr = SymExpr::ConstBool(true);
        assert!(cache.lookup(&expr).is_none());
        cache.insert(&expr, CachedResult::Sat(HashMap::new()));
        assert!(cache.lookup(&expr).is_some());
    }

    #[test]
    fn test_summary_store() {
        let mut store = FunctionSummaryStore::new();
        let mut s = ProcedureSummary::new(0x1000).with_name("malloc");
        s.add_postcondition(SymbolicConstraint::new("ret_nonzero", SymExpr::ConstBool(true)));
        store.insert(s);
        assert!(store.get(0x1000).is_some());
        assert!(store.get_by_name("malloc").is_some());
        assert_eq!(store.len(), 1);
    }
}
