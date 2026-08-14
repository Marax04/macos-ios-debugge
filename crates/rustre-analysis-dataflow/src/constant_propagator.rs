//! `constant_propagator` — Constant propagation using a sparse conditional
//! constant (SCC) lattice.
//!
//! # Relationship to [`crate::constant_propagation`]
//! This module provides a **generic forward worklist CP** over an abstract
//! `PropBlock`/`VarId` IR.  It does not require SSA form and is IR-agnostic.
//!
//! [`crate::constant_propagation`] implements the full **Wegman-Zadeck SCCP
//! algorithm** over the project's SSA IR ([`crate::ssa::SsaFunction`]), with
//! two worklists and conditional-branch folding.  The two modules are
//! intentionally kept separate because they target different use cases.
//!
//! This module provides [`ConstantPropagator`] which propagates constants
//! through a control-flow graph using the three-valued lattice:
//!
//! ```text
//! Top  (unknown / not yet analysed)
//!  |
//! Const(c)  (exactly one value)
//!  |
//! Bottom  (multiple values / non-constant)
//! ```
//!
//! # Key types
//! - [`ConstLattice`]        — the per-variable lattice value.
//! - [`PropState`]           — the per-block propagation environment.
//! - [`PropResult`]          — the final analysis result.
//! - [`ConstantPropagator`]  — configurable analysis driver.
//! - [`propagate_constants`] — convenience entry point.

use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// ConstLattice
// ─────────────────────────────────────────────────────────────────────────────

/// Three-valued constant-propagation lattice element for one variable.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ConstLattice {
    /// Optimistic starting value: the variable has not yet been analysed.
    #[default]
    Top,
    /// The variable is known to hold exactly this constant value.
    Const(i64),
    /// The variable may hold more than one value (or a non-constant).
    Bottom,
}

impl ConstLattice {
    /// Meet (greatest lower bound) of two lattice values.
    ///
    /// ```text
    /// meet(Top,      x)        = x
    /// meet(x,        Top)      = x
    /// meet(Const(a), Const(b)) = if a == b { Const(a) } else { Bottom }
    /// meet(Bottom,   _)        = Bottom
    /// meet(_,        Bottom)   = Bottom
    /// ```
    #[must_use]
    pub fn meet(a: &Self, b: &Self) -> Self {
        match (a, b) {
            (Self::Top, x) | (x, Self::Top) => x.clone(),
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Const(x), Self::Const(y)) => {
                if x == y {
                    Self::Const(*x)
                } else {
                    Self::Bottom
                }
            }
        }
    }

    /// Return `true` if this value is a known constant.
    #[must_use]
    pub const fn is_const(&self) -> bool {
        matches!(self, Self::Const(_))
    }

    /// Return `true` if this value is `Bottom` (non-constant).
    #[must_use]
    pub const fn is_bottom(&self) -> bool {
        matches!(self, Self::Bottom)
    }

    /// Return `true` if this value is `Top` (not yet seen).
    #[must_use]
    pub const fn is_top(&self) -> bool {
        matches!(self, Self::Top)
    }

    /// Extract the constant value, if any.
    #[must_use]
    pub const fn as_const(&self) -> Option<i64> {
        if let Self::Const(c) = self {
            Some(*c)
        } else {
            None
        }
    }
}


impl std::fmt::Display for ConstLattice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Top => write!(f, "⊤"),
            Self::Const(c) => write!(f, "{c}"),
            Self::Bottom => write!(f, "⊥"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VarId
// ─────────────────────────────────────────────────────────────────────────────

/// Compact identifier for a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VarId(pub u32);

impl VarId {
    #[must_use]
    pub const fn new(v: u32) -> Self {
        Self(v)
    }
}

impl std::fmt::Display for VarId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PropExpr — abstract expression for the propagator
// ─────────────────────────────────────────────────────────────────────────────

/// An expression whose value can be constant-folded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropExpr {
    /// A literal integer constant.
    Literal(i64),
    /// Read from a variable.
    Var(VarId),
    /// Binary operation on two operands.
    BinOp(BinOpKind, Box<Self>, Box<Self>),
    /// Unary operation.
    UnaryOp(UnaryOpKind, Box<Self>),
    /// Phi-node: takes the join of all incoming values.
    Phi(Vec<VarId>),
    /// Unknown / non-constant source (e.g. memory read).
    Unknown,
}

/// Supported binary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinOpKind {
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    Shl,
    Shr,
}

/// Supported unary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOpKind {
    Neg,
    Not,
    Abs,
}

impl PropExpr {
    /// Evaluate the expression to a [`ConstLattice`] given the current
    /// per-variable state.
    #[must_use]
    pub fn eval(&self, state: &PropState) -> ConstLattice {
        match self {
            Self::Literal(v) => ConstLattice::Const(*v),
            Self::Var(id) => state.get(*id).clone(),
            Self::BinOp(op, lhs, rhs) => {
                let l = lhs.eval(state);
                let r = rhs.eval(state);
                match (&l, &r) {
                    (ConstLattice::Bottom, _) | (_, ConstLattice::Bottom) => ConstLattice::Bottom,
                    (ConstLattice::Top, _) | (_, ConstLattice::Top) => ConstLattice::Top,
                    (ConstLattice::Const(a), ConstLattice::Const(b)) => {
                        fold_bin_op(*op, *a, *b)
                    }
                }
            }
            Self::UnaryOp(op, operand) => match operand.eval(state) {
                ConstLattice::Const(v) => fold_unary_op(*op, v),
                other => other,
            },
            Self::Phi(vars) => {
                let mut acc = ConstLattice::Top;
                for &v in vars {
                    acc = ConstLattice::meet(&acc, state.get(v));
                }
                acc
            }
            Self::Unknown => ConstLattice::Bottom,
        }
    }
}

fn fold_bin_op(op: BinOpKind, a: i64, b: i64) -> ConstLattice {
    let result = match op {
        BinOpKind::Add => a.checked_add(b),
        BinOpKind::Sub => a.checked_sub(b),
        BinOpKind::Mul => a.checked_mul(b),
        BinOpKind::Div => {
            if b == 0 {
                return ConstLattice::Bottom;
            }
            a.checked_div(b)
        }
        BinOpKind::And => Some(a & b),
        BinOpKind::Or => Some(a | b),
        BinOpKind::Xor => Some(a ^ b),
        BinOpKind::Shl => {
            if !(0..64).contains(&b) {
                return ConstLattice::Bottom;
            }
            // b validated to [0, 63]; unwrap() is infallible here
            Some(a << u32::try_from(b).unwrap())
        }
        BinOpKind::Shr => {
            if !(0..64).contains(&b) {
                return ConstLattice::Bottom;
            }
            // Arithmetic (sign-extending) shift: `i64::wrapping_shr` already
            // does this correctly for signed operands. The previous
            // implementation went through `cast_unsigned`/`cast_signed`,
            // which performs a *logical* shift instead and produced a huge
            // positive result for negative constants (e.g. `-8 >> 1` came
            // out as `i64::MAX/2`-ish instead of the correct `-4`).
            Some(a.wrapping_shr(u32::try_from(b).unwrap()))
        }
    };
    result.map_or(ConstLattice::Bottom, ConstLattice::Const)
}

const fn fold_unary_op(op: UnaryOpKind, v: i64) -> ConstLattice {
    match op {
        UnaryOpKind::Neg => ConstLattice::Const(v.wrapping_neg()),
        UnaryOpKind::Not => ConstLattice::Const(!v),
        UnaryOpKind::Abs => ConstLattice::Const(v.wrapping_abs()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PropStmt — a single statement for the propagator
// ─────────────────────────────────────────────────────────────────────────────

/// A single abstract statement for constant-propagation purposes.
#[derive(Debug, Clone)]
pub struct PropStmt {
    /// The variable being defined (if any).
    pub def: Option<VarId>,
    /// The right-hand-side expression.
    pub rhs: PropExpr,
    /// Whether this statement is a conditional branch.
    /// If `Some((true_var, false_var))`, the branch is taken on a nonzero
    /// condition and drives block-specific fact refinement.
    pub is_branch: bool,
}

impl PropStmt {
    /// A definition: `def = rhs`.
    #[must_use]
    pub const fn assign(def: VarId, rhs: PropExpr) -> Self {
        Self {
            def: Some(def),
            rhs,
            is_branch: false,
        }
    }

    /// A statement with no definition (side effect only).
    #[must_use]
    pub const fn effect(rhs: PropExpr) -> Self {
        Self {
            def: None,
            rhs,
            is_branch: false,
        }
    }

    /// A conditional branch on `cond_var`.
    #[must_use]
    pub const fn branch(cond: PropExpr) -> Self {
        Self {
            def: None,
            rhs: cond,
            is_branch: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PropState — per-block lattice environment
// ─────────────────────────────────────────────────────────────────────────────

/// The per-block abstract state: a map from [`VarId`] to [`ConstLattice`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropState {
    pub values: HashMap<VarId, ConstLattice>,
}

impl PropState {
    /// Create a new state with no information (all variables at Top).
    #[must_use]
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    /// Get the lattice value for a variable (Top if not yet seen).
    #[must_use]
    pub fn get(&self, var: VarId) -> &ConstLattice {
        self.values.get(&var).unwrap_or(&ConstLattice::Top)
    }

    /// Set the lattice value for a variable.
    pub fn set(&mut self, var: VarId, value: ConstLattice) {
        self.values.insert(var, value);
    }

    /// Join `other` into `self` (meet on every variable).
    ///
    /// Returns `true` if any value changed.
    pub fn join_from(&mut self, other: &Self) -> bool {
        let mut changed = false;
        for (&var, val) in &other.values {
            let current = self.values.entry(var).or_insert(ConstLattice::Top);
            let new_val = ConstLattice::meet(current, val);
            if new_val != *current {
                *current = new_val;
                changed = true;
            }
        }
        // Variables in `self` but not in `other` stay unchanged.
        changed
    }

    /// Return all variables whose lattice value is `Const(c)`.
    #[must_use]
    pub fn constants(&self) -> Vec<(VarId, i64)> {
        let mut result: Vec<(VarId, i64)> = self
            .values
            .iter()
            .filter_map(|(&v, l)| l.as_const().map(|c| (v, c)))
            .collect();
        result.sort_by_key(|(v, _)| *v);
        result
    }
}

impl Default for PropState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PropBlock — a basic block for the propagator
// ─────────────────────────────────────────────────────────────────────────────

/// A basic block in the CFG for constant propagation.
#[derive(Debug, Clone)]
pub struct PropBlock {
    /// Unique block id (`0..n`).
    pub id: usize,
    /// Statements in program order.
    pub stmts: Vec<PropStmt>,
    /// Successor block ids.
    pub succs: Vec<usize>,
}

// ─────────────────────────────────────────────────────────────────────────────
// PropResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of constant propagation.
#[derive(Debug, Clone)]
pub struct PropResult {
    /// Per-block state on entry (`in_states[i]` = state entering block `i`).
    pub in_states: Vec<PropState>,
    /// Per-block state on exit (`out_states[i]` = state leaving block `i`).
    pub out_states: Vec<PropState>,
    /// Number of worklist iterations until convergence.
    pub iterations: usize,
}

impl PropResult {
    /// Return the constants known at the *entry* of block `id`.
    #[must_use]
    pub fn constants_in(&self, block_id: usize) -> Vec<(VarId, i64)> {
        self.in_states
            .get(block_id)
            .map(PropState::constants)
            .unwrap_or_default()
    }

    /// Return the constants known at the *exit* of block `id`.
    #[must_use]
    pub fn constants_out(&self, block_id: usize) -> Vec<(VarId, i64)> {
        self.out_states
            .get(block_id)
            .map(PropState::constants)
            .unwrap_or_default()
    }

    /// Return the lattice value of `var` at the *entry* of block `id`.
    #[must_use]
    pub fn value_in(&self, block_id: usize, var: VarId) -> ConstLattice {
        self.in_states
            .get(block_id)
            .map_or(ConstLattice::Top, |s| s.get(var).clone())
    }

    /// Return the lattice value of `var` at the *exit* of block `id`.
    #[must_use]
    pub fn value_out(&self, block_id: usize, var: VarId) -> ConstLattice {
        self.out_states
            .get(block_id)
            .map_or(ConstLattice::Top, |s| s.get(var).clone())
    }

    /// Collect all variables that are globally constant (constant in every
    /// block's exit state).
    #[must_use]
    pub fn globally_constant_vars(&self) -> Vec<(VarId, i64)> {
        if self.out_states.is_empty() {
            return vec![];
        }
        // Collect all var ids mentioned across all states.
        let all_vars: HashSet<VarId> = self
            .out_states
            .iter()
            .flat_map(|s| s.values.keys().copied())
            .collect();

        let mut result = Vec::new();
        'var_loop: for var in all_vars {
            let mut const_val: Option<i64> = None;
            for state in &self.out_states {
                match state.get(var) {
                    ConstLattice::Top => {} // not constrained here
                    ConstLattice::Const(c) => match const_val {
                        None => const_val = Some(*c),
                        Some(v) if v == *c => {}
                        _ => continue 'var_loop,
                    },
                    ConstLattice::Bottom => continue 'var_loop,
                }
            }
            if let Some(c) = const_val {
                result.push((var, c));
            }
        }
        result.sort_by_key(|(v, _)| *v);
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstantPropagator
// ─────────────────────────────────────────────────────────────────────────────

/// Configurable constant propagator.
///
/// Implements the classic forward worklist algorithm with the three-valued
/// lattice.  Optimistic start: all variables begin at `Top`.
#[derive(Debug, Clone)]
pub struct ConstantPropagator {
    /// Maximum worklist iterations before giving up.
    pub max_iterations: usize,
    /// If `true`, apply constant-folding to every expression while
    /// propagating (improves precision for chains of constants).
    pub fold_exprs: bool,
}

impl Default for ConstantPropagator {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstantPropagator {
    /// Create a propagator with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_iterations: 100_000,
            fold_exprs: true,
        }
    }

    /// Apply the transfer function for one block.
    ///
    /// Processes statements in program order, evaluating each RHS and
    /// updating the abstract state.
    #[must_use]
    pub fn transfer(&self, block: &PropBlock, in_state: &PropState) -> PropState {
        let mut state = in_state.clone();
        for stmt in &block.stmts {
            if let Some(def) = stmt.def {
                let value = stmt.rhs.eval(&state);
                state.set(def, value);
            }
            // Branch statements don't define variables; they refine state only
            // in the richer SCC algorithm.  Here we just evaluate for
            // side-effect tracking.
        }
        state
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// propagate_constants  — top-level entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Run constant propagation over the given CFG.
///
/// # Arguments
/// - `blocks`      — basic blocks (ids must form a contiguous `0..n` range).
/// - `entry`       — id of the function entry block.
/// - `preds`       — predecessor lists (`preds[i]` = predecessors of block `i`).
/// - `propagator`  — configured [`ConstantPropagator`] instance.
///
/// # Returns
/// A [`PropResult`] with per-block in/out states.
#[must_use]
pub fn propagate_constants(
    blocks: &[PropBlock],
    entry: usize,
    preds: &[Vec<usize>],
    propagator: &ConstantPropagator,
) -> PropResult {
    let n = blocks.len();
    if n == 0 {
        return PropResult {
            in_states: vec![],
            out_states: vec![],
            iterations: 0,
        };
    }

    // Initialize all states to Top (empty map = all Top by default).
    let mut in_states: Vec<PropState> = (0..n).map(|_| PropState::new()).collect();
    let mut out_states: Vec<PropState> = (0..n)
        .map(|i| propagator.transfer(&blocks[i], &in_states[i]))
        .collect();

    // Worklist starts with all blocks.
    let mut worklist: VecDeque<usize> = (0..n).collect();
    let mut in_worklist: Vec<bool> = vec![true; n];
    let mut iterations = 0usize;

    while let Some(bid) = worklist.pop_front() {
        in_worklist[bid] = false;
        iterations += 1;
        if iterations > propagator.max_iterations {
            break;
        }

        // Compute new in-state = meet of all predecessors' out-states.
        let mut new_in = PropState::new();
        let block_preds = preds.get(bid).map_or(&[][..], Vec::as_slice);
        for &pred in block_preds {
            if pred < n {
                new_in.join_from(&out_states[pred]);
            }
        }
        // Entry block: control also arrives from outside the function, where
        // every variable holds an arbitrary (unknown) value — the boundary
        // state is Bottom for every variable.  When the entry block has
        // predecessors (a loop back-edge to the entry), its in-state must be
        // the meet of that boundary with the predecessors' out-states, i.e.
        // Bottom for every variable mentioned.  Taking only the predecessor
        // meet would unsoundly claim loop-carried constants on the very
        // first entry into the function.
        if bid == entry {
            if block_preds.is_empty() {
                new_in = PropState::new();
            } else {
                for v in new_in.values.values_mut() {
                    *v = ConstLattice::Bottom;
                }
            }
        }

        let new_out = propagator.transfer(&blocks[bid], &new_in);

        if new_out != out_states[bid] {
            out_states[bid] = new_out;
            // Re-queue successors.
            for &succ in &blocks[bid].succs {
                if succ < n && !in_worklist[succ] {
                    in_worklist[succ] = true;
                    worklist.push_back(succ);
                }
            }
        }
        in_states[bid] = new_in;
    }

    PropResult {
        in_states,
        out_states,
        iterations,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FoldingRewriter — apply prop results to rewrite expressions
// ─────────────────────────────────────────────────────────────────────────────

/// Rewrites a [`PropExpr`] using the known constant state, replacing
/// `Var(v)` with `Literal(c)` wherever the variable is known to be constant.
#[must_use]
pub fn rewrite_expr(expr: &PropExpr, state: &PropState) -> PropExpr {
    match expr {
        PropExpr::Var(v) => {
            state.get(*v).as_const().map_or(PropExpr::Var(*v), PropExpr::Literal)
        }
        PropExpr::BinOp(op, lhs, rhs) => {
            let new_lhs = rewrite_expr(lhs, state);
            let new_rhs = rewrite_expr(rhs, state);
            // Try to constant-fold immediately.
            if let (PropExpr::Literal(a), PropExpr::Literal(b)) = (&new_lhs, &new_rhs)
                && let ConstLattice::Const(c) = fold_bin_op(*op, *a, *b) {
                    return PropExpr::Literal(c);
                }
            PropExpr::BinOp(*op, Box::new(new_lhs), Box::new(new_rhs))
        }
        PropExpr::UnaryOp(op, operand) => {
            let new_op = rewrite_expr(operand, state);
            if let PropExpr::Literal(v) = &new_op
                && let ConstLattice::Const(c) = fold_unary_op(*op, *v) {
                    return PropExpr::Literal(c);
                }
            PropExpr::UnaryOp(*op, Box::new(new_op))
        }
        PropExpr::Phi(vars) => PropExpr::Phi(vars.clone()),
        PropExpr::Literal(v) => PropExpr::Literal(*v),
        PropExpr::Unknown => PropExpr::Unknown,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PropagationStats — summary across a batch of functions
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated propagation statistics.
#[derive(Debug, Clone, Default)]
pub struct PropagationStats {
    /// Total functions processed.
    pub functions: usize,
    /// Total variables found to be constant (summed across all functions).
    pub total_constants_found: usize,
    /// Total worklist iterations across all functions.
    pub total_iterations: usize,
}

impl PropagationStats {
    /// Record results for one function.
    pub fn record(&mut self, result: &PropResult) {
        self.functions += 1;
        self.total_iterations += result.iterations;
        self.total_constants_found += result.globally_constant_vars().len();
    }

    /// Average iterations per function.
    #[must_use]
    pub fn avg_iterations(&self) -> f64 {
        if self.functions == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.total_iterations).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.functions).unwrap_or(u32::MAX))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn v(n: u32) -> VarId {
        VarId::new(n)
    }

    fn lit(n: i64) -> PropExpr {
        PropExpr::Literal(n)
    }

    fn var_expr(n: u32) -> PropExpr {
        PropExpr::Var(v(n))
    }

    fn make_blocks(
        layout: Vec<(usize, Vec<PropStmt>, Vec<usize>)>,
    ) -> (Vec<PropBlock>, Vec<Vec<usize>>) {
        let n = layout.len();
        let mut preds: Vec<Vec<usize>> = vec![vec![]; n];
        let blocks: Vec<PropBlock> = layout
            .into_iter()
            .map(|(id, stmts, succs)| {
                for &s in &succs {
                    if s < n {
                        preds[s].push(id);
                    }
                }
                PropBlock { id, stmts, succs }
            })
            .collect();
        (blocks, preds)
    }

    #[test]
    fn test_const_lattice_meet() {
        assert_eq!(ConstLattice::meet(&ConstLattice::Top, &ConstLattice::Const(5)), ConstLattice::Const(5));
        assert_eq!(ConstLattice::meet(&ConstLattice::Const(3), &ConstLattice::Const(3)), ConstLattice::Const(3));
        assert_eq!(ConstLattice::meet(&ConstLattice::Const(3), &ConstLattice::Const(4)), ConstLattice::Bottom);
        assert_eq!(ConstLattice::meet(&ConstLattice::Bottom, &ConstLattice::Const(9)), ConstLattice::Bottom);
    }

    #[test]
    fn test_propagate_literal_assignment() {
        // Block 0: v0 = 42
        let (blocks, preds) = make_blocks(vec![
            (0, vec![PropStmt::assign(v(0), lit(42))], vec![]),
        ]);
        let prop = ConstantPropagator::new();
        let result = propagate_constants(&blocks, 0, &preds, &prop);
        assert_eq!(result.value_out(0, v(0)), ConstLattice::Const(42));
    }

    #[test]
    fn test_propagate_chain() {
        // Block 0: v0 = 10
        // Block 1: v1 = v0 + 5  → should fold to 15
        let (blocks, preds) = make_blocks(vec![
            (0, vec![PropStmt::assign(v(0), lit(10))], vec![1]),
            (
                1,
                vec![PropStmt::assign(
                    v(1),
                    PropExpr::BinOp(BinOpKind::Add, Box::new(var_expr(0)), Box::new(lit(5))),
                )],
                vec![],
            ),
        ]);
        let prop = ConstantPropagator::new();
        let result = propagate_constants(&blocks, 0, &preds, &prop);
        assert_eq!(result.value_out(1, v(1)), ConstLattice::Const(15));
    }

    #[test]
    fn test_diamond_becomes_bottom() {
        // Block 0 →{1,2}→ 3
        // Block 1: v0 = 10, Block 2: v0 = 20 → v0 is Bottom at Block 3
        let (blocks, preds) = make_blocks(vec![
            (0, vec![], vec![1, 2]),
            (1, vec![PropStmt::assign(v(0), lit(10))], vec![3]),
            (2, vec![PropStmt::assign(v(0), lit(20))], vec![3]),
            (3, vec![], vec![]),
        ]);
        let prop = ConstantPropagator::new();
        let result = propagate_constants(&blocks, 0, &preds, &prop);
        assert_eq!(result.value_in(3, v(0)), ConstLattice::Bottom);
    }

    #[test]
    fn test_diamond_same_value_stays_const() {
        // Both branches assign v0 = 7 → still Const(7) at block 3.
        let (blocks, preds) = make_blocks(vec![
            (0, vec![], vec![1, 2]),
            (1, vec![PropStmt::assign(v(0), lit(7))], vec![3]),
            (2, vec![PropStmt::assign(v(0), lit(7))], vec![3]),
            (3, vec![], vec![]),
        ]);
        let prop = ConstantPropagator::new();
        let result = propagate_constants(&blocks, 0, &preds, &prop);
        assert_eq!(result.value_in(3, v(0)), ConstLattice::Const(7));
    }

    #[test]
    fn test_unknown_gives_bottom() {
        let (blocks, preds) = make_blocks(vec![
            (0, vec![PropStmt::assign(v(0), PropExpr::Unknown)], vec![]),
        ]);
        let prop = ConstantPropagator::new();
        let result = propagate_constants(&blocks, 0, &preds, &prop);
        assert_eq!(result.value_out(0, v(0)), ConstLattice::Bottom);
    }

    #[test]
    fn test_phi_same_value() {
        // v1 = phi(v0, v0) where v0 = 3 in both predecessors.
        let (blocks, preds) = make_blocks(vec![
            (0, vec![PropStmt::assign(v(0), lit(3))], vec![2]),
            (1, vec![PropStmt::assign(v(0), lit(3))], vec![2]),
            (
                2,
                vec![PropStmt::assign(v(1), PropExpr::Phi(vec![v(0), v(0)]))],
                vec![],
            ),
        ]);
        let prop = ConstantPropagator::new();
        let result = propagate_constants(&blocks, 0, &preds, &prop);
        // v0 enters block 2 from both predecessors as 3.
        assert_eq!(result.value_in(2, v(0)), ConstLattice::Const(3));
    }

    #[test]
    fn test_globally_constant_vars() {
        let (blocks, preds) = make_blocks(vec![
            (0, vec![PropStmt::assign(v(0), lit(5))], vec![1]),
            (1, vec![PropStmt::assign(v(1), lit(10))], vec![]),
        ]);
        let prop = ConstantPropagator::new();
        let result = propagate_constants(&blocks, 0, &preds, &prop);
        let globals = result.globally_constant_vars();
        let ids: Vec<VarId> = globals.iter().map(|(v, _)| *v).collect();
        assert!(ids.contains(&v(0)));
        assert!(ids.contains(&v(1)));
    }

    #[test]
    fn test_rewrite_expr() {
        let mut state = PropState::new();
        state.set(v(0), ConstLattice::Const(4));
        state.set(v(1), ConstLattice::Const(6));
        let expr = PropExpr::BinOp(
            BinOpKind::Mul,
            Box::new(var_expr(0)),
            Box::new(var_expr(1)),
        );
        let rewritten = rewrite_expr(&expr, &state);
        assert_eq!(rewritten, PropExpr::Literal(24));
    }

    #[test]
    fn test_fold_div_by_zero() {
        let mut state = PropState::new();
        state.set(v(0), ConstLattice::Const(10));
        state.set(v(1), ConstLattice::Const(0));
        let expr = PropExpr::BinOp(
            BinOpKind::Div,
            Box::new(var_expr(0)),
            Box::new(var_expr(1)),
        );
        assert_eq!(expr.eval(&state), ConstLattice::Bottom);
    }

    #[test]
    fn test_propagation_stats() {
        let (blocks, preds) = make_blocks(vec![
            (0, vec![PropStmt::assign(v(0), lit(99))], vec![]),
        ]);
        let prop = ConstantPropagator::new();
        let result = propagate_constants(&blocks, 0, &preds, &prop);
        let mut stats = PropagationStats::default();
        stats.record(&result);
        assert_eq!(stats.functions, 1);
        assert!(stats.total_constants_found > 0);
    }

    #[test]
    fn test_empty_cfg() {
        let prop = ConstantPropagator::new();
        let result = propagate_constants(&[], 0, &[], &prop);
        assert_eq!(result.iterations, 0);
        assert!(result.in_states.is_empty());
    }

    #[test]
    fn test_const_lattice_predicates_and_display() {
        assert!(ConstLattice::Top.is_top());
        assert!(!ConstLattice::Top.is_const());
        assert!(!ConstLattice::Top.is_bottom());
        assert!(ConstLattice::Const(5).is_const());
        assert_eq!(ConstLattice::Const(5).as_const(), Some(5));
        assert!(ConstLattice::Bottom.is_bottom());
        assert_eq!(ConstLattice::Bottom.as_const(), None);
        assert_eq!(format!("{}", ConstLattice::Top), "⊤");
        assert_eq!(format!("{}", ConstLattice::Const(7)), "7");
        assert_eq!(format!("{}", ConstLattice::Bottom), "⊥");
    }

    #[test]
    fn test_var_id_display_and_new() {
        let id = VarId::new(3);
        assert_eq!(id.0, 3);
        assert_eq!(format!("{id}"), "v3");
    }

    #[test]
    fn test_prop_state_join_from_reports_change() {
        let mut a = PropState::new();
        let mut b = PropState::new();
        b.set(v(0), ConstLattice::Const(1));
        // First join introduces new info -> changed.
        assert!(a.join_from(&b));
        // Joining identical info again -> no change.
        assert!(!a.join_from(&b));
        // Joining conflicting info -> changes to Bottom.
        let mut c = PropState::new();
        c.set(v(0), ConstLattice::Const(2));
        assert!(a.join_from(&c));
        assert_eq!(a.get(v(0)), &ConstLattice::Bottom);
    }

    #[test]
    fn test_transfer_direct() {
        let prop = ConstantPropagator::new();
        let block = PropBlock {
            id: 0,
            stmts: vec![
                PropStmt::assign(v(0), lit(2)),
                PropStmt::assign(
                    v(1),
                    PropExpr::BinOp(BinOpKind::Mul, Box::new(var_expr(0)), Box::new(lit(3))),
                ),
            ],
            succs: vec![],
        };
        let out = prop.transfer(&block, &PropState::new());
        assert_eq!(out.get(v(1)), &ConstLattice::Const(6));
    }

    #[test]
    fn test_bin_op_sub_and_bitwise() {
        let mut state = PropState::new();
        state.set(v(0), ConstLattice::Const(12));
        state.set(v(1), ConstLattice::Const(5));
        let sub = PropExpr::BinOp(BinOpKind::Sub, Box::new(var_expr(0)), Box::new(var_expr(1)));
        assert_eq!(sub.eval(&state), ConstLattice::Const(7));
        let and = PropExpr::BinOp(BinOpKind::And, Box::new(var_expr(0)), Box::new(var_expr(1)));
        assert_eq!(and.eval(&state), ConstLattice::Const(12 & 5));
        let or = PropExpr::BinOp(BinOpKind::Or, Box::new(var_expr(0)), Box::new(var_expr(1)));
        assert_eq!(or.eval(&state), ConstLattice::Const(12 | 5));
        let xor = PropExpr::BinOp(BinOpKind::Xor, Box::new(var_expr(0)), Box::new(var_expr(1)));
        assert_eq!(xor.eval(&state), ConstLattice::Const(12 ^ 5));
    }

    #[test]
    fn test_shl_and_shr_positive() {
        let mut state = PropState::new();
        state.set(v(0), ConstLattice::Const(4));
        state.set(v(1), ConstLattice::Const(2));
        let shl = PropExpr::BinOp(BinOpKind::Shl, Box::new(var_expr(0)), Box::new(var_expr(1)));
        assert_eq!(shl.eval(&state), ConstLattice::Const(16));
        let shr = PropExpr::BinOp(BinOpKind::Shr, Box::new(var_expr(0)), Box::new(var_expr(1)));
        assert_eq!(shr.eval(&state), ConstLattice::Const(1));
    }

    #[test]
    fn test_shr_preserves_sign_for_negative_operand() {
        // Regression test: right-shifting a negative constant must be an
        // arithmetic (sign-extending) shift, matching plain `i64 >> n`
        // semantics, not a logical shift over the unsigned bit pattern.
        let mut state = PropState::new();
        state.set(v(0), ConstLattice::Const(-8));
        state.set(v(1), ConstLattice::Const(1));
        let shr = PropExpr::BinOp(BinOpKind::Shr, Box::new(var_expr(0)), Box::new(var_expr(1)));
        assert_eq!(shr.eval(&state), ConstLattice::Const(-4));
    }

    #[test]
    fn test_shift_out_of_range_is_bottom() {
        let mut state = PropState::new();
        state.set(v(0), ConstLattice::Const(1));
        state.set(v(1), ConstLattice::Const(64));
        let shl = PropExpr::BinOp(BinOpKind::Shl, Box::new(var_expr(0)), Box::new(var_expr(1)));
        assert_eq!(shl.eval(&state), ConstLattice::Bottom);
        state.set(v(1), ConstLattice::Const(-1));
        let shr = PropExpr::BinOp(BinOpKind::Shr, Box::new(var_expr(0)), Box::new(var_expr(1)));
        assert_eq!(shr.eval(&state), ConstLattice::Bottom);
    }

    #[test]
    fn test_unary_not_and_abs() {
        let mut state = PropState::new();
        state.set(v(0), ConstLattice::Const(5));
        let not_expr = PropExpr::UnaryOp(UnaryOpKind::Not, Box::new(var_expr(0)));
        assert_eq!(not_expr.eval(&state), ConstLattice::Const(!5i64));
        state.set(v(0), ConstLattice::Const(-5));
        let abs_expr = PropExpr::UnaryOp(UnaryOpKind::Abs, Box::new(var_expr(0)));
        assert_eq!(abs_expr.eval(&state), ConstLattice::Const(5));
    }

    #[test]
    fn test_entry_with_back_edge_does_not_claim_loop_constant_at_entry() {
        // Regression test (found by prop_soundness randomized testing,
        // minimized): entry block with a self-loop.
        //   Block 0: v0 = 1;  succs = [0]
        // Before the fix, in[0] was computed purely as the meet of
        // predecessor out-states ({v0: Const(1)}), claiming v0 == 1 at the
        // entry of block 0 — but on the very first entry into the function
        // v0 holds an arbitrary initial value.  The entry in-state must meet
        // the function boundary (Bottom for every variable).
        let (blocks, preds) = make_blocks(vec![
            (0, vec![PropStmt::assign(v(0), lit(1))], vec![0]),
        ]);
        let prop = ConstantPropagator::new();
        let result = propagate_constants(&blocks, 0, &preds, &prop);
        assert_ne!(
            result.value_in(0, v(0)),
            ConstLattice::Const(1),
            "entry in-state must not claim a loop-carried constant"
        );
        assert!(result.constants_in(0).is_empty());
        // The exit state is still precise: v0 == 1 after the assignment.
        assert_eq!(result.value_out(0, v(0)), ConstLattice::Const(1));
    }

    #[test]
    fn test_neg_unary() {
        let (blocks, preds) = make_blocks(vec![(
            0,
            vec![
                PropStmt::assign(v(0), lit(7)),
                PropStmt::assign(
                    v(1),
                    PropExpr::UnaryOp(UnaryOpKind::Neg, Box::new(var_expr(0))),
                ),
            ],
            vec![],
        )]);
        let prop = ConstantPropagator::new();
        let result = propagate_constants(&blocks, 0, &preds, &prop);
        assert_eq!(result.value_out(0, v(1)), ConstLattice::Const(-7));
    }
}
