//! Available expressions analysis.
//!
//! An expression is *available* at program point `p` if, on every path from
//! the function entry to `p`, the expression has been computed and none of its
//! operands have been redefined since.
//!
//! Audit note (dataflow-crate iteration 5): grepped the whole workspace for
//! `rustre_analysis_dataflow::` usage — nothing outside this crate calls into
//! this module. Only its own unit tests exercise it — treat it as orphaned
//! library code until a real consumer shows up.
//!
//! This is a forward **must** analysis: the lattice join is set-intersection
//! and the initial value for non-entry blocks is the full expression universe.
//!
//! # Key types
//! - [`ExprId`]  — compact identifier for an expression.
//! - [`Expr`]    — a side-effect-free expression that can be CSE'd.
//! - [`ExprSet`] — a must-lattice (intersection on join).
//! - [`AvailableExpressions`] — the full analysis, input + result.
//! - [`compute_available`]    — top-level entry point.

use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// ExprId
// ─────────────────────────────────────────────────────────────────────────────

/// Compact, copy-friendly identifier for an expression in the universe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExprId(pub u32);

impl ExprId {
    /// Create a new expression id.
    #[must_use]
    pub const fn new(v: u32) -> Self {
        Self(v)
    }
}

impl std::fmt::Display for ExprId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "e{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VarId
// ─────────────────────────────────────────────────────────────────────────────

/// Compact, copy-friendly identifier for a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VarId(pub u32);

impl VarId {
    #[must_use]
    pub const fn new(v: u32) -> Self {
        Self(v)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprKind — structural representation of an expression
// ─────────────────────────────────────────────────────────────────────────────

/// The structural shape of an expression.
///
/// Only side-effect-free expressions that can be safely hoisted are
/// representable here.  Memory accesses are deliberately excluded because
/// their availability depends on alias information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExprKind {
    /// Binary arithmetic or logical operation.
    BinOp {
        op: BinOpKind,
        lhs: VarId,
        rhs: VarId,
    },
    /// Unary operation on a variable.
    UnaryOp { op: UnaryOpKind, operand: VarId },
    /// Cast or zero/sign-extension of a variable.
    Cast { from: VarId, width_bytes: u8 },
    /// Constant value (always available).
    Const { value: i64 },
    /// Phi-operand expression (available when entering from a specific pred).
    Phi { var: VarId, version: u32 },
}

/// Supported binary operations for expression tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinOpKind {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
}

/// Supported unary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOpKind {
    Neg,
    Not,
    Abs,
}

// ─────────────────────────────────────────────────────────────────────────────
// Expr
// ─────────────────────────────────────────────────────────────────────────────

/// A uniquely-identified, side-effect-free expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expr {
    /// Stable identifier within the expression universe.
    pub id: ExprId,
    /// Structural form of the expression.
    pub kind: ExprKind,
    /// Set of variables whose modification kills this expression.
    pub uses: HashSet<VarId>,
}

impl Expr {
    /// Create an expression and derive its `uses` set automatically.
    #[must_use]
    pub fn new(id: ExprId, kind: ExprKind) -> Self {
        let uses = uses_of(&kind);
        Self { id, kind, uses }
    }

    /// Return `true` if this expression uses `var`.
    #[must_use]
    pub fn uses_var(&self, var: VarId) -> bool {
        self.uses.contains(&var)
    }
}

impl std::hash::Hash for Expr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.kind.hash(state);
    }
}

fn uses_of(kind: &ExprKind) -> HashSet<VarId> {
    match kind {
        ExprKind::BinOp { lhs, rhs, .. } => [*lhs, *rhs].into_iter().collect(),
        ExprKind::UnaryOp { operand, .. } => std::iter::once(*operand).collect(),
        ExprKind::Cast { from, .. } => std::iter::once(*from).collect(),
        ExprKind::Const { .. } => HashSet::new(),
        ExprKind::Phi { var, .. } => std::iter::once(*var).collect(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprSet  — must-lattice (intersection)
// ─────────────────────────────────────────────────────────────────────────────

/// A set of expression ids.
///
/// The lattice ordering is ⊇ (superset is "lower" in the must-analysis
/// lattice):
/// - **Top** (initial value for non-entry blocks) = full universe.
/// - **Bottom** (boundary / join result when no info) = empty set.
/// - **Join** (at merge points) = intersection (conservatively, an expression
///   is available only if it is available on *all* paths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExprSet {
    /// The set of currently-available expression ids.
    pub available: HashSet<ExprId>,
    /// When `true` this set represents the universe (top element).
    pub is_top: bool,
}

impl ExprSet {
    /// The bottom element: empty set.
    #[must_use]
    pub fn bottom() -> Self {
        Self {
            available: HashSet::new(),
            is_top: false,
        }
    }

    /// The top element: the full universe (lazy — no ids stored).
    #[must_use]
    pub fn top() -> Self {
        Self {
            available: HashSet::new(),
            is_top: true,
        }
    }

    /// The top element initialized with a concrete universe.
    #[must_use]
    pub fn top_with(universe: impl IntoIterator<Item = ExprId>) -> Self {
        Self {
            available: universe.into_iter().collect(),
            is_top: true,
        }
    }

    /// Join (meet in the availability lattice = intersection).
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        match (self.is_top, other.is_top) {
            (true, true) => Self {
                available: self
                    .available
                    .intersection(&other.available)
                    .copied()
                    .collect(),
                is_top: true,
            },
            (true, false) => other.clone(),
            (false, true) => self.clone(),
            (false, false) => Self {
                available: self
                    .available
                    .intersection(&other.available)
                    .copied()
                    .collect(),
                is_top: false,
            },
        }
    }

    /// Return `true` if `expr` is currently available.
    #[must_use]
    pub fn contains(&self, expr: ExprId) -> bool {
        // Universe — expression is available unless the set was explicitly
        // reduced (is_top + concrete set means the set IS the universe).
        self.available.contains(&expr)
    }

    /// Kill all expressions that use `var`.
    pub fn kill_var(&mut self, var: VarId, universe: &[Expr]) {
        let to_remove: Vec<ExprId> = universe
            .iter()
            .filter(|e| e.uses_var(var) && self.available.contains(&e.id))
            .map(|e| e.id)
            .collect();
        for id in to_remove {
            self.available.remove(&id);
        }
    }

    /// Generate (add) an expression to the available set.
    pub fn add(&mut self, id: ExprId) {
        self.available.insert(id);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Statement model for this analysis
// ─────────────────────────────────────────────────────────────────────────────

/// A single statement abstracted for available-expressions analysis.
#[derive(Debug, Clone)]
pub struct AvailStmt {
    /// The expression computed (if any) and assigned to a temporary.
    pub expr_id: Option<ExprId>,
    /// The variable defined by this statement (if any).
    pub def: Option<VarId>,
    /// Variables read by this statement (for use-tracking).
    pub uses: Vec<VarId>,
}

impl AvailStmt {
    /// A statement that computes `expr` and defines `def`.
    #[must_use]
    pub const fn assign(def: VarId, expr_id: ExprId, uses: Vec<VarId>) -> Self {
        Self {
            expr_id: Some(expr_id),
            def: Some(def),
            uses,
        }
    }

    /// A statement that only reads variables (no definition, no new expression).
    #[must_use]
    pub const fn read_only(uses: Vec<VarId>) -> Self {
        Self {
            expr_id: None,
            def: None,
            uses,
        }
    }

    /// A statement that defines a variable without computing a tracked expression.
    #[must_use]
    pub const fn define(def: VarId) -> Self {
        Self {
            expr_id: None,
            def: Some(def),
            uses: vec![],
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BasicBlock model
// ─────────────────────────────────────────────────────────────────────────────

/// A basic block in the CFG for available-expressions analysis.
#[derive(Debug, Clone)]
pub struct AvailBlock {
    /// Unique block id.
    pub id: usize,
    /// Statements in program order.
    pub stmts: Vec<AvailStmt>,
    /// Successor block ids.
    pub succs: Vec<usize>,
}

// ─────────────────────────────────────────────────────────────────────────────
// AvailableExpressions  — main analysis struct
// ─────────────────────────────────────────────────────────────────────────────

/// Available expressions analysis.
///
/// Implements the classic forward must-analysis (Cooper & Torczon §9.2).
///
/// # Instantiation
/// ```
/// use rustre_analysis_dataflow::available_expressions::{
///     AvailableExpressions, Expr, ExprId, ExprKind, BinOpKind, VarId,
/// };
/// let exprs = vec![
///     Expr::new(ExprId::new(0), ExprKind::BinOp { op: BinOpKind::Add,
///         lhs: VarId::new(0), rhs: VarId::new(1) }),
/// ];
/// let ae = AvailableExpressions::new(exprs);
/// ```
#[derive(Debug, Clone)]
pub struct AvailableExpressions {
    /// The complete expression universe (all expressions that could be
    /// available anywhere in the function).
    pub universe: Vec<Expr>,
}

impl AvailableExpressions {
    /// Create a new analysis with the given expression universe.
    #[must_use]
    pub const fn new(universe: Vec<Expr>) -> Self {
        Self { universe }
    }

    /// Compute the transfer function for one block.
    ///
    /// `in_set` is the available-expression set on entry to the block.
    /// Returns the set on exit.
    #[must_use]
    pub fn transfer(&self, block: &AvailBlock, in_set: &ExprSet) -> ExprSet {
        let mut out = in_set.clone();
        for stmt in &block.stmts {
            // Kill expressions using the defined variable.
            if let Some(def) = stmt.def {
                out.kill_var(def, &self.universe);
            }
            // Gen the expression computed by this statement — but only if it
            // does not itself use the variable this same statement just
            // redefined (e.g. `v0 = v0 + v1`): once `v0` is overwritten, the
            // syntactic expression `v0 + v1` no longer denotes the value that
            // was just computed, since availability is tracked by variable
            // identity rather than SSA version. Marking it available here
            // would let a later use of the same syntactic expression be
            // wrongly treated as redundant with the pre-redefinition value.
            if let Some(expr_id) = stmt.expr_id {
                let self_referential = stmt.def.is_some_and(|def| {
                    self.universe
                        .iter()
                        .find(|e| e.id == expr_id)
                        .is_some_and(|e| e.uses_var(def))
                });
                if !self_referential {
                    out.add(expr_id);
                }
            }
        }
        out
    }

    /// The initial value for non-entry blocks (top = all expressions available).
    #[must_use]
    pub fn initial(&self) -> ExprSet {
        ExprSet::top_with(self.universe.iter().map(|e| e.id))
    }

    /// The boundary value at the function entry (bottom = nothing available).
    #[must_use]
    pub fn boundary() -> ExprSet {
        ExprSet::bottom()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AvailResult
// ─────────────────────────────────────────────────────────────────────────────

/// Per-block available-expression sets.
#[derive(Debug, Clone)]
pub struct AvailResult {
    /// Available expressions on entry to each block (indexed by block id).
    pub in_sets: Vec<ExprSet>,
    /// Available expressions on exit from each block (indexed by block id).
    pub out_sets: Vec<ExprSet>,
    /// Number of worklist iterations until convergence.
    pub iterations: usize,
}

impl AvailResult {
    /// Return the set of expressions available on entry to `block_id`.
    #[must_use]
    pub fn avail_in(&self, block_id: usize) -> Option<&ExprSet> {
        self.in_sets.get(block_id)
    }

    /// Return the set of expressions available on exit from `block_id`.
    #[must_use]
    pub fn avail_out(&self, block_id: usize) -> Option<&ExprSet> {
        self.out_sets.get(block_id)
    }

    /// Return all expression ids that are available on entry to `block_id`.
    #[must_use]
    pub fn available_at_entry(&self, block_id: usize) -> Vec<ExprId> {
        self.in_sets
            .get(block_id)
            .map(|s| {
                let mut v: Vec<ExprId> = s.available.iter().copied().collect();
                v.sort();
                v
            })
            .unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// compute_available  — entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Run the available-expressions analysis over a CFG.
///
/// # Arguments
/// - `blocks`  — basic blocks in any order (ids must be `0..n`).
/// - `entry`   — id of the entry block.
/// - `preds`   — predecessor lists for each block (`preds[i]` = predecessors
///   of block `i`).
/// - `analysis` — the configured [`AvailableExpressions`] instance.
///
/// # Returns
/// A [`AvailResult`] with per-block in/out sets.
///
/// # Complexity
/// O(n × |universe|) per iteration, O(d × n) iterations where d is the
/// loop nesting depth (typically very small).
#[must_use]
pub fn compute_available(
    blocks: &[AvailBlock],
    entry: usize,
    preds: &[Vec<usize>],
    analysis: &AvailableExpressions,
) -> AvailResult {
    let n = blocks.len();
    if n == 0 {
        return AvailResult {
            in_sets: vec![],
            out_sets: vec![],
            iterations: 0,
        };
    }

    // Initialize: entry gets bottom, all others get top.
    let mut in_sets: Vec<ExprSet> = (0..n)
        .map(|i| {
            if i == entry {
                AvailableExpressions::boundary()
            } else {
                analysis.initial()
            }
        })
        .collect();

    let mut out_sets: Vec<ExprSet> = (0..n)
        .map(|i| analysis.transfer(&blocks[i], &in_sets[i]))
        .collect();

    // Worklist: start with all blocks.
    let mut worklist: VecDeque<usize> = (0..n).collect();
    let mut in_worklist: Vec<bool> = vec![true; n];
    let mut iterations = 0usize;

    while let Some(bid) = worklist.pop_front() {
        in_worklist[bid] = false;
        iterations += 1;

        // Compute new in_set = ⋂ out[pred] for all predecessors.
        let new_in = if bid == entry {
            AvailableExpressions::boundary()
        } else {
            // `preds` may be shorter than `blocks` (caller-supplied, possibly
            // malformed) and individual predecessor indices may be
            // out-of-range; treat any such entry as "no predecessor" instead
            // of panicking.
            let block_preds: &[usize] = preds.get(bid).map_or(&[], Vec::as_slice);
            let mut valid = block_preds.iter().copied().filter(|&p| p < n);
            match valid.next() {
                None => analysis.initial(),
                Some(first) => {
                    let mut acc = out_sets[first].clone();
                    for p in valid {
                        acc = acc.join(&out_sets[p]);
                    }
                    acc
                }
            }
        };

        let new_out = analysis.transfer(&blocks[bid], &new_in);

        if new_out != out_sets[bid] {
            out_sets[bid] = new_out;
            // Re-queue successors.
            for &succ in &blocks[bid].succs {
                if succ < n && !in_worklist[succ] {
                    in_worklist[succ] = true;
                    worklist.push_back(succ);
                }
            }
        }
        in_sets[bid] = new_in;
    }

    AvailResult {
        in_sets,
        out_sets,
        iterations,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExpressionUniverse  — builder for the expression set
// ─────────────────────────────────────────────────────────────────────────────

/// Helper for incrementally building the expression universe.
#[derive(Debug, Clone, Default)]
pub struct ExpressionUniverse {
    exprs: Vec<Expr>,
    index: HashMap<ExprKind, ExprId>,
    next_id: u32,
}

impl ExpressionUniverse {
    /// Create an empty universe.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern an expression, returning its [`ExprId`].
    /// If the expression is already present, returns the existing id.
    pub fn intern(&mut self, kind: ExprKind) -> ExprId {
        if let Some(&id) = self.index.get(&kind) {
            return id;
        }
        let id = ExprId::new(self.next_id);
        self.next_id += 1;
        self.index.insert(kind.clone(), id);
        self.exprs.push(Expr::new(id, kind));
        id
    }

    /// Intern a binary-op expression.
    pub fn bin_op(&mut self, op: BinOpKind, lhs: VarId, rhs: VarId) -> ExprId {
        self.intern(ExprKind::BinOp { op, lhs, rhs })
    }

    /// Intern a unary-op expression.
    pub fn unary_op(&mut self, op: UnaryOpKind, operand: VarId) -> ExprId {
        self.intern(ExprKind::UnaryOp { op, operand })
    }

    /// Intern a constant.
    pub fn constant(&mut self, value: i64) -> ExprId {
        self.intern(ExprKind::Const { value })
    }

    /// Consume the builder and return the expression vector.
    #[must_use]
    pub fn into_exprs(self) -> Vec<Expr> {
        self.exprs
    }

    /// Number of interned expressions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.exprs.len()
    }

    /// Return `true` if no expressions have been interned.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.exprs.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CseOpportunity  — CSE candidate
// ─────────────────────────────────────────────────────────────────────────────

/// A common-subexpression elimination opportunity identified after analysis.
#[derive(Debug, Clone)]
pub struct CseOpportunity {
    /// The expression that is redundantly computed.
    pub expr_id: ExprId,
    /// The block where the redundant computation occurs.
    pub block_id: usize,
    /// The statement index within the block.
    pub stmt_index: usize,
}

/// Scan the analysis result for CSE opportunities.
///
/// A statement at `(block, stmt)` is a CSE candidate when the expression it
/// computes is available **at that statement** — not merely on entry to the
/// block.
///
/// The distinction is not pedantic. Testing every statement against the block's
/// entry set ignores kills performed by earlier statements in the same block,
/// so a recomputation whose operands were just redefined gets reported as
/// redundant; acting on it substitutes the pre-redefinition value. This is the
/// unsafe direction of wrong — over-reporting, not under-reporting.
///
/// `analysis` is required because deciding what a definition kills needs the
/// expression universe. The per-statement walk below mirrors
/// [`AvailableExpressions::transfer`], which already had it right.
#[must_use]
pub fn find_cse_opportunities(
    analysis: &AvailableExpressions,
    blocks: &[AvailBlock],
    result: &AvailResult,
) -> Vec<CseOpportunity> {
    let mut ops = Vec::new();
    for block in blocks {
        let Some(in_set) = result.avail_in(block.id) else {
            continue;
        };
        // Replay the block's own effects statement by statement so each
        // candidate is judged against the state that actually reaches it.
        let mut cur = in_set.clone();
        for (si, stmt) in block.stmts.iter().enumerate() {
            if let Some(def) = stmt.def {
                cur.kill_var(def, &analysis.universe);
            }
            if let Some(expr_id) = stmt.expr_id {
                if cur.contains(expr_id) {
                    ops.push(CseOpportunity {
                        expr_id,
                        block_id: block.id,
                        stmt_index: si,
                    });
                }
                // Gen, with the same self-reference guard as `transfer`: an
                // expression that reads the variable this statement just
                // redefined no longer denotes the value computed here.
                let self_referential = stmt.def.is_some_and(|def| {
                    analysis
                        .universe
                        .iter()
                        .find(|e| e.id == expr_id)
                        .is_some_and(|e| e.uses_var(def))
                });
                if !self_referential {
                    cur.add(expr_id);
                }
            }
        }
    }
    ops
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_blocks(
        layout: Vec<(usize, Vec<AvailStmt>, Vec<usize>)>,
    ) -> (Vec<AvailBlock>, Vec<Vec<usize>>) {
        let n = layout.len();
        let mut preds: Vec<Vec<usize>> = vec![vec![]; n];
        let blocks: Vec<AvailBlock> = layout
            .into_iter()
            .map(|(id, stmts, succs)| {
                for &s in &succs {
                    if s < n {
                        preds[s].push(id);
                    }
                }
                AvailBlock { id, stmts, succs }
            })
            .collect();
        (blocks, preds)
    }

    fn simple_universe() -> AvailableExpressions {
        let mut u = ExpressionUniverse::new();
        let v0 = VarId::new(0);
        let v1 = VarId::new(1);
        u.bin_op(BinOpKind::Add, v0, v1);
        u.bin_op(BinOpKind::Mul, v0, v1);
        AvailableExpressions::new(u.into_exprs())
    }

    #[test]
    fn test_expr_set_bottom_has_nothing() {
        let s = ExprSet::bottom();
        assert!(!s.contains(ExprId::new(0)));
    }

    #[test]
    fn test_expr_set_top_has_everything() {
        let s = ExprSet::top_with([ExprId::new(0), ExprId::new(1)]);
        assert!(s.contains(ExprId::new(0)));
        assert!(s.contains(ExprId::new(1)));
    }

    #[test]
    fn test_join_two_tops_intersects() {
        let a = ExprSet::top_with([ExprId::new(0), ExprId::new(1)]);
        let b = ExprSet::top_with([ExprId::new(1), ExprId::new(2)]);
        let j = a.join(&b);
        assert!(j.contains(ExprId::new(1)));
        assert!(!j.contains(ExprId::new(0)));
        assert!(!j.contains(ExprId::new(2)));
    }

    #[test]
    fn test_join_top_and_bottom_gives_bottom() {
        let a = ExprSet::top_with([ExprId::new(0)]);
        let b = ExprSet::bottom();
        let j = a.join(&b);
        assert!(!j.contains(ExprId::new(0)));
    }

    #[test]
    fn test_kill_var_removes_dependent_exprs() {
        let mut u = ExpressionUniverse::new();
        let v0 = VarId::new(0);
        let v1 = VarId::new(1);
        let eid = u.bin_op(BinOpKind::Add, v0, v1);
        let exprs = u.into_exprs();

        let mut s = ExprSet::top_with([eid]);
        s.kill_var(v0, &exprs);
        assert!(!s.contains(eid));
    }

    #[test]
    fn test_linear_chain_propagation() {
        // 0 → 1 → 2
        // Block 0 computes e0 = v0 + v1
        // Block 1 computes e0 again (CSE opportunity)
        let mut u = ExpressionUniverse::new();
        let v0 = VarId::new(0);
        let v1 = VarId::new(1);
        let e0 = u.bin_op(BinOpKind::Add, v0, v1);
        let analysis = AvailableExpressions::new(u.into_exprs());

        let (blocks, preds) = make_blocks(vec![
            (
                0,
                vec![AvailStmt::assign(VarId::new(2), e0, vec![v0, v1])],
                vec![1],
            ),
            (
                1,
                vec![AvailStmt::assign(VarId::new(3), e0, vec![v0, v1])],
                vec![2],
            ),
            (2, vec![], vec![]),
        ]);

        let result = compute_available(&blocks, 0, &preds, &analysis);
        // e0 should be available on entry to block 1 (computed in block 0).
        let avail_in_1 = result.avail_in(1).unwrap();
        assert!(avail_in_1.contains(e0), "e0 should be available at block 1");
    }

    #[test]
    fn test_kill_propagation() {
        // 0 computes e0 = v0 + v1, then 1 kills v0, then 2 checks.
        let mut u = ExpressionUniverse::new();
        let v0 = VarId::new(0);
        let v1 = VarId::new(1);
        let e0 = u.bin_op(BinOpKind::Add, v0, v1);
        let analysis = AvailableExpressions::new(u.into_exprs());

        let (blocks, preds) = make_blocks(vec![
            (0, vec![AvailStmt::assign(VarId::new(2), e0, vec![v0, v1])], vec![1]),
            (1, vec![AvailStmt::define(v0)], vec![2]),
            (2, vec![], vec![]),
        ]);

        let result = compute_available(&blocks, 0, &preds, &analysis);
        // After block 1 kills v0, e0 must not be available at block 2.
        let avail_in_2 = result.avail_in(2).unwrap();
        assert!(!avail_in_2.contains(e0), "e0 killed after v0 redefined");
    }

    #[test]
    fn test_diamond_intersection() {
        // Entry(0) → {1,2} → 3
        // Block 1 computes e0, block 2 does not → e0 not available at 3.
        let mut u = ExpressionUniverse::new();
        let v0 = VarId::new(0);
        let v1 = VarId::new(1);
        let e0 = u.bin_op(BinOpKind::Add, v0, v1);
        let analysis = AvailableExpressions::new(u.into_exprs());

        let (blocks, preds) = make_blocks(vec![
            (0, vec![], vec![1, 2]),
            (1, vec![AvailStmt::assign(VarId::new(2), e0, vec![v0, v1])], vec![3]),
            (2, vec![], vec![3]),
            (3, vec![], vec![]),
        ]);

        let result = compute_available(&blocks, 0, &preds, &analysis);
        // e0 is not available on all paths to block 3 (path through block 2 lacks it).
        let avail_in_3 = result.avail_in(3).unwrap();
        assert!(!avail_in_3.contains(e0), "e0 not on all paths to block 3");
    }

    #[test]
    fn test_cse_opportunity_detection() {
        let mut u = ExpressionUniverse::new();
        let v0 = VarId::new(0);
        let v1 = VarId::new(1);
        let e0 = u.bin_op(BinOpKind::Add, v0, v1);
        let analysis = AvailableExpressions::new(u.into_exprs());

        let (blocks, preds) = make_blocks(vec![
            (0, vec![AvailStmt::assign(VarId::new(2), e0, vec![v0, v1])], vec![1]),
            (1, vec![AvailStmt::assign(VarId::new(3), e0, vec![v0, v1])], vec![]),
        ]);

        let result = compute_available(&blocks, 0, &preds, &analysis);
        let opps = find_cse_opportunities(&analysis, &blocks, &result);
        assert!(!opps.is_empty(), "expect CSE opportunity in block 1");
        assert_eq!(opps[0].block_id, 1);
        assert_eq!(opps[0].expr_id, e0);
    }

    #[test]
    fn test_expression_universe_intern() {
        let mut u = ExpressionUniverse::new();
        let v0 = VarId::new(0);
        let v1 = VarId::new(1);
        let e1 = u.bin_op(BinOpKind::Add, v0, v1);
        let e2 = u.bin_op(BinOpKind::Add, v0, v1);
        // Same expression should be interned to the same id.
        assert_eq!(e1, e2);
        assert_eq!(u.len(), 1);
    }

    #[test]
    fn test_empty_cfg() {
        let analysis = simple_universe();
        let result = compute_available(&[], 0, &[], &analysis);
        assert_eq!(result.iterations, 0);
        assert!(result.in_sets.is_empty());
    }

    #[test]
    fn test_iterations_count() {
        let mut u = ExpressionUniverse::new();
        let v0 = VarId::new(0);
        let v1 = VarId::new(1);
        u.bin_op(BinOpKind::Add, v0, v1);
        let analysis = AvailableExpressions::new(u.into_exprs());
        let (blocks, preds) = make_blocks(vec![(0, vec![], vec![])]);
        let result = compute_available(&blocks, 0, &preds, &analysis);
        assert!(result.iterations > 0);
    }

    #[test]
    fn test_malformed_preds_shorter_than_blocks_does_not_panic() {
        // `preds` has fewer entries than `blocks` — must be treated as "no
        // predecessors" for the missing tail, not panic on index-out-of-bounds.
        let analysis = simple_universe();
        let blocks = vec![
            AvailBlock { id: 0, stmts: vec![], succs: vec![1] },
            AvailBlock { id: 1, stmts: vec![], succs: vec![] },
        ];
        let preds: Vec<Vec<usize>> = vec![vec![]]; // missing entry for block 1
        let result = compute_available(&blocks, 0, &preds, &analysis);
        assert_eq!(result.in_sets.len(), 2);
    }

    #[test]
    fn test_self_referential_def_does_not_stay_available() {
        // Statement `v0 = v0 + v1` computes e0 = v0+v1 using the OLD v0, then
        // redefines v0. Afterward, "v0+v1" as a syntactic expression means
        // (new v0)+v1, a different value — so e0 must NOT be considered
        // available after this statement, even though the statement itself
        // both uses and defines v0 and "generates" e0.
        let mut u = ExpressionUniverse::new();
        let v0 = VarId::new(0);
        let v1 = VarId::new(1);
        let e0 = u.bin_op(BinOpKind::Add, v0, v1);
        let analysis = AvailableExpressions::new(u.into_exprs());

        let block = AvailBlock {
            id: 0,
            // def == v0, which is also a use of the generated expression.
            stmts: vec![AvailStmt::assign(v0, e0, vec![v0, v1])],
            succs: vec![],
        };
        let in_set = ExprSet::bottom();
        let out = analysis.transfer(&block, &in_set);
        assert!(
            !out.contains(e0),
            "e0 uses v0, which this same statement redefines; it must be killed, not left available"
        );
    }

    #[test]
    fn test_transfer_direct_gen_and_kill() {
        // Direct unit test of `transfer` (previously only exercised through
        // `compute_available`).
        let mut u = ExpressionUniverse::new();
        let v0 = VarId::new(0);
        let v1 = VarId::new(1);
        let v2 = VarId::new(2);
        let e0 = u.bin_op(BinOpKind::Add, v0, v1);
        let analysis = AvailableExpressions::new(u.into_exprs());

        let block = AvailBlock {
            id: 0,
            stmts: vec![AvailStmt::assign(v2, e0, vec![v0, v1])],
            succs: vec![],
        };
        let out = analysis.transfer(&block, &ExprSet::bottom());
        assert!(out.contains(e0));
    }

    #[test]
    fn test_avail_out_and_available_at_entry() {
        let mut u = ExpressionUniverse::new();
        let v0 = VarId::new(0);
        let v1 = VarId::new(1);
        let e0 = u.bin_op(BinOpKind::Add, v0, v1);
        let analysis = AvailableExpressions::new(u.into_exprs());

        let (blocks, preds) = make_blocks(vec![
            (0, vec![AvailStmt::assign(VarId::new(2), e0, vec![v0, v1])], vec![1]),
            (1, vec![], vec![]),
        ]);

        let result = compute_available(&blocks, 0, &preds, &analysis);
        let out0 = result.avail_out(0).unwrap();
        assert!(out0.contains(e0));
        assert_eq!(result.available_at_entry(1), vec![e0]);
        assert!(result.avail_out(99).is_none());
    }

    #[test]
    fn test_expr_uses_var_and_read_only_stmt() {
        let mut u = ExpressionUniverse::new();
        let v0 = VarId::new(0);
        let v1 = VarId::new(1);
        let _e0 = u.bin_op(BinOpKind::Add, v0, v1);
        let exprs = u.into_exprs();
        assert!(exprs[0].uses_var(v0));
        assert!(!exprs[0].uses_var(VarId::new(2)));

        let stmt = AvailStmt::read_only(vec![v0, v1]);
        assert!(stmt.def.is_none());
        assert!(stmt.expr_id.is_none());
        assert_eq!(stmt.uses, vec![v0, v1]);
    }

    #[test]
    fn test_expression_universe_unary_and_constant() {
        let mut u = ExpressionUniverse::new();
        assert!(u.is_empty());
        let e_neg = u.unary_op(UnaryOpKind::Neg, VarId::new(0));
        let e_c = u.constant(42);
        assert_ne!(e_neg, e_c);
        assert_eq!(u.len(), 2);
        assert!(!u.is_empty());
    }

    #[test]
    fn test_expr_id_display() {
        assert_eq!(ExprId::new(7).to_string(), "e7");
    }

    #[test]
    fn test_malformed_preds_out_of_range_index_does_not_panic() {
        // A predecessor index that is out of range for `blocks` must be
        // ignored rather than causing an out-of-bounds panic.
        let analysis = simple_universe();
        let blocks = vec![AvailBlock { id: 0, stmts: vec![], succs: vec![] }];
        let preds: Vec<Vec<usize>> = vec![vec![42]];
        let result = compute_available(&blocks, 0, &preds, &analysis);
        assert_eq!(result.in_sets.len(), 1);
    }
}
