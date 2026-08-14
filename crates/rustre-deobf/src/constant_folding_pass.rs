//! Constant-folding deobfuscation pass for the `RustRE` Suite.
//!
//! Implements a full IR-level constant-folding pass that operates on an in-memory
//! representation of a function's basic blocks.  The pass repeatedly rewrites
//! any binary or unary expression whose operands are all known constants until
//! no more rewrites are possible (fixed-point iteration).
//!
//! # Architecture
//!
//! ```text
//! FoldableExpr  — pure value expression tree
//!     │
//!     ├── Const(i64)
//!     ├── BinOp { op, lhs, rhs }
//!     └── UnOp  { op, operand }
//!
//! FoldResult — outcome of a single fold attempt
//!
//! ConstantFoldingPass::fold_function(blocks)
//!     └── fold_block → fold_expr (recursive, post-order)
//! ```

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{DeobfContext, DeobfError, DeobfPass, DeobfResult};

// ─────────────────────────────────────────────────────────────────────────────
// Binary and Unary operators
// ─────────────────────────────────────────────────────────────────────────────

/// Binary arithmetic / bitwise / comparison operators supported by the fold pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinOp {
    /// Integer addition.
    Add,
    /// Integer subtraction.
    Sub,
    /// Integer multiplication.
    Mul,
    /// Signed integer division (panics on divide-by-zero; check before folding).
    Div,
    /// Signed integer remainder.
    Rem,
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Logical shift left.
    Shl,
    /// Logical shift right.
    Shr,
    /// Arithmetic shift right (sign-extending).
    Asr,
    /// Equality comparison (yields 0 or 1).
    Eq,
    /// Inequality comparison.
    Ne,
    /// Signed less-than.
    Lt,
    /// Signed less-than-or-equal.
    Le,
    /// Signed greater-than.
    Gt,
    /// Signed greater-than-or-equal.
    Ge,
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Rem => "%",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
            Self::Shl => "<<",
            Self::Shr => ">>",
            Self::Asr => ">>>",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
        };
        write!(f, "{s}")
    }
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnOp {
    /// Arithmetic negation.
    Neg,
    /// Bitwise NOT.
    Not,
    /// Zero-extend to 8-bit (mask with 0xFF).
    ZextByte,
    /// Zero-extend to 16-bit (mask with 0xFFFF).
    ZextWord,
    /// Zero-extend to 32-bit (mask with `0xFFFF_FFFF`).
    ZextDword,
    /// Sign-extend from 8-bit.
    SextByte,
    /// Sign-extend from 16-bit.
    SextWord,
    /// Sign-extend from 32-bit.
    SextDword,
}

impl fmt::Display for UnOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Neg => "neg",
            Self::Not => "not",
            Self::ZextByte => "zext8",
            Self::ZextWord => "zext16",
            Self::ZextDword => "zext32",
            Self::SextByte => "sext8",
            Self::SextWord => "sext16",
            Self::SextDword => "sext32",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FoldableExpr
// ─────────────────────────────────────────────────────────────────────────────

/// A foldable value expression in the IR.
///
/// The tree is deliberately simple: only pure, side-effect-free nodes are
/// included so that the pass can freely re-order or eliminate them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FoldableExpr {
    /// A compile-time constant.
    Const(i64),
    /// An SSA variable reference whose value may or may not be known.
    Var(String),
    /// A binary operation on two sub-expressions.
    BinOp {
        /// The operator.
        op: BinOp,
        /// Left-hand operand.
        lhs: Box<Self>,
        /// Right-hand operand.
        rhs: Box<Self>,
    },
    /// A unary operation on a sub-expression.
    UnOp {
        /// The operator.
        op: UnOp,
        /// Operand.
        operand: Box<Self>,
    },
    /// A conditional select: `if cond != 0 { then_val } else { else_val }`.
    Select {
        /// Condition expression.
        cond: Box<Self>,
        /// Value when condition is non-zero.
        then_val: Box<Self>,
        /// Value when condition is zero.
        else_val: Box<Self>,
    },
}

impl FoldableExpr {
    /// Return `true` when this expression is a compile-time constant.
    #[must_use]
    pub const fn is_const(&self) -> bool {
        matches!(self, Self::Const(_))
    }

    /// If this expression is a constant, return its value.
    #[must_use]
    pub const fn as_const(&self) -> Option<i64> {
        match self {
            Self::Const(v) => Some(*v),
            _ => None,
        }
    }

    /// Compute the depth of the expression tree.
    #[must_use]
    pub fn depth(&self) -> usize {
        match self {
            Self::Const(_) | Self::Var(_) => 0,
            Self::UnOp { operand, .. } => 1 + operand.depth(),
            Self::BinOp { lhs, rhs, .. } => 1 + lhs.depth().max(rhs.depth()),
            Self::Select {
                cond,
                then_val,
                else_val,
                ..
            } => 1 + cond.depth().max(then_val.depth()).max(else_val.depth()),
        }
    }

    /// Count the total number of nodes in this expression tree.
    #[must_use]
    pub fn node_count(&self) -> usize {
        match self {
            Self::Const(_) | Self::Var(_) => 1,
            Self::UnOp { operand, .. } => 1 + operand.node_count(),
            Self::BinOp { lhs, rhs, .. } => 1 + lhs.node_count() + rhs.node_count(),
            Self::Select {
                cond,
                then_val,
                else_val,
                ..
            } => 1 + cond.node_count() + then_val.node_count() + else_val.node_count(),
        }
    }
}

impl fmt::Display for FoldableExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(v) => write!(f, "{v:#x}"),
            Self::Var(name) => write!(f, "${name}"),
            Self::BinOp { op, lhs, rhs } => write!(f, "({lhs} {op} {rhs})"),
            Self::UnOp { op, operand } => write!(f, "{op}({operand})"),
            Self::Select {
                cond,
                then_val,
                else_val,
            } => write!(f, "({cond} ? {then_val} : {else_val})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FoldResult
// ─────────────────────────────────────────────────────────────────────────────

/// The outcome of a single constant-fold attempt on a [`FoldableExpr`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldResult {
    /// The expression was folded to a constant.
    Folded(i64),
    /// The expression could not be folded (not all operands are known).
    NotFoldable,
    /// A divide-by-zero or shift-overflow was detected; the expression is
    /// replaced with a sentinel constant (0) to prevent crashes.
    DivisionByZero,
    /// An overflow was detected during shift; the result is 0.
    ShiftOverflow,
    /// An algebraic identity simplified the expression to one of its operands
    /// (e.g. `x + 0` → `x`). The exact operand is not retained here; consumers
    /// that want to rewrite the IR should re-inspect the original `BinOp`.
    IdentityPassthrough,
}

impl FoldResult {
    /// Returns true if a non-trivial simplification occurred (a constant fold,
    /// a sentinel substitution, or an algebraic identity).
    #[must_use] 
    pub const fn is_simplified(&self) -> bool {
        !matches!(self, Self::NotFoldable)
    }

    /// If this is a concrete folded constant, return it.
    #[must_use] 
    pub const fn as_constant(&self) -> Option<i64> {
        match self {
            Self::Folded(v) => Some(*v),
            Self::DivisionByZero | Self::ShiftOverflow => Some(0),
            _ => None,
        }
    }
}

impl FoldResult {
    /// Return `true` if the expression was successfully folded.
    #[must_use]
    pub const fn is_folded(&self) -> bool {
        matches!(self, Self::Folded(_))
    }

    /// Return the folded constant value, if any.
    #[must_use]
    pub const fn value(&self) -> Option<i64> {
        match self {
            Self::Folded(v) => Some(*v),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core folding logic
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluate a single binary operation on two known constant values.
///
/// Returns `None` if the operation is undefined (e.g. division by zero).
#[must_use]
pub fn eval_binop(op: BinOp, lhs: i64, rhs: i64) -> Option<i64> {
    match op {
        BinOp::Add => Some(lhs.wrapping_add(rhs)),
        BinOp::Sub => Some(lhs.wrapping_sub(rhs)),
        BinOp::Mul => Some(lhs.wrapping_mul(rhs)),
        BinOp::Div => {
            if rhs == 0 {
                None
            } else {
                Some(lhs.wrapping_div(rhs))
            }
        }
        BinOp::Rem => {
            if rhs == 0 {
                None
            } else {
                Some(lhs.wrapping_rem(rhs))
            }
        }
        BinOp::And => Some(lhs & rhs),
        BinOp::Or => Some(lhs | rhs),
        BinOp::Xor => Some(lhs ^ rhs),
        BinOp::Shl => {
            if (0..64).contains(&rhs) {
                let shift = u32::try_from(rhs).unwrap_or(0);
                Some(lhs.wrapping_shl(shift))
            } else {
                None
            }
        }
        BinOp::Shr => {
            if (0..64).contains(&rhs) {
                let shift = u32::try_from(rhs).unwrap_or(0);
                Some(lhs.cast_unsigned().wrapping_shr(shift).cast_signed())
            } else {
                None
            }
        }
        BinOp::Asr => {
            if (0..64).contains(&rhs) {
                let shift = u32::try_from(rhs).unwrap_or(0);
                Some(lhs.wrapping_shr(shift))
            } else {
                None
            }
        }
        BinOp::Eq => Some(i64::from(lhs == rhs)),
        BinOp::Ne => Some(i64::from(lhs != rhs)),
        BinOp::Lt => Some(i64::from(lhs < rhs)),
        BinOp::Le => Some(i64::from(lhs <= rhs)),
        BinOp::Gt => Some(i64::from(lhs > rhs)),
        BinOp::Ge => Some(i64::from(lhs >= rhs)),
    }
}

/// Evaluate a single unary operation on a known constant.
#[must_use]
pub fn eval_unop(op: UnOp, val: i64) -> i64 {
    match op {
        UnOp::Neg => val.wrapping_neg(),
        UnOp::Not => !val,
        UnOp::ZextByte => val & 0xFF,
        UnOp::ZextWord => val & 0xFFFF,
        UnOp::ZextDword => val & 0xFFFF_FFFF,
        UnOp::SextByte => {
            let b = val.to_ne_bytes();
            i64::from(i8::from_ne_bytes([b[0]]))
        }
        UnOp::SextWord => {
            let b = val.to_ne_bytes();
            i64::from(i16::from_ne_bytes([b[0], b[1]]))
        }
        UnOp::SextDword => {
            let b = val.to_ne_bytes();
            i64::from(i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
        }
    }
}

/// Maximum expression-tree depth allowed before we bail out to avoid
/// a stack overflow on adversarially deep deserialized expressions.
const MAX_FOLD_DEPTH: usize = 512;

/// Attempt to fold `expr` to a constant given the variable environment `env`.
///
/// The function recurses in post-order: leaf nodes are evaluated first, then
/// their parents.  If any sub-expression is not constant, the enclosing binary
/// or unary operation cannot be folded.
#[must_use]
pub fn fold_expr<S: ::std::hash::BuildHasher>(expr: &FoldableExpr, env: &HashMap<String, i64, S>) -> FoldResult {
    fold_expr_depth(expr, env, 0)
}

fn fold_expr_depth<S: ::std::hash::BuildHasher>(expr: &FoldableExpr, env: &HashMap<String, i64, S>, depth: usize) -> FoldResult {
    if depth > MAX_FOLD_DEPTH {
        return FoldResult::NotFoldable;
    }
    fold_expr_inner(expr, env, depth)
}

fn fold_expr_inner<S: ::std::hash::BuildHasher>(expr: &FoldableExpr, env: &HashMap<String, i64, S>, depth: usize) -> FoldResult {
    match expr {
        FoldableExpr::Const(v) => FoldResult::Folded(*v),
        FoldableExpr::Var(name) => {
            if let Some(&v) = env.get(name.as_str()) {
                FoldResult::Folded(v)
            } else {
                FoldResult::NotFoldable
            }
        }
        FoldableExpr::UnOp { op, operand } => {
            match fold_expr_depth(operand, env, depth + 1) {
                FoldResult::Folded(v) => FoldResult::Folded(eval_unop(*op, v)),
                other => other,
            }
        }
        FoldableExpr::BinOp { op, lhs, rhs } => {
            let lv = fold_expr_depth(lhs, env, depth + 1);
            let rv = fold_expr_depth(rhs, env, depth + 1);
            match (lv, rv) {
                (FoldResult::Folded(l), FoldResult::Folded(r)) => {
                    eval_binop(*op, l, r).map_or_else(
                        || match op {
                            BinOp::Div | BinOp::Rem => FoldResult::DivisionByZero,
                            BinOp::Shl | BinOp::Shr | BinOp::Asr => FoldResult::ShiftOverflow,
                            _ => FoldResult::NotFoldable,
                        },
                        FoldResult::Folded,
                    )
                }
                // Algebraic identities that apply even with unknown operands:
                // x * 0 = 0, x & 0 = 0, x ^ x = 0 (if both sides are same var)
                (FoldResult::Folded(0), _) if matches!(op, BinOp::Mul | BinOp::And) => {
                    FoldResult::Folded(0)
                }
                (_, FoldResult::Folded(0)) if matches!(op, BinOp::Mul | BinOp::And) => {
                    FoldResult::Folded(0)
                }
                // x + 0 = x, x - 0 = x, x | 0 = x, x ^ 0 = x  (rhs is known zero, lhs unknown)
                (FoldResult::NotFoldable, FoldResult::Folded(0))
                    if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Or | BinOp::Xor) =>
                {
                    FoldResult::IdentityPassthrough
                }
                // 0 + x = x, 0 | x = x (lhs is known zero, rhs unknown)
                (FoldResult::Folded(0), FoldResult::NotFoldable)
                    if matches!(op, BinOp::Add | BinOp::Or) =>
                {
                    FoldResult::IdentityPassthrough
                }
                _ => FoldResult::NotFoldable,
            }
        }
        FoldableExpr::Select {
            cond,
            then_val,
            else_val,
        } => {
            match fold_expr_depth(cond, env, depth + 1) {
                FoldResult::Folded(0) => fold_expr_depth(else_val, env, depth + 1),
                FoldResult::Folded(_) => fold_expr_depth(then_val, env, depth + 1),
                _ => {
                    // Even if the condition is unknown, if both branches are
                    // equal constants we can fold.
                    let tv = fold_expr_depth(then_val, env, depth + 1);
                    let ev = fold_expr_depth(else_val, env, depth + 1);
                    if tv == ev {
                        tv
                    } else {
                        FoldResult::NotFoldable
                    }
                }
            }
        }
    }
}

/// Replace all foldable sub-expressions in `expr` with their constant values,
/// returning a new expression tree (possibly with fewer nodes).
///
/// This performs a bottom-up rewrite: after each node's children are rewritten,
/// an attempt is made to fold the node itself.
#[must_use]
pub fn rewrite_expr<S: ::std::hash::BuildHasher>(expr: FoldableExpr, env: &HashMap<String, i64, S>) -> FoldableExpr {
    match expr {
        FoldableExpr::Const(_) | FoldableExpr::Var(_) => {
            // Leaf: try substituting from env.
            match fold_expr(&expr, env) {
                FoldResult::Folded(v) => FoldableExpr::Const(v),
                _ => expr,
            }
        }
        FoldableExpr::UnOp { op, operand } => {
            let rewritten_op = rewrite_expr(*operand, env);
            let node = FoldableExpr::UnOp {
                op,
                operand: Box::new(rewritten_op),
            };
            match fold_expr(&node, env) {
                FoldResult::Folded(v) => FoldableExpr::Const(v),
                _ => node,
            }
        }
        FoldableExpr::BinOp { op, lhs, rhs } => {
            let rl = rewrite_expr(*lhs, env);
            let rr = rewrite_expr(*rhs, env);
            let node = FoldableExpr::BinOp {
                op,
                lhs: Box::new(rl),
                rhs: Box::new(rr),
            };
            match fold_expr(&node, env) {
                FoldResult::Folded(v) => FoldableExpr::Const(v),
                _ => node,
            }
        }
        FoldableExpr::Select {
            cond,
            then_val,
            else_val,
        } => {
            let rc = rewrite_expr(*cond, env);
            let rt = rewrite_expr(*then_val, env);
            let re = rewrite_expr(*else_val, env);
            let node = FoldableExpr::Select {
                cond: Box::new(rc),
                then_val: Box::new(rt),
                else_val: Box::new(re),
            };
            match fold_expr(&node, env) {
                FoldResult::Folded(v) => FoldableExpr::Const(v),
                _ => node,
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IR data structures for functions and basic blocks
// ─────────────────────────────────────────────────────────────────────────────

/// A single IR assignment statement: `var = expr`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrAssign {
    /// The SSA variable being defined.
    pub target: String,
    /// The value expression.
    pub expr: FoldableExpr,
}

/// A single IR basic block: a sequence of assignments followed by a
/// fall-through or branch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IrBlock {
    /// Block label (e.g. `"bb0"`, `"loop_body"`).
    pub label: String,
    /// Ordered sequence of assignments.
    pub stmts: Vec<IrAssign>,
}

impl IrBlock {
    /// Create an empty block with the given label.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            stmts: Vec::new(),
        }
    }

    /// Append an assignment.
    pub fn push(&mut self, target: impl Into<String>, expr: FoldableExpr) {
        self.stmts.push(IrAssign {
            target: target.into(),
            expr,
        });
    }

    /// Count assignments.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.stmts.len()
    }

    /// Whether the block has no statements.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.stmts.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstantFoldingPass
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics collected during one run of [`ConstantFoldingPass::fold_function`].
#[derive(Debug, Clone, Default)]
pub struct FoldStats {
    /// Number of expressions folded in total.
    pub exprs_folded: usize,
    /// Number of fixed-point iterations performed.
    pub iterations: usize,
    /// Number of division-by-zero events suppressed.
    pub div_zeros: usize,
    /// Number of shift-overflow events suppressed.
    pub shift_overflows: usize,
    /// Number of algebraic-identity simplifications (e.g. `x + 0` → `x`).
    pub identity_passthroughs: usize,
}

/// Constant-folding pass over a function's IR blocks.
///
/// The pass maintains a *constant environment* mapping variable names to their
/// known constant values.  It iterates over all blocks and statements in order:
///
/// 1. For each assignment `v = expr`, try to fold `expr`.
/// 2. If `expr` folded to a constant, add `v → constant` to the environment.
/// 3. Rewrite `expr` in-place with its simplified form.
/// 4. Repeat until no more expressions can be folded (fixed-point).
///
/// This intentionally does *not* model control flow — it is a purely
/// intra-block, forward dataflow analysis.  That is sufficient for a large
/// fraction of obfuscated constant arithmetic.
#[derive(Debug, Clone)]
pub struct ConstantFoldingPass {
    /// Maximum number of fixed-point iterations before giving up.
    pub max_iterations: usize,
    /// Pre-populated constant values (e.g. from prior passes or the user).
    pub seed_env: HashMap<String, i64>,
}

impl Default for ConstantFoldingPass {
    fn default() -> Self {
        Self {
            max_iterations: 64,
            seed_env: HashMap::new(),
        }
    }
}

impl ConstantFoldingPass {
    /// Create a new pass with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a pass with a pre-populated constant environment.
    #[must_use]
    pub fn with_seeds(seeds: HashMap<String, i64>) -> Self {
        Self {
            seed_env: seeds,
            ..Self::default()
        }
    }

    /// Set the maximum number of fixed-point iterations.
    #[must_use]
    pub const fn with_max_iterations(mut self, n: usize) -> Self {
        self.max_iterations = n;
        self
    }

    /// Run constant folding over a mutable slice of [`IrBlock`]s.
    ///
    /// Returns [`FoldStats`] describing what was done.  The blocks are modified
    /// in-place.
    pub fn fold_function(&self, blocks: &mut [IrBlock]) -> FoldStats {
        let mut stats = FoldStats::default();
        let mut env: HashMap<String, i64> = self.seed_env.clone();

        for _iter in 0..self.max_iterations {
            let mut changed = false;
            stats.iterations += 1;

            for block in blocks.iter_mut() {
                for stmt in stmt_iter_mut(&mut block.stmts) {
                    // Try folding the current expression.
                    let result = fold_expr(&stmt.expr, &env);
                    match &result {
                        FoldResult::Folded(v) => {
                            if stmt.expr == FoldableExpr::Const(*v) {
                                // Already a const; still record in env.
                                env.insert(stmt.target.clone(), *v);
                            } else {
                                stmt.expr = FoldableExpr::Const(*v);
                                env.insert(stmt.target.clone(), *v);
                                stats.exprs_folded += 1;
                                changed = true;
                            }
                        }
                        FoldResult::DivisionByZero => {
                            stats.div_zeros += 1;
                            stmt.expr = FoldableExpr::Const(0);
                            env.insert(stmt.target.clone(), 0);
                            changed = true;
                        }
                        FoldResult::ShiftOverflow => {
                            stats.shift_overflows += 1;
                            stmt.expr = FoldableExpr::Const(0);
                            env.insert(stmt.target.clone(), 0);
                            changed = true;
                        }
                        FoldResult::NotFoldable => {
                            // Rewrite sub-expressions that can be folded.
                            let new_expr = rewrite_expr(stmt.expr.clone(), &env);
                            if new_expr != stmt.expr {
                                stmt.expr = new_expr;
                                changed = true;
                                stats.exprs_folded += 1;
                            }
                        }
                        FoldResult::IdentityPassthrough => {
                            // An algebraic identity (e.g. `x + 0`) reduces the
                            // expression to one of its operands. Rewrite the
                            // sub-expression to drop the no-op binop.
                            let new_expr = rewrite_expr(stmt.expr.clone(), &env);
                            if new_expr != stmt.expr {
                                stmt.expr = new_expr;
                                changed = true;
                            }
                            stats.identity_passthroughs += 1;
                        }
                    }
                }
            }

            if !changed {
                break;
            }
        }

        stats
    }
}

/// Helper that returns a mutable iterator over assignments in a block.
fn stmt_iter_mut(stmts: &mut [IrAssign]) -> impl Iterator<Item = &mut IrAssign> {
    stmts.iter_mut()
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfPass integration
// ─────────────────────────────────────────────────────────────────────────────

/// Lightweight binary-level [`DeobfPass`] wrapper for `ConstantFoldingPass`.
///
/// Operates on the structured binary rather than an IR; scans for the
/// 9-byte opcode-operand-operand encoding used by the rest of `rustre-deobf`
/// and folds trivial arithmetic at the byte level.
#[derive(Debug, Clone, Default)]
pub struct BinaryConstantFoldPass;

impl BinaryConstantFoldPass {
    /// Create a new pass instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl DeobfPass for BinaryConstantFoldPass {
    fn name(&self) -> &'static str {
        "binary-constant-fold"
    }

    fn description(&self) -> &'static str {
        "Scan binary for trivially constant arithmetic expressions and evaluate them in-place"
    }

    fn is_applicable(&self, ctx: &DeobfContext) -> bool {
        ctx.binary.len() >= 9
    }

    fn run(&self, ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
        let data = &ctx.binary;
        let mut patches = Vec::new();
        let mut i = 0;
        while i + 8 < data.len() {
            let op = data[i];
            let a = u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
            let b = u32::from_le_bytes([data[i + 5], data[i + 6], data[i + 7], data[i + 8]]);
            let result: Option<u32> = match op {
                0x01 => Some(a.wrapping_add(b)),
                0x02 => Some(a.wrapping_sub(b)),
                0x03 => Some(a & b),
                0x04 => Some(a | b),
                0x05 => Some(a ^ b),
                0x06 => Some(a.wrapping_mul(b)),
                0x07 => {
                    if b != 0 {
                        Some(a.wrapping_div(b))
                    } else {
                        Some(0) // div-by-zero → 0
                    }
                }
                _ => None,
            };
            if let Some(r) = result {
                let original = data[i..i + 9].to_vec();
                let mut replacement = vec![0u8; 9];
                replacement[0] = 0x01; // ADD identity
                replacement[1..5].copy_from_slice(&r.to_le_bytes());
                patches.push(crate::Patch::new(
                    i,
                    original,
                    replacement,
                    format!("const-fold op={op:#04x} {a:#010x} {b:#010x} = {r:#010x}"),
                ));
                i += 9;
            } else {
                i += 1;
            }
        }
        let count = patches.len();
        let modified = patches.iter().map(|p| p.patched.len()).sum();
        let transformations: Vec<String> = patches.iter().map(|p| p.reason.clone()).collect();
        ctx.patches.extend(patches);
        Ok(DeobfResult::new(count, transformations, modified, 0.95))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn c(v: i64) -> FoldableExpr {
        FoldableExpr::Const(v)
    }

    fn var(name: &str) -> FoldableExpr {
        FoldableExpr::Var(name.to_string())
    }

    fn binop(op: BinOp, l: FoldableExpr, r: FoldableExpr) -> FoldableExpr {
        FoldableExpr::BinOp {
            op,
            lhs: Box::new(l),
            rhs: Box::new(r),
        }
    }

    fn unop(op: UnOp, v: FoldableExpr) -> FoldableExpr {
        FoldableExpr::UnOp {
            op,
            operand: Box::new(v),
        }
    }

    #[test]
    fn test_fold_const_add() {
        let expr = binop(BinOp::Add, c(3), c(4));
        assert_eq!(fold_expr(&expr, &HashMap::new()), FoldResult::Folded(7));
    }

    #[test]
    fn test_fold_const_mul() {
        let expr = binop(BinOp::Mul, c(6), c(7));
        assert_eq!(fold_expr(&expr, &HashMap::new()), FoldResult::Folded(42));
    }

    #[test]
    fn test_fold_div_by_zero() {
        let expr = binop(BinOp::Div, c(10), c(0));
        assert_eq!(fold_expr(&expr, &HashMap::new()), FoldResult::DivisionByZero);
    }

    #[test]
    fn test_fold_shift_overflow() {
        let expr = binop(BinOp::Shl, c(1), c(100));
        assert_eq!(fold_expr(&expr, &HashMap::new()), FoldResult::ShiftOverflow);
    }

    #[test]
    fn test_fold_shr_logical_negative() {
        // Logical right shift (Shr) treats the operand as unsigned: shifting
        // -1 (all-ones bit pattern) right by 1 must zero-extend the top bit,
        // yielding i64::MAX rather than -1.
        let expr = binop(BinOp::Shr, c(-1), c(1));
        assert_eq!(
            fold_expr(&expr, &HashMap::new()),
            FoldResult::Folded(i64::MAX)
        );
    }

    #[test]
    fn test_fold_asr_arithmetic_negative() {
        // Arithmetic right shift (Asr) sign-extends: shifting -1 right by any
        // amount in range preserves the sign and stays -1.
        let expr = binop(BinOp::Asr, c(-1), c(1));
        assert_eq!(fold_expr(&expr, &HashMap::new()), FoldResult::Folded(-1));
    }

    #[test]
    fn test_fold_shr_vs_asr_distinct_negative() {
        // For the same negative input and shift count, Shr and Asr must
        // produce different results, confirming logical vs arithmetic
        // semantics are not conflated.
        let shr_expr = binop(BinOp::Shr, c(-8), c(2));
        let asr_expr = binop(BinOp::Asr, c(-8), c(2));
        let shr_res = fold_expr(&shr_expr, &HashMap::new());
        let asr_res = fold_expr(&asr_expr, &HashMap::new());
        assert_eq!(asr_res, FoldResult::Folded(-2));
        assert_eq!(
            shr_res,
            FoldResult::Folded(((-8i64 as u64) >> 2) as i64)
        );
        assert_ne!(shr_res, asr_res);
    }

    #[test]
    fn test_fold_var_from_env() {
        let mut env = HashMap::new();
        env.insert("x".to_string(), 42i64);
        let expr = binop(BinOp::Add, var("x"), c(8));
        assert_eq!(fold_expr(&expr, &env), FoldResult::Folded(50));
    }

    #[test]
    fn test_fold_unknown_var() {
        let expr = binop(BinOp::Add, var("x"), c(1));
        assert_eq!(fold_expr(&expr, &HashMap::new()), FoldResult::NotFoldable);
    }

    #[test]
    fn test_algebraic_mul_zero() {
        let expr = binop(BinOp::Mul, var("x"), c(0));
        assert_eq!(fold_expr(&expr, &HashMap::new()), FoldResult::Folded(0));
    }

    #[test]
    fn test_fold_unop_neg() {
        let expr = unop(UnOp::Neg, c(5));
        assert_eq!(fold_expr(&expr, &HashMap::new()), FoldResult::Folded(-5));
    }

    #[test]
    fn test_fold_unop_sext_byte() {
        let expr = unop(UnOp::SextByte, c(0xFF));
        assert_eq!(fold_expr(&expr, &HashMap::new()), FoldResult::Folded(-1));
    }

    #[test]
    fn test_fold_select_const_cond_true() {
        let expr = FoldableExpr::Select {
            cond: Box::new(c(1)),
            then_val: Box::new(c(42)),
            else_val: Box::new(c(0)),
        };
        assert_eq!(fold_expr(&expr, &HashMap::new()), FoldResult::Folded(42));
    }

    #[test]
    fn test_fold_select_const_cond_false() {
        let expr = FoldableExpr::Select {
            cond: Box::new(c(0)),
            then_val: Box::new(c(42)),
            else_val: Box::new(c(99)),
        };
        assert_eq!(fold_expr(&expr, &HashMap::new()), FoldResult::Folded(99));
    }

    #[test]
    fn test_fold_function_propagates_constants() {
        let mut blocks = vec![IrBlock::new("bb0")];
        blocks[0].push("a", c(10));
        blocks[0].push("b", c(20));
        blocks[0].push(
            "c",
            binop(BinOp::Add, var("a"), var("b")),
        );
        let pass = ConstantFoldingPass::new();
        let stats = pass.fold_function(&mut blocks);
        assert!(stats.exprs_folded > 0);
        let c_expr = &blocks[0].stmts[2].expr;
        assert_eq!(c_expr.as_const(), Some(30));
    }

    #[test]
    fn test_fold_function_nested() {
        // (2 + 3) * (4 - 1) = 5 * 3 = 15
        let inner_l = binop(BinOp::Add, c(2), c(3));
        let inner_r = binop(BinOp::Sub, c(4), c(1));
        let mut blocks = vec![IrBlock::new("bb0")];
        blocks[0].push("result", binop(BinOp::Mul, inner_l, inner_r));
        let pass = ConstantFoldingPass::new();
        let stats = pass.fold_function(&mut blocks);
        assert!(stats.exprs_folded >= 1);
        assert_eq!(blocks[0].stmts[0].expr.as_const(), Some(15));
    }

    #[test]
    fn test_rewrite_expr_partial() {
        let mut env = HashMap::new();
        env.insert("k".to_string(), 5i64);
        // (k + x) — k is known, x is not; result should simplify to (5 + x)
        let expr = binop(BinOp::Add, var("k"), var("x"));
        let rewritten = rewrite_expr(expr, &env);
        match &rewritten {
            FoldableExpr::BinOp { lhs, .. } => {
                assert_eq!(lhs.as_const(), Some(5));
            }
            _ => panic!("expected BinOp"),
        }
    }

    #[test]
    fn test_eval_binop_xor() {
        assert_eq!(eval_binop(BinOp::Xor, 0xAA, 0xFF), Some(0x55));
    }

    #[test]
    fn test_eval_binop_comparison() {
        assert_eq!(eval_binop(BinOp::Eq, 3, 3), Some(1));
        assert_eq!(eval_binop(BinOp::Ne, 3, 4), Some(1));
        assert_eq!(eval_binop(BinOp::Lt, 2, 5), Some(1));
        assert_eq!(eval_binop(BinOp::Ge, 5, 5), Some(1));
    }

    #[test]
    fn test_ir_block_push_and_len() {
        let mut block = IrBlock::new("test");
        assert!(block.is_empty());
        block.push("x", c(1));
        assert_eq!(block.len(), 1);
    }
}
