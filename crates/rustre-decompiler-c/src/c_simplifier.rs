//! C AST simplifier — algebraic and structural optimizations.
//!
//! [`CSimplifier`] rewrites [`CExpr`] and [`CStmt`] trees to produce
//! cleaner, more readable pseudocode.

/// Re-export of [`std::collections::HashMap`] so callers can stash per-function
/// simplification tables without importing `std::collections`.
pub use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::c_printer::{BinOp, CExpr, CStmt, CType, UnOp};

// ─────────────────────────────────────────────────────────────────────────────
// SimplifyStats
// ─────────────────────────────────────────────────────────────────────────────

/// Counts of rewrites performed.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SimplifyStats {
    pub redundant_casts_removed: u32,
    pub double_negations_removed: u32,
    pub constant_folds: u32,
    pub null_checks_simplified: u32,
    pub dead_assignments_removed: u32,
    pub tautologies_removed: u32,
    pub total_rewrites: u32,
}

impl SimplifyStats {
    pub const fn add(&mut self, other: &Self) {
        self.redundant_casts_removed += other.redundant_casts_removed;
        self.double_negations_removed += other.double_negations_removed;
        self.constant_folds += other.constant_folds;
        self.null_checks_simplified += other.null_checks_simplified;
        self.dead_assignments_removed += other.dead_assignments_removed;
        self.tautologies_removed += other.tautologies_removed;
        self.total_rewrites += other.total_rewrites;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstantValue helper
// ─────────────────────────────────────────────────────────────────────────────

/// Extract an integer constant from an expression, if it is one.
const fn as_int_const(expr: &CExpr) -> Option<i64> {
    match expr {
        CExpr::IntLit(n) => Some(*n),
        CExpr::UIntLit(n) => {
            // Guard against values above i64::MAX which would silently become negative.
            if *n <= i64::MAX as u64 {
                Some((*n).cast_signed())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Returns true if the expression is the integer literal 0.
fn is_zero(expr: &CExpr) -> bool {
    as_int_const(expr) == Some(0)
}

/// Returns true if the expression is the integer literal 1.
fn is_one(expr: &CExpr) -> bool {
    as_int_const(expr) == Some(1)
}

/// Returns true if the expression is `NULL` or `0` cast to a pointer.
fn is_null_like(expr: &CExpr) -> bool {
    matches!(expr, CExpr::Null) || is_zero(expr)
}

// ─────────────────────────────────────────────────────────────────────────────
// Type compatibility helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns true if a cast from `src` to `dst` is redundant (same type).
fn is_redundant_cast(dst: &CType, src_expr: &CExpr) -> bool {
    // Try to infer the type of src_expr
    let inferred_type = infer_type(src_expr);
    inferred_type.is_some_and(|t| types_equivalent(dst, &t))
}

fn infer_type(expr: &CExpr) -> Option<CType> {
    match expr {
        CExpr::IntLit(_) => Some(CType::Int(32, true)),
        CExpr::UIntLit(_) => Some(CType::Int(32, false)),
        CExpr::FloatLit(_) => Some(CType::Float(64)),
        CExpr::Null => Some(CType::Pointer(Box::new(CType::Void))),
        CExpr::Cast(ty, _) => Some(*ty.clone()),
        _ => None,
    }
}

fn types_equivalent(a: &CType, b: &CType) -> bool {
    // Simplified equivalence: just equality
    a == b
}

// ─────────────────────────────────────────────────────────────────────────────
// CSimplifier
// ─────────────────────────────────────────────────────────────────────────────

/// Bitfield of enabled simplification passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimplifierPasses(u8);

impl SimplifierPasses {
    const CONSTANT_PROPAGATION: u8 = 0b0001;
    const DEAD_ASSIGNMENT_ELIMINATION: u8 = 0b0010;
    const CAST_REMOVAL: u8 = 0b0100;
    const BOOL_SIMPLIFICATION: u8 = 0b1000;
    /// All passes enabled.
    pub const ALL: Self = Self(0b1111);

    #[must_use]
    pub const fn constant_propagation(self) -> bool { self.0 & Self::CONSTANT_PROPAGATION != 0 }
    #[must_use]
    pub const fn dead_assignment_elimination(self) -> bool { self.0 & Self::DEAD_ASSIGNMENT_ELIMINATION != 0 }
    #[must_use]
    pub const fn cast_removal(self) -> bool { self.0 & Self::CAST_REMOVAL != 0 }
    #[must_use]
    pub const fn bool_simplification(self) -> bool { self.0 & Self::BOOL_SIMPLIFICATION != 0 }
}

impl Default for SimplifierPasses {
    fn default() -> Self { Self::ALL }
}

/// Performs simplification passes on C AST nodes.
pub struct CSimplifier {
    pub max_passes: u32,
    pub passes: SimplifierPasses,
}

impl Default for CSimplifier {
    fn default() -> Self {
        Self {
            max_passes: 4,
            passes: SimplifierPasses::ALL,
        }
    }
}

/// Maximum recursion depth for expression simplification.  An adversarially
/// deep AST (e.g. `((((…))))` with thousands of levels) would otherwise stack-
/// overflow; this cap turns that into an early-return instead.
const MAX_SIMPLIFY_DEPTH: u32 = 512;

impl CSimplifier {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Simplify an expression in place. Returns the simplified expression and stats.
    #[must_use]
    pub fn simplify_expr(&self, expr: CExpr) -> (CExpr, SimplifyStats) {
        let mut stats = SimplifyStats::default();
        let result = self.simplify_expr_inner(expr, &mut stats, 0);
        (result, stats)
    }

    fn simplify_binop(&self, op: BinOp, lhs: CExpr, rhs: CExpr, stats: &mut SimplifyStats) -> CExpr {
        // Constant folding
        if self.passes.constant_propagation()
            && let (Some(l), Some(r)) = (as_int_const(&lhs), as_int_const(&rhs))
                && let Some(folded) = Self::fold_int_op(op, l, r) {
                    stats.constant_folds += 1;
                    stats.total_rewrites += 1;
                    return CExpr::IntLit(folded);
                }
        // Additive identity
        if matches!(op, BinOp::Add | BinOp::Sub) && is_zero(&rhs) { stats.total_rewrites += 1; return lhs; }
        if matches!(op, BinOp::Add) && is_zero(&lhs) { stats.total_rewrites += 1; return rhs; }
        // Multiplicative identity/zero
        if matches!(op, BinOp::Mul) && is_one(&rhs)  { stats.total_rewrites += 1; return lhs; }
        if matches!(op, BinOp::Mul) && is_one(&lhs)  { stats.total_rewrites += 1; return rhs; }
        if matches!(op, BinOp::Mul) && (is_zero(&lhs) || is_zero(&rhs)) { stats.constant_folds += 1; stats.total_rewrites += 1; return CExpr::IntLit(0); }
        // Bitwise identity/zero
        if matches!(op, BinOp::BitOr)  && is_zero(&rhs) { stats.total_rewrites += 1; return lhs; }
        if matches!(op, BinOp::BitAnd) && (is_zero(&lhs) || is_zero(&rhs)) { stats.total_rewrites += 1; return CExpr::IntLit(0); }
        if matches!(op, BinOp::BitXor) && is_zero(&rhs) { stats.total_rewrites += 1; return lhs; }
        // x ^ x → 0
        if matches!(op, BinOp::BitXor) && let (CExpr::Ident(a), CExpr::Ident(b)) = (&lhs, &rhs) && a == b {
            stats.total_rewrites += 1; return CExpr::IntLit(0);
        }
        // x - x → 0
        if matches!(op, BinOp::Sub) && let (CExpr::Ident(a), CExpr::Ident(b)) = (&lhs, &rhs) && a == b {
            stats.total_rewrites += 1; return CExpr::IntLit(0);
        }
        // Remove redundant casts: (T)x op (T)y → x op y
        if self.passes.cast_removal()
            && matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div)
            && let (CExpr::Cast(ty_l, inner_l), CExpr::Cast(ty_r, inner_r)) = (&lhs, &rhs) && ty_l == ty_r {
                stats.redundant_casts_removed += 2; stats.total_rewrites += 1;
                return CExpr::BinOp(op, inner_l.clone(), inner_r.clone());
            }
        // Null checks
        if matches!(op, BinOp::Ne) && is_null_like(&rhs) && let CExpr::Ident(_) = &lhs {
            stats.null_checks_simplified += 1; stats.total_rewrites += 1; return lhs;
        }
        if matches!(op, BinOp::Eq) && is_null_like(&rhs) && let CExpr::Ident(_) = &lhs {
            stats.null_checks_simplified += 1; stats.total_rewrites += 1;
            return CExpr::UnOp(UnOp::Not, Box::new(lhs));
        }
        CExpr::BinOp(op, Box::new(lhs), Box::new(rhs))
    }

    fn simplify_expr_inner(&self, expr: CExpr, stats: &mut SimplifyStats, depth: u32) -> CExpr {
        if depth >= MAX_SIMPLIFY_DEPTH { return expr; }
        match expr {
            CExpr::Cast(ty, inner) if self.passes.cast_removal() => {
                let inner = self.simplify_expr_inner(*inner, stats, depth + 1);
                if is_redundant_cast(&ty, &inner) {
                    stats.redundant_casts_removed += 1; stats.total_rewrites += 1; inner
                } else {
                    CExpr::Cast(ty, Box::new(inner))
                }
            }
            CExpr::UnOp(UnOp::Not, inner) if self.passes.bool_simplification() => {
                let inner = self.simplify_expr_inner(*inner, stats, depth + 1);
                if let CExpr::UnOp(UnOp::Not, deep) = inner {
                    stats.double_negations_removed += 1; stats.total_rewrites += 1;
                    self.simplify_expr_inner(*deep, stats, depth + 1)
                } else { CExpr::UnOp(UnOp::Not, Box::new(inner)) }
            }
            CExpr::UnOp(UnOp::Neg, inner) => {
                let inner = self.simplify_expr_inner(*inner, stats, depth + 1);
                if let CExpr::UnOp(UnOp::Neg, deep) = inner {
                    stats.total_rewrites += 1; self.simplify_expr_inner(*deep, stats, depth + 1)
                } else { CExpr::UnOp(UnOp::Neg, Box::new(inner)) }
            }
            CExpr::UnOp(op, inner) => {
                CExpr::UnOp(op, Box::new(self.simplify_expr_inner(*inner, stats, depth + 1)))
            }
            CExpr::BinOp(op, lhs, rhs) => {
                let lhs = self.simplify_expr_inner(*lhs, stats, depth + 1);
                let rhs = self.simplify_expr_inner(*rhs, stats, depth + 1);
                self.simplify_binop(op, lhs, rhs, stats)
            }
            CExpr::Call(func, args) => {
                let func = self.simplify_expr_inner(*func, stats, depth + 1);
                let args = args.into_iter().map(|a| self.simplify_expr_inner(a, stats, depth + 1)).collect();
                CExpr::Call(Box::new(func), args)
            }
            CExpr::Index(arr, idx) => {
                let arr = self.simplify_expr_inner(*arr, stats, depth + 1);
                let idx = self.simplify_expr_inner(*idx, stats, depth + 1);
                CExpr::Index(Box::new(arr), Box::new(idx))
            }
            CExpr::Member(obj, field, arrow) => {
                CExpr::Member(Box::new(self.simplify_expr_inner(*obj, stats, depth + 1)), field, arrow)
            }
            CExpr::Ternary(cond, then, else_) => {
                let cond = self.simplify_expr_inner(*cond, stats, depth + 1);
                let then = self.simplify_expr_inner(*then, stats, depth + 1);
                let else_ = self.simplify_expr_inner(*else_, stats, depth + 1);
                if let Some(c) = as_int_const(&cond) {
                    stats.constant_folds += 1; stats.total_rewrites += 1;
                    return if c != 0 { then } else { else_ };
                }
                CExpr::Ternary(Box::new(cond), Box::new(then), Box::new(else_))
            }
            other => other,
        }
    }

    fn fold_int_op(op: BinOp, l: i64, r: i64) -> Option<i64> {
        match op {
            BinOp::Add => Some(l.wrapping_add(r)),
            BinOp::Sub => Some(l.wrapping_sub(r)),
            BinOp::Mul => Some(l.wrapping_mul(r)),
            BinOp::Div if r != 0 => Some(l / r),
            BinOp::Mod if r != 0 => Some(l % r),
            BinOp::BitAnd => Some(l & r),
            BinOp::BitOr => Some(l | r),
            BinOp::BitXor => Some(l ^ r),
            BinOp::Shl if (0..64).contains(&r) => Some(l.wrapping_shl(u32::try_from(r).unwrap_or(u32::MAX))),
            BinOp::Shr if (0..64).contains(&r) => Some(l.wrapping_shr(u32::try_from(r).unwrap_or(u32::MAX))),
            BinOp::Eq => Some(i64::from(l == r)),
            BinOp::Ne => Some(i64::from(l != r)),
            BinOp::Lt => Some(i64::from(l < r)),
            BinOp::Le => Some(i64::from(l <= r)),
            BinOp::Gt => Some(i64::from(l > r)),
            BinOp::Ge => Some(i64::from(l >= r)),
            _ => None,
        }
    }

    /// Simplify a list of statements (dead-assignment elimination, etc.).
    #[must_use]
    pub fn simplify_stmts(&self, stmts: Vec<CStmt>) -> (Vec<CStmt>, SimplifyStats) {
        let mut tally = SimplifyStats::default();
        let mut out = Vec::with_capacity(stmts.len());

        // First pass: simplify each statement's expressions.
        for stmt in stmts {
            let (simplified, s) = self.simplify_stmt(stmt);
            tally.add(&s);
            out.push(simplified);
        }

        // Dead-assignment elimination pass.
        if self.passes.dead_assignment_elimination() {
            let (out2, dae_stats) = Self::eliminate_dead_assignments(out);
            tally.add(&dae_stats);
            return (out2, tally);
        }

        (out, tally)
    }

    fn simplify_stmt(&self, stmt: CStmt) -> (CStmt, SimplifyStats) {
        let mut stats = SimplifyStats::default();
        let result = match stmt {
            CStmt::Expr(e) => {
                let (e2, s) = self.simplify_expr(e);
                stats.add(&s);
                CStmt::Expr(e2)
            }
            CStmt::Decl { ty, name, init } => {
                let init2 = init.map(|e| {
                    let (e2, s) = self.simplify_expr(e);
                    stats.add(&s);
                    e2
                });
                CStmt::Decl {
                    ty,
                    name,
                    init: init2,
                }
            }
            CStmt::Return(val) => {
                let val2 = val.map(|e| {
                    let (e2, s) = self.simplify_expr(e);
                    stats.add(&s);
                    e2
                });
                CStmt::Return(val2)
            }
            CStmt::If { cond, then, else_ } => {
                let (cond2, cs) = self.simplify_expr(cond);
                stats.add(&cs);
                let (then2, ts) = self.simplify_stmts(then);
                stats.add(&ts);
                let else2 = else_.map(|e| {
                    let (e2, es) = self.simplify_stmts(e);
                    stats.add(&es);
                    e2
                });
                CStmt::If {
                    cond: cond2,
                    then: then2,
                    else_: else2,
                }
            }
            CStmt::While { cond, body } => {
                let (cond2, cs) = self.simplify_expr(cond);
                stats.add(&cs);
                let (body2, bs) = self.simplify_stmts(body);
                stats.add(&bs);
                CStmt::While {
                    cond: cond2,
                    body: body2,
                }
            }
            CStmt::For {
                init,
                cond,
                update,
                body,
            } => {
                let cond2 = cond.map(|c| {
                    let (c2, cs) = self.simplify_expr(c);
                    stats.add(&cs);
                    c2
                });
                let update2 = update.map(|u| {
                    let (u2, us) = self.simplify_expr(u);
                    stats.add(&us);
                    u2
                });
                let (body2, bs) = self.simplify_stmts(body);
                stats.add(&bs);
                CStmt::For {
                    init,
                    cond: cond2,
                    update: update2,
                    body: body2,
                }
            }
            other => other,
        };
        (result, stats)
    }

    /// Remove assignments to variables that are never read after being written.
    fn eliminate_dead_assignments(stmts: Vec<CStmt>) -> (Vec<CStmt>, SimplifyStats) {
        let mut tally = SimplifyStats::default();
        // Collect which variables are read.
        let mut read_vars: std::collections::HashSet<String> = std::collections::HashSet::new();
        for stmt in &stmts {
            collect_reads(stmt, &mut read_vars);
        }
        let mut out = Vec::with_capacity(stmts.len());
        for stmt in stmts {
            match &stmt {
                CStmt::Decl {
                    name,
                    init: Some(_),
                    ..
                } => {
                    if !read_vars.contains(name) {
                        // Declared but never read → remove
                        tally.dead_assignments_removed += 1;
                        tally.total_rewrites += 1;
                        continue;
                    }
                }
                CStmt::Expr(CExpr::BinOp(BinOp::Assign, lhs, _)) => {
                    if let CExpr::Ident(name) = lhs.as_ref()
                        && !read_vars.contains(name) {
                            tally.dead_assignments_removed += 1;
                            tally.total_rewrites += 1;
                            continue;
                        }
                }
                _ => {}
            }
            out.push(stmt);
        }
        (out, tally)
    }
}

fn collect_reads(stmt: &CStmt, out: &mut std::collections::HashSet<String>) {
    match stmt {
        CStmt::Expr(e) | CStmt::Return(Some(e)) | CStmt::Decl { init: Some(e), .. } => collect_reads_expr(e, out),
        CStmt::If { cond, then, else_ } => {
            collect_reads_expr(cond, out);
            for s in then {
                collect_reads(s, out);
            }
            if let Some(els) = else_ {
                for s in els {
                    collect_reads(s, out);
                }
            }
        }
        CStmt::While { cond, body } | CStmt::DoWhile { cond, body } => {
            collect_reads_expr(cond, out);
            for s in body {
                collect_reads(s, out);
            }
        }
        CStmt::For {
            cond, update, body, ..
        } => {
            if let Some(c) = cond {
                collect_reads_expr(c, out);
            }
            if let Some(u) = update {
                collect_reads_expr(u, out);
            }
            for s in body {
                collect_reads(s, out);
            }
        }
        _ => {}
    }
}

fn collect_reads_expr(expr: &CExpr, out: &mut std::collections::HashSet<String>) {
    match expr {
        CExpr::Ident(name) => {
            out.insert(name.clone());
        }
        CExpr::BinOp(BinOp::Assign, lhs, rhs) => {
            // Left side of assignment is a write, not a read (unless it's complex)
            if !matches!(lhs.as_ref(), CExpr::Ident(_)) {
                collect_reads_expr(lhs, out);
            }
            collect_reads_expr(rhs, out);
        }
        CExpr::BinOp(_, l, r) => {
            collect_reads_expr(l, out);
            collect_reads_expr(r, out);
        }
        CExpr::UnOp(_, e) | CExpr::Cast(_, e) => collect_reads_expr(e, out),
        CExpr::Call(f, args) => {
            collect_reads_expr(f, out);
            for a in args {
                collect_reads_expr(a, out);
            }
        }
        CExpr::Index(a, i) => {
            collect_reads_expr(a, out);
            collect_reads_expr(i, out);
        }
        CExpr::Member(o, _, _) => collect_reads_expr(o, out),
        CExpr::Ternary(c, t, e) => {
            collect_reads_expr(c, out);
            collect_reads_expr(t, out);
            collect_reads_expr(e, out);
        }
        _ => {}
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c_printer::{BinOp, CExpr, CStmt, CType, UnOp};

    fn simplifier() -> CSimplifier {
        CSimplifier::new()
    }

    fn ident(name: &str) -> CExpr {
        CExpr::Ident(name.to_string())
    }
    fn ilit(n: i64) -> CExpr {
        CExpr::IntLit(n)
    }
    fn binop(op: BinOp, l: CExpr, r: CExpr) -> CExpr {
        CExpr::BinOp(op, Box::new(l), Box::new(r))
    }
    fn unop(op: UnOp, e: CExpr) -> CExpr {
        CExpr::UnOp(op, Box::new(e))
    }

    // --- Constant folding ---

    #[test]
    fn fold_add_constants() {
        let e = binop(BinOp::Add, ilit(3), ilit(4));
        let (r, s) = simplifier().simplify_expr(e);
        assert_eq!(r, ilit(7));
        assert_eq!(s.constant_folds, 1);
    }

    #[test]
    fn fold_mul_constants() {
        let e = binop(BinOp::Mul, ilit(6), ilit(7));
        let (r, _) = simplifier().simplify_expr(e);
        assert_eq!(r, ilit(42));
    }

    #[test]
    fn fold_sub_constants() {
        let e = binop(BinOp::Sub, ilit(10), ilit(3));
        let (r, _) = simplifier().simplify_expr(e);
        assert_eq!(r, ilit(7));
    }

    #[test]
    fn fold_eq_true() {
        let e = binop(BinOp::Eq, ilit(5), ilit(5));
        let (r, _) = simplifier().simplify_expr(e);
        assert_eq!(r, ilit(1));
    }

    #[test]
    fn fold_ne_false() {
        let e = binop(BinOp::Ne, ilit(3), ilit(3));
        let (r, _) = simplifier().simplify_expr(e);
        assert_eq!(r, ilit(0));
    }

    // --- Identity element elimination ---

    #[test]
    fn add_zero_rhs() {
        let e = binop(BinOp::Add, ident("x"), ilit(0));
        let (r, stats) = simplifier().simplify_expr(e);
        assert_eq!(r, ident("x"));
        assert_eq!(stats.total_rewrites, 1);
    }

    #[test]
    fn sub_zero() {
        let e = binop(BinOp::Sub, ident("y"), ilit(0));
        let (r, _) = simplifier().simplify_expr(e);
        assert_eq!(r, ident("y"));
    }

    #[test]
    fn mul_by_one() {
        let e = binop(BinOp::Mul, ident("z"), ilit(1));
        let (r, _) = simplifier().simplify_expr(e);
        assert_eq!(r, ident("z"));
    }

    #[test]
    fn mul_by_zero() {
        let e = binop(BinOp::Mul, ident("a"), ilit(0));
        let (r, _) = simplifier().simplify_expr(e);
        assert_eq!(r, ilit(0));
    }

    // --- Boolean simplification ---

    #[test]
    fn double_not() {
        let e = unop(UnOp::Not, unop(UnOp::Not, ident("x")));
        let (r, stats) = simplifier().simplify_expr(e);
        assert_eq!(r, ident("x"));
        assert_eq!(stats.double_negations_removed, 1);
    }

    #[test]
    fn double_neg() {
        let e = unop(UnOp::Neg, unop(UnOp::Neg, ident("x")));
        let (r, _) = simplifier().simplify_expr(e);
        assert_eq!(r, ident("x"));
    }

    // --- XOR same → 0 ---

    #[test]
    fn xor_self_zero() {
        let e = binop(BinOp::BitXor, ident("x"), ident("x"));
        let (r, _) = simplifier().simplify_expr(e);
        assert_eq!(r, ilit(0));
    }

    // --- Sub same → 0 ---

    #[test]
    fn sub_self_zero() {
        let e = binop(BinOp::Sub, ident("v"), ident("v"));
        let (r, _) = simplifier().simplify_expr(e);
        assert_eq!(r, ilit(0));
    }

    // --- Null checks ---

    #[test]
    fn ne_zero_simplify() {
        let e = binop(BinOp::Ne, ident("p"), ilit(0));
        let (r, stats) = simplifier().simplify_expr(e);
        assert_eq!(r, ident("p"));
        assert_eq!(stats.null_checks_simplified, 1);
    }

    #[test]
    fn eq_zero_simplify_to_not() {
        let e = binop(BinOp::Eq, ident("p"), ilit(0));
        let (r, stats) = simplifier().simplify_expr(e);
        assert_eq!(r, unop(UnOp::Not, ident("p")));
        assert_eq!(stats.null_checks_simplified, 1);
    }

    // --- Redundant cast removal ---

    #[test]
    fn redundant_cast_int() {
        let e = CExpr::Cast(Box::new(CType::Int(32, true)), Box::new(ilit(5)));
        let (_r, stats) = simplifier().simplify_expr(e);
        // ilit(5) has inferred type Int(32, true), so cast is redundant
        assert_eq!(stats.redundant_casts_removed, 1);
    }

    // --- Cast pair removal in binop ---

    #[test]
    fn cast_pair_in_add() {
        let ty = CType::Int(32, true);
        let l = CExpr::Cast(Box::new(ty.clone()), Box::new(ident("a")));
        let r = CExpr::Cast(Box::new(ty), Box::new(ident("b")));
        let e = binop(BinOp::Add, l, r);
        let (_result, stats) = simplifier().simplify_expr(e);
        assert_eq!(stats.redundant_casts_removed, 2);
    }

    // --- Ternary constant fold ---

    #[test]
    fn ternary_const_true() {
        let e = CExpr::Ternary(
            Box::new(ilit(1)),
            Box::new(ident("yes")),
            Box::new(ident("no")),
        );
        let (r, _) = simplifier().simplify_expr(e);
        assert_eq!(r, ident("yes"));
    }

    #[test]
    fn ternary_const_false() {
        let e = CExpr::Ternary(
            Box::new(ilit(0)),
            Box::new(ident("yes")),
            Box::new(ident("no")),
        );
        let (r, _) = simplifier().simplify_expr(e);
        assert_eq!(r, ident("no"));
    }

    // --- BitAnd with 0 ---

    #[test]
    fn bitand_zero() {
        let e = binop(BinOp::BitAnd, ident("x"), ilit(0));
        let (r, _) = simplifier().simplify_expr(e);
        assert_eq!(r, ilit(0));
    }

    // --- Statements ---

    #[test]
    fn stmt_return_folds_expr() {
        let stmts = vec![CStmt::Return(Some(binop(BinOp::Add, ilit(2), ilit(3))))];
        let (r, s) = simplifier().simplify_stmts(stmts);
        assert_eq!(s.constant_folds, 1);
        if let CStmt::Return(Some(CExpr::IntLit(5))) = &r[0] {
        } else {
            panic!("expected 5");
        }
    }

    // --- Dead assignment elimination ---

    #[test]
    fn dead_assignment_removed() {
        // int unused = 5;  (never referenced → removed)
        // return 0;
        let stmts = vec![
            CStmt::Decl {
                ty: CType::Int(32, true),
                name: "unused".into(),
                init: Some(ilit(5)),
            },
            CStmt::Return(Some(ilit(0))),
        ];
        let (r, s) = simplifier().simplify_stmts(stmts);
        assert_eq!(s.dead_assignments_removed, 1);
        assert_eq!(r.len(), 1); // Only the return remains
    }

    #[test]
    fn live_assignment_kept() {
        // int x = 5; return x;
        let stmts = vec![
            CStmt::Decl {
                ty: CType::Int(32, true),
                name: "x".into(),
                init: Some(ilit(5)),
            },
            CStmt::Return(Some(ident("x"))),
        ];
        let (r, s) = simplifier().simplify_stmts(stmts);
        assert_eq!(s.dead_assignments_removed, 0);
        assert_eq!(r.len(), 2);
    }

    // --- SimplifyStats ---

    #[test]
    fn simplify_stats_add() {
        let mut a = SimplifyStats {
            constant_folds: 2,
            ..Default::default()
        };
        let b = SimplifyStats {
            constant_folds: 3,
            ..Default::default()
        };
        a.add(&b);
        assert_eq!(a.constant_folds, 5);
    }
}
