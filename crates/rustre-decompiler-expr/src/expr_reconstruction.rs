//! Complex expression reconstruction.
//!
//! Collapses redundant cast chains, detects compound-assignment patterns
//! (`x = x + 1` → `x += 1` → `x++`), recognises ternary / lazy-evaluation
//! patterns, and identifies pointer-to-int / int-to-pointer round-trips.


use crate::{BinOp, Expr, UnOp};

// ─────────────────────────────────────────────────────────────────────────────
// Compound-assignment detection
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of compound assignment recognised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompoundAssign {
    /// `v += rhs`
    AddAssign { var: String, rhs: Expr },
    /// `v -= rhs`
    SubAssign { var: String, rhs: Expr },
    /// `v *= rhs`
    MulAssign { var: String, rhs: Expr },
    /// `v /= rhs`
    DivAssign { var: String, rhs: Expr },
    /// `v &= rhs`
    AndAssign { var: String, rhs: Expr },
    /// `v |= rhs`
    OrAssign  { var: String, rhs: Expr },
    /// `v ^= rhs`
    XorAssign { var: String, rhs: Expr },
    /// `v <<= rhs`
    ShlAssign { var: String, rhs: Expr },
    /// `v >>= rhs`
    ShrAssign { var: String, rhs: Expr },
    /// `v++`
    PostInc   { var: String },
    /// `v--`
    PostDec   { var: String },
    /// `++v`
    PreInc    { var: String },
    /// `--v`
    PreDec    { var: String },
}

impl CompoundAssign {
    /// Emit a C string for this compound assignment.
    #[must_use]
    pub fn to_c_string(&self) -> String {
        match self {
            Self::PostInc { var } => format!("{var}++"),
            Self::PostDec { var } => format!("{var}--"),
            Self::PreInc  { var } => format!("++{var}"),
            Self::PreDec  { var } => format!("--{var}"),
            Self::AddAssign { var, rhs } => format!("{var} += {rhs}"),
            Self::SubAssign { var, rhs } => format!("{var} -= {rhs}"),
            Self::MulAssign { var, rhs } => format!("{var} *= {rhs}"),
            Self::DivAssign { var, rhs } => format!("{var} /= {rhs}"),
            Self::AndAssign { var, rhs } => format!("{var} &= {rhs}"),
            Self::OrAssign  { var, rhs } => format!("{var} |= {rhs}"),
            Self::XorAssign { var, rhs } => format!("{var} ^= {rhs}"),
            Self::ShlAssign { var, rhs } => format!("{var} <<= {rhs}"),
            Self::ShrAssign { var, rhs } => format!("{var} >>= {rhs}"),
        }
    }
}

/// Detect whether an assignment `lhs = expr` is a compound assignment.
///
/// Pattern: `lhs = lhs OP rhs` where `lhs` is a `Var`.
/// Special: `lhs = lhs + 1` → `lhs++`, `lhs = lhs - 1` → `lhs--`.
#[must_use]
pub fn detect_compound_assign(lhs: &str, expr: &Expr) -> Option<CompoundAssign> {
    if let Expr::BinOp(op, a, b) = expr {
        if a.as_var() == Some(lhs) {
            let rhs = b.as_ref().clone();
            let is_one = b.as_const() == Some(1);
            return Some(match op {
                BinOp::Add if is_one => CompoundAssign::PostInc { var: lhs.to_string() },
                BinOp::Sub if is_one => CompoundAssign::PostDec { var: lhs.to_string() },
                BinOp::Add => CompoundAssign::AddAssign { var: lhs.to_string(), rhs },
                BinOp::Sub => CompoundAssign::SubAssign { var: lhs.to_string(), rhs },
                BinOp::Mul => CompoundAssign::MulAssign { var: lhs.to_string(), rhs },
                BinOp::Div => CompoundAssign::DivAssign { var: lhs.to_string(), rhs },
                BinOp::And => CompoundAssign::AndAssign { var: lhs.to_string(), rhs },
                BinOp::Or  => CompoundAssign::OrAssign  { var: lhs.to_string(), rhs },
                BinOp::Xor => CompoundAssign::XorAssign { var: lhs.to_string(), rhs },
                BinOp::Shl => CompoundAssign::ShlAssign { var: lhs.to_string(), rhs },
                BinOp::Shr => CompoundAssign::ShrAssign { var: lhs.to_string(), rhs },
                _ => return None,
            });
        }
        // Also recognise commutative: `lhs = 1 + lhs` → lhs++
        if b.as_var() == Some(lhs) && op.is_commutative() {
            let rhs = a.as_ref().clone();
            let is_one = a.as_const() == Some(1);
            return Some(match op {
                BinOp::Add if is_one => CompoundAssign::PreInc { var: lhs.to_string() },
                BinOp::Add => CompoundAssign::AddAssign { var: lhs.to_string(), rhs },
                BinOp::Mul => CompoundAssign::MulAssign { var: lhs.to_string(), rhs },
                BinOp::And => CompoundAssign::AndAssign { var: lhs.to_string(), rhs },
                BinOp::Or  => CompoundAssign::OrAssign  { var: lhs.to_string(), rhs },
                BinOp::Xor => CompoundAssign::XorAssign { var: lhs.to_string(), rhs },
                _ => return None,
            });
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Cast chain collapsing
// ─────────────────────────────────────────────────────────────────────────────

/// Collapse redundant cast chains.
///
/// Rules:
/// * `(T)(T)x → (T)x`
/// * `(T2)(T1)x → (T2)x` when `T2 ≤ T1` bits (outer is narrower or equal).
/// * `(T2)(T1)x` is kept when T2 is wider (the inner cast may be meaningful).
/// * `(ptr)( (int)ptr )` round-trip → original pointer.
/// * `(int)(ptr)int` round-trip → original int.
#[must_use]
pub fn collapse_casts(expr: Expr) -> Expr {
    match expr {
        Expr::UnOp(UnOp::Cast(outer), inner) => {
            let inner = collapse_casts(*inner);
            // Double cast: (T2)(T1)x
            if let Expr::UnOp(UnOp::Cast(inner_w), inner_inner) = &inner
                && outer.bits() <= inner_w.bits()
            {
                // Outer is no wider than inner → merge.
                return collapse_casts(Expr::UnOp(
                    UnOp::Cast(outer),
                    inner_inner.clone(),
                ));
            }
            Expr::UnOp(UnOp::Cast(outer), Box::new(inner))
        }
        Expr::BinOp(op, a, b) => Expr::BinOp(
            op,
            Box::new(collapse_casts(*a)),
            Box::new(collapse_casts(*b)),
        ),
        Expr::UnOp(op, e) => Expr::UnOp(op, Box::new(collapse_casts(*e))),
        Expr::Load { ptr, size } => Expr::Load {
            ptr: Box::new(collapse_casts(*ptr)),
            size,
        },
        Expr::FieldAccess { base, offset } => Expr::FieldAccess {
            base: Box::new(collapse_casts(*base)),
            offset,
        },
        Expr::Index { base, index, elem_size } => Expr::Index {
            base: Box::new(collapse_casts(*base)),
            index: Box::new(collapse_casts(*index)),
            elem_size,
        },
        Expr::Call { callee, args } => Expr::Call {
            callee: Box::new(collapse_casts(*callee)),
            args: args.into_iter().map(collapse_casts).collect(),
        },
        Expr::Ternary { cond, then_expr, else_expr } => Expr::Ternary {
            cond: Box::new(collapse_casts(*cond)),
            then_expr: Box::new(collapse_casts(*then_expr)),
            else_expr: Box::new(collapse_casts(*else_expr)),
        },
        other => other,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ternary detection
// ─────────────────────────────────────────────────────────────────────────────

/// Represents a detected ternary expression.
#[derive(Debug, Clone)]
pub struct TernaryPattern {
    pub condition: Expr,
    pub then_val: Expr,
    pub else_val: Expr,
}

impl TernaryPattern {
    #[must_use]
    pub fn to_expr(self) -> Expr {
        Expr::Ternary {
            cond: Box::new(self.condition),
            then_expr: Box::new(self.then_val),
            else_expr: Box::new(self.else_val),
        }
    }

    #[must_use]
    pub fn to_c_string(&self) -> String {
        format!("({} ? {} : {})", self.condition, self.then_val, self.else_val)
    }
}

/// Detect whether a `select`-style phi node can be rewritten as a ternary.
///
/// Pattern: `phi(cond_true_val, cond_false_val)` where the phi has exactly
/// two incoming values and the associated conditions are complementary.
///
/// A simpler form: `(cond != 0) ? a : b` is already a ternary — just
/// re-use the existing `Ternary` node.
#[must_use]
pub fn detect_ternary(phi: &Expr, cond: &Expr) -> Option<TernaryPattern> {
    if let Expr::Phi(exprs) = phi
        && exprs.len() == 2 {
            return Some(TernaryPattern {
                condition: cond.clone(),
                then_val: exprs[0].clone(),
                else_val: exprs[1].clone(),
            });
        }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Pointer ↔ integer round-trip detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detect and simplify `(int)(ptr)int` round-trips and
/// `(ptr)(int)ptr` round-trips.
///
/// These appear frequently around `CONTAINING_RECORD` macros and custom
/// allocators.
#[must_use]
pub fn remove_ptr_int_roundtrip(expr: Expr) -> Expr {
    match expr {
        // (ptr_cast)((int_cast)(ptr_expr)) → ptr_expr  when sizes match.
        Expr::UnOp(UnOp::Cast(outer), ref inner) => {
            if let Expr::UnOp(UnOp::Cast(inner_w), ref innermost) = **inner {
                // If both casts cancel each other (e.g. int64→ptr→int64),
                // and the outermost width equals innermost's original width,
                // this is a round-trip.
                if outer == inner_w {
                    return remove_ptr_int_roundtrip(*innermost.clone());
                }
            }
            expr
        }
        Expr::BinOp(op, a, b) => Expr::BinOp(
            op,
            Box::new(remove_ptr_int_roundtrip(*a)),
            Box::new(remove_ptr_int_roundtrip(*b)),
        ),
        Expr::UnOp(op, e) => Expr::UnOp(op, Box::new(remove_ptr_int_roundtrip(*e))),
        Expr::Ternary { cond, then_expr, else_expr } => Expr::Ternary {
            cond: Box::new(remove_ptr_int_roundtrip(*cond)),
            then_expr: Box::new(remove_ptr_int_roundtrip(*then_expr)),
            else_expr: Box::new(remove_ptr_int_roundtrip(*else_expr)),
        },
        other => other,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lazy evaluation pattern detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detects short-circuit evaluation patterns used for null checks and pointer
/// validity guards.
///
/// Patterns:
/// * `ptr != NULL && ptr->field`  (null-guarded dereference)
/// * `cond || fallback`           (default value pattern)
#[derive(Debug, Clone)]
pub enum LazyPattern {
    /// `ptr != NULL && <use of ptr>` — null pointer guard.
    NullGuard { ptr: Expr, body: Expr },
    /// `cond || default_val` — or-default.
    OrDefault { cond: Expr, default_val: Expr },
}

#[must_use]
pub fn detect_lazy_pattern(expr: &Expr) -> Option<LazyPattern> {
    match expr {
        Expr::BinOp(BinOp::LAnd, cond, body) => {
            // cond is `ptr != NULL` or `ptr != 0`.
            if let Expr::BinOp(BinOp::Ne, ptr_expr, null_expr) = cond.as_ref()
                && null_expr.as_const() == Some(0) {
                    return Some(LazyPattern::NullGuard {
                        ptr: *ptr_expr.clone(),
                        body: *body.clone(),
                    });
                }
            None
        }
        Expr::BinOp(BinOp::LOr, cond, default_val) => {
            Some(LazyPattern::OrDefault {
                cond: *cond.clone(),
                default_val: *default_val.clone(),
            })
        }
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprReconstructor — top-level reconstruction pass
// ─────────────────────────────────────────────────────────────────────────────

/// Applies all reconstruction passes to an assignment list.
#[derive(Debug, Default)]
pub struct ExprReconstructor {
    /// Number of patterns collapsed.
    pub rewrites: usize,
}

impl ExprReconstructor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply reconstruction to a single expression.
    #[must_use]
    pub fn reconstruct_expr(&mut self, expr: Expr) -> Expr {
        let e = collapse_casts(expr);
        
        remove_ptr_int_roundtrip(e)
    }

    /// Apply reconstruction to a sequence of `(dst, expr)` assignments and
    /// return the simplified list including compound-assignment detection.
    #[must_use]
    pub fn reconstruct_assignments(
        &mut self,
        assigns: Vec<(String, Expr)>,
    ) -> Vec<ReconstructedAssign> {
        assigns
            .into_iter()
            .map(|(dst, expr)| {
                let expr = self.reconstruct_expr(expr);
                if let Some(compound) = detect_compound_assign(&dst, &expr) {
                    self.rewrites += 1;
                    ReconstructedAssign::Compound(compound)
                } else {
                    ReconstructedAssign::Simple { dst, expr }
                }
            })
            .collect()
    }
}

/// An assignment after reconstruction.
#[derive(Debug, Clone)]
pub enum ReconstructedAssign {
    /// A plain `dst = expr` assignment.
    Simple { dst: String, expr: Expr },
    /// A compound assignment `dst OP= rhs` or increment/decrement.
    Compound(CompoundAssign),
}

impl ReconstructedAssign {
    #[must_use]
    pub fn to_c_string(&self) -> String {
        match self {
            Self::Simple { dst, expr } => format!("{dst} = {expr}"),
            Self::Compound(c) => c.to_c_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IntWidth;

    fn c(v: i64) -> Expr { Expr::Const(v, IntWidth::I64) }
    fn var(n: &str) -> Expr { Expr::Var(n.to_string()) }
    fn cast(w: IntWidth, e: Expr) -> Expr { Expr::UnOp(UnOp::Cast(w), Box::new(e)) }

    // ── compound assign ───────────────────────────────────────────────────────

    #[test]
    fn test_detect_post_inc() {
        let expr = Expr::BinOp(BinOp::Add, Box::new(var("i")), Box::new(c(1)));
        let r = detect_compound_assign("i", &expr);
        assert!(matches!(r, Some(CompoundAssign::PostInc { .. })));
    }

    #[test]
    fn test_detect_post_dec() {
        let expr = Expr::BinOp(BinOp::Sub, Box::new(var("i")), Box::new(c(1)));
        let r = detect_compound_assign("i", &expr);
        assert!(matches!(r, Some(CompoundAssign::PostDec { .. })));
    }

    #[test]
    fn test_detect_add_assign() {
        let expr = Expr::BinOp(BinOp::Add, Box::new(var("x")), Box::new(c(5)));
        let r = detect_compound_assign("x", &expr);
        assert!(matches!(r, Some(CompoundAssign::AddAssign { .. })));
    }

    #[test]
    fn test_detect_and_assign() {
        let expr = Expr::BinOp(BinOp::And, Box::new(var("flags")), Box::new(c(0xFF)));
        let r = detect_compound_assign("flags", &expr);
        assert!(matches!(r, Some(CompoundAssign::AndAssign { .. })));
    }

    #[test]
    fn test_detect_or_assign() {
        let expr = Expr::BinOp(BinOp::Or, Box::new(var("mask")), Box::new(c(1)));
        let r = detect_compound_assign("mask", &expr);
        assert!(matches!(r, Some(CompoundAssign::OrAssign { .. })));
    }

    #[test]
    fn test_no_compound_different_var() {
        let expr = Expr::BinOp(BinOp::Add, Box::new(var("y")), Box::new(c(1)));
        assert!(detect_compound_assign("x", &expr).is_none());
    }

    #[test]
    fn test_post_inc_c_string() {
        let ca = CompoundAssign::PostInc { var: "i".to_string() };
        assert_eq!(ca.to_c_string(), "i++");
    }

    #[test]
    fn test_post_dec_c_string() {
        let ca = CompoundAssign::PostDec { var: "j".to_string() };
        assert_eq!(ca.to_c_string(), "j--");
    }

    // ── cast chain collapse ───────────────────────────────────────────────────

    #[test]
    fn test_double_cast_same_type() {
        // (i32)(i32)x → (i32)x
        let e = cast(IntWidth::I32, cast(IntWidth::I32, var("x")));
        let r = collapse_casts(e);
        assert!(matches!(r, Expr::UnOp(UnOp::Cast(IntWidth::I32), _)));
        if let Expr::UnOp(_, inner) = r {
            // The inner should be just `x`, not another cast.
            assert!(matches!(*inner, Expr::Var(_)));
        }
    }

    #[test]
    fn test_double_cast_outer_narrower() {
        // (i8)(i32)x → (i8)x  [outer=8, inner=32 → outer smaller → merge]
        let e = cast(IntWidth::I8, cast(IntWidth::I32, var("x")));
        let r = collapse_casts(e);
        if let Expr::UnOp(UnOp::Cast(w), inner) = r {
            assert_eq!(w, IntWidth::I8);
            assert!(matches!(*inner, Expr::Var(_)));
        }
    }

    #[test]
    fn test_double_cast_outer_wider_keeps_both() {
        // (i64)(i32)x — outer is wider, might be sign-extension, keep.
        let e = cast(IntWidth::I64, cast(IntWidth::I32, var("x")));
        let r = collapse_casts(e);
        // Should keep outer cast wrapping inner cast.
        assert!(matches!(r, Expr::UnOp(UnOp::Cast(IntWidth::I64), _)));
    }

    // ── ptr-int round trip ────────────────────────────────────────────────────

    #[test]
    fn test_round_trip_cancelled() {
        // (u64)(u64)x → x
        let e = cast(IntWidth::U64, cast(IntWidth::U64, var("p")));
        let r = remove_ptr_int_roundtrip(e);
        assert_eq!(r, var("p"));
    }

    // ── ternary detection ─────────────────────────────────────────────────────

    #[test]
    fn test_ternary_from_phi() {
        let phi = Expr::Phi(vec![c(1), c(0)]);
        let cond = var("flag");
        let r = detect_ternary(&phi, &cond);
        assert!(r.is_some());
        let t = r.unwrap();
        assert_eq!(t.then_val, c(1));
        assert_eq!(t.else_val, c(0));
    }

    #[test]
    fn test_ternary_to_c_string() {
        let t = TernaryPattern {
            condition: var("c"),
            then_val: c(1),
            else_val: c(0),
        };
        let s = t.to_c_string();
        assert!(s.contains('?') && s.contains(':'));
    }

    // ── lazy evaluation ───────────────────────────────────────────────────────

    #[test]
    fn test_null_guard_detection() {
        // (ptr != 0) && use_ptr
        let cond = Expr::BinOp(BinOp::Ne, Box::new(var("ptr")), Box::new(c(0)));
        let body = Expr::Load { ptr: Box::new(var("ptr")), size: 4 };
        let e = Expr::BinOp(BinOp::LAnd, Box::new(cond), Box::new(body));
        let r = detect_lazy_pattern(&e);
        assert!(matches!(r, Some(LazyPattern::NullGuard { .. })));
    }

    #[test]
    fn test_or_default_detection() {
        let e = Expr::BinOp(BinOp::LOr, Box::new(var("opt")), Box::new(c(42)));
        let r = detect_lazy_pattern(&e);
        assert!(matches!(r, Some(LazyPattern::OrDefault { .. })));
    }

    // ── ExprReconstructor ─────────────────────────────────────────────────────

    #[test]
    fn test_reconstructor_detects_inc() {
        let mut r = ExprReconstructor::new();
        let assigns = vec![(
            "i".to_string(),
            Expr::BinOp(BinOp::Add, Box::new(var("i")), Box::new(c(1))),
        )];
        let result = r.reconstruct_assignments(assigns);
        assert!(matches!(result[0], ReconstructedAssign::Compound(CompoundAssign::PostInc { .. })));
        assert!(r.rewrites > 0);
    }

    #[test]
    fn test_reconstructor_simple_unchanged() {
        let mut r = ExprReconstructor::new();
        let assigns = vec![(
            "x".to_string(),
            Expr::BinOp(BinOp::Add, Box::new(var("a")), Box::new(var("b"))),
        )];
        let result = r.reconstruct_assignments(assigns);
        assert!(matches!(result[0], ReconstructedAssign::Simple { .. }));
    }

    #[test]
    fn test_reconstructor_collapses_cast() {
        let mut r = ExprReconstructor::new();
        let assigns = vec![(
            "y".to_string(),
            cast(IntWidth::I8, cast(IntWidth::I32, var("x"))),
        )];
        let result = r.reconstruct_assignments(assigns);
        if let ReconstructedAssign::Simple { expr, .. } = &result[0]
            && let Expr::UnOp(UnOp::Cast(w), inner) = expr {
                assert_eq!(*w, IntWidth::I8);
                assert!(matches!(**inner, Expr::Var(_)));
            }
    }
}
