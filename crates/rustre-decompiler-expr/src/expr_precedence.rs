//! Operator precedence and minimal parenthesization.
//!
//! Implements:
//! - The C operator precedence table (matching GCC/Clang output conventions).
//! - A minimal parenthesization algorithm: inserts parentheses only where
//!   needed to preserve the intended evaluation order.
//! - Associativity rules (left/right/none).
//! - Side-effect ordering helpers used when reordering expressions.

use crate::{BinOp, Expr, UnOp};

// ─────────────────────────────────────────────────────────────────────────────
// Precedence / associativity
// ─────────────────────────────────────────────────────────────────────────────

/// Operator associativity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Associativity {
    Left,
    Right,
    /// Non-associative (e.g. chained comparisons require parentheses).
    None,
}

/// C operator precedence levels (higher = binds tighter).
///
/// Based on the ISO C11 standard grammar / GCC convention.
/// Levels are chosen so that they match the common "C precedence table"
/// used in textbooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrecedenceLevel(pub u8);

impl PrecedenceLevel {
    /// Comma operator (lowest).
    pub const COMMA: Self = Self(1);
    /// Assignment operators (`=`, `+=`, …).
    pub const ASSIGN: Self = Self(2);
    /// Ternary `? :`.
    pub const TERNARY: Self = Self(3);
    /// Logical OR `||`.
    pub const LOR: Self = Self(4);
    /// Logical AND `&&`.
    pub const LAND: Self = Self(5);
    /// Bitwise OR `|`.
    pub const BOR: Self = Self(6);
    /// Bitwise XOR `^`.
    pub const BXOR: Self = Self(7);
    /// Bitwise AND `&`.
    pub const BAND: Self = Self(8);
    /// Equality `==`, `!=`.
    pub const EQUALITY: Self = Self(9);
    /// Relational `<`, `<=`, `>`, `>=`.
    pub const RELATIONAL: Self = Self(10);
    /// Shift `<<`, `>>`.
    pub const SHIFT: Self = Self(11);
    /// Additive `+`, `-`.
    pub const ADDITIVE: Self = Self(12);
    /// Multiplicative `*`, `/`, `%`.
    pub const MULTIPLICATIVE: Self = Self(13);
    /// Unary operators (highest among typical binary ops).
    pub const UNARY: Self = Self(14);
    /// Primary (atoms, calls, subscripts).
    pub const PRIMARY: Self = Self(15);
}

/// Return the C precedence level and associativity for a binary operator.
#[must_use]
pub const fn binop_precedence(op: BinOp) -> (PrecedenceLevel, Associativity) {
    match op {
        BinOp::LOr  => (PrecedenceLevel::LOR,           Associativity::Left),
        BinOp::LAnd => (PrecedenceLevel::LAND,          Associativity::Left),
        BinOp::Or   => (PrecedenceLevel::BOR,           Associativity::Left),
        BinOp::Xor  => (PrecedenceLevel::BXOR,         Associativity::Left),
        BinOp::And  => (PrecedenceLevel::BAND,          Associativity::Left),
        BinOp::Eq | BinOp::Ne
                    => (PrecedenceLevel::EQUALITY,      Associativity::Left),
        BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge
                    => (PrecedenceLevel::RELATIONAL,    Associativity::None),
        BinOp::Shl | BinOp::Shr | BinOp::Sar
                    => (PrecedenceLevel::SHIFT,         Associativity::Left),
        BinOp::Add | BinOp::Sub
                    => (PrecedenceLevel::ADDITIVE,      Associativity::Left),
        BinOp::Mul | BinOp::Div | BinOp::Mod
                    => (PrecedenceLevel::MULTIPLICATIVE, Associativity::Left),
    }
}

/// Return the C precedence level for a unary operator.
#[must_use]
pub const fn unop_precedence(_op: UnOp) -> PrecedenceLevel {
    PrecedenceLevel::UNARY
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal parenthesization
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the parenthesization pass.
#[derive(Debug, Clone, Copy)]
pub struct ParenConfig {
    /// Always parenthesize all binary operations (safe / maximum).
    pub full_parens: bool,
    /// Insert parentheses around ternary inside binary expressions.
    pub paren_ternary_in_binary: bool,
}

impl Default for ParenConfig {
    fn default() -> Self {
        Self {
            full_parens: false,
            paren_ternary_in_binary: true,
        }
    }
}

/// Decides whether `child` needs parentheses when appearing as the `is_right`
/// operand of a `parent` binary operator.
///
/// Returns `true` when parentheses are required.
#[must_use]
pub fn needs_parens(parent_op: BinOp, child: &Expr, is_right: bool) -> bool {
    let (parent_prec, parent_assoc) = binop_precedence(parent_op);

    match child {
        Expr::BinOp(child_op, _, _) => {
            let (child_prec, _) = binop_precedence(*child_op);
            if child_prec < parent_prec {
                return true; // child binds less tightly
            }
            if child_prec == parent_prec {
                // Same precedence: need parens on right for left-associative ops,
                // and on left for right-associative ops.
                return match parent_assoc {
                    Associativity::Left  => is_right,
                    Associativity::Right => !is_right,
                    Associativity::None  => true, // always safe
                };
            }
            false
        }
        Expr::Ternary { .. } => {
            // Ternaries are confusing; always add parens when nested in binops.
            true
        }
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// C expression printer with minimal parentheses
// ─────────────────────────────────────────────────────────────────────────────

/// Emits a C expression string with the minimal set of parentheses required to
/// preserve the intended evaluation order.
#[derive(Default)]
pub struct MinimalParenPrinter {
    pub config: ParenConfig,
}


impl MinimalParenPrinter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Print `expr` to a string with minimal parentheses.
    #[must_use]
    pub fn print(&self, expr: &Expr) -> String {
        self.print_inner(expr, None, false)
    }

    /// `parent_op`: the enclosing binary operator (if any).
    /// `is_right`: whether `expr` is the right operand.
    fn print_inner(&self, expr: &Expr, parent_op: Option<BinOp>, is_right: bool) -> String {
        let needs_wrap = parent_op.is_some_and(|pop| {
            needs_parens(pop, expr, is_right) || self.config.full_parens && expr.is_binop()
        });

        let s = match expr {
            Expr::Const(v, _) => {
                if (-1000..1000).contains(v) {
                    format!("{v}")
                } else {
                    format!("{v:#x}")
                }
            }
            Expr::Var(n) => n.clone(),

            Expr::BinOp(op, a, b) => {
                let left  = self.print_inner(a, Some(*op), false);
                let right = self.print_inner(b, Some(*op), true);
                format!("{left} {} {right}", op.as_str())
            }

            Expr::UnOp(op, e) => {
                let inner = self.print_inner(e, None, false);
                match op {
                    UnOp::Cast(w) => format!("({w}){inner}"),
                    UnOp::Deref  => {
                        // Dereference of a complex expr needs parens.
                        if e.is_binop() || matches!(e.as_ref(), Expr::Ternary { .. }) {
                            format!("*({inner})")
                        } else {
                            format!("*{inner}")
                        }
                    }
                    UnOp::AddrOf => format!("&{inner}"),
                    UnOp::Neg    => format!("-{inner}"),
                    UnOp::Not    => format!("~{inner}"),
                    UnOp::LNot   => format!("!{inner}"),
                }
            }

            Expr::Load { ptr, size } => {
                let inner = self.print_inner(ptr, None, false);
                format!("*(uint{}_t *){inner}", size * 8)
            }

            Expr::FieldAccess { base, offset } => {
                let b = self.print_inner(base, None, false);
                format!("FIELD({b}, {offset:#x})")
            }

            Expr::Index { base, index, .. } => {
                let b = self.print_inner(base, None, false);
                let i = self.print_inner(index, None, false);
                format!("{b}[{i}]")
            }

            Expr::Call { callee, args } => {
                let c = self.print_inner(callee, None, false);
                let args_s: Vec<String> =
                    args.iter().map(|a| self.print_inner(a, None, false)).collect();
                format!("{}({})", c, args_s.join(", "))
            }

            Expr::Ternary { cond, then_expr, else_expr } => {
                let c = self.print_inner(cond, None, false);
                let t = self.print_inner(then_expr, None, false);
                let e = self.print_inner(else_expr, None, false);
                format!("{c} ? {t} : {e}")
            }

            Expr::Phi(exprs) => {
                let parts: Vec<String> = exprs.iter().map(|e| self.print_inner(e, None, false)).collect();
                format!("phi({})", parts.join(", "))
            }
        };

        if needs_wrap { format!("({s})") } else { s }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Side-effect ordering
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `expr` has observable side-effects.
///
/// Side-effecting nodes: `Call`, `Load`, `Store` (encoded as assignment in
/// the AST).  Phi nodes are considered side-effect free as they are a control-
/// flow artefact.
#[must_use]
pub fn has_side_effects(expr: &Expr) -> bool {
    match expr {
        Expr::Const(_, _) | Expr::Var(_) | Expr::Phi(_) => false,
        // memory read can alias; calls are side-effecting
        Expr::Load { .. } | Expr::Call { .. } => true,
        Expr::BinOp(_, a, b) => has_side_effects(a) || has_side_effects(b),
        Expr::UnOp(_, e)     => has_side_effects(e),
        Expr::FieldAccess { base, .. } => has_side_effects(base),
        Expr::Index { base, index, .. } => has_side_effects(base) || has_side_effects(index),
        Expr::Ternary { cond, then_expr, else_expr } => {
            // The branches are not always evaluated, but the condition always
            // is.  For ordering purposes, treat ternary as side-effecting if
            // any branch is.
            has_side_effects(cond) || has_side_effects(then_expr) || has_side_effects(else_expr)
        }
    }
}

/// Return `true` if two expressions can be safely reordered (i.e. neither has
/// side effects or they do not share memory).
///
/// This is a conservative approximation.
#[must_use]
pub fn can_reorder(a: &Expr, b: &Expr) -> bool {
    !has_side_effects(a) && !has_side_effects(b)
}

// ─────────────────────────────────────────────────────────────────────────────
// Precedence table
// ─────────────────────────────────────────────────────────────────────────────

/// Return a human-readable precedence table for all `BinOp` variants.
#[must_use]
pub fn precedence_table() -> Vec<(&'static str, u8, &'static str)> {
    vec![
        ("||",  PrecedenceLevel::LOR.0,           "left"),
        ("&&",  PrecedenceLevel::LAND.0,          "left"),
        ("|",   PrecedenceLevel::BOR.0,           "left"),
        ("^",   PrecedenceLevel::BXOR.0,          "left"),
        ("&",   PrecedenceLevel::BAND.0,          "left"),
        ("==",  PrecedenceLevel::EQUALITY.0,      "left"),
        ("!=",  PrecedenceLevel::EQUALITY.0,      "left"),
        ("<",   PrecedenceLevel::RELATIONAL.0,    "none"),
        ("<=",  PrecedenceLevel::RELATIONAL.0,    "none"),
        (">",   PrecedenceLevel::RELATIONAL.0,    "none"),
        (">=",  PrecedenceLevel::RELATIONAL.0,    "none"),
        ("<<",  PrecedenceLevel::SHIFT.0,         "left"),
        (">>",  PrecedenceLevel::SHIFT.0,         "left"),
        ("+",   PrecedenceLevel::ADDITIVE.0,      "left"),
        ("-",   PrecedenceLevel::ADDITIVE.0,      "left"),
        ("*",   PrecedenceLevel::MULTIPLICATIVE.0, "left"),
        ("/",   PrecedenceLevel::MULTIPLICATIVE.0, "left"),
        ("%",   PrecedenceLevel::MULTIPLICATIVE.0, "left"),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn c(v: i64) -> Expr { Expr::Const(v, crate::IntWidth::I64) }
    fn var(n: &str) -> Expr { Expr::Var(n.to_string()) }
    fn binop(op: BinOp, a: Expr, b: Expr) -> Expr { Expr::BinOp(op, Box::new(a), Box::new(b)) }

    fn printer() -> MinimalParenPrinter { MinimalParenPrinter::new() }

    // ── needs_parens ──────────────────────────────────────────────────────────

    #[test]
    fn test_high_prec_child_no_parens() {
        // In `a + b * c`, `b * c` does not need parens (Mul > Add).
        let child = binop(BinOp::Mul, var("b"), var("c"));
        assert!(!needs_parens(BinOp::Add, &child, true));
    }

    #[test]
    fn test_low_prec_child_needs_parens() {
        // In `a * (b + c)`, the addition needs parens.
        let child = binop(BinOp::Add, var("b"), var("c"));
        assert!(needs_parens(BinOp::Mul, &child, true));
    }

    #[test]
    fn test_same_prec_right_assoc_left_no_parens() {
        // `a - b - c` → left-assoc; right operand `b - c` needs parens.
        let child = binop(BinOp::Sub, var("b"), var("c"));
        assert!(needs_parens(BinOp::Sub, &child, true));  // right → yes
        assert!(!needs_parens(BinOp::Sub, &child, false)); // left → no
    }

    #[test]
    fn test_ternary_always_needs_parens_in_binop() {
        let t = Expr::Ternary {
            cond: Box::new(var("c")),
            then_expr: Box::new(c(1)),
            else_expr: Box::new(c(0)),
        };
        assert!(needs_parens(BinOp::Add, &t, true));
    }

    // ── MinimalParenPrinter ───────────────────────────────────────────────────

    #[test]
    fn test_print_simple() {
        assert_eq!(printer().print(&var("x")), "x");
        assert_eq!(printer().print(&c(42)), "42");
    }

    #[test]
    fn test_print_no_redundant_parens() {
        // a + b * c → should NOT have parens around b * c.
        let e = binop(BinOp::Add, var("a"), binop(BinOp::Mul, var("b"), var("c")));
        let s = printer().print(&e);
        assert!(!s.contains('('));
    }

    #[test]
    fn test_print_necessary_parens() {
        // a * (b + c) → parens required.
        let e = binop(BinOp::Mul, var("a"), binop(BinOp::Add, var("b"), var("c")));
        let s = printer().print(&e);
        assert!(s.contains('('));
    }

    #[test]
    fn test_print_subtraction_left_assoc() {
        // (a - b) - c → no parens needed for left group.
        let e = binop(BinOp::Sub, binop(BinOp::Sub, var("a"), var("b")), var("c"));
        let s = printer().print(&e);
        // `a - b - c` without parens.
        assert!(!s.contains('('));
    }

    #[test]
    fn test_print_subtraction_right_group_needs_parens() {
        // a - (b - c) → parens around right group.
        let e = binop(BinOp::Sub, var("a"), binop(BinOp::Sub, var("b"), var("c")));
        let s = printer().print(&e);
        assert!(s.contains('('));
    }

    #[test]
    fn test_print_unary_neg() {
        let e = Expr::UnOp(UnOp::Neg, Box::new(var("x")));
        assert_eq!(printer().print(&e), "-x");
    }

    #[test]
    fn test_print_array_index() {
        let e = Expr::Index {
            base: Box::new(var("arr")),
            index: Box::new(var("i")),
            elem_size: 4,
        };
        let s = printer().print(&e);
        assert_eq!(s, "arr[i]");
    }

    #[test]
    fn test_print_call() {
        let e = Expr::Call {
            callee: Box::new(var("foo")),
            args: vec![c(1), var("x")],
        };
        let s = printer().print(&e);
        assert!(s.starts_with("foo("));
        assert!(s.contains('1'));
        assert!(s.contains('x'));
    }

    #[test]
    fn test_print_ternary() {
        let e = Expr::Ternary {
            cond: Box::new(var("c")),
            then_expr: Box::new(c(1)),
            else_expr: Box::new(c(0)),
        };
        let s = printer().print(&e);
        assert!(s.contains('?') && s.contains(':'));
    }

    // ── side-effect ordering ──────────────────────────────────────────────────

    #[test]
    fn test_no_side_effects_const_var() {
        assert!(!has_side_effects(&c(42)));
        assert!(!has_side_effects(&var("x")));
    }

    #[test]
    fn test_load_has_side_effects() {
        let e = Expr::Load { ptr: Box::new(var("p")), size: 4 };
        assert!(has_side_effects(&e));
    }

    #[test]
    fn test_call_has_side_effects() {
        let e = Expr::Call {
            callee: Box::new(var("f")),
            args: vec![],
        };
        assert!(has_side_effects(&e));
    }

    #[test]
    fn test_can_reorder_pure() {
        assert!(can_reorder(&c(1), &var("x")));
    }

    #[test]
    fn test_cannot_reorder_with_load() {
        let load = Expr::Load { ptr: Box::new(var("p")), size: 4 };
        assert!(!can_reorder(&load, &var("x")));
    }

    // ── precedence table ──────────────────────────────────────────────────────

    #[test]
    fn test_precedence_table_not_empty() {
        assert!(!precedence_table().is_empty());
    }

    #[test]
    fn test_precedence_mul_higher_than_add() {
        let (add_prec, _) = binop_precedence(BinOp::Add);
        let (mul_prec, _) = binop_precedence(BinOp::Mul);
        assert!(mul_prec > add_prec);
    }

    #[test]
    fn test_precedence_and_lower_than_eq() {
        let (land_prec, _) = binop_precedence(BinOp::LAnd);
        let (eq_prec, _) = binop_precedence(BinOp::Eq);
        assert!(eq_prec > land_prec);
    }
}
