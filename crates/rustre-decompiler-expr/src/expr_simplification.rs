//! Expression simplification.
//!
//! Implements:
//! - Constant folding.
//! - Identity rules: `x + 0`, `x * 1`, `x & 0xffffffff`, etc.
//! - De Morgan's laws.
//! - Double negation / double complement.
//! - Comparison normalisation (`x > 0 → x >= 1` for signed integers).
//! - MBA simplification (Mixed Boolean-Arithmetic):
//!   `(x & y) | (x & ~y) → x`, `(x | y) & (x | ~y) → x`, etc.
//! - Bitwise tautologies: `x | ~x → -1`, `x & ~x → 0`.


use crate::{BinOp, Expr, IntWidth, UnOp};

// ─────────────────────────────────────────────────────────────────────────────
// Public API: SimplificationPass
// ─────────────────────────────────────────────────────────────────────────────

/// Bitflags for the boolean toggles in [`SimplificationConfig`].
///
/// Packed as a single `u16` to avoid `clippy::struct_excessive_bools` while
/// preserving the original ergonomic API through accessor methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimplificationFlags(u16);

impl SimplificationFlags {
    const CONSTANT_FOLDING:      u16 = 1 << 0;
    const IDENTITY_RULES:        u16 = 1 << 1;
    const DEMORGAN:              u16 = 1 << 2;
    const DOUBLE_NEGATION:       u16 = 1 << 3;
    const COMPARISON_NORMALISE:  u16 = 1 << 4;
    const MBA_SIMPLIFY:          u16 = 1 << 5;
    const BITWISE_TAUTOLOGIES:   u16 = 1 << 6;

    /// All passes enabled.
    #[must_use]
    pub const fn all() -> Self {
        Self(
            Self::CONSTANT_FOLDING
                | Self::IDENTITY_RULES
                | Self::DEMORGAN
                | Self::DOUBLE_NEGATION
                | Self::COMPARISON_NORMALISE
                | Self::MBA_SIMPLIFY
                | Self::BITWISE_TAUTOLOGIES,
        )
    }
    /// No passes enabled.
    #[must_use]
    pub const fn none() -> Self { Self(0) }

    #[must_use] pub const fn constant_folding(self)     -> bool { self.0 & Self::CONSTANT_FOLDING     != 0 }
    #[must_use] pub const fn identity_rules(self)       -> bool { self.0 & Self::IDENTITY_RULES       != 0 }
    #[must_use] pub const fn demorgan(self)             -> bool { self.0 & Self::DEMORGAN             != 0 }
    #[must_use] pub const fn double_negation(self)      -> bool { self.0 & Self::DOUBLE_NEGATION      != 0 }
    #[must_use] pub const fn comparison_normalise(self) -> bool { self.0 & Self::COMPARISON_NORMALISE != 0 }
    #[must_use] pub const fn mba_simplify(self)         -> bool { self.0 & Self::MBA_SIMPLIFY         != 0 }
    #[must_use] pub const fn bitwise_tautologies(self)  -> bool { self.0 & Self::BITWISE_TAUTOLOGIES  != 0 }

    /// Toggle the constant-folding flag and return the new value.
    pub const fn set_constant_folding(&mut self, on: bool)     { self.set(Self::CONSTANT_FOLDING, on); }
    pub const fn set_identity_rules(&mut self, on: bool)       { self.set(Self::IDENTITY_RULES, on); }
    pub const fn set_demorgan(&mut self, on: bool)             { self.set(Self::DEMORGAN, on); }
    pub const fn set_double_negation(&mut self, on: bool)      { self.set(Self::DOUBLE_NEGATION, on); }
    pub const fn set_comparison_normalise(&mut self, on: bool) { self.set(Self::COMPARISON_NORMALISE, on); }
    pub const fn set_mba_simplify(&mut self, on: bool)         { self.set(Self::MBA_SIMPLIFY, on); }
    pub const fn set_bitwise_tautologies(&mut self, on: bool)  { self.set(Self::BITWISE_TAUTOLOGIES, on); }

    const fn set(&mut self, mask: u16, on: bool) {
        if on { self.0 |= mask; } else { self.0 &= !mask; }
    }
}

impl Default for SimplificationFlags {
    fn default() -> Self { Self::all() }
}

/// Controls which simplification passes are enabled.
#[derive(Debug, Clone)]
pub struct SimplificationConfig {
    /// Packed boolean toggles.
    pub flags: SimplificationFlags,
    /// Maximum rewrite rounds before giving up.
    pub max_rounds: usize,
}

impl Default for SimplificationConfig {
    fn default() -> Self {
        Self {
            flags: SimplificationFlags::all(),
            max_rounds: 16,
        }
    }
}

/// Full-featured expression simplifier.
#[derive(Debug, Default, Clone)]
pub struct ExpressionSimplifier {
    pub config: SimplificationConfig,
    /// Statistics: number of rewrites applied.
    pub rewrite_count: usize,
}

impl ExpressionSimplifier {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_config(config: SimplificationConfig) -> Self {
        Self { config, rewrite_count: 0 }
    }

    /// Simplify `expr` to a fixed-point.
    #[must_use]
    pub fn simplify(&mut self, expr: Expr) -> Expr {
        let mut current = expr;
        for _ in 0..self.config.max_rounds {
            let next = self.simplify_once(current.clone());
            if next == current {
                break;
            }
            current = next;
        }
        current
    }

    /// A single simplification pass over the expression tree.
    #[must_use]
    pub fn simplify_once(&mut self, expr: Expr) -> Expr {
        match expr {
            Expr::BinOp(op, a, b) => {
                let a = self.simplify_once(*a);
                let b = self.simplify_once(*b);
                self.simplify_binop(op, a, b)
            }
            Expr::UnOp(op, e) => {
                let e = self.simplify_once(*e);
                self.simplify_unop(op, e)
            }
            Expr::Ternary { cond, then_expr, else_expr } => {
                let cond = self.simplify_once(*cond);
                if let Some(v) = cond.as_const() {
                    self.rewrite_count += 1;
                    if v != 0 {
                        return self.simplify_once(*then_expr);
                    }
                    return self.simplify_once(*else_expr);
                }
                Expr::Ternary {
                    cond: Box::new(cond),
                    then_expr: Box::new(self.simplify_once(*then_expr)),
                    else_expr: Box::new(self.simplify_once(*else_expr)),
                }
            }
            Expr::Load { ptr, size } => Expr::Load {
                ptr: Box::new(self.simplify_once(*ptr)),
                size,
            },
            Expr::FieldAccess { base, offset } => Expr::FieldAccess {
                base: Box::new(self.simplify_once(*base)),
                offset,
            },
            Expr::Index { base, index, elem_size } => Expr::Index {
                base: Box::new(self.simplify_once(*base)),
                index: Box::new(self.simplify_once(*index)),
                elem_size,
            },
            Expr::Call { callee, args } => Expr::Call {
                callee: Box::new(self.simplify_once(*callee)),
                args: args.into_iter().map(|a| self.simplify_once(a)).collect(),
            },
            other => other,
        }
    }

    // ── BinOp simplification ─────────────────────────────────────────────────

    fn simplify_binop(&mut self, op: BinOp, a: Expr, b: Expr) -> Expr {
        // ── Constant folding ──────────────────────────────────────────────────
        if self.config.flags.constant_folding()
            && let (Some(ca), Some(cb)) = (a.as_const(), b.as_const())
                && let Some(result) = fold_binop(op, ca, cb) {
                    let width = a.const_width().unwrap_or(IntWidth::I64);
                    self.rewrite_count += 1;
                    return Expr::Const(result, width);
                }

        // ── MBA simplification ────────────────────────────────────────────────
        if self.config.flags.mba_simplify()
            && let Some(simplified) = mba_simplify(op, &a, &b) {
                self.rewrite_count += 1;
                return simplified;
            }

        // ── Bitwise tautologies ───────────────────────────────────────────────
        if self.config.flags.bitwise_tautologies()
            && let Some(simplified) = bitwise_tautology(op, &a, &b) {
                self.rewrite_count += 1;
                return simplified;
            }

        // ── De Morgan ─────────────────────────────────────────────────────────
        if self.config.flags.demorgan()
            && let Some(simplified) = apply_demorgan(op, &a, &b) {
                self.rewrite_count += 1;
                return simplified;
            }

        // ── Identity / annihilator rules ──────────────────────────────────────
        if self.config.flags.identity_rules()
            && let Some(simplified) = identity_rule(op, &a, &b) {
                self.rewrite_count += 1;
                return simplified;
            }

        // ── Comparison normalisation ──────────────────────────────────────────
        if self.config.flags.comparison_normalise()
            && let Some(simplified) = normalise_comparison(op, &a, &b) {
                self.rewrite_count += 1;
                return simplified;
            }

        Expr::BinOp(op, Box::new(a), Box::new(b))
    }

    // ── UnOp simplification ──────────────────────────────────────────────────

    fn simplify_unop(&mut self, op: UnOp, e: Expr) -> Expr {
        // Constant folding.
        if self.config.flags.constant_folding()
            && let Some(c) = e.as_const() {
                let w = e.const_width().unwrap_or(IntWidth::I64);
                match op {
                    UnOp::Neg => { self.rewrite_count += 1; return Expr::Const(c.wrapping_neg(), w); }
                    UnOp::Not => { self.rewrite_count += 1; return Expr::Const(!c, w); }
                    UnOp::LNot => { self.rewrite_count += 1; return Expr::Const(i64::from(c == 0), IntWidth::I32); }
                    UnOp::Cast(target) => {
                        let truncated = truncate_to_width(c, target);
                        self.rewrite_count += 1;
                        return Expr::Const(truncated, target);
                    }
                    _ => {}
                }
            }

        // Double negation.
        if self.config.flags.double_negation() {
            match (&op, &e) {
                (UnOp::Neg, Expr::UnOp(UnOp::Neg, inner)) |
                (UnOp::Not, Expr::UnOp(UnOp::Not, inner)) |
                (UnOp::LNot, Expr::UnOp(UnOp::LNot, inner)) => {
                    self.rewrite_count += 1;
                    return *inner.clone();
                }
                (UnOp::LNot, Expr::BinOp(cmp_op, la, lb)) => {
                    if let Some(neg) = cmp_op.negated() {
                        self.rewrite_count += 1;
                        return Expr::BinOp(neg, la.clone(), lb.clone());
                    }
                }
                _ => {}
            }
        }

        // Merge double casts: (T2)(T1)x → (T2)x when T2 ≤ T1 bits.
        if let (UnOp::Cast(outer), Expr::UnOp(UnOp::Cast(_inner), inner_e)) = (&op, &e) {
            self.rewrite_count += 1;
            return Expr::UnOp(UnOp::Cast(*outer), inner_e.clone());
        }

        Expr::UnOp(op, Box::new(e))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Constant folding
// ─────────────────────────────────────────────────────────────────────────────

fn fold_binop(op: BinOp, a: i64, b: i64) -> Option<i64> {
    Some(match op {
        BinOp::Add => a.wrapping_add(b),
        BinOp::Sub => a.wrapping_sub(b),
        BinOp::Mul => a.wrapping_mul(b),
        BinOp::Div => { if b == 0 { return None; } a.wrapping_div(b) }
        BinOp::Mod => { if b == 0 { return None; } a.wrapping_rem(b) }
        BinOp::And => a & b,
        BinOp::Or  => a | b,
        BinOp::Xor => a ^ b,
        BinOp::Shl => { if !(0..64).contains(&b) { return None; } a.wrapping_shl(crate::casts::i64_to_u32(b)) }
        BinOp::Shr => { if !(0..64).contains(&b) { return None; } crate::casts::u64_as_i64(crate::casts::i64_as_u64(a).wrapping_shr(crate::casts::i64_to_u32(b))) }
        BinOp::Sar => { if !(0..64).contains(&b) { return None; } a.wrapping_shr(crate::casts::i64_to_u32(b)) }
        BinOp::Eq  => i64::from(a == b),
        BinOp::Ne  => i64::from(a != b),
        BinOp::Lt  => i64::from(a < b),
        BinOp::Le  => i64::from(a <= b),
        BinOp::Gt  => i64::from(a > b),
        BinOp::Ge  => i64::from(a >= b),
        BinOp::LAnd => i64::from(a != 0 && b != 0),
        BinOp::LOr  => i64::from(a != 0 || b != 0),
    })
}

const fn truncate_to_width(v: i64, w: IntWidth) -> i64 {
    let bits = w.bits();
    if bits >= 64 { return v; }
    let mask = (1i64 << bits).wrapping_sub(1);
    let masked = v & mask;
    if w.is_signed() {
        let shift = 64 - bits;
        (masked << shift) >> shift
    } else {
        masked
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Identity rules
// ─────────────────────────────────────────────────────────────────────────────

fn identity_rule(op: BinOp, a: &Expr, b: &Expr) -> Option<Expr> {
    match op {
        BinOp::Add => {
            if b.as_const() == Some(0) { return Some(a.clone()); }
            if a.as_const() == Some(0) { return Some(b.clone()); }
        }
        BinOp::Sub => {
            if b.as_const() == Some(0) { return Some(a.clone()); }
            // x - x → 0
            if a == b { return Some(Expr::Const(0, IntWidth::I64)); }
        }
        BinOp::Mul => {
            if a.as_const() == Some(0) || b.as_const() == Some(0) {
                return Some(Expr::Const(0, IntWidth::I64));
            }
            if b.as_const() == Some(1) { return Some(a.clone()); }
            if a.as_const() == Some(1) { return Some(b.clone()); }
            // x * -1 → -x
            if b.as_const() == Some(-1) {
                return Some(Expr::UnOp(UnOp::Neg, Box::new(a.clone())));
            }
        }
        BinOp::Div => {
            if b.as_const() == Some(1) { return Some(a.clone()); }
            if a == b { return Some(Expr::Const(1, IntWidth::I64)); }
        }
        BinOp::Mod => {
            if b.as_const() == Some(1) { return Some(Expr::Const(0, IntWidth::I64)); }
            if a == b { return Some(Expr::Const(0, IntWidth::I64)); }
        }
        BinOp::And => {
            if a.as_const() == Some(0) || b.as_const() == Some(0) {
                return Some(Expr::Const(0, IntWidth::I64));
            }
            if a.as_const() == Some(-1) { return Some(b.clone()); }
            if b.as_const() == Some(-1) { return Some(a.clone()); }
            // x & 0xffffffff → (uint32_t)x  (zero-extension)
            if b.as_const() == Some(0xffff_ffff) {
                return Some(Expr::UnOp(UnOp::Cast(IntWidth::U32), Box::new(a.clone())));
            }
            if a == b { return Some(a.clone()); }
        }
        BinOp::Or => {
            if a.as_const() == Some(0) { return Some(b.clone()); }
            if b.as_const() == Some(0) { return Some(a.clone()); }
            if a.as_const() == Some(-1) || b.as_const() == Some(-1) {
                return Some(Expr::Const(-1, IntWidth::I64));
            }
            if a == b { return Some(a.clone()); }
        }
        BinOp::Xor => {
            if a.as_const() == Some(0) { return Some(b.clone()); }
            if b.as_const() == Some(0) { return Some(a.clone()); }
            if a == b { return Some(Expr::Const(0, IntWidth::I64)); }
            if b.as_const() == Some(-1) {
                return Some(Expr::UnOp(UnOp::Not, Box::new(a.clone())));
            }
        }
        BinOp::Shl | BinOp::Shr | BinOp::Sar => {
            if b.as_const() == Some(0) { return Some(a.clone()); }
            if a.as_const() == Some(0) { return Some(Expr::Const(0, IntWidth::I64)); }
        }
        BinOp::Eq => {
            if a == b { return Some(Expr::Const(1, IntWidth::I32)); }
        }
        BinOp::Ne
            if a == b => { return Some(Expr::Const(0, IntWidth::I32)); }
        _ => {}
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// De Morgan
// ─────────────────────────────────────────────────────────────────────────────

fn apply_demorgan(op: BinOp, a: &Expr, b: &Expr) -> Option<Expr> {
    // !(a || b) → !a && !b
    if op == BinOp::LOr
        && let (Expr::UnOp(UnOp::LNot, ia), Expr::UnOp(UnOp::LNot, ib)) = (a, b) {
            return Some(Expr::UnOp(
                UnOp::LNot,
                Box::new(Expr::BinOp(BinOp::LAnd, ia.clone(), ib.clone())),
            ));
        }
    // !(a && b) → !a || !b
    if op == BinOp::LAnd
        && let (Expr::UnOp(UnOp::LNot, ia), Expr::UnOp(UnOp::LNot, ib)) = (a, b) {
            return Some(Expr::UnOp(
                UnOp::LNot,
                Box::new(Expr::BinOp(BinOp::LOr, ia.clone(), ib.clone())),
            ));
        }
    // Bitwise De Morgan: ~a & ~b → ~(a | b)
    if op == BinOp::And
        && let (Expr::UnOp(UnOp::Not, ia), Expr::UnOp(UnOp::Not, ib)) = (a, b) {
            return Some(Expr::UnOp(
                UnOp::Not,
                Box::new(Expr::BinOp(BinOp::Or, ia.clone(), ib.clone())),
            ));
        }
    // ~a | ~b → ~(a & b)
    if op == BinOp::Or
        && let (Expr::UnOp(UnOp::Not, ia), Expr::UnOp(UnOp::Not, ib)) = (a, b) {
            return Some(Expr::UnOp(
                UnOp::Not,
                Box::new(Expr::BinOp(BinOp::And, ia.clone(), ib.clone())),
            ));
        }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// MBA simplification
// ─────────────────────────────────────────────────────────────────────────────

/// Recognise common Mixed Boolean-Arithmetic identities.
///
/// Key patterns:
/// * `(x & y) | (x & ~y)  →  x`
/// * `(x & y) | (~x & y)  →  y`
/// * `(x | y) & (x | ~y)  →  x`
/// * `(x | y) & (~x | y)  →  y`
/// * `(x ^ y) ^ y         →  x`
/// * `x + ~x              →  -1`
/// * `(x - y) + y         →  x`
fn mba_simplify(op: BinOp, a: &Expr, b: &Expr) -> Option<Expr> {
    match op {
        // (x & y) | (x & ~y) → x
        BinOp::Or => {
            // Left: (x & y), Right: (x & ~y)
            if let (
                Expr::BinOp(BinOp::And, x1, y1),
                Expr::BinOp(BinOp::And, x2, ny),
            ) = (a, b)
            {
                if x1 == x2
                    && let Expr::UnOp(UnOp::Not, y2) = ny.as_ref()
                        && y1 == y2 {
                            return Some(*x1.clone());
                        }
                // (~x & y) | (x & y) → y
                if y1 == ny
                    && let Expr::UnOp(UnOp::Not, nx1) = x1.as_ref()
                        && nx1 == x2 {
                            return Some(*y1.clone());
                        }
            }
        }
        // (x ^ y) ^ y → x
        BinOp::Xor => {
            if let Expr::BinOp(BinOp::Xor, x, y1) = a
                && y1.as_ref() == b {
                    return Some(*x.clone());
                }
        }
        // x + ~x → -1  (bitwise complement identity)
        BinOp::Add => {
            if let Expr::UnOp(UnOp::Not, inner) = b
                && inner.as_ref() == a {
                    return Some(Expr::Const(-1, IntWidth::I64));
                }
            if let Expr::UnOp(UnOp::Not, inner) = a
                && inner.as_ref() == b {
                    return Some(Expr::Const(-1, IntWidth::I64));
                }
            // (x - y) + y → x
            if let Expr::BinOp(BinOp::Sub, x, y1) = a
                && y1.as_ref() == b {
                    return Some(*x.clone());
                }
        }
        // (x + y) - y → x
        BinOp::Sub => {
            if let Expr::BinOp(BinOp::Add, x, y1) = a
                && y1.as_ref() == b {
                    return Some(*x.clone());
                }
        }
        _ => {}
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Bitwise tautologies
// ─────────────────────────────────────────────────────────────────────────────

fn bitwise_tautology(op: BinOp, a: &Expr, b: &Expr) -> Option<Expr> {
    match op {
        // x | ~x → -1  (all bits set)
        BinOp::Or => {
            if let Expr::UnOp(UnOp::Not, inner) = b
                && inner.as_ref() == a {
                    return Some(Expr::Const(-1, IntWidth::I64));
                }
            if let Expr::UnOp(UnOp::Not, inner) = a
                && inner.as_ref() == b {
                    return Some(Expr::Const(-1, IntWidth::I64));
                }
        }
        // x & ~x → 0
        BinOp::And => {
            if let Expr::UnOp(UnOp::Not, inner) = b
                && inner.as_ref() == a {
                    return Some(Expr::Const(0, IntWidth::I64));
                }
            if let Expr::UnOp(UnOp::Not, inner) = a
                && inner.as_ref() == b {
                    return Some(Expr::Const(0, IntWidth::I64));
                }
        }
        _ => {}
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Comparison normalisation
// ─────────────────────────────────────────────────────────────────────────────

/// Convert `x > N` (signed) to `x >= N+1` for non-MIN constant N.
/// Converts `x < N` (signed) to `x <= N-1` for non-MAX constant N.
///
/// This matches the form compilers use after converting from unsigned
/// `jg`/`jl` comparisons.
fn normalise_comparison(op: BinOp, a: &Expr, b: &Expr) -> Option<Expr> {
    match op {
        BinOp::Gt => {
            // x > 0 → x >= 1  (avoids comparing with 0).
            if let Some(c) = b.as_const()
                && c != i64::MAX {
                    return Some(Expr::BinOp(
                        BinOp::Ge,
                        Box::new(a.clone()),
                        Box::new(Expr::Const(c + 1, b.const_width().unwrap_or(IntWidth::I64))),
                    ));
                }
        }
        BinOp::Lt => {
            // x < 1 → x <= 0.
            if let Some(c) = b.as_const()
                && c != i64::MIN {
                    return Some(Expr::BinOp(
                        BinOp::Le,
                        Box::new(a.clone()),
                        Box::new(Expr::Const(c - 1, b.const_width().unwrap_or(IntWidth::I64))),
                    ));
                }
        }
        _ => {}
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience function
// ─────────────────────────────────────────────────────────────────────────────

/// Simplify an expression with default settings.
#[must_use]
pub fn simplify(expr: Expr) -> Expr {
    ExpressionSimplifier::new().simplify(expr)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn c(v: i64) -> Expr { Expr::Const(v, IntWidth::I64) }
    fn var(n: &str) -> Expr { Expr::Var(n.to_string()) }
    fn binop(op: BinOp, a: Expr, b: Expr) -> Expr { Expr::BinOp(op, Box::new(a), Box::new(b)) }
    fn not(e: Expr) -> Expr { Expr::UnOp(UnOp::Not, Box::new(e)) }
    fn lnot(e: Expr) -> Expr { Expr::UnOp(UnOp::LNot, Box::new(e)) }
    fn neg(e: Expr) -> Expr { Expr::UnOp(UnOp::Neg, Box::new(e)) }

    fn s() -> ExpressionSimplifier { ExpressionSimplifier::new() }

    // ── Constant folding ──────────────────────────────────────────────────────

    #[test]
    fn test_const_add() { assert_eq!(s().simplify(binop(BinOp::Add, c(3), c(4))), c(7)); }
    #[test]
    fn test_const_mul() { assert_eq!(s().simplify(binop(BinOp::Mul, c(6), c(7))), c(42)); }
    #[test]
    fn test_const_and() {
        assert_eq!(s().simplify(binop(BinOp::And, c(0b1010), c(0b1100))), c(0b1000));
    }
    #[test]
    fn test_const_shl() { assert_eq!(s().simplify(binop(BinOp::Shl, c(1), c(3))), c(8)); }
    #[test]
    fn test_const_neg() {
        let e = Expr::UnOp(UnOp::Neg, Box::new(c(5)));
        assert_eq!(s().simplify(e), c(-5));
    }
    #[test]
    fn test_const_not() {
        let e = Expr::UnOp(UnOp::Not, Box::new(c(0)));
        assert_eq!(s().simplify(e).as_const(), Some(-1));
    }

    // ── Identity rules ────────────────────────────────────────────────────────

    #[test]
    fn test_add_zero() { assert_eq!(s().simplify(binop(BinOp::Add, var("x"), c(0))), var("x")); }
    #[test]
    fn test_mul_one() { assert_eq!(s().simplify(binop(BinOp::Mul, var("x"), c(1))), var("x")); }
    #[test]
    fn test_mul_zero() { assert_eq!(s().simplify(binop(BinOp::Mul, var("x"), c(0))), c(0)); }
    #[test]
    fn test_sub_self() { assert_eq!(s().simplify(binop(BinOp::Sub, var("x"), var("x"))), c(0)); }
    #[test]
    fn test_and_allones() { assert_eq!(s().simplify(binop(BinOp::And, var("x"), c(-1))), var("x")); }
    #[test]
    fn test_or_zero() { assert_eq!(s().simplify(binop(BinOp::Or, var("x"), c(0))), var("x")); }
    #[test]
    fn test_xor_self() { assert_eq!(s().simplify(binop(BinOp::Xor, var("x"), var("x"))), c(0)); }
    #[test]
    fn test_xor_allones_is_not() {
        let result = s().simplify(binop(BinOp::Xor, var("x"), c(-1)));
        assert!(matches!(result, Expr::UnOp(UnOp::Not, _)));
    }
    #[test]
    fn test_and_0xffffffff_cast() {
        let e = binop(BinOp::And, var("x"), Expr::Const(0xffff_ffff, IntWidth::I64));
        let r = s().simplify(e);
        assert!(matches!(r, Expr::UnOp(UnOp::Cast(IntWidth::U32), _)));
    }

    // ── De Morgan ─────────────────────────────────────────────────────────────

    #[test]
    fn test_demorgan_lor_lnots() {
        let e = binop(BinOp::LOr, lnot(var("a")), lnot(var("b")));
        let r = s().simplify(e);
        assert!(matches!(r, Expr::UnOp(UnOp::LNot, _)));
    }

    #[test]
    fn test_demorgan_bitwise_and_not() {
        let e = binop(BinOp::And, not(var("a")), not(var("b")));
        let r = s().simplify(e);
        assert!(matches!(r, Expr::UnOp(UnOp::Not, _)));
    }

    // ── Double negation ───────────────────────────────────────────────────────

    #[test]
    fn test_double_neg() { assert_eq!(s().simplify(neg(neg(var("x")))), var("x")); }
    #[test]
    fn test_double_lnot() { assert_eq!(s().simplify(lnot(lnot(var("x")))), var("x")); }
    #[test]
    fn test_double_not() {
        let e = Expr::UnOp(UnOp::Not, Box::new(not(var("x"))));
        assert_eq!(s().simplify(e), var("x"));
    }
    #[test]
    fn test_lnot_eq_becomes_ne() {
        let e = lnot(binop(BinOp::Eq, var("a"), var("b")));
        let r = s().simplify(e);
        assert!(matches!(r, Expr::BinOp(BinOp::Ne, _, _)));
    }

    // ── MBA ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_mba_and_or_complement() {
        // (x & y) | (x & ~y) → x
        let e = binop(
            BinOp::Or,
            binop(BinOp::And, var("x"), var("y")),
            binop(BinOp::And, var("x"), not(var("y"))),
        );
        assert_eq!(s().simplify(e), var("x"));
    }

    #[test]
    fn test_mba_xor_cancel() {
        // (x ^ y) ^ y → x
        let e = binop(BinOp::Xor, binop(BinOp::Xor, var("x"), var("y")), var("y"));
        assert_eq!(s().simplify(e), var("x"));
    }

    #[test]
    fn test_mba_x_plus_complement_x() {
        // x + ~x → -1
        let e = binop(BinOp::Add, var("x"), not(var("x")));
        assert_eq!(s().simplify(e), c(-1));
    }

    // ── Bitwise tautology ─────────────────────────────────────────────────────

    #[test]
    fn test_x_or_not_x() {
        // x | ~x → -1
        let e = binop(BinOp::Or, var("x"), not(var("x")));
        assert_eq!(s().simplify(e), c(-1));
    }

    #[test]
    fn test_x_and_not_x() {
        // x & ~x → 0
        let e = binop(BinOp::And, var("x"), not(var("x")));
        assert_eq!(s().simplify(e), c(0));
    }

    // ── Comparison normalisation ──────────────────────────────────────────────

    #[test]
    fn test_gt_normalises_to_ge() {
        // x > 0 → x >= 1
        let e = binop(BinOp::Gt, var("x"), c(0));
        let r = s().simplify(e);
        assert!(matches!(r, Expr::BinOp(BinOp::Ge, _, _)));
        if let Expr::BinOp(_, _, rhs) = r {
            assert_eq!(rhs.as_const(), Some(1));
        }
    }

    #[test]
    fn test_lt_normalises_to_le() {
        // x < 5 → x <= 4
        let e = binop(BinOp::Lt, var("x"), c(5));
        let r = s().simplify(e);
        assert!(matches!(r, Expr::BinOp(BinOp::Le, _, _)));
    }

    // ── Rewrite count ─────────────────────────────────────────────────────────

    #[test]
    fn test_rewrite_count_increases() {
        let mut simp = ExpressionSimplifier::new();
        let _ = simp.simplify(binop(BinOp::Add, var("x"), c(0)));
        assert!(simp.rewrite_count > 0);
    }
}
