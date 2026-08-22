//! Peephole optimizer for lifted x86 IR.
//!
//! Operates on a `Vec<Effect>` (the output of the lifter for a single
//! instruction or a linear block) and applies a set of algebraic rewrites
//! that reduce the IR to a canonical, minimal form before the instruction
//! stream is handed to the MLIL lifting pass.
//!
//! ## Rewrites implemented
//!
//! **Constant folding** (via `x86_eval::fold_expr`):
//!   - `Add(Const(3), Const(4))` → `Const(7)`
//!   - `CmpEqZero(Const(0))` → `Const(1)`
//!
//! **Identity elimination**:
//!   - `Add(x, Const(0))` → `x`
//!   - `Sub(x, Const(0))` → `x`
//!   - `Mul(x, Const(1))` → `x`
//!   - `And(x, Const(0))` → `Const(0)`
//!   - `Or(x, Const(0))` → `x`
//!   - `Xor(x, Const(0))` → `x`
//!   - `Shl(x, Const(0))` → `x`
//!   - `Shr(x, Const(0))` → `x`
//!   - `Not(Not(x))` → `x`
//!
//! **Self-cancellation**:
//!   - `Xor(x, x)` (where x is the same register) → `Const(0)`
//!   - `Sub(x, x)` → `Const(0)`
//!   - `And(x, x)` → `x`
//!   - `Or(x, x)` → `x`
//!
//! **Dead-code elimination**:
//!   - `RegWrite` to a temporary `__tN` that is never read again in the block.
//!   - Flag writes (`cf`, `pf`, etc.) that are not read by any subsequent
//!     instruction in the block (requires backward liveness info).
//!
//! **Strength reduction**:
//!   - `Mul(x, Const(2))` → `Add(x, x)` (avoids multiply)
//!   - `Mul(x, Const(4))` → `Shl(x, Const(2))`
//!   - `Mul(x, Const(8))` → `Shl(x, Const(3))`
//!
//! ## Design
//!
//! All rewrites are structural: they never introduce new side effects and
//! never change observable semantics for concrete inputs. The pass is
//! **idempotent**: applying it twice produces the same result as applying
//! it once.

use crate::x86_eval::fold_expr;
use crate::{Effect, IrExpr};
use std::collections::HashSet;

// ─────────────────────────────────────────────────────────────────────────────
// Expression rewriting
// ─────────────────────────────────────────────────────────────────────────────

/// Apply all algebraic rewrites to an `IrExpr`, returning the simplified form.
/// Recursively simplifies sub-expressions bottom-up.
#[must_use]
pub fn simplify_expr(expr: &IrExpr) -> IrExpr {
    // First, constant-fold the expression tree.
    let folded = fold_expr(expr);
    // Then apply structural identities.
    apply_identities(&folded)
}

fn apply_identities_arith(expr: &IrExpr) -> Option<IrExpr> {
    match expr {
        IrExpr::Mul(a, b) => {
            let sa = apply_identities(a);
            let sb = apply_identities(b);
            // x * 0 → 0
            if matches!(&sb, IrExpr::Const(0)) || matches!(&sa, IrExpr::Const(0)) {
                return Some(IrExpr::Const(0));
            }
            // x * 1 → x
            if matches!(&sb, IrExpr::Const(1)) {
                return Some(sa);
            }
            if matches!(&sa, IrExpr::Const(1)) {
                return Some(sb);
            }
            // x * 2 → x + x
            if matches!(&sb, IrExpr::Const(2)) {
                return Some(IrExpr::Add(Box::new(sa.clone()), Box::new(sa)));
            }
            // x * 4 → x << 2
            if matches!(&sb, IrExpr::Const(4)) {
                return Some(IrExpr::Shl(Box::new(sa), Box::new(IrExpr::Const(2))));
            }
            // x * 8 → x << 3
            if matches!(&sb, IrExpr::Const(8)) {
                return Some(IrExpr::Shl(Box::new(sa), Box::new(IrExpr::Const(3))));
            }
            // x * 16 → x << 4
            if matches!(&sb, IrExpr::Const(16)) {
                return Some(IrExpr::Shl(Box::new(sa), Box::new(IrExpr::Const(4))));
            }
            Some(IrExpr::Mul(Box::new(sa), Box::new(sb)))
        }
        IrExpr::And(a, b) => {
            let sa = apply_identities(a);
            let sb = apply_identities(b);
            if matches!(&sb, IrExpr::Const(0)) || matches!(&sa, IrExpr::Const(0)) {
                return Some(IrExpr::Const(0));
            }
            if let (IrExpr::Reg(ra), IrExpr::Reg(rb)) = (&sa, &sb)
                && ra == rb {
                    return Some(sa);
                }
            Some(IrExpr::And(Box::new(sa), Box::new(sb)))
        }
        IrExpr::Or(a, b) => {
            let sa = apply_identities(a);
            let sb = apply_identities(b);
            if matches!(&sb, IrExpr::Const(0)) { return Some(sa); }
            if matches!(&sa, IrExpr::Const(0)) { return Some(sb); }
            if let (IrExpr::Reg(ra), IrExpr::Reg(rb)) = (&sa, &sb)
                && ra == rb {
                    return Some(sa);
                }
            Some(IrExpr::Or(Box::new(sa), Box::new(sb)))
        }
        IrExpr::Xor(a, b) => {
            let sa = apply_identities(a);
            let sb = apply_identities(b);
            if matches!(&sb, IrExpr::Const(0)) { return Some(sa); }
            if matches!(&sa, IrExpr::Const(0)) { return Some(sb); }
            if let (IrExpr::Reg(ra), IrExpr::Reg(rb)) = (&sa, &sb)
                && ra == rb {
                    return Some(IrExpr::Const(0));
                }
            Some(IrExpr::Xor(Box::new(sa), Box::new(sb)))
        }
        _ => None,
    }
}

fn apply_identities_shifts_cmps(expr: &IrExpr) -> Option<IrExpr> {
    match expr {
        IrExpr::Shl(a, b) => {
            let sa = apply_identities(a);
            let sb = apply_identities(b);
            if matches!(&sb, IrExpr::Const(0)) { return Some(sa); }
            if matches!(&sa, IrExpr::Const(0)) { return Some(IrExpr::Const(0)); }
            Some(IrExpr::Shl(Box::new(sa), Box::new(sb)))
        }
        IrExpr::Shr(a, b) => {
            let sa = apply_identities(a);
            let sb = apply_identities(b);
            if matches!(&sb, IrExpr::Const(0)) { return Some(sa); }
            if matches!(&sa, IrExpr::Const(0)) { return Some(IrExpr::Const(0)); }
            Some(IrExpr::Shr(Box::new(sa), Box::new(sb)))
        }
        IrExpr::CmpEq(a, b) => {
            Some(IrExpr::CmpEq(Box::new(apply_identities(a)), Box::new(apply_identities(b))))
        }
        IrExpr::CmpLt(a, b) => {
            Some(IrExpr::CmpLt(Box::new(apply_identities(a)), Box::new(apply_identities(b))))
        }
        IrExpr::CmpGt(a, b) => {
            Some(IrExpr::CmpGt(Box::new(apply_identities(a)), Box::new(apply_identities(b))))
        }
        IrExpr::Eq(a, b) => {
            Some(IrExpr::Eq(Box::new(apply_identities(a)), Box::new(apply_identities(b))))
        }
        IrExpr::Ne(a, b) => {
            Some(IrExpr::Ne(Box::new(apply_identities(a)), Box::new(apply_identities(b))))
        }
        IrExpr::IfThenElse(c, t, e) => Some(IrExpr::IfThenElse(
            Box::new(apply_identities(c)),
            Box::new(apply_identities(t)),
            Box::new(apply_identities(e)),
        )),
        _ => None,
    }
}

fn apply_identities(expr: &IrExpr) -> IrExpr {
    match expr {
        IrExpr::Const(_) | IrExpr::Reg(_) | IrExpr::Undef => expr.clone(),

        // Double NOT: Not(Not(x)) → x
        IrExpr::Not(inner) => {
            let si = apply_identities(inner);
            if let IrExpr::Not(inner2) = &si {
                apply_identities(inner2)
            } else {
                IrExpr::Not(Box::new(si))
            }
        }

        IrExpr::CmpEqZero(inner) => IrExpr::CmpEqZero(Box::new(apply_identities(inner))),
        IrExpr::Parity(inner) => IrExpr::Parity(Box::new(apply_identities(inner))),
        IrExpr::Deref(addr, size) => IrExpr::Deref(Box::new(apply_identities(addr)), *size),

        // ADD
        IrExpr::Add(a, b) => {
            let sa = apply_identities(a);
            let sb = apply_identities(b);
            if matches!(&sb, IrExpr::Const(0)) { return sa; }
            if matches!(&sa, IrExpr::Const(0)) { return sb; }
            IrExpr::Add(Box::new(sa), Box::new(sb))
        }

        // SUB
        IrExpr::Sub(a, b) => {
            let sa = apply_identities(a);
            let sb = apply_identities(b);
            if matches!(&sb, IrExpr::Const(0)) { return sa; }
            if let (IrExpr::Reg(ra), IrExpr::Reg(rb)) = (&sa, &sb)
                && ra == rb {
                    return IrExpr::Const(0);
                }
            IrExpr::Sub(Box::new(sa), Box::new(sb))
        }

        other => apply_identities_arith(other)
            .or_else(|| apply_identities_shifts_cmps(other))
            .unwrap_or_else(|| apply_identities_rest(other)),
    }
}

fn apply_identities_rest(expr: &IrExpr) -> IrExpr {
    match expr {
        // AND
        IrExpr::And(a, b) => {
            let sa = apply_identities(a);
            let sb = apply_identities(b);
            // x & 0 → 0
            if matches!(&sb, IrExpr::Const(0)) || matches!(&sa, IrExpr::Const(0)) {
                return IrExpr::Const(0);
            }
            // x & x → x
            if let (IrExpr::Reg(ra), IrExpr::Reg(rb)) = (&sa, &sb)
                && ra == rb {
                    return sa;
                }
            IrExpr::And(Box::new(sa), Box::new(sb))
        }

        // OR
        IrExpr::Or(a, b) => {
            let sa = apply_identities(a);
            let sb = apply_identities(b);
            // x | 0 → x
            if matches!(&sb, IrExpr::Const(0)) {
                return sa;
            }
            if matches!(&sa, IrExpr::Const(0)) {
                return sb;
            }
            // x | x → x
            if let (IrExpr::Reg(ra), IrExpr::Reg(rb)) = (&sa, &sb)
                && ra == rb {
                    return sa;
                }
            IrExpr::Or(Box::new(sa), Box::new(sb))
        }

        // XOR
        IrExpr::Xor(a, b) => {
            let sa = apply_identities(a);
            let sb = apply_identities(b);
            // x ^ 0 → x
            if matches!(&sb, IrExpr::Const(0)) {
                return sa;
            }
            if matches!(&sa, IrExpr::Const(0)) {
                return sb;
            }
            // x ^ x → 0
            if let (IrExpr::Reg(ra), IrExpr::Reg(rb)) = (&sa, &sb)
                && ra == rb {
                    return IrExpr::Const(0);
                }
            IrExpr::Xor(Box::new(sa), Box::new(sb))
        }

        // SHL
        IrExpr::Shl(a, b) => {
            let sa = apply_identities(a);
            let sb = apply_identities(b);
            if matches!(&sb, IrExpr::Const(0)) { return sa; }
            if matches!(&sa, IrExpr::Const(0)) { return IrExpr::Const(0); }
            IrExpr::Shl(Box::new(sa), Box::new(sb))
        }

        // SHR
        IrExpr::Shr(a, b) => {
            let sa = apply_identities(a);
            let sb = apply_identities(b);
            if matches!(&sb, IrExpr::Const(0)) { return sa; }
            if matches!(&sa, IrExpr::Const(0)) { return IrExpr::Const(0); }
            IrExpr::Shr(Box::new(sa), Box::new(sb))
        }

        IrExpr::CmpEq(a, b) => {
            IrExpr::CmpEq(Box::new(apply_identities(a)), Box::new(apply_identities(b)))
        }
        IrExpr::CmpLt(a, b) => {
            IrExpr::CmpLt(Box::new(apply_identities(a)), Box::new(apply_identities(b)))
        }
        IrExpr::CmpGt(a, b) => {
            IrExpr::CmpGt(Box::new(apply_identities(a)), Box::new(apply_identities(b)))
        }
        IrExpr::Eq(a, b) => {
            IrExpr::Eq(Box::new(apply_identities(a)), Box::new(apply_identities(b)))
        }
        IrExpr::Ne(a, b) => {
            IrExpr::Ne(Box::new(apply_identities(a)), Box::new(apply_identities(b)))
        }
        IrExpr::IfThenElse(c, t, e) => IrExpr::IfThenElse(
            Box::new(apply_identities(c)),
            Box::new(apply_identities(t)),
            Box::new(apply_identities(e)),
        ),
        other => other.clone(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Effect simplification
// ─────────────────────────────────────────────────────────────────────────────

/// Simplify all `IrExpr` trees within a single `Effect`.
#[must_use]
pub fn simplify_effect(eff: &Effect) -> Effect {
    match eff {
        Effect::RegWrite { reg, value } => Effect::RegWrite {
            reg: reg.clone(),
            value: simplify_expr(value),
        },
        Effect::MemWrite { addr, value, size } => Effect::MemWrite {
            addr: simplify_expr(addr),
            value: simplify_expr(value),
            size: *size,
        },
        Effect::MemRead { addr, dest, size } => Effect::MemRead {
            addr: simplify_expr(addr),
            dest: dest.clone(),
            size: *size,
        },
        Effect::Call { target } => Effect::Call {
            target: simplify_expr(target),
        },
        Effect::Branch { target, condition } => Effect::Branch {
            target: simplify_expr(target),
            condition: condition.as_ref().map(simplify_expr),
        },
        Effect::Return { value } => Effect::Return {
            value: value.as_ref().map(simplify_expr),
        },
        Effect::Syscall { nr } => Effect::Syscall {
            nr: simplify_expr(nr),
        },
        Effect::Intrinsic { name, args } => Effect::Intrinsic {
            name: name.clone(),
            args: args.iter().map(simplify_expr).collect(),
        },
        Effect::Trap { vector } => Effect::Trap { vector: *vector },
        Effect::ConditionalTrap { condition, vector } => Effect::ConditionalTrap {
            condition: simplify_expr(condition),
            vector: *vector,
        },
        Effect::NoReturn => Effect::NoReturn,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Dead-code elimination
// ─────────────────────────────────────────────────────────────────────────────

const X86_FLAGS: [&str; 8] = ["cf", "pf", "af", "zf", "sf", "of", "df", "if"];

/// Eliminate dead `RegWrite` effects from a slice.
///
/// An effect is dead if it is a `RegWrite` to a name that:
///   1. is a temporary (`__tN` prefix) **and** is not read by any subsequent
///      effect in the slice, or
///   2. is a flag register **and** is not read by any subsequent effect.
///
/// The pass is conservative: it only eliminates within the given slice;
/// effects at the boundary of basic blocks are left alive.
#[must_use]
pub fn eliminate_dead_writes(effects: &[Effect]) -> Vec<Effect> {
    // Build the set of all registers read by effects *after* each position.
    // We do this in a backward pass.
    let n = effects.len();
    let mut live_after: Vec<HashSet<String>> = vec![HashSet::new(); n + 1];

    for i in (0..n).rev() {
        // Standard backward liveness: live_in = use(i) ∪ (live_out(i) − def(i)).
        //
        // The kill MUST be applied before the uses are added, otherwise an
        // effect that both reads and writes the same register (e.g.
        // `__t0 = __t0 + 1`) has its own read killed by its own write, and the
        // producing write earlier in the block is then wrongly considered dead.
        let mut live = live_after[i + 1].clone();
        // Remove what is defined by effect i (killed).
        for r in effects[i].written_registers() {
            live.remove(&r);
        }
        // Add all registers read by effect i (a use always makes it live-in).
        for r in effects[i].read_registers() {
            live.insert(r);
        }
        live_after[i] = live;
    }

    // Now filter: drop writes to temporaries or flags that are dead.
    let mut result = Vec::with_capacity(n);
    for (i, eff) in effects.iter().enumerate() {
        if let Effect::RegWrite { reg, .. } = eff {
            let is_temp = reg.starts_with("__t");
            let is_flag = X86_FLAGS.contains(&reg.as_str());
            if (is_temp || is_flag) && !live_after[i + 1].contains(reg.as_str()) {
                // Dead write — skip it.
                continue;
            }
        }
        result.push(simplify_effect(eff));
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Full optimisation pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Apply the full peephole optimisation pipeline to an effect slice:
///
///   1. simplify all expressions (constant fold + identities),
///   2. eliminate dead writes (temporaries and flags not read later).
///
/// The pass is run until a fixed point is reached (max 8 iterations).
#[must_use]
pub fn optimise_effects(effects: &[Effect]) -> Vec<Effect> {
    let mut current: Vec<Effect> = effects.to_vec();
    for _ in 0..8 {
        let next = eliminate_dead_writes(&current);
        if effects_equal(&next, &current) {
            return next;
        }
        current = next;
    }
    current
}

/// Shallow structural equality check for two effect slices.
fn effects_equal(a: &[Effect], b: &[Effect]) -> bool {
    a == b
}

// ─────────────────────────────────────────────────────────────────────────────
// Optimisation statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of what the optimiser did to a single block.
#[derive(Debug, Clone, Default)]
pub struct OptStats {
    /// Number of effects before optimisation.
    pub effects_before: usize,
    /// Number of effects after optimisation.
    pub effects_after: usize,
    /// Number of constant foldings applied.
    pub folds_applied: usize,
    /// Number of dead writes eliminated.
    pub dead_writes_removed: usize,
}

impl OptStats {
    /// Compute stats by running the optimiser and comparing before/after.
    #[must_use]
    pub fn from_effects(effects: &[Effect]) -> Self {
        let before = effects.len();
        let opt = optimise_effects(effects);
        let after = opt.len();
        Self {
            effects_before: before,
            effects_after: after,
            folds_applied: 0, // would require instrumenting simplify_expr
            dead_writes_removed: before.saturating_sub(after),
        }
    }

    /// Fraction of effects eliminated (0.0–1.0).
    #[must_use]
    pub fn reduction_ratio(&self) -> f64 {
        if self.effects_before == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.dead_writes_removed).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.effects_before).unwrap_or(u32::MAX))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Effect, IrExpr};

    // ── simplify_expr ────────────────────────────────────────────────────────

    #[test]
    fn simplify_const() {
        assert_eq!(simplify_expr(&IrExpr::Const(42)), IrExpr::Const(42));
    }

    #[test]
    fn simplify_add_zero_right() {
        let e = IrExpr::Add(
            Box::new(IrExpr::Reg("rax".into())),
            Box::new(IrExpr::Const(0)),
        );
        assert_eq!(simplify_expr(&e), IrExpr::Reg("rax".into()));
    }

    #[test]
    fn simplify_add_zero_left() {
        let e = IrExpr::Add(
            Box::new(IrExpr::Const(0)),
            Box::new(IrExpr::Reg("rax".into())),
        );
        assert_eq!(simplify_expr(&e), IrExpr::Reg("rax".into()));
    }

    #[test]
    fn simplify_sub_zero() {
        let e = IrExpr::Sub(
            Box::new(IrExpr::Reg("rbx".into())),
            Box::new(IrExpr::Const(0)),
        );
        assert_eq!(simplify_expr(&e), IrExpr::Reg("rbx".into()));
    }

    #[test]
    fn simplify_sub_self() {
        let e = IrExpr::Sub(
            Box::new(IrExpr::Reg("rcx".into())),
            Box::new(IrExpr::Reg("rcx".into())),
        );
        assert_eq!(simplify_expr(&e), IrExpr::Const(0));
    }

    #[test]
    fn simplify_mul_one() {
        let e = IrExpr::Mul(
            Box::new(IrExpr::Reg("rdx".into())),
            Box::new(IrExpr::Const(1)),
        );
        assert_eq!(simplify_expr(&e), IrExpr::Reg("rdx".into()));
    }

    #[test]
    fn simplify_mul_zero() {
        let e = IrExpr::Mul(
            Box::new(IrExpr::Reg("rsi".into())),
            Box::new(IrExpr::Const(0)),
        );
        assert_eq!(simplify_expr(&e), IrExpr::Const(0));
    }

    #[test]
    fn simplify_mul_by_2_is_add() {
        let e = IrExpr::Mul(
            Box::new(IrExpr::Reg("rdi".into())),
            Box::new(IrExpr::Const(2)),
        );
        match simplify_expr(&e) {
            IrExpr::Add(a, b) => {
                assert_eq!(*a, IrExpr::Reg("rdi".into()));
                assert_eq!(*b, IrExpr::Reg("rdi".into()));
            }
            other => panic!("expected Add, got {other:?}"),
        }
    }

    #[test]
    fn simplify_mul_by_4_is_shl_2() {
        let e = IrExpr::Mul(
            Box::new(IrExpr::Reg("r8".into())),
            Box::new(IrExpr::Const(4)),
        );
        assert_eq!(
            simplify_expr(&e),
            IrExpr::Shl(
                Box::new(IrExpr::Reg("r8".into())),
                Box::new(IrExpr::Const(2))
            )
        );
    }

    #[test]
    fn simplify_mul_by_8_is_shl_3() {
        let e = IrExpr::Mul(
            Box::new(IrExpr::Reg("r9".into())),
            Box::new(IrExpr::Const(8)),
        );
        assert_eq!(
            simplify_expr(&e),
            IrExpr::Shl(
                Box::new(IrExpr::Reg("r9".into())),
                Box::new(IrExpr::Const(3))
            )
        );
    }

    #[test]
    fn simplify_and_zero() {
        let e = IrExpr::And(
            Box::new(IrExpr::Reg("rax".into())),
            Box::new(IrExpr::Const(0)),
        );
        assert_eq!(simplify_expr(&e), IrExpr::Const(0));
    }

    #[test]
    fn simplify_and_self() {
        let e = IrExpr::And(
            Box::new(IrExpr::Reg("rbx".into())),
            Box::new(IrExpr::Reg("rbx".into())),
        );
        assert_eq!(simplify_expr(&e), IrExpr::Reg("rbx".into()));
    }

    #[test]
    fn simplify_or_zero() {
        let e = IrExpr::Or(
            Box::new(IrExpr::Const(0)),
            Box::new(IrExpr::Reg("rcx".into())),
        );
        assert_eq!(simplify_expr(&e), IrExpr::Reg("rcx".into()));
    }

    #[test]
    fn simplify_or_self() {
        let e = IrExpr::Or(
            Box::new(IrExpr::Reg("rdx".into())),
            Box::new(IrExpr::Reg("rdx".into())),
        );
        assert_eq!(simplify_expr(&e), IrExpr::Reg("rdx".into()));
    }

    #[test]
    fn simplify_xor_zero() {
        let e = IrExpr::Xor(
            Box::new(IrExpr::Reg("rsi".into())),
            Box::new(IrExpr::Const(0)),
        );
        assert_eq!(simplify_expr(&e), IrExpr::Reg("rsi".into()));
    }

    #[test]
    fn simplify_xor_self() {
        let e = IrExpr::Xor(
            Box::new(IrExpr::Reg("rdi".into())),
            Box::new(IrExpr::Reg("rdi".into())),
        );
        assert_eq!(simplify_expr(&e), IrExpr::Const(0));
    }

    #[test]
    fn simplify_shl_zero() {
        let e = IrExpr::Shl(
            Box::new(IrExpr::Reg("r10".into())),
            Box::new(IrExpr::Const(0)),
        );
        assert_eq!(simplify_expr(&e), IrExpr::Reg("r10".into()));
    }

    #[test]
    fn simplify_shr_zero() {
        let e = IrExpr::Shr(
            Box::new(IrExpr::Reg("r11".into())),
            Box::new(IrExpr::Const(0)),
        );
        assert_eq!(simplify_expr(&e), IrExpr::Reg("r11".into()));
    }

    #[test]
    fn simplify_double_not() {
        let e = IrExpr::Not(Box::new(IrExpr::Not(Box::new(IrExpr::Reg("rax".into())))));
        assert_eq!(simplify_expr(&e), IrExpr::Reg("rax".into()));
    }

    #[test]
    fn simplify_nested_consts() {
        // (3 + 4) * 0 → 0
        let inner = IrExpr::Add(Box::new(IrExpr::Const(3)), Box::new(IrExpr::Const(4)));
        let outer = IrExpr::Mul(Box::new(inner), Box::new(IrExpr::Const(0)));
        assert_eq!(simplify_expr(&outer), IrExpr::Const(0));
    }

    #[test]
    fn simplify_cmp_eq_zero_const() {
        let e = IrExpr::CmpEqZero(Box::new(IrExpr::Const(5)));
        assert_eq!(simplify_expr(&e), IrExpr::Const(0));
    }

    #[test]
    fn simplify_shl_zero_base() {
        let e = IrExpr::Shl(
            Box::new(IrExpr::Const(0)),
            Box::new(IrExpr::Reg("rcx".into())),
        );
        assert_eq!(simplify_expr(&e), IrExpr::Const(0));
    }

    // ── simplify_effect ──────────────────────────────────────────────────────

    #[test]
    fn simplify_effect_reg_write() {
        let e = Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Add(
                Box::new(IrExpr::Const(0)),
                Box::new(IrExpr::Reg("rbx".into())),
            ),
        };
        match simplify_effect(&e) {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "rax");
                assert_eq!(value, IrExpr::Reg("rbx".into()));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn simplify_effect_branch_const_cond() {
        let e = Effect::Branch {
            target: IrExpr::Const(0x0040_1000),
            condition: Some(IrExpr::Xor(
                Box::new(IrExpr::Reg("zf".into())),
                Box::new(IrExpr::Const(0)),
            )),
        };
        match simplify_effect(&e) {
            Effect::Branch {
                condition: Some(c), ..
            } => {
                assert_eq!(c, IrExpr::Reg("zf".into()));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ── eliminate_dead_writes ────────────────────────────────────────────────

    #[test]
    fn dce_keeps_live_reg_write() {
        let effects = vec![
            Effect::RegWrite {
                reg: "rax".into(),
                value: IrExpr::Const(1),
            },
            Effect::RegWrite {
                reg: "rbx".into(),
                value: IrExpr::Add(
                    Box::new(IrExpr::Reg("rax".into())),
                    Box::new(IrExpr::Const(1)),
                ),
            },
        ];
        let opt = eliminate_dead_writes(&effects);
        // rax is live because rbx reads it; both should remain.
        assert_eq!(opt.len(), 2);
    }

    #[test]
    fn dce_removes_dead_flag_write() {
        // zf is written but never read → should be eliminated.
        let effects = vec![
            Effect::RegWrite {
                reg: "zf".into(),
                value: IrExpr::Const(1),
            },
            Effect::RegWrite {
                reg: "rax".into(),
                value: IrExpr::Const(5),
            },
        ];
        let opt = eliminate_dead_writes(&effects);
        // The zf write is dead; rax write should survive.
        let has_rax = opt
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rax"));
        assert!(has_rax, "rax should survive");
        let has_dead_zf = opt
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "zf"));
        assert!(!has_dead_zf, "dead zf should be eliminated");
    }

    #[test]
    fn dce_keeps_flag_if_read() {
        let effects = vec![
            Effect::RegWrite {
                reg: "zf".into(),
                value: IrExpr::Const(1),
            },
            Effect::Branch {
                target: IrExpr::Const(0x0040_1000),
                condition: Some(IrExpr::Reg("zf".into())),
            },
        ];
        let opt = eliminate_dead_writes(&effects);
        // zf is read by the branch → must survive.
        let has_zf = opt
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "zf"));
        assert!(has_zf, "live zf should not be eliminated");
    }

    #[test]
    fn dce_removes_dead_temp() {
        // __t0 is written but never read.
        let effects = vec![
            Effect::RegWrite {
                reg: "__t0".into(),
                value: IrExpr::Const(42),
            },
            Effect::RegWrite {
                reg: "rax".into(),
                value: IrExpr::Const(1),
            },
        ];
        let opt = eliminate_dead_writes(&effects);
        let has_temp = opt
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "__t0"));
        assert!(!has_temp, "dead temp should be eliminated");
    }

    #[test]
    fn dce_keeps_mem_write() {
        // Memory writes always have side effects and are never eliminated.
        let effects = vec![Effect::MemWrite {
            addr: IrExpr::Const(0x1000),
            value: IrExpr::Const(0),
            size: 8,
        }];
        let opt = eliminate_dead_writes(&effects);
        assert_eq!(opt.len(), 1);
    }

    // ── optimise_effects ────────────────────────────────────────────────────

    #[test]
    fn opt_idempotent() {
        let effects = vec![
            Effect::RegWrite {
                reg: "rax".into(),
                value: IrExpr::Add(
                    Box::new(IrExpr::Const(0)),
                    Box::new(IrExpr::Reg("rbx".into())),
                ),
            },
            Effect::RegWrite {
                reg: "zf".into(),
                value: IrExpr::Const(0),
            },
        ];
        let first = optimise_effects(&effects);
        let second = optimise_effects(&first);
        assert_eq!(first.len(), second.len());
    }

    #[test]
    fn opt_reduces_xor_self_zeroing() {
        // xor rax, rax idiom: produces Const(0) after simplification.
        let effects = vec![Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Xor(
                Box::new(IrExpr::Reg("rax".into())),
                Box::new(IrExpr::Reg("rax".into())),
            ),
        }];
        let opt = optimise_effects(&effects);
        assert_eq!(opt.len(), 1);
        match &opt[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "rax");
                assert_eq!(*value, IrExpr::Const(0));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ── OptStats ────────────────────────────────────────────────────────────

    #[test]
    fn opt_stats_zero_reduction_for_live_writes() {
        let effects = vec![Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Const(1),
        }];
        let s = OptStats::from_effects(&effects);
        assert_eq!(s.effects_before, 1);
        // rax is not a temp or flag, so it survives.
        assert_eq!(s.effects_after, 1);
        assert_eq!(s.dead_writes_removed, 0);
    }

    #[test]
    fn opt_stats_reduction_ratio_empty() {
        let s = OptStats::default();
        assert_eq!(s.reduction_ratio(), 0.0);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Property-based tests (per the standing enterprise-hardening mandate's
    // request for deeper rustre-il test coverage — second module covered
    // in rustre-il-lift after `x86_eval::eval_expr`; this one is chosen
    // because the module's own doc comment claims the pass "never changes
    // observable semantics for concrete inputs" — a genuine, testable
    // correctness invariant, not just no-panic).
    // ─────────────────────────────────────────────────────────────────────
    mod proptests {
        use super::*;
        use crate::x86_eval::{X86CpuState, diff_states, exec_effects};
        use proptest::prelude::*;

        fn ir_expr() -> impl Strategy<Value = IrExpr> {
            let leaf = prop_oneof![
                any::<u16>().prop_map(|v| IrExpr::Const(u64::from(v))),
                prop_oneof![Just("eax"), Just("ebx"), Just("ecx")]
                    .prop_map(|r| IrExpr::Reg(r.to_string())),
            ];
            leaf.prop_recursive(4, 32, 4, |inner| {
                prop_oneof![
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| IrExpr::Add(Box::new(a), Box::new(b))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| IrExpr::Sub(Box::new(a), Box::new(b))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| IrExpr::And(Box::new(a), Box::new(b))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| IrExpr::Or(Box::new(a), Box::new(b))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| IrExpr::Xor(Box::new(a), Box::new(b))),
                    inner.prop_map(|a| IrExpr::Not(Box::new(a))),
                ]
            })
        }

        fn effect() -> impl Strategy<Value = Effect> {
            prop_oneof![
                (prop_oneof![Just("eax"), Just("ebx"), Just("ecx"), Just("__t0")], ir_expr())
                    .prop_map(|(reg, value)| Effect::RegWrite { reg: reg.to_string(), value }),
            ]
        }

        proptest! {
            /// The peephole optimizer must never panic on an arbitrary
            /// effect sequence.
            #[test]
            fn optimise_effects_never_panics(effects in prop::collection::vec(effect(), 0..12)) {
                let _ = optimise_effects(&effects);
            }

            /// Semantic preservation (the module's own documented
            /// contract): running the ORIGINAL effect sequence and the
            /// OPTIMIZED one against fresh, identical CPU states must never
            /// leave the optimized state DISAGREEING with a concretely-
            /// known original value. Static rewrites like the module's own
            /// documented `Sub(x, x) -> Const(0)` self-cancellation are
            /// mathematically sound for ANY runtime value of `x` — so the
            /// optimizer legitimately turns some `Unknown` results (where
            /// the plain interpreter conservatively propagates unknown
            /// register values through an op it doesn't special-case) into
            /// concrete ones. That's a precision REFINEMENT, not a
            /// semantic change, so only flag a diff when the original
            /// value was ALREADY concrete and the optimized value
            /// disagrees with it — a genuine contradiction.
            #[test]
            fn optimise_effects_preserves_semantics(effects in prop::collection::vec(effect(), 0..12)) {
                let optimised = optimise_effects(&effects);

                let mut state_orig = X86CpuState::new();
                let _ = exec_effects(&effects, &mut state_orig);
                let mut state_opt = X86CpuState::new();
                let _ = exec_effects(&optimised, &mut state_opt);

                let diffs: Vec<_> = diff_states(&state_orig, &state_opt)
                    .into_iter()
                    .filter(|d| matches!(d.expected, crate::x86_eval::EvalValue::Concrete(_)))
                    .collect();
                prop_assert!(
                    diffs.is_empty(),
                    "optimizer contradicted a known-concrete value: {diffs:?}"
                );
            }

            /// Idempotence (the module's own documented contract):
            /// applying the pass twice must produce the same result as
            /// applying it once.
            #[test]
            fn optimise_effects_is_idempotent(effects in prop::collection::vec(effect(), 0..12)) {
                let once = optimise_effects(&effects);
                let twice = optimise_effects(&once);
                prop_assert_eq!(once, twice);
            }
        }

        // ─────────────────────────────────────────────────────────────
        // Soundness generators: richer than `effect()` above, which only
        // ever emits RegWrites whose VALUES read eax/ebx/ecx. That blind
        // spot is why the pre-existing properties never exercised a
        // read of a temporary, and so never caught the backward-liveness
        // kill/use ordering bug in `eliminate_dead_writes`.
        // ─────────────────────────────────────────────────────────────

        /// Registers usable as noise: never the sentinel, so that noise can
        /// neither clobber nor read the sentinel and invalidate the property.
        const NOISE_REGS: [&str; 5] = ["eax", "ebx", "ecx", "__t0", "zf"];

        const SENTINEL_REG: &str = "rsentinel";

        /// An expression over noise registers only (never the sentinel).
        fn noise_expr() -> impl Strategy<Value = IrExpr> {
            let leaf = prop_oneof![
                any::<u16>().prop_map(|v| IrExpr::Const(u64::from(v))),
                prop::sample::select(NOISE_REGS.as_slice())
                    .prop_map(|r| IrExpr::Reg(r.to_string())),
            ];
            leaf.prop_recursive(3, 16, 3, |inner| {
                prop_oneof![
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| IrExpr::Add(Box::new(a), Box::new(b))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| IrExpr::Xor(Box::new(a), Box::new(b))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| IrExpr::And(Box::new(a), Box::new(b))),
                    inner.prop_map(|a| IrExpr::Not(Box::new(a))),
                ]
            })
        }

        /// Arbitrary noise effects spanning every `Effect` variant that the
        /// optimizer inspects. None of them touch `SENTINEL_REG`.
        fn noise_effect() -> impl Strategy<Value = Effect> {
            prop_oneof![
                (prop::sample::select(NOISE_REGS.as_slice()), noise_expr())
                    .prop_map(|(reg, value)| Effect::RegWrite { reg: reg.to_string(), value }),
                (noise_expr(), noise_expr())
                    .prop_map(|(addr, value)| Effect::MemWrite { addr, value, size: 8 }),
                (noise_expr(), prop::sample::select(NOISE_REGS.as_slice()))
                    .prop_map(|(addr, dest)| Effect::MemRead { addr, dest: dest.to_string(), size: 8 }),
                noise_expr().prop_map(|target| Effect::Call { target }),
                (noise_expr(), prop::option::of(noise_expr()))
                    .prop_map(|(target, condition)| Effect::Branch { target, condition }),
                noise_expr().prop_map(|nr| Effect::Syscall { nr }),
                Just(Effect::NoReturn),
            ]
        }

        /// Does any effect in `slice` write `reg`?
        fn writes_reg(slice: &[Effect], reg: &str) -> bool {
            slice.iter().any(|e| e.written_registers().iter().any(|w| w == reg))
        }

        proptest! {
            /// PROPERTY 1 (generalized): the optimizer never panics on an
            /// arbitrary bounded sequence spanning ALL effect variants —
            /// not just RegWrite, as the older no-panic property did.
            #[test]
            fn optimiser_never_panics_on_any_effect_mix(
                effects in prop::collection::vec(noise_effect(), 0..16)
            ) {
                let _ = optimise_effects(&effects);
                let _ = eliminate_dead_writes(&effects);
                let _ = OptStats::from_effects(&effects);
            }

            /// PROPERTY 2: optimizing is non-growing — it may delete
            /// effects but must never invent them.
            #[test]
            fn optimiser_never_grows_effect_count(
                effects in prop::collection::vec(noise_effect(), 0..16)
            ) {
                let optimised = optimise_effects(&effects);
                prop_assert!(
                    optimised.len() <= effects.len(),
                    "optimizer grew {} -> {}", effects.len(), optimised.len()
                );
                prop_assert!(eliminate_dead_writes(&effects).len() <= effects.len());

                // OptStats must agree with reality.
                let stats = OptStats::from_effects(&effects);
                prop_assert_eq!(stats.effects_before, effects.len());
                prop_assert_eq!(stats.effects_after, optimised.len());
                prop_assert!(stats.reduction_ratio() <= 1.0);
            }

            /// PROPERTY 3 (SOUNDNESS): a write to a NON-temporary,
            /// NON-flag register that is read afterwards must NEVER be
            /// eliminated. A sentinel write+read pair is embedded at
            /// random positions inside random surrounding noise that (by
            /// construction) neither writes nor reads the sentinel.
            #[test]
            fn live_write_to_normal_reg_is_never_eliminated(
                prefix in prop::collection::vec(noise_effect(), 0..6),
                middle in prop::collection::vec(noise_effect(), 0..6),
                suffix in prop::collection::vec(noise_effect(), 0..6),
                value in noise_expr(),
            ) {
                let mut effects = prefix;
                effects.push(Effect::RegWrite {
                    reg: SENTINEL_REG.to_string(),
                    value,
                });
                effects.extend(middle);
                // The read of the sentinel, after the write.
                effects.push(Effect::Return {
                    value: Some(IrExpr::Reg(SENTINEL_REG.to_string())),
                });
                effects.extend(suffix);

                let optimised = optimise_effects(&effects);
                prop_assert!(
                    writes_reg(&optimised, SENTINEL_REG),
                    "live write to non-temp/non-flag reg {} was eliminated\nin:  {:?}\nout: {:?}",
                    SENTINEL_REG, effects, optimised
                );
            }

            /// PROPERTY 3b (SOUNDNESS, memory): `MemWrite` is an
            /// observable side effect and must never be dropped, whatever
            /// noise surrounds it.
            #[test]
            fn memory_writes_are_never_eliminated(
                prefix in prop::collection::vec(noise_effect(), 0..6),
                suffix in prop::collection::vec(noise_effect(), 0..6),
                addr in noise_expr(),
                value in noise_expr(),
            ) {
                let expected = prefix.iter().chain(suffix.iter())
                    .filter(|e| matches!(e, Effect::MemWrite { .. }))
                    .count() + 1;

                let mut effects = prefix;
                effects.push(Effect::MemWrite { addr, value, size: 8 });
                effects.extend(suffix);

                let optimised = optimise_effects(&effects);
                let got = optimised.iter()
                    .filter(|e| matches!(e, Effect::MemWrite { .. }))
                    .count();
                prop_assert_eq!(got, expected, "a MemWrite was eliminated: {:?}", optimised);
            }

            /// PROPERTY 3c (SOUNDNESS, the regression guard for the real
            /// bug found while writing these): the optimizer must never
            /// turn a DEFINED temporary read into an UNDEFINED one.
            ///
            /// Dead-write elimination is allowed to delete a temp write
            /// that nothing reads. It is NOT allowed to delete a temp
            /// write that a later effect reads — including the case where
            /// the reader is a self-referencing write like
            /// `__t0 = __t0 + 1`, which is precisely what the old
            /// `live_in = (live_out ∪ use) − def` ordering got wrong.
            #[test]
            fn optimiser_never_creates_a_read_of_an_undefined_temp(
                effects in prop::collection::vec(noise_effect(), 0..16)
            ) {
                let optimised = optimise_effects(&effects);

                for reg in NOISE_REGS {
                    // Index of the first read of `reg`, and whether a write
                    // to `reg` precedes it, in a given slice.
                    let defined_before_first_read = |slice: &[Effect]| -> Option<bool> {
                        let first_read = slice.iter().position(|e| {
                            e.read_registers().iter().any(|r| r == reg)
                        })?;
                        Some(writes_reg(&slice[..first_read], reg))
                    };

                    // Only meaningful when the INPUT itself had the temp
                    // defined before its first use; the optimizer cannot be
                    // blamed for garbage it was handed.
                    if defined_before_first_read(&effects) == Some(true)
                        && let Some(still_defined) = defined_before_first_read(&optimised) {
                            prop_assert!(
                                still_defined,
                                "optimizer removed the defining write of `{}`, making its \
                                 first read undefined\nin:  {:?}\nout: {:?}",
                                reg, effects, optimised
                            );
                        }
                }
            }

            /// A self-referencing write chain must survive: the minimal,
            /// deterministic shrink of the bug that property 3c catches.
            #[test]
            fn self_referencing_temp_chain_survives(n in 1usize..6) {
                let mut effects = vec![Effect::RegWrite {
                    reg: "__t0".to_string(),
                    value: IrExpr::Const(1),
                }];
                for _ in 0..n {
                    effects.push(Effect::RegWrite {
                        reg: "__t0".to_string(),
                        value: IrExpr::Add(
                            Box::new(IrExpr::Reg("__t0".to_string())),
                            Box::new(IrExpr::Const(1)),
                        ),
                    });
                }
                effects.push(Effect::RegWrite {
                    reg: "eax".to_string(),
                    value: IrExpr::Reg("__t0".to_string()),
                });

                let optimised = optimise_effects(&effects);
                // Nothing is dead here: every write feeds the next read.
                prop_assert_eq!(
                    optimised.len(), effects.len(),
                    "a live self-referencing temp write was eliminated: {:?}", optimised
                );
            }
        }
    }
}
