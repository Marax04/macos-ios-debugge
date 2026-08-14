//! MLIL optimizer for `rustre-il-mlil`.
//!
//! Provides a set of SSA-based optimization passes over [`MlilFunction`]:
//! dead-code elimination, copy propagation, constant propagation, common
//! subexpression elimination, and algebraic simplification.  Each pass
//! implements the [`MlilOptPass`] trait and is orchestrated by [`MlilOptimizer`].

use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use std::fmt;

use crate::{MlilExpr, MlilFunction, MlilInstruction, Size, SsaVar};

// ---------------------------------------------------------------------------
// OptimizationStats
// ---------------------------------------------------------------------------

/// Aggregated statistics across all optimization passes.
#[derive(Debug, Clone, Default)]
pub struct OptimizationStats {
    /// Instructions removed by dead-code elimination.
    pub dead_code_removed: usize,
    /// Copy assignments propagated.
    pub copies_propagated: usize,
    /// Constant expressions folded.
    pub constants_folded: usize,
    /// CSE substitutions made.
    pub cse_replacements: usize,
    /// Algebraic identities simplified.
    pub algebraic_simplifications: usize,
    /// Total pass iterations executed.
    pub pass_iterations: usize,
}

impl OptimizationStats {
    /// Sum of all change counters.
    #[must_use]
    pub const fn total_changes(&self) -> usize {
        self.dead_code_removed
            + self.copies_propagated
            + self.constants_folded
            + self.cse_replacements
            + self.algebraic_simplifications
    }
}

impl fmt::Display for OptimizationStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "dead={} copy={} const={} cse={} alg={} iter={}",
            self.dead_code_removed,
            self.copies_propagated,
            self.constants_folded,
            self.cse_replacements,
            self.algebraic_simplifications,
            self.pass_iterations,
        )
    }
}

// ---------------------------------------------------------------------------
// MlilOptPass trait
// ---------------------------------------------------------------------------

/// A single optimization pass over an MLIL function.
pub trait MlilOptPass: fmt::Debug {
    /// Human-readable pass name.
    fn name(&self) -> &'static str;

    /// Run the pass on `func`.  Returns the number of changes made.
    fn run(&mut self, func: &mut MlilFunction) -> usize;

    /// Whether the pass should re-run until no changes occur.
    fn is_fixed_point(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// DeadCodeElim
// ---------------------------------------------------------------------------

/// Removes SSA definitions whose defined variable is never used.
///
/// Only safe for pure (side-effect-free) assignments; stores and calls are
/// always kept.
#[derive(Debug, Default)]
pub struct DeadCodeElim;

impl DeadCodeElim {
    /// Collect all SSA variables that appear on the *use* side of any
    /// instruction in `func`.
    #[must_use] 
    pub fn collect_uses(func: &MlilFunction) -> HashSet<SsaVar> {
        let mut used = HashSet::new();
        for block in &func.blocks {
            for ai in &block.instrs {
                collect_uses_in_instr(&ai.instr, &mut used);
            }
        }
        used
    }
}

fn collect_uses_in_instr(instr: &MlilInstruction, used: &mut HashSet<SsaVar>) {
    match instr {
        MlilInstruction::Assign { src, .. } => collect_expr_uses(src, used),
        MlilInstruction::Store { addr, src, .. } => {
            collect_expr_uses(addr, used);
            collect_expr_uses(src, used);
        }
        MlilInstruction::Jump { dest } => collect_expr_uses(dest, used),
        MlilInstruction::CondJump { cond, .. } => collect_expr_uses(cond, used),
        MlilInstruction::Call { dest, args, .. } | MlilInstruction::TailCall { dest, args } => {
            collect_expr_uses(dest, used);
            for a in args {
                collect_expr_uses(a, used);
            }
        }
        MlilInstruction::Ret { values } => {
            for v in values {
                collect_expr_uses(v, used);
            }
        }
        MlilInstruction::Phi { sources, .. } => {
            for s in sources {
                used.insert(s.clone());
            }
        }
        MlilInstruction::SysCall { args, .. } => {
            for a in args {
                collect_expr_uses(a, used);
            }
        }
        _ => {}
    }
}

impl MlilOptPass for DeadCodeElim {
    fn name(&self) -> &'static str {
        "DeadCodeElim"
    }

    fn run(&mut self, func: &mut MlilFunction) -> usize {
        let used = Self::collect_uses(func);
        let mut removed = 0;
        for block in &mut func.blocks {
            block.instrs.retain(|ai| {
                if let MlilInstruction::Assign { dest, src, .. } = &ai.instr
                    && !used.contains(dest) && !expr_has_side_effects(src) {
                        removed += 1;
                        return false;
                    }
                true
            });
        }
        removed
    }
}

// ---------------------------------------------------------------------------
// CopyPropagation
// ---------------------------------------------------------------------------

/// Propagates copy assignments `x = y` by replacing uses of `x` with `y`.
#[derive(Debug, Default)]
pub struct CopyPropagation;

impl MlilOptPass for CopyPropagation {
    fn name(&self) -> &'static str {
        "CopyPropagation"
    }

    fn run(&mut self, func: &mut MlilFunction) -> usize {
        // Build copy map: var → copied-from var.
        let mut copies: HashMap<SsaVar, SsaVar> = HashMap::new();
        for block in &func.blocks {
            for ai in &block.instrs {
                if let MlilInstruction::Assign {
                    dest,
                    src: MlilExpr::Var { var, .. },
                    ..
                } = &ai.instr
                {
                    copies.insert(dest.clone(), var.clone());
                }
            }
        }
        if copies.is_empty() {
            return 0;
        }
        // Apply substitution throughout all expressions.
        let mut changed = 0;
        for block in &mut func.blocks {
            for ai in &mut block.instrs {
                changed += substitute_vars_in_instr(&mut ai.instr, &copies);
            }
        }
        changed
    }
}

// ---------------------------------------------------------------------------
// ConstantProp
// ---------------------------------------------------------------------------

/// Constant propagation: replaces uses of variables known to hold a
/// compile-time constant with the constant directly.
#[derive(Debug, Default)]
pub struct ConstantProp;

impl MlilOptPass for ConstantProp {
    fn name(&self) -> &'static str {
        "ConstantProp"
    }

    fn run(&mut self, func: &mut MlilFunction) -> usize {
        // Build constant map: var → (value, size).
        let mut consts: HashMap<SsaVar, (u64, Size)> = HashMap::new();
        for block in &func.blocks {
            for ai in &block.instrs {
                if let MlilInstruction::Assign {
                    dest,
                    src: MlilExpr::Const { value, size },
                    ..
                } = &ai.instr
                {
                    consts.insert(dest.clone(), (*value, *size));
                }
            }
        }
        if consts.is_empty() {
            return 0;
        }
        let mut changed = 0;
        for block in &mut func.blocks {
            for ai in &mut block.instrs {
                changed += replace_const_in_instr(&mut ai.instr, &consts);
            }
        }
        changed
    }
}

// ---------------------------------------------------------------------------
// CommonSubexpr
// ---------------------------------------------------------------------------

/// Common subexpression elimination: replaces duplicate computations with a
/// reference to the first SSA variable that computed the same expression.
#[derive(Debug, Default)]
pub struct CommonSubexpr;

impl MlilOptPass for CommonSubexpr {
    fn name(&self) -> &'static str {
        "CommonSubexpr"
    }

    fn run(&mut self, func: &mut MlilFunction) -> usize {
        // Map from expression text → first-seen defining var.
        let mut seen: HashMap<String, SsaVar> = HashMap::new();
        let mut replacements: HashMap<SsaVar, SsaVar> = HashMap::new();

        for block in &func.blocks {
            for ai in &block.instrs {
                if let MlilInstruction::Assign { dest, src, .. } = &ai.instr
                    && !expr_has_side_effects(src) {
                        let key = format!("{src:?}");
                        if let Some(prev) = seen.get(&key) {
                            replacements.insert(dest.clone(), prev.clone());
                        } else {
                            seen.insert(key, dest.clone());
                        }
                    }
            }
        }

        if replacements.is_empty() {
            return 0;
        }
        let mut changed = 0;
        for block in &mut func.blocks {
            for ai in &mut block.instrs {
                changed += substitute_vars_in_instr(&mut ai.instr, &replacements);
            }
        }
        changed
    }
}

// ---------------------------------------------------------------------------
// AlgebraicSimplify
// ---------------------------------------------------------------------------

/// Algebraic simplification: applies identities such as `x + 0 → x`,
/// `x * 1 → x`, `x ^ x → 0`, `x & 0 → 0`, etc.
#[derive(Debug, Default)]
pub struct AlgebraicSimplify;

impl AlgebraicSimplify {
    /// Attempt to simplify `expr` in place.  Returns the number of rewrites.
    pub fn simplify_expr(expr: &mut MlilExpr) -> usize {
        Self::simplify_expr_depth(expr, 0)
    }

    fn simplify_expr_depth(expr: &mut MlilExpr, depth: usize) -> usize {
        // Guard against pathologically deep expression trees from adversarial input.
        if depth > 512 {
            return 0;
        }
        let mut changes = 0;

        // Recursively simplify children first.
        changes += Self::simplify_children_depth(expr, depth + 1);

        let simplified = match expr {
            // x + 0 → x
            MlilExpr::Add(l, r, _) if is_zero(r) => {
                changes += 1;
                Some(*l.clone())
            }
            // 0 + x → x
            MlilExpr::Add(l, r, _) if is_zero(l) => {
                changes += 1;
                Some(*r.clone())
            }
            // x - 0 → x
            MlilExpr::Sub(l, r, _) if is_zero(r) => {
                changes += 1;
                Some(*l.clone())
            }
            // x * 0 → 0
            MlilExpr::Mul(l, r, s) if is_zero(l) || is_zero(r) => {
                changes += 1;
                let sz = *s;
                let _ = (l, r);
                Some(MlilExpr::Const { value: 0, size: sz })
            }
            // x * 1 → x
            MlilExpr::Mul(l, r, _) if is_one(r) => {
                changes += 1;
                Some(*l.clone())
            }
            MlilExpr::Mul(l, r, _) if is_one(l) => {
                changes += 1;
                Some(*r.clone())
            }
            // x & 0 → 0
            MlilExpr::And(l, r, s) if is_zero(l) || is_zero(r) => {
                changes += 1;
                let sz = *s;
                let _ = (l, r);
                Some(MlilExpr::Const { value: 0, size: sz })
            }
            // x & x → x  (same var)
            MlilExpr::And(l, r, _) if same_var(l, r) => {
                changes += 1;
                Some(*l.clone())
            }
            // x | 0 → x
            MlilExpr::Or(l, r, _) if is_zero(r) => {
                changes += 1;
                Some(*l.clone())
            }
            MlilExpr::Or(l, r, _) if is_zero(l) => {
                changes += 1;
                Some(*r.clone())
            }
            // x | x → x
            MlilExpr::Or(l, r, _) if same_var(l, r) => {
                changes += 1;
                Some(*l.clone())
            }
            // x ^ x → 0
            MlilExpr::Xor(l, r, s) if same_var(l, r) => {
                changes += 1;
                let sz = *s;
                let _ = (l, r);
                Some(MlilExpr::Const { value: 0, size: sz })
            }
            // x ^ 0 → x
            MlilExpr::Xor(l, r, _) if is_zero(r) => {
                changes += 1;
                Some(*l.clone())
            }
            // x << 0 → x,  x >> 0 → x,  x >>a 0 → x
            MlilExpr::Shl(l, r, _) | MlilExpr::Shr(l, r, _) | MlilExpr::Sar(l, r, _)
                if is_zero(r) =>
            {
                changes += 1;
                Some(*l.clone())
            }
            // x - x → 0
            MlilExpr::Sub(l, r, s) if same_var(l, r) => {
                changes += 1;
                let sz = *s;
                let _ = (l, r);
                Some(MlilExpr::Const { value: 0, size: sz })
            }
            // Constant folding for binary ops.
            MlilExpr::Add(l, r, s) => {
                const_fold_binary(l, r, *s, u64::wrapping_add).inspect(|_v| {
                    changes += 1;
                })
            }
            MlilExpr::Sub(l, r, s) => {
                const_fold_binary(l, r, *s, u64::wrapping_sub).inspect(|_v| {
                    changes += 1;
                })
            }
            MlilExpr::Mul(l, r, s) => {
                const_fold_binary(l, r, *s, u64::wrapping_mul).inspect(|_v| {
                    changes += 1;
                })
            }
            MlilExpr::And(l, r, s) => const_fold_binary(l, r, *s, |a, b| a & b).inspect(|_v| {
                changes += 1;
            }),
            MlilExpr::Or(l, r, s) => const_fold_binary(l, r, *s, |a, b| a | b).inspect(|_v| {
                changes += 1;
            }),
            MlilExpr::Xor(l, r, s) => const_fold_binary(l, r, *s, |a, b| a ^ b).inspect(|_v| {
                changes += 1;
            }),
            MlilExpr::Shl(l, r, s) => {
                let bits = s.bits() as u32;
                let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
                const_fold_binary(l, r, *s, |a, b| a.wrapping_shl((b as u32) % bits) & mask).inspect(|_v| {
                    changes += 1;
                })
            }
            MlilExpr::Shr(l, r, s) => {
                let bits = s.bits() as u32;
                let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
                const_fold_binary(l, r, *s, |a, b| (a & mask).wrapping_shr((b as u32) % bits) & mask).inspect(|_v| {
                    changes += 1;
                })
            }
            _ => None,
        };

        if let Some(new_expr) = simplified {
            *expr = new_expr;
        }
        changes
    }

    fn simplify_children_depth(expr: &mut MlilExpr, depth: usize) -> usize {
        let mut changes = 0;
        match expr {
            MlilExpr::Add(l, r, _)
            | MlilExpr::Sub(l, r, _)
            | MlilExpr::Mul(l, r, _)
            | MlilExpr::DivU(l, r, _)
            | MlilExpr::DivS(l, r, _)
            | MlilExpr::And(l, r, _)
            | MlilExpr::Or(l, r, _)
            | MlilExpr::Xor(l, r, _)
            | MlilExpr::Shl(l, r, _)
            | MlilExpr::Shr(l, r, _)
            | MlilExpr::Sar(l, r, _)
            | MlilExpr::FAdd(l, r, _)
            | MlilExpr::FSub(l, r, _)
            | MlilExpr::FMul(l, r, _)
            | MlilExpr::FDiv(l, r, _)
            | MlilExpr::CmpEq(l, r)
            | MlilExpr::CmpNe(l, r)
            | MlilExpr::CmpSlt(l, r)
            | MlilExpr::CmpUlt(l, r)
            | MlilExpr::CmpSle(l, r)
            | MlilExpr::CmpUle(l, r) => {
                changes += Self::simplify_expr_depth(l, depth);
                changes += Self::simplify_expr_depth(r, depth);
            }
            MlilExpr::Neg(e, _)
            | MlilExpr::Not(e, _)
            | MlilExpr::ZeroExtend { expr: e, .. }
            | MlilExpr::SignExtend { expr: e, .. } => {
                changes += Self::simplify_expr_depth(e, depth);
            }
            MlilExpr::Load { addr, .. } => {
                changes += Self::simplify_expr_depth(addr, depth);
            }
            _ => {}
        }
        changes
    }
}

impl MlilOptPass for AlgebraicSimplify {
    fn name(&self) -> &'static str {
        "AlgebraicSimplify"
    }

    fn run(&mut self, func: &mut MlilFunction) -> usize {
        let mut changed = 0;
        for block in &mut func.blocks {
            for ai in &mut block.instrs {
                if let MlilInstruction::Assign { src, .. } = &mut ai.instr {
                    changed += Self::simplify_expr(src);
                }
            }
        }
        changed
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

const fn is_zero(expr: &MlilExpr) -> bool {
    matches!(expr, MlilExpr::Const { value: 0, .. })
}

const fn is_one(expr: &MlilExpr) -> bool {
    matches!(expr, MlilExpr::Const { value: 1, .. })
}

fn same_var(l: &MlilExpr, r: &MlilExpr) -> bool {
    if let (MlilExpr::Var { var: vl, .. }, MlilExpr::Var { var: vr, .. }) = (l, r) {
        vl == vr
    } else {
        false
    }
}

fn const_fold_binary<F>(l: &MlilExpr, r: &MlilExpr, size: Size, op: F) -> Option<MlilExpr>
where
    F: Fn(u64, u64) -> u64,
{
    if let (MlilExpr::Const { value: lv, .. }, MlilExpr::Const { value: rv, .. }) = (l, r) {
        Some(MlilExpr::Const {
            value: op(*lv, *rv),
            size,
        })
    } else {
        None
    }
}

fn collect_expr_uses(expr: &MlilExpr, uses: &mut HashSet<SsaVar>) {
    match expr {
        MlilExpr::Var { var, .. } => {
            uses.insert(var.clone());
        }
        MlilExpr::Add(l, r, _)
        | MlilExpr::Sub(l, r, _)
        | MlilExpr::Mul(l, r, _)
        | MlilExpr::DivU(l, r, _)
        | MlilExpr::DivS(l, r, _)
        | MlilExpr::And(l, r, _)
        | MlilExpr::Or(l, r, _)
        | MlilExpr::Xor(l, r, _)
        | MlilExpr::Shl(l, r, _)
        | MlilExpr::Shr(l, r, _)
        | MlilExpr::Sar(l, r, _)
        | MlilExpr::FAdd(l, r, _)
        | MlilExpr::FSub(l, r, _)
        | MlilExpr::FMul(l, r, _)
        | MlilExpr::FDiv(l, r, _)
        | MlilExpr::CmpEq(l, r)
        | MlilExpr::CmpNe(l, r)
        | MlilExpr::CmpSlt(l, r)
        | MlilExpr::CmpUlt(l, r)
        | MlilExpr::CmpSle(l, r)
        | MlilExpr::CmpUle(l, r) => {
            collect_expr_uses(l, uses);
            collect_expr_uses(r, uses);
        }
        MlilExpr::Neg(e, _)
        | MlilExpr::Not(e, _)
        | MlilExpr::ZeroExtend { expr: e, .. }
        | MlilExpr::SignExtend { expr: e, .. } => collect_expr_uses(e, uses),
        MlilExpr::Load { addr, .. } => collect_expr_uses(addr, uses),
        MlilExpr::Call { dest, args, .. } => {
            collect_expr_uses(dest, uses);
            for a in args {
                collect_expr_uses(a, uses);
            }
        }
        _ => {}
    }
}

fn substitute_vars_in_instr(instr: &mut MlilInstruction, map: &HashMap<SsaVar, SsaVar>) -> usize {
    match instr {
        MlilInstruction::Assign { src, .. } => substitute_expr_vars(src, map),
        MlilInstruction::Store { src, addr, .. } => {
            substitute_expr_vars(src, map) + substitute_expr_vars(addr, map)
        }
        MlilInstruction::Jump { dest } => substitute_expr_vars(dest, map),
        MlilInstruction::CondJump { cond, .. } => substitute_expr_vars(cond, map),
        MlilInstruction::Call { dest, args, .. } | MlilInstruction::TailCall { dest, args } => {
            let mut c = substitute_expr_vars(dest, map);
            for a in args {
                c += substitute_expr_vars(a, map);
            }
            c
        }
        MlilInstruction::Ret { values } => values
            .iter_mut()
            .map(|v| substitute_expr_vars(v, map))
            .sum(),
        MlilInstruction::SysCall { args, .. } => {
            args.iter_mut().map(|a| substitute_expr_vars(a, map)).sum()
        }
        _ => 0,
    }
}

fn replace_const_in_instr(
    instr: &mut MlilInstruction,
    map: &HashMap<SsaVar, (u64, Size)>,
) -> usize {
    match instr {
        MlilInstruction::Assign { src, .. } => replace_const_in_expr(src, map),
        MlilInstruction::Store { src, addr, .. } => {
            replace_const_in_expr(src, map) + replace_const_in_expr(addr, map)
        }
        MlilInstruction::Jump { dest } => replace_const_in_expr(dest, map),
        MlilInstruction::CondJump { cond, .. } => replace_const_in_expr(cond, map),
        MlilInstruction::Call { dest, args, .. } | MlilInstruction::TailCall { dest, args } => {
            let mut c = replace_const_in_expr(dest, map);
            for a in args {
                c += replace_const_in_expr(a, map);
            }
            c
        }
        MlilInstruction::Ret { values } => values
            .iter_mut()
            .map(|v| replace_const_in_expr(v, map))
            .sum(),
        MlilInstruction::SysCall { args, .. } => {
            args.iter_mut().map(|a| replace_const_in_expr(a, map)).sum()
        }
        _ => 0,
    }
}

fn substitute_expr_vars(expr: &mut MlilExpr, map: &HashMap<SsaVar, SsaVar>) -> usize {
    match expr {
        MlilExpr::Var { var, .. } => {
            if let Some(replacement) = map.get(var) {
                *var = replacement.clone();
                1
            } else {
                0
            }
        }
        MlilExpr::Add(l, r, _)
        | MlilExpr::Sub(l, r, _)
        | MlilExpr::Mul(l, r, _)
        | MlilExpr::DivU(l, r, _)
        | MlilExpr::DivS(l, r, _)
        | MlilExpr::And(l, r, _)
        | MlilExpr::Or(l, r, _)
        | MlilExpr::Xor(l, r, _)
        | MlilExpr::Shl(l, r, _)
        | MlilExpr::Shr(l, r, _)
        | MlilExpr::Sar(l, r, _)
        | MlilExpr::FAdd(l, r, _)
        | MlilExpr::FSub(l, r, _)
        | MlilExpr::FMul(l, r, _)
        | MlilExpr::FDiv(l, r, _)
        | MlilExpr::CmpEq(l, r)
        | MlilExpr::CmpNe(l, r)
        | MlilExpr::CmpSlt(l, r)
        | MlilExpr::CmpUlt(l, r)
        | MlilExpr::CmpSle(l, r)
        | MlilExpr::CmpUle(l, r) => substitute_expr_vars(l, map) + substitute_expr_vars(r, map),
        MlilExpr::Neg(e, _)
        | MlilExpr::Not(e, _)
        | MlilExpr::ZeroExtend { expr: e, .. }
        | MlilExpr::SignExtend { expr: e, .. } => substitute_expr_vars(e, map),
        MlilExpr::Load { addr, .. } => substitute_expr_vars(addr, map),
        MlilExpr::Call { dest, args, .. } => {
            let mut c = substitute_expr_vars(dest, map);
            for a in args {
                c += substitute_expr_vars(a, map);
            }
            c
        }
        _ => 0,
    }
}

fn replace_const_in_expr(expr: &mut MlilExpr, map: &HashMap<SsaVar, (u64, Size)>) -> usize {
    match expr {
        MlilExpr::Var { var, .. } => {
            if let Some(&(value, size)) = map.get(var) {
                *expr = MlilExpr::Const { value, size };
                1
            } else {
                0
            }
        }
        MlilExpr::Add(l, r, _)
        | MlilExpr::Sub(l, r, _)
        | MlilExpr::Mul(l, r, _)
        | MlilExpr::DivU(l, r, _)
        | MlilExpr::DivS(l, r, _)
        | MlilExpr::And(l, r, _)
        | MlilExpr::Or(l, r, _)
        | MlilExpr::Xor(l, r, _)
        | MlilExpr::Shl(l, r, _)
        | MlilExpr::Shr(l, r, _)
        | MlilExpr::Sar(l, r, _)
        | MlilExpr::FAdd(l, r, _)
        | MlilExpr::FSub(l, r, _)
        | MlilExpr::FMul(l, r, _)
        | MlilExpr::FDiv(l, r, _)
        | MlilExpr::CmpEq(l, r)
        | MlilExpr::CmpNe(l, r)
        | MlilExpr::CmpSlt(l, r)
        | MlilExpr::CmpUlt(l, r)
        | MlilExpr::CmpSle(l, r)
        | MlilExpr::CmpUle(l, r) => replace_const_in_expr(l, map) + replace_const_in_expr(r, map),
        MlilExpr::Neg(e, _)
        | MlilExpr::Not(e, _)
        | MlilExpr::ZeroExtend { expr: e, .. }
        | MlilExpr::SignExtend { expr: e, .. } => replace_const_in_expr(e, map),
        MlilExpr::Load { addr, .. } => replace_const_in_expr(addr, map),
        MlilExpr::Call { dest, args, .. } => {
            let mut c = replace_const_in_expr(dest, map);
            for a in args {
                c += replace_const_in_expr(a, map);
            }
            c
        }
        _ => 0,
    }
}

fn expr_has_side_effects(expr: &MlilExpr) -> bool {
    match expr {
        MlilExpr::Load { .. } | MlilExpr::Call { .. } => true,
        MlilExpr::Add(l, r, _)
        | MlilExpr::Sub(l, r, _)
        | MlilExpr::Mul(l, r, _)
        | MlilExpr::DivU(l, r, _)
        | MlilExpr::DivS(l, r, _)
        | MlilExpr::And(l, r, _)
        | MlilExpr::Or(l, r, _)
        | MlilExpr::Xor(l, r, _)
        | MlilExpr::Shl(l, r, _)
        | MlilExpr::Shr(l, r, _)
        | MlilExpr::Sar(l, r, _)
        | MlilExpr::FAdd(l, r, _)
        | MlilExpr::FSub(l, r, _)
        | MlilExpr::FMul(l, r, _)
        | MlilExpr::FDiv(l, r, _)
        | MlilExpr::CmpEq(l, r)
        | MlilExpr::CmpNe(l, r)
        | MlilExpr::CmpSlt(l, r)
        | MlilExpr::CmpUlt(l, r)
        | MlilExpr::CmpSle(l, r)
        | MlilExpr::CmpUle(l, r) => expr_has_side_effects(l) || expr_has_side_effects(r),
        MlilExpr::Neg(e, _)
        | MlilExpr::Not(e, _)
        | MlilExpr::ZeroExtend { expr: e, .. }
        | MlilExpr::SignExtend { expr: e, .. } => expr_has_side_effects(e),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// MlilOptimizer
// ---------------------------------------------------------------------------

/// Orchestrates multiple [`MlilOptPass`]es over an [`MlilFunction`].
#[derive(Debug)]
pub struct MlilOptimizer {
    passes: Vec<Box<dyn MlilOptPass>>,
    /// Maximum number of fixed-point iterations before giving up.
    pub max_iterations: usize,
    /// Accumulated statistics.
    pub stats: OptimizationStats,
}

impl MlilOptimizer {
    /// Construct an optimizer with the default pass pipeline.
    #[must_use]
    pub fn default_pipeline() -> Self {
        Self {
            passes: vec![
                Box::new(ConstantProp),
                Box::new(CopyPropagation),
                Box::new(AlgebraicSimplify),
                Box::new(CommonSubexpr),
                Box::new(DeadCodeElim),
            ],
            max_iterations: 20,
            stats: OptimizationStats::default(),
        }
    }

    /// Construct an optimizer with a custom pass list.
    #[must_use]
    pub fn with_passes(passes: Vec<Box<dyn MlilOptPass>>) -> Self {
        Self {
            passes,
            max_iterations: 20,
            stats: OptimizationStats::default(),
        }
    }

    /// Run the full pass pipeline on `func` until convergence or iteration
    /// limit.  Returns total number of changes applied.
    pub fn optimize(&mut self, func: &mut MlilFunction) -> usize {
        let mut total = 0;
        for _ in 0..self.max_iterations {
            let mut round = 0;
            for pass in &mut self.passes {
                let changes = pass.run(func);
                round += changes;
                self.stats.pass_iterations += 1;
                // Route changes to stats by pass name.
                match pass.name() {
                    "DeadCodeElim" => self.stats.dead_code_removed += changes,
                    "CopyPropagation" => self.stats.copies_propagated += changes,
                    "ConstantProp" => self.stats.constants_folded += changes,
                    "CommonSubexpr" => self.stats.cse_replacements += changes,
                    "AlgebraicSimplify" => self.stats.algebraic_simplifications += changes,
                    _ => {}
                }
            }
            total += round;
            if round == 0 {
                break;
            }
        }
        total
    }
}

// ---------------------------------------------------------------------------
// PassReport — human-readable summary of an optimization run
// ---------------------------------------------------------------------------

/// A formatted report produced after running the optimizer.
#[derive(Debug, Clone, Default)]
pub struct PassReport {
    /// Name of each pass that ran, in execution order.
    pub pass_names: Vec<String>,
    /// Changes made by each pass (same order as `pass_names`).
    pub changes_per_pass: Vec<usize>,
    /// Total changes across all passes.
    pub total_changes: usize,
    /// Number of fixed-point iterations required.
    pub iterations: usize,
}

impl PassReport {
    /// Return the name of the pass that made the most changes.
    #[must_use]
    pub fn most_active_pass(&self) -> Option<&str> {
        self.changes_per_pass
            .iter()
            .enumerate()
            .max_by_key(|(_, c)| **c)
            .and_then(|(i, _)| self.pass_names.get(i).map(String::as_str))
    }
}

impl std::fmt::Display for PassReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PassReport {{ total={}, iters={} }}",
            self.total_changes, self.iterations
        )
    }
}

// ---------------------------------------------------------------------------
// ExprWalker — recursive expression visitor utility
// ---------------------------------------------------------------------------

/// Recursively visits every sub-expression in a [`MlilExpr`] tree.
pub struct ExprWalker;

impl ExprWalker {
    /// Count the number of leaf nodes (constants and variables) in `expr`.
    #[must_use]
    pub fn count_leaves(expr: &MlilExpr) -> usize {
        match expr {
            MlilExpr::Const { .. }
            | MlilExpr::Var { .. }
            | MlilExpr::Undefined(_)
            | MlilExpr::StackPointer(_)
            | MlilExpr::Flag { .. } => 1,
            MlilExpr::Add(l, r, _)
            | MlilExpr::Sub(l, r, _)
            | MlilExpr::Mul(l, r, _)
            | MlilExpr::DivU(l, r, _)
            | MlilExpr::DivS(l, r, _)
            | MlilExpr::And(l, r, _)
            | MlilExpr::Or(l, r, _)
            | MlilExpr::Xor(l, r, _)
            | MlilExpr::Shl(l, r, _)
            | MlilExpr::Shr(l, r, _)
            | MlilExpr::Sar(l, r, _)
            | MlilExpr::FAdd(l, r, _)
            | MlilExpr::FSub(l, r, _)
            | MlilExpr::FMul(l, r, _)
            | MlilExpr::FDiv(l, r, _)
            | MlilExpr::CmpEq(l, r)
            | MlilExpr::CmpNe(l, r)
            | MlilExpr::CmpSlt(l, r)
            | MlilExpr::CmpUlt(l, r)
            | MlilExpr::CmpSle(l, r)
            | MlilExpr::CmpUle(l, r) => Self::count_leaves(l) + Self::count_leaves(r),
            MlilExpr::Neg(e, _)
            | MlilExpr::Not(e, _)
            | MlilExpr::FNeg(e, _)
            | MlilExpr::ZeroExtend { expr: e, .. }
            | MlilExpr::SignExtend { expr: e, .. }
            | MlilExpr::IntToFloat { expr: e, .. }
            | MlilExpr::FloatToInt { expr: e, .. } => Self::count_leaves(e),
            MlilExpr::Select { cond, true_val, false_val, .. } => {
                Self::count_leaves(cond) + Self::count_leaves(true_val) + Self::count_leaves(false_val)
            }
            MlilExpr::Load { addr, .. } => Self::count_leaves(addr),
            MlilExpr::Call { dest, args, .. } => {
                Self::count_leaves(dest) + args.iter().map(Self::count_leaves).sum::<usize>()
            }
        }
    }

    /// Depth of the expression tree (1 for a leaf).
    #[must_use]
    pub fn depth(expr: &MlilExpr) -> usize {
        match expr {
            MlilExpr::Const { .. }
            | MlilExpr::Var { .. }
            | MlilExpr::Undefined(_)
            | MlilExpr::StackPointer(_)
            | MlilExpr::Flag { .. } => 1,
            MlilExpr::Add(l, r, _)
            | MlilExpr::Sub(l, r, _)
            | MlilExpr::Mul(l, r, _)
            | MlilExpr::DivU(l, r, _)
            | MlilExpr::DivS(l, r, _)
            | MlilExpr::And(l, r, _)
            | MlilExpr::Or(l, r, _)
            | MlilExpr::Xor(l, r, _)
            | MlilExpr::Shl(l, r, _)
            | MlilExpr::Shr(l, r, _)
            | MlilExpr::Sar(l, r, _)
            | MlilExpr::FAdd(l, r, _)
            | MlilExpr::FSub(l, r, _)
            | MlilExpr::FMul(l, r, _)
            | MlilExpr::FDiv(l, r, _)
            | MlilExpr::CmpEq(l, r)
            | MlilExpr::CmpNe(l, r)
            | MlilExpr::CmpSlt(l, r)
            | MlilExpr::CmpUlt(l, r)
            | MlilExpr::CmpSle(l, r)
            | MlilExpr::CmpUle(l, r) => 1 + Self::depth(l).max(Self::depth(r)),
            MlilExpr::Neg(e, _)
            | MlilExpr::Not(e, _)
            | MlilExpr::FNeg(e, _)
            | MlilExpr::ZeroExtend { expr: e, .. }
            | MlilExpr::SignExtend { expr: e, .. }
            | MlilExpr::IntToFloat { expr: e, .. }
            | MlilExpr::FloatToInt { expr: e, .. } => 1 + Self::depth(e),
            MlilExpr::Select { cond, true_val, false_val, .. } => {
                1 + Self::depth(cond).max(Self::depth(true_val)).max(Self::depth(false_val))
            }
            MlilExpr::Load { addr, .. } => 1 + Self::depth(addr),
            MlilExpr::Call { dest, args, .. } => {
                let arg_depth = args.iter().map(Self::depth).max().unwrap_or(0);
                1 + Self::depth(dest).max(arg_depth)
            }
        }
    }

    /// Collect all SSA variables referenced in `expr`.
    pub fn collect_vars(expr: &MlilExpr, out: &mut HashSet<SsaVar>) {
        match expr {
            MlilExpr::Var { var, .. } => {
                out.insert(var.clone());
            }
            MlilExpr::Add(l, r, _)
            | MlilExpr::Sub(l, r, _)
            | MlilExpr::Mul(l, r, _)
            | MlilExpr::DivU(l, r, _)
            | MlilExpr::DivS(l, r, _)
            | MlilExpr::And(l, r, _)
            | MlilExpr::Or(l, r, _)
            | MlilExpr::Xor(l, r, _)
            | MlilExpr::Shl(l, r, _)
            | MlilExpr::Shr(l, r, _)
            | MlilExpr::Sar(l, r, _)
            | MlilExpr::FAdd(l, r, _)
            | MlilExpr::FSub(l, r, _)
            | MlilExpr::FMul(l, r, _)
            | MlilExpr::FDiv(l, r, _)
            | MlilExpr::CmpEq(l, r)
            | MlilExpr::CmpNe(l, r)
            | MlilExpr::CmpSlt(l, r)
            | MlilExpr::CmpUlt(l, r)
            | MlilExpr::CmpSle(l, r)
            | MlilExpr::CmpUle(l, r) => {
                Self::collect_vars(l, out);
                Self::collect_vars(r, out);
            }
            MlilExpr::Neg(e, _)
            | MlilExpr::Not(e, _)
            | MlilExpr::ZeroExtend { expr: e, .. }
            | MlilExpr::SignExtend { expr: e, .. } => Self::collect_vars(e, out),
            MlilExpr::Load { addr, .. } => Self::collect_vars(addr, out),
            MlilExpr::Call { dest, args, .. } => {
                Self::collect_vars(dest, out);
                for a in args {
                    Self::collect_vars(a, out);
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// InstructionCounter — counts various instruction kinds in a function
// ---------------------------------------------------------------------------

/// Counts various instruction categories in an [`MlilFunction`].
#[derive(Debug, Clone, Default)]
pub struct InstructionCounter {
    pub assignments: usize,
    pub stores: usize,
    pub returns: usize,
    pub calls: usize,
}

impl InstructionCounter {
    /// Count all instruction categories in `func`.
    #[must_use] 
    pub fn count(func: &MlilFunction) -> Self {
        let mut c = Self::default();
        for block in &func.blocks {
            for ai in &block.instrs {
                match &ai.instr {
                    MlilInstruction::Assign { .. } => c.assignments += 1,
                    MlilInstruction::Store { .. } => c.stores += 1,
                    MlilInstruction::Ret { .. } => c.returns += 1,
                    MlilInstruction::Call { .. } | MlilInstruction::TailCall { .. } => c.calls += 1,
                    _ => {}
                }
            }
        }
        c
    }

    /// Total instruction count.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.assignments + self.stores + self.returns + self.calls
    }
}

// ---------------------------------------------------------------------------
// StrengthReduction — replaces expensive ops with cheaper equivalents
// ---------------------------------------------------------------------------

/// Replaces multiply-by-power-of-two with a shift, and similar rewrites.
#[derive(Debug, Default)]
pub struct StrengthReduction;

impl StrengthReduction {
    /// If `expr` is a multiply by a power of two, return the equivalent shift.
    #[must_use] 
    pub fn try_mul_to_shift(expr: &MlilExpr) -> Option<MlilExpr> {
        if let MlilExpr::Mul(l, r, size) = expr {
            let size = *size;
            if let MlilExpr::Const { value, .. } = r.as_ref() {
                let v = *value;
                if v > 0 && v.is_power_of_two() {
                    let shift = u64::from(v.trailing_zeros());
                    return Some(MlilExpr::Shl(
                        l.clone(),
                        Box::new(MlilExpr::Const { value: shift, size }),
                        size,
                    ));
                }
            }
            // commutative: try left operand
            if let MlilExpr::Const { value, .. } = l.as_ref() {
                let v = *value;
                if v > 0 && v.is_power_of_two() {
                    let shift = u64::from(v.trailing_zeros());
                    return Some(MlilExpr::Shl(
                        r.clone(),
                        Box::new(MlilExpr::Const { value: shift, size }),
                        size,
                    ));
                }
            }
        }
        None
    }

    /// Apply strength reduction to all assignments in `func`.
    /// Returns the number of rewrites.
    pub fn run(func: &mut MlilFunction) -> usize {
        let mut rewrites = 0;
        for block in &mut func.blocks {
            for ai in &mut block.instrs {
                if let MlilInstruction::Assign { src, .. } = &mut ai.instr
                    && let Some(new_expr) = Self::try_mul_to_shift(src) {
                        *src = new_expr;
                        rewrites += 1;
                    }
            }
        }
        rewrites
    }
}

// ---------------------------------------------------------------------------
// PeepholeOptimizer — targeted rewrite rules operating on instruction pairs
// ---------------------------------------------------------------------------

/// Applies classic 2-instruction peephole rewrites, such as:
/// * Store followed by Load at same address → forward the stored value.
/// * Assign followed by same Assign → remove first.
#[derive(Debug, Default)]
pub struct MlilPeepholeOptimizer {
    pub rewrites: usize,
}

impl MlilPeepholeOptimizer {
    /// Apply peephole optimizations in all blocks of `func`.
    pub fn run(&mut self, func: &mut MlilFunction) {
        for block in &mut func.blocks {
            self.process_block(&mut block.instrs);
        }
    }

    fn process_block(&mut self, instrs: &mut Vec<crate::MlilAnnotatedInstr>) {
        let mut i = 0;
        while i + 1 < instrs.len() {
            // Remove double-assignment to same var with same value.
            let pair_match = matches!(
                (&instrs[i].instr, &instrs[i + 1].instr),
                (
                    MlilInstruction::Assign { dest: d1, src: s1, .. },
                    MlilInstruction::Assign { dest: d2, src: s2, .. },
                ) if d1 == d2 && s1 == s2
            );
            if pair_match {
                instrs.remove(i);
                self.rewrites += 1;
                continue;
            }
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// OptimizationPipeline — extensible pipeline wrapper
// ---------------------------------------------------------------------------

/// A named, extensible optimization pipeline.
#[derive(Debug)]
pub struct OptimizationPipeline {
    pub name: String,
    optimizer: MlilOptimizer,
    pub last_total: usize,
}

impl OptimizationPipeline {
    /// Create a new named pipeline with the default pass set.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            optimizer: MlilOptimizer::default_pipeline(),
            last_total: 0,
        }
    }

    /// Run the pipeline on `func`, returning total changes.
    pub fn run(&mut self, func: &mut MlilFunction) -> usize {
        let total = self.optimizer.optimize(func);
        self.last_total = total;
        total
    }

    /// Access accumulated statistics.
    #[must_use]
    pub const fn stats(&self) -> &OptimizationStats {
        &self.optimizer.stats
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlilAnnotatedInstr, MlilBasicBlock};
    use rustre_core::address::Address;

    fn var(name: &str, v: u32, size: Size) -> MlilExpr {
        MlilExpr::Var {
            var: SsaVar::new(name, v),
            size,
        }
    }

    fn konst(value: u64, size: Size) -> MlilExpr {
        MlilExpr::Const { value, size }
    }

    fn assign(dest: &str, v: u32, src: MlilExpr) -> MlilInstruction {
        MlilInstruction::Assign {
            dest: SsaVar::new(dest, v),
            size: Size::QWord,
            src,
        }
    }

    fn ret(value: MlilExpr) -> MlilInstruction {
        MlilInstruction::Ret {
            values: vec![value],
        }
    }

    fn make_func(instrs: Vec<MlilInstruction>) -> MlilFunction {
        let annotated: Vec<MlilAnnotatedInstr> = instrs
            .into_iter()
            .map(|i| MlilAnnotatedInstr {
                address: Address::new(0),
                instr: i,
            })
            .collect();
        let block = MlilBasicBlock {
            id: 0,
            start: Address::new(0),
            end: Address::new(0),
            instrs: annotated,
            predecessors: Vec::new(),
            successors: Vec::new(),
        };
        let mut func = MlilFunction::new(Address::new(0));
        func.blocks.push(block);
        func
    }

    // --- OptimizationStats tests ---

    #[test]
    fn stats_total_changes_zero() {
        let s = OptimizationStats::default();
        assert_eq!(s.total_changes(), 0);
    }

    #[test]
    fn stats_total_changes_sum() {
        let s = OptimizationStats {
            dead_code_removed: 1,
            copies_propagated: 2,
            constants_folded: 3,
            cse_replacements: 4,
            algebraic_simplifications: 5,
            pass_iterations: 0,
        };
        assert_eq!(s.total_changes(), 15);
    }

    #[test]
    fn stats_display_works() {
        let s = OptimizationStats {
            dead_code_removed: 1,
            ..Default::default()
        };
        let s = format!("{s}");
        assert!(s.contains("dead=1"));
    }

    // --- AlgebraicSimplify tests ---

    #[test]
    fn algebraic_x_plus_zero() {
        let mut expr = MlilExpr::Add(
            Box::new(var("x", 0, Size::QWord)),
            Box::new(konst(0, Size::QWord)),
            Size::QWord,
        );
        let changes = AlgebraicSimplify::simplify_expr(&mut expr);
        assert!(changes > 0);
        assert!(matches!(expr, MlilExpr::Var { .. }));
    }

    #[test]
    fn algebraic_x_minus_x() {
        let mut expr = MlilExpr::Sub(
            Box::new(var("x", 0, Size::QWord)),
            Box::new(var("x", 0, Size::QWord)),
            Size::QWord,
        );
        AlgebraicSimplify::simplify_expr(&mut expr);
        assert_eq!(expr, konst(0, Size::QWord));
    }

    #[test]
    fn algebraic_const_fold_add() {
        let mut expr = MlilExpr::Add(
            Box::new(konst(3, Size::QWord)),
            Box::new(konst(7, Size::QWord)),
            Size::QWord,
        );
        AlgebraicSimplify::simplify_expr(&mut expr);
        assert_eq!(expr, konst(10, Size::QWord));
    }

    // --- ConstantProp tests ---

    #[test]
    fn const_prop_single_def() {
        let instrs = vec![
            assign("x", 1, konst(42, Size::QWord)),
            ret(var("x", 1, Size::QWord)),
        ];
        let mut func = make_func(instrs);
        let changes = ConstantProp.run(&mut func);
        assert!(changes > 0);
    }

    // --- CopyPropagation tests ---

    #[test]
    fn copy_prop_simple() {
        let instrs = vec![
            assign("x", 1, var("y", 0, Size::QWord)),
            ret(var("x", 1, Size::QWord)),
        ];
        let mut func = make_func(instrs);
        let changes = CopyPropagation.run(&mut func);
        assert!(changes > 0);
    }

    // --- DeadCodeElim tests ---

    #[test]
    fn dce_removes_unused_pure_def() {
        let instrs = vec![
            assign("unused", 1, konst(99, Size::QWord)),
            ret(konst(0, Size::QWord)),
        ];
        let mut func = make_func(instrs);
        let changes = DeadCodeElim.run(&mut func);
        assert!(changes > 0);
        assert_eq!(func.blocks[0].instrs.len(), 1);
    }

    #[test]
    fn dce_keeps_used_def() {
        let instrs = vec![
            assign("x", 1, konst(5, Size::QWord)),
            ret(var("x", 1, Size::QWord)),
        ];
        let mut func = make_func(instrs);
        let changes = DeadCodeElim.run(&mut func);
        assert_eq!(changes, 0);
        assert_eq!(func.blocks[0].instrs.len(), 2);
    }

    // --- MlilOptimizer tests ---

    #[test]
    fn optimizer_default_pipeline_runs() {
        let instrs = vec![
            assign("x", 1, konst(5, Size::QWord)),
            assign(
                "y",
                1,
                MlilExpr::Add(
                    Box::new(var("x", 1, Size::QWord)),
                    Box::new(konst(0, Size::QWord)),
                    Size::QWord,
                ),
            ),
            ret(var("y", 1, Size::QWord)),
        ];
        let mut func = make_func(instrs);
        let mut opt = MlilOptimizer::default_pipeline();
        let changes = opt.optimize(&mut func);
        assert!(changes > 0);
    }

    #[test]
    fn is_zero_helper() {
        assert!(is_zero(&konst(0, Size::QWord)));
        assert!(!is_zero(&konst(1, Size::QWord)));
    }

    #[test]
    fn is_one_helper() {
        assert!(is_one(&konst(1, Size::QWord)));
        assert!(!is_one(&konst(0, Size::QWord)));
    }

    #[test]
    fn same_var_helper() {
        let a = var("x", 1, Size::QWord);
        let b = var("x", 1, Size::QWord);
        let c = var("y", 1, Size::QWord);
        assert!(same_var(&a, &b));
        assert!(!same_var(&a, &c));
    }

    // --- ExprWalker tests ---

    #[test]
    fn expr_walker_count_leaves_const() {
        let e = konst(42, Size::QWord);
        assert_eq!(ExprWalker::count_leaves(&e), 1);
    }

    #[test]
    fn expr_walker_depth_leaf() {
        assert_eq!(ExprWalker::depth(&konst(0, Size::QWord)), 1);
    }

    #[test]
    fn expr_walker_collect_vars() {
        let e = MlilExpr::Add(
            Box::new(var("x", 1, Size::QWord)),
            Box::new(var("y", 2, Size::QWord)),
            Size::QWord,
        );
        let mut set = HashSet::new();
        ExprWalker::collect_vars(&e, &mut set);
        assert!(set.contains(&SsaVar::new("x", 1)));
        assert!(set.contains(&SsaVar::new("y", 2)));
    }

    // --- InstructionCounter tests ---

    #[test]
    fn instruction_counter_empty() {
        let func = make_func(vec![]);
        let c = InstructionCounter::count(&func);
        assert_eq!(c.total(), 0);
    }

    #[test]
    fn instruction_counter_counts_assignment() {
        let func = make_func(vec![assign("x", 1, konst(0, Size::QWord))]);
        let c = InstructionCounter::count(&func);
        assert_eq!(c.assignments, 1);
    }

    // --- StrengthReduction tests ---

    #[test]
    fn strength_mul_by_power_of_two_right() {
        let expr = MlilExpr::Mul(
            Box::new(var("x", 0, Size::QWord)),
            Box::new(konst(4, Size::QWord)),
            Size::QWord,
        );
        let result = StrengthReduction::try_mul_to_shift(&expr);
        assert!(result.is_some());
    }

    #[test]
    fn strength_mul_non_power_of_two() {
        let expr = MlilExpr::Mul(
            Box::new(var("x", 0, Size::QWord)),
            Box::new(konst(3, Size::QWord)),
            Size::QWord,
        );
        assert!(StrengthReduction::try_mul_to_shift(&expr).is_none());
    }

    // --- OptimizationPipeline tests ---

    #[test]
    fn pipeline_run() {
        let instrs = vec![assign("x", 1, konst(5, Size::QWord))];
        let mut func = make_func(instrs);
        let mut p = OptimizationPipeline::new("test");
        let _ = p.run(&mut func);
        assert_eq!(p.name, "test");
    }

    // --- MlilPeepholeOptimizer tests ---

    #[test]
    fn peephole_removes_duplicate_assign() {
        let instrs = vec![
            assign("x", 1, konst(5, Size::QWord)),
            assign("x", 1, konst(5, Size::QWord)), // duplicate
        ];
        let mut func = make_func(instrs);
        let mut ph = MlilPeepholeOptimizer::default();
        ph.run(&mut func);
        assert_eq!(ph.rewrites, 1);
        assert_eq!(func.blocks[0].instrs.len(), 1);
    }

    #[test]
    fn collect_uses_finds_all_vars() {
        let instrs = vec![assign(
            "out",
            1,
            MlilExpr::Add(
                Box::new(var("a", 0, Size::QWord)),
                Box::new(var("b", 0, Size::QWord)),
                Size::QWord,
            ),
        )];
        let func = make_func(instrs);
        let uses = DeadCodeElim::collect_uses(&func);
        assert!(uses.contains(&SsaVar::new("a", 0)));
        assert!(uses.contains(&SsaVar::new("b", 0)));
    }

    // --- PassReport tests ---

    #[test]
    fn pass_report_most_active() {
        let r = PassReport {
            pass_names: vec!["A".into(), "B".into()],
            changes_per_pass: vec![5, 10],
            total_changes: 15,
            iterations: 2,
        };
        assert_eq!(r.most_active_pass(), Some("B"));
    }
}
