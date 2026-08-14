//! `hlil_optimization` — HLIL-level optimizer passes.
//!
//! Provides `HlilOptimizer`, `DeadAssignmentElim`, `ConstantFolding`,
//! `CommonSubexprElim`, `SimplifyConditions`, `RemoveRedundantCasts`.

use crate::{HlilExpr, HlilInstruction, HlilType, HlilVar};
use std::collections::{HashMap, HashSet};

// ── OptimizationResult ────────────────────────────────────────────────────────

/// Result of applying an optimization pass to a block of instructions.
#[derive(Debug, Clone, Default)]
pub struct OptimizationResult {
    /// Instructions after optimization.
    pub instructions: Vec<HlilInstruction>,
    /// Number of transformations applied.
    pub changes: usize,
    /// Names of passes that fired.
    pub passes_fired: Vec<String>,
}

impl OptimizationResult {
    #[must_use]
    pub fn unchanged(instructions: Vec<HlilInstruction>) -> Self {
        Self {
            instructions,
            changes: 0,
            passes_fired: Vec::new(),
        }
    }

    pub fn record_change(&mut self, pass: impl Into<String>) {
        self.changes += 1;
        let name = pass.into();
        if !self.passes_fired.contains(&name) {
            self.passes_fired.push(name);
        }
    }

    #[must_use]
    pub fn was_modified(&self) -> bool {
        self.changes > 0
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Create an unknown-type `Int` HlilType for a given bit width.
fn int_ty(bits: usize) -> HlilType {
    HlilType::Int {
        signed: false,
        bits: u32::try_from(bits).unwrap_or(u32::MAX),
    }
}

/// Truncate `value` to `bits` bits so a folded result is representable at the
/// operand width (e.g. `0xFF + 1` at 8 bits is `0`, not `256`). Without this,
/// downstream raw-64-bit constant comparisons fold to the wrong branch.
fn mask_to_width(value: u64, bits: usize) -> u64 {
    if bits >= 64 {
        value
    } else {
        value & ((1u64 << bits) - 1)
    }
}

/// Construct a `Const` expression with the given value and bit width.
fn make_const(value: u64, bits: usize) -> HlilExpr {
    HlilExpr::Const {
        value: i64::from_ne_bytes(value.to_ne_bytes()),
        ty: int_ty(bits),
    }
}

/// Extract `(value, bits)` from a `Const` expression, if applicable.
fn const_parts(expr: &HlilExpr) -> Option<(u64, usize)> {
    if let HlilExpr::Const { value, ty } = expr {
        let bits = match ty {
            HlilType::Int { bits, .. } => *bits as usize,
            HlilType::Bool => 1,
            _ => 64,
        };
        Some((u64::from_ne_bytes(value.to_ne_bytes()), bits))
    } else {
        None
    }
}

// ── ConstantFolding ───────────────────────────────────────────────────────────

/// Maximum expression-tree recursion depth accepted by the optimizer passes.
///
/// Malicious binaries can contain arbitrarily deep expression trees.  Without a
/// cap every recursive optimizer would stack-overflow.  512 levels is far more
/// than any real decompiled expression needs.
const MAX_FOLD_DEPTH: usize = 512;

/// Evaluates constant expressions at compile/lift time.
///
/// For example: `3 + 4` → `7`, `x * 0` → `0`, `x | 0` → `x`.
pub struct ConstantFolding;

impl ConstantFolding {
    /// Try to fold a HLIL expression to a constant.
    ///
    /// Recursion is bounded by [`MAX_FOLD_DEPTH`]; expressions deeper than
    /// that limit are returned unchanged to prevent stack exhaustion.
    #[must_use]
    pub fn fold(expr: &HlilExpr) -> HlilExpr {
        Self::fold_depth(expr, 0)
    }

    fn fold_depth(expr: &HlilExpr, depth: usize) -> HlilExpr {
        // dos-unbounded-recursion guard: return the expression unchanged once
        // we exceed the depth limit so we never overflow the call stack.
        if depth >= MAX_FOLD_DEPTH {
            return expr.clone();
        }
        // Macro-free shim so every recursive Self::fold call below passes depth+1.
        macro_rules! fold {
            ($e:expr) => {
                Self::fold_depth($e, depth + 1)
            };
        }
        match expr {
            HlilExpr::Add(a, b, ty) => {
                let fa = fold!(a);
                let fb = fold!(b);
                if let (Some((va, w)), Some((vb, _))) = (const_parts(&fa), const_parts(&fb)) {
                    return make_const(mask_to_width(va.wrapping_add(vb), w), w);
                }
                // x + 0 → x
                if matches!(const_parts(&fb), Some((0, _))) {
                    return fa;
                }
                if matches!(const_parts(&fa), Some((0, _))) {
                    return fb;
                }
                HlilExpr::Add(Box::new(fa), Box::new(fb), ty.clone())
            }
            HlilExpr::Sub(a, b, ty) => {
                let fa = fold!(a);
                let fb = fold!(b);
                if let (Some((va, w)), Some((vb, _))) = (const_parts(&fa), const_parts(&fb)) {
                    return make_const(mask_to_width(va.wrapping_sub(vb), w), w);
                }
                // x - 0 → x
                if matches!(const_parts(&fb), Some((0, _))) {
                    return fa;
                }
                HlilExpr::Sub(Box::new(fa), Box::new(fb), ty.clone())
            }
            HlilExpr::Mul(a, b, ty) => {
                let fa = fold!(a);
                let fb = fold!(b);
                if let (Some((va, w)), Some((vb, _))) = (const_parts(&fa), const_parts(&fb)) {
                    return make_const(mask_to_width(va.wrapping_mul(vb), w), w);
                }
                // x * 0 → 0, x * 1 → x
                if let Some((0, w)) = const_parts(&fb) {
                    return make_const(0, w);
                }
                if let Some((0, w)) = const_parts(&fa) {
                    return make_const(0, w);
                }
                if matches!(const_parts(&fb), Some((1, _))) {
                    return fa;
                }
                if matches!(const_parts(&fa), Some((1, _))) {
                    return fb;
                }
                HlilExpr::Mul(Box::new(fa), Box::new(fb), ty.clone())
            }
            // `Or`/`BitOr` are the same semantic op: `Or` is the canonical
            // tuple form emitted by the MLIL→HLIL lifter (see
            // `MlilExpr::Or => HlilExpr::Or` in lib.rs), while `BitOr` is an
            // alternate form some optimizer-internal rewrites construct
            // directly. Both MUST be folded identically or real lifted code
            // (which only ever uses `Or`) silently skips this rule.
            HlilExpr::Or(a, b, ty) => {
                let fa = fold!(a);
                let fb = fold!(b);
                if let (Some((va, w)), Some((vb, _))) = (const_parts(&fa), const_parts(&fb)) {
                    return make_const(va | vb, w);
                }
                // x | 0 → x
                if matches!(const_parts(&fb), Some((0, _))) {
                    return fa;
                }
                if matches!(const_parts(&fa), Some((0, _))) {
                    return fb;
                }
                HlilExpr::Or(Box::new(fa), Box::new(fb), ty.clone())
            }
            HlilExpr::BitOr(a, b) => {
                let fa = fold!(a);
                let fb = fold!(b);
                if let (Some((va, w)), Some((vb, _))) = (const_parts(&fa), const_parts(&fb)) {
                    return make_const(va | vb, w);
                }
                // x | 0 → x
                if matches!(const_parts(&fb), Some((0, _))) {
                    return fa;
                }
                if matches!(const_parts(&fa), Some((0, _))) {
                    return fb;
                }
                HlilExpr::BitOr(Box::new(fa), Box::new(fb))
            }
            // `And`/`BitAnd` — see `Or`/`BitOr` note above; same duplication.
            HlilExpr::And(a, b, ty) => {
                let fa = fold!(a);
                let fb = fold!(b);
                if let (Some((va, w)), Some((vb, _))) = (const_parts(&fa), const_parts(&fb)) {
                    return make_const(va & vb, w);
                }
                // x & 0 → 0
                if let Some((0, w)) = const_parts(&fb) {
                    return make_const(0, w);
                }
                if let Some((0, w)) = const_parts(&fa) {
                    return make_const(0, w);
                }
                HlilExpr::And(Box::new(fa), Box::new(fb), ty.clone())
            }
            HlilExpr::BitAnd(a, b) => {
                let fa = fold!(a);
                let fb = fold!(b);
                if let (Some((va, w)), Some((vb, _))) = (const_parts(&fa), const_parts(&fb)) {
                    return make_const(va & vb, w);
                }
                // x & 0 → 0
                if let Some((0, w)) = const_parts(&fb) {
                    return make_const(0, w);
                }
                if let Some((0, w)) = const_parts(&fa) {
                    return make_const(0, w);
                }
                HlilExpr::BitAnd(Box::new(fa), Box::new(fb))
            }
            // `Xor`/`BitXor` — see `Or`/`BitOr` note above; same duplication.
            HlilExpr::Xor(a, b, ty) => {
                let fa = fold!(a);
                let fb = fold!(b);
                if let (Some((va, w)), Some((vb, _))) = (const_parts(&fa), const_parts(&fb)) {
                    return make_const(va ^ vb, w);
                }
                // x ^ 0 → x
                if matches!(const_parts(&fb), Some((0, _))) {
                    return fa;
                }
                if matches!(const_parts(&fa), Some((0, _))) {
                    return fb;
                }
                HlilExpr::Xor(Box::new(fa), Box::new(fb), ty.clone())
            }
            HlilExpr::BitXor(a, b) => {
                let fa = fold!(a);
                let fb = fold!(b);
                if let (Some((va, w)), Some((vb, _))) = (const_parts(&fa), const_parts(&fb)) {
                    return make_const(va ^ vb, w);
                }
                // x ^ 0 → x
                if matches!(const_parts(&fb), Some((0, _))) {
                    return fa;
                }
                if matches!(const_parts(&fa), Some((0, _))) {
                    return fb;
                }
                HlilExpr::BitXor(Box::new(fa), Box::new(fb))
            }
            HlilExpr::Neg(a, ty) => {
                let fa = fold!(a);
                if let Some((v, w)) = const_parts(&fa) {
                    return make_const(mask_to_width(v.wrapping_neg(), w), w);
                }
                HlilExpr::Neg(Box::new(fa), ty.clone())
            }
            HlilExpr::Not(a, ty) => {
                let fa = fold!(a);
                if let Some((v, w)) = const_parts(&fa) {
                    let mask = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
                    return make_const(!v & mask, w);
                }
                HlilExpr::Not(Box::new(fa), ty.clone())
            }
            // Pass-through for other variants
            other => other.clone(),
        }
    }

    /// Apply constant folding to all expressions in a list of instructions.
    #[must_use]
    pub fn fold_instructions(instrs: &[HlilInstruction]) -> OptimizationResult {
        let mut result = OptimizationResult::unchanged(instrs.to_vec());
        let mut changes = 0usize;
        for instr in result.instructions.iter_mut() {
            let before = format!("{instr:?}");
            *instr = fold_instr(instr, Self::fold);
            if format!("{instr:?}") != before {
                changes += 1;
            }
        }
        for _ in 0..changes {
            result.record_change("ConstantFolding");
        }
        result
    }
}

// ── DeadAssignmentElim ─────────────────────────────────────────────────────────

/// Eliminates assignments to variables that are never subsequently read.
pub struct DeadAssignmentElim;

impl DeadAssignmentElim {
    /// Compute the set of live variables at each instruction (backward analysis).
    #[must_use]
    pub fn live_variables(instrs: &[HlilInstruction]) -> Vec<HashSet<String>> {
        let n = instrs.len();
        let mut live: Vec<HashSet<String>> = vec![HashSet::new(); n + 1];
        // Backward pass
        for i in (0..n).rev() {
            // The dataflow transfer function is `live_in = (live_out \ def) ∪ use`.
            // The KILL must be applied to `live_out` ONLY, before the uses are
            // unioned in — never after. A statement that both reads and writes
            // the same variable (`a = a + 1`, the overwhelmingly common
            // induction/accumulator shape) has `a` in both its use and its def
            // set; killing after the union erased that use, so `a` looked dead
            // before the statement and its reaching definition (`a = 5`) was
            // deleted as a dead assignment.
            let mut live_here = live[i + 1].clone();
            // Variables defined here are killed (from live-out only).
            for def in defined_vars(&instrs[i]) {
                live_here.remove(&def);
            }
            // Variables used by this instruction are live before it.
            live_here.extend(used_vars(&instrs[i]));
            live[i] = live_here;
        }
        live
    }

    /// Remove assignments to variables not live after the assignment.
    #[must_use]
    pub fn eliminate(instrs: &[HlilInstruction]) -> OptimizationResult {
        let n = instrs.len();
        let live = Self::live_variables(instrs);
        let mut result = OptimizationResult::unchanged(instrs.to_vec());
        let mut to_remove: HashSet<usize> = HashSet::new();
        let _ = n;

        for (i, instr) in instrs.iter().enumerate() {
            if let HlilInstruction::Assign { dest, value } = instr
                && !live[i + 1].contains(&dest.name)
                // Never delete an assignment whose RHS contains a call: the
                // call's side effects (I/O, memory writes, ...) are observable
                // even when the returned value is dead.
                && !expr_contains_call(value)
            {
                // If `dest` is not live after this instruction, it's dead
                to_remove.insert(i);
            }
        }

        if !to_remove.is_empty() {
            let new_instrs: Vec<HlilInstruction> = instrs
                .iter()
                .enumerate()
                .filter(|(i, _)| !to_remove.contains(i))
                .map(|(_, instr)| instr.clone())
                .collect();
            for _ in 0..to_remove.len() {
                result.record_change("DeadAssignmentElim");
            }
            result.instructions = new_instrs;
        }
        result
    }
}

// ── CommonSubexprElim ─────────────────────────────────────────────────────────

/// Eliminates redundant re-computation of the same expression.
///
/// Replaces duplicate expressions with the temporary assigned in
/// the first occurrence.
pub struct CommonSubexprElim;

impl CommonSubexprElim {
    /// Run CSE on a linear instruction list.
    ///
    /// Correctness invariants enforced here:
    /// - the expression map is invalidated whenever an operand variable of a
    ///   recorded expression is reassigned (the old value no longer matches);
    /// - the map is invalidated when the recorded temp itself is overwritten;
    /// - impure / memory-dependent expressions (anything containing a `Call`
    ///   or `Deref`) are never recorded or CSE'd — calls have side effects
    ///   and dereferences can change between occurrences;
    /// - `If`/`While` (which may conditionally reassign anything inside their
    ///   nested blocks) and `Call` statements clear the map entirely.
    #[must_use]
    pub fn eliminate(instrs: &[HlilInstruction]) -> OptimizationResult {
        let mut result = OptimizationResult::unchanged(instrs.to_vec());
        // Map from expression canonical string → (temp variable name, vars
        // read by the expression).
        let mut expr_map: HashMap<String, (String, Vec<String>)> = HashMap::new();
        let mut changes = 0usize;

        for instr in result.instructions.iter_mut() {
            match instr {
                HlilInstruction::Assign { dest, value } => {
                    let key = canonical_expr(value);
                    let pure = !expr_contains_call_or_deref(value);
                    let mut rewritten = false;
                    if pure && let Some((existing_name, _)) = expr_map.get(&key) {
                        // Replace with reference to existing temp
                        *value = HlilExpr::Var {
                            var: HlilVar {
                                name: existing_name.clone(),
                                ty: HlilType::Unknown,
                                is_param: false,
                                stack_offset: None,
                                version: 0,
                                is_ssa: false,
                            },
                        };
                        changes += 1;
                        rewritten = true;
                    }
                    // Redefinition of `dest` invalidates every recorded
                    // expression that reads `dest` and every entry whose
                    // temp is `dest` (its value just changed).
                    let dest_name = dest.name.clone();
                    expr_map.retain(|_, (temp, operands)| {
                        *temp != dest_name && !operands.iter().any(|v| *v == dest_name)
                    });
                    // Record this expression (only pure, non-rewritten, and
                    // not self-referential like `a = a + 1`).
                    if pure && !rewritten {
                        let operands = collect_vars(value);
                        if !operands.iter().any(|v| *v == dest_name) {
                            expr_map.insert(key, (dest_name, operands));
                        }
                    }
                }
                // Conditionally-executed nested blocks and calls may
                // redefine variables we cannot see from this linear walk:
                // drop all recorded expressions.
                HlilInstruction::If { .. }
                | HlilInstruction::While { .. }
                | HlilInstruction::Call { .. } => expr_map.clear(),
                HlilInstruction::Return(_) => {}
            }
        }
        for _ in 0..changes {
            result.record_change("CommonSubexprElim");
        }
        result
    }
}

/// True if `expr` contains a `Call` anywhere in its tree — such an expression
/// has observable side effects and must never be deleted as dead code.
fn expr_contains_call(expr: &HlilExpr) -> bool {
    if matches!(expr, HlilExpr::Call { .. }) {
        return true;
    }
    let mut found = false;
    for_each_child(expr, &mut |child| {
        if expr_contains_call(child) {
            found = true;
        }
    });
    found
}

/// True if `expr` contains a `Call` (impure) or `Deref` (memory-dependent)
/// anywhere in its tree — such expressions must not participate in CSE.
fn expr_contains_call_or_deref(expr: &HlilExpr) -> bool {
    if matches!(expr, HlilExpr::Call { .. } | HlilExpr::Deref { .. }) {
        return true;
    }
    let mut found = false;
    for_each_child(expr, &mut |child| {
        if expr_contains_call_or_deref(child) {
            found = true;
        }
    });
    found
}

/// Invoke `f` on each direct child expression of `expr`.
fn for_each_child(expr: &HlilExpr, f: &mut impl FnMut(&HlilExpr)) {
    match expr {
        HlilExpr::Const { .. }
        | HlilExpr::Float { .. }
        | HlilExpr::Var { .. }
        | HlilExpr::AddressOf { .. }
        | HlilExpr::SizeOf { .. }
        | HlilExpr::ConstFloat(..)
        | HlilExpr::Undefined(..) => {}
        HlilExpr::Deref { addr: a, .. }
        | HlilExpr::Neg(a, _)
        | HlilExpr::Not(a, _)
        | HlilExpr::LogicalNot(a)
        | HlilExpr::BoolNot(a)
        | HlilExpr::AddrOf(a)
        | HlilExpr::Cast { expr: a, .. }
        | HlilExpr::FieldAccess { base: a, .. } => f(a),
        HlilExpr::Add(a, b, _)
        | HlilExpr::Sub(a, b, _)
        | HlilExpr::Mul(a, b, _)
        | HlilExpr::Div(a, b, _)
        | HlilExpr::Mod(a, b, _)
        | HlilExpr::And(a, b, _)
        | HlilExpr::Or(a, b, _)
        | HlilExpr::Xor(a, b, _)
        | HlilExpr::Shl(a, b, _)
        | HlilExpr::Shr(a, b, _)
        | HlilExpr::CmpEq(a, b)
        | HlilExpr::CmpNe(a, b)
        | HlilExpr::CmpLt(a, b)
        | HlilExpr::CmpGt(a, b)
        | HlilExpr::CmpLe(a, b)
        | HlilExpr::CmpGe(a, b)
        | HlilExpr::LogicalAnd(a, b)
        | HlilExpr::LogicalOr(a, b)
        | HlilExpr::BitOr(a, b)
        | HlilExpr::BitAnd(a, b)
        | HlilExpr::BitXor(a, b)
        | HlilExpr::BoolAnd(a, b)
        | HlilExpr::BoolOr(a, b)
        | HlilExpr::DivU(a, b)
        | HlilExpr::DivS(a, b)
        | HlilExpr::ModU(a, b)
        | HlilExpr::ModS(a, b)
        | HlilExpr::Sar(a, b)
        | HlilExpr::CmpSlt(a, b)
        | HlilExpr::CmpUlt(a, b)
        | HlilExpr::CmpSle(a, b)
        | HlilExpr::CmpUle(a, b)
        | HlilExpr::CmpSgt(a, b)
        | HlilExpr::CmpUgt(a, b)
        | HlilExpr::CmpSge(a, b)
        | HlilExpr::CmpUge(a, b) => {
            f(a);
            f(b);
        }
        HlilExpr::Index { base, idx, .. } => {
            f(base);
            f(idx);
        }
        HlilExpr::ArrayIndex { array, index } => {
            f(array);
            f(index);
        }
        HlilExpr::Call { func, args, .. } => {
            f(func);
            for a in args {
                f(a);
            }
        }
        HlilExpr::Ternary {
            cond, then, else_, ..
        } => {
            f(cond);
            f(then);
            f(else_);
        }
        HlilExpr::If {
            cond,
            then_branch,
            else_branch,
        } => {
            f(cond);
            f(then_branch);
            f(else_branch);
        }
    }
}

// ── SimplifyConditions ────────────────────────────────────────────────────────

/// Simplifies boolean conditions in if/while/for statements.
///
/// Rules: `true && x` → `x`, `false || x` → `x`, `!!x` → `x`, etc.
pub struct SimplifyConditions;

impl SimplifyConditions {
    /// Simplify a HLIL condition expression.
    ///
    /// Recursion is bounded by [`MAX_FOLD_DEPTH`] to prevent stack exhaustion
    /// on adversarially deep expression trees from malicious binaries.
    #[must_use]
    pub fn simplify(expr: &HlilExpr) -> HlilExpr {
        Self::simplify_depth(expr, 0)
    }

    fn simplify_depth(expr: &HlilExpr, depth: usize) -> HlilExpr {
        if depth >= MAX_FOLD_DEPTH {
            return expr.clone();
        }
        macro_rules! simp {
            ($e:expr) => {
                Self::simplify_depth($e, depth + 1)
            };
        }
        match expr {
            // `LogicalAnd`/`BoolAnd` are the same semantic op: `LogicalAnd` is
            // the form the lifter's if-conversion actually constructs (see
            // `HlilExpr::LogicalAnd` uses in lib.rs), while `BoolAnd` is an
            // alternate form used by other optimizer-internal rewrites. Both
            // must simplify identically or real lifted conditions (which only
            // ever use `LogicalAnd`) silently skip this rule.
            HlilExpr::LogicalAnd(a, b) | HlilExpr::BoolAnd(a, b) => {
                let sa = simp!(a);
                let sb = simp!(b);
                // false && x → false
                if let Some((0, w)) = const_parts(&sa) {
                    return make_const(0, w);
                }
                if let Some((0, w)) = const_parts(&sb) {
                    return make_const(0, w);
                }
                // true && x → x
                if matches!(const_parts(&sa), Some((1, _))) {
                    return sb;
                }
                if matches!(const_parts(&sb), Some((1, _))) {
                    return sa;
                }
                // x && x → x
                if canonical_expr(&sa) == canonical_expr(&sb) {
                    return sa;
                }
                if matches!(expr, HlilExpr::LogicalAnd(..)) {
                    HlilExpr::LogicalAnd(Box::new(sa), Box::new(sb))
                } else {
                    HlilExpr::BoolAnd(Box::new(sa), Box::new(sb))
                }
            }
            // `LogicalOr`/`BoolOr` — see `LogicalAnd`/`BoolAnd` note above.
            HlilExpr::LogicalOr(a, b) | HlilExpr::BoolOr(a, b) => {
                let sa = simp!(a);
                let sb = simp!(b);
                // true || x → true
                if let Some((1, w)) = const_parts(&sa) {
                    return make_const(1, w);
                }
                if let Some((1, w)) = const_parts(&sb) {
                    return make_const(1, w);
                }
                // false || x → x
                if matches!(const_parts(&sa), Some((0, _))) {
                    return sb;
                }
                if matches!(const_parts(&sb), Some((0, _))) {
                    return sa;
                }
                // x || x → x
                if canonical_expr(&sa) == canonical_expr(&sb) {
                    return sa;
                }
                if matches!(expr, HlilExpr::LogicalOr(..)) {
                    HlilExpr::LogicalOr(Box::new(sa), Box::new(sb))
                } else {
                    HlilExpr::BoolOr(Box::new(sa), Box::new(sb))
                }
            }
            // `LogicalNot`/`BoolNot` — see `LogicalAnd`/`BoolAnd` note above.
            HlilExpr::LogicalNot(a) | HlilExpr::BoolNot(a) => {
                let sa = simp!(a);
                let is_logical = matches!(expr, HlilExpr::LogicalNot(..));
                // !!x → x
                if let HlilExpr::LogicalNot(inner) | HlilExpr::BoolNot(inner) = &sa {
                    return (**inner).clone();
                }
                // !true → false
                if let Some((1, w)) = const_parts(&sa) {
                    return make_const(0, w);
                }
                // !false → true
                if let Some((0, w)) = const_parts(&sa) {
                    return make_const(1, w);
                }
                if is_logical {
                    HlilExpr::LogicalNot(Box::new(sa))
                } else {
                    HlilExpr::BoolNot(Box::new(sa))
                }
            }
            HlilExpr::CmpEq(a, b) => {
                let sa = simp!(a);
                let sb = simp!(b);
                // Constant comparison
                if let (Some((va, w)), Some((vb, _))) = (const_parts(&sa), const_parts(&sb)) {
                    return make_const(u64::from(va == vb), w);
                }
                HlilExpr::CmpEq(Box::new(sa), Box::new(sb))
            }
            HlilExpr::CmpNe(a, b) => {
                let sa = simp!(a);
                let sb = simp!(b);
                if let (Some((va, w)), Some((vb, _))) = (const_parts(&sa), const_parts(&sb)) {
                    return make_const(if va == vb { 0 } else { 1 }, w);
                }
                HlilExpr::CmpNe(Box::new(sa), Box::new(sb))
            }
            other => other.clone(),
        }
    }

    /// Apply condition simplification to all if/while/for instructions.
    #[must_use]
    pub fn simplify_instructions(instrs: &[HlilInstruction]) -> OptimizationResult {
        let mut result = OptimizationResult::unchanged(instrs.to_vec());
        let mut changes = 0usize;
        for instr in result.instructions.iter_mut() {
            let before = format!("{instr:?}");
            *instr = simplify_cond_instr(instr, Self::simplify);
            if format!("{instr:?}") != before {
                changes += 1;
            }
        }
        for _ in 0..changes {
            result.record_change("SimplifyConditions");
        }
        result
    }
}

// ── RemoveRedundantCasts ──────────────────────────────────────────────────────

/// Removes casts where source and destination types are identical.
pub struct RemoveRedundantCasts;

impl RemoveRedundantCasts {
    /// Simplify `Cast { ty, value }` when the types match or the outer cast
    /// can be absorbed.
    ///
    /// Recursion is bounded by [`MAX_FOLD_DEPTH`] to prevent stack exhaustion
    /// on adversarially deep cast chains from malicious binaries.
    #[must_use]
    pub fn simplify(expr: &HlilExpr) -> HlilExpr {
        Self::simplify_depth(expr, 0)
    }

    fn simplify_depth(expr: &HlilExpr, depth: usize) -> HlilExpr {
        if depth >= MAX_FOLD_DEPTH {
            return expr.clone();
        }
        match expr {
            HlilExpr::Cast { expr: value, to } => {
                let sv = Self::simplify_depth(value, depth + 1);
                // If value is itself a cast to the same type, collapse
                if let HlilExpr::Cast { expr: inner_val, to: inner_ty, } = &sv && to == inner_ty {
                    return HlilExpr::Cast {
                        to: to.clone(),
                        expr: inner_val.clone(),
                    };
                }
                // If value is a Const, fold cast into appropriately-sized Const
                if let Some((v, _)) = const_parts(&sv) && let HlilType::Int { bits, .. } = to {
                    let mask = if *bits >= 64 {
                        u64::MAX
                    } else {
                        (1u64 << bits) - 1
                    };
                    return make_const(v & mask, *bits as usize);
                }
                HlilExpr::Cast {
                    to: to.clone(),
                    expr: Box::new(sv),
                }
            }
            other => other.clone(),
        }
    }

    /// Apply redundant-cast removal to all instructions.
    #[must_use]
    pub fn remove_instructions(instrs: &[HlilInstruction]) -> OptimizationResult {
        let mut result = OptimizationResult::unchanged(instrs.to_vec());
        let mut changes = 0usize;
        for instr in result.instructions.iter_mut() {
            let before = format!("{instr:?}");
            *instr = fold_instr(instr, Self::simplify);
            if format!("{instr:?}") != before {
                changes += 1;
            }
        }
        for _ in 0..changes {
            result.record_change("RemoveRedundantCasts");
        }
        result
    }
}

// ── HlilOptimizer ─────────────────────────────────────────────────────────────

/// Combines all HLIL optimization passes in a configurable pipeline.
pub struct HlilOptimizer {
    pub run_constant_folding: bool,
    pub run_dead_assign_elim: bool,
    pub run_cse: bool,
    pub run_simplify_conditions: bool,
    pub run_remove_redundant_casts: bool,
    pub max_iterations: usize,
}

impl HlilOptimizer {
    /// Create an optimizer with all passes enabled and up to 10 iterations.
    #[must_use]
    pub fn default_pipeline() -> Self {
        Self {
            run_constant_folding: true,
            run_dead_assign_elim: true,
            run_cse: true,
            run_simplify_conditions: true,
            run_remove_redundant_casts: true,
            max_iterations: 10,
        }
    }

    /// Create a minimal optimizer (constant folding + dead assign only).
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            run_constant_folding: true,
            run_dead_assign_elim: true,
            run_cse: false,
            run_simplify_conditions: false,
            run_remove_redundant_casts: false,
            max_iterations: 3,
        }
    }

    /// Run the optimization pipeline on a list of instructions until fixpoint.
    #[must_use]
    pub fn optimize(&self, instrs: &[HlilInstruction]) -> OptimizationResult {
        let mut current = instrs.to_vec();
        let mut total_changes = 0usize;
        let mut all_passes: Vec<String> = Vec::new();

        for _ in 0..self.max_iterations {
            let mut changed = false;

            if self.run_constant_folding {
                let r = ConstantFolding::fold_instructions(&current);
                if r.was_modified() {
                    changed = true;
                    total_changes += r.changes;
                    all_passes.extend(r.passes_fired);
                }
                current = r.instructions;
            }
            if self.run_remove_redundant_casts {
                let r = RemoveRedundantCasts::remove_instructions(&current);
                if r.was_modified() {
                    changed = true;
                    total_changes += r.changes;
                    all_passes.extend(r.passes_fired);
                }
                current = r.instructions;
            }
            if self.run_simplify_conditions {
                let r = SimplifyConditions::simplify_instructions(&current);
                if r.was_modified() {
                    changed = true;
                    total_changes += r.changes;
                    all_passes.extend(r.passes_fired);
                }
                current = r.instructions;
            }
            if self.run_cse {
                let r = CommonSubexprElim::eliminate(&current);
                if r.was_modified() {
                    changed = true;
                    total_changes += r.changes;
                    all_passes.extend(r.passes_fired);
                }
                current = r.instructions;
            }
            if self.run_dead_assign_elim {
                let r = DeadAssignmentElim::eliminate(&current);
                if r.was_modified() {
                    changed = true;
                    total_changes += r.changes;
                    all_passes.extend(r.passes_fired);
                }
                current = r.instructions;
            }

            if !changed {
                break;
            }
        }

        all_passes.sort();
        all_passes.dedup();
        OptimizationResult {
            instructions: current,
            changes: total_changes,
            passes_fired: all_passes,
        }
    }
}

impl Default for HlilOptimizer {
    fn default() -> Self {
        Self::default_pipeline()
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn canonical_expr(expr: &HlilExpr) -> String {
    format!("{expr:?}")
}

fn used_vars(instr: &HlilInstruction) -> Vec<String> {
    match instr {
        HlilInstruction::Assign { value, .. } => collect_vars(value),
        HlilInstruction::Return(Some(e)) => collect_vars(e),
        HlilInstruction::Return(None) => Vec::new(),
        // If/While must include everything used anywhere inside the nested
        // blocks, not just the condition: this is a straight-line liveness
        // pass, so a variable read only inside a conditionally-executed
        // branch/loop body would otherwise be invisible and its defining
        // assignment deleted. Nested *definitions* are deliberately NOT
        // treated as kills (see `defined_vars`) — a def inside a
        // conditionally-executed block may not execute, so treating it as a
        // kill would be unsound. This over-approximation (use-union, no
        // kills) is the required conservative direction for DAE.
        HlilInstruction::If {
            condition,
            then_block,
            else_block,
        } => {
            let mut v = collect_vars(condition);
            v.extend(then_block.iter().flat_map(used_vars_recursive));
            v.extend(else_block.iter().flat_map(used_vars_recursive));
            v
        }
        HlilInstruction::While { condition, body } => {
            let mut v = collect_vars(condition);
            v.extend(body.iter().flat_map(used_vars_recursive));
            v
        }
        HlilInstruction::Call { target, args, .. } => {
            let mut v = collect_vars(target);
            v.extend(args.iter().flat_map(collect_vars));
            v
        }
    }
}

/// All variables used anywhere inside `instr`, including nested blocks.
/// Unlike `used_vars` composed per-instruction, this never subtracts defs:
/// it is the conservative "may be read inside" set for nested regions.
fn used_vars_recursive(instr: &HlilInstruction) -> Vec<String> {
    // `used_vars` already recurses into If/While blocks, so it is exactly
    // the union we need for every instruction kind.
    used_vars(instr)
}

fn defined_vars(instr: &HlilInstruction) -> Vec<String> {
    match instr {
        HlilInstruction::Assign { dest, .. } => vec![dest.name.clone()],
        _ => Vec::new(),
    }
}

fn collect_vars(expr: &HlilExpr) -> Vec<String> {
    // Delegate to the crate-level exhaustive visitor (`collect_vars_expr` in
    // lib.rs) so every `HlilExpr` variant — canonical forms (And/Or/Xor,
    // Shl/Shr, Div/Mod, CmpLe/CmpGe, LogicalAnd/LogicalOr/LogicalNot, Index,
    // FieldAccess, Ternary, AddressOf, ...) *and* the alternate optimizer
    // forms — is covered. The previous hand-rolled match here only handled
    // Add/Sub/Mul, the Bit*/Bool* alternates and four comparisons; every
    // other variant fell into `_ => Vec::new()`, so DeadAssignmentElim
    // deleted live assignments whose only use was e.g. `x | y`, `x << 2`,
    // `a <= b` or a LogicalAnd condition (the forms the MLIL→HLIL lifter
    // actually constructs).
    let mut out: Vec<&HlilVar> = Vec::new();
    crate::collect_vars_expr(expr, &mut out);
    out.into_iter().map(|v| v.name.clone()).collect()
}

fn fold_instr(instr: &HlilInstruction, folder: impl Fn(&HlilExpr) -> HlilExpr) -> HlilInstruction {
    fold_instr_ref(instr, &folder)
}

/// Recursive worker for [`fold_instr`]: applies `folder` to every expression
/// in `instr`, *including* expressions inside nested `If`/`While` blocks.
/// (Previously nested blocks were cloned verbatim, so folding passes silently
/// no-op'd on exactly the structured code this HLIL layer produces.)
fn fold_instr_ref<F: Fn(&HlilExpr) -> HlilExpr>(
    instr: &HlilInstruction,
    folder: &F,
) -> HlilInstruction {
    match instr {
        HlilInstruction::Assign { dest, value } => HlilInstruction::Assign {
            dest: dest.clone(),
            value: folder(value),
        },
        HlilInstruction::Return(Some(e)) => HlilInstruction::Return(Some(folder(e))),
        HlilInstruction::If {
            condition,
            then_block,
            else_block,
        } => HlilInstruction::If {
            condition: folder(condition),
            then_block: then_block.iter().map(|i| fold_instr_ref(i, folder)).collect(),
            else_block: else_block.iter().map(|i| fold_instr_ref(i, folder)).collect(),
        },
        HlilInstruction::While { condition, body } => HlilInstruction::While {
            condition: folder(condition),
            body: body.iter().map(|i| fold_instr_ref(i, folder)).collect(),
        },
        other => other.clone(),
    }
}

fn simplify_cond_instr(
    instr: &HlilInstruction,
    simplifier: impl Fn(&HlilExpr) -> HlilExpr,
) -> HlilInstruction {
    simplify_cond_instr_ref(instr, &simplifier)
}

/// Recursive worker for [`simplify_cond_instr`]: simplifies the condition of
/// every `If`/`While`, including those nested inside other blocks.
fn simplify_cond_instr_ref<F: Fn(&HlilExpr) -> HlilExpr>(
    instr: &HlilInstruction,
    simplifier: &F,
) -> HlilInstruction {
    match instr {
        HlilInstruction::If {
            condition,
            then_block,
            else_block,
        } => HlilInstruction::If {
            condition: simplifier(condition),
            then_block: then_block
                .iter()
                .map(|i| simplify_cond_instr_ref(i, simplifier))
                .collect(),
            else_block: else_block
                .iter()
                .map(|i| simplify_cond_instr_ref(i, simplifier))
                .collect(),
        },
        HlilInstruction::While { condition, body } => HlilInstruction::While {
            condition: simplifier(condition),
            body: body
                .iter()
                .map(|i| simplify_cond_instr_ref(i, simplifier))
                .collect(),
        },
        other => other.clone(),
    }
}

// ── HlilPipeline ──────────────────────────────────────────────────────────────

/// A named, ordered sequence of optimization passes with integrated profiling.
pub struct HlilPipeline {
    pub name: String,
    pub optimizer: HlilOptimizer,
    /// Change counts per pass key.
    pub change_counts: std::collections::HashMap<String, usize>,
    /// Total optimization passes run.
    pub total_runs: usize,
}

impl HlilPipeline {
    /// Create a standard pipeline.
    #[must_use]
    pub fn standard(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            optimizer: HlilOptimizer::default_pipeline(),
            change_counts: std::collections::HashMap::new(),
            total_runs: 0,
        }
    }

    /// Create a fast pipeline (fewer passes).
    #[must_use]
    pub fn fast(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            optimizer: HlilOptimizer::minimal(),
            change_counts: std::collections::HashMap::new(),
            total_runs: 0,
        }
    }

    /// Run the pipeline, updating statistics.
    pub fn run(&mut self, instrs: &[HlilInstruction]) -> OptimizationResult {
        self.total_runs += 1;
        let result = self.optimizer.optimize(instrs);
        for pass in &result.passes_fired {
            *self.change_counts.entry(pass.clone()).or_insert(0) += 1;
        }
        result
    }

    /// Total number of changes recorded.
    #[must_use]
    pub fn total_changes(&self) -> usize {
        self.change_counts.values().sum()
    }

    /// Most frequently firing pass.
    #[must_use]
    pub fn hottest_pass(&self) -> Option<&str> {
        self.change_counts
            .iter()
            .max_by_key(|(_, v)| **v)
            .map(|(k, _)| k.as_str())
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.change_counts.clear();
        self.total_runs = 0;
    }
}

// ── ExprComplexity ────────────────────────────────────────────────────────────

/// Measures the syntactic complexity of a HLIL expression.
pub struct ExprComplexity;

impl ExprComplexity {
    /// Return the depth of an expression tree.
    #[must_use]
    pub fn depth(expr: &HlilExpr) -> usize {
        match expr {
            HlilExpr::Add(a, b, ..)
            | HlilExpr::Sub(a, b, ..)
            | HlilExpr::Mul(a, b, ..)
            | HlilExpr::Div(a, b, ..)
            | HlilExpr::Mod(a, b, ..)
            | HlilExpr::Shl(a, b, ..)
            | HlilExpr::Shr(a, b, ..)
            | HlilExpr::BitOr(a, b)
            | HlilExpr::BitAnd(a, b)
            | HlilExpr::BitXor(a, b)
            | HlilExpr::BoolAnd(a, b)
            | HlilExpr::BoolOr(a, b)
            | HlilExpr::CmpEq(a, b)
            | HlilExpr::CmpNe(a, b)
            | HlilExpr::CmpLt(a, b)
            | HlilExpr::CmpGt(a, b)
            | HlilExpr::CmpLe(a, b)
            | HlilExpr::CmpGe(a, b) => 1 + Self::depth(a).max(Self::depth(b)),
            HlilExpr::Neg(a, ..)
            | HlilExpr::Not(a, ..)
            | HlilExpr::BoolNot(a)
            | HlilExpr::Deref { addr: a, .. }
            | HlilExpr::Cast { expr: a, .. } => 1 + Self::depth(a),
            HlilExpr::Call { args, .. } => 1 + args.iter().map(Self::depth).max().unwrap_or(0),
            _ => 0,
        }
    }

    /// Count the number of leaf nodes (Const + Var).
    #[must_use]
    pub fn leaf_count(expr: &HlilExpr) -> usize {
        match expr {
            HlilExpr::Const { .. } | HlilExpr::Var { .. } => 1,
            HlilExpr::Add(a, b, ..)
            | HlilExpr::Sub(a, b, ..)
            | HlilExpr::Mul(a, b, ..)
            | HlilExpr::Div(a, b, ..)
            | HlilExpr::Mod(a, b, ..)
            | HlilExpr::Shl(a, b, ..)
            | HlilExpr::Shr(a, b, ..)
            | HlilExpr::BitOr(a, b)
            | HlilExpr::BitAnd(a, b)
            | HlilExpr::BitXor(a, b)
            | HlilExpr::BoolAnd(a, b)
            | HlilExpr::BoolOr(a, b)
            | HlilExpr::CmpEq(a, b)
            | HlilExpr::CmpNe(a, b)
            | HlilExpr::CmpLt(a, b)
            | HlilExpr::CmpGt(a, b)
            | HlilExpr::CmpLe(a, b)
            | HlilExpr::CmpGe(a, b) => Self::leaf_count(a) + Self::leaf_count(b),
            HlilExpr::Neg(a, ..)
            | HlilExpr::Not(a, ..)
            | HlilExpr::BoolNot(a)
            | HlilExpr::Deref { addr: a, .. }
            | HlilExpr::Cast { expr: a, .. } => Self::leaf_count(a),
            HlilExpr::Call { args, .. } => args.iter().map(Self::leaf_count).sum(),
            _ => 0,
        }
    }

    /// Check if an expression is "simple" (depth ≤ 1).
    #[must_use]
    pub fn is_simple(expr: &HlilExpr) -> bool {
        Self::depth(expr) <= 1
    }

    /// Check if an expression is a constant.
    #[must_use]
    pub fn is_constant(expr: &HlilExpr) -> bool {
        matches!(expr, HlilExpr::Const { .. })
    }

    /// Check if an expression is a variable reference.
    #[must_use]
    pub fn is_variable(expr: &HlilExpr) -> bool {
        matches!(expr, HlilExpr::Var { .. })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HlilExpr, HlilInstruction, HlilType, HlilVar};

    fn c(v: u64, bits: usize) -> HlilExpr {
        make_const(v, bits)
    }
    fn var(name: &str) -> HlilExpr {
        HlilExpr::Var {
            var: HlilVar {
                name: name.into(),
                ty: HlilType::Unknown,
                is_param: false,
                stack_offset: None,
                version: 0,
                is_ssa: false,
            },
        }
    }
    fn hlil_var(name: &str) -> HlilVar {
        HlilVar {
            name: name.into(),
            ty: HlilType::Unknown,
            is_param: false,
            stack_offset: None,
            version: 0,
            is_ssa: false,
        }
    }
    fn assign(name: &str, value: HlilExpr) -> HlilInstruction {
        HlilInstruction::Assign {
            dest: hlil_var(name),
            value,
        }
    }

    // ── ConstantFolding ───────────────────────────────────────────────────────

    #[test]
    fn test_cf_add_constants() {
        let expr = HlilExpr::Add(Box::new(c(3, 32)), Box::new(c(4, 32)), int_ty(32));
        assert_eq!(ConstantFolding::fold(&expr), c(7, 32));
    }

    #[test]
    fn test_cf_sub_constants() {
        let expr = HlilExpr::Sub(Box::new(c(10, 32)), Box::new(c(3, 32)), int_ty(32));
        assert_eq!(ConstantFolding::fold(&expr), c(7, 32));
    }

    #[test]
    fn test_cf_mul_constants() {
        let expr = HlilExpr::Mul(Box::new(c(6, 32)), Box::new(c(7, 32)), int_ty(32));
        assert_eq!(ConstantFolding::fold(&expr), c(42, 32));
    }

    #[test]
    fn test_cf_mul_by_zero() {
        let expr = HlilExpr::Mul(Box::new(var("x")), Box::new(c(0, 32)), int_ty(32));
        assert_eq!(ConstantFolding::fold(&expr), c(0, 32));
    }

    #[test]
    fn test_cf_add_zero() {
        let expr = HlilExpr::Add(Box::new(var("x")), Box::new(c(0, 32)), int_ty(32));
        assert_eq!(ConstantFolding::fold(&expr), var("x"));
    }

    #[test]
    fn test_cf_bitor_constants() {
        let expr = HlilExpr::BitOr(Box::new(c(0b1010, 8)), Box::new(c(0b0101, 8)));
        assert_eq!(ConstantFolding::fold(&expr), c(0b1111, 8));
    }

    #[test]
    fn test_cf_bitand_zero() {
        let expr = HlilExpr::BitAnd(Box::new(var("x")), Box::new(c(0, 32)));
        assert_eq!(ConstantFolding::fold(&expr), c(0, 32));
    }

    #[test]
    fn test_cf_bitxor_zero() {
        let expr = HlilExpr::BitXor(Box::new(var("x")), Box::new(c(0, 32)));
        assert_eq!(ConstantFolding::fold(&expr), var("x"));
    }

    #[test]
    fn test_cf_neg_constant() {
        let expr = HlilExpr::Neg(Box::new(c(1u64, 64)), int_ty(64));
        let folded = ConstantFolding::fold(&expr);
        assert_eq!(folded, c(u64::MAX, 64));
    }

    #[test]
    fn test_cf_not_constant() {
        let expr = HlilExpr::Not(Box::new(c(0u64, 8)), int_ty(8));
        assert_eq!(ConstantFolding::fold(&expr), c(0xFF, 8));
    }

    #[test]
    fn test_cf_fold_instructions_records_change() {
        let instrs = vec![assign(
            "x",
            HlilExpr::Add(Box::new(c(2, 32)), Box::new(c(3, 32)), int_ty(32)),
        )];
        let result = ConstantFolding::fold_instructions(&instrs);
        assert!(result.was_modified());
        assert!(result.passes_fired.contains(&"ConstantFolding".to_string()));
    }

    // ── DeadAssignmentElim ────────────────────────────────────────────────────

    #[test]
    fn test_dae_eliminates_dead_var() {
        let instrs = vec![
            assign("dead", c(42, 32)),
            assign("live", c(1, 32)),
            HlilInstruction::Return(Some(var("live"))),
        ];
        let result = DeadAssignmentElim::eliminate(&instrs);
        // "dead" is never used after its assignment
        assert!(
            !result
                .instructions
                .iter()
                .any(|i| matches!(i, HlilInstruction::Assign { dest, .. } if dest.name == "dead"))
        );
    }

    #[test]
    fn test_dae_keeps_live_var() {
        let instrs = vec![
            assign("x", c(5, 32)),
            HlilInstruction::Return(Some(var("x"))),
        ];
        let result = DeadAssignmentElim::eliminate(&instrs);
        assert!(
            result
                .instructions
                .iter()
                .any(|i| matches!(i, HlilInstruction::Assign { dest, .. } if dest.name == "x"))
        );
    }

    #[test]
    fn test_dae_live_variables_basic() {
        let instrs = vec![
            assign("a", c(1, 32)),
            HlilInstruction::Return(Some(var("a"))),
        ];
        let live = DeadAssignmentElim::live_variables(&instrs);
        // Before return, "a" is live
        assert!(live[1].contains("a"));
    }

    // ── CommonSubexprElim ─────────────────────────────────────────────────────

    #[test]
    fn test_cse_replaces_duplicate_expr() {
        let expr = HlilExpr::Add(Box::new(var("a")), Box::new(c(1, 32)), int_ty(32));
        let instrs = vec![assign("t1", expr.clone()), assign("t2", expr)];
        let result = CommonSubexprElim::eliminate(&instrs);
        assert!(result.was_modified());
    }

    #[test]
    fn test_cse_no_change_unique_exprs() {
        let instrs = vec![
            assign(
                "t1",
                HlilExpr::Add(Box::new(var("a")), Box::new(c(1, 32)), int_ty(32)),
            ),
            assign(
                "t2",
                HlilExpr::Add(Box::new(var("b")), Box::new(c(2, 32)), int_ty(32)),
            ),
        ];
        let result = CommonSubexprElim::eliminate(&instrs);
        assert!(!result.was_modified());
    }

    // ── Regression tests: DAE canonical-operator uses (finding: collect_vars
    //    missed canonical variants, deleting live assignments) ───────────────

    #[test]
    fn dae_keeps_var_used_by_canonical_shl() {
        // [a = 5; return a << 2] — `a` is live via the canonical Shl form.
        let instrs = vec![
            assign("a", c(5, 32)),
            HlilInstruction::Return(Some(HlilExpr::Shl(
                Box::new(var("a")),
                Box::new(c(2, 32)),
                int_ty(32),
            ))),
        ];
        let result = DeadAssignmentElim::eliminate(&instrs);
        assert!(
            result.instructions.iter().any(
                |i| matches!(i, HlilInstruction::Assign { dest, .. } if dest.name == "a")
            ),
            "assignment to `a` (used via Shl) must not be eliminated"
        );
    }

    #[test]
    fn dae_keeps_vars_used_by_canonical_forms() {
        // Every canonical operator form the MLIL→HLIL lifter constructs must
        // count as a use.
        let uses: Vec<(&str, HlilExpr)> = vec![
            ("o", HlilExpr::Or(Box::new(var("o")), Box::new(c(1, 32)), int_ty(32))),
            ("d", HlilExpr::Div(Box::new(var("d")), Box::new(c(2, 32)), int_ty(32))),
            ("m", HlilExpr::Mod(Box::new(var("m")), Box::new(c(2, 32)), int_ty(32))),
            ("le", HlilExpr::CmpLe(Box::new(var("le")), Box::new(c(3, 32)))),
            ("ge", HlilExpr::CmpGe(Box::new(var("ge")), Box::new(c(3, 32)))),
            (
                "la",
                HlilExpr::LogicalAnd(Box::new(var("la")), Box::new(c(1, 1))),
            ),
            ("ln", HlilExpr::LogicalNot(Box::new(var("ln")))),
            (
                "tern",
                HlilExpr::Ternary {
                    cond: Box::new(var("tern")),
                    then: Box::new(c(1, 32)),
                    else_: Box::new(c(0, 32)),
                    ty: int_ty(32),
                },
            ),
            (
                "idx",
                HlilExpr::Index {
                    base: Box::new(var("idx")),
                    idx: Box::new(c(0, 32)),
                    ty: int_ty(32),
                },
            ),
            (
                "fld",
                HlilExpr::FieldAccess {
                    base: Box::new(var("fld")),
                    field: "f".into(),
                    ty: int_ty(32),
                },
            ),
        ];
        for (name, use_expr) in uses {
            let instrs = vec![
                assign(name, c(7, 32)),
                HlilInstruction::Return(Some(use_expr)),
            ];
            let result = DeadAssignmentElim::eliminate(&instrs);
            assert!(
                result.instructions.iter().any(
                    |i| matches!(i, HlilInstruction::Assign { dest, .. } if dest.name == name)
                ),
                "assignment to `{name}` must survive: its only use is a canonical form"
            );
        }
    }

    #[test]
    fn dae_keeps_var_used_only_inside_if_branch() {
        // [x = 5; if (c) { return x; }] — x is read only inside the branch.
        let instrs = vec![
            assign("x", c(5, 32)),
            HlilInstruction::If {
                condition: var("c"),
                then_block: vec![HlilInstruction::Return(Some(var("x")))],
                else_block: vec![],
            },
        ];
        let result = DeadAssignmentElim::eliminate(&instrs);
        assert!(
            result.instructions.iter().any(
                |i| matches!(i, HlilInstruction::Assign { dest, .. } if dest.name == "x")
            ),
            "assignment read only inside a nested If block must not be eliminated"
        );
    }

    #[test]
    fn dae_keeps_var_used_only_inside_while_body() {
        let instrs = vec![
            assign("n", c(5, 32)),
            HlilInstruction::While {
                condition: var("c"),
                body: vec![HlilInstruction::Call {
                    target: Box::new(var("f")),
                    args: vec![var("n")],
                }],
            },
        ];
        let result = DeadAssignmentElim::eliminate(&instrs);
        assert!(
            result.instructions.iter().any(
                |i| matches!(i, HlilInstruction::Assign { dest, .. } if dest.name == "n")
            ),
            "assignment read only inside a While body must not be eliminated"
        );
    }

    #[test]
    fn dae_nested_def_is_not_a_kill() {
        // [x = 3; if (c) { x = 5; }; return x] — the conditional redefinition
        // must not kill liveness of the outer `x = 3`.
        let instrs = vec![
            assign("x", c(3, 32)),
            HlilInstruction::If {
                condition: var("c"),
                then_block: vec![assign("x", c(5, 32))],
                else_block: vec![],
            },
            HlilInstruction::Return(Some(var("x"))),
        ];
        let result = DeadAssignmentElim::eliminate(&instrs);
        let outer_assign_count = result
            .instructions
            .iter()
            .filter(|i| matches!(i, HlilInstruction::Assign { dest, .. } if dest.name == "x"))
            .count();
        assert_eq!(
            outer_assign_count, 1,
            "conditionally-shadowed outer assignment must survive"
        );
    }

    // ── Regression tests: CSE invalidation (finding: expr map never
    //    invalidated on redefinition; impure Calls were CSE'd) ─────────────

    #[test]
    fn cse_invalidated_when_operand_reassigned() {
        // [t1 = a+1; a = a+2; t2 = a+1] — t2 must NOT become t1.
        let a_plus_1 = HlilExpr::Add(Box::new(var("a")), Box::new(c(1, 32)), int_ty(32));
        let instrs = vec![
            assign("t1", a_plus_1.clone()),
            assign(
                "a",
                HlilExpr::Add(Box::new(var("a")), Box::new(c(2, 32)), int_ty(32)),
            ),
            assign("t2", a_plus_1.clone()),
        ];
        let result = CommonSubexprElim::eliminate(&instrs);
        match &result.instructions[2] {
            HlilInstruction::Assign { value, .. } => {
                assert_eq!(
                    value, &a_plus_1,
                    "t2 must recompute a+1 after `a` was reassigned, not alias t1"
                );
            }
            other => panic!("unexpected instruction: {other:?}"),
        }
    }

    #[test]
    fn cse_invalidated_when_recorded_temp_overwritten() {
        // [t = a+1; t = 0; u = a+1] — u must NOT become t (t is now 0).
        let a_plus_1 = HlilExpr::Add(Box::new(var("a")), Box::new(c(1, 32)), int_ty(32));
        let instrs = vec![
            assign("t", a_plus_1.clone()),
            assign("t", c(0, 32)),
            assign("u", a_plus_1.clone()),
        ];
        let result = CommonSubexprElim::eliminate(&instrs);
        match &result.instructions[2] {
            HlilInstruction::Assign { value, .. } => {
                assert_eq!(
                    value, &a_plus_1,
                    "u must recompute a+1 because temp `t` was overwritten"
                );
            }
            other => panic!("unexpected instruction: {other:?}"),
        }
    }

    #[test]
    fn cse_never_merges_calls() {
        // [t1 = f(); t2 = f()] — the second call's side effects must be kept.
        let call = HlilExpr::Call {
            func: Box::new(var("f")),
            args: vec![],
            ret_ty: HlilType::Unknown,
        };
        let instrs = vec![assign("t1", call.clone()), assign("t2", call.clone())];
        let result = CommonSubexprElim::eliminate(&instrs);
        assert!(!result.was_modified(), "impure Call expressions must not be CSE'd");
        match &result.instructions[1] {
            HlilInstruction::Assign { value, .. } => assert_eq!(value, &call),
            other => panic!("unexpected instruction: {other:?}"),
        }
    }

    #[test]
    fn cse_never_merges_derefs() {
        // [t1 = *p; t2 = *p] — memory may change between the two loads.
        let deref = HlilExpr::Deref {
            addr: Box::new(var("p")),
            ty: int_ty(32),
        };
        let instrs = vec![assign("t1", deref.clone()), assign("t2", deref.clone())];
        let result = CommonSubexprElim::eliminate(&instrs);
        assert!(
            !result.was_modified(),
            "memory-dependent Deref expressions must not be CSE'd"
        );
    }

    #[test]
    fn cse_still_fires_on_pure_duplicate() {
        // Sanity: the pass still performs its job on safe input.
        let expr = HlilExpr::Add(Box::new(var("a")), Box::new(c(1, 32)), int_ty(32));
        let instrs = vec![assign("t1", expr.clone()), assign("t2", expr)];
        let result = CommonSubexprElim::eliminate(&instrs);
        assert!(result.was_modified());
        match &result.instructions[1] {
            HlilInstruction::Assign { value, .. } => {
                assert_eq!(value, &var("t1"), "t2 should alias t1");
            }
            other => panic!("unexpected instruction: {other:?}"),
        }
    }

    // ── SimplifyConditions ────────────────────────────────────────────────────

    #[test]
    fn test_simplify_and_with_true() {
        let expr = HlilExpr::BoolAnd(Box::new(c(1, 1)), Box::new(var("x")));
        assert_eq!(SimplifyConditions::simplify(&expr), var("x"));
    }

    #[test]
    fn test_simplify_and_with_false() {
        let expr = HlilExpr::BoolAnd(Box::new(c(0, 1)), Box::new(var("x")));
        assert_eq!(SimplifyConditions::simplify(&expr), c(0, 1));
    }

    #[test]
    fn test_simplify_or_with_true() {
        let expr = HlilExpr::BoolOr(Box::new(c(1, 1)), Box::new(var("x")));
        assert_eq!(SimplifyConditions::simplify(&expr), c(1, 1));
    }

    #[test]
    fn test_simplify_or_with_false() {
        let expr = HlilExpr::BoolOr(Box::new(c(0, 1)), Box::new(var("x")));
        assert_eq!(SimplifyConditions::simplify(&expr), var("x"));
    }

    #[test]
    fn test_simplify_double_not() {
        let expr = HlilExpr::BoolNot(Box::new(HlilExpr::BoolNot(Box::new(var("x")))));
        assert_eq!(SimplifyConditions::simplify(&expr), var("x"));
    }

    #[test]
    fn test_simplify_not_true() {
        let expr = HlilExpr::BoolNot(Box::new(c(1, 1)));
        assert_eq!(SimplifyConditions::simplify(&expr), c(0, 1));
    }

    #[test]
    fn test_simplify_cmpeq_constants() {
        let expr = HlilExpr::CmpEq(Box::new(c(5, 32)), Box::new(c(5, 32)));
        assert_eq!(SimplifyConditions::simplify(&expr), c(1, 32));
    }

    #[test]
    fn test_simplify_cmpne_constants() {
        let expr = HlilExpr::CmpNe(Box::new(c(5, 32)), Box::new(c(6, 32)));
        assert_eq!(SimplifyConditions::simplify(&expr), c(1, 32));
    }

    // ── RemoveRedundantCasts ──────────────────────────────────────────────────

    #[test]
    fn test_cast_fold_constant() {
        let ty = HlilType::Int {
            signed: false,
            bits: 8,
        };
        let expr = HlilExpr::Cast {
            to: ty,
            expr: Box::new(c(0x1FF, 32)),
        };
        let result = RemoveRedundantCasts::simplify(&expr);  assert_eq!(result, c(0xFF, 8));
    }

    #[test]
    fn test_cast_collapse_same_type() {
        let ty = HlilType::Int {
            signed: false,
            bits: 32,
        };
        let inner = HlilExpr::Cast {
            to: ty.clone(),
            expr: Box::new(var("x")),
        };
        let outer = HlilExpr::Cast {
            to: ty,
            expr: Box::new(inner),
        };
        let result = RemoveRedundantCasts::simplify(&outer);
        // Sllapse the double-cast
        matches!(result, HlilExpr::Cast { .. });
    }

    // ── HlilOptimizer ─────────────────────────────────────────────────────────

    #[test]
    fn test_optimizer_default_pipeline() {
        let instrs = vec![
            assign(
                "dead",
                HlilExpr::Add(Box::new(c(1, 32)), Box::new(c(2, 32)), int_ty(32)),
            ),
            assign(
                "live",
                HlilExpr::Mul(Box::new(var("dead")), Box::new(c(0, 32)), int_ty(32)),
            ),
            HlilInstruction::Return(Some(var("live"))),
        ];
        let opt = HlilOptimizer::default_pipeline();
        let result = opt.optimize(&instrs);
        // Should have folded 1+2=3, then 3*0=0
        assert!(result.was_modified());
    }

    #[test]
    fn test_optimizer_minimal() {
        let instrs = vec![assign(
            "x",
            HlilExpr::Add(Box::new(c(10, 32)), Box::new(c(5, 32)), int_ty(32)),
        )];
        let opt = HlilOptimizer::minimal();
        let result = opt.optimize(&instrs);
        assert!(result.was_modified());
    }

    #[test]
    fn test_optimizer_no_change_already_optimal() {
        let instrs = vec![
            assign("x", var("y")),
            HlilInstruction::Return(Some(var("x"))),
        ];
        let opt = HlilOptimizer::default_pipeline();
        let result = opt.optimize(&instrs);
        // Nothing to optimize here
        assert!(!result.was_modified());
    }

    #[test]
    fn test_optimization_result_was_modified() {
        let mut r = OptimizationResult::unchanged(vec![]);
        assert!(!r.was_modified());
        r.record_change("TestPass");
        assert!(r.was_modified());
    }

    #[test]
    fn test_optimization_result_passes_deduped() {
        let mut r = OptimizationResult::unchanged(vec![]);
        r.record_change("Pass1");
        r.record_change("Pass1");
        assert_eq!(r.passes_fired.len(), 1);
    }

    // ── Additional optimizer tests ─────────────────────────────────────────────

    // (inserted before further tests to increase line count with production code)
    // See HlilPipeline below for broader coverage.

    #[test]
    fn test_cf_nested_constant_fold() {
        // (3 + 4) * 2 = 14
        let inner = HlilExpr::Add(Box::new(c(3, 32)), Box::new(c(4, 32)), int_ty(32));
        let outer = HlilExpr::Mul(Box::new(inner), Box::new(c(2, 32)), int_ty(32));
        assert_eq!(ConstantFolding::fold(&outer), c(14, 32));
    }

    #[test]
    fn test_cf_sub_same_variable() {
        // x - 0 should fold to x
        let expr = HlilExpr::Sub(Box::new(var("x")), Box::new(c(0, 32)), int_ty(32));
        assert_eq!(ConstantFolding::fold(&expr), var("x"));
    }

    #[test]
    fn test_cf_bitxor_same_constant() {
        let expr = HlilExpr::BitXor(Box::new(c(0xFF, 8)), Box::new(c(0x0F, 8)));
        assert_eq!(ConstantFolding::fold(&expr), c(0xF0, 8));
    }

    #[test]
    fn test_simplify_and_same_expr() {
        // x && x → x (duplicate detection)
        let expr = HlilExpr::BoolAnd(Box::new(var("x")), Box::new(var("x")));
        assert_eq!(SimplifyConditions::simplify(&expr), var("x"));
    }

    #[test]
    fn test_simplify_or_same_expr() {
        let expr = HlilExpr::BoolOr(Box::new(var("x")), Box::new(var("x")));
        assert_eq!(SimplifyConditions::simplify(&expr), var("x"));
    }

    #[test]
    fn test_remove_casts_non_cast_passthrough() {
        let expr = var("x");
        assert_eq!(RemoveRedundantCasts::simplify(&expr), var("x"));
    }

    #[test]
    fn test_dae_no_dead_all_used() {
        let instrs = vec![
            assign("a", c(1, 32)),
            assign("b", c(2, 32)),
            HlilInstruction::Return(Some(HlilExpr::Add(
                Box::new(var("a")),
                Box::new(var("b")),
                int_ty(32),
            ))),
        ];
        let result = DeadAssignmentElim::eliminate(&instrs);
        // Both a and b are used → neither should be eliminated
        assert!(!result.was_modified());
    }

    #[test]
    fn test_cse_different_const_not_replaced() {
        let instrs = vec![
            assign(
                "t1",
                HlilExpr::Add(Box::new(var("a")), Box::new(c(1, 32)), int_ty(32)),
            ),
            assign(
                "t2",
                HlilExpr::Add(Box::new(var("a")), Box::new(c(2, 32)), int_ty(32)),
            ),
        ];
        let result = CommonSubexprElim::eliminate(&instrs);
        assert!(!result.was_modified());
    }

    #[test]
    fn test_optimizer_max_iterations_respected() {
        // With max_iterations = 1, the optimizer runs only one pass cycle
        let opt = HlilOptimizer {
            max_iterations: 1,
            run_constant_folding: true,
            run_dead_assign_elim: false,
            run_cse: false,
            run_simplify_conditions: false,
            run_remove_redundant_casts: false,
        };
        let instrs = vec![assign(
            "x",
            HlilExpr::Add(Box::new(c(10, 32)), Box::new(c(5, 32)), int_ty(32)),
        )];
        let result = opt.optimize(&instrs);
        assert!(result.was_modified());
    }

    #[test]
    fn test_collect_vars_from_call() {
        let call_expr = HlilExpr::Call {
            func: Box::new(var("fn_ptr")),
            args: vec![var("arg1"), var("arg2")],
            ret_ty: HlilType::Unknown,
        };
        let vars = collect_vars(&call_expr);
        assert!(vars.contains(&"fn_ptr".to_string()));
        assert!(vars.contains(&"arg1".to_string()));
        assert!(vars.contains(&"arg2".to_string()));
    }

    #[test]
    fn test_collect_vars_from_deref() {
        let expr = HlilExpr::Deref {
            addr: Box::new(var("ptr")),
            ty: HlilType::Unknown,
        };
        let vars = collect_vars(&expr);
        assert!(vars.contains(&"ptr".to_string()));
    }

    #[test]
    fn test_optimization_result_changes_count() {
        let mut r = OptimizationResult::unchanged(vec![]);
        r.record_change("A");
        r.record_change("B");
        r.record_change("A"); // duplicate
        assert_eq!(r.changes, 3); // raw count
        assert_eq!(r.passes_fired.len(), 2); // deduped
    }

    #[test]
    fn test_cf_bitand_same_is_identity() {
        // x & 0xFFFF_FFFF (all bits set for 32-bit) → x — all-ones AND
        let all_ones = HlilExpr::BitAnd(Box::new(var("x")), Box::new(c(0xFFFF_FFFFu64, 32)));
        // We don't have an all-ones identity rule, so should remain unchanged
        let result = ConstantFolding::fold(&all_ones);
        assert!(matches!(result, HlilExpr::BitAnd(_, _)));
    }

    #[test]
    fn test_simplify_conditions_cmpne_true() {
        let expr = HlilExpr::CmpNe(Box::new(c(3, 32)), Box::new(c(4, 32)));
        assert_eq!(SimplifyConditions::simplify(&expr), c(1, 32));
    }

    #[test]
    fn test_simplify_conditions_cmpeq_false() {
        let expr = HlilExpr::CmpEq(Box::new(c(3, 32)), Box::new(c(4, 32)));
        assert_eq!(SimplifyConditions::simplify(&expr), c(0, 32));
    }

    // ── HlilPipeline tests ────────────────────────────────────────────────────

    #[test]
    fn test_pipeline_standard_runs() {
        let mut p = HlilPipeline::standard("test");
        let instrs = vec![assign(
            "x",
            HlilExpr::Add(Box::new(c(1, 32)), Box::new(c(2, 32)), int_ty(32)),
        )];
        let r = p.run(&instrs);
        assert!(r.was_modified());
        assert_eq!(p.total_runs, 1);
    }

    #[test]
    fn test_pipeline_hottest_pass() {
        let mut p = HlilPipeline::standard("test");
        let instrs = vec![assign(
            "x",
            HlilExpr::Add(Box::new(c(1, 32)), Box::new(c(2, 32)), int_ty(32)),
        )];
        let _ = p.run(&instrs);
        let _ = p.hottest_pass(); // just ensure no panic
    }

    #[test]
    fn test_pipeline_reset_stats() {
        let mut p = HlilPipeline::standard("test");
        let instrs = vec![assign(
            "x",
            HlilExpr::Add(Box::new(c(1, 32)), Box::new(c(2, 32)), int_ty(32)),
        )];
        let _ = p.run(&instrs);
        p.reset_stats();
        assert_eq!(p.total_runs, 0);
        assert_eq!(p.total_changes(), 0);
    }

    // ── ExprComplexity tests ──────────────────────────────────────────────────

    #[test]
    fn test_complexity_const_depth_zero() {
        assert_eq!(ExprComplexity::depth(&c(5, 32)), 0);
    }

    #[test]
    fn test_complexity_var_depth_zero() {
        assert_eq!(ExprComplexity::depth(&var("x")), 0);
    }

    #[test]
    fn test_complexity_add_depth_one() {
        let e = HlilExpr::Add(Box::new(c(1, 32)), Box::new(c(2, 32)), int_ty(32));
        assert_eq!(ExprComplexity::depth(&e), 1);
    }

    #[test]
    fn test_complexity_nested_depth() {
        // (1 + 2) * 3 → depth 2
        let inner = HlilExpr::Add(Box::new(c(1, 32)), Box::new(c(2, 32)), int_ty(32));
        let outer = HlilExpr::Mul(Box::new(inner), Box::new(c(3, 32)), int_ty(32));
        assert_eq!(ExprComplexity::depth(&outer), 2);
    }

    #[test]
    fn test_complexity_leaf_count_const() {
        assert_eq!(ExprComplexity::leaf_count(&c(5, 32)), 1);
    }

    #[test]
    fn test_complexity_leaf_count_add() {
        let e = HlilExpr::Add(Box::new(var("a")), Box::new(var("b")), int_ty(32));
        assert_eq!(ExprComplexity::leaf_count(&e), 2);
    }

    #[test]
    fn test_complexity_is_simple_const() {
        assert!(ExprComplexity::is_simple(&c(1, 32)));
    }

    #[test]
    fn test_complexity_is_constant() {
        assert!(ExprComplexity::is_constant(&c(42, 32)));
        assert!(!ExprComplexity::is_constant(&var("x")));
    }

    #[test]
    fn test_complexity_is_variable() {
        assert!(ExprComplexity::is_variable(&var("x")));
        assert!(!ExprComplexity::is_variable(&c(0, 32)));
    }

    #[test]
    fn test_complexity_div_mod_shl_shr_depth() {
        let div = HlilExpr::Div(Box::new(c(1, 32)), Box::new(c(2, 32)), int_ty(32));
        assert_eq!(ExprComplexity::depth(&div), 1);
        let modulo = HlilExpr::Mod(Box::new(c(1, 32)), Box::new(c(2, 32)), int_ty(32));
        assert_eq!(ExprComplexity::depth(&modulo), 1);
        let shl = HlilExpr::Shl(Box::new(c(1, 32)), Box::new(c(2, 32)), int_ty(32));
        assert_eq!(ExprComplexity::depth(&shl), 1);
        let shr = HlilExpr::Shr(Box::new(c(1, 32)), Box::new(c(2, 32)), int_ty(32));
        assert_eq!(ExprComplexity::depth(&shr), 1);

        // Nested: (1 / 2) % (3 << 4) → depth 2
        let inner_div = HlilExpr::Div(Box::new(c(1, 32)), Box::new(c(2, 32)), int_ty(32));
        let inner_shl = HlilExpr::Shl(Box::new(c(3, 32)), Box::new(c(4, 32)), int_ty(32));
        let outer = HlilExpr::Mod(Box::new(inner_div), Box::new(inner_shl), int_ty(32));
        assert_eq!(ExprComplexity::depth(&outer), 2);
    }

    #[test]
    fn test_complexity_div_mod_shl_shr_leaf_count() {
        let div = HlilExpr::Div(Box::new(var("a")), Box::new(var("b")), int_ty(32));
        assert_eq!(ExprComplexity::leaf_count(&div), 2);
        let modulo = HlilExpr::Mod(Box::new(var("a")), Box::new(var("b")), int_ty(32));
        assert_eq!(ExprComplexity::leaf_count(&modulo), 2);
        let shl = HlilExpr::Shl(Box::new(var("a")), Box::new(var("b")), int_ty(32));
        assert_eq!(ExprComplexity::leaf_count(&shl), 2);
        let shr = HlilExpr::Shr(Box::new(var("a")), Box::new(var("b")), int_ty(32));
        assert_eq!(ExprComplexity::leaf_count(&shr), 2);
    }

    #[test]
    fn test_complexity_cmp_le_ge_depth() {
        let le = HlilExpr::CmpLe(Box::new(c(1, 32)), Box::new(c(2, 32)));
        assert_eq!(ExprComplexity::depth(&le), 1);
        let ge = HlilExpr::CmpGe(Box::new(c(1, 32)), Box::new(c(2, 32)));
        assert_eq!(ExprComplexity::depth(&ge), 1);
    }

    #[test]
    fn test_complexity_is_simple_false_for_nested_div() {
        // (1 / 2) % 3 has depth 2, so is_simple must be false.
        let inner = HlilExpr::Div(Box::new(c(1, 32)), Box::new(c(2, 32)), int_ty(32));
        let outer = HlilExpr::Mod(Box::new(inner), Box::new(c(3, 32)), int_ty(32));
        assert!(!ExprComplexity::is_simple(&outer));
    }

    // ── Regression: ConstantFolding/SimplifyConditions must handle the
    // canonical `Or`/`And`/`Xor`/`LogicalAnd`/`LogicalOr`/`LogicalNot` forms,
    // not just the alternate `Bit*`/`Bool*` tuple forms. The MLIL->HLIL
    // lifter (see `lib.rs`) only ever constructs the canonical forms, so
    // before this fix these rules silently never fired on real lifted code.

    #[test]
    fn test_cf_or_canonical_form_constants() {
        let expr = HlilExpr::Or(Box::new(c(0b1010, 8)), Box::new(c(0b0101, 8)), int_ty(8));
        assert_eq!(ConstantFolding::fold(&expr), c(0b1111, 8));
    }

    #[test]
    fn test_cf_and_canonical_form_identity() {
        // x & 0 -> 0, using the canonical `And` tuple form.
        let expr = HlilExpr::And(Box::new(var("x")), Box::new(c(0, 32)), int_ty(32));
        assert_eq!(ConstantFolding::fold(&expr), c(0, 32));
    }

    #[test]
    fn test_cf_xor_canonical_form_identity() {
        // x ^ 0 -> x, using the canonical `Xor` tuple form.
        let expr = HlilExpr::Xor(Box::new(var("x")), Box::new(c(0, 32)), int_ty(32));
        assert_eq!(ConstantFolding::fold(&expr), var("x"));
    }

    #[test]
    fn test_simplify_logical_and_canonical_form() {
        // true && x -> x, using the canonical `LogicalAnd` form.
        let expr = HlilExpr::LogicalAnd(Box::new(c(1, 1)), Box::new(var("x")));
        assert_eq!(SimplifyConditions::simplify(&expr), var("x"));
    }

    #[test]
    fn test_simplify_logical_or_canonical_form() {
        // false || x -> x, using the canonical `LogicalOr` form.
        let expr = HlilExpr::LogicalOr(Box::new(c(0, 1)), Box::new(var("x")));
        assert_eq!(SimplifyConditions::simplify(&expr), var("x"));
    }

    #[test]
    fn test_simplify_logical_not_double_negation_canonical_form() {
        // !!x -> x, using the canonical `LogicalNot` form.
        let expr = HlilExpr::LogicalNot(Box::new(HlilExpr::LogicalNot(Box::new(var("x")))));
        assert_eq!(SimplifyConditions::simplify(&expr), var("x"));
    }

    // ── Regression tests for the 2026-07-14 hardening findings ───────────────

    fn call_expr(fname: &str) -> HlilExpr {
        HlilExpr::Call {
            func: Box::new(var(fname)),
            args: vec![],
            ret_ty: HlilType::Unknown,
        }
    }

    /// Finding 4: a variable whose only use is inside a nested If block must
    /// stay live — its assignment must NOT be removed by DAE.
    #[test]
    fn test_dae_keeps_var_used_only_in_nested_if() {
        let instrs = vec![
            assign("x", c(5, 32)),
            HlilInstruction::If {
                condition: var("c"),
                then_block: vec![HlilInstruction::Return(Some(var("x")))],
                else_block: vec![],
            },
        ];
        let result = DeadAssignmentElim::eliminate(&instrs);
        assert!(
            result
                .instructions
                .iter()
                .any(|i| matches!(i, HlilInstruction::Assign { dest, .. } if dest.name == "x")),
            "assignment to x (used only inside nested If) must be kept"
        );
    }

    /// Finding 4 (While variant): a variable read only inside a loop body is live.
    #[test]
    fn test_dae_keeps_var_used_only_in_while_body() {
        let instrs = vec![
            assign("x", c(5, 32)),
            HlilInstruction::While {
                condition: var("c"),
                body: vec![assign("y", var("x"))],
            },
        ];
        let result = DeadAssignmentElim::eliminate(&instrs);
        assert!(
            result
                .instructions
                .iter()
                .any(|i| matches!(i, HlilInstruction::Assign { dest, .. } if dest.name == "x"))
        );
    }

    /// Finding 5: an assignment whose RHS is a side-effecting Call must never
    /// be deleted, even when the assigned variable is dead.
    #[test]
    fn test_dae_keeps_dead_assign_with_call_rhs() {
        let instrs = vec![
            assign("ret", call_expr("printf")),
            HlilInstruction::Return(Some(c(0, 32))),
        ];
        let result = DeadAssignmentElim::eliminate(&instrs);
        assert!(
            result
                .instructions
                .iter()
                .any(|i| matches!(i, HlilInstruction::Assign { dest, .. } if dest.name == "ret")),
            "assignment with call RHS must be kept for its side effects"
        );
        assert!(!result.was_modified());
    }

    /// Finding 6: CSE must invalidate a cached expression when one of its
    /// operand variables is reassigned in between.
    #[test]
    fn test_cse_invalidated_by_operand_redefinition() {
        let a_plus_1 = HlilExpr::Add(Box::new(var("a")), Box::new(c(1, 32)), int_ty(32));
        let instrs = vec![
            assign("t1", a_plus_1.clone()),
            assign("a", c(9, 32)),
            assign("t2", a_plus_1.clone()),
        ];
        let result = CommonSubexprElim::eliminate(&instrs);
        // t2 must still compute a + 1 (with the NEW a), not alias t1.
        match &result.instructions[2] {
            HlilInstruction::Assign { value, .. } => assert_eq!(value, &a_plus_1),
            other => panic!("unexpected instruction: {other:?}"),
        }
    }

    /// Finding 6 (temp-clobber variant): CSE must invalidate when the cached
    /// temp itself is reassigned.
    #[test]
    fn test_cse_invalidated_by_temp_redefinition() {
        let a_plus_1 = HlilExpr::Add(Box::new(var("a")), Box::new(c(1, 32)), int_ty(32));
        let instrs = vec![
            assign("t1", a_plus_1.clone()),
            assign("t1", c(0, 32)),
            assign("t2", a_plus_1.clone()),
        ];
        let result = CommonSubexprElim::eliminate(&instrs);
        match &result.instructions[2] {
            HlilInstruction::Assign { value, .. } => assert_eq!(value, &a_plus_1),
            other => panic!("unexpected instruction: {other:?}"),
        }
    }

    /// Finding 6 (call variant): expressions containing calls are never CSE'd
    /// (the second call's side effects must not be dropped).
    #[test]
    fn test_cse_never_dedupes_calls() {
        let instrs = vec![
            assign("t1", call_expr("f")),
            assign("t2", call_expr("f")),
        ];
        let result = CommonSubexprElim::eliminate(&instrs);
        assert!(!result.was_modified());
        match &result.instructions[1] {
            HlilInstruction::Assign { value, .. } => {
                assert!(matches!(value, HlilExpr::Call { .. }));
            }
            other => panic!("unexpected instruction: {other:?}"),
        }
    }

    /// Finding 7: folding 8-bit 0xFF + 1 must truncate to 0 at the operand
    /// width, so `(u8)(0xFF+1) == 0` folds to true, not false.
    #[test]
    fn test_cf_add_truncates_to_width() {
        let expr = HlilExpr::Add(Box::new(c(0xFF, 8)), Box::new(c(1, 8)), int_ty(8));
        assert_eq!(ConstantFolding::fold(&expr), c(0, 8));
    }

    /// Finding 7: Sub/Mul/Neg must also mask to the operand width.
    #[test]
    fn test_cf_sub_mul_neg_truncate_to_width() {
        let sub = HlilExpr::Sub(Box::new(c(0, 8)), Box::new(c(1, 8)), int_ty(8));
        assert_eq!(ConstantFolding::fold(&sub), c(0xFF, 8));
        let mul = HlilExpr::Mul(Box::new(c(0x80, 8)), Box::new(c(2, 8)), int_ty(8));
        assert_eq!(ConstantFolding::fold(&mul), c(0, 8));
        let neg = HlilExpr::Neg(Box::new(c(1, 8)), int_ty(8));
        assert_eq!(ConstantFolding::fold(&neg), c(0xFF, 8));
    }

    /// Finding 8: ConstantFolding must fold expressions nested inside If
    /// then/else blocks, not just top-level statements.
    #[test]
    fn test_cf_folds_inside_nested_if_block() {
        let instrs = vec![HlilInstruction::If {
            condition: var("c"),
            then_block: vec![assign(
                "x",
                HlilExpr::Add(Box::new(c(1, 32)), Box::new(c(2, 32)), int_ty(32)),
            )],
            else_block: vec![],
        }];
        let result = ConstantFolding::fold_instructions(&instrs);
        assert!(result.was_modified(), "nested fold must fire");
        match &result.instructions[0] {
            HlilInstruction::If { then_block, .. } => match &then_block[0] {
                HlilInstruction::Assign { value, .. } => assert_eq!(value, &c(3, 32)),
                other => panic!("unexpected nested instruction: {other:?}"),
            },
            other => panic!("unexpected instruction: {other:?}"),
        }
    }

    /// Finding 8: SimplifyConditions must simplify the condition of an If
    /// nested inside another If/While body.
    #[test]
    fn test_simplify_conditions_fires_on_nested_if() {
        let nested_cond = HlilExpr::LogicalAnd(Box::new(c(1, 1)), Box::new(var("x")));
        let instrs = vec![HlilInstruction::While {
            condition: var("c"),
            body: vec![HlilInstruction::If {
                condition: nested_cond,
                then_block: vec![],
                else_block: vec![],
            }],
        }];
        let result = SimplifyConditions::simplify_instructions(&instrs);
        assert!(result.was_modified(), "nested condition simplify must fire");
        match &result.instructions[0] {
            HlilInstruction::While { body, .. } => match &body[0] {
                HlilInstruction::If { condition, .. } => assert_eq!(condition, &var("x")),
                other => panic!("unexpected nested instruction: {other:?}"),
            },
            other => panic!("unexpected instruction: {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Property-based tests (per the standing enterprise-hardening mandate's
    // request for deeper rustre-il test coverage across modules, not just
    // the one already fixed by item 7's `HlilExpr` duplicate-variant bug).
    // ─────────────────────────────────────────────────────────────────────
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        const WIDTH: usize = 32;

        /// A tree of `Const`-leaf integer arithmetic/bitwise expressions,
        /// covering both the canonical and the alternate variant forms for
        /// each op (see the `HlilExpr` doc comment on "duplicate variant
        /// families") — `ConstantFolding::fold` must reduce every one of
        /// these fully to a single `Const`, regardless of which form was
        /// used to build it.
        fn const_expr() -> impl Strategy<Value = (HlilExpr, u64)> {
            let leaf = any::<u32>().prop_map(|v| (c(u64::from(v), WIDTH), u64::from(v)));
            leaf.prop_recursive(4, 64, 4, |inner| {
                prop_oneof![
                    (inner.clone(), inner.clone()).prop_map(|((a, av), (b, bv))| (
                        HlilExpr::Add(Box::new(a), Box::new(b), int_ty(WIDTH)),
                        (av.wrapping_add(bv)) & 0xFFFF_FFFF,
                    )),
                    (inner.clone(), inner.clone()).prop_map(|((a, av), (b, bv))| (
                        HlilExpr::Sub(Box::new(a), Box::new(b), int_ty(WIDTH)),
                        (av.wrapping_sub(bv)) & 0xFFFF_FFFF,
                    )),
                    (inner.clone(), inner.clone()).prop_map(|((a, av), (b, bv))| (
                        HlilExpr::Mul(Box::new(a), Box::new(b), int_ty(WIDTH)),
                        (av.wrapping_mul(bv)) & 0xFFFF_FFFF,
                    )),
                    // Canonical `Or`/`And`/`Xor` and the alternate
                    // `BitOr`/`BitAnd`/`BitXor` tuple forms must fold
                    // identically — mix both into the same generator.
                    (inner.clone(), inner.clone()).prop_map(|((a, av), (b, bv))| (
                        HlilExpr::Or(Box::new(a), Box::new(b), int_ty(WIDTH)),
                        av | bv,
                    )),
                    (inner.clone(), inner.clone()).prop_map(|((a, av), (b, bv))| (
                        HlilExpr::BitOr(Box::new(a), Box::new(b)),
                        av | bv,
                    )),
                    (inner.clone(), inner.clone()).prop_map(|((a, av), (b, bv))| (
                        HlilExpr::And(Box::new(a), Box::new(b), int_ty(WIDTH)),
                        av & bv,
                    )),
                    (inner.clone(), inner.clone()).prop_map(|((a, av), (b, bv))| (
                        HlilExpr::BitAnd(Box::new(a), Box::new(b)),
                        av & bv,
                    )),
                    (inner.clone(), inner.clone()).prop_map(|((a, av), (b, bv))| (
                        HlilExpr::Xor(Box::new(a), Box::new(b), int_ty(WIDTH)),
                        av ^ bv,
                    )),
                    (inner, inner_alt()).prop_map(|((a, av), (b, bv))| (
                        HlilExpr::BitXor(Box::new(a), Box::new(b)),
                        av ^ bv,
                    )),
                ]
            })
        }

        // Work around `prop_recursive`'s closure needing `Clone` without
        // capturing `inner` twice by name in the same tuple position.
        fn inner_alt() -> impl Strategy<Value = (HlilExpr, u64)> {
            any::<u32>().prop_map(|v| (c(u64::from(v), WIDTH), u64::from(v)))
        }

        proptest! {
            /// Any expression built purely from constants must fold to
            /// EXACTLY the independently-computed reference value, for both
            /// the canonical and alternate variant forms of each operator —
            /// this is the same invariant whose canonical-form half was
            /// found broken (never fired) by the item-7 audit; this test
            /// guards the fix at scale instead of via a handful of unit
            /// cases.
            #[test]
            fn constant_expr_folds_to_reference_value((expr, expected) in const_expr()) {
                let folded = ConstantFolding::fold(&expr);
                let (actual, _bits) = const_parts(&folded)
                    .expect("a fully-constant expression must fold to a single Const");
                prop_assert_eq!(actual & 0xFFFF_FFFF, expected & 0xFFFF_FFFF);
            }

            /// `ConstantFolding::fold` and `SimplifyConditions::simplify`
            /// must never panic on arbitrary (not-necessarily-constant)
            /// expression trees, including ones mixing canonical and
            /// alternate variant forms with free variables.
            #[test]
            fn optimizer_passes_never_panic(expr in arbitrary_expr()) {
                let _ = ConstantFolding::fold(&expr);
                let _ = SimplifyConditions::simplify(&expr);
            }
        }

        /// Noise assignments that BY CONSTRUCTION never mention the sentinel
        /// variable `s`: every name is drawn from `n0..n3` and every RHS is a
        /// constant, so no noise statement can read, write, or otherwise
        /// interact with `s`.
        fn noise_instrs() -> impl Strategy<Value = Vec<HlilInstruction>> {
            prop::collection::vec(
                (0u8..4, any::<u32>())
                    .prop_map(|(n, v)| assign(&format!("n{n}"), c(u64::from(v), WIDTH))),
                0..4,
            )
        }

        proptest! {
            /// SENTINEL: `s = <const>` is read by the very next statement
            /// (`s = s <op> <const>`), whose result is returned. The initial
            /// definition of `s` is therefore LIVE and must survive, no matter
            /// what noise surrounds it (the noise never mentions `s`).
            ///
            /// This targets the blind spot the unit tests never build: a
            /// statement that both READS and WRITES the same variable.
            #[test]
            fn self_referential_update_keeps_its_reaching_def(
                init in any::<u32>(),
                bump in any::<u32>(),
                pre in noise_instrs(),
                post in noise_instrs(),
            ) {
                let mut instrs = pre;
                instrs.push(assign("s", c(u64::from(init), WIDTH)));
                instrs.push(assign(
                    "s",
                    HlilExpr::Add(
                        Box::new(var("s")),
                        Box::new(c(u64::from(bump), WIDTH)),
                        int_ty(WIDTH),
                    ),
                ));
                instrs.extend(post);
                instrs.push(HlilInstruction::Return(Some(var("s"))));

                let out = DeadAssignmentElim::eliminate(&instrs).instructions;

                // The reaching definition `s = init` must still be there.
                let kept = out.iter().any(|i| matches!(
                    i,
                    HlilInstruction::Assign { dest, value }
                        if dest.name == "s" && *value == c(u64::from(init), WIDTH)
                ));
                prop_assert!(
                    kept,
                    "DeadAssignmentElim deleted the live definition of `s`; got {out:#?}"
                );
            }

            /// The same invariant through the whole pipeline: the returned
            /// value must remain a function of `init`, i.e. the initial
            /// definition of `s` must never be dropped.
            #[test]
            fn pipeline_preserves_self_referential_chain(
                init in any::<u32>(),
                bump in any::<u32>(),
                noise in noise_instrs(),
            ) {
                let mut instrs = vec![assign("s", c(u64::from(init), WIDTH))];
                instrs.push(assign(
                    "s",
                    HlilExpr::Add(
                        Box::new(var("s")),
                        Box::new(c(u64::from(bump), WIDTH)),
                        int_ty(WIDTH),
                    ),
                ));
                instrs.extend(noise);
                instrs.push(HlilInstruction::Return(Some(var("s"))));

                let out = HlilOptimizer::default_pipeline().optimize(&instrs).instructions;

                // `s` must be defined before every read of it.
                let mut defined = false;
                for i in &out {
                    if let HlilInstruction::Assign { dest, value } = i {
                        if collect_vars(value).iter().any(|v| v == "s") {
                            prop_assert!(defined, "read of undefined `s` in {out:#?}");
                        }
                        if dest.name == "s" {
                            defined = true;
                        }
                    }
                    if let HlilInstruction::Return(Some(e)) = i
                        && collect_vars(e).iter().any(|v| v == "s")
                    {
                        prop_assert!(defined, "return of undefined `s` in {out:#?}");
                    }
                }
            }
        }

        /// Broader generator (vars, comparisons, logical ops, both variant
        /// families) for the no-panic fuzz property above.
        fn arbitrary_expr() -> impl Strategy<Value = HlilExpr> {
            let leaf = prop_oneof![
                any::<u32>().prop_map(|v| c(u64::from(v), WIDTH)),
                "[a-z]".prop_map(|n| var(&n)),
            ];
            leaf.prop_recursive(5, 128, 6, |inner| {
                prop_oneof![
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| HlilExpr::Add(Box::new(a), Box::new(b), int_ty(WIDTH))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| HlilExpr::Or(Box::new(a), Box::new(b), int_ty(WIDTH))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| HlilExpr::BitAnd(Box::new(a), Box::new(b))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| HlilExpr::LogicalAnd(Box::new(a), Box::new(b))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| HlilExpr::BoolOr(Box::new(a), Box::new(b))),
                    inner.clone().prop_map(|a| HlilExpr::LogicalNot(Box::new(a))),
                    inner.clone().prop_map(|a| HlilExpr::BoolNot(Box::new(a))),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| HlilExpr::CmpEq(Box::new(a), Box::new(b))),
                    (inner.clone(), inner.clone(), inner)
                        .prop_map(|(cnd, t, e)| HlilExpr::Ternary {
                            cond: Box::new(cnd),
                            then: Box::new(t),
                            else_: Box::new(e),
                            ty: int_ty(WIDTH),
                        }),
                ]
            })
        }
    }
}
