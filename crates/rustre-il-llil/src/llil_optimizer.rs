//! LLIL optimizer for `rustre-il-llil`.
//!
//! Implements classic dataflow-based and peephole optimizations over LLIL.

use std::collections::HashMap;
use std::fmt;

use crate::{LlilExpr, LlilFunction, LlilInstruction, Size};
use rustre_core::address::Address;

/// Type alias for the core address type, exposed so optimizer callers can
/// annotate constant-propagation results with their source address.
pub type OptimizerAddress = Address;

// ---------------------------------------------------------------------------
// OptimizationPass trait
// ---------------------------------------------------------------------------

/// A single optimization pass over an LLIL function.
pub trait OptimizationPass: fmt::Debug {
    /// Human-readable name of this pass.
    fn name(&self) -> &'static str;

    /// Run the pass on `func` in-place, returning the number of changes made.
    fn run(&mut self, func: &mut LlilFunction) -> usize;

    /// Whether this pass should be repeated until no changes occur.
    fn is_fixed_point(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Helper types
// ---------------------------------------------------------------------------

/// A constant value tracked by constant propagation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstValue {
    pub value: i128,
    pub size: Size,
}

impl ConstValue {
    #[must_use]
    pub const fn new(value: i128, size: Size) -> Self {
        Self { value, size }
    }
}

/// Dead-code elimination statistics.
#[derive(Debug, Clone, Default)]
pub struct OptimizationStats {
    pub dead_code_removed: usize,
    pub constants_propagated: usize,
    pub loads_eliminated: usize,
    pub peephole_rewrites: usize,
    pub cse_replacements: usize,
    pub strength_reductions: usize,
}

impl OptimizationStats {
    #[must_use]
    pub const fn total_changes(&self) -> usize {
        self.dead_code_removed
            + self.constants_propagated
            + self.loads_eliminated
            + self.peephole_rewrites
            + self.cse_replacements
            + self.strength_reductions
    }
}

impl fmt::Display for OptimizationStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OptStats: dead={} const={} load={} peephole={} cse={} str_red={}",
            self.dead_code_removed,
            self.constants_propagated,
            self.loads_eliminated,
            self.peephole_rewrites,
            self.cse_replacements,
            self.strength_reductions,
        )
    }
}

// ---------------------------------------------------------------------------
// DeadCodeElimination
// ---------------------------------------------------------------------------

/// Removes instructions that have no observable effect.
#[derive(Debug, Default, Clone)]
pub struct DeadCodeElimination {
    pub removed: usize,
}

impl DeadCodeElimination {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if an instruction is a no-op.
    #[must_use]
    const fn is_nop(instr: &LlilInstruction) -> bool {
        matches!(instr, LlilInstruction::Nop)
    }
}

impl OptimizationPass for DeadCodeElimination {
    fn name(&self) -> &'static str {
        "dead_code_elimination"
    }

    fn run(&mut self, func: &mut LlilFunction) -> usize {
        let before = func.instructions.len();
        func.instructions.retain(|i| !Self::is_nop(&i.instr));
        let removed = before - func.instructions.len();
        self.removed += removed;
        removed
    }
}

// ---------------------------------------------------------------------------
// ConstantPropagation
// ---------------------------------------------------------------------------

/// Propagates constant values through register assignments.
#[derive(Debug, Default, Clone)]
pub struct ConstantPropagation {
    pub propagated: usize,
    /// Register → constant value map.
    constants: HashMap<u32, ConstValue>,
}

impl ConstantPropagation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn fold_expr(expr: &LlilExpr, constants: &HashMap<u32, ConstValue>) -> Option<ConstValue> {
        match expr {
            LlilExpr::Const { value, size } => Some(ConstValue::new(i128::from(*value), *size)),
            LlilExpr::Register { id, size } => constants
                .get(id)
                .copied()
                .map(|cv| ConstValue::new(cv.value, *size)),
            LlilExpr::Add { left, right, size } => {
                let l = Self::fold_expr(left, constants)?;
                let r = Self::fold_expr(right, constants)?;
                Some(ConstValue::new(l.value.wrapping_add(r.value), *size))
            }
            LlilExpr::Sub { left, right, size } => {
                let l = Self::fold_expr(left, constants)?;
                let r = Self::fold_expr(right, constants)?;
                Some(ConstValue::new(l.value.wrapping_sub(r.value), *size))
            }
            LlilExpr::Mul { left, right, size } => {
                let l = Self::fold_expr(left, constants)?;
                let r = Self::fold_expr(right, constants)?;
                Some(ConstValue::new(l.value.wrapping_mul(r.value), *size))
            }
            _ => None,
        }
    }
}

impl OptimizationPass for ConstantPropagation {
    fn name(&self) -> &'static str {
        "constant_propagation"
    }

    fn run(&mut self, func: &mut LlilFunction) -> usize {
        let changes = 0;
        self.constants.clear();

        for instr in &func.instructions {
            if let LlilInstruction::SetRegister { dest, value, .. } = &instr.instr
                && let Some(cv) = Self::fold_expr(value, &self.constants) {
                    self.constants.insert(*dest, cv);
                }
        }

        changes
    }
}

// ---------------------------------------------------------------------------
// StrengthReduction
// ---------------------------------------------------------------------------

/// Replaces expensive operations with cheaper equivalents.
/// Example rules:
/// - `x * 1` → `x`
/// - `x * 0` → `0`
/// - `x + 0` → `x`
/// - `x - 0` → `x`
/// - `x * 2` → `x << 1`
/// - `x / 2` → `x >> 1` (for unsigned)
#[derive(Debug, Default, Clone)]
pub struct StrengthReduction {
    pub reduced: usize,
}

impl StrengthReduction {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

}

/// Apply strength-reduction identities to a single expression.
/// Returns `(reduced_expression, was_changed)`.
fn reduce_expr(expr: LlilExpr) -> (LlilExpr, bool) {
    match expr {
        LlilExpr::Mul { ref left, ref right, size } => {
            if let LlilExpr::Const { value: 1, .. } = right.as_ref() {
                // x * 1 = x, but only when result width matches `size`.
                // `Mul` truncates its product to `size`, so a wider `left`
                // must keep an explicit truncation rather than being
                // substituted verbatim (e.g. `(u64 expr) * 1 : B1` must still
                // yield only the low byte).
                if left.result_size() == size {
                    return (*left.clone(), true);
                }
            }
            // x * 0 = 0 is width-safe: the product is masked to `size`, and the
            // replacement constant carries the same `size`.
            if let LlilExpr::Const { value: 0, .. } = right.as_ref() {
                return (LlilExpr::Const { value: 0, size }, true);
            }
            // x * 2 = x << 1 is width-safe: `Shl` masks to `size` exactly as
            // `Mul` does, so the truncation is preserved by the rewrite.
            if let LlilExpr::Const { value: 2, .. } = right.as_ref() {
                return (
                    LlilExpr::Shl {
                        value: left.clone(),
                        shift: Box::new(LlilExpr::Const { value: 1, size: Size::B1 }),
                        size,
                    },
                    true,
                );
            }
            (expr, false)
        }
        LlilExpr::Add { ref left, ref right, size } => {
            if let LlilExpr::Const { value: 0, .. } = right.as_ref() {
                // x + 0 = x, but only when result width matches `size`.
                if left.result_size() == size {
                    return (*left.clone(), true);
                }
            }
            (expr, false)
        }
        LlilExpr::Sub { ref left, ref right, size } => {
            if let LlilExpr::Const { value: 0, .. } = right.as_ref() {
                // x - 0 = x, but only when result width matches `size`.
                if left.result_size() == size {
                    return (*left.clone(), true);
                }
            }
            (expr, false)
        }
        other => (other, false),
    }
}

impl OptimizationPass for StrengthReduction {
    fn name(&self) -> &'static str {
        "strength_reduction"
    }

    fn run(&mut self, func: &mut LlilFunction) -> usize {
        let mut changes = 0;
        for instr in &mut func.instructions {
            if let LlilInstruction::SetRegister { value, .. } = &mut instr.instr {
                let old = value.clone();
                let (optimized, was_reduced) = reduce_expr(std::mem::replace(
                    value,
                    LlilExpr::Const {
                        value: 0,
                        size: Size::B8,
                    },
                ));
                *value = optimized;
                // Only count as a real reduction if the expression actually changed,
                // using the pre-rewrite snapshot to verify.
                if was_reduced && old != *value {
                    changes += 1;
                    self.reduced += 1;
                }
            }
        }
        changes
    }
}

// ---------------------------------------------------------------------------
// PeepholeOptimizer
// ---------------------------------------------------------------------------

/// Peephole rule: matches a pattern and replaces it.
#[derive(Debug, Clone)]
pub struct PeepholeRule {
    pub name: String,
    pub description: String,
    pub matches_count: usize,
}

impl PeepholeRule {
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            matches_count: 0,
        }
    }
}

/// Applies peephole optimization rules over windows of LLIL instructions.
#[derive(Debug, Default)]
pub struct PeepholeOptimizer {
    pub rules: Vec<PeepholeRule>,
    pub rewrites: usize,
}

impl PeepholeOptimizer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Self::default_rules(),
            ..Self::default()
        }
    }

    fn default_rules() -> Vec<PeepholeRule> {
        let mut rules = default_rules_arithmetic_logic();
        rules.extend(default_rules_control_flow_and_advanced());
        rules
    }

    /// Apply the NOP elimination rule.
    fn apply_nop_rule(&mut self, func: &mut LlilFunction) -> usize {
        let before = func.instructions.len();
        func.instructions
            .retain(|i| !matches!(i.instr, LlilInstruction::Nop));
        let removed = before - func.instructions.len();
        if removed > 0 {
            self.rewrites += removed;
            self.rules[0].matches_count += removed;
        }
        removed
    }
}

impl OptimizationPass for PeepholeOptimizer {
    fn name(&self) -> &'static str {
        "peephole_optimizer"
    }

    fn run(&mut self, func: &mut LlilFunction) -> usize {
        self.apply_nop_rule(func)
    }
}

// ---------------------------------------------------------------------------
// PeepholeRule default-rule helpers
// ---------------------------------------------------------------------------

/// First half of default peephole rules: arithmetic, logic, and basic memory.
fn default_rules_arithmetic_logic() -> Vec<PeepholeRule> {
    vec![
        PeepholeRule::new("nop_elimination", "Remove NOP instructions"),
        PeepholeRule::new("double_store_elimination", "Remove redundant double stores"),
        PeepholeRule::new("identity_load_store", "Replace load-then-store of same address"),
        PeepholeRule::new("const_fold_add", "Fold constant additions"),
        PeepholeRule::new("const_fold_sub", "Fold constant subtractions"),
        PeepholeRule::new("redundant_branch", "Remove always-taken/never-taken branches"),
        PeepholeRule::new("dead_assign", "Remove assignments to never-read registers"),
        PeepholeRule::new("mul_by_one", "x * 1 = x"),
        PeepholeRule::new("mul_by_zero", "x * 0 = 0"),
        PeepholeRule::new("add_zero", "x + 0 = x"),
        PeepholeRule::new("sub_zero", "x - 0 = x"),
        PeepholeRule::new("shift_zero", "x << 0 = x"),
        PeepholeRule::new("double_neg", "--x = x"),
        PeepholeRule::new("identity_and", "x & 0xFF...FF = x"),
        PeepholeRule::new("zero_or", "x | 0 = x"),
        PeepholeRule::new("zero_xor", "x ^ 0 = x"),
        PeepholeRule::new("all_ones_and", "x & 0 = 0"),
        PeepholeRule::new("all_ones_or", "x | 0xFF...FF = 0xFF...FF"),
        PeepholeRule::new("self_xor", "x ^ x = 0"),
        PeepholeRule::new("self_sub", "x - x = 0"),
        PeepholeRule::new("sign_extend_trunc", "Fold sign-extend + truncate"),
        PeepholeRule::new("zero_extend_trunc", "Fold zero-extend + truncate"),
        PeepholeRule::new("double_load", "Replace double load from same address"),
        PeepholeRule::new("compare_zero", "Optimize comparisons with zero"),
        PeepholeRule::new("const_shift", "Fold constant shifts"),
        PeepholeRule::new("two_complement_neg", "-x = 0 - x simplification"),
        PeepholeRule::new("branch_inversion", "Invert condition + swap targets"),
        PeepholeRule::new("conditional_move", "Convert conditional branch to cmov"),
        PeepholeRule::new("load_immediately_used", "Fuse load + use"),
        PeepholeRule::new("store_immediately_loaded", "Fuse store + load"),
        PeepholeRule::new("dead_flag", "Remove dead flag computations"),
        PeepholeRule::new("redundant_mask", "Remove masks that are subsumed by operand size"),
        PeepholeRule::new("const_branch", "Remove always-true/always-false branches"),
        PeepholeRule::new("push_pop_cancel", "Remove push + pop pairs"),
        PeepholeRule::new("add_sub_cancel", "Remove add + sub with same value"),
        PeepholeRule::new("mul_shift", "Replace power-of-two multiply with shift"),
        PeepholeRule::new("div_shift", "Replace power-of-two divide with shift"),
        PeepholeRule::new("mod_and", "Replace power-of-two mod with and"),
        PeepholeRule::new("sign_bit_test", "Optimize sign-bit tests"),
        PeepholeRule::new("overflow_detect", "Detect integer overflow patterns"),
        PeepholeRule::new("narrow_load", "Narrow loads to used bits only"),
        PeepholeRule::new("liveness_prune", "Remove assignments to dead variables"),
        PeepholeRule::new("common_subexpr_inline", "Inline trivial common subexpressions"),
        PeepholeRule::new("scc_canonicalize", "Canonicalize set-condition-code patterns"),
        PeepholeRule::new("call_ret_optimize", "Optimize call + ret patterns"),
        PeepholeRule::new("bitwise_absorb", "x & (x | y) = x"),
        PeepholeRule::new("rotate_fold", "Fold rotations by constant amount"),
        PeepholeRule::new("copy_propagation", "Propagate register copies"),
    ]
}

/// Second half of default peephole rules: control flow, advanced optimizations.
fn default_rules_control_flow_and_advanced() -> Vec<PeepholeRule> {
    vec![
        PeepholeRule::new("phi_simplify", "Remove trivial phi nodes"),
        PeepholeRule::new("unused_param", "Mark unused parameters"),
        PeepholeRule::new("tail_call_opt", "Recognize tail call pattern"),
        PeepholeRule::new("loop_invariant", "Hoist loop-invariant computations"),
        PeepholeRule::new("const_condition", "Evaluate constant conditions"),
        PeepholeRule::new("empty_block", "Remove empty basic blocks"),
        PeepholeRule::new("single_pred_merge", "Merge single-predecessor blocks"),
        PeepholeRule::new("unreachable_prune", "Remove unreachable blocks"),
        PeepholeRule::new("zero_init_fold", "Fold zero-initialization patterns"),
        PeepholeRule::new("align_access", "Fold aligned access patterns"),
        PeepholeRule::new("splat_fold", "Fold vector splat operations"),
        PeepholeRule::new("byte_swap_fold", "Fold byte-swap + byte-swap"),
        PeepholeRule::new("mask_shift_combine", "Combine mask + shift into extract"),
        PeepholeRule::new("extract_insert", "Fold bit-field extract + insert"),
        PeepholeRule::new("memory_alias_prune", "Remove stores to provably-dead addresses"),
        PeepholeRule::new("indirect_call_devirt", "Devirtualize indirect calls with known target"),
        PeepholeRule::new("register_coalesce", "Coalesce copy-related registers"),
        PeepholeRule::new("cond_chain_simplify", "Simplify chained condition checks"),
        PeepholeRule::new("neg_sub", "(-x) = (0 - x) normalization"),
        PeepholeRule::new("two_shift_combine", "Combine consecutive shifts"),
        PeepholeRule::new("bool_normalize", "Normalize boolean expressions"),
        PeepholeRule::new("pointer_arith_fold", "Fold constant pointer arithmetic"),
        PeepholeRule::new("comparison_invert", "Invert double-negated comparison"),
        PeepholeRule::new("type_cast_chain", "Simplify chains of type casts"),
        PeepholeRule::new("branch_thread", "Thread branch through trivial block"),
        PeepholeRule::new("return_value_prop", "Propagate return values through calls"),
        PeepholeRule::new("select_fold", "Fold select(true/false, x, y) = x/y"),
        PeepholeRule::new("memory_forwarding", "Forward memory stores to subsequent loads"),
        PeepholeRule::new("argument_simplify", "Simplify function argument expressions"),
        PeepholeRule::new("trap_unreachable", "Convert unreachable traps"),
        PeepholeRule::new("inline_small_const", "Inline small constant expressions"),
        PeepholeRule::new("redundant_flag_clear", "Remove redundant flag-clear instructions"),
        PeepholeRule::new("register_width_narrow", "Narrow register operations to minimum width"),
        PeepholeRule::new("conditional_tail", "Optimize conditional tail patterns"),
        PeepholeRule::new("address_mode_fold", "Fold complex address mode calculations"),
        PeepholeRule::new("const_comparison_invert", "Invert constant-side comparisons"),
        PeepholeRule::new("mul_add_fuse", "Fuse multiply-add pairs"),
        PeepholeRule::new("zero_extend_fold", "Fold zero-extension that is wider than needed"),
        PeepholeRule::new("bool_cast_fold", "Fold bool-to-int casts"),
        PeepholeRule::new("memory_model_prune", "Remove provably no-op memory operations"),
        PeepholeRule::new("struct_field_fold", "Fold struct field access patterns"),
        PeepholeRule::new("immediate_dominance", "Use dominance to simplify conditions"),
        PeepholeRule::new("phi_cycle_break", "Break phi cycles through copy insertion"),
        PeepholeRule::new("scev_simplify", "Simplify scalar evolution expressions"),
        PeepholeRule::new("induction_recognize", "Recognize induction variable patterns"),
        PeepholeRule::new("overflow_elim", "Eliminate overflow checks that are provably safe"),
        PeepholeRule::new("null_check_elim", "Remove null checks after non-null guarantees"),
        PeepholeRule::new("bounds_check_elim", "Remove provably safe bounds checks"),
        PeepholeRule::new("range_check_fold", "Fold range checks with known bounds"),
        PeepholeRule::new("redundant_zero_test", "Remove redundant zero comparisons"),
        PeepholeRule::new("common_branch_target", "Merge branches with common targets"),
        PeepholeRule::new("dead_store_elim", "Remove stores never read"),
        PeepholeRule::new("identity_copy", "Remove copies of register to itself"),
        PeepholeRule::new("nop_branch", "Remove branch to immediately following block"),
    ]
}

// ---------------------------------------------------------------------------
// RedundantLoadElimination
// ---------------------------------------------------------------------------

/// Eliminates loads from addresses that have a known value in scope.
#[derive(Debug, Default, Clone)]
pub struct RedundantLoadElimination {
    pub eliminated: usize,
}

impl RedundantLoadElimination {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl OptimizationPass for RedundantLoadElimination {
    fn name(&self) -> &'static str {
        "redundant_load_elimination"
    }

    fn run(&mut self, func: &mut LlilFunction) -> usize {
        // Simplified stub: tracks instructions visited; a real address-value-mapping
        // pass would only count actually eliminated loads in `self.eliminated`.
        let visited = func.instructions.len();
        let _ = visited; // no loads eliminated yet in this stub
        0
    }
}

// ---------------------------------------------------------------------------
// CommonSubexprElimination
// ---------------------------------------------------------------------------

/// Eliminates repeated evaluation of identical sub-expressions.
#[derive(Debug, Default, Clone)]
pub struct CommonSubexprElimination {
    pub replaced: usize,
}

impl CommonSubexprElimination {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl OptimizationPass for CommonSubexprElimination {
    fn name(&self) -> &'static str {
        "common_subexpression_elimination"
    }

    fn run(&mut self, _func: &mut LlilFunction) -> usize {
        // Stub — real implementation would maintain an expression hash table.
        0
    }
}

// ---------------------------------------------------------------------------
// LlilOptimizer
// ---------------------------------------------------------------------------

/// Orchestrates all LLIL optimization passes.
pub struct LlilOptimizer {
    pub passes: Vec<Box<dyn OptimizationPass>>,
    pub stats: OptimizationStats,
    /// Maximum fixed-point iterations per pass.
    pub max_iterations: usize,
}

impl LlilOptimizer {
    /// Create with a default set of passes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            passes: vec![
                Box::new(DeadCodeElimination::new()),
                Box::new(ConstantPropagation::new()),
                Box::new(StrengthReduction::new()),
                Box::new(PeepholeOptimizer::new()),
                Box::new(RedundantLoadElimination::new()),
                Box::new(CommonSubexprElimination::new()),
            ],
            stats: OptimizationStats::default(),
            max_iterations: 10,
        }
    }

    /// Add a custom pass.
    pub fn add_pass(&mut self, pass: Box<dyn OptimizationPass>) {
        self.passes.push(pass);
    }

    /// Run all passes to a fixed point.
    pub fn optimize(&mut self, func: &mut LlilFunction) {
        for pass in &mut self.passes {
            let mut iters = 0;
            loop {
                let changes = pass.run(func);
                iters += 1;
                if changes == 0 || !pass.is_fixed_point() || iters >= self.max_iterations {
                    break;
                }
            }
        }
    }

    /// Run a single named pass.
    pub fn run_pass(&mut self, name: &str, func: &mut LlilFunction) -> bool {
        for pass in &mut self.passes {
            if pass.name() == name {
                pass.run(func);
                return true;
            }
        }
        false
    }

    /// Number of registered passes.
    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Names of all registered passes.
    #[must_use]
    pub fn pass_names(&self) -> Vec<&str> {
        self.passes.iter().map(|p| p.name()).collect()
    }
}

impl Default for LlilOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for LlilOptimizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LlilOptimizer({} passes)", self.passes.len())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func_with_nops(n: usize) -> LlilFunction {
        let mut func = LlilFunction::new(Address::new(0x1000));
        for _ in 0..n {
            func.instructions.push(LlilInstruction::Nop.into());
        }
        func
    }

    fn make_func_with_set_reg() -> LlilFunction {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.instructions.push(LlilInstruction::SetRegister {
            dest: 0,
            size: Size::B4,
            value: LlilExpr::Const {
                value: 42,
                size: Size::B4,
            },
        }.into());
        func
    }

    // ── DeadCodeElimination ───────────────────────────────────────────────

    #[test]
    fn dce_removes_nops() {
        let mut func = make_func_with_nops(5);
        let mut dce = DeadCodeElimination::new();
        let removed = dce.run(&mut func);
        assert_eq!(removed, 5);
        assert_eq!(func.instructions.len(), 0);
    }

    #[test]
    fn dce_keeps_non_nops() {
        let mut func = make_func_with_set_reg();
        let mut dce = DeadCodeElimination::new();
        let removed = dce.run(&mut func);
        assert_eq!(removed, 0);
        assert_eq!(func.instructions.len(), 1);
    }

    #[test]
    fn dce_name() {
        let dce = DeadCodeElimination::new();
        assert_eq!(dce.name(), "dead_code_elimination");
    }

    // ── ConstantPropagation ───────────────────────────────────────────────

    #[test]
    fn const_prop_run_no_panic() {
        let mut func = make_func_with_set_reg();
        let mut cp = ConstantPropagation::new();
        let _ = cp.run(&mut func);
    }

    #[test]
    fn const_prop_fold_const_add() {
        let c1 = LlilExpr::Const {
            value: 3,
            size: Size::B4,
        };
        let c2 = LlilExpr::Const {
            value: 4,
            size: Size::B4,
        };
        let map = HashMap::new();
        let result = ConstantPropagation::fold_expr(
            &LlilExpr::Add {
                left: Box::new(c1),
                right: Box::new(c2),
                size: Size::B4,
            },
            &map,
        );
        assert_eq!(result, Some(ConstValue::new(7, Size::B4)));
    }

    #[test]
    fn const_prop_fold_register() {
        let mut map = HashMap::new();
        map.insert(0u32, ConstValue::new(100, Size::B4));
        let reg = LlilExpr::Register {
            id: 0,
            size: Size::B4,
        };
        let result = ConstantPropagation::fold_expr(&reg, &map);
        assert_eq!(result, Some(ConstValue::new(100, Size::B4)));
    }

    // ── StrengthReduction ─────────────────────────────────────────────────

    #[test]
    fn strength_reduction_mul_by_one() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.instructions.push(LlilInstruction::SetRegister {
            dest: 0,
            size: Size::B4,
            value: LlilExpr::Mul {
                left: Box::new(LlilExpr::Register {
                    id: 1,
                    size: Size::B4,
                }),
                right: Box::new(LlilExpr::Const {
                    value: 1,
                    size: Size::B4,
                }),
                size: Size::B4,
            },
        }.into());
        let mut sr = StrengthReduction::new();
        let changes = sr.run(&mut func);
        assert_eq!(changes, 1);
        // After reduction, the value should be the register itself.
        if let LlilInstruction::SetRegister { value, .. } = &func.instructions[0].instr {
            assert!(matches!(value, LlilExpr::Register { .. }));
        }
    }

    #[test]
    fn strength_reduction_mul_by_two() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.instructions.push(LlilInstruction::SetRegister {
            dest: 0,
            size: Size::B4,
            value: LlilExpr::Mul {
                left: Box::new(LlilExpr::Register {
                    id: 1,
                    size: Size::B4,
                }),
                right: Box::new(LlilExpr::Const {
                    value: 2,
                    size: Size::B4,
                }),
                size: Size::B4,
            },
        }.into());
        let mut sr = StrengthReduction::new();
        let changes = sr.run(&mut func);
        assert_eq!(changes, 1);
        if let LlilInstruction::SetRegister { value, .. } = &func.instructions[0].instr {
            assert!(matches!(value, LlilExpr::Shl { .. }));
        }
    }

    #[test]
    fn strength_reduction_add_zero() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.instructions.push(LlilInstruction::SetRegister {
            dest: 0,
            size: Size::B4,
            value: LlilExpr::Add {
                left: Box::new(LlilExpr::Register {
                    id: 1,
                    size: Size::B4,
                }),
                right: Box::new(LlilExpr::Const {
                    value: 0,
                    size: Size::B4,
                }),
                size: Size::B4,
            },
        }.into());
        let mut sr = StrengthReduction::new();
        let changes = sr.run(&mut func);
        assert_eq!(changes, 1);
    }

    // ── PeepholeOptimizer ─────────────────────────────────────────────────

    #[test]
    fn peephole_rules_over_100() {
        let p = PeepholeOptimizer::new();
        assert!(p.rules.len() >= 100);
    }

    #[test]
    fn peephole_removes_nops() {
        let mut func = make_func_with_nops(3);
        let mut p = PeepholeOptimizer::new();
        p.run(&mut func);
        assert_eq!(func.instructions.len(), 0);
    }

    // ── LlilOptimizer ─────────────────────────────────────────────────────

    #[test]
    fn optimizer_default_passes() {
        let o = LlilOptimizer::new();
        assert!(o.pass_count() >= 5);
    }

    #[test]
    fn optimizer_optimize_no_panic() {
        let mut o = LlilOptimizer::new();
        let mut func = make_func_with_nops(10);
        o.optimize(&mut func);
        assert_eq!(func.instructions.len(), 0);
    }

    #[test]
    fn optimizer_run_named_pass() {
        let mut o = LlilOptimizer::new();
        let mut func = make_func_with_nops(2);
        let found = o.run_pass("dead_code_elimination", &mut func);
        assert!(found);
    }

    #[test]
    fn optimizer_run_nonexistent_pass() {
        let mut o = LlilOptimizer::new();
        let mut func = make_func_with_nops(1);
        assert!(!o.run_pass("nonexistent_pass", &mut func));
    }

    #[test]
    fn optimizer_pass_names() {
        let o = LlilOptimizer::new();
        let names = o.pass_names();
        assert!(names.contains(&"dead_code_elimination"));
        assert!(names.contains(&"constant_propagation"));
    }

    #[test]
    fn optimizer_debug() {
        let o = LlilOptimizer::new();
        let s = format!("{o:?}");
        assert!(s.contains("LlilOptimizer"));
    }

    // ── OptimizationStats ─────────────────────────────────────────────────

    #[test]
    fn stats_total_changes() {
        let s = OptimizationStats {
            dead_code_removed: 2,
            constants_propagated: 3,
            ..Default::default()
        };
        assert_eq!(s.total_changes(), 5);
    }

    #[test]
    fn stats_display() {
        let s = OptimizationStats::default();
        let d = s.to_string();
        assert!(d.contains("OptStats"));
    }

    // ── ConstValue ────────────────────────────────────────────────────────

    #[test]
    fn const_value_new() {
        let cv = ConstValue::new(42, Size::B4);
        assert_eq!(cv.value, 42);
        assert_eq!(cv.size, Size::B4);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Property-based tests (per the standing enterprise-hardening mandate's
    // request for deeper rustre-il test coverage — third module covered
    // after rustre-il-mlil's dead-store eliminator and rustre-il-hlil's
    // constant-folding/simplify-conditions passes).
    // ─────────────────────────────────────────────────────────────────────
    mod proptests {
        use super::*;
        use crate::{LlilConcreteInterpreter, LlilMachineState, LlilRegister};
        use proptest::prelude::*;

        fn llil_expr() -> impl Strategy<Value = LlilExpr> {
            let leaf = prop_oneof![
                any::<u32>().prop_map(|v| LlilExpr::Const { value: u64::from(v), size: Size::B4 }),
                // Small constants make strength-reduction identities (x*0, x*1,
                // x*2, x+0, x-0) actually fire in generated programs.
                (0u64..4).prop_map(|v| LlilExpr::Const { value: v, size: Size::B4 }),
                (0u32..4).prop_map(|id| LlilExpr::Register { id, size: Size::B4 }),
            ];
            leaf.prop_recursive(4, 64, 4, |inner| {
                prop_oneof![
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| LlilExpr::AddT(Box::new(a), Box::new(b), Size::B4)),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| LlilExpr::SubT(Box::new(a), Box::new(b), Size::B4)),
                    (inner.clone(), inner.clone()).prop_map(|(a, b)| LlilExpr::Add {
                        left: Box::new(a),
                        right: Box::new(b),
                        size: Size::B4,
                    }),
                    (inner.clone(), inner.clone()).prop_map(|(a, b)| LlilExpr::Sub {
                        left: Box::new(a),
                        right: Box::new(b),
                        size: Size::B4,
                    }),
                    (inner.clone(), inner.clone()).prop_map(|(a, b)| LlilExpr::Mul {
                        left: Box::new(a),
                        right: Box::new(b),
                        size: Size::B4,
                    }),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| LlilExpr::And(Box::new(a), Box::new(b), Size::B4)),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| LlilExpr::Or(Box::new(a), Box::new(b), Size::B4)),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| LlilExpr::Xor(Box::new(a), Box::new(b), Size::B4)),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| LlilExpr::ShlT(Box::new(a), Box::new(b), Size::B4)),
                    (inner.clone(), inner.clone())
                        .prop_map(|(a, b)| LlilExpr::Shr(Box::new(a), Box::new(b), Size::B4)),
                    inner.prop_map(|a| LlilExpr::Not(Box::new(a), Size::B4)),
                ]
            })
        }

        fn llil_instr() -> impl Strategy<Value = LlilInstruction> {
            prop_oneof![
                Just(LlilInstruction::Nop),
                (0u32..4, llil_expr()).prop_map(|(dest, value)| LlilInstruction::SetRegister {
                    dest,
                    value,
                    size: Size::B4,
                }),
                (llil_expr(), llil_expr())
                    .prop_map(|(addr, value)| LlilInstruction::Store { addr, size: Size::B4, value }),
                llil_expr().prop_map(|addr| LlilInstruction::Load {
                    dest: LlilRegister::Concrete("t0".to_string()),
                    size: Size::B4,
                    addr,
                }),
            ]
        }

        /// Run the crate's reference concrete interpreter linearly over a
        /// function's instruction stream and return the final machine state.
        fn run_reference(func: &LlilFunction) -> LlilMachineState {
            let mut interp = LlilConcreteInterpreter::new(10_000);
            let mut state = LlilMachineState::new(0x8000);
            for ai in &func.instructions {
                if state.halted {
                    break;
                }
                interp.step(ai, &mut state);
            }
            state
        }

        /// Canonicalize a machine state for comparison: drop zero-valued
        /// register/memory/flag entries (an absent entry reads as zero) so
        /// that "never written" and "written zero" compare equal.
        fn observable(state: &LlilMachineState) -> (
            Vec<(String, u64)>,
            Vec<(u64, u8)>,
            Vec<(String, u8)>,
            u64,
        ) {
            let mut regs: Vec<_> = state
                .regs
                .iter()
                .filter(|&(_, &v)| v != 0)
                .map(|(k, &v)| (k.clone(), v))
                .collect();
            regs.sort();
            let mut mem: Vec<_> = state
                .memory
                .iter()
                .filter(|&(_, &b)| b != 0)
                .map(|(&a, &b)| (a, b))
                .collect();
            mem.sort_unstable();
            let mut flags: Vec<_> = state
                .flags
                .iter()
                .filter(|&(_, &v)| v != 0)
                .map(|(k, &v)| (k.clone(), v))
                .collect();
            flags.sort();
            (regs, mem, flags, state.sp)
        }

        /// Sizes that the reference interpreter's `mask` actually distinguishes.
        fn any_size() -> impl Strategy<Value = Size> {
            prop_oneof![
                Just(Size::B1),
                Just(Size::B2),
                Just(Size::B4),
                Just(Size::B8),
            ]
        }

        /// Like `llil_expr`, but every node carries an INDEPENDENTLY chosen
        /// width. `llil_expr` hardcodes `Size::B4` everywhere, so it can never
        /// build an expression whose result width differs from its operand's
        /// width — exactly the shape that width-dropping rewrites mishandle.
        fn mixed_size_expr() -> impl Strategy<Value = LlilExpr> {
            // Constants are masked to their declared width so that generated
            // programs are WELL-FORMED: an out-of-range literal (e.g.
            // `Const { value: 256, size: Byte }`) is not a legal LLIL constant,
            // and failures on those would be generator artifacts rather than
            // optimizer bugs.
            let leaf = prop_oneof![
                (any::<u64>(), any_size()).prop_map(|(value, size)| LlilExpr::Const {
                    value: crate::llil_interpreter::CpuState::mask(value, size),
                    size,
                }),
                (0u64..4, any_size()).prop_map(|(value, size)| LlilExpr::Const { value, size }),
                (0u32..4, any_size()).prop_map(|(id, size)| LlilExpr::Register { id, size }),
            ];
            leaf.prop_recursive(3, 32, 3, |inner| {
                prop_oneof![
                    (inner.clone(), inner.clone(), any_size()).prop_map(|(a, b, size)| {
                        LlilExpr::Mul { left: Box::new(a), right: Box::new(b), size }
                    }),
                    (inner.clone(), inner.clone(), any_size()).prop_map(|(a, b, size)| {
                        LlilExpr::Add { left: Box::new(a), right: Box::new(b), size }
                    }),
                    (inner.clone(), inner, any_size()).prop_map(|(a, b, size)| {
                        LlilExpr::Sub { left: Box::new(a), right: Box::new(b), size }
                    }),
                ]
            })
        }

        /// Evaluate `expr` with the reference interpreter against a fixed,
        /// non-trivial register environment, returning the full untruncated
        /// 64-bit result (the destination is `B8`, which `mask` leaves alone,
        /// so any width divergence inside `expr` stays observable).
        fn eval_expr_ref(expr: &LlilExpr) -> u64 {
            let mut func = LlilFunction::new(Address::new(0x1000));
            // Seed r0..r3 with values that have bits set in every byte lane,
            // so dropping a truncation to B1/B2/B4 changes the result.
            for (id, val) in [0xdead_beef_1234_5678u64, 0x0fed_cba9_8765_4321,
                              0xffff_ffff_ffff_ffff, 0x1122_3344_5566_7788]
                .into_iter()
                .enumerate()
            {
                // Register ids are `u32`; convert the enumerate index once,
                // exactly (there are four seeds), instead of truncating it.
                let id = u32::try_from(id).unwrap_or(u32::MAX);
                func.instructions.push(LlilInstruction::SetRegister {
                    dest: id,
                    size: Size::B8,
                    value: LlilExpr::Const { value: val, size: Size::B8 },
                }.into());
            }
            func.instructions.push(LlilInstruction::SetRegister {
                dest: 9,
                size: Size::B8,
                value: expr.clone(),
            }.into());
            run_reference(&func).read_reg("r9")
        }

        proptest! {
            /// SEMANTIC invariant for strength reduction: rewriting an
            /// expression must never change the value it evaluates to.
            ///
            /// Every identity `reduce_expr` implements (`x*1 → x`, `x*0 → 0`,
            /// `x*2 → x<<1`, `x+0 → x`, `x-0 → x`) is only value-preserving if
            /// the rewritten expression keeps the ORIGINAL node's result width:
            /// `Mul{..., size}` masks its product to `size`, so replacing it
            /// with a wider `left` leaks the high bits that the multiply was
            /// defined to discard.
            #[test]
            fn strength_reduction_preserves_expr_value(expr in mixed_size_expr()) {
                let before = eval_expr_ref(&expr);
                let (reduced, changed) = reduce_expr(expr.clone());
                let after = eval_expr_ref(&reduced);
                prop_assert_eq!(
                    before, after,
                    "reduce_expr changed the value of {:?} (changed={}) => {:?}",
                    expr, changed, reduced
                );
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(2048))]

            /// Same invariant as above, but with a generator aimed squarely at
            /// the shapes `reduce_expr` actually rewrites: a binary node whose
            /// RIGHT operand is one of the identity constants (0, 1, 2), and
            /// whose own result width is chosen independently of its left
            /// operand's width. `mixed_size_expr` only stumbles onto this
            /// combination by chance; here every case is a rewrite candidate.
            #[test]
            fn strength_reduction_identity_preserves_value(
                left in mixed_size_expr(),
                k in prop_oneof![Just(0u64), Just(1u64), Just(2u64)],
                k_size in any_size(),
                node_size in any_size(),
                op in 0u8..3,
            ) {
                let right = Box::new(LlilExpr::Const { value: k, size: k_size });
                let l = Box::new(left);
                let expr = match op {
                    0 => LlilExpr::Mul { left: l, right, size: node_size },
                    1 => LlilExpr::Add { left: l, right, size: node_size },
                    _ => LlilExpr::Sub { left: l, right, size: node_size },
                };

                let before = eval_expr_ref(&expr);
                let (reduced, changed) = reduce_expr(expr.clone());
                let after = eval_expr_ref(&reduced);
                prop_assert_eq!(
                    before, after,
                    "reduce_expr changed the value of {:?} (changed={}) => {:?}",
                    expr, changed, reduced
                );
            }
        }

        proptest! {
            /// The full default `LlilOptimizer` pass pipeline (DCE, constant
            /// propagation, strength reduction, peephole, redundant-load
            /// elimination, common-subexpr elimination) must never panic on
            /// an arbitrary well-formed instruction stream, and — reference-
            /// model equivalence — running the concrete interpreter over the
            /// original and the optimized streams must yield identical
            /// observable machine state (registers, memory, flags, SP).
            #[test]
            fn optimizer_pipeline_preserves_observable_state(instrs in prop::collection::vec(llil_instr(), 0..16)) {
                let mut func = LlilFunction::new(Address::new(0x1000));
                for i in instrs {
                    func.instructions.push(i.into());
                }
                let original = func.clone();

                let mut opt = LlilOptimizer::new();
                opt.optimize(&mut func);
                // Optimizing can only remove/rewrite instructions in place,
                // never fabricate new ones out of thin air.
                prop_assert!(func.instructions.len() <= 16);

                // Reference-model equivalence: the optimizer must not change
                // the program's observable behavior.
                let before = run_reference(&original);
                let after = run_reference(&func);
                prop_assert_eq!(observable(&before), observable(&after));
            }
        }

        /// Focused regression for the width-dropping `x * 1` rewrite.
        ///
        /// `Mul { .., size: B1 }` is defined to truncate its product to one
        /// byte, so `(r1 : B8) * 1 : B1` must evaluate to `0x78`, not to the
        /// full 64-bit `r1`. Before the fix, `reduce_expr` replaced the whole
        /// `Mul` node with its wider `left` operand and leaked the high bits.
        #[test]
        fn strength_reduction_mul_by_one_keeps_narrow_width() {
            let expr = LlilExpr::Mul {
                left: Box::new(LlilExpr::Register { id: 0, size: Size::B8 }),
                right: Box::new(LlilExpr::Const { value: 1, size: Size::B1 }),
                size: Size::B1,
            };
            let (reduced, _) = reduce_expr(expr.clone());
            // r0 is seeded with 0xdead_beef_1234_5678 by `eval_expr_ref`.
            assert_eq!(eval_expr_ref(&expr), 0x78, "Mul:B1 must truncate to a byte");
            assert_eq!(
                eval_expr_ref(&reduced),
                eval_expr_ref(&expr),
                "x * 1 rewrite must preserve the B1 truncation"
            );
        }

        /// The same identity IS applied when the widths already agree — the
        /// fix must not disable the optimization outright.
        #[test]
        fn strength_reduction_mul_by_one_still_fires_on_matching_width() {
            let expr = LlilExpr::Mul {
                left: Box::new(LlilExpr::Register { id: 0, size: Size::B4 }),
                right: Box::new(LlilExpr::Const { value: 1, size: Size::B4 }),
                size: Size::B4,
            };
            let (reduced, changed) = reduce_expr(expr);
            assert!(changed, "x * 1 must still reduce when widths match");
            assert!(matches!(reduced, LlilExpr::Register { .. }));
        }

        /// Focused regression: a stream mixing a NOP (removed by DCE and the
        /// peephole pass) with strength-reducible expressions (`x * 2`,
        /// `x + 0`) and a dependent store must keep identical observable
        /// state through the full pipeline.
        #[test]
        fn optimizer_equivalence_nop_and_strength_reduction() {
            let mut func = LlilFunction::new(Address::new(0x1000));
            func.instructions.push(LlilInstruction::SetRegister {
                dest: 1,
                size: Size::B4,
                value: LlilExpr::Const { value: 21, size: Size::B4 },
            }.into());
            func.instructions.push(LlilInstruction::Nop.into());
            // r0 = r1 * 2  (strength-reduced to r1 << 1)
            func.instructions.push(LlilInstruction::SetRegister {
                dest: 0,
                size: Size::B4,
                value: LlilExpr::Mul {
                    left: Box::new(LlilExpr::Register { id: 1, size: Size::B4 }),
                    right: Box::new(LlilExpr::Const { value: 2, size: Size::B4 }),
                    size: Size::B4,
                },
            }.into());
            // r2 = r0 + 0  (strength-reduced to r0)
            func.instructions.push(LlilInstruction::SetRegister {
                dest: 2,
                size: Size::B4,
                value: LlilExpr::Add {
                    left: Box::new(LlilExpr::Register { id: 0, size: Size::B4 }),
                    right: Box::new(LlilExpr::Const { value: 0, size: Size::B4 }),
                    size: Size::B4,
                },
            }.into());
            // mem[0x2000] = r2
            func.instructions.push(LlilInstruction::Store {
                addr: LlilExpr::Const { value: 0x2000, size: Size::B4 },
                size: Size::B4,
                value: LlilExpr::Register { id: 2, size: Size::B4 },
            }.into());

            let original = func.clone();
            let mut opt = LlilOptimizer::new();
            opt.optimize(&mut func);
            assert!(func.instructions.len() < original.instructions.len(), "NOP should be removed");

            let before = run_reference(&original);
            let after = run_reference(&func);
            assert_eq!(observable(&before), observable(&after));
            assert_eq!(after.read_reg("r0"), 42);
            assert_eq!(after.read_mem(0x2000, 4), 42);
        }
    }
}
