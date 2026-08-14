//! `cil_optimizer` — Optimize CIL instruction sequences.
//!
//! Provides [`CilOptimizer`] which applies a configurable pipeline of
//! [`OptimizationPass`]es to a `Vec<CilInstruction>`, performing constant
//! folding, dead-code elimination, branch simplification, and nop removal.

use rustre_dotnet::{CilInstruction, CilOperand};
use serde::{Deserialize, Serialize};

// ─── OptimizationLevel ───────────────────────────────────────────────────────

/// Preset optimization levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OptimizationLevel {
    /// No optimization.
    None,
    /// Only trivially safe passes (nop removal, constant folding of literals).
    Safe,
    /// Adds dead-code elimination and branch simplification.
    Moderate,
    /// All passes enabled.
    Aggressive,
}

impl OptimizationLevel {
    /// Build the ordered list of passes for this level.
    #[must_use]
    pub fn passes(self) -> Vec<OptimizationPass> {
        match self {
            Self::None => vec![],
            Self::Safe => vec![
                OptimizationPass::RemoveNops,
                OptimizationPass::FoldConstants,
            ],
            Self::Moderate => vec![
                OptimizationPass::RemoveNops,
                OptimizationPass::FoldConstants,
                OptimizationPass::EliminateDeadPushPop,
                OptimizationPass::SimplifyBranches,
            ],
            Self::Aggressive => vec![
                OptimizationPass::RemoveNops,
                OptimizationPass::FoldConstants,
                OptimizationPass::EliminateDeadPushPop,
                OptimizationPass::SimplifyBranches,
                OptimizationPass::RemoveUnreachableCode,
                OptimizationPass::PeepholeArithmetic,
                OptimizationPass::InlineReturnConst,
            ],
        }
    }
}

// ─── OptimizationPass ────────────────────────────────────────────────────────

/// A single optimization pass that can be applied to a CIL instruction list.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OptimizationPass {
    /// Remove `nop` instructions.
    RemoveNops,
    /// Fold binary arithmetic of two adjacent integer constant loads.
    FoldConstants,
    /// Remove `dup`/`pop` and `ldc`/`pop` pairs (dead push elimination).
    EliminateDeadPushPop,
    /// Simplify `br.s`/`br` that jump over a single instruction.
    SimplifyBranches,
    /// Remove instructions after an unconditional branch or `ret`/`throw`.
    RemoveUnreachableCode,
    /// Peephole arithmetic: `ldc.i4 N; mul/add 0/1` simplifications.
    PeepholeArithmetic,
    /// Inline `ldc.i4 N; ret` into `ldc.i4 N; ret` (no-op if already minimal).
    InlineReturnConst,
    /// Custom pass identified by a name (no-op in this implementation; hook point).
    Custom(String),
}

impl OptimizationPass {
    /// Human-readable name.
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::RemoveNops => "remove-nops",
            Self::FoldConstants => "fold-constants",
            Self::EliminateDeadPushPop => "elim-dead-push-pop",
            Self::SimplifyBranches => "simplify-branches",
            Self::RemoveUnreachableCode => "remove-unreachable",
            Self::PeepholeArithmetic => "peephole-arith",
            Self::InlineReturnConst => "inline-return-const",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Apply this pass to a mutable instruction list.
    /// Returns the number of instructions removed or changed.
    pub fn apply(&self, instrs: &mut Vec<CilInstruction>) -> usize {
        match self {
            Self::RemoveNops => remove_nops(instrs),
            Self::FoldConstants => fold_constants(instrs),
            Self::EliminateDeadPushPop => elim_dead_push_pop(instrs),
            Self::SimplifyBranches => simplify_branches(instrs),
            Self::RemoveUnreachableCode => remove_unreachable(instrs),
            Self::PeepholeArithmetic => peephole_arithmetic(instrs),
            Self::InlineReturnConst => inline_return_const(instrs),
            Self::Custom(_) => 0,
        }
    }
}

// ─── OptimizationResult ──────────────────────────────────────────────────────

/// The result of running the optimizer on a method body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationResult {
    /// How many instructions were in the body before optimization.
    pub original_count: usize,
    /// How many instructions are in the body after optimization.
    pub optimized_count: usize,
    /// Number of instructions removed overall.
    pub removed: usize,
    /// Number of instructions modified (counted separately from removed).
    pub modified: usize,
    /// Per-pass change counts `(pass_name, delta)`.
    pub pass_results: Vec<(String, usize)>,
    /// Whether the instruction list was changed at all.
    pub changed: bool,
}

impl OptimizationResult {
    /// Reduction percentage (0–100).
    #[must_use]
    pub fn reduction_pct(&self) -> f64 {
        if self.original_count == 0 {
            return 0.0;
        }
        (self.removed as f64 / self.original_count as f64) * 100.0
    }
}

// ─── CilOptimizer ────────────────────────────────────────────────────────────

/// Applies a pipeline of [`OptimizationPass`]es to CIL instruction lists.
///
/// ```ignore
/// let mut opt = CilOptimizer::new(OptimizationLevel::Moderate);
/// let result = opt.optimize(&mut instrs);
/// println!("removed {} instructions", result.removed);
/// ```
pub struct CilOptimizer {
    /// Ordered list of passes to apply.
    passes: Vec<OptimizationPass>,
    /// Maximum number of full-pipeline iterations (for fixed-point convergence).
    pub max_iterations: usize,
    /// Whether to re-number offsets after optimization.
    pub renumber_offsets: bool,
}

impl CilOptimizer {
    /// Create an optimizer from an `OptimizationLevel`.
    #[must_use]
    pub fn new(level: OptimizationLevel) -> Self {
        Self {
            passes: level.passes(),
            max_iterations: 3,
            renumber_offsets: true,
        }
    }

    /// Create an optimizer with a custom list of passes.
    #[must_use]
    pub const fn with_passes(passes: Vec<OptimizationPass>) -> Self {
        Self {
            passes,
            max_iterations: 3,
            renumber_offsets: true,
        }
    }

    /// Add a pass to the end of the pipeline.
    pub fn add_pass(&mut self, pass: OptimizationPass) {
        self.passes.push(pass);
    }

    /// Run the optimizer, returning a result summary.
    pub fn optimize(&self, instrs: &mut Vec<CilInstruction>) -> OptimizationResult {
        let original_count = instrs.len();
        let mut total_removed = 0usize;
        let mut total_modified = 0usize;
        let mut pass_results: Vec<(String, usize)> = Vec::new();

        for _iter in 0..self.max_iterations {
            let mut changed_this_iter = false;
            for pass in &self.passes {
                let before = instrs.len();
                let changed = pass.apply(instrs);
                let after = instrs.len();
                let removed_now = before.saturating_sub(after);
                total_removed += removed_now;
                total_modified += changed.saturating_sub(removed_now);
                if removed_now > 0 || changed > 0 {
                    changed_this_iter = true;
                }
                pass_results.push((pass.name().to_string(), changed));
            }
            if !changed_this_iter {
                break;
            }
        }

        if self.renumber_offsets {
            renumber(instrs);
        }

        let changed = instrs.len() != original_count || total_modified > 0;
        OptimizationResult {
            original_count,
            optimized_count: instrs.len(),
            removed: total_removed,
            modified: total_modified,
            pass_results,
            changed,
        }
    }

    /// Optimize a single-method body using the `fold_constants` pass only
    /// (quick utility method).
    pub fn fold(&self, instrs: &mut Vec<CilInstruction>) -> usize {
        fold_constants(instrs)
    }

    /// Access the current pass list.
    #[must_use]
    pub fn passes(&self) -> &[OptimizationPass] {
        &self.passes
    }
}

// ─── Pass implementations ─────────────────────────────────────────────────────

/// Remove all `nop` instructions.
pub fn remove_nops(instrs: &mut Vec<CilInstruction>) -> usize {
    let before = instrs.len();
    instrs.retain(|i| i.opcode != "nop");
    before - instrs.len()
}

/// Fold constant arithmetic: `ldc.i4 A; ldc.i4 B; add/sub/mul` → `ldc.i4 result`.
pub fn fold_constants(instrs: &mut Vec<CilInstruction>) -> usize {
    let mut changed = 0usize;
    let mut i = 0usize;

    while i + 2 < instrs.len() {
        let a = const_i32(&instrs[i]);
        let b = const_i32(&instrs[i + 1]);
        let op = instrs[i + 2].opcode.as_str();

        if let (Some(va), Some(vb)) = (a, b) {
            let result: Option<i32> = match op {
                "add" => va.checked_add(vb),
                "sub" => va.checked_sub(vb),
                "mul" => va.checked_mul(vb),
                "and" => Some(va & vb),
                "or" => Some(va | vb),
                "xor" => Some(va ^ vb),
                _ => None,
            };
            if let Some(r) = result {
                // Replace the three instructions with a single ldc.i4
                let offset = instrs[i].offset;
                let new_instr = CilInstruction::with_i32(offset, "ldc.i4", r);
                instrs.drain(i..i + 3);
                instrs.insert(i, new_instr);
                changed += 1;
                continue; // re-check at same position
            }
        }
        i += 1;
    }
    changed
}

/// Remove `dup; pop` pairs and `ldc.i4 _; pop` sequences.
pub fn elim_dead_push_pop(instrs: &mut Vec<CilInstruction>) -> usize {
    let mut changed = 0usize;
    let mut i = 0usize;

    while i + 1 < instrs.len() {
        let push = is_pure_push(&instrs[i]);
        let next_is_pop = instrs[i + 1].opcode == "pop";

        if push && next_is_pop {
            instrs.drain(i..i + 2);
            changed += 1;
            // do not advance i; re-check
        } else {
            i += 1;
        }
    }
    changed
}

/// Simplify `br` to the immediately following instruction (jump to next).
pub fn simplify_branches(instrs: &mut Vec<CilInstruction>) -> usize {
    let mut to_remove: Vec<usize> = Vec::new();

    for i in 0..instrs.len() {
        let instr = &instrs[i];
        if instr.opcode == "br" || instr.opcode == "br.s" {
            if let CilOperand::Branch(target) = instr.operand {
                // If the target equals the offset of the next instruction it's a no-op branch
                if let Some(next) = instrs.get(i + 1) {
                    if next.offset == target {
                        to_remove.push(i);
                    }
                }
            }
        }
    }
    let removed = to_remove.len();
    for &idx in to_remove.iter().rev() {
        instrs.remove(idx);
    }
    removed
}

/// Remove instructions after an unconditional `br`, `ret`, or `throw`.
pub fn remove_unreachable(instrs: &mut Vec<CilInstruction>) -> usize {
    let mut cut_at = None;
    for (i, instr) in instrs.iter().enumerate() {
        if matches!(instr.opcode.as_str(), "ret" | "throw" | "rethrow" | "br" | "br.s" | "jmp") {
            if i + 1 < instrs.len() {
                cut_at = Some(i + 1);
            }
            break;
        }
    }

    cut_at.map_or(0, |cut| {
        let removed = instrs.len() - cut;
        instrs.truncate(cut);
        removed
    })
}

// ─── peephole_arithmetic ─────────────────────────────────────────────────────

/// Peephole arithmetic simplifications:
/// - `ldc.i4 0; add` → nothing (remove both)
/// - `ldc.i4 1; mul` → nothing
/// - `ldc.i4 0; mul` → `ldc.i4 0` (replace pair)
pub fn peephole_arithmetic(instrs: &mut Vec<CilInstruction>) -> usize {
    let mut changed = 0usize;
    let mut i = 0usize;

    while i + 1 < instrs.len() {
        let maybe_const = const_i32(&instrs[i]);
        let op = instrs[i + 1].opcode.clone();

        match (maybe_const, op.as_str()) {
            (Some(0), "add") | (Some(0), "sub") => {
                // `ldc.i4 0; add/sub` — neutral; just remove both
                instrs.drain(i..i + 2);
                changed += 1;
            }
            (Some(1), "mul") => {
                // `ldc.i4 1; mul` — identity; remove both
                instrs.drain(i..i + 2);
                changed += 1;
            }
            (Some(0), "mul") => {
                // `ldc.i4 0; mul` — result is always 0; replace with `pop; ldc.i4 0`
                // (we need to pop the value below, so keep it conservative)
                i += 1;
            }
            (Some(0), "or") => {
                // `ldc.i4 0; or` — identity; remove both
                instrs.drain(i..i + 2);
                changed += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    changed
}

/// Simplify a body that ends with `ldc.i4 N; ret` by ensuring it has no
/// unnecessary instructions before the final push+ret pair.
pub fn inline_return_const(instrs: &mut Vec<CilInstruction>) -> usize {
    // Detect the canonical `ldc.i4 N; ret` tail and report a single "inlinable"
    // shape. The pass is conservative: it does not rewrite anything, but its
    // return value tells callers whether the body is a candidate.
    let n = instrs.len();
    if n < 2 {
        return 0;
    }
    let last = &instrs[n - 1];
    let prev = &instrs[n - 2];
    if last.opcode == "ret" && const_i32(prev).is_some() {
        return 1;
    }
    0
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Extract an i32 constant if this instruction is a constant-load.
fn const_i32(instr: &CilInstruction) -> Option<i32> {
    match instr.opcode.as_str() {
        "ldc.i4" => {
            if let CilOperand::Int32(v) = instr.operand {
                return Some(v);
            }
            None
        }
        "ldc.i4.s" => {
            if let CilOperand::Int8(v) = instr.operand {
                return Some(i32::from(v));
            }
            None
        }
        "ldc.i4.0" => Some(0),
        "ldc.i4.1" => Some(1),
        "ldc.i4.2" => Some(2),
        "ldc.i4.3" => Some(3),
        "ldc.i4.4" => Some(4),
        "ldc.i4.5" => Some(5),
        "ldc.i4.6" => Some(6),
        "ldc.i4.7" => Some(7),
        "ldc.i4.8" => Some(8),
        "ldc.i4.m1" => Some(-1),
        _ => None,
    }
}

/// Whether an instruction has no side effects and pushes exactly one value.
fn is_pure_push(instr: &CilInstruction) -> bool {
    matches!(
        instr.opcode.as_str(),
        "ldc.i4"
            | "ldc.i4.s"
            | "ldc.i4.0"
            | "ldc.i4.1"
            | "ldc.i4.2"
            | "ldc.i4.3"
            | "ldc.i4.4"
            | "ldc.i4.5"
            | "ldc.i4.6"
            | "ldc.i4.7"
            | "ldc.i4.8"
            | "ldc.i4.m1"
            | "ldc.i8"
            | "ldnull"
            | "dup"
    )
}

/// Renumber the `offset` fields of all instructions sequentially (byte-offset
/// approximation: each instruction is counted as 1 unit for simplicity).
pub fn renumber(instrs: &mut Vec<CilInstruction>) {
    for (i, instr) in instrs.iter_mut().enumerate() {
        instr.offset = i as u32;
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_dotnet::CilInstruction;

    fn ldc(offset: u32, v: i32) -> CilInstruction {
        CilInstruction::with_i32(offset, "ldc.i4", v)
    }

    fn op(offset: u32, name: &str) -> CilInstruction {
        CilInstruction::simple(offset, name)
    }

    #[test]
    fn test_remove_nops() {
        let mut instrs = vec![
            op(0, "nop"),
            ldc(1, 42),
            op(2, "nop"),
            op(3, "ret"),
        ];
        let removed = remove_nops(&mut instrs);
        assert_eq!(removed, 2);
        assert_eq!(instrs.len(), 2);
        assert!(instrs.iter().all(|i| i.opcode != "nop"));
    }

    #[test]
    fn test_fold_constants_add() {
        let mut instrs = vec![ldc(0, 3), ldc(1, 4), op(2, "add"), op(3, "ret")];
        let changed = fold_constants(&mut instrs);
        assert_eq!(changed, 1);
        assert_eq!(instrs.len(), 2);
        assert_eq!(const_i32(&instrs[0]), Some(7));
    }

    #[test]
    fn test_fold_constants_mul() {
        let mut instrs = vec![ldc(0, 6), ldc(1, 7), op(2, "mul"), op(3, "ret")];
        fold_constants(&mut instrs);
        assert_eq!(const_i32(&instrs[0]), Some(42));
    }

    #[test]
    fn test_fold_constants_sub() {
        let mut instrs = vec![ldc(0, 10), ldc(1, 3), op(2, "sub")];
        fold_constants(&mut instrs);
        assert_eq!(const_i32(&instrs[0]), Some(7));
    }

    #[test]
    fn test_fold_constants_no_change() {
        let mut instrs = vec![ldc(0, 1), op(1, "ret")];
        let changed = fold_constants(&mut instrs);
        assert_eq!(changed, 0);
    }

    #[test]
    fn test_elim_dead_push_pop() {
        let mut instrs = vec![
            ldc(0, 99),
            op(1, "pop"),
            op(2, "ret"),
        ];
        let changed = elim_dead_push_pop(&mut instrs);
        assert_eq!(changed, 1);
        assert_eq!(instrs.len(), 1);
    }

    #[test]
    fn test_remove_unreachable() {
        let mut instrs = vec![
            op(0, "ret"),
            ldc(1, 0),
            op(2, "nop"),
        ];
        let removed = remove_unreachable(&mut instrs);
        assert_eq!(removed, 2);
        assert_eq!(instrs.len(), 1);
    }

    #[test]
    fn test_simplify_branch_to_next() {
        let mut instrs = vec![
            CilInstruction::branch(0, "br.s", 1),
            op(1, "ret"),
        ];
        let removed = simplify_branches(&mut instrs);
        assert_eq!(removed, 1);
        assert_eq!(instrs[0].opcode, "ret");
    }

    #[test]
    fn test_peephole_add_zero() {
        let mut instrs = vec![
            ldc(0, 5),   // value on stack
            ldc(1, 0),   // constant 0
            op(2, "add"),
        ];
        // After elim: ldc 0; add → removed
        let changed = peephole_arithmetic(&mut instrs);
        assert_eq!(changed, 1);
    }

    #[test]
    fn test_peephole_mul_one() {
        let mut instrs = vec![
            ldc(0, 5),
            CilInstruction::simple(1, "ldc.i4.1"),
            op(2, "mul"),
        ];
        let changed = peephole_arithmetic(&mut instrs);
        assert_eq!(changed, 1);
    }

    #[test]
    fn test_optimizer_moderate() {
        let mut instrs = vec![
            op(0, "nop"),
            ldc(1, 3),
            ldc(2, 4),
            op(3, "add"),
            op(4, "ret"),
            op(5, "nop"), // unreachable
        ];
        let opt = CilOptimizer::new(OptimizationLevel::Moderate);
        let result = opt.optimize(&mut instrs);
        assert!(result.changed);
        // After nop-removal + fold + unreachable removal the body is minimal
        assert!(instrs.iter().all(|i| i.opcode != "nop"));
    }

    #[test]
    fn test_optimizer_no_op() {
        let mut instrs = vec![ldc(0, 42), op(1, "ret")];
        let opt = CilOptimizer::new(OptimizationLevel::None);
        let result = opt.optimize(&mut instrs);
        assert!(!result.changed);
        assert_eq!(result.removed, 0);
    }

    #[test]
    fn test_renumber() {
        let mut instrs = vec![op(100, "nop"), op(200, "ret")];
        renumber(&mut instrs);
        assert_eq!(instrs[0].offset, 0);
        assert_eq!(instrs[1].offset, 1);
    }

    #[test]
    fn test_fold_constants_xor() {
        let mut instrs = vec![ldc(0, 0xFF), ldc(1, 0x0F), op(2, "xor")];
        fold_constants(&mut instrs);
        assert_eq!(const_i32(&instrs[0]), Some(0xFF ^ 0x0F));
    }

    #[test]
    fn test_reduction_pct() {
        let result = OptimizationResult {
            original_count: 10,
            optimized_count: 7,
            removed: 3,
            modified: 0,
            pass_results: vec![],
            changed: true,
        };
        assert!((result.reduction_pct() - 30.0).abs() < 0.01);
    }
}
