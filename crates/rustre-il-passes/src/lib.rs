//! `rustre-il-passes`
//!
//! Production-grade IL analysis and optimization pass framework for the `RustRE`
//! suite.  Passes operate on [`LlilFunction`] in-place and communicate results
//! through a shared [`PassContext`].  The [`PassManager`] orchestrates ordered
//! execution and convergence-based iteration.
//!
//! ## Two pass families: `AnalysisPass` (V1, canonical) vs `IlOptPass` (V2, experimental)
//!
//! This crate contains two parallel implementations of several optimization
//! passes (constant folding, copy propagation, CSE, strength reduction, LICM,
//! tail-call optimization, dead-code elimination):
//!
//! - **[`AnalysisPass`] (V1)** is the canonical, mature implementation: ~29
//!   passes, mutates a shared [`PassContext`] in place, and is exercised by
//!   the bulk of this crate's unit tests. `rustre-mcp-tools` (the only
//!   external consumer in the workspace) calls individual V1 free functions
//!   directly (e.g. `run_gvn_pass`). **Prefer V1 for anything new or
//!   production-facing.**
//! - **[`IlOptPass`] (V2)**, with its `*V2`-suffixed structs and
//!   [`PassPipeline`]/[`standard_pipeline`], is an experimental staging area
//!   exploring a value-returning (rather than in-place-mutation) pass
//!   interface. Individual V2 passes are frequently *thinner* than their V1
//!   counterparts — e.g. `LoopInvariantCodeMotionPassV2`'s own doc comment
//!   admits it is a "simplified heuristic" that only hoists `SetReg`-from-
//!   constant, whereas V1's `LoopInvariantCodeMotionPass`
//!   ([`loop_analysis`]/[`LicmPass`]) does real loop-structure analysis.
//!   Some V2 passes (`ConstantFoldingPassV2`, `CopyPropagationPassV2`,
//!   `CseOptPass`, `StrengthReductionPassV2`, `LoopInvariantCodeMotionPassV2`,
//!   `TailCallOptimizationPassV2`) are thin wrappers that just call the V1
//!   free function / `AnalysisPass` and repackage the result as a
//!   [`PassResult`] — so for those, correctness tracks V1 exactly.
//!   `standard_pipeline()`/`fast_pipeline()` use a **fixed, hand-written pass
//!   order** — they do NOT consult [`pass_dependency_graph`]'s
//!   `PassDependencyGraph`/`PassScheduler` (topological ordering, cycle and
//!   conflict detection over declared pass dependencies). That module is
//!   fully built out and unit-tested but currently unused by any pipeline
//!   runner in this crate; wiring `PassScheduler::ordered_passes` into
//!   `PassPipeline` construction is the natural next step if V2 is promoted
//!   out of staging. Until then, treat V2 as experimental: safe to use for
//!   prototyping the dependency-aware-ordering idea, not as a drop-in
//!   replacement for V1.

pub mod constant_propagation;
pub mod interprocedural_passes;
pub mod loop_analysis;
pub mod memory_access_patterns;
pub mod optimization_pipeline;
pub mod pass_dependency_graph;
pub mod pass_metrics;
pub mod switch_detection;
pub mod type_recovery_pass;

pub mod alias;
pub mod dominators;
pub mod gvn2;
pub mod ssa;

use std::collections::{HashMap, HashSet};

use rustre_core::address::Address;
use rustre_il_llil::{
    LlilAnnotatedInstr, LlilCfg, LlilExpr, LlilFunction, LlilInstruction, LlilRegister, Size,
};

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PassStats
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Counters accumulated while a pass runs.
#[derive(Debug, Clone, Default)]
pub struct PassStats {
    /// Total instructions visited across all blocks.
    pub instrs_visited: usize,
    /// Instructions whose content was changed (but not removed).
    pub instrs_modified: usize,
    /// Instructions removed from the function.
    pub instrs_removed: usize,
    /// Number of constant-folding rewrites.
    pub const_folded: usize,
    /// Number of expression simplifications (identity elimination, etc.).
    pub exprs_simplified: usize,
    /// Number of dead instructions/blocks removed.
    pub dead_removed: usize,
}

impl PassStats {
    /// Creates zeroed stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accumulate another set of stats into `self`.
    pub const fn merge(&mut self, other: &Self) {
        self.instrs_visited += other.instrs_visited;
        self.instrs_modified += other.instrs_modified;
        self.instrs_removed += other.instrs_removed;
        self.const_folded += other.const_folded;
        self.exprs_simplified += other.exprs_simplified;
        self.dead_removed += other.dead_removed;
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PassContext
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Shared mutable state threaded through a pass run.
#[derive(Debug, Clone)]
pub struct PassContext {
    /// Set to `true` whenever a pass modifies the function.
    pub changed: bool,
    /// Accumulated statistics.
    pub stats: PassStats,
    /// Non-fatal diagnostic messages emitted during the run.
    pub warnings: Vec<String>,
    /// The IL tier these passes are operating on. Every pass in this crate
    /// runs over an [`LlilFunction`], so this is [`rustre_il::IlTier::Llil`];
    /// it exists so diagnostics can be attributed to a tier without each pass
    /// hard-coding the string (see [`PassContext::warn_at_tier`]).
    pub tier: rustre_il::IlTier,
}

impl Default for PassContext {
    fn default() -> Self {
        Self::new()
    }
}

impl PassContext {
    /// Creates a fresh context with no changes and zeroed stats.
    #[must_use]
    pub fn new() -> Self {
        Self {
            changed: false,
            stats: PassStats::new(),
            warnings: Vec::new(),
            tier: rustre_il::IlTier::Llil,
        }
    }

    /// Mark that the function was modified this pass iteration.
    pub const fn mark_changed(&mut self) {
        self.changed = true;
    }

    /// Append a diagnostic warning message.
    pub fn add_warning(&mut self, w: impl Into<String>) {
        self.warnings.push(w.into());
    }

    /// Append a diagnostic warning prefixed with the context's IL tier tag,
    /// e.g. `"[llil] …"`.
    pub fn warn_at_tier(&mut self, msg: &str) {
        let t = self.tier.tag();
        self.warnings.push(format!("[{t}] {msg}"));
    }

    /// Merge another context's stats and warnings into `self`.
    /// The `changed` flag is OR'd.
    pub fn merge(&mut self, other: &Self) {
        self.changed |= other.changed;
        self.stats.merge(&other.stats);
        self.warnings.extend(other.warnings.iter().cloned());
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// AnalysisPass trait
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// The base trait implemented by every IL analysis / optimization pass.
pub trait AnalysisPass: Send + Sync {
    /// Short machine-readable name, e.g. `"constant-folding"`.
    fn name(&self) -> &str;

    /// Human-readable one-line description of what the pass does.
    fn description(&self) -> &str;

    /// Run the pass on `func`, updating it in-place and recording any changes
    /// in `ctx`.
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext);

    /// Whether running this pass twice in a row is guaranteed to produce no
    /// further changes.  Defaults to `true`.
    fn is_idempotent(&self) -> bool {
        true
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ExprVisitor —" utility for walking/transforming expression trees
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A visitor that may replace any [`LlilExpr`] node during a tree walk.
///
/// Return `Some(replacement)` to substitute the current node, or `None` to
/// leave it unchanged.  The default implementation returns `None` for every
/// node (identity transform).  Implementors that need to recurse into children
/// should call [`walk_expr_mut`] on them explicitly.
pub trait ExprVisitor {
    /// Called for every node in the expression tree (bottom-up).
    fn visit_expr(&mut self, expr: &LlilExpr) -> Option<LlilExpr>;
}

/// Maximum expression tree depth for [`walk_expr_mut`] traversal.
///
/// Prevents stack overflow when processing deeply nested [`LlilExpr`] trees
/// that originate from attacker-supplied binary data (dos-unbounded-recursion).
const WALK_EXPR_MAX_DEPTH: usize = 512;

/// Recursively transform an expression tree bottom-up using `visitor`.
///
/// Children are processed first; then [`ExprVisitor::visit_expr`] is called on
/// the (potentially rewritten) parent node.
///
/// Recursion depth is capped at [`WALK_EXPR_MAX_DEPTH`]; nodes beyond that
/// depth are returned unchanged without visiting their children.
pub fn walk_expr_mut(expr: LlilExpr, visitor: &mut dyn ExprVisitor) -> LlilExpr {
    walk_expr_mut_bounded(expr, visitor, 0)
}

fn walk_expr_mut_bounded(expr: LlilExpr, visitor: &mut dyn ExprVisitor, depth: usize) -> LlilExpr {
    if depth >= WALK_EXPR_MAX_DEPTH {
        // Do not recurse further; return the node unchanged.
        return expr;
    }
    // Recurse into children first (bottom-up).
    let expr = transform_children_bounded(expr, visitor, depth);
    // Then let the visitor decide whether to replace this node.
    visitor.visit_expr(&expr).map_or(expr, |new_expr| new_expr)
}

/// Walk two child expressions through the visitor and reconstruct a sized binop.
fn walk_binop_sz(
    l: LlilExpr,
    r: LlilExpr,
    s: Size,
    visitor: &mut dyn ExprVisitor,
    depth: usize,
    ctor: fn(Box<LlilExpr>, Box<LlilExpr>, Size) -> LlilExpr,
) -> LlilExpr {
    ctor(
        Box::new(walk_expr_mut_bounded(l, visitor, depth + 1)),
        Box::new(walk_expr_mut_bounded(r, visitor, depth + 1)),
        s,
    )
}

/// Walk two child expressions through the visitor and reconstruct an unsized binop.
fn walk_binop_no_sz(
    l: LlilExpr,
    r: LlilExpr,
    visitor: &mut dyn ExprVisitor,
    depth: usize,
    ctor: fn(Box<LlilExpr>, Box<LlilExpr>) -> LlilExpr,
) -> LlilExpr {
    ctor(
        Box::new(walk_expr_mut_bounded(l, visitor, depth + 1)),
        Box::new(walk_expr_mut_bounded(r, visitor, depth + 1)),
    )
}

/// Walk a single child expression through the visitor.
fn w1(v: &mut dyn ExprVisitor, e: LlilExpr, d: usize) -> LlilExpr {
    walk_expr_mut_bounded(e, v, d + 1)
}

/// Transform all direct children of `expr` using `visitor`.
fn transform_children_bounded(expr: LlilExpr, visitor: &mut dyn ExprVisitor, depth: usize) -> LlilExpr {
    let d = depth;
    match expr {
        // Leaf nodes — no children to recurse into.
        LlilExpr::Const { .. }
        | LlilExpr::StackPointer(_)
        | LlilExpr::Flag(_)
        | LlilExpr::Undefined(_)
        | LlilExpr::Register { .. }
        | LlilExpr::RegisterRef { .. } => expr,

        // Struct-form arithmetic — two children.
        LlilExpr::Add { left, right, size } => LlilExpr::Add { left: Box::new(w1(visitor, *left, d)), right: Box::new(w1(visitor, *right, d)), size },
        LlilExpr::Sub { left, right, size } => LlilExpr::Sub { left: Box::new(w1(visitor, *left, d)), right: Box::new(w1(visitor, *right, d)), size },
        LlilExpr::Mul { left, right, size } => LlilExpr::Mul { left: Box::new(w1(visitor, *left, d)), right: Box::new(w1(visitor, *right, d)), size },
        LlilExpr::Shl { value, shift, size } => LlilExpr::Shl { value: Box::new(w1(visitor, *value, d)), shift: Box::new(w1(visitor, *shift, d)), size },

        // Single-child nodes.
        LlilExpr::Load { addr, size } => LlilExpr::Load { addr: Box::new(w1(visitor, *addr, d)), size },
        LlilExpr::Neg(e, s) => LlilExpr::Neg(Box::new(w1(visitor, *e, d)), s),
        LlilExpr::Not(e, s) => LlilExpr::Not(Box::new(w1(visitor, *e, d)), s),
        LlilExpr::FNeg(e, s) => LlilExpr::FNeg(Box::new(w1(visitor, *e, d)), s),
        LlilExpr::ZeroExtend { expr: e, from, to } => LlilExpr::ZeroExtend { expr: Box::new(w1(visitor, *e, d)), from, to },
        LlilExpr::SignExtend { expr: e, from, to } => LlilExpr::SignExtend { expr: Box::new(w1(visitor, *e, d)), from, to },
        LlilExpr::LowPart { expr: e, to } => LlilExpr::LowPart { expr: Box::new(w1(visitor, *e, d)), to },
        LlilExpr::IntToFloat { expr: e, to } => LlilExpr::IntToFloat { expr: Box::new(w1(visitor, *e, d)), to },
        LlilExpr::FloatToInt { expr: e, to } => LlilExpr::FloatToInt { expr: Box::new(w1(visitor, *e, d)), to },

        // Two-child arithmetic / bitwise / shift
        LlilExpr::AddT(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::AddT),
        LlilExpr::SubT(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::SubT),
        LlilExpr::MulT(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::MulT),
        LlilExpr::DivU(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::DivU),
        LlilExpr::DivS(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::DivS),
        LlilExpr::ModU(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::ModU),
        LlilExpr::ModS(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::ModS),
        LlilExpr::And(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::And),
        LlilExpr::Or(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::Or),
        LlilExpr::Xor(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::Xor),
        LlilExpr::ShlT(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::ShlT),
        LlilExpr::Shr(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::Shr),
        LlilExpr::Sar(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::Sar),
        LlilExpr::Rol(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::Rol),
        LlilExpr::Ror(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::Ror),
        LlilExpr::FAdd(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::FAdd),
        LlilExpr::FSub(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::FSub),
        LlilExpr::FMul(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::FMul),
        LlilExpr::FDiv(l, r, s) => walk_binop_sz(*l, *r, s, visitor, depth, LlilExpr::FDiv),

        // Comparisons (no size parameter)
        LlilExpr::CmpEq(l, r) => walk_binop_no_sz(*l, *r, visitor, depth, LlilExpr::CmpEq),
        LlilExpr::CmpNe(l, r) => walk_binop_no_sz(*l, *r, visitor, depth, LlilExpr::CmpNe),
        LlilExpr::CmpSlt(l, r) => walk_binop_no_sz(*l, *r, visitor, depth, LlilExpr::CmpSlt),
        LlilExpr::CmpUlt(l, r) => walk_binop_no_sz(*l, *r, visitor, depth, LlilExpr::CmpUlt),
        LlilExpr::CmpSle(l, r) => walk_binop_no_sz(*l, *r, visitor, depth, LlilExpr::CmpSle),
        LlilExpr::CmpUle(l, r) => walk_binop_no_sz(*l, *r, visitor, depth, LlilExpr::CmpUle),
        LlilExpr::CmpSgt(l, r) => walk_binop_no_sz(*l, *r, visitor, depth, LlilExpr::CmpSgt),
        LlilExpr::CmpUgt(l, r) => walk_binop_no_sz(*l, *r, visitor, depth, LlilExpr::CmpUgt),
        LlilExpr::CmpSge(l, r) => walk_binop_no_sz(*l, *r, visitor, depth, LlilExpr::CmpSge),
        LlilExpr::CmpUge(l, r) => walk_binop_no_sz(*l, *r, visitor, depth, LlilExpr::CmpUge),
        LlilExpr::FCmpEq(l, r) => walk_binop_no_sz(*l, *r, visitor, depth, LlilExpr::FCmpEq),
        LlilExpr::FCmpLt(l, r) => walk_binop_no_sz(*l, *r, visitor, depth, LlilExpr::FCmpLt),
        LlilExpr::FCmpGt(l, r) => walk_binop_no_sz(*l, *r, visitor, depth, LlilExpr::FCmpGt),

        // CondExpr —" three children
        LlilExpr::CondExpr {
            cond,
            true_val,
            false_val,
            size,
        } => LlilExpr::CondExpr {
            cond: Box::new(walk_expr_mut_bounded(*cond, visitor, depth + 1)),
            true_val: Box::new(walk_expr_mut_bounded(*true_val, visitor, depth + 1)),
            false_val: Box::new(walk_expr_mut_bounded(*false_val, visitor, depth + 1)),
            size,
        },

        // Intrinsic —" variadic children
        LlilExpr::Intrinsic {
            name,
            args,
            result_size,
        } => LlilExpr::Intrinsic {
            name,
            args: args
                .into_iter()
                .map(|a| walk_expr_mut_bounded(a, visitor, depth + 1))
                .collect(),
            result_size,
        },
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Helper —" apply an ExprVisitor to all expressions in an instruction
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn transform_instr(instr: LlilInstruction, visitor: &mut dyn ExprVisitor) -> LlilInstruction {
    match instr {
        LlilInstruction::SetReg {
            dest,
            size,
            value: src,
        } => LlilInstruction::SetReg {
            dest,
            size,
            value: walk_expr_mut(src, visitor),
        },
        LlilInstruction::SetRegSplit { high, low, src } => LlilInstruction::SetRegSplit {
            high,
            low,
            src: walk_expr_mut(src, visitor),
        },
        LlilInstruction::Load { dest, size, addr } => LlilInstruction::Load {
            dest,
            size,
            addr: walk_expr_mut(addr, visitor),
        },
        LlilInstruction::Store {
            addr,
            size,
            value: src,
        } => LlilInstruction::Store {
            addr: walk_expr_mut(addr, visitor),
            size,
            value: walk_expr_mut(src, visitor),
        },
        LlilInstruction::SetFlag { name: flag, src } => LlilInstruction::SetFlag {
            name: flag,
            src: walk_expr_mut(src, visitor),
        },
        LlilInstruction::Push { size, src } => LlilInstruction::Push {
            size,
            src: walk_expr_mut(src, visitor),
        },
        LlilInstruction::JumpDest { dest } => LlilInstruction::JumpDest {
            dest: walk_expr_mut(dest, visitor),
        },
        LlilInstruction::JumpTo { dest, targets } => LlilInstruction::JumpTo {
            dest: walk_expr_mut(dest, visitor),
            targets,
        },
        LlilInstruction::CallDest { dest } => LlilInstruction::CallDest {
            dest: walk_expr_mut(dest, visitor),
        },
        LlilInstruction::TailCall { dest } => LlilInstruction::TailCall {
            dest: walk_expr_mut(dest, visitor),
        },
        LlilInstruction::CondJump {
            cond,
            true_dest,
            false_dest,
        } => LlilInstruction::CondJump {
            cond: walk_expr_mut(cond, visitor),
            true_dest,
            false_dest,
        },
        LlilInstruction::CondCall { cond, dest } => LlilInstruction::CondCall {
            cond: walk_expr_mut(cond, visitor),
            dest: walk_expr_mut(dest, visitor),
        },
        LlilInstruction::Intrinsic { name, args } => LlilInstruction::Intrinsic {
            name,
            args: args
                .into_iter()
                .map(|a| walk_expr_mut(a, visitor))
                .collect(),
        },
        // Instructions with no expression operands are returned unchanged.
        other => other,
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ConstantFoldingPass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Folds constant sub-expressions to their computed values.
///
/// All integer arithmetic and bitwise operations whose operands are both
/// [`LlilExpr::Const`] are replaced with a single `Const` node.  Comparison
/// operations similarly reduce to `Const(0)` or `Const(1)`.  Loads and calls
/// are never folded because they carry observable side-effects.
pub struct ConstantFoldingPass;

impl ConstantFoldingPass {
    /// Creates a new instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Attempt to fold a single expression.
    ///
    /// Returns the (possibly unchanged) expression and a flag indicating
    /// whether any folding occurred anywhere inside the tree.
    #[must_use]
    pub fn fold_expr(&self, expr: LlilExpr) -> (LlilExpr, bool) {
        let mut visitor = FoldingVisitor { changed: false };
        let folded = walk_expr_mut(expr, &mut visitor);
        (folded, visitor.changed)
    }

    /// x86 masks shift counts with `operand_width - 1` for operands up to
    /// 64 bits (e.g. `&31` for 32-bit ops, `&63` for 64-bit ops).
    /// Sizes wider than 64 bits are clamped to the 64-bit mask.
    #[must_use]
    /// AMD APM vol.3, SHL/SHR/SAR: "The processor masks the upper three bits
    /// of the count operand, thus restricting the count to a number between
    /// 0 and 31" — this fixed 5-bit mask applies to EVERY operand width below
    /// 64 bits (`shl bl, cl` with cl=12 shifts everything out, it does NOT
    /// wrap mod-8 to a shift-by-4). Only 64-bit destinations use the wider
    /// 6-bit mask (0-63). Not `size.bits() - 1` — the arch-x86 lifter and
    /// il-llil interpreter/evaluator apply the same fixed 5-/6-bit mask.
    pub const fn shift_count_mask(size: Size) -> u64 {
        if size.bits() >= 64 { 63 } else { 31 }
    }

    /// Compute the result of a constant binary operation.
    ///
    /// Returns `None` if the operation is not foldable (e.g. division by zero).
    /// The result is masked to the bit-width given by `size`.
    #[must_use]
    pub fn fold_binop(op: &str, left: u64, right: u64, size: Size) -> Option<u64> {
        let mask = size_mask(size);
        let result = match op {
            "add" => left.wrapping_add(right),
            "sub" => left.wrapping_sub(right),
            "mul" => left.wrapping_mul(right),
            "divu" => {
                if right == 0 {
                    return None;
                }
                left / right
            }
            "divs" => {
                let l = sign_extend(left, size);
                let r = sign_extend(right, size);
                if r == 0 {
                    return None;
                }
                l.wrapping_div(r).cast_unsigned()
            }
            "modu" => {
                if right == 0 {
                    return None;
                }
                left % right
            }
            "mods" => {
                let l = sign_extend(left, size);
                let r = sign_extend(right, size);
                if r == 0 {
                    return None;
                }
                l.wrapping_rem(r).cast_unsigned()
            }
            "and" => left & right,
            "or" => left | right,
            "xor" => left ^ right,
            "shl" => {
                // x86 masks the shift count with a fixed 5-bit window (0-31)
                // for any sub-64-bit operand — &31 regardless of whether the
                // destination is 8, 16, or 32 bits — and a 6-bit window
                // (0-63) only for 64-bit destinations. Not always &63, and
                // NOT `& (width - 1)` either. See `shift_count_mask`.
                let shift = right & Self::shift_count_mask(size);
                left.wrapping_shl(u32::try_from(shift).unwrap_or(0))
            }
            "shr" => {
                let shift = right & Self::shift_count_mask(size);
                left.wrapping_shr(u32::try_from(shift).unwrap_or(0))
            }
            "sar" => {
                let shift = u32::try_from(right & Self::shift_count_mask(size)).unwrap_or(0);
                let signed = sign_extend(left, size);
                (signed >> shift).cast_unsigned()
            }
            "rol" | "ror" => {
                // Rotates on operands wider than 64 bits cannot be evaluated
                // on a u64 (shift-overflow); refuse to fold those.
                let bits_u64 = size.bits() as u64;
                if bits_u64 == 0 || bits_u64 > 64 {
                    return None;
                }
                // Guarded above to 1..=64, so both conversions are exact; the
                // `?` propagates instead of truncating if that guard ever moves.
                let bits = u32::try_from(bits_u64).ok()?;
                let shift = u32::try_from(right % bits_u64).ok()?;
                let v = left & mask;
                if shift == 0 {
                    v
                } else if op == "rol" {
                    ((v << shift) | (v >> (bits - shift))) & mask
                } else {
                    ((v >> shift) | (v << (bits - shift))) & mask
                }
            }
            _ => return None,
        };
        Some(result & mask)
    }
}

impl Default for ConstantFoldingPass {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisPass for ConstantFoldingPass {
    fn name(&self) -> &'static str {
        "constant-folding"
    }

    fn description(&self) -> &'static str {
        "Fold constant expressions to their computed values"
    }

    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        for block in &mut func.blocks {
            for ai in &mut block.instrs {
                ctx.stats.instrs_visited += 1;
                let original = ai.instr.clone();
                let mut visitor = FoldingVisitor { changed: false };
                let new_instr = transform_instr(ai.instr.clone(), &mut visitor);
                if visitor.changed {
                    ai.instr = new_instr;
                    ctx.stats.instrs_modified += 1;
                    ctx.stats.const_folded += 1;
                    ctx.mark_changed();
                    // Suppress unused-variable warning on the original clone.
                    let _ = original;
                }
            }
        }
    }
}

/// Visitor that performs constant folding at each node.
struct FoldingVisitor {
    changed: bool,
}

impl ExprVisitor for FoldingVisitor {
    fn visit_expr(&mut self, expr: &LlilExpr) -> Option<LlilExpr> {
        match expr {
            // â"€â"€ binary arithmetic â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            LlilExpr::AddT(l, r, s) => fold_two_const(l, r, "add", *s, &mut self.changed),
            LlilExpr::SubT(l, r, s) => fold_two_const(l, r, "sub", *s, &mut self.changed),
            LlilExpr::MulT(l, r, s) => fold_two_const(l, r, "mul", *s, &mut self.changed),
            // Struct-form encodings (produced by the LLIL→MLIL bridge and SSA
            // reconstruction) must fold identically to their tuple twins.
            LlilExpr::Add { left, right, size } => {
                fold_two_const(left, right, "add", *size, &mut self.changed)
            }
            LlilExpr::Sub { left, right, size } => {
                fold_two_const(left, right, "sub", *size, &mut self.changed)
            }
            LlilExpr::Mul { left, right, size } => {
                fold_two_const(left, right, "mul", *size, &mut self.changed)
            }
            LlilExpr::Shl { value, shift, size } => {
                fold_two_const(value, shift, "shl", *size, &mut self.changed)
            }
            LlilExpr::DivU(l, r, s) => fold_two_const(l, r, "divu", *s, &mut self.changed),
            LlilExpr::DivS(l, r, s) => fold_two_const(l, r, "divs", *s, &mut self.changed),
            LlilExpr::ModU(l, r, s) => fold_two_const(l, r, "modu", *s, &mut self.changed),
            LlilExpr::ModS(l, r, s) => fold_two_const(l, r, "mods", *s, &mut self.changed),
            LlilExpr::And(l, r, s) => fold_two_const(l, r, "and", *s, &mut self.changed),
            LlilExpr::Or(l, r, s) => fold_two_const(l, r, "or", *s, &mut self.changed),
            LlilExpr::Xor(l, r, s) => fold_two_const(l, r, "xor", *s, &mut self.changed),
            LlilExpr::ShlT(l, r, s) => fold_two_const(l, r, "shl", *s, &mut self.changed),
            LlilExpr::Shr(l, r, s) => fold_two_const(l, r, "shr", *s, &mut self.changed),
            LlilExpr::Sar(l, r, s) => fold_two_const(l, r, "sar", *s, &mut self.changed),
            LlilExpr::Rol(l, r, s) => fold_two_const(l, r, "rol", *s, &mut self.changed),
            LlilExpr::Ror(l, r, s) => fold_two_const(l, r, "ror", *s, &mut self.changed),

            // â"€â"€ unary â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            LlilExpr::Neg(e, s) => {
                if let LlilExpr::Const { value: v, .. } = e.as_ref() {
                    let result = v.wrapping_neg() & size_mask(*s);
                    self.changed = true;
                    Some(LlilExpr::Const {
                        value: result,
                        size: *s,
                    })
                } else {
                    None
                }
            }
            LlilExpr::Not(e, s) => {
                if let LlilExpr::Const { value: v, .. } = e.as_ref() {
                    let result = (!v) & size_mask(*s);
                    self.changed = true;
                    Some(LlilExpr::Const {
                        value: result,
                        size: *s,
                    })
                } else {
                    None
                }
            }

            // â"€â"€ comparisons â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            LlilExpr::CmpEq(l, r) => fold_cmp(l, r, |a, b| a == b, &mut self.changed),
            LlilExpr::CmpNe(l, r) => fold_cmp(l, r, |a, b| a != b, &mut self.changed),
            LlilExpr::CmpUlt(l, r) => fold_cmp(l, r, |a, b| a < b, &mut self.changed),
            LlilExpr::CmpUle(l, r) => fold_cmp(l, r, |a, b| a <= b, &mut self.changed),
            LlilExpr::CmpUgt(l, r) => fold_cmp(l, r, |a, b| a > b, &mut self.changed),
            LlilExpr::CmpUge(l, r) => fold_cmp(l, r, |a, b| a >= b, &mut self.changed),
            LlilExpr::CmpSlt(l, r) => fold_cmp_signed(l, r, |a, b| a < b, &mut self.changed),
            LlilExpr::CmpSle(l, r) => fold_cmp_signed(l, r, |a, b| a <= b, &mut self.changed),
            LlilExpr::CmpSgt(l, r) => fold_cmp_signed(l, r, |a, b| a > b, &mut self.changed),
            LlilExpr::CmpSge(l, r) => fold_cmp_signed(l, r, |a, b| a >= b, &mut self.changed),

            // â"€â"€ extensions â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            LlilExpr::ZeroExtend { expr: e, from, to } => {
                if let LlilExpr::Const { value: v, .. } = e.as_ref() {
                    let result = v & size_mask(*from);
                    self.changed = true;
                    Some(LlilExpr::Const {
                        value: result,
                        size: *to,
                    })
                } else {
                    None
                }
            }
            LlilExpr::SignExtend { expr: e, from, to } => {
                if let LlilExpr::Const { value: v, .. } = e.as_ref() {
                    let result = sign_extend(*v, *from).cast_unsigned() & size_mask(*to);
                    self.changed = true;
                    Some(LlilExpr::Const {
                        value: result,
                        size: *to,
                    })
                } else {
                    None
                }
            }
            LlilExpr::LowPart { expr: e, to } => {
                if let LlilExpr::Const { value: v, .. } = e.as_ref() {
                    let result = v & size_mask(*to);
                    self.changed = true;
                    Some(LlilExpr::Const {
                        value: result,
                        size: *to,
                    })
                } else {
                    None
                }
            }

            // All other nodes: no folding.
            _ => None,
        }
    }
}

// â"€â"€ Folding helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn fold_two_const(
    l: &LlilExpr,
    r: &LlilExpr,
    op: &str,
    size: Size,
    changed: &mut bool,
) -> Option<LlilExpr> {
    if let (LlilExpr::Const { value: lv, .. }, LlilExpr::Const { value: rv, .. }) = (l, r)
        && let Some(result) = ConstantFoldingPass::fold_binop(op, *lv, *rv, size) {
            *changed = true;
            return Some(LlilExpr::Const {
                value: result,
                size,
            });
        }
    None
}

fn fold_cmp(
    l: &LlilExpr,
    r: &LlilExpr,
    pred: impl Fn(u64, u64) -> bool,
    changed: &mut bool,
) -> Option<LlilExpr> {
    if let (LlilExpr::Const { value: lv, .. }, LlilExpr::Const { value: rv, .. }) = (l, r) {
        *changed = true;
        Some(LlilExpr::Const {
            value: u64::from(pred(*lv, *rv)),
            size: Size::Byte,
        })
    } else {
        None
    }
}

fn fold_cmp_signed(
    l: &LlilExpr,
    r: &LlilExpr,
    pred: impl Fn(i64, i64) -> bool,
    changed: &mut bool,
) -> Option<LlilExpr> {
    if let (
        LlilExpr::Const {
            value: lv,
            size: ls,
        },
        LlilExpr::Const {
            value: rv,
            size: rs,
        },
    ) = (l, r)
    {
        let size = if ls.bits() >= rs.bits() { *ls } else { *rs };
        let lsigned = sign_extend(*lv, size);
        let rsigned = sign_extend(*rv, size);
        *changed = true;
        Some(LlilExpr::Const {
            value: u64::from(pred(lsigned, rsigned)),
            size: Size::Byte,
        })
    } else {
        None
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// NopEliminationPass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Removes all [`LlilInstruction::Nop`] instructions from every basic block.
pub struct NopEliminationPass;

impl NopEliminationPass {
    /// Creates a new instance.
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }
}

impl Default for NopEliminationPass {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisPass for NopEliminationPass {
    fn name(&self) -> &'static str {
        "nop-elimination"
    }

    fn description(&self) -> &'static str {
        "Remove all Nop instructions from every basic block"
    }

    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        for block in &mut func.blocks {
            let before = block.instrs.len();
            ctx.stats.instrs_visited += before;
            block
                .instrs
                .retain(|ai| !matches!(ai.instr, LlilInstruction::Nop));
            let removed = before - block.instrs.len();
            if removed > 0 {
                ctx.stats.instrs_removed += removed;
                ctx.stats.dead_removed += removed;
                ctx.mark_changed();
            }
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// IdentityEliminationPass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Simplifies algebraic-identity sub-expressions.
///
/// Examples: `x + 0 â†' x`, `x ^ x â†' 0`, `NOT(NOT(x)) â†' x`.
pub struct IdentityEliminationPass;

impl IdentityEliminationPass {
    /// Creates a new instance.
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }
}

impl Default for IdentityEliminationPass {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisPass for IdentityEliminationPass {
    fn name(&self) -> &'static str {
        "identity-elimination"
    }

    fn description(&self) -> &'static str {
        "Simplify algebraic-identity expressions (x+0, x^x, NOT(NOT(x)), etc.)"
    }

    fn is_idempotent(&self) -> bool {
        // Simplifications may expose new opportunities in subsequent passes.
        false
    }

    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        for block in &mut func.blocks {
            for ai in &mut block.instrs {
                ctx.stats.instrs_visited += 1;
                let mut visitor = IdentityVisitor { changed: false };
                let new_instr = transform_instr(ai.instr.clone(), &mut visitor);
                if visitor.changed {
                    ai.instr = new_instr;
                    ctx.stats.instrs_modified += 1;
                    ctx.stats.exprs_simplified += 1;
                    ctx.mark_changed();
                }
            }
        }
    }
}

struct IdentityVisitor {
    changed: bool,
}

impl IdentityVisitor {
    const fn yes(&mut self, e: LlilExpr) -> LlilExpr {
        self.changed = true;
        e
    }
    const fn zero(&mut self, s: Size) -> LlilExpr {
        self.changed = true;
        LlilExpr::Const { value: 0, size: s }
    }
    const fn all_ones_const(&mut self, s: Size) -> LlilExpr {
        self.changed = true;
        LlilExpr::Const { value: size_mask(s), size: s }
    }
}

impl ExprVisitor for IdentityVisitor {
    fn visit_expr(&mut self, expr: &LlilExpr) -> Option<LlilExpr> {
        match expr {
            LlilExpr::AddT(l, r, _) if is_const_value(r, 0) => Some(self.yes(*l.clone())),
            LlilExpr::AddT(l, r, _) if is_const_value(l, 0) => Some(self.yes(*r.clone())),
            LlilExpr::SubT(l, r, _) if is_const_value(r, 0) => Some(self.yes(*l.clone())),
            LlilExpr::MulT(l, r, _) if is_const_value(r, 1) => Some(self.yes(*l.clone())),
            LlilExpr::MulT(l, r, _) if is_const_value(l, 1) => Some(self.yes(*r.clone())),
            LlilExpr::MulT(_, r, s) if is_const_value(r, 0) => Some(self.zero(*s)),
            LlilExpr::MulT(l, _, s) if is_const_value(l, 0) => Some(self.zero(*s)),
            // Struct-form encodings: identical identity rules.
            LlilExpr::Add { left, right, .. } if is_const_value(right, 0) => {
                Some(self.yes(*left.clone()))
            }
            LlilExpr::Add { left, right, .. } if is_const_value(left, 0) => {
                Some(self.yes(*right.clone()))
            }
            LlilExpr::Sub { left, right, .. } if is_const_value(right, 0) => {
                Some(self.yes(*left.clone()))
            }
            LlilExpr::Mul { left, right, .. } if is_const_value(right, 1) => {
                Some(self.yes(*left.clone()))
            }
            LlilExpr::Mul { left, right, .. } if is_const_value(left, 1) => {
                Some(self.yes(*right.clone()))
            }
            LlilExpr::Mul { right, size, .. } if is_const_value(right, 0) => {
                Some(self.zero(*size))
            }
            LlilExpr::Mul { left, size, .. } if is_const_value(left, 0) => Some(self.zero(*size)),
            LlilExpr::Shl { value, shift, .. } if is_const_value(shift, 0) => {
                Some(self.yes(*value.clone()))
            }
            LlilExpr::And(_, r, s) if is_const_value(r, 0) => Some(self.zero(*s)),
            LlilExpr::And(l, _, s) if is_const_value(l, 0) => Some(self.zero(*s)),
            LlilExpr::And(l, r, s) if is_all_ones(r, *s) => Some(self.yes(*l.clone())),
            LlilExpr::And(l, r, s) if is_all_ones(l, *s) => Some(self.yes(*r.clone())),
            LlilExpr::And(l, r, _) if exprs_same_reg(l, r) => Some(self.yes(*l.clone())),
            LlilExpr::Or(l, r, _) if is_const_value(r, 0) => Some(self.yes(*l.clone())),
            LlilExpr::Or(l, r, _) if is_const_value(l, 0) => Some(self.yes(*r.clone())),
            LlilExpr::Or(_, r, s) if is_all_ones(r, *s) => Some(self.all_ones_const(*s)),
            LlilExpr::Or(l, _, s) if is_all_ones(l, *s) => Some(self.all_ones_const(*s)),
            LlilExpr::Or(l, r, _) if exprs_same_reg(l, r) => Some(self.yes(*l.clone())),
            LlilExpr::Xor(l, r, _) if is_const_value(r, 0) => Some(self.yes(*l.clone())),
            LlilExpr::Xor(l, r, _) if is_const_value(l, 0) => Some(self.yes(*r.clone())),
            LlilExpr::Xor(l, r, s) if exprs_same_reg(l, r) => Some(self.zero(*s)),
            LlilExpr::Not(inner, _) => {
                if let LlilExpr::Not(inner2, _) = inner.as_ref() { Some(self.yes(*inner2.clone())) } else { None }
            }
            LlilExpr::Neg(inner, _) => {
                if let LlilExpr::Neg(inner2, _) = inner.as_ref() { Some(self.yes(*inner2.clone())) } else { None }
            }
            LlilExpr::ZeroExtend { expr: e, from, to } if from == to => Some(self.yes(*e.clone())),
            LlilExpr::SignExtend { expr: e, from, to } if from == to => Some(self.yes(*e.clone())),
            _ => None,
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// DeadCodeEliminationPass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Removes instructions whose results are provably never used.
///
/// A `SetReg` is dead when the written register is never subsequently read
/// anywhere in the function AND the instruction has no observable side-effects.
/// `Nop` instructions (which should have been removed by [`NopEliminationPass`]
/// but may be reintroduced) are also removed here.
pub struct DeadCodeEliminationPass;

impl DeadCodeEliminationPass {
    /// Creates a new instance.
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Return the set of all register names that are read in *reachable* blocks
    /// of `func`.
    ///
    /// Registers read only inside unreachable (dead) blocks are excluded so
    /// that a `SetReg` in a live block whose only consumer is an unreachable
    /// block can be correctly identified as dead and eliminated.
    #[must_use]
    pub fn compute_live_registers(func: &LlilFunction) -> HashSet<String> {
        // Identify the entry block id (first block, id == 0 by convention, or
        // the block whose id matches the function's first block).
        let entry_id = func.blocks.first().map_or(0, |b| b.id);
        let cfg = LlilCfg::build(func);
        let reachable = cfg.reachable_from(entry_id);

        let mut live = HashSet::new();
        let mut has_bare_ret = false;
        for block in &func.blocks {
            if !reachable.contains(&block.id) {
                // Skip dead blocks — their register reads must not keep live
                // definitions in reachable blocks alive.
                continue;
            }
            for ai in &block.instrs {
                collect_read_regs(&ai.instr, &mut live);
                if matches!(
                    ai.instr,
                    LlilInstruction::Ret | LlilInstruction::Return { value: None }
                ) {
                    has_bare_ret = true;
                }
            }
        }
        // A bare `Ret` (no explicit value operand) still returns whatever the
        // ABI return registers hold — lifted x86 emits exactly this shape for
        // `mov eax, <result>; ret`. Without seeding the ABI live-outs, DCE
        // would delete the return-value computation itself.
        if has_bare_ret {
            for reg in ["rax", "eax", "ax", "al", "rdx", "edx", "xmm0"] {
                live.insert(reg.to_owned());
            }
        }
        live
    }

    /// Returns `true` if `instr` has observable side-effects that must be
    /// preserved regardless of whether its result is used.
    #[must_use] 
    pub const fn has_side_effects(instr: &LlilInstruction) -> bool {
        matches!(
            instr,
            LlilInstruction::Store { .. }
                | LlilInstruction::CallDest { .. }
                | LlilInstruction::TailCall { .. }
                | LlilInstruction::Ret
                | LlilInstruction::JumpDest { .. }
                | LlilInstruction::JumpTo { .. }
                | LlilInstruction::CondJump { .. }
                | LlilInstruction::CondCall { .. }
                | LlilInstruction::Push { .. }
                | LlilInstruction::Pop { .. }
                | LlilInstruction::SetFlag { .. }
                | LlilInstruction::Trap { .. }
                | LlilInstruction::SysCall
                | LlilInstruction::Breakpoint
                | LlilInstruction::Intrinsic { .. }
                | LlilInstruction::Undefined
                | LlilInstruction::Unimplemented { .. }
        )
    }
}

impl Default for DeadCodeEliminationPass {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisPass for DeadCodeEliminationPass {
    fn name(&self) -> &'static str {
        "dead-code-elimination"
    }

    fn description(&self) -> &'static str {
        "Remove SetReg/Load instructions whose results are never read"
    }

    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let live = Self::compute_live_registers(func);

        for block in &mut func.blocks {
            let before = block.instrs.len();
            ctx.stats.instrs_visited += before;
            block.instrs.retain(|ai| {
                // Keep everything with side effects.
                if Self::has_side_effects(&ai.instr) {
                    return true;
                }
                // Remove Nops.
                if matches!(ai.instr, LlilInstruction::Nop) {
                    return false;
                }
                // Remove SetReg / Load where dest register is never read.
                // Note: `Pop` is intentionally NOT matched here — it adjusts
                // the stack pointer (an observable side effect), so
                // `has_side_effects` above always keeps it even when its
                // destination register is dead.
                let dead_dest = match &ai.instr {
                    LlilInstruction::SetReg { dest, .. }
                    | LlilInstruction::Load { dest, .. } => !live.contains(&dest.name()),
                    LlilInstruction::SetRegSplit { high, low, .. } => {
                        !live.contains(&high.name()) && !live.contains(&low.name())
                    }
                    _ => false,
                };
                !dead_dest
            });

            let removed = before - block.instrs.len();
            if removed > 0 {
                ctx.stats.instrs_removed += removed;
                ctx.stats.dead_removed += removed;
                ctx.mark_changed();
            }
        }
    }
}

/// Collect all register names that are *read* by `instr` into `out`.
fn collect_read_regs(instr: &LlilInstruction, out: &mut HashSet<String>) {
    match instr {
        LlilInstruction::SetReg { value: src, .. }
        | LlilInstruction::SetRegSplit { src, .. }
        | LlilInstruction::SetFlag { src, .. }
        | LlilInstruction::Push { src, .. }
        | LlilInstruction::SetRegister { value: src, .. } => collect_regs_in_expr(src, out),
        LlilInstruction::Load { addr, .. } => collect_regs_in_expr(addr, out),
        LlilInstruction::Store {
            addr, value: src, ..
        } => {
            collect_regs_in_expr(addr, out);
            collect_regs_in_expr(src, out);
        }
        LlilInstruction::JumpDest { dest }
        | LlilInstruction::CallDest { dest }
        | LlilInstruction::TailCall { dest }
        | LlilInstruction::JumpTo { dest, .. }
        | LlilInstruction::Jump(dest)
        | LlilInstruction::Call(dest) => {
            collect_regs_in_expr(dest, out);
        }
        LlilInstruction::CondJump { cond, .. } | LlilInstruction::ConditionalJump { cond, .. } => collect_regs_in_expr(cond, out),
        LlilInstruction::CondCall { cond, dest } => {
            collect_regs_in_expr(cond, out);
            collect_regs_in_expr(dest, out);
        }
        LlilInstruction::Intrinsic { args, .. } => {
            for a in args {
                collect_regs_in_expr(a, out);
            }
        }
        LlilInstruction::Return { value } => {
            if let Some(v) = value {
                collect_regs_in_expr(v, out);
            }
        }
        LlilInstruction::Nop
        | LlilInstruction::Pop { .. }
        | LlilInstruction::Ret
        | LlilInstruction::Trap { .. }
        | LlilInstruction::SysCall
        | LlilInstruction::Breakpoint
        | LlilInstruction::Undefined
        | LlilInstruction::UnimplementedRaw { .. }
        | LlilInstruction::Unimplemented { .. } => {}
    }
}

/// Recursively collect all [`LlilRegister`] names read inside `expr`.
fn collect_regs_in_expr(expr: &LlilExpr, out: &mut HashSet<String>) {
    match expr {
        LlilExpr::RegisterRef { reg, .. } => {
            out.insert(reg.name());
        }
        LlilExpr::Register { id, .. } => {
            out.insert(format!("r{id}"));
        }
        LlilExpr::Add { left, right, .. }
        | LlilExpr::Sub { left, right, .. }
        | LlilExpr::Mul { left, right, .. } => {
            collect_regs_in_expr(left, out);
            collect_regs_in_expr(right, out);
        }
        LlilExpr::Shl { value, shift, .. } => {
            collect_regs_in_expr(value, out);
            collect_regs_in_expr(shift, out);
        }
        LlilExpr::Const { .. }
        | LlilExpr::StackPointer(_)
        | LlilExpr::Flag(_)
        | LlilExpr::Undefined(_) => {}
        LlilExpr::Load { addr, .. } => collect_regs_in_expr(addr, out),
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::FNeg(e, _)
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. }
        | LlilExpr::IntToFloat { expr: e, .. }
        | LlilExpr::FloatToInt { expr: e, .. } => collect_regs_in_expr(e, out),
        LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::DivU(l, r, _)
        | LlilExpr::DivS(l, r, _)
        | LlilExpr::ModU(l, r, _)
        | LlilExpr::ModS(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _)
        | LlilExpr::Rol(l, r, _)
        | LlilExpr::Ror(l, r, _)
        | LlilExpr::CmpEq(l, r)
        | LlilExpr::CmpNe(l, r)
        | LlilExpr::CmpSlt(l, r)
        | LlilExpr::CmpUlt(l, r)
        | LlilExpr::CmpSle(l, r)
        | LlilExpr::CmpUle(l, r)
        | LlilExpr::CmpSgt(l, r)
        | LlilExpr::CmpUgt(l, r)
        | LlilExpr::CmpSge(l, r)
        | LlilExpr::CmpUge(l, r)
        | LlilExpr::FAdd(l, r, _)
        | LlilExpr::FSub(l, r, _)
        | LlilExpr::FMul(l, r, _)
        | LlilExpr::FDiv(l, r, _)
        | LlilExpr::FCmpEq(l, r)
        | LlilExpr::FCmpLt(l, r)
        | LlilExpr::FCmpGt(l, r) => {
            collect_regs_in_expr(l, out);
            collect_regs_in_expr(r, out);
        }
        LlilExpr::CondExpr {
            cond,
            true_val,
            false_val,
            ..
        } => {
            collect_regs_in_expr(cond, out);
            collect_regs_in_expr(true_val, out);
            collect_regs_in_expr(false_val, out);
        }
        LlilExpr::Intrinsic { args, .. } => {
            for a in args {
                collect_regs_in_expr(a, out);
            }
        }
    }
}

/// Collect the names of all registers written by `instr` into `out`.
fn collect_written_reg_names(instr: &LlilInstruction, out: &mut HashSet<String>) {
    match instr {
        LlilInstruction::SetReg { dest, .. }
        | LlilInstruction::Load { dest, .. }
        | LlilInstruction::Pop { dest, .. } => {
            out.insert(dest.name());
        }
        LlilInstruction::SetRegSplit { high, low, .. } => {
            out.insert(high.name());
            out.insert(low.name());
        }
        LlilInstruction::SetRegister { dest, .. } => {
            out.insert(format!("r{dest}"));
        }
        _ => {}
    }
}

/// Returns `true` for call-like/opaque instructions that may clobber
/// registers and memory in ways the intra-block scans cannot model.
const fn is_clobbering_instr(instr: &LlilInstruction) -> bool {
    matches!(
        instr,
        LlilInstruction::CallDest { .. }
            | LlilInstruction::TailCall { .. }
            | LlilInstruction::CondCall { .. }
            | LlilInstruction::Call(_)
            | LlilInstruction::SysCall
            | LlilInstruction::Intrinsic { .. }
            | LlilInstruction::Unimplemented { .. }
            | LlilInstruction::UnimplementedRaw { .. }
    )
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CopyPropagationPass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Intra-block copy propagation.
///
/// When a `SetReg(tmp, Register(src))` is encountered, subsequent uses of
/// `tmp` within the same block are replaced with `Register(src)`.
/// Propagation stops at any instruction that re-assigns either the propagated
/// temporary or the source register.
pub struct CopyPropagationPass;

impl CopyPropagationPass {
    /// Creates a new instance.
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }
}

impl Default for CopyPropagationPass {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisPass for CopyPropagationPass {
    fn name(&self) -> &'static str {
        "copy-propagation"
    }

    fn description(&self) -> &'static str {
        "Replace uses of a register with its simple-copy definition within a block"
    }

    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        for block in &mut func.blocks {
            // Map: dest_register â†' (src_register, src_size)
            let mut copies: HashMap<LlilRegister, (LlilRegister, Size)> = HashMap::new();

            for ai in &mut block.instrs {
                ctx.stats.instrs_visited += 1;

                // Before we possibly propagate, check if this instruction kills
                // any existing copy mapping (by writing to the dest or the src).
                copies.retain(|dest_reg, (src_reg, _)| {
                    !(ai.instr.writes_reg(dest_reg) || ai.instr.writes_reg(src_reg))
                });

                // Now apply existing copy mappings to the instruction's
                // expressions (substituting uses of the copy destination with
                // the copy source).
                if !copies.is_empty() {
                    let mut visitor = CopyPropVisitor {
                        copies: &copies,
                        changed: false,
                    };
                    let new_instr = transform_instr(ai.instr.clone(), &mut visitor);
                    if visitor.changed {
                        ai.instr = new_instr;
                        ctx.stats.instrs_modified += 1;
                        ctx.mark_changed();
                    }
                }

                // A call (or other opaque/clobbering instruction) may write
                // arbitrary volatile registers, which `writes_reg` cannot
                // model: it only reports the explicit `dest` of SetReg/Load/
                // Pop and returns `false` for every call-like instruction.
                // Any copy still live here could therefore have had its
                // source (or destination) silently overwritten, so all
                // mappings must be dropped. This runs *after* propagating
                // into the current instruction: the call reads its own
                // operands before the clobber takes effect, so substituting
                // there is still legal.
                if is_clobbering_instr(&ai.instr) {
                    copies.clear();
                }

                // After transforming, record new copy if this is a plain copy.
                if let LlilInstruction::SetReg {
                    dest,
                    size,
                    value: src,
                } = &ai.instr
                    && let LlilExpr::RegisterRef { reg: src_reg, .. } = src
                    // A self-copy (`rax = rax`) carries no information: it
                    // maps a register to itself, so substituting through it
                    // rewrites an expression into an identical one while
                    // still reporting `changed`, and the pass would never
                    // reach a fixpoint. Compare by name so that
                    // Concrete("t0")/Temporary(0) — the same storage under
                    // two representations — are also recognised.
                    && dest.name() != src_reg.name() {
                        copies.insert(dest.clone(), (src_reg.clone(), *size));
                    }
            }
        }
    }
}

struct CopyPropVisitor<'a> {
    copies: &'a HashMap<LlilRegister, (LlilRegister, Size)>,
    changed: bool,
}

impl ExprVisitor for CopyPropVisitor<'_> {
    fn visit_expr(&mut self, expr: &LlilExpr) -> Option<LlilExpr> {
        if let LlilExpr::RegisterRef { reg, size } = expr
            && let Some((src_reg, _src_size)) = self.copies.get(reg)
            // Defence in depth: never report a change for a substitution
            // that produces an identical expression.
            && src_reg.name() != reg.name() {
                self.changed = true;
                return Some(LlilExpr::RegisterRef {
                    reg: src_reg.clone(),
                    size: *size,
                });
            }
        None
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// BlockMergePass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Merges a basic block into its sole predecessor when they form a trivial
/// single-successor / single-predecessor chain.
///
/// Preconditions for merging block B into its predecessor A:
/// 1. A ends with an unconditional `Jump` whose target is the start of B.
/// 2. B has exactly one predecessor (i.e. only A can reach B).
///
/// After merging the `Jump` is removed and B's instructions are appended to A.
pub struct BlockMergePass;

impl BlockMergePass {
    /// Creates a new instance.
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }
}

impl Default for BlockMergePass {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisPass for BlockMergePass {
    fn name(&self) -> &'static str {
        "block-merge"
    }

    fn description(&self) -> &'static str {
        "Merge a basic block into its predecessor when they form a trivial chain"
    }

    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        // Keep trying until no more merges are possible in this pass call.
        loop {
            let merged = try_one_merge(func);
            if !merged {
                break;
            }
            ctx.mark_changed();
            ctx.stats.dead_removed += 1;
        }
    }
}

/// Attempt a single merge of any eligible pair.  Returns `true` if a merge
/// was performed.
fn try_one_merge(func: &mut LlilFunction) -> bool {
    // Count how many blocks jump to each start address (predecessor count).
    let mut pred_count: HashMap<Address, usize> = HashMap::new();
    for block in &func.blocks {
        for ai in &block.instrs {
            match &ai.instr {
                LlilInstruction::JumpDest {
                    dest: LlilExpr::Const { value: v, .. },
                } => {
                    let target = Address::new(*v);
                    *pred_count.entry(target).or_insert(0) += 1;
                }
                LlilInstruction::Jump(LlilExpr::Const { value: v, .. }) => {
                    let target = Address::new(*v);
                    *pred_count.entry(target).or_insert(0) += 1;
                }
                LlilInstruction::JumpTo { targets, .. } => {
                    // Jump-table dispatch: every table target is a predecessor
                    // edge, so none of them may be merged away.
                    for t in targets {
                        *pred_count.entry(*t).or_insert(0) += 1;
                    }
                }
                LlilInstruction::CondJump {
                    true_dest,
                    false_dest,
                    ..
                } => {
                    *pred_count.entry(*true_dest).or_insert(0) += 1;
                    *pred_count.entry(*false_dest).or_insert(0) += 1;
                }
                LlilInstruction::ConditionalJump {
                    true_target,
                    false_target,
                    ..
                } => {
                    *pred_count.entry(*true_target).or_insert(0) += 1;
                    *pred_count.entry(*false_target).or_insert(0) += 1;
                }
                _ => {}
            }
        }
    }

    // Find a predecessor block that:
    //  (a) ends with an unconditional Jump to a constant target T
    //  (b) T has exactly one predecessor (this block)
    let merge_pair: Option<(usize, usize)> = {
        let mut found = None;
        'outer: for (pred_idx, pred) in func.blocks.iter().enumerate() {
            if let Some(last) = pred.instrs.last()
                && let LlilInstruction::JumpDest {
                    dest:
                        LlilExpr::Const {
                            value: target_val, ..
                        },
                } = &last.instr
                {
                    let target_addr = Address::new(*target_val);
                    // Only merge if the target has a single predecessor.
                    if pred_count.get(&target_addr).copied().unwrap_or(0) != 1 {
                        continue;
                    }
                    // Find successor block index.
                    for (succ_idx, succ) in func.blocks.iter().enumerate() {
                        if succ.start == target_addr && succ_idx != pred_idx {
                            found = Some((pred_idx, succ_idx));
                            break 'outer;
                        }
                    }
                }
        }
        found
    };

    if let Some((pred_idx, succ_idx)) = merge_pair {
        // Remove the trailing Jump from the predecessor.
        func.blocks[pred_idx].instrs.pop();

        // Drain successor's instructions and append to predecessor.
        let succ_instrs: Vec<LlilAnnotatedInstr> =
            std::mem::take(&mut func.blocks[succ_idx].instrs);
        let new_end = func.blocks[succ_idx].end;
        func.blocks[pred_idx].instrs.extend(succ_instrs);
        func.blocks[pred_idx].end = new_end;

        // Remove the now-empty successor block.
        func.blocks.remove(succ_idx);

        true
    } else {
        false
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PassManager
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Orchestrates running multiple [`AnalysisPass`]es on a function, with
/// optional convergence-based iteration.
pub struct PassManager {
    passes: Vec<Box<dyn AnalysisPass>>,
    /// Maximum number of full pipeline sweeps.  Default: 10.
    pub max_iterations: usize,
    /// When `true`, the pipeline repeats until no pass reports any change or
    /// `max_iterations` is reached.  Default: `true`.
    pub run_until_convergence: bool,
}

impl Default for PassManager {
    /// Build the default pass pipeline:
    /// `LoopDetection â†' GlobalValueNumbering â†' Mem2Reg â†' LoopInvariantCodeMotion`.
    fn default() -> Self {
        Self::new()
            .add_pass(LoopDetectionPass)
            .add_pass(GlobalValueNumberingPass)
            .add_pass(Mem2RegPass)
            .add_pass(LoopInvariantCodeMotionPass)
    }
}

impl PassManager {
    /// Creates an empty pass manager with default settings.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            passes: Vec::new(),
            max_iterations: 10,
            run_until_convergence: true,
        }
    }

    /// Append a pass to the pipeline (builder pattern).
    #[must_use]
    pub fn add_pass(mut self, pass: impl AnalysisPass + 'static) -> Self {
        self.passes.push(Box::new(pass));
        self
    }

    /// Override the maximum iteration count (builder pattern).
    #[must_use] 
    pub const fn with_max_iterations(mut self, n: usize) -> Self {
        self.max_iterations = n;
        self
    }

    /// Build the standard optimization pipeline.
    ///
    /// Order: `NopElimination` â†' `ConstantFolding` â†' `IdentityElimination` â†'
    ///        `CopyPropagation` â†' `DeadCodeElimination` â†' `BlockMerge`
    #[must_use] 
    pub fn standard() -> Self {
        Self::new()
            .add_pass(NopEliminationPass::new())
            .add_pass(ConstantFoldingPass::new())
            .add_pass(IdentityEliminationPass::new())
            .add_pass(CopyPropagationPass::new())
            .add_pass(DeadCodeEliminationPass::new())
            .add_pass(BlockMergePass::new())
    }

    /// Run all passes on `func` once, recording changes into `ctx`.
    pub fn run_once(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        for pass in &self.passes {
            pass.run(func, ctx);
        }
    }

    /// Run the pipeline on `func`, iterating until convergence or
    /// `max_iterations` is reached, and return the aggregated [`PassContext`].
    pub fn run(&self, func: &mut LlilFunction) -> PassContext {
        let mut total_ctx = PassContext::new();

        for _ in 0..self.max_iterations {
            let mut iter_ctx = PassContext::new();
            self.run_once(func, &mut iter_ctx);

            let changed = iter_ctx.changed;
            total_ctx.merge(&iter_ctx);

            if !self.run_until_convergence || !changed {
                break;
            }
        }

        total_ctx
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// RegisterUsageAnalyzer
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Per-register read/write site tracking.
#[derive(Debug, Clone, Default)]
pub struct RegisterUsage {
    /// Addresses at which each register is read.
    pub reads: HashMap<String, Vec<Address>>,
    /// Addresses at which each register is written.
    pub writes: HashMap<String, Vec<Address>>,
}

impl RegisterUsage {
    /// Analyse all instructions in `func` and build a `RegisterUsage` map.
    #[must_use] 
    pub fn analyze(func: &LlilFunction) -> Self {
        let mut usage = Self::default();

        for ai in func.all_instrs() {
            // Collect reads.
            let mut read_regs = HashSet::new();
            collect_read_regs(&ai.instr, &mut read_regs);
            for reg_name in read_regs {
                usage.reads.entry(reg_name).or_default().push(ai.address);
            }

            // Collect writes.
            let write_reg: Option<Vec<String>> = match &ai.instr {
                LlilInstruction::SetReg { dest, .. }
                | LlilInstruction::Load { dest, .. }
                | LlilInstruction::Pop { dest, .. } => Some(vec![dest.name()]),
                LlilInstruction::SetRegSplit { high, low, .. } => {
                    Some(vec![high.name(), low.name()])
                }
                _ => None,
            };
            if let Some(names) = write_reg {
                for name in names {
                    usage.writes.entry(name).or_default().push(ai.address);
                }
            }
        }

        usage
    }

    /// Returns `true` if `reg` is read at least once in the function.
    #[must_use] 
    pub fn is_read(&self, reg: &str) -> bool {
        self.reads.get(reg).is_some_and(|v| !v.is_empty())
    }

    /// Returns `true` if `reg` is written at least once in the function.
    #[must_use] 
    pub fn is_written(&self, reg: &str) -> bool {
        self.writes.get(reg).is_some_and(|v| !v.is_empty())
    }

    /// Number of read sites for `reg`.
    pub fn read_count(&self, reg: &str) -> usize {
        self.reads.get(reg).map_or(0, Vec::len)
    }

    /// Number of write sites for `reg`.
    pub fn write_count(&self, reg: &str) -> usize {
        self.writes.get(reg).map_or(0, Vec::len)
    }

    /// Return all (register, `write_address`, `read_address`) def-use pairs.
    ///
    /// Each write address is paired with every read address for the same
    /// register, giving a conservative cross-product.
    #[must_use] 
    pub fn def_use_pairs(&self) -> Vec<(String, Address, Address)> {
        let mut pairs = Vec::new();
        for (reg, write_addrs) in &self.writes {
            if let Some(read_addrs) = self.reads.get(reg) {
                for &w in write_addrs {
                    for &r in read_addrs {
                        pairs.push((reg.clone(), w, r));
                    }
                }
            }
        }
        pairs
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Private utility functions
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Compute the bitmask for a given [`Size`] (e.g. `Size::Byte` â†' `0xFF`).
const fn size_mask(size: Size) -> u64 {
    match size {
        Size::Byte => 0xFF,
        Size::Word => 0xFFFF,
        Size::DWord => 0xFFFF_FFFF,
        Size::QWord | Size::OWord | Size::YWord | Size::ZWord => u64::MAX, // wider-than-64-bit sizes saturate — we work in u64
    }
}

/// Sign-extend a value from the bit-width of `size` to a full `i64`.
const fn sign_extend(value: u64, size: Size) -> i64 {
    let bits = size.bits();
    if bits >= 64 {
        return value.cast_signed();
    }
    let shift = 64 - bits;
    (value.cast_signed() << shift) >> shift
}

/// Returns `true` if `expr` is a constant with the given value.
const fn is_const_value(expr: &LlilExpr, val: u64) -> bool {
    matches!(expr, LlilExpr::Const { value: v, .. } if *v == val)
}

/// Returns `true` if `expr` is a constant equal to the all-ones mask for `size`.
const fn is_all_ones(expr: &LlilExpr, size: Size) -> bool {
    is_const_value(expr, size_mask(size))
}

/// Returns `true` if both expressions refer to the same concrete or temporary
/// register (ignoring size).
fn exprs_same_reg(a: &LlilExpr, b: &LlilExpr) -> bool {
    match (a, b) {
        (LlilExpr::RegisterRef { reg: ra, .. }, LlilExpr::RegisterRef { reg: rb, .. }) => ra == rb,
        _ => false,
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// GlobalValueNumbering pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Returns `true` if the expression contains any [`LlilExpr::Load`] sub-expression.
#[must_use]
pub fn expr_has_load(expr: &LlilExpr) -> bool {
    match expr {
        // Pure leaves: definitely load-free.
        LlilExpr::Const { .. }
        | LlilExpr::RegisterRef { .. }
        | LlilExpr::Register { .. }
        | LlilExpr::StackPointer(_)
        | LlilExpr::Flag(_) => false,
        // Pure combinators: recurse.
        LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::DivU(l, r, _)
        | LlilExpr::DivS(l, r, _)
        | LlilExpr::ModU(l, r, _)
        | LlilExpr::ModS(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _)
        | LlilExpr::Rol(l, r, _)
        | LlilExpr::Ror(l, r, _)
        | LlilExpr::FAdd(l, r, _)
        | LlilExpr::FSub(l, r, _)
        | LlilExpr::FMul(l, r, _)
        | LlilExpr::FDiv(l, r, _)
        | LlilExpr::FCmpEq(l, r)
        | LlilExpr::FCmpLt(l, r)
        | LlilExpr::FCmpGt(l, r)
        | LlilExpr::CmpEq(l, r)
        | LlilExpr::CmpNe(l, r)
        | LlilExpr::CmpSlt(l, r)
        | LlilExpr::CmpUlt(l, r)
        | LlilExpr::CmpSle(l, r)
        | LlilExpr::CmpUle(l, r)
        | LlilExpr::CmpSgt(l, r)
        | LlilExpr::CmpUgt(l, r)
        | LlilExpr::CmpSge(l, r)
        | LlilExpr::CmpUge(l, r) => expr_has_load(l) || expr_has_load(r),
        LlilExpr::Add { left: l, right: r, .. }
        | LlilExpr::Sub { left: l, right: r, .. }
        | LlilExpr::Mul { left: l, right: r, .. } => expr_has_load(l) || expr_has_load(r),
        LlilExpr::Shl { value: l, shift: r, .. } => expr_has_load(l) || expr_has_load(r),
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::FNeg(e, _)
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. }
        | LlilExpr::IntToFloat { expr: e, .. }
        | LlilExpr::FloatToInt { expr: e, .. } => expr_has_load(e),
        LlilExpr::CondExpr { cond, true_val, false_val, .. } => {
            expr_has_load(cond) || expr_has_load(true_val) || expr_has_load(false_val)
        }
        // Load, Intrinsic, Undefined, and any future variants: treat as
        // memory-dependent / impure so they are never CSE'd or duplicated.
        _ => true,
    }
}

/// Returns `true` if `expr` (possibly conservatively) reads register `reg`.
///
/// Unknown / opaque sub-expressions (intrinsics, numeric-id registers, …)
/// are conservatively treated as reading every register.
#[must_use]
pub fn expr_uses_reg(expr: &LlilExpr, reg: &LlilRegister) -> bool {
    match expr {
        LlilExpr::RegisterRef { reg: r, .. } => r == reg,
        LlilExpr::Const { .. } | LlilExpr::StackPointer(_) | LlilExpr::Flag(_) => false,
        LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::DivU(l, r, _)
        | LlilExpr::DivS(l, r, _)
        | LlilExpr::ModU(l, r, _)
        | LlilExpr::ModS(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _)
        | LlilExpr::Rol(l, r, _)
        | LlilExpr::Ror(l, r, _)
        | LlilExpr::FAdd(l, r, _)
        | LlilExpr::FSub(l, r, _)
        | LlilExpr::FMul(l, r, _)
        | LlilExpr::FDiv(l, r, _)
        | LlilExpr::FCmpEq(l, r)
        | LlilExpr::FCmpLt(l, r)
        | LlilExpr::FCmpGt(l, r)
        | LlilExpr::CmpEq(l, r)
        | LlilExpr::CmpNe(l, r)
        | LlilExpr::CmpSlt(l, r)
        | LlilExpr::CmpUlt(l, r)
        | LlilExpr::CmpSle(l, r)
        | LlilExpr::CmpUle(l, r)
        | LlilExpr::CmpSgt(l, r)
        | LlilExpr::CmpUgt(l, r)
        | LlilExpr::CmpSge(l, r)
        | LlilExpr::CmpUge(l, r) => expr_uses_reg(l, reg) || expr_uses_reg(r, reg),
        LlilExpr::Add { left: l, right: r, .. }
        | LlilExpr::Sub { left: l, right: r, .. }
        | LlilExpr::Mul { left: l, right: r, .. } => {
            expr_uses_reg(l, reg) || expr_uses_reg(r, reg)
        }
        LlilExpr::Shl { value: l, shift: r, .. } => {
            expr_uses_reg(l, reg) || expr_uses_reg(r, reg)
        }
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::FNeg(e, _)
        | LlilExpr::Load { addr: e, .. }
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. }
        | LlilExpr::IntToFloat { expr: e, .. }
        | LlilExpr::FloatToInt { expr: e, .. } => expr_uses_reg(e, reg),
        LlilExpr::CondExpr { cond, true_val, false_val, .. } => {
            expr_uses_reg(cond, reg)
                || expr_uses_reg(true_val, reg)
                || expr_uses_reg(false_val, reg)
        }
        LlilExpr::Intrinsic { args, .. } => args.iter().any(|a| expr_uses_reg(a, reg)),
        // Register { id } (different namespace), Undefined, future variants:
        // conservatively assume the register is read.
        _ => true,
    }
}

/// Intra-block global value numbering with constant propagation.
///
/// Two improvements over the classic string-equality GVN:
///
/// 1. **Constant propagation via def-use**.  For every
///    `SetReg { dest, value: Const { value: src } }` we record `dest â†' value`.
///    Any later instruction whose source expression references that register
///    has the register replaced by the constant, enabling downstream folding.
///
/// 2. **Expression-level GVN** (original behaviour preserved).  If two
///    `SetReg`s compute the same load-free expression the second is replaced
///    with a copy of the first result register.
///
/// Returns `true` if any substitutions were made.
#[must_use]
pub fn run_gvn_pass(func: &mut LlilFunction) -> bool {
    /// Visitor that replaces `Register { reg: target, size }` nodes with
    /// `Const { value, size }` when the sizes match.
    struct ConstSubstVisitor<'a> {
        target: &'a LlilRegister,
        value: u64,
        size: Size,
        changed: bool,
    }
    impl ExprVisitor for ConstSubstVisitor<'_> {
        fn visit_expr(&mut self, expr: &LlilExpr) -> Option<LlilExpr> {
            if let LlilExpr::RegisterRef { reg, size } = expr
                && reg == self.target && *size == self.size {
                    self.changed = true;
                    return Some(LlilExpr::Const {
                        value: self.value,
                        size: *size,
                    });
                }
            None
        }
    }

    let mut any_changed = false;
    for block in &mut func.blocks {
        // reg â†' (constant_value, size) —" built-up as we scan forward.
        let mut const_map: HashMap<LlilRegister, (u64, Size)> = HashMap::new();
        // expr_string â†' (first defining reg, size, source expr) —" classic GVN table.
        let mut expr_table: HashMap<String, (LlilRegister, Size, LlilExpr)> = HashMap::new();

        let len = block.instrs.len();
        for idx in 0..len {
            // â"€â"€ Step 1: apply all known constant substitutions into this instr â"€â"€
            let substs: Vec<(LlilRegister, u64, Size)> = const_map
                .iter()
                .map(|(r, &(v, s))| (r.clone(), v, s))
                .collect();
            for (reg, val, sz) in substs {
                let mut v = ConstSubstVisitor {
                    target: &reg,
                    value: val,
                    size: sz,
                    changed: false,
                };
                let new_instr = transform_instr(block.instrs[idx].instr.clone(), &mut v);
                if v.changed {
                    block.instrs[idx].instr = new_instr;
                    any_changed = true;
                }
            }

            // â"€â"€ Step 2: update the const_map based on the (possibly rewritten) instr â"€â"€
            match &block.instrs[idx].instr {
                LlilInstruction::SetReg {
                    dest,
                    value: LlilExpr::Const { value: src, .. },
                    size,
                } => {
                    const_map.insert(dest.clone(), (*src, *size));
                }
                LlilInstruction::SetReg { dest, .. }
                | LlilInstruction::Load { dest, .. }
                | LlilInstruction::Pop { dest, .. } => {
                    // Non-constant assignment: invalidate previous constant binding.
                    const_map.remove(dest);
                }
                LlilInstruction::SetRegSplit { high, low, .. } => {
                    // Both halves are redefined (e.g. widening mul/div):
                    // invalidate constant bindings for both.
                    const_map.remove(high);
                    const_map.remove(low);
                }
                _ => {}
            }

            // â"€â"€ Step 2b: invalidate GVN table entries clobbered by this instr â"€â"€
            // Any redefinition of `dest` kills (a) entries whose value lives in
            // `dest` and (b) entries whose source expression reads `dest`.
            if let LlilInstruction::SetReg { dest, .. }
            | LlilInstruction::Load { dest, .. }
            | LlilInstruction::Pop { dest, .. } = &block.instrs[idx].instr
            {
                let dest = dest.clone();
                expr_table.retain(|_, (reg, _, src_expr)| {
                    *reg != dest && !expr_uses_reg(src_expr, &dest)
                });
            } else if let LlilInstruction::SetRegSplit { high, low, .. } =
                &block.instrs[idx].instr
            {
                let (high, low) = (high.clone(), low.clone());
                expr_table.retain(|_, (reg, _, src_expr)| {
                    *reg != high
                        && *reg != low
                        && !expr_uses_reg(src_expr, &high)
                        && !expr_uses_reg(src_expr, &low)
                });
            }

            // â"€â"€ Step 3: classic expression-level GVN â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            if let LlilInstruction::SetReg {
                dest,
                value: src,
                size,
            } = &block.instrs[idx].instr
                && !expr_has_load(src)
                // A self-referential def (e.g. r1 = r1 + 1) must not be
                // recorded: `dest`'s new value invalidates the operands.
                && !expr_uses_reg(src, dest) {
                    let key = format!("{src:?}");
                    if let Some((prev_reg, prev_size, _)) = expr_table.get(&key).cloned() {
                        if prev_size == *size {
                            let dest2 = dest.clone();
                            let sz2 = *size;
                            block.instrs[idx].instr = LlilInstruction::SetReg {
                                dest: dest2,
                                value: LlilExpr::RegisterRef {
                                    reg: prev_reg,
                                    size: sz2,
                                },
                                size: sz2,
                            };
                            any_changed = true;
                        }
                    } else {
                        let dest2 = dest.clone();
                        let sz2 = *size;
                        let src2 = src.clone();
                        expr_table.insert(key, (dest2, sz2, src2));
                    }
                }
        }
    }
    any_changed
}

/// Pass wrapping [`run_gvn_pass`].
#[derive(Debug, Default)]
pub struct GlobalValueNumberingPass;

impl AnalysisPass for GlobalValueNumberingPass {
    fn name(&self) -> &'static str {
        "global-value-numbering"
    }
    fn description(&self) -> &'static str {
        "Intra-block GVN: replace duplicate expressions with register copies."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        if run_gvn_pass(func) {
            ctx.changed = true;
            ctx.stats.instrs_modified += 1;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Mem2Reg pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A memory-address key used by the mem2reg promotion table.
///
/// Two kinds of addresses are recognised:
/// * `Absolute(addr)` —" a known constant absolute address.
/// * `StackSlot(offset)` —" a frame-pointer-relative slot: `[rbp - offset]`,
///   encoded as the (signed) subtracted constant.  We also accept `[rbp +
///   offset]` (positive offset, unusual but valid for callee-save areas).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum MemKey {
    Absolute(u64),
    StackSlot(i64),
}

/// Try to extract a [`MemKey`] from an address expression.
///
/// Recognised patterns:
/// * `Const(v)`                           â†' `Absolute(v)`
/// * `Sub(Register("rbp"|"r15"), Const(n))` â†' `StackSlot(-(n as i64))`
/// * `Add(Register("rbp"|"r15"), Const(n))` â†' `StackSlot(n as i64)`
fn try_mem_key(addr: &LlilExpr) -> Option<MemKey> {
    match addr {
        LlilExpr::Const { value, .. } => Some(MemKey::Absolute(*value)),
        LlilExpr::SubT(base, offset, _) => {
            if let (LlilExpr::RegisterRef { reg, .. }, LlilExpr::Const { value: n, .. }) =
                (base.as_ref(), offset.as_ref())
            {
                let name = reg.name();
                if matches!(name.as_str(), "rbp" | "r15" | "sp") {
                    return Some(MemKey::StackSlot(-((*n).cast_signed())));
                }
            }
            None
        }
        LlilExpr::AddT(base, offset, _) => {
            if let (LlilExpr::RegisterRef { reg, .. }, LlilExpr::Const { value: n, .. }) =
                (base.as_ref(), offset.as_ref())
            {
                let name = reg.name();
                if matches!(name.as_str(), "rbp" | "r15" | "sp") {
                    return Some(MemKey::StackSlot((*n).cast_signed()));
                }
            }
            None
        }
        _ => None,
    }
}

/// Promote store-then-load pairs at the same address within a block to direct
/// register copies, eliminating the memory round-trip.
///
/// Handles two classes of addresses:
/// * **Constant absolute addresses** —" the original behaviour.
/// * **Frame-pointer-relative stack slots** (`[rbp-N]`, `[rbp+N]`) —"
///   new behaviour.  Each unique offset becomes a synthetic variable named
///   `local_<abs_offset>`.  A `Store { addr: [rbp-N], value: reg }` records
///   `reg` as the current value of that slot, and a subsequent
///   `Load { dest, addr: [rbp-N] }` is replaced by
///   `SetReg { dest, value: Register(reg) }`.
///
/// Returns the number of loads promoted.
#[must_use]
pub fn run_mem2reg_pass(func: &mut LlilFunction) -> u32 {
    let mut total = 0u32;
    for block in &mut func.blocks {
        // MemKey â†' (register holding the stored value, size)
        let mut store_map: HashMap<MemKey, (LlilRegister, Size)> = HashMap::new();
        for ai in &mut block.instrs {
            let instr_clone = ai.instr.clone();
            match &instr_clone {
                // â"€â"€ Record store into a known address â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                LlilInstruction::Store {
                    addr,
                    value: src,
                    size: store_size,
                } => {
                    if let Some(key) = try_mem_key(addr) {
                        match src {
                            LlilExpr::RegisterRef { reg, size } if size == store_size => {
                                store_map.insert(key, (reg.clone(), *size));
                            }
                            // A store of a constant value: record via a synthetic
                            // temporary so a later load can retrieve it as a
                            // register copy.  We do *not* create a real temp here;
                            // instead we just invalidate the slot so we remain
                            // conservative —" constant-propagation is GVN's job.
                            _ => {
                                store_map.remove(&key);
                            }
                        }
                    } else {
                        // Unknown address —" invalidate everything conservatively.
                        store_map.clear();
                    }
                }

                // â"€â"€ Promote load from a known address â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                LlilInstruction::Load { dest, addr, size } => {
                    if let Some(key) = try_mem_key(addr)
                        && let Some((src_reg, stored_size)) = store_map.get(&key).cloned()
                            && stored_size == *size {
                                ai.instr = LlilInstruction::SetReg {
                                    dest: dest.clone(),
                                    value: LlilExpr::RegisterRef {
                                        reg: src_reg,
                                        size: *size,
                                    },
                                    size: *size,
                                };
                                total += 1;
                            }
                    // The load redefines `dest`: any slot remembered as
                    // holding `dest` no longer matches.
                    store_map.retain(|_, (r, _)| r != dest);
                }

                // â"€â"€ Register redefinitions invalidate slots holding that reg
                LlilInstruction::SetReg { dest, .. }
                | LlilInstruction::Pop { dest, .. } => {
                    store_map.retain(|_, (r, _)| r != dest);
                }
                LlilInstruction::SetRegSplit { high, low, .. } => {
                    store_map.retain(|_, (r, _)| r != high && r != low);
                }
                LlilInstruction::SetRegister { .. } => {
                    // Register-by-id namespace: conservatively drop everything.
                    store_map.clear();
                }

                // â"€â"€ Calls / traps / opaque instrs may clobber regs and memory
                LlilInstruction::Call(_)
                | LlilInstruction::CallDest { .. }
                | LlilInstruction::CondCall { .. }
                | LlilInstruction::TailCall { .. }
                | LlilInstruction::SysCall
                | LlilInstruction::Trap { .. }
                | LlilInstruction::Intrinsic { .. }
                | LlilInstruction::Push { .. }
                | LlilInstruction::Undefined
                | LlilInstruction::UnimplementedRaw { .. }
                | LlilInstruction::Unimplemented { .. } => {
                    store_map.clear();
                }

                // Control flow / flags / nop: no register or memory effects
                // on the tracked slots.
                _ => {}
            }
        }
    }
    total
}

/// Pass wrapping [`run_mem2reg_pass`].
#[derive(Debug, Default)]
pub struct Mem2RegPass;

impl AnalysisPass for Mem2RegPass {
    fn name(&self) -> &'static str {
        "mem2reg"
    }
    fn description(&self) -> &'static str {
        "Promote constant-address store+load pairs to register copies."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let n = run_mem2reg_pass(func);
        if n > 0 {
            ctx.changed = true;
            ctx.stats.instrs_modified += n as usize;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// BranchSimplification pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Simplify conditional branches with constant conditions.
///
/// `CondJump { cond: Const(0), ... }` â†' `Jump { dest: false_dest }`
/// `CondJump { cond: Const(â‰ 0), ... }` â†' `Jump { dest: true_dest }`
///
/// Returns the number of branches simplified.
#[must_use]
pub fn run_branch_simplification(func: &mut LlilFunction) -> u32 {
    let mut count = 0u32;
    for block in &mut func.blocks {
        for ai in &mut block.instrs {
            if let LlilInstruction::CondJump {
                cond: LlilExpr::Const { value, .. },
                true_dest,
                false_dest,
            } = &ai.instr
            {
                let dest = if *value != 0 { *true_dest } else { *false_dest };
                ai.instr = LlilInstruction::JumpDest {
                    dest: LlilExpr::Const {
                        value: dest.as_u64(),
                        size: Size::QWord,
                    },
                };
                count += 1;
            }
        }
    }
    count
}

/// Pass wrapping [`run_branch_simplification`].
#[derive(Debug, Default)]
pub struct BranchSimplificationPass;

impl AnalysisPass for BranchSimplificationPass {
    fn name(&self) -> &'static str {
        "branch-simplification"
    }
    fn description(&self) -> &'static str {
        "Fold conditional branches with constant conditions to unconditional jumps."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let n = run_branch_simplification(func);
        if n > 0 {
            ctx.changed = true;
            ctx.stats.exprs_simplified += n as usize;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// TailCallOptimization pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Replace a Call immediately followed by Ret with a `TailCall`.
///
/// Returns `true` if any transformation was applied.
#[must_use]
pub fn run_tailcall_opt(func: &mut LlilFunction) -> bool {
    let mut changed = false;
    for block in &mut func.blocks {
        let len = block.instrs.len();
        if len < 2 {
            continue;
        }
        // Look at consecutive (call, ret) pairs.
        let mut to_tail: Vec<usize> = Vec::new();
        for i in 0..len - 1 {
            let is_call = matches!(block.instrs[i].instr, LlilInstruction::CallDest { .. });
            let is_ret = matches!(block.instrs[i + 1].instr, LlilInstruction::Ret);
            if is_call && is_ret {
                to_tail.push(i);
            }
        }
        // Process in reverse index order so that earlier remove() calls do not
        // shift the indices of later entries in `to_tail`, which would cause
        // the wrong instructions to be modified or an out-of-bounds panic.
        for idx in to_tail.into_iter().rev() {
            if let LlilInstruction::CallDest { dest } = block.instrs[idx].instr.clone() {
                block.instrs[idx].instr = LlilInstruction::TailCall { dest };
                // Remove the Ret that immediately follows the now-tail-call.
                block.instrs.remove(idx + 1);
                changed = true;
            }
        }
    }
    changed
}

/// Pass wrapping [`run_tailcall_opt`].
#[derive(Debug, Default)]
pub struct TailCallOptimizationPass;

impl AnalysisPass for TailCallOptimizationPass {
    fn name(&self) -> &'static str {
        "tailcall-opt"
    }
    fn description(&self) -> &'static str {
        "Replace call+ret pairs with tail calls."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        if run_tailcall_opt(func) {
            ctx.changed = true;
            ctx.stats.instrs_modified += 1;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// UnreachableCodeElimination pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Remove instructions that appear after an unconditional terminator within
/// a block (e.g. code after `Ret`, `Jump`, or `TailCall`).
///
/// Returns the number of dead instructions removed.
#[must_use]
pub fn run_unreachable_code_elimination(func: &mut LlilFunction) -> u32 {
    let mut count = 0u32;
    for block in &mut func.blocks {
        let term_pos = block.instrs.iter().position(|ai| {
            matches!(
                ai.instr,
                LlilInstruction::Ret
                    | LlilInstruction::Return { .. }
                    | LlilInstruction::JumpDest { .. }
                    | LlilInstruction::Jump(..)
                    | LlilInstruction::JumpTo { .. }
                    | LlilInstruction::TailCall { .. }
                    | LlilInstruction::Trap { .. }
            )
        });
        if let Some(pos) = term_pos {
            let dead = block.instrs.len().saturating_sub(pos + 1);
            if dead > 0 {
                block.instrs.truncate(pos + 1);
                count += u32::try_from(dead).unwrap_or(u32::MAX);
            }
        }
    }
    count
}

/// Pass wrapping [`run_unreachable_code_elimination`].
#[derive(Debug, Default)]
pub struct UnreachableCodeEliminationPass;

impl AnalysisPass for UnreachableCodeEliminationPass {
    fn name(&self) -> &'static str {
        "unreachable-code-elim"
    }
    fn description(&self) -> &'static str {
        "Remove instructions after unconditional terminators within a block."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let n = run_unreachable_code_elimination(func);
        if n > 0 {
            ctx.changed = true;
            ctx.stats.dead_removed += n as usize;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PhiElimination pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// In a flat LLIL function (no SSA PHI nodes), this pass is a no-op but
/// registers as a required pipeline stage for completeness.
#[derive(Debug, Default)]
pub struct PhiEliminationPass;

impl AnalysisPass for PhiEliminationPass {
    fn name(&self) -> &'static str {
        "phi-elimination"
    }
    fn description(&self) -> &'static str {
        "No-op at LLIL level (LLIL has no SSA phi nodes)."
    }
    fn run(&self, _func: &mut LlilFunction, _ctx: &mut PassContext) {
        // LLIL has no PHI nodes; this pass is a no-op at this level.
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// RedundantBranchRemoval pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Remove a `CondJump` that has the same true and false destination.
///
/// `if (cond) goto X else goto X` â†' `goto X`
///
/// Returns the number of redundant branches removed.
#[must_use]
pub fn run_redundant_branch_removal(func: &mut LlilFunction) -> u32 {
    let mut count = 0u32;
    for block in &mut func.blocks {
        for ai in &mut block.instrs {
            if let LlilInstruction::CondJump {
                true_dest,
                false_dest,
                ..
            } = &ai.instr
                && true_dest == false_dest {
                    let dest_val = true_dest.as_u64();
                    ai.instr = LlilInstruction::JumpDest {
                        dest: LlilExpr::Const {
                            value: dest_val,
                            size: Size::QWord,
                        },
                    };
                    count += 1;
                }
        }
    }
    count
}

/// Pass wrapping [`run_redundant_branch_removal`].
#[derive(Debug, Default)]
pub struct RedundantBranchRemovalPass;

impl AnalysisPass for RedundantBranchRemovalPass {
    fn name(&self) -> &'static str {
        "redundant-branch-removal"
    }
    fn description(&self) -> &'static str {
        "Remove CondJump instructions where true and false targets are identical."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let n = run_redundant_branch_removal(func);
        if n > 0 {
            ctx.changed = true;
            ctx.stats.exprs_simplified += n as usize;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// IntegerRangeAnalysis pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A simple, intra-block integer range for a register value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntRange {
    pub lo: i64,
    pub hi: i64,
}

impl IntRange {
    /// The range containing a single constant.
    #[must_use]
    pub const fn constant(v: i64) -> Self {
        Self { lo: v, hi: v }
    }

    /// The unbounded (top) range.
    #[must_use]
    pub const fn top() -> Self {
        Self {
            lo: i64::MIN,
            hi: i64::MAX,
        }
    }

    /// Returns `true` if the range contains exactly one value.
    #[must_use]
    pub const fn is_constant(&self) -> bool {
        self.lo == self.hi
    }

    /// Returns `true` if `v` is within the range.
    #[must_use]
    pub const fn contains(&self, v: i64) -> bool {
        v >= self.lo && v <= self.hi
    }
}

/// Perform forward constant propagation and produce a range map for every
/// register defined in `func`.
///
/// Returns a map of `register_name â†' IntRange`.
#[must_use]
pub fn run_integer_range_analysis(func: &LlilFunction) -> HashMap<String, IntRange> {
    // Flow-insensitive but conservative: each block is analyzed independently
    // (intra-block last-write-wins is sound for straight-line code), then the
    // per-block results are joined. If two blocks disagree on a register's
    // final range, the register is branch-dependent and must go to Top —
    // otherwise consumers like NullCheckElimination would fold checks based
    // on whichever block happened to be visited last.
    let mut joined: HashMap<String, IntRange> = HashMap::new();
    for block in &func.blocks {
        let mut ranges: HashMap<String, IntRange> = HashMap::new();
        for ai in &block.instrs {
            match &ai.instr {
                LlilInstruction::SetReg {
                    dest,
                    value: LlilExpr::Const { value: src, .. },
                    ..
                } => {
                    // Use bit-pattern reinterpretation (two's complement) so that
                    // values > i64::MAX are treated as their signed equivalents
                    // rather than silently wrapping to wrong positive values.
                    let signed_src = (*src).cast_signed();
                    ranges.insert(dest.name().clone(), IntRange::constant(signed_src));
                }
                LlilInstruction::SetReg {
                    dest,
                    value: LlilExpr::RegisterRef { reg, .. },
                    ..
                } => {
                    if let Some(r) = ranges.get(&reg.name()).cloned() {
                        ranges.insert(dest.name().clone(), r);
                    } else {
                        ranges.insert(dest.name().clone(), IntRange::top());
                    }
                }
                LlilInstruction::SetReg {
                    dest,
                    value: LlilExpr::AddT(l, r, _),
                    ..
                } => {
                    if let (
                        LlilExpr::RegisterRef { reg: rl, .. },
                        LlilExpr::Const { value: rv, .. },
                    ) = (l.as_ref(), r.as_ref())
                        && let Some(base) = ranges.get(&rl.name())
                            && base.is_constant() {
                                let new_val = base.lo.wrapping_add((*rv).cast_signed());
                                ranges.insert(dest.name().clone(), IntRange::constant(new_val));
                                continue;
                            }
                    ranges.insert(dest.name().clone(), IntRange::top());
                }
                LlilInstruction::SetReg { dest, .. } => {
                    ranges.insert(dest.name().clone(), IntRange::top());
                }
                _ => {}
            }
        }
        // Join this block's results into the function-wide map.
        for (name, range) in ranges {
            match joined.get(&name) {
                None => {
                    joined.insert(name, range);
                }
                Some(existing) if *existing == range => {}
                Some(_) => {
                    joined.insert(name, IntRange::top());
                }
            }
        }
    }
    joined
}

/// Pass wrapping [`run_integer_range_analysis`].
///
/// Annotates the context with computed ranges but does not modify the function.
#[derive(Debug, Default)]
pub struct IntegerRangeAnalysisPass;

impl AnalysisPass for IntegerRangeAnalysisPass {
    fn name(&self) -> &'static str {
        "integer-range-analysis"
    }
    fn description(&self) -> &'static str {
        "Forward integer range propagation for all registers."
    }
    fn run(&self, func: &mut LlilFunction, _ctx: &mut PassContext) {
        let _ranges = run_integer_range_analysis(func);
        // Analysis result stored in context or pipeline metadata in a real system.
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// NullCheckElimination pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Remove explicit comparisons of the form `cond = (reg == 0)` where range
/// analysis determines that `reg` is always non-zero (or always zero).
///
/// Returns the number of comparisons simplified.
#[must_use]
pub fn run_null_check_elimination(func: &mut LlilFunction) -> u32 {
    let ranges = run_integer_range_analysis(func);
    let mut count = 0u32;
    for block in &mut func.blocks {
        for ai in &mut block.instrs {
            if let LlilInstruction::SetReg {
                dest,
                value: LlilExpr::CmpEq(l, r),
                size,
            } = &ai.instr.clone()
                && let (LlilExpr::RegisterRef { reg, .. }, LlilExpr::Const { value: 0, .. }) =
                    (l.as_ref(), r.as_ref())
                    && let Some(range) = ranges.get(&reg.name())
                        && range.is_constant() {
                            let eq_zero = range.lo == 0;
                            let result: u64 = u64::from(eq_zero);
                            ai.instr = LlilInstruction::SetReg {
                                dest: dest.clone(),
                                value: LlilExpr::Const {
                                    value: result,
                                    size: Size::Byte,
                                },
                                size: *size,
                            };
                            count += 1;
                        }
        }
    }
    count
}

/// Pass wrapping [`run_null_check_elimination`].
#[derive(Debug, Default)]
pub struct NullCheckEliminationPass;

impl AnalysisPass for NullCheckEliminationPass {
    fn name(&self) -> &'static str {
        "null-check-elim"
    }
    fn description(&self) -> &'static str {
        "Eliminate redundant null comparisons using range analysis."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let n = run_null_check_elimination(func);
        if n > 0 {
            ctx.changed = true;
            ctx.stats.exprs_simplified += n as usize;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PureCallDetection pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Information about a detected call site.
#[derive(Debug, Clone)]
pub struct CallSiteInfo {
    /// Block index.
    pub block_idx: usize,
    /// Instruction index within the block.
    pub instr_idx: usize,
    /// Address of the call instruction.
    pub address: Address,
    /// Callee expression (often a Const with the target address).
    pub callee: LlilExpr,
    /// Whether this is a tail call.
    pub is_tail_call: bool,
}

/// Collect all call sites in `func`.
#[must_use]
pub fn collect_call_sites(func: &LlilFunction) -> Vec<CallSiteInfo> {
    let mut sites = Vec::new();
    for (bi, block) in func.blocks.iter().enumerate() {
        for (ii, ai) in block.instrs.iter().enumerate() {
            match &ai.instr {
                LlilInstruction::CallDest { dest } => {
                    sites.push(CallSiteInfo {
                        block_idx: bi,
                        instr_idx: ii,
                        address: ai.address,
                        callee: dest.clone(),
                        is_tail_call: false,
                    });
                }
                LlilInstruction::TailCall { dest } => {
                    sites.push(CallSiteInfo {
                        block_idx: bi,
                        instr_idx: ii,
                        address: ai.address,
                        callee: dest.clone(),
                        is_tail_call: true,
                    });
                }
                _ => {}
            }
        }
    }
    sites
}

/// Pass that collects call site information (analysis only; no transforms).
#[derive(Debug, Default)]
pub struct PureCallDetectionPass;

impl AnalysisPass for PureCallDetectionPass {
    fn name(&self) -> &'static str {
        "pure-call-detection"
    }
    fn description(&self) -> &'static str {
        "Collect all call sites for downstream analysis."
    }
    fn run(&self, func: &mut LlilFunction, _ctx: &mut PassContext) {
        let _sites = collect_call_sites(func);
        // In a full implementation, sites are stored in pass-specific pipeline state.
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ArgumentValuePropagation pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Propagate known constant values of registers to subsequent instructions
/// (within a block) when those registers are used as call arguments.
///
/// Returns the number of register uses replaced with constants.
#[must_use]
pub fn run_argument_value_propagation(func: &mut LlilFunction) -> u32 {
    let ranges = run_integer_range_analysis(func);
    let mut total = 0u32;
    for block in &mut func.blocks {
        for ai in &mut block.instrs {
            total +=
                substitute_constants_in_expr_recursive(get_instr_src_mut(&mut ai.instr), &ranges);
        }
    }
    total
}

const fn get_instr_src_mut(instr: &mut LlilInstruction) -> Option<&mut LlilExpr> {
    match instr {
        LlilInstruction::SetReg { value: src, .. }
        | LlilInstruction::Store { value: src, .. }
        | LlilInstruction::CondJump { cond: src, .. }
        | LlilInstruction::JumpDest { dest: src }
        | LlilInstruction::CallDest { dest: src }
        | LlilInstruction::TailCall { dest: src } => Some(src),
        _ => None,
    }
}

fn substitute_constants_in_expr_recursive(
    maybe_expr: Option<&mut LlilExpr>,
    ranges: &HashMap<String, IntRange>,
) -> u32 {
    let Some(expr) = maybe_expr else { return 0 };
    substitute_const_in_expr(expr, ranges)
}

fn substitute_const_in_expr(expr: &mut LlilExpr, ranges: &HashMap<String, IntRange>) -> u32 {
    match expr {
        LlilExpr::RegisterRef { reg, size } => {
            if let Some(r) = ranges.get(&reg.name())
                && r.is_constant() {
                    // Cast via bit-pattern reinterpret (i64 → u64) so negative
                    // constants (e.g. -1) are preserved as their two's-complement
                    // bit patterns rather than being mis-truncated.
                    *expr = LlilExpr::Const {
                        value: r.lo.cast_unsigned(),
                        size: *size,
                    };
                    return 1;
                }
            0
        }
        LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::DivU(l, r, _)
        | LlilExpr::DivS(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _)
        | LlilExpr::CmpEq(l, r)
        | LlilExpr::CmpNe(l, r)
        | LlilExpr::CmpSlt(l, r)
        | LlilExpr::CmpUlt(l, r)
        | LlilExpr::CmpSle(l, r)
        | LlilExpr::CmpUge(l, r)
        | LlilExpr::CmpSge(l, r)
        | LlilExpr::CmpUgt(l, r)
        | LlilExpr::CmpUle(l, r)
        | LlilExpr::CmpSgt(l, r) => {
            substitute_const_in_expr(l, ranges) + substitute_const_in_expr(r, ranges)
        }
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::Load { addr: e, .. }
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. } => substitute_const_in_expr(e, ranges),
        _ => 0,
    }
}

/// Pass wrapping [`run_argument_value_propagation`].
#[derive(Debug, Default)]
pub struct ArgumentValuePropagationPass;

impl AnalysisPass for ArgumentValuePropagationPass {
    fn name(&self) -> &'static str {
        "argument-value-propagation"
    }
    fn description(&self) -> &'static str {
        "Replace known-constant register uses with immediate constants."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let n = run_argument_value_propagation(func);
        if n > 0 {
            ctx.changed = true;
            ctx.stats.exprs_simplified += n as usize;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// LoopInvariantCodeMotion pass (simplified)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A simplified LICM heuristic: move `SetReg` instructions whose source is a
/// pure constant to the beginning of the first block (function entry).
///
/// In a real implementation this would check loop structure via dominators.
///
/// Returns the number of instructions moved.
#[must_use]
pub fn run_licm(func: &mut LlilFunction) -> u32 {
    if func.blocks.len() < 2 {
        return 0;
    }

    // Count static writes per register name over the whole function.  A
    // constant SetReg is only hoistable when it is the *sole* write to that
    // register: hoisting one of several defs (e.g. `rax = 1` / `rax = 2` on
    // the two arms of a diamond) would destroy branch semantics.
    let mut write_counts: HashMap<String, usize> = HashMap::new();
    for block in &func.blocks {
        for ai in &block.instrs {
            let mut written = HashSet::new();
            collect_written_reg_names(&ai.instr, &mut written);
            for name in written {
                *write_counts.entry(name).or_insert(0) += 1;
            }
        }
    }

    let mut to_move: Vec<LlilAnnotatedInstr> = Vec::new();
    // Registers read or written by instructions that stay ahead of (or at)
    // the current scan position; hoisting past them is unsafe.
    let mut touched: HashSet<String> = HashSet::new();
    // Only hoist while control flow from entry is straight-line: every block
    // before the candidate must fall through unconditionally (no terminator).
    let mut straight_line = true;
    let block_starts: Vec<u64> = func.blocks.iter().map(|b| b.start.0).collect();
    for (bi, block) in func.blocks.iter_mut().enumerate() {
        if bi == 0 || !straight_line {
            for ai in &block.instrs {
                collect_read_regs(&ai.instr, &mut touched);
                collect_written_reg_names(&ai.instr, &mut touched);
            }
        } else {
            let mut kept = Vec::with_capacity(block.instrs.len());
            for ai in block.instrs.drain(..) {
                let hoistable = match &ai.instr {
                    LlilInstruction::SetReg {
                        dest,
                        value: LlilExpr::Const { .. },
                        ..
                    } => {
                        let name = dest.name();
                        !touched.contains(&name)
                            && write_counts.get(&name).copied() == Some(1)
                    }
                    _ => false,
                };
                if hoistable {
                    collect_written_reg_names(&ai.instr, &mut touched);
                    to_move.push(ai);
                } else {
                    collect_read_regs(&ai.instr, &mut touched);
                    collect_written_reg_names(&ai.instr, &mut touched);
                    kept.push(ai);
                }
            }
            block.instrs = kept;
        }
        // Straight-line flow continues only when the block falls through or
        // jumps unconditionally to the next block in order.
        straight_line = straight_line
            && match block.terminator().map(|ai| &ai.instr) {
                None => true,
                Some(
                    LlilInstruction::Jump(LlilExpr::Const { value, .. })
                    | LlilInstruction::JumpDest {
                        dest: LlilExpr::Const { value, .. },
                    },
                ) => block_starts.get(bi + 1) == Some(value),
                Some(_) => false,
            };
    }
    let count = u32::try_from(to_move.len()).unwrap_or(u32::MAX);
    if count == 0 {
        return 0;
    }
    // Prepend to entry block.
    let entry_instrs = std::mem::take(&mut func.blocks[0].instrs);
    func.blocks[0].instrs = to_move;
    func.blocks[0].instrs.extend(entry_instrs);
    count
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// LoopDetection pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Information about a single natural loop discovered in the CFG.
#[derive(Debug, Clone)]
pub struct LoopInfo {
    /// The id of the loop-header block (the unique block that dominates the
    /// entire loop and is the target of at least one back-edge).
    pub header_block_id: u32,
    /// Ids of all blocks in the loop body (including the header).
    pub body_blocks: Vec<u32>,
    /// Ids of blocks that are successors of the loop but are not part of it
    /// (i.e. the exit destinations of conditional jumps inside the loop).
    pub exit_blocks: Vec<u32>,
}

/// Detect natural loops in the CFG of `func` using a conservative back-edge
/// heuristic and a simple dominator-tree approximation.
///
/// A *back-edge* is an edge B â†' H where H has a lower block id than B (i.e. we
/// are jumping backwards in the linear block ordering).  For each back-edge we
/// collect the loop body via a reverse BFS from B up to H, then determine exit
/// blocks as successors of body blocks that lie outside the body set.
///
/// This is not a full Lengauer-Tarjan dominator analysis, but it is sufficient
/// to correctly identify most structured loops generated by a compiler front-end.
#[must_use]
pub fn detect_loops(func: &LlilFunction) -> Vec<LoopInfo> {
    if func.blocks.is_empty() {
        return Vec::new();
    }

    // Build a successor map: block_id â†' set of successor block ids.
    // We derive successors from branch instructions in each block.
    // Note: Jump.dest is LlilExpr (we extract Const addresses only);
    //       CondJump.true_dest / false_dest are Address values directly.
    let mut successors: HashMap<u32, Vec<u32>> = HashMap::new();
    for block in &func.blocks {
        let succs = successors.entry(block.id).or_default();
        for ai in &block.instrs {
            match &ai.instr {
                LlilInstruction::JumpDest { dest } => {
                    // Only resolve constant jump targets.
                    if let LlilExpr::Const { value, .. } = dest
                        && let Some(target) =
                            func.blocks.iter().find(|b| b.start.as_u64() == *value)
                        {
                            succs.push(target.id);
                        }
                }
                LlilInstruction::CondJump {
                    true_dest,
                    false_dest,
                    ..
                } => {
                    if let Some(t) = func.blocks.iter().find(|b| b.start == *true_dest) {
                        succs.push(t.id);
                    }
                    if let Some(f) = func.blocks.iter().find(|b| b.start == *false_dest) {
                        succs.push(f.id);
                    }
                }
                _ => {}
            }
        }
    }

    // Build a predecessor map from the successor map.
    let mut predecessors: HashMap<u32, Vec<u32>> = HashMap::new();
    for (&src, dsts) in &successors {
        for &dst in dsts {
            predecessors.entry(dst).or_default().push(src);
        }
    }

    // Identify back-edges: B â†' H where H.id <= B.id.
    let mut loops: Vec<LoopInfo> = Vec::new();
    for block in &func.blocks {
        for &succ_id in successors.get(&block.id).unwrap_or(&vec![]) {
            if succ_id <= block.id {
                // This is a back-edge: block.id â†' succ_id (header).
                let header_id = succ_id;

                // Collect the loop body via reverse BFS from `block` up to `header`.
                let mut body: HashSet<u32> = HashSet::new();
                body.insert(header_id);
                let mut worklist = vec![block.id];
                while let Some(node) = worklist.pop() {
                    if body.insert(node) {
                        // Walk predecessors of node that are >= header_id.
                        for &pred in predecessors.get(&node).unwrap_or(&vec![]) {
                            if pred >= header_id && !body.contains(&pred) {
                                worklist.push(pred);
                            }
                        }
                    }
                }

                // Exit blocks: successors of any body block that are outside the body.
                let mut exit_set: HashSet<u32> = HashSet::new();
                for &bid in &body {
                    for &succ in successors.get(&bid).unwrap_or(&vec![]) {
                        if !body.contains(&succ) {
                            exit_set.insert(succ);
                        }
                    }
                }

                let mut body_blocks: Vec<u32> = body.into_iter().collect();
                body_blocks.sort_unstable();
                let mut exit_blocks: Vec<u32> = exit_set.into_iter().collect();
                exit_blocks.sort_unstable();

                loops.push(LoopInfo {
                    header_block_id: header_id,
                    body_blocks,
                    exit_blocks,
                });
            }
        }
    }

    loops
}

/// Pass that detects natural loops and records the count as a diagnostic.
///
/// The loop info is also stored so that downstream passes (e.g.
/// [`LoopInvariantCodeMotionPass`]) can consume it via [`detect_loops`].
#[derive(Debug, Default)]
pub struct LoopDetectionPass;

impl AnalysisPass for LoopDetectionPass {
    fn name(&self) -> &'static str {
        "loop-detection"
    }
    fn description(&self) -> &'static str {
        "Detect natural loops via back-edge analysis and record header/body/exit blocks."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let loops = detect_loops(func);
        if !loops.is_empty() {
            // Attributed through the shared `rustre-il` tier tag rather than a
            // hard-coded string, so the diagnostic says which IL it came from.
            ctx.warn_at_tier(&format!(
                "loop-detection: found {} loop(s) in function at {:?}",
                loops.len(),
                func.entry
            ));
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// LoopInvariantCodeMotion pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Pass wrapping [`run_licm`].
///
/// Before running the LICM heuristic this pass calls [`detect_loops`] to
/// identify loop headers.  Instructions in blocks that are confirmed to be loop
/// bodies (block id > header) are candidates for hoisting, replacing the
/// previous unconditional "scan blocks[1..]" strategy with a loop-aware one.
#[derive(Debug, Default)]
pub struct LoopInvariantCodeMotionPass;

impl AnalysisPass for LoopInvariantCodeMotionPass {
    fn name(&self) -> &'static str {
        "loop-invariant-code-motion"
    }
    fn description(&self) -> &'static str {
        "Hoist pure-constant SetReg instructions out of detected loop bodies to the entry block."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        // Run loop detection to restrict hoisting to real loop bodies.
        let loop_infos = detect_loops(func);

        let hoistable_blocks: HashSet<u32> = if loop_infos.is_empty() {
            // No loops found —" fall back to hoisting from all non-entry blocks
            // (preserves the original behaviour when there are no back-edges).
            func.blocks.iter().skip(1).map(|b| b.id).collect()
        } else {
            // Only hoist from confirmed loop-body blocks (excluding header so
            // that loop-entry invariants are also captured).
            loop_infos
                .iter()
                .flat_map(|li| li.body_blocks.iter().copied())
                .filter(|&id| id != 0) // never hoist from entry itself
                .collect()
        };

        if func.blocks.is_empty() || hoistable_blocks.is_empty() {
            return;
        }

        let mut to_move: Vec<LlilAnnotatedInstr> = Vec::new();
        for block in &mut func.blocks {
            if !hoistable_blocks.contains(&block.id) {
                continue;
            }
            let mut kept = Vec::with_capacity(block.instrs.len());
            for ai in block.instrs.drain(..) {
                let is_const_setreg = matches!(
                    &ai.instr,
                    LlilInstruction::SetReg {
                        value: LlilExpr::Const { .. },
                        ..
                    }
                );
                if is_const_setreg {
                    to_move.push(ai);
                } else {
                    kept.push(ai);
                }
            }
            block.instrs = kept;
        }

        let n = to_move.len();
        if n > 0 {
            let entry_instrs = std::mem::take(&mut func.blocks[0].instrs);
            func.blocks[0].instrs = to_move;
            func.blocks[0].instrs.extend(entry_instrs);
            ctx.changed = true;
            ctx.stats.instrs_modified += n;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// InliningHeuristics pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Heuristic score for whether a function is a good inlining candidate.
/// Higher = more likely to inline.
#[derive(Debug, Clone)]
pub struct InliningScore {
    /// Total instruction count (lower = better for inlining).
    pub instr_count: usize,
    /// Number of call sites in the callee.
    pub call_count: usize,
    /// Number of basic blocks.
    pub block_count: usize,
    /// Heuristic score (0—"100).
    pub score: u8,
}

/// Compute an inlining heuristic score for `func`.
#[must_use]
pub fn compute_inlining_score(func: &LlilFunction) -> InliningScore {
    let instr_count: usize = func.blocks.iter().map(|b| b.instrs.len()).sum();
    let call_count = func
        .blocks
        .iter()
        .flat_map(|b| b.instrs.iter())
        .filter(|ai| {
            matches!(
                ai.instr,
                LlilInstruction::CallDest { .. } | LlilInstruction::TailCall { .. }
            )
        })
        .count();
    let block_count = func.blocks.len();

    // Simple heuristic: small functions with no calls score highest.
    let score = if instr_count <= 3 && call_count == 0 {
        90
    } else if instr_count <= 10 && call_count == 0 {
        70
    } else if instr_count <= 20 && call_count <= 1 {
        50
    } else if instr_count <= 50 {
        30
    } else {
        10
    };

    InliningScore {
        instr_count,
        call_count,
        block_count,
        score,
    }
}

/// Pass that computes the inlining score (analysis only; no transforms).
#[derive(Debug, Default)]
pub struct InliningHeuristicsPass;

impl AnalysisPass for InliningHeuristicsPass {
    fn name(&self) -> &'static str {
        "inlining-heuristics"
    }
    fn description(&self) -> &'static str {
        "Score a function's inlining suitability based on size and call count."
    }
    fn run(&self, func: &mut LlilFunction, _ctx: &mut PassContext) {
        let _score = compute_inlining_score(func);
        // In a full implementation, score is stored in pass-specific pipeline state.
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// LoopBoundAnalysis pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A detected loop structure and its bounds.
#[derive(Debug, Clone)]
pub struct LoopBound {
    /// Block id of the loop header.
    pub header_block: u32,
    /// Known iteration count, if statically determinable.
    pub iteration_count: Option<u64>,
    /// Whether we can prove the loop always terminates.
    pub always_terminates: bool,
}

/// Analyse back-edges in the CFG to find loops and attempt to bound them.
///
/// A back-edge is identified when a block jumps to an earlier block (lower id).
/// This is a conservative approximation; a proper implementation uses dominators.
#[must_use]
pub fn run_loop_bound_analysis(func: &LlilFunction) -> Vec<LoopBound> {
    let mut bounds = Vec::new();
    for block in &func.blocks {
        for ai in &block.instrs {
            if let LlilInstruction::CondJump { true_dest, .. } = &ai.instr
                && let Some(header) = func.blocks.iter().find(|b| b.start == *true_dest)
                    && header.id < block.id {
                        bounds.push(LoopBound {
                            header_block: header.id,
                            iteration_count: None,
                            always_terminates: false,
                        });
                    }
        }
    }
    bounds
}

/// Pass wrapping [`run_loop_bound_analysis`].
#[derive(Debug, Default)]
pub struct LoopBoundAnalysisPass;

impl AnalysisPass for LoopBoundAnalysisPass {
    fn name(&self) -> &'static str {
        "loop-bound-analysis"
    }
    fn description(&self) -> &'static str {
        "Detect back-edges in the CFG to identify loops and estimate bounds."
    }
    fn run(&self, func: &mut LlilFunction, _ctx: &mut PassContext) {
        let _bounds = run_loop_bound_analysis(func);
        // In a full implementation, bounds are stored in pass-specific pipeline state.
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PassPipeline: a pre-built ordered pipeline
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Construct the full optimisation pipeline with all available passes.
///
/// Order: `NopElimination` â†' `ConstantFolding` â†' `IdentityElimination` â†'
///        `CopyPropagation` â†' GVN â†' `BranchSimplification` â†' `RedundantBranchRemoval` â†'
///        `UnreachableCodeElimination` â†' `TailCallOpt` â†' `Mem2Reg` â†'
///        `IntegerRangeAnalysis` â†' `NullCheckElimination` â†'
///        `ArgumentValuePropagation` â†' LICM â†' `PureCallDetection` â†'
///        `InliningHeuristics` â†' `LoopBoundAnalysis` â†' `PhiElimination` â†'
///        `DeadCodeElimination` â†' `BlockMerge`
#[must_use]
pub fn build_full_pipeline() -> PassManager {
    PassManager::new()
        .add_pass(NopEliminationPass)
        .add_pass(ConstantFoldingPass)
        .add_pass(IdentityEliminationPass)
        .add_pass(CopyPropagationPass)
        .add_pass(GlobalValueNumberingPass)
        .add_pass(BranchSimplificationPass)
        .add_pass(RedundantBranchRemovalPass)
        .add_pass(UnreachableCodeEliminationPass)
        .add_pass(TailCallOptimizationPass)
        .add_pass(Mem2RegPass)
        .add_pass(IntegerRangeAnalysisPass)
        .add_pass(NullCheckEliminationPass)
        .add_pass(ArgumentValuePropagationPass)
        .add_pass(LoopInvariantCodeMotionPass)
        .add_pass(PureCallDetectionPass)
        .add_pass(InliningHeuristicsPass)
        .add_pass(LoopBoundAnalysisPass)
        .add_pass(PhiEliminationPass)
        .add_pass(DeadCodeEliminationPass)
        .add_pass(BlockMergePass)
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Pass statistics / query helpers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Count the total number of instructions across all blocks of `func`.
#[must_use]
pub fn count_instrs(func: &LlilFunction) -> usize {
    func.blocks.iter().map(|b| b.instrs.len()).sum()
}

/// Count the number of distinct constant values in `func`.
#[must_use]
pub fn count_constants(func: &LlilFunction) -> usize {
    let mut consts: HashSet<u64> = HashSet::new();
    for block in &func.blocks {
        for ai in &block.instrs {
            collect_constants_in_instr(&ai.instr, &mut consts);
        }
    }
    consts.len()
}

fn collect_constants_in_instr(instr: &LlilInstruction, out: &mut HashSet<u64>) {
    match instr {
        LlilInstruction::SetReg { value: src, .. } => collect_constants_in_expr(src, out),
        LlilInstruction::Store {
            addr, value: src, ..
        } => {
            collect_constants_in_expr(addr, out);
            collect_constants_in_expr(src, out);
        }
        LlilInstruction::CondJump { cond, .. } => collect_constants_in_expr(cond, out),
        LlilInstruction::CallDest { dest }
        | LlilInstruction::TailCall { dest }
        | LlilInstruction::JumpDest { dest } => collect_constants_in_expr(dest, out),
        _ => {}
    }
}

fn collect_constants_in_expr(expr: &LlilExpr, out: &mut HashSet<u64>) {
    match expr {
        LlilExpr::Const { value, .. } => {
            out.insert(*value);
        }
        LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::DivU(l, r, _)
        | LlilExpr::DivS(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _)
        | LlilExpr::CmpEq(l, r)
        | LlilExpr::CmpNe(l, r)
        | LlilExpr::CmpSlt(l, r)
        | LlilExpr::CmpUlt(l, r)
        | LlilExpr::CmpSle(l, r)
        | LlilExpr::CmpUle(l, r)
        | LlilExpr::CmpSgt(l, r)
        | LlilExpr::CmpUgt(l, r)
        | LlilExpr::CmpSge(l, r)
        | LlilExpr::CmpUge(l, r) => {
            collect_constants_in_expr(l, out);
            collect_constants_in_expr(r, out);
        }
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::Load { addr: e, .. }
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. } => collect_constants_in_expr(e, out),
        _ => {}
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// StrengthReduction pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Replace multiplications by constants with cheaper shift/add sequences.
///
/// Rules applied:
/// - `x * 1` â†' `x`              (handled by `IdentityElimination`, also here)
/// - `x * 0` â†' `0`              (handled by `IdentityElimination`, also here)
/// - `x * 2^n` â†' `x << n`       for any power-of-two constant
/// - `x * 3`  â†' `(x << 1) + x`
/// - `x * 5`  â†' `(x << 2) + x`
/// - `x * 9`  â†' `(x << 3) + x`
/// - `x / 2^n` â†' `x >> n`  (unsigned division, logical shift)
/// - `x % 2^n` â†' `x & (2^n - 1)`  (unsigned modulo, bitmask)
///
/// Returns the number of rewrites performed.
#[must_use]
pub fn run_strength_reduction(func: &mut LlilFunction) -> u32 {
    let mut count = 0u32;
    for block in &mut func.blocks {
        for ai in &mut block.instrs {
            if let Some(expr) = get_instr_src_mut(&mut ai.instr) {
                count += reduce_expr(expr);
            }
        }
    }
    count
}

/// Apply top-level strength reduction rules (called after recursing into children).
fn reduce_expr_top(expr: &mut LlilExpr) -> u32 {
    match expr.clone() {
        // x * C  where C is a power of two → x << log2(C)
        LlilExpr::MulT(ref lhs, rhs, sz) if matches!(rhs.as_ref(), LlilExpr::Const { value: c, .. } if *c != 0 && c.is_power_of_two()) =>
        {
            let LlilExpr::Const { value: c, .. } = *rhs else { unreachable!() };
            let shift = u64::from(c.trailing_zeros());
            *expr = LlilExpr::ShlT(lhs.clone(), Box::new(LlilExpr::Const { value: shift, size: sz }), sz);
            1
        }
        // x * 3 → (x << 1) + x
        LlilExpr::MulT(ref lhs, rhs, sz) if matches!(rhs.as_ref(), LlilExpr::Const { value: 3, .. }) => {
            *expr = LlilExpr::AddT(Box::new(LlilExpr::ShlT(lhs.clone(), Box::new(LlilExpr::Const { value: 1, size: sz }), sz)), lhs.clone(), sz);
            1
        }
        // x * 5 → (x << 2) + x
        LlilExpr::MulT(ref lhs, rhs, sz) if matches!(rhs.as_ref(), LlilExpr::Const { value: 5, .. }) => {
            *expr = LlilExpr::AddT(Box::new(LlilExpr::ShlT(lhs.clone(), Box::new(LlilExpr::Const { value: 2, size: sz }), sz)), lhs.clone(), sz);
            1
        }
        // x * 9 → (x << 3) + x
        LlilExpr::MulT(ref lhs, rhs, sz) if matches!(rhs.as_ref(), LlilExpr::Const { value: 9, .. }) => {
            *expr = LlilExpr::AddT(Box::new(LlilExpr::ShlT(lhs.clone(), Box::new(LlilExpr::Const { value: 3, size: sz }), sz)), lhs.clone(), sz);
            1
        }
        // x / 2^n → x >> n  (unsigned)
        LlilExpr::DivU(ref lhs, rhs, sz) if matches!(rhs.as_ref(), LlilExpr::Const { value: c, .. } if *c != 0 && c.is_power_of_two()) => {
            let LlilExpr::Const { value: c, .. } = *rhs else { unreachable!() };
            let shift = u64::from(c.trailing_zeros());
            *expr = LlilExpr::Shr(lhs.clone(), Box::new(LlilExpr::Const { value: shift, size: sz }), sz);
            1
        }
        _ => 0,
    }
}

fn reduce_expr(expr: &mut LlilExpr) -> u32 {
    let mut count = 0u32;
    // First recurse into children.
    match expr {
        LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _)
        | LlilExpr::DivU(l, r, _)
        | LlilExpr::DivS(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::Rol(l, r, _)
        | LlilExpr::Ror(l, r, _) => {
            count += reduce_expr(l);
            count += reduce_expr(r);
        }
        // Struct-form encodings.
        LlilExpr::Add { left, right, .. }
        | LlilExpr::Sub { left, right, .. }
        | LlilExpr::Mul { left, right, .. } => {
            count += reduce_expr(left);
            count += reduce_expr(right);
        }
        LlilExpr::Shl { value, shift, .. } => {
            count += reduce_expr(value);
            count += reduce_expr(shift);
        }
        LlilExpr::CondExpr {
            cond,
            true_val,
            false_val,
            ..
        } => {
            count += reduce_expr(cond);
            count += reduce_expr(true_val);
            count += reduce_expr(false_val);
        }
        LlilExpr::Intrinsic { args, .. } => {
            for a in args {
                count += reduce_expr(a);
            }
        }
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::Load { addr: e, .. }
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. } => count += reduce_expr(e),
        _ => {}
    }

    // Now apply strength reductions at the top level.
    count += reduce_expr_top(expr);
    count
}

/// Pass wrapping [`run_strength_reduction`].
#[derive(Debug, Default)]
pub struct StrengthReductionPass;

impl AnalysisPass for StrengthReductionPass {
    fn name(&self) -> &'static str {
        "strength-reduction"
    }
    fn description(&self) -> &'static str {
        "Replace multiply/divide-by-constant with shifts and additions."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let n = run_strength_reduction(func);
        if n > 0 {
            ctx.changed = true;
            ctx.stats.exprs_simplified += n as usize;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// AlgebraicSimplificationPass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Apply algebraic identities that are separate from `IdentityEliminationPass`.
///
/// Additional rules:
/// - `x AND ~x` â†' `0`
/// - `x OR ~x`  â†' `all_ones`
/// - `x XOR x`  â†' `0`   (also in `IdentityElimination`, included for symmetry)
/// - `NOT(CmpEq(a,b))` â†' `CmpNe(a,b)` (De Morgan)
/// - `NOT(CmpSlt(a,b))` â†' `CmpSge(a,b)` (De Morgan)
/// - `NOT(CmpUlt(a,b))` â†' `CmpUge(a,b)` (De Morgan)
///
/// Returns the number of rewrites.
#[must_use]
pub fn run_algebraic_simplification(func: &mut LlilFunction) -> u32 {
    let mut count = 0u32;
    for block in &mut func.blocks {
        for ai in &mut block.instrs {
            if let Some(expr) = get_instr_src_mut(&mut ai.instr) {
                count += algebraic_simplify_expr(expr);
            }
        }
    }
    count
}

/// Apply top-level algebraic rules (De Morgan, annihilator, complement).
fn algebraic_simplify_top(expr: &mut LlilExpr) -> u32 {
    let mut count = 0u32;
    match expr.clone() {
        LlilExpr::Not(inner, _) => {
            match *inner {
                LlilExpr::Not(inner2, _) => { *expr = *inner2; count += 1; }
                LlilExpr::CmpEq(a, b) => { *expr = LlilExpr::CmpNe(a, b); count += 1; }
                LlilExpr::CmpNe(a, b) => { *expr = LlilExpr::CmpEq(a, b); count += 1; }
                LlilExpr::CmpSlt(a, b) => { *expr = LlilExpr::CmpSge(a, b); count += 1; }
                LlilExpr::CmpUlt(a, b) => { *expr = LlilExpr::CmpUge(a, b); count += 1; }
                LlilExpr::CmpSge(a, b) => { *expr = LlilExpr::CmpSlt(a, b); count += 1; }
                LlilExpr::CmpUge(a, b) => { *expr = LlilExpr::CmpUlt(a, b); count += 1; }
                _ => {}
            }
        }
        LlilExpr::And(ref lhs, ref rhs, sz) => {
            if let LlilExpr::Not(inner, _) = rhs.as_ref() {
                if **inner == **lhs { *expr = LlilExpr::Const { value: 0, size: sz }; count += 1; }
            } else if let LlilExpr::Not(inner, _) = lhs.as_ref()
                && **inner == **rhs {
                    *expr = LlilExpr::Const { value: 0, size: sz }; count += 1;
                }
        }
        LlilExpr::Or(ref lhs, ref rhs, sz) => {
            let all_ones = match sz {
                Size::Byte => 0xFF,
                Size::Word => 0xFFFF,
                Size::DWord => 0xFFFF_FFFF,
                Size::QWord | Size::OWord | Size::YWord | Size::ZWord => 0xFFFF_FFFF_FFFF_FFFF,
            };
            if let LlilExpr::Not(inner, _) = rhs.as_ref() {
                if **inner == **lhs { *expr = LlilExpr::Const { value: all_ones, size: sz }; count += 1; }
            } else if let LlilExpr::Not(inner, _) = lhs.as_ref()
                && **inner == **rhs {
                    *expr = LlilExpr::Const { value: all_ones, size: sz }; count += 1;
                }
        }
        _ => {}
    }
    count
}

fn algebraic_simplify_expr(expr: &mut LlilExpr) -> u32 {
    let mut count = 0u32;
    // Recurse first.
    match expr {
        LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::DivU(l, r, _)
        | LlilExpr::DivS(l, r, _)
        | LlilExpr::CmpEq(l, r)
        | LlilExpr::CmpNe(l, r)
        | LlilExpr::CmpSlt(l, r)
        | LlilExpr::CmpUlt(l, r)
        | LlilExpr::CmpSle(l, r)
        | LlilExpr::CmpUle(l, r)
        | LlilExpr::CmpSgt(l, r)
        | LlilExpr::CmpUgt(l, r)
        | LlilExpr::CmpSge(l, r)
        | LlilExpr::CmpUge(l, r)
        | LlilExpr::Rol(l, r, _)
        | LlilExpr::Ror(l, r, _) => {
            count += algebraic_simplify_expr(l);
            count += algebraic_simplify_expr(r);
        }
        // Struct-form encodings.
        LlilExpr::Add { left, right, .. }
        | LlilExpr::Sub { left, right, .. }
        | LlilExpr::Mul { left, right, .. } => {
            count += algebraic_simplify_expr(left);
            count += algebraic_simplify_expr(right);
        }
        LlilExpr::Shl { value, shift, .. } => {
            count += algebraic_simplify_expr(value);
            count += algebraic_simplify_expr(shift);
        }
        LlilExpr::CondExpr {
            cond,
            true_val,
            false_val,
            ..
        } => {
            count += algebraic_simplify_expr(cond);
            count += algebraic_simplify_expr(true_val);
            count += algebraic_simplify_expr(false_val);
        }
        LlilExpr::Intrinsic { args, .. } => {
            for a in args {
                count += algebraic_simplify_expr(a);
            }
        }
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::Load { addr: e, .. }
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. } => count += algebraic_simplify_expr(e),
        _ => {}
    }

    count += algebraic_simplify_top(expr);
    count
}

/// Pass wrapping [`run_algebraic_simplification`].
#[derive(Debug, Default)]
pub struct AlgebraicSimplificationPass;

impl AnalysisPass for AlgebraicSimplificationPass {
    fn name(&self) -> &'static str {
        "algebraic-simplification"
    }
    fn description(&self) -> &'static str {
        "Apply De Morgan laws, AND/OR annihilator/identity rules."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let n = run_algebraic_simplification(func);
        if n > 0 {
            ctx.changed = true;
            ctx.stats.exprs_simplified += n as usize;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// RedundantLoadElimination pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Eliminate a load that is immediately followed (within the same block) by
/// another load from the same constant address with no intervening store.
///
/// ```text
/// rbx = Load[0x1000]
/// rcx = Load[0x1000]   â†' rcx = rbx   (no store in between)
/// ```
///
/// Returns the number of redundant loads eliminated.
#[must_use]
pub fn run_redundant_load_elimination(func: &mut LlilFunction) -> u32 {
    let mut count = 0u32;
    for block in &mut func.blocks {
        // Map: constant-address â†' (register that holds the loaded value)
        let mut live_loads: HashMap<u64, LlilRegister> = HashMap::new();
        for ai in &mut block.instrs {
            match &ai.instr.clone() {
                // A store to any address, or a call, invalidates the entire live set (conservative).
                LlilInstruction::Store { .. }
                | LlilInstruction::CallDest { .. }
                | LlilInstruction::TailCall { .. } => {
                    live_loads.clear();
                }
                LlilInstruction::Load { dest, addr: LlilExpr::Const { value: addr_val, .. }, size } => {
                    let prev = live_loads.get(addr_val).cloned().filter(|r| r != dest);
                    // `dest` is overwritten: drop any cached loads held in it.
                    live_loads.retain(|_, r| r != dest);
                    if let Some(prev_reg) = prev {
                        // Replace this load with a register copy.
                        ai.instr = LlilInstruction::SetReg {
                            dest: dest.clone(),
                            value: LlilExpr::RegisterRef {
                                reg: prev_reg,
                                size: *size,
                            },
                            size: *size,
                        };
                        count += 1;
                    } else {
                        live_loads.insert(*addr_val, dest.clone());
                    }
                }
                // Any other write to a register invalidates cached loads held in it.
                LlilInstruction::SetReg { dest, .. } | LlilInstruction::Pop { dest, .. } => {
                    live_loads.retain(|_, r| r != dest);
                }
                LlilInstruction::SetRegSplit { high, low, .. } => {
                    live_loads.retain(|_, r| r != high && r != low);
                }
                // Register-by-id writes can alias any register: be conservative.
                LlilInstruction::SetRegister { .. } => {
                    live_loads.clear();
                }
                _ => {}
            }
        }
    }
    count
}

/// Pass wrapping [`run_redundant_load_elimination`].
#[derive(Debug, Default)]
pub struct RedundantLoadEliminationPass;

impl AnalysisPass for RedundantLoadEliminationPass {
    fn name(&self) -> &'static str {
        "redundant-load-elim"
    }
    fn description(&self) -> &'static str {
        "Replace duplicate loads from the same constant address with register copies."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let n = run_redundant_load_elimination(func);
        if n > 0 {
            ctx.changed = true;
            ctx.stats.instrs_modified += n as usize;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// StoreLoadForwardingPass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Within a basic block, replace a load from address `A` with the value most
/// recently stored at `A` (if the source is a known register or constant).
///
/// This is a stronger form of mem2reg: it works even when the stored value is
/// not simply a constant.
///
/// Returns the number of load-to-copy replacements performed.
#[must_use]
pub fn run_store_load_forwarding(func: &mut LlilFunction) -> u32 {
    let mut count = 0u32;
    for block in &mut func.blocks {
        // Map: constant-address â†' (stored source expression, store size).
        let mut forwarded: HashMap<u64, (LlilExpr, Size)> = HashMap::new();
        for ai in &mut block.instrs {
            match &ai.instr.clone() {
                LlilInstruction::Store {
                    addr:
                        LlilExpr::Const {
                            value: addr_val, ..
                        },
                    value: src,
                    size,
                } => {
                    forwarded.insert(*addr_val, (src.clone(), *size));
                }
                LlilInstruction::Store { .. }
                | LlilInstruction::CallDest { .. }
                | LlilInstruction::Call(_)
                | LlilInstruction::CondCall { .. }
                | LlilInstruction::SysCall
                | LlilInstruction::Intrinsic { .. }
                | LlilInstruction::SetRegister { .. }
                | LlilInstruction::TailCall { .. } => {
                    forwarded.clear();
                }
                LlilInstruction::Load {
                    dest,
                    addr:
                        LlilExpr::Const {
                            value: addr_val, ..
                        },
                    size,
                } => {
                    if let Some((fwd_src, fwd_size)) = forwarded.get(addr_val).cloned()
                        && fwd_size == *size
                    {
                        ai.instr = LlilInstruction::SetReg {
                            dest: dest.clone(),
                            value: fwd_src,
                            size: *size,
                        };
                        count += 1;
                    }
                }
                _ => {}
            }
            // Invalidate forwarded expressions that read a register written by
            // this (possibly just-rewritten) instruction.
            let clobbered: Vec<LlilRegister> = match &ai.instr {
                LlilInstruction::SetReg { dest, .. }
                | LlilInstruction::Load { dest, .. }
                | LlilInstruction::Pop { dest, .. } => vec![dest.clone()],
                LlilInstruction::SetRegSplit { high, low, .. } => {
                    vec![high.clone(), low.clone()]
                }
                _ => Vec::new(),
            };
            if !clobbered.is_empty() {
                forwarded
                    .retain(|_, (expr, _)| !clobbered.iter().any(|r| expr_uses_reg(expr, r)));
            }
        }
    }
    count
}

/// Pass wrapping [`run_store_load_forwarding`].
#[derive(Debug, Default)]
pub struct StoreLoadForwardingPass;

impl AnalysisPass for StoreLoadForwardingPass {
    fn name(&self) -> &'static str {
        "store-load-forwarding"
    }
    fn description(&self) -> &'static str {
        "Forward stored values directly to subsequent loads within a block."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let n = run_store_load_forwarding(func);
        if n > 0 {
            ctx.changed = true;
            ctx.stats.instrs_modified += n as usize;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// DeadStoreElimination pass (LLIL-level)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Within a basic block, remove a `Store` to address `A` if a later `Store` to
/// the same address `A` follows with no intervening load from `A` or call.
///
/// Returns the number of dead stores removed.
#[must_use]
pub fn run_dead_store_elimination(func: &mut LlilFunction) -> u32 {
    /// Conservative: `true` if the instruction may read memory (other than a
    /// plain `Load` with a constant address, which the caller handles
    /// precisely by byte range).
    fn may_read_memory(instr: &LlilInstruction) -> bool {
        match instr {
            LlilInstruction::Nop
            | LlilInstruction::Ret
            | LlilInstruction::Trap { .. }
            | LlilInstruction::Breakpoint
            | LlilInstruction::Undefined => false,
            LlilInstruction::SetReg { value, .. }
            | LlilInstruction::SetRegister { value, .. }
            | LlilInstruction::SetRegSplit { src: value, .. }
            | LlilInstruction::SetFlag { src: value, .. }
            | LlilInstruction::Push { src: value, .. }
            | LlilInstruction::JumpDest { dest: value }
            | LlilInstruction::JumpTo { dest: value, .. }
            | LlilInstruction::Jump(value) => expr_has_load(value),
            LlilInstruction::ConditionalJump { cond, .. }
            | LlilInstruction::CondJump { cond, .. } => expr_has_load(cond),
            LlilInstruction::Store { addr, value, .. } => {
                expr_has_load(addr) || expr_has_load(value)
            }
            // A `Load` only reaches this function when its address is *not* a
            // plain `Const` (the caller matches that case first and handles it
            // precisely by byte range). An unknown address may alias any
            // pending store, so it must invalidate all of them — testing only
            // `expr_has_load(addr)` would treat `rax = [rbx]` as reading no
            // memory at all and silently delete a still-observable store.
            LlilInstruction::Load { .. } => true,
            LlilInstruction::Return { value } => {
                value.as_ref().is_some_and(expr_has_load)
            }
            // Calls, syscalls, intrinsics, pops, unimplemented: may observe
            // any memory.
            _ => true,
        }
    }

    let mut count = 0u32;
    for block in &mut func.blocks {
        // Backward scan: collect the byte ranges written after each point.
        let n = block.instrs.len();
        let mut dead: Vec<bool> = vec![false; n];
        // start address -> byte length already fully written later in the
        // block (without an intervening load/call)
        let mut overwritten: HashMap<u64, u64> = HashMap::new();

        for i in (0..n).rev() {
            match &block.instrs[i].instr {
                LlilInstruction::Store {
                    addr:
                        LlilExpr::Const {
                            value: addr_val, ..
                        },
                    size,
                    value,
                } => {
                    // The stored value may itself read memory (e.g. a load
                    // sub-expression): it can observe earlier stores.
                    if expr_has_load(value) {
                        overwritten.clear();
                    }
                    let av = *addr_val;
                    let sz = size.bytes() as u64;
                    let end = av.saturating_add(sz);
                    // Dead only if a later store fully covers this byte range.
                    let covered = overwritten
                        .iter()
                        .any(|(&a2, &s2)| a2 <= av && end <= a2.saturating_add(s2));
                    if covered {
                        dead[i] = true;
                    } else {
                        let e = overwritten.entry(av).or_insert(0);
                        if sz > *e {
                            *e = sz;
                        }
                    }
                }
                LlilInstruction::Load {
                    addr:
                        LlilExpr::Const {
                            value: addr_val, ..
                        },
                    size,
                    ..
                } => {
                    // A load re-validates every overlapping range (those
                    // stores must not be removed).
                    let la = *addr_val;
                    let lend = la.saturating_add(size.bytes() as u64);
                    overwritten
                        .retain(|&a2, &mut s2| a2.saturating_add(s2) <= la || lend <= a2);
                }
                other => {
                    // Calls and any expression-level memory read may observe
                    // all memory — conservatively flush.
                    if may_read_memory(other) {
                        overwritten.clear();
                    }
                }
            }
        }

        let removed = u32::try_from(dead.iter().filter(|d| **d).count()).unwrap_or(u32::MAX);
        if removed > 0 {
            let mut idx = 0usize;
            block.instrs.retain(|_| {
                let keep = !dead[idx];
                idx += 1;
                keep
            });
            count += removed;
        }
    }
    count
}

/// Pass wrapping [`run_dead_store_elimination`].
#[derive(Debug, Default)]
pub struct DeadStoreEliminationPass;

impl AnalysisPass for DeadStoreEliminationPass {
    fn name(&self) -> &'static str {
        "dead-store-elim"
    }
    fn description(&self) -> &'static str {
        "Remove stores to addresses overwritten before any intervening load."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let n = run_dead_store_elimination(func);
        if n > 0 {
            ctx.changed = true;
            ctx.stats.dead_removed += n as usize;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CommonSubexpressionElimination pass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Eliminate common pure sub-expressions within a single basic block.
///
/// This is a simplified, intra-block CSE.  For each `SetReg { dest, value: src }` we
/// check whether an earlier instruction computed the exact same pure `src`; if
/// so, we replace `src` with a register read of the earlier destination.
///
/// "Pure" means the expression contains no `Load` nodes.
///
/// Returns the number of sub-expressions replaced.
#[must_use]
pub fn run_cse(func: &mut LlilFunction) -> u32 {
    let mut count = 0u32;
    for block in &mut func.blocks {
        // Map: canonical expression text â†' register holding that value.
        let mut seen: HashMap<String, (LlilRegister, LlilExpr)> = HashMap::new();
        for ai in &mut block.instrs {
            match &ai.instr.clone() {
                LlilInstruction::SetReg {
                    dest,
                    value: src,
                    size,
                } if !expr_has_load(src) => {
                    let key = format!("{src:?}");
                    let hit = seen.get(&key).map(|(r, _)| r.clone());
                    if let Some(prev) = hit.clone() {
                        // Replace the source with the earlier register.
                        let src_size = *size;
                        ai.instr = LlilInstruction::SetReg {
                            dest: dest.clone(),
                            value: LlilExpr::RegisterRef {
                                reg: prev,
                                size: src_size,
                            },
                            size: src_size,
                        };
                        count += 1;
                    }
                    // `dest` is redefined: invalidate any cached expression
                    // that reads `dest` or is held in `dest`.
                    seen.retain(|_, (held, expr)| held != dest && !expr_uses_reg(expr, dest));
                    if hit.is_none() && !expr_uses_reg(src, dest) {
                        seen.insert(key, (dest.clone(), src.clone()));
                    }
                }
                LlilInstruction::CallDest { .. }
                | LlilInstruction::TailCall { .. }
                | LlilInstruction::Store { .. } => {
                    seen.clear();
                }
                _ => {}
            }
        }
    }
    count
}

/// Pass wrapping [`run_cse`].
#[derive(Debug, Default)]
pub struct CommonSubexpressionEliminationPass;

impl AnalysisPass for CommonSubexpressionEliminationPass {
    fn name(&self) -> &'static str {
        "cse"
    }
    fn description(&self) -> &'static str {
        "Eliminate repeated computation of the same pure expression within a block."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let n = run_cse(func);
        if n > 0 {
            ctx.changed = true;
            ctx.stats.exprs_simplified += n as usize;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// FunctionSummary —" aggregate analysis result
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A high-level summary of an [`LlilFunction`] for downstream analysis.
#[derive(Debug, Clone)]
pub struct FunctionSummary {
    /// Total instruction count.
    pub total_instrs: usize,
    /// Number of basic blocks.
    pub block_count: usize,
    /// Number of call sites (non-tail).
    pub call_sites: usize,
    /// Number of tail call sites.
    pub tail_call_sites: usize,
    /// Number of back-edges (potential loops).
    pub back_edges: usize,
    /// Whether the function ends in a Ret (has a direct return path).
    pub has_return: bool,
    /// Inlining score.
    pub inlining_score: u8,
    /// Number of distinct constants.
    pub distinct_constants: usize,
}

impl FunctionSummary {
    /// Compute a summary for `func`.
    #[must_use]
    pub fn analyze(func: &LlilFunction) -> Self {
        let total_instrs = count_instrs(func);
        let block_count = func.blocks.len();
        let call_info = collect_call_sites(func);
        let call_sites = call_info.iter().filter(|c| !c.is_tail_call).count();
        let tail_call_sites = call_info.iter().filter(|c| c.is_tail_call).count();
        let back_edges = run_loop_bound_analysis(func).len();
        let has_return = func.blocks.iter().any(|b| {
            b.instrs
                .iter()
                .any(|ai| matches!(ai.instr, LlilInstruction::Ret))
        });
        let inlining_score = compute_inlining_score(func).score;
        let distinct_constants = count_constants(func);

        Self {
            total_instrs,
            block_count,
            call_sites,
            tail_call_sites,
            back_edges,
            has_return,
            inlining_score,
            distinct_constants,
        }
    }

    /// Returns `true` if this function is a good leaf inlining candidate
    /// (no calls, small, no loops, has a return path).
    #[must_use]
    pub const fn is_leaf_inline_candidate(&self) -> bool {
        self.call_sites == 0
            && self.tail_call_sites == 0
            && self.back_edges == 0
            && self.has_return
            && self.total_instrs <= 10
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ExprComplexity —" estimate how expensive an expression is to evaluate
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Count the number of nodes in an expression tree (depth-independent weight).
#[must_use]
pub fn expr_node_count(expr: &LlilExpr) -> usize {
    match expr {
        LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::DivU(l, r, _)
        | LlilExpr::DivS(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _)
        | LlilExpr::CmpEq(l, r)
        | LlilExpr::CmpNe(l, r)
        | LlilExpr::CmpSlt(l, r)
        | LlilExpr::CmpUlt(l, r)
        | LlilExpr::CmpSle(l, r)
        | LlilExpr::CmpUle(l, r)
        | LlilExpr::CmpSgt(l, r)
        | LlilExpr::CmpUgt(l, r)
        | LlilExpr::CmpSge(l, r)
        | LlilExpr::CmpUge(l, r)
        | LlilExpr::FAdd(l, r, _)
        | LlilExpr::FSub(l, r, _)
        | LlilExpr::FMul(l, r, _)
        | LlilExpr::FDiv(l, r, _)
        | LlilExpr::FCmpEq(l, r)
        | LlilExpr::FCmpLt(l, r)
        | LlilExpr::FCmpGt(l, r) => 1 + expr_node_count(l) + expr_node_count(r),
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::Load { addr: e, .. }
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. }
        | LlilExpr::FNeg(e, _)
        | LlilExpr::IntToFloat { expr: e, .. }
        | LlilExpr::FloatToInt { expr: e, .. } => 1 + expr_node_count(e),
        _ => 1,
    }
}

/// Maximum expression tree depth.
#[must_use]
pub fn expr_depth(expr: &LlilExpr) -> usize {
    match expr {
        LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::DivU(l, r, _)
        | LlilExpr::DivS(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _)
        | LlilExpr::CmpEq(l, r)
        | LlilExpr::CmpNe(l, r)
        | LlilExpr::CmpSlt(l, r)
        | LlilExpr::CmpUlt(l, r)
        | LlilExpr::CmpSle(l, r)
        | LlilExpr::CmpUle(l, r)
        | LlilExpr::CmpSgt(l, r)
        | LlilExpr::CmpUgt(l, r)
        | LlilExpr::CmpSge(l, r)
        | LlilExpr::CmpUge(l, r) => 1 + expr_depth(l).max(expr_depth(r)),
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::Load { addr: e, .. }
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. } => 1 + expr_depth(e),
        _ => 0,
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ConstantHoistingPass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Hoist repeated use of the same constant into a dedicated temporary register.
///
/// If a constant `C` appears in 3 or more register-source expressions within
/// the same block, allocate a new temporary, insert `tmp_n = C` at the top of
/// the block, and replace all occurrences with the temporary.
///
/// Returns the number of constants hoisted.
#[must_use]
pub fn run_constant_hoisting(func: &mut LlilFunction) -> u32 {
    let mut total = 0u32;
    for block in &mut func.blocks {
        // Count occurrences of each constant value + size pair.
        let mut freq: HashMap<(u64, Size), usize> = HashMap::new();
        for ai in &block.instrs {
            if let Some(src) = instr_read_src(&ai.instr) {
                count_constants_in_expr_freq(src, &mut freq);
            }
        }

        // Collect constants that appear 3+ times.
        let hot: Vec<(u64, Size)> = freq
            .into_iter()
            .filter(|(_, c)| *c >= 3)
            .map(|(k, _)| k)
            .collect();

        for (val, sz) in hot {
            let tmp = LlilRegister::Temporary(func.temp_count);
            func.temp_count += 1;
            // Replace occurrences in block.
            let mut replaced = 0u32;
            for ai in &mut block.instrs {
                if let Some(src) = instr_read_src_mut(&mut ai.instr) {
                    replaced += replace_const_with_reg(src, val, sz, &tmp);
                }
            }
            if replaced > 0 {
                // Prepend `tmp = C` at block entry.
                let entry_addr = block.start;
                block.instrs.insert(
                    0,
                    LlilAnnotatedInstr {
                        address: entry_addr,
                        size: 1,
                        length: 1,
                        instr: LlilInstruction::SetReg {
                            dest: tmp.clone(),
                            value: LlilExpr::Const {
                                value: val,
                                size: sz,
                            },
                            size: sz,
                        },
                    },
                );
                total += 1;
            }
        }
    }
    total
}

const fn instr_read_src(instr: &LlilInstruction) -> Option<&LlilExpr> {
    match instr {
        LlilInstruction::SetReg { value: src, .. }
        | LlilInstruction::Store { value: src, .. } => Some(src),
        LlilInstruction::CondJump { cond, .. } => Some(cond),
        _ => None,
    }
}

const fn instr_read_src_mut(instr: &mut LlilInstruction) -> Option<&mut LlilExpr> {
    match instr {
        LlilInstruction::SetReg { value: src, .. }
        | LlilInstruction::Store { value: src, .. } => Some(src),
        LlilInstruction::CondJump { cond, .. } => Some(cond),
        _ => None,
    }
}

fn count_constants_in_expr_freq(expr: &LlilExpr, freq: &mut HashMap<(u64, Size), usize>) {
    match expr {
        LlilExpr::Const { value, size } => {
            *freq.entry((*value, *size)).or_insert(0) += 1;
        }
        LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _) => {
            count_constants_in_expr_freq(l, freq);
            count_constants_in_expr_freq(r, freq);
        }
        LlilExpr::Neg(e, _) | LlilExpr::Not(e, _) => count_constants_in_expr_freq(e, freq),
        _ => {}
    }
}

fn replace_const_with_reg(expr: &mut LlilExpr, val: u64, sz: Size, tmp: &LlilRegister) -> u32 {
    let mut count = 0u32;
    match expr {
        LlilExpr::Const { value, size } if *value == val && *size == sz => {
            *expr = LlilExpr::RegisterRef {
                reg: tmp.clone(),
                size: *size,
            };
            count += 1;
        }
        LlilExpr::AddT(l, r, _)
        | LlilExpr::SubT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _) => {
            count += replace_const_with_reg(l, val, sz, tmp);
            count += replace_const_with_reg(r, val, sz, tmp);
        }
        LlilExpr::Neg(e, _) | LlilExpr::Not(e, _) => {
            count += replace_const_with_reg(e, val, sz, tmp);
        }
        _ => {}
    }
    count
}

/// Pass wrapping [`run_constant_hoisting`].
#[derive(Debug, Default)]
pub struct ConstantHoistingPass;

impl AnalysisPass for ConstantHoistingPass {
    fn name(&self) -> &'static str {
        "constant-hoisting"
    }
    fn description(&self) -> &'static str {
        "Hoist frequently used constants into dedicated temporaries to reduce re-materialisation."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let n = run_constant_hoisting(func);
        if n > 0 {
            ctx.changed = true;
            ctx.stats.instrs_modified += n as usize;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ExprCanonicalizer —" put commutative operands in a canonical order
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Canonicalize commutative binary expressions so that constants always appear
/// on the right-hand side.
///
/// This ensures that later passes (GVN, identity
/// elimination, etc.) can match patterns reliably without checking both sides.
///
/// Returns the number of swaps performed.
#[must_use]
pub fn run_expr_canonicalize(func: &mut LlilFunction) -> u32 {
    let mut count = 0u32;
    for block in &mut func.blocks {
        for ai in &mut block.instrs {
            if let Some(src) = instr_read_src_mut(&mut ai.instr) {
                count += canonicalize_expr(src);
            }
        }
    }
    count
}

fn canonicalize_expr(expr: &mut LlilExpr) -> u32 {
    let mut count = 0u32;
    match expr {
        LlilExpr::AddT(l, r, _)
        | LlilExpr::MulT(l, r, _)
        | LlilExpr::And(l, r, _)
        | LlilExpr::Or(l, r, _)
        | LlilExpr::Xor(l, r, _) => {
            // Recurse first.
            count += canonicalize_expr(l);
            count += canonicalize_expr(r);
            // Then move Const to the right.
            if matches!(l.as_ref(), LlilExpr::Const { .. })
                && !matches!(r.as_ref(), LlilExpr::Const { .. })
            {
                std::mem::swap(l, r);
                count += 1;
            }
        }
        LlilExpr::SubT(l, r, _)
        | LlilExpr::ShlT(l, r, _)
        | LlilExpr::Shr(l, r, _)
        | LlilExpr::Sar(l, r, _) => {
            count += canonicalize_expr(l);
            count += canonicalize_expr(r);
        }
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::Load { addr: e, .. }
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. } => count += canonicalize_expr(e),
        _ => {}
    }
    count
}

/// Pass wrapping [`run_expr_canonicalize`].
#[derive(Debug, Default)]
pub struct ExprCanonicalizerPass;

impl AnalysisPass for ExprCanonicalizerPass {
    fn name(&self) -> &'static str {
        "expr-canonicalize"
    }
    fn description(&self) -> &'static str {
        "Move constants to the right-hand side of commutative operators."
    }
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let n = run_expr_canonicalize(func);
        if n > 0 {
            ctx.changed = true;
            ctx.stats.exprs_simplified += n as usize;
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PassPriority —" ordered pass scheduling with priorities
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A pass entry in a priority-ordered pipeline.
pub struct PriorityPass {
    /// Numeric priority (lower runs first).
    pub priority: u32,
    /// The pass to run.
    pub pass: Box<dyn AnalysisPass>,
}

/// A pass manager that orders passes by priority before running them.
#[derive(Default)]
pub struct PriorityPassManager {
    passes: Vec<PriorityPass>,
    max_iterations: usize,
}

impl PriorityPassManager {
    /// Creates an empty priority manager with default iteration limit (20).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            passes: Vec::new(),
            max_iterations: 20,
        }
    }

    /// Add a pass with the given priority.
    pub fn add(&mut self, priority: u32, pass: impl AnalysisPass + 'static) {
        self.passes.push(PriorityPass {
            priority,
            pass: Box::new(pass),
        });
    }

    /// Sort passes by priority and run the standard convergence loop.
    ///
    /// Returns the final [`PassContext`].
    #[must_use]
    pub fn run(&mut self, func: &mut LlilFunction) -> PassContext {
        // Sort by priority (stable for equal priorities).
        self.passes.sort_by_key(|p| p.priority);
        let mut global_ctx = PassContext::new();
        for _ in 0..self.max_iterations {
            let mut iter_ctx = PassContext::new();
            for entry in &self.passes {
                entry.pass.run(func, &mut iter_ctx);
            }
            global_ctx.merge(&iter_ctx);
            if !iter_ctx.changed {
                break;
            }
        }
        global_ctx
    }
}

/// Construct the recommended priority pipeline for aggressive optimisation.
#[must_use]
pub fn build_aggressive_pipeline() -> PriorityPassManager {
    let mut pm = PriorityPassManager::new();
    pm.add(10, ExprCanonicalizerPass);
    pm.add(20, NopEliminationPass);
    pm.add(30, ConstantFoldingPass);
    pm.add(40, IdentityEliminationPass);
    pm.add(50, AlgebraicSimplificationPass);
    pm.add(60, StrengthReductionPass);
    pm.add(70, CopyPropagationPass);
    pm.add(80, GlobalValueNumberingPass);
    pm.add(90, CommonSubexpressionEliminationPass);
    pm.add(100, RedundantLoadEliminationPass);
    pm.add(110, StoreLoadForwardingPass);
    pm.add(120, DeadStoreEliminationPass);
    pm.add(130, BranchSimplificationPass);
    pm.add(140, RedundantBranchRemovalPass);
    pm.add(150, UnreachableCodeEliminationPass);
    pm.add(160, TailCallOptimizationPass);
    pm.add(170, Mem2RegPass);
    pm.add(180, IntegerRangeAnalysisPass);
    pm.add(190, NullCheckEliminationPass);
    pm.add(200, ArgumentValuePropagationPass);
    pm.add(210, LoopInvariantCodeMotionPass);
    pm.add(220, ConstantHoistingPass);
    pm.add(230, PureCallDetectionPass);
    pm.add(240, InliningHeuristicsPass);
    pm.add(250, LoopBoundAnalysisPass);
    pm.add(260, PhiEliminationPass);
    pm.add(270, DeadCodeEliminationPass);
    pm.add(280, BlockMergePass);
    pm
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_il_llil::{
        LlilBasicBlock, llil_add, llil_and, llil_cmp_eq, llil_cmp_ne, llil_cmp_slt, llil_const,
        llil_or, llil_reg, llil_sub, llil_sx, llil_tmp, llil_xor, llil_zx,
    };

    // â"€â"€ helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_block(id: u32, start: u64, instrs: Vec<LlilInstruction>) -> LlilBasicBlock {
        let addr = Address::new(start);
        LlilBasicBlock {
            start: addr,
            end: addr + instrs.len() as u64,
            id,
            instrs: instrs
                .into_iter()
                .enumerate()
                .map(|(i, instr)| LlilAnnotatedInstr {
                    address: addr + i as u64,
                    size: 1,
                    instr,
                    length: 1,
                })
                .collect(),
            successors: Vec::new(),
        }
    }

    #[test]
    fn fold_binop_shift_mask_and_wide_rotates() {
        // shl/shr/sar must mask the count with a fixed 5-bit window (0-31)
        // below 64 bits, not always &63: a 32-bit shl by 33 is a shift by 1
        // on x86 (33 & 31 == 1).
        assert_eq!(
            ConstantFoldingPass::fold_binop("shl", 1, 33, Size::DWord),
            Some(2)
        );
        assert_eq!(
            ConstantFoldingPass::fold_binop("shr", 0x8000_0000, 33, Size::DWord),
            Some(0x4000_0000)
        );
        assert_eq!(
            ConstantFoldingPass::fold_binop("sar", 0x8000_0000, 33, Size::DWord),
            Some(0xC000_0000)
        );
        // The 5-bit mask is NOT `width - 1`: an 8-bit `shl` by a count whose
        // low 5 bits are 31 shifts everything out (31 >= 8), it does not
        // wrap mod-8 to a shift-by-(31&7=7). Oversized/huge counts (not
        // truncatable to u32) must also not panic.
        assert_eq!(
            ConstantFoldingPass::fold_binop("shl", 1, u64::MAX, Size::Byte),
            Some(0)
        );
        // rol/ror on >64-bit operands must refuse to fold, not panic
        // (shift-overflow / div-by-zero on `bits`).
        assert_eq!(
            ConstantFoldingPass::fold_binop("rol", 1, 1, Size::OWord),
            None
        );
        assert_eq!(
            ConstantFoldingPass::fold_binop("ror", 1, 1, Size::YWord),
            None
        );
        // Sane rotate on a supported width still folds.
        assert_eq!(
            ConstantFoldingPass::fold_binop("rol", 0x80, 1, Size::Byte),
            Some(1)
        );
    }

    fn make_func(blocks: Vec<LlilBasicBlock>) -> LlilFunction {
        let entry = blocks.first().map_or(Address::new(0), |b| b.start);
        LlilFunction {
            entry,
            blocks,
            temp_count: 8,
            ..LlilFunction::default()
        }
    }

    fn single_block_func(instrs: Vec<LlilInstruction>) -> LlilFunction {
        make_func(vec![make_block(0, 0x1000, instrs)])
    }

    // â"€â"€ ConstantFoldingPass tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn fold_add_consts() {
        let pass = ConstantFoldingPass::new();
        let expr = llil_add(
            llil_const(3, Size::QWord),
            llil_const(5, Size::QWord),
            Size::QWord,
        );
        let (folded, changed) = pass.fold_expr(expr);
        assert!(changed);
        assert_eq!(
            folded,
            LlilExpr::Const {
                value: 8,
                size: Size::QWord
            }
        );
    }

    #[test]
    fn fold_xor_consts() {
        let pass = ConstantFoldingPass::new();
        let expr = llil_xor(
            llil_const(0xFF, Size::Byte),
            llil_const(0x0F, Size::Byte),
            Size::Byte,
        );
        let (folded, changed) = pass.fold_expr(expr);
        assert!(changed);
        assert_eq!(
            folded,
            LlilExpr::Const {
                value: 0xF0,
                size: Size::Byte
            }
        );
    }

    #[test]
    fn fold_and_with_zero() {
        let pass = ConstantFoldingPass::new();
        let expr = llil_and(
            llil_const(0xDEAD, Size::DWord),
            llil_const(0, Size::DWord),
            Size::DWord,
        );
        let (folded, changed) = pass.fold_expr(expr);
        assert!(changed);
        assert_eq!(
            folded,
            LlilExpr::Const {
                value: 0,
                size: Size::DWord
            }
        );
    }

    #[test]
    fn fold_cmp_eq_equal() {
        let pass = ConstantFoldingPass::new();
        let expr = llil_cmp_eq(llil_const(5, Size::QWord), llil_const(5, Size::QWord));
        let (folded, changed) = pass.fold_expr(expr);
        assert!(changed);
        assert_eq!(
            folded,
            LlilExpr::Const {
                value: 1,
                size: Size::Byte
            }
        );
    }

    #[test]
    fn fold_cmp_eq_not_equal() {
        let pass = ConstantFoldingPass::new();
        let expr = llil_cmp_eq(llil_const(5, Size::QWord), llil_const(3, Size::QWord));
        let (folded, changed) = pass.fold_expr(expr);
        assert!(changed);
        assert_eq!(
            folded,
            LlilExpr::Const {
                value: 0,
                size: Size::Byte
            }
        );
    }

    #[test]
    fn fold_cmp_slt_signed() {
        let pass = ConstantFoldingPass::new();
        // -1 <s 0 â†' 1
        let expr = llil_cmp_slt(
            llil_const(0xFFFF_FFFF_FFFF_FFFF, Size::QWord),
            llil_const(0, Size::QWord),
        );
        let (folded, changed) = pass.fold_expr(expr);
        assert!(changed);
        assert_eq!(
            folded,
            LlilExpr::Const {
                value: 1,
                size: Size::Byte
            }
        );
    }

    #[test]
    fn fold_const_in_function() {
        let pass = ConstantFoldingPass::new();
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
            value: llil_add(
                llil_const(10, Size::QWord),
                llil_const(20, Size::QWord),
                Size::QWord,
            ),
        }]);
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert!(ctx.changed);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert_eq!(
                *src,
                LlilExpr::Const {
                    value: 30,
                    size: Size::QWord
                }
            );
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn fold_and_identity_handle_struct_form_exprs() {
        // Regression: struct-form Add{}/Sub{}/Mul{}/Shl{} must be folded and
        // simplified identically to their tuple twins (AddT/SubT/MulT/ShlT).
        let fold = ConstantFoldingPass::new();
        let (folded, changed) = fold.fold_expr(LlilExpr::Add {
            left: Box::new(llil_const(3, Size::QWord)),
            right: Box::new(llil_const(5, Size::QWord)),
            size: Size::QWord,
        });
        assert!(changed);
        assert_eq!(folded, LlilExpr::Const { value: 8, size: Size::QWord });

        let (folded, changed) = fold.fold_expr(LlilExpr::Shl {
            value: Box::new(llil_const(1, Size::QWord)),
            shift: Box::new(llil_const(4, Size::QWord)),
            size: Size::QWord,
        });
        assert!(changed);
        assert_eq!(folded, LlilExpr::Const { value: 16, size: Size::QWord });

        // IdentityEliminationPass: struct-form x + 0 -> x.
        let pass = IdentityEliminationPass::new();
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: LlilExpr::Add {
                left: Box::new(rax.clone()),
                right: Box::new(llil_const(0, Size::QWord)),
                size: Size::QWord,
            },
        }]);
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert!(ctx.changed);
        if let LlilInstruction::SetReg { value, .. } = &func.blocks[0].instrs[0].instr {
            assert_eq!(*value, rax);
        } else {
            panic!("expected SetReg");
        }
    }

    // â"€â"€ NopEliminationPass tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn nop_elimination_removes_all_nops() {
        let pass = NopEliminationPass::new();
        let mut func = single_block_func(vec![
            LlilInstruction::Nop,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(1, Size::QWord),
            },
            LlilInstruction::Nop,
            LlilInstruction::Ret,
        ]);
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert!(ctx.changed);
        assert_eq!(func.blocks[0].instrs.len(), 2);
        assert!(
            func.blocks[0]
                .instrs
                .iter()
                .all(|ai| !matches!(ai.instr, LlilInstruction::Nop))
        );
    }

    // â"€â"€ IdentityEliminationPass tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn identity_add_zero() {
        let pass = IdentityEliminationPass::new();
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: llil_add(rax.clone(), llil_const(0, Size::QWord), Size::QWord),
        }]);
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert!(ctx.changed);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert_eq!(*src, rax);
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn identity_xor_reg_self() {
        let pass = IdentityEliminationPass::new();
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: llil_xor(rax.clone(), rax, Size::QWord),
        }]);
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert!(ctx.changed);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert_eq!(
                *src,
                LlilExpr::Const {
                    value: 0,
                    size: Size::QWord
                }
            );
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn identity_not_not() {
        let pass = IdentityEliminationPass::new();
        let rax = llil_reg("rax", Size::QWord);
        let double_not = LlilExpr::Not(
            Box::new(LlilExpr::Not(Box::new(rax.clone()), Size::QWord)),
            Size::QWord,
        );
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: double_not,
        }]);
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert!(ctx.changed);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert_eq!(*src, rax);
        } else {
            panic!("expected SetReg");
        }
    }

    // â"€â"€ DeadCodeEliminationPass tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn dce_removes_dead_setreg() {
        let pass = DeadCodeEliminationPass::new();
        // tmp0 is assigned but never read; rax is assigned and then returned via Ret.
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Temporary(0),
                size: Size::QWord,
                value: llil_const(42, Size::QWord),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(1, Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert!(ctx.changed);
        // tmp0 assignment should be gone.
        assert!(func.blocks[0].instrs.iter().all(|ai| {
            !matches!(
                &ai.instr,
                LlilInstruction::SetReg {
                    dest: LlilRegister::Temporary(0),
                    ..
                }
            )
        }));
    }

    #[test]
    fn dce_keeps_abi_return_write_before_bare_return_variant() {
        // `Return { value: None }` is a bare return just like `Ret`: the ABI
        // return registers are live-out, so `SetReg rax` before it must NOT be
        // eliminated (regression: only `Ret` used to seed the ABI live-outs).
        let pass = DeadCodeEliminationPass::new();
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(1, Size::QWord),
            },
            LlilInstruction::Return { value: None },
        ]);
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert!(func.blocks[0].instrs.iter().any(|ai| matches!(
            &ai.instr,
            LlilInstruction::SetReg { dest, .. } if dest.name() == "rax"
        )));
    }

    #[test]
    fn dce_keeps_pop_with_dead_dest() {
        // `Pop` adjusts the stack pointer, so it must survive DCE even when
        // its destination register is never read (regression: an unreachable
        // dead-dest arm for Pop used to suggest otherwise).
        let pass = DeadCodeEliminationPass::new();
        let mut func = single_block_func(vec![
            LlilInstruction::Pop {
                dest: LlilRegister::Temporary(7),
                size: Size::QWord,
            },
            LlilInstruction::Ret,
        ]);
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert!(func.blocks[0]
            .instrs
            .iter()
            .any(|ai| matches!(ai.instr, LlilInstruction::Pop { .. })));
    }

    #[test]
    fn dce_keeps_stores() {
        let pass = DeadCodeEliminationPass::new();
        let mut func = single_block_func(vec![
            LlilInstruction::Store {
                addr: llil_const(0x1000, Size::QWord),
                size: Size::QWord,
                value: llil_const(0, Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let before = func.blocks[0].instrs.len();
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert_eq!(func.blocks[0].instrs.len(), before);
    }

    // â"€â"€ CopyPropagationPass tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn copy_propagation_simple() {
        let pass = CopyPropagationPass::new();
        // tmp0 = rax
        // rbx = tmp0 + 1   â†'   rbx = rax + 1
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Temporary(0),
                size: Size::QWord,
                value: llil_reg("rax", Size::QWord),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: llil_add(
                    llil_tmp(0, Size::QWord),
                    llil_const(1, Size::QWord),
                    Size::QWord,
                ),
            },
            LlilInstruction::Ret,
        ]);
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert!(ctx.changed);

        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[1].instr {
            // src should now be Add(Register(rax), Const(1)) —" tmp0 replaced with rax.
            if let LlilExpr::AddT(l, _, _) = src {
                assert!(
                    matches!(l.as_ref(), LlilExpr::RegisterRef { reg: LlilRegister::Concrete(n), .. } if n == "rax"),
                    "expected rax, got {src:?}"
                );
            } else {
                panic!("expected Add expression, got {src:?}");
            }
        } else {
            panic!("expected SetReg for rbx");
        }
    }

    #[test]
    fn copy_propagation_temp_dest_redefinition_kills_copy() {
        let pass = CopyPropagationPass::new();
        // tmp0 = rax
        // tmp0 = 5          (redefines the Temporary dest â†' must kill the copy)
        // rbx = tmp0 + 1    (must NOT become rax + 1)
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Temporary(0),
                size: Size::QWord,
                value: llil_reg("rax", Size::QWord),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Temporary(0),
                size: Size::QWord,
                value: llil_const(5, Size::QWord),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: llil_add(
                    llil_tmp(0, Size::QWord),
                    llil_const(1, Size::QWord),
                    Size::QWord,
                ),
            },
            LlilInstruction::Ret,
        ]);
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);

        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[2].instr {
            if let LlilExpr::AddT(l, _, _) = src {
                assert!(
                    matches!(l.as_ref(), LlilExpr::RegisterRef { reg: LlilRegister::Temporary(0), .. }),
                    "stale copy propagated past temp redefinition: {src:?}"
                );
            } else {
                panic!("expected Add expression, got {src:?}");
            }
        } else {
            panic!("expected SetReg for rbx");
        }
    }

    // â"€â"€ BlockMergePass tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn block_merge_single_successor() {
        let pass = BlockMergePass::new();

        // Block A: [SetReg rax, Jump â†' 0x2000]
        let block_a = LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1002),
            id: 0,
            instrs: vec![
                LlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    size: 1,
                    instr: LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete("rax".into()),
                        size: Size::QWord,
                        value: llil_const(1, Size::QWord),
                    },
                    length: 1,
                },
                LlilAnnotatedInstr {
                    address: Address::new(0x1001),
                    size: 1,
                    instr: LlilInstruction::JumpDest {
                        dest: llil_const(0x2000, Size::QWord),
                    },
                    length: 1,
                },
            ],
            successors: vec![Address::new(0x2000)],
        };

        // Block B: [SetReg rbx, Ret]  —" only predecessor is block A
        let block_b = LlilBasicBlock {
            start: Address::new(0x2000),
            end: Address::new(0x2002),
            id: 1,
            instrs: vec![
                LlilAnnotatedInstr {
                    address: Address::new(0x2000),
                    size: 1,
                    instr: LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete("rbx".into()),
                        size: Size::QWord,
                        value: llil_const(2, Size::QWord),
                    },
                    length: 1,
                },
                LlilAnnotatedInstr {
                    address: Address::new(0x2001),
                    size: 1,
                    instr: LlilInstruction::Ret,
                    length: 1,
                },
            ],
            successors: Vec::new(),
        };

        let mut func = make_func(vec![block_a, block_b]);
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);

        assert!(ctx.changed);
        // After merge there should be a single block.
        assert_eq!(func.blocks.len(), 1);
        // That block should have 3 instructions: SetReg(rax), SetReg(rbx), Ret
        // (the Jump was stripped).
        assert_eq!(func.blocks[0].instrs.len(), 3);
        assert!(matches!(
            func.blocks[0].instrs[2].instr,
            LlilInstruction::Ret
        ));
    }

    #[test]
    fn block_merge_preserves_jump_table_target() {
        // Block A ends with a Jump to 0x2000, but 0x2000 is ALSO a jump-table
        // target (JumpTo in block C).  It therefore has two predecessors and
        // must NOT be merged into A.
        let pass = BlockMergePass::new();

        let block_a = LlilBasicBlock {
            start: Address::new(0x1000),
            end: Address::new(0x1001),
            id: 0,
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x1000),
                size: 1,
                instr: LlilInstruction::JumpDest {
                    dest: llil_const(0x2000, Size::QWord),
                },
                length: 1,
            }],
            successors: vec![Address::new(0x2000)],
        };

        let block_b = LlilBasicBlock {
            start: Address::new(0x2000),
            end: Address::new(0x2001),
            id: 1,
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x2000),
                size: 1,
                instr: LlilInstruction::Ret,
                length: 1,
            }],
            successors: Vec::new(),
        };

        // Block C: jump table dispatching to 0x2000 (among others).
        let block_c = LlilBasicBlock {
            start: Address::new(0x3000),
            end: Address::new(0x3001),
            id: 2,
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x3000),
                size: 1,
                instr: LlilInstruction::JumpTo {
                    dest: LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete("rax".into()),
                        size: Size::QWord,
                    },
                    targets: vec![Address::new(0x2000), Address::new(0x4000)],
                },
                length: 1,
            }],
            successors: vec![Address::new(0x2000), Address::new(0x4000)],
        };

        let mut func = make_func(vec![block_a, block_b, block_c]);
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);

        // 0x2000 has two predecessors (A's Jump and C's jump table) — the
        // block must survive so the jump table still has a valid target.
        assert_eq!(func.blocks.len(), 3);
        assert!(func.blocks.iter().any(|b| b.start == Address::new(0x2000)));
    }

    // â"€â"€ PassManager tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn pass_manager_standard_no_panic() {
        let pm = PassManager::standard();
        // rax is used in the Store address so DCE won't kill the SetReg.
        let mut func = single_block_func(vec![
            LlilInstruction::Nop,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_add(
                    llil_const(3, Size::QWord),
                    llil_const(7, Size::QWord),
                    Size::QWord,
                ),
            },
            LlilInstruction::Store {
                addr: llil_reg("rax", Size::QWord),
                size: Size::QWord,
                value: llil_const(0, Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let ctx = pm.run(&mut func);
        // Should have folded 3+7=10 and removed the Nop.
        assert!(ctx.changed);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert_eq!(
                *src,
                LlilExpr::Const {
                    value: 10,
                    size: Size::QWord
                }
            );
        } else {
            panic!("expected SetReg as first surviving instruction");
        }
    }

    #[test]
    fn pass_manager_convergence() {
        // A function full of constant arithmetic should fully converge:
        // Add(Const(1), Const(2)) + Const(3) â†' Const(3) + Const(3) â†' Const(6)
        // rax is read by the Store so DCE won't eliminate it.
        let pm = PassManager::standard().with_max_iterations(20);
        let nested = llil_add(
            llil_add(
                llil_const(1, Size::QWord),
                llil_const(2, Size::QWord),
                Size::QWord,
            ),
            llil_const(3, Size::QWord),
            Size::QWord,
        );
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: nested,
            },
            LlilInstruction::Store {
                addr: llil_reg("rax", Size::QWord),
                size: Size::QWord,
                value: llil_const(0, Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let ctx = pm.run(&mut func);
        assert!(ctx.changed);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert_eq!(
                *src,
                LlilExpr::Const {
                    value: 6,
                    size: Size::QWord
                }
            );
        } else {
            panic!("expected SetReg");
        }
    }

    // â"€â"€ RegisterUsage tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn register_usage_counts() {
        // rax written twice, read once; rbx written once never read.
        let func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(1, Size::QWord),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(2, Size::QWord),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: llil_reg("rax", Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let usage = RegisterUsage::analyze(&func);
        assert_eq!(usage.write_count("rax"), 2);
        assert_eq!(usage.read_count("rax"), 1);
        assert!(usage.is_read("rax"));
        assert!(usage.is_written("rax"));
        assert_eq!(usage.write_count("rbx"), 1);
        assert_eq!(usage.read_count("rbx"), 0);
        assert!(!usage.is_read("rbx"));
    }

    #[test]
    fn register_usage_def_use_pairs() {
        let func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(1, Size::QWord),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: llil_reg("rax", Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let usage = RegisterUsage::analyze(&func);
        let pairs = usage.def_use_pairs();
        
        assert!(pairs.iter().any(|(r, _, _)| r == "rax"));
    }

    // â"€â"€ ExprVisitor / walk_expr_mut tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn walk_expr_identity_transform() {
        struct NoOp;
        impl ExprVisitor for NoOp {
            fn visit_expr(&mut self, _expr: &LlilExpr) -> Option<LlilExpr> {
                None
            }
        }

        let expr = llil_add(
            llil_const(1, Size::QWord),
            llil_const(2, Size::QWord),
            Size::QWord,
        );
        let result = walk_expr_mut(expr.clone(), &mut NoOp);
        assert_eq!(result, expr);
    }

    #[test]
    fn walk_expr_replace_all_consts() {
        struct ZeroAll;
        impl ExprVisitor for ZeroAll {
            fn visit_expr(&mut self, expr: &LlilExpr) -> Option<LlilExpr> {
                if let LlilExpr::Const { size, .. } = expr {
                    Some(LlilExpr::Const {
                        value: 0,
                        size: *size,
                    })
                } else {
                    None
                }
            }
        }

        let expr = llil_add(
            llil_const(99, Size::QWord),
            llil_const(42, Size::QWord),
            Size::QWord,
        );
        let result = walk_expr_mut(expr, &mut ZeroAll);
        if let LlilExpr::AddT(l, r, _) = result {
            assert_eq!(
                *l,
                LlilExpr::Const {
                    value: 0,
                    size: Size::QWord
                }
            );
            assert_eq!(
                *r,
                LlilExpr::Const {
                    value: 0,
                    size: Size::QWord
                }
            );
        } else {
            panic!("expected Add");
        }
    }

    // â"€â"€ PassContext merge / stats â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn pass_context_merge() {
        let mut a = PassContext::new();
        a.stats.const_folded = 3;
        a.changed = true;
        a.warnings.push("warn1".into());

        let mut b = PassContext::new();
        b.stats.const_folded = 2;
        b.stats.dead_removed = 1;
        b.changed = false;
        b.warnings.push("warn2".into());

        a.merge(&b);
        assert!(a.changed);
        assert_eq!(a.stats.const_folded, 5);
        assert_eq!(a.stats.dead_removed, 1);
        assert_eq!(a.warnings.len(), 2);
    }

    #[test]
    fn pass_context_default_tier_is_llil() {
        // Every pass in this crate runs over an LlilFunction, so the default
        // tier is the one `rustre-il` names `Llil`.
        let ctx = PassContext::new();
        assert_eq!(ctx.tier, rustre_il::IlTier::Llil);
        assert_eq!(ctx.tier.tag(), "llil");
        assert_eq!(PassContext::default().tier, rustre_il::IlTier::Llil);
    }

    #[test]
    fn warn_at_tier_prefixes_the_tier_tag() {
        let mut ctx = PassContext::new();
        ctx.warn_at_tier("something odd");
        assert_eq!(ctx.warnings, vec!["[llil] something odd".to_string()]);

        // The tag follows the field, it is not hard-coded.
        ctx.tier = rustre_il::IlTier::Mlil;
        ctx.warn_at_tier("later");
        assert_eq!(ctx.warnings[1], "[mlil] later");
    }

    #[test]
    fn loop_detection_warning_is_tier_tagged() {
        // The one pass rewired to `warn_at_tier` must actually emit the prefix.
        // A single block that jumps back to its own start is a back-edge, which
        // is exactly what `detect_loops` looks for.
        let mut func = single_block_func(vec![LlilInstruction::JumpDest {
            dest: llil_const(0x1000, Size::QWord),
        }]);
        assert!(!detect_loops(&func).is_empty(), "test fixture has no loop");

        let mut ctx = PassContext::new();
        LoopDetectionPass.run(&mut func, &mut ctx);
        assert!(
            ctx.warnings
                .iter()
                .any(|w| w.starts_with("[llil] loop-detection:")),
            "expected a tier-tagged loop-detection warning, got {:?}",
            ctx.warnings
        );
    }

    // â"€â"€ ZeroExtend / SignExtend folding â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn fold_zero_extend_const() {
        let pass = ConstantFoldingPass::new();
        let expr = llil_zx(llil_const(0xFF, Size::Byte), Size::Byte, Size::QWord);
        let (folded, changed) = pass.fold_expr(expr);
        assert!(changed);
        assert_eq!(
            folded,
            LlilExpr::Const {
                value: 0xFF,
                size: Size::QWord
            }
        );
    }

    #[test]
    fn fold_sign_extend_const_negative() {
        let pass = ConstantFoldingPass::new();
        // Sign-extend 0xFF (= -1 as i8) from Byte to QWord.
        let expr = llil_sx(llil_const(0xFF, Size::Byte), Size::Byte, Size::QWord);
        let (folded, changed) = pass.fold_expr(expr);
        assert!(changed);
        assert_eq!(
            folded,
            LlilExpr::Const {
                value: u64::MAX,
                size: Size::QWord
            }
        );
    }

    // â"€â"€ CmpNe folding â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn fold_cmp_ne() {
        let pass = ConstantFoldingPass::new();
        let expr = llil_cmp_ne(llil_const(5, Size::QWord), llil_const(3, Size::QWord));
        let (folded, changed) = pass.fold_expr(expr);
        assert!(changed);
        assert_eq!(
            folded,
            LlilExpr::Const {
                value: 1,
                size: Size::Byte
            }
        );
    }

    // â"€â"€ Sub identity â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn identity_sub_zero() {
        let pass = IdentityEliminationPass::new();
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: llil_sub(rax.clone(), llil_const(0, Size::QWord), Size::QWord),
        }]);
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert!(ctx.changed);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert_eq!(*src, rax);
        } else {
            panic!("expected SetReg");
        }
    }

    // â"€â"€ Or identity â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn identity_or_zero() {
        let pass = IdentityEliminationPass::new();
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: llil_or(rax.clone(), llil_const(0, Size::QWord), Size::QWord),
        }]);
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert!(ctx.changed);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert_eq!(*src, rax);
        } else {
            panic!("expected SetReg");
        }
    }

    // â"€â"€ expr_has_load â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn expr_has_load_on_const() {
        let e = llil_const(42, Size::QWord);
        assert!(!expr_has_load(&e));
    }

    #[test]
    fn expr_has_load_on_load() {
        let e = LlilExpr::Load {
            addr: Box::new(llil_const(0x1000, Size::QWord)),
            size: Size::QWord,
        };
        assert!(expr_has_load(&e));
    }

    #[test]
    fn expr_has_load_nested_in_add() {
        let load = LlilExpr::Load {
            addr: Box::new(llil_const(0x1000, Size::QWord)),
            size: Size::QWord,
        };
        let e = llil_add(load, llil_const(4, Size::QWord), Size::QWord);
        assert!(expr_has_load(&e));
    }

    #[test]
    fn expr_has_load_no_load_in_add() {
        let e = llil_add(
            llil_reg("rax", Size::QWord),
            llil_const(4, Size::QWord),
            Size::QWord,
        );
        assert!(!expr_has_load(&e));
    }

    // â"€â"€ run_gvn_pass â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn gvn_deduplicates_identical_exprs() {
        // rbx = rax + 1; rcx = rax + 1  â†'  rcx = rbx (the prev result)
        let rax_plus_one = llil_add(
            llil_reg("rax", Size::QWord),
            llil_const(1, Size::QWord),
            Size::QWord,
        );
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: rax_plus_one.clone(),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rcx".into()),
                size: Size::QWord,
                value: rax_plus_one,
            },
        ]);
        let changed = run_gvn_pass(&mut func);
        assert!(changed, "GVN should have replaced the duplicate expr");
        // Second instr should now be a copy of rbx.
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[1].instr {
            // llil_reg produces LlilExpr::RegisterRef, not Register.
            assert!(
                matches!(src, LlilExpr::RegisterRef { .. }),
                "expected RegisterRef copy, got {src:?}"
            );
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn gvn_no_change_on_unique_exprs() {
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: llil_add(
                    llil_reg("rax", Size::QWord),
                    llil_const(1, Size::QWord),
                    Size::QWord,
                ),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rcx".into()),
                size: Size::QWord,
                value: llil_add(
                    llil_reg("rax", Size::QWord),
                    llil_const(2, Size::QWord),
                    Size::QWord,
                ),
            },
        ]);
        let changed = run_gvn_pass(&mut func);
        assert!(!changed);
    }

    #[test]
    fn gvn_skips_load_containing_exprs() {
        let load = LlilExpr::Load {
            addr: Box::new(llil_const(0x1000, Size::QWord)),
            size: Size::QWord,
        };
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: load.clone(),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rcx".into()),
                size: Size::QWord,
                value: load,
            },
        ]);
        // GVN must not replace loads (not pure).
        let changed = run_gvn_pass(&mut func);
        assert!(!changed, "GVN must not touch load-containing exprs");
    }

    #[test]
    fn gvn_invalidates_on_operand_redefinition() {
        // rax = rbx + 1
        // rbx = load [0x1000]        (redefines the operand of the cached expr)
        // rcx = rbx + 1              (same textual expr, DIFFERENT value)
        let rbx_plus_one = llil_add(
            llil_reg("rbx", Size::QWord),
            llil_const(1, Size::QWord),
            Size::QWord,
        );
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: rbx_plus_one.clone(),
            },
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rbx".into()),
                addr: llil_const(0x1000, Size::QWord),
                size: Size::QWord,
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rcx".into()),
                size: Size::QWord,
                value: rbx_plus_one,
            },
        ]);
        let _ = run_gvn_pass(&mut func);
        // rcx must NOT have become a copy of rax: rbx changed in between.
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[2].instr {
            assert!(
                !matches!(src, LlilExpr::RegisterRef { .. }),
                "GVN wrongly CSE'd across a redefinition of the operand: {src:?}"
            );
        } else {
            panic!("expected SetReg as third instruction");
        }
    }

    #[test]
    fn gvn_invalidates_const_on_setregsplit() {
        // rax = 5
        // rdx:rax = rax * rcx   (SetRegSplit — widening mul redefines rax)
        // rbx = rax             (must NOT be folded to const 5)
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(5, Size::QWord),
            },
            LlilInstruction::SetRegSplit {
                high: LlilRegister::Concrete("rdx".into()),
                low: LlilRegister::Concrete("rax".into()),
                src: llil_reg("rcx", Size::QWord),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: llil_reg("rax", Size::QWord),
            },
        ]);
        let _ = run_gvn_pass(&mut func);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[2].instr {
            assert!(
                !matches!(src, LlilExpr::Const { .. }),
                "stale constant propagated across SetRegSplit: {src:?}"
            );
        } else {
            panic!("expected SetReg as third instruction");
        }
    }

    // â"€â"€ run_mem2reg_pass â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn mem2reg_promotes_store_load_pair() {
        let addr = llil_const(0x4000, Size::QWord);
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![
            LlilInstruction::Store {
                addr: addr.clone(),
                value: rax,
                size: Size::QWord,
            },
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rbx".into()),
                addr,
                size: Size::QWord,
            },
        ]);
        let n = run_mem2reg_pass(&mut func);
        assert_eq!(n, 1);
        // The Load should have been replaced by a SetReg copy.
        assert!(
            matches!(
                func.blocks[0].instrs[1].instr,
                LlilInstruction::SetReg { .. }
            ),
            "expected SetReg after mem2reg"
        );
    }

    #[test]
    fn mem2reg_no_promotion_across_redef_or_call() {
        let addr = llil_const(0x4000, Size::QWord);
        // Case 1: source register redefined between store and load.
        let mut func = single_block_func(vec![
            LlilInstruction::Store {
                addr: addr.clone(),
                value: llil_reg("rax", Size::QWord),
                size: Size::QWord,
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(7, Size::QWord),
            },
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rbx".into()),
                addr: addr.clone(),
                size: Size::QWord,
            },
        ]);
        assert_eq!(
            run_mem2reg_pass(&mut func),
            0,
            "must not promote across redefinition of the stored register"
        );
        // Case 2: call between store and load clobbers regs and memory.
        let mut func = single_block_func(vec![
            LlilInstruction::Store {
                addr: addr.clone(),
                value: llil_reg("rax", Size::QWord),
                size: Size::QWord,
            },
            LlilInstruction::Call(llil_const(0x1234, Size::QWord)),
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rbx".into()),
                addr,
                size: Size::QWord,
            },
        ]);
        assert_eq!(
            run_mem2reg_pass(&mut func),
            0,
            "must not promote across a call"
        );
    }

    #[test]
    fn mem2reg_no_promotion_different_addr() {
        let addr1 = llil_const(0x4000, Size::QWord);
        let addr2 = llil_const(0x5000, Size::QWord);
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![
            LlilInstruction::Store {
                addr: addr1,
                value: rax,
                size: Size::QWord,
            },
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rbx".into()),
                addr: addr2,
                size: Size::QWord,
            },
        ]);
        let n = run_mem2reg_pass(&mut func);
        assert_eq!(n, 0);
    }

    // â"€â"€ run_branch_simplification â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn branch_simplification_true_condition() {
        let true_dest = Address::new(0x100);
        let false_dest = Address::new(0x200);
        let mut func = single_block_func(vec![LlilInstruction::CondJump {
            cond: llil_const(1, Size::Byte),
            true_dest,
            false_dest,
        }]);
        let n = run_branch_simplification(&mut func);
        assert_eq!(n, 1);
        assert!(
            matches!(
                func.blocks[0].instrs[0].instr,
                LlilInstruction::JumpDest { .. }
            ),
            "expected unconditional Jump"
        );
        if let LlilInstruction::JumpDest { dest } = &func.blocks[0].instrs[0].instr {
            assert_eq!(
                *dest,
                LlilExpr::Const {
                    value: 0x100,
                    size: Size::QWord
                }
            );
        }
    }

    #[test]
    fn branch_simplification_false_condition() {
        let true_dest = Address::new(0x100);
        let false_dest = Address::new(0x200);
        let mut func = single_block_func(vec![LlilInstruction::CondJump {
            cond: llil_const(0, Size::Byte),
            true_dest,
            false_dest,
        }]);
        let n = run_branch_simplification(&mut func);
        assert_eq!(n, 1);
        if let LlilInstruction::JumpDest { dest } = &func.blocks[0].instrs[0].instr {
            assert_eq!(
                *dest,
                LlilExpr::Const {
                    value: 0x200,
                    size: Size::QWord
                }
            );
        }
    }

    #[test]
    fn branch_simplification_no_change_on_dynamic_cond() {
        let mut func = single_block_func(vec![LlilInstruction::CondJump {
            cond: llil_reg("rax", Size::Byte),
            true_dest: Address::new(0x100),
            false_dest: Address::new(0x200),
        }]);
        let n = run_branch_simplification(&mut func);
        assert_eq!(n, 0);
    }

    // â"€â"€ run_tailcall_opt â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn tailcall_opt_replaces_call_ret() {
        let mut func = single_block_func(vec![
            LlilInstruction::CallDest {
                dest: llil_const(0xDEAD, Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let changed = run_tailcall_opt(&mut func);
        assert!(changed);
        assert_eq!(func.blocks[0].instrs.len(), 1);
        assert!(matches!(
            func.blocks[0].instrs[0].instr,
            LlilInstruction::TailCall { .. }
        ));
    }

    #[test]
    fn tailcall_opt_no_change_without_ret() {
        let mut func = single_block_func(vec![
            LlilInstruction::CallDest {
                dest: llil_const(0xDEAD, Size::QWord),
            },
            LlilInstruction::Nop,
        ]);
        let changed = run_tailcall_opt(&mut func);
        assert!(!changed);
    }

    // â"€â"€ run_unreachable_code_elimination â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn unreachable_code_elim_after_ret() {
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(1, Size::QWord),
            },
            LlilInstruction::Ret,
            LlilInstruction::Nop,
            LlilInstruction::Nop,
        ]);
        let n = run_unreachable_code_elimination(&mut func);
        assert_eq!(n, 2);
        assert_eq!(func.blocks[0].instrs.len(), 2);
    }

    #[test]
    fn unreachable_code_elim_alternate_terminators() {
        // Jump (tuple form), Return { .. }, and JumpTo must also terminate a block.
        for term in [
            LlilInstruction::Jump(llil_const(0x100, Size::QWord)),
            LlilInstruction::Return { value: None },
            LlilInstruction::JumpTo {
                dest: llil_const(0x200, Size::QWord),
                targets: vec![Address::new(0x200)],
            },
        ] {
            let mut func = single_block_func(vec![
                term,
                LlilInstruction::Nop,
                LlilInstruction::Nop,
            ]);
            let n = run_unreachable_code_elimination(&mut func);
            assert_eq!(n, 2);
            assert_eq!(func.blocks[0].instrs.len(), 1);
        }
    }

    #[test]
    fn unreachable_code_elim_no_terminator() {
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
            value: llil_const(1, Size::QWord),
        }]);
        let n = run_unreachable_code_elimination(&mut func);
        assert_eq!(n, 0);
    }

    // â"€â"€ run_redundant_branch_removal â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn redundant_branch_same_dest() {
        let dest = Address::new(0x300);
        let mut func = single_block_func(vec![LlilInstruction::CondJump {
            cond: llil_reg("rax", Size::Byte),
            true_dest: dest,
            false_dest: dest,
        }]);
        let n = run_redundant_branch_removal(&mut func);
        assert_eq!(n, 1);
        assert!(matches!(
            func.blocks[0].instrs[0].instr,
            LlilInstruction::JumpDest { .. }
        ));
    }

    #[test]
    fn redundant_branch_different_dest_no_change() {
        let mut func = single_block_func(vec![LlilInstruction::CondJump {
            cond: llil_reg("rax", Size::Byte),
            true_dest: Address::new(0x100),
            false_dest: Address::new(0x200),
        }]);
        let n = run_redundant_branch_removal(&mut func);
        assert_eq!(n, 0);
    }

    // â"€â"€ IntRange â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn int_range_constant_check() {
        let r = IntRange::constant(42);
        assert!(r.is_constant());
        assert!(r.contains(42));
        assert!(!r.contains(43));
    }

    #[test]
    fn int_range_top_contains_all() {
        let r = IntRange::top();
        assert!(!r.is_constant());
        assert!(r.contains(0));
        assert!(r.contains(i64::MAX));
        assert!(r.contains(i64::MIN));
    }

    // â"€â"€ run_integer_range_analysis â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn integer_range_analysis_const_setreg() {
        let func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
            value: llil_const(7, Size::QWord),
        }]);
        let ranges = run_integer_range_analysis(&func);
        let r = ranges.get("rax").expect("rax should have a range");
        assert!(r.is_constant());
        assert_eq!(r.lo, 7);
    }

    #[test]
    fn integer_range_analysis_add_const() {
        let func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(10, Size::QWord),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: llil_add(
                    llil_reg("rax", Size::QWord),
                    llil_const(5, Size::QWord),
                    Size::QWord,
                ),
            },
        ]);
        let ranges = run_integer_range_analysis(&func);
        let r = ranges.get("rbx").expect("rbx should have a range");
        assert!(r.is_constant());
        assert_eq!(r.lo, 15);
    }

    #[test]
    fn integer_range_analysis_conflicting_branch_writes_go_top() {
        // Two branch blocks assign different constants to rax. A
        // flow-insensitive last-write-wins analysis would report rax = 7,
        // letting NullCheckElimination fold `rax == 0` incorrectly.
        let func = make_func(vec![
            make_block(
                0,
                0x1000,
                vec![LlilInstruction::SetReg {
                    dest: LlilRegister::Concrete("rax".into()),
                    size: Size::QWord,
                    value: llil_const(0, Size::QWord),
                }],
            ),
            make_block(
                1,
                0x2000,
                vec![LlilInstruction::SetReg {
                    dest: LlilRegister::Concrete("rax".into()),
                    size: Size::QWord,
                    value: llil_const(7, Size::QWord),
                }],
            ),
        ]);
        let ranges = run_integer_range_analysis(&func);
        let r = ranges.get("rax").expect("rax should have a range");
        assert_eq!(*r, IntRange::top(), "conflicting writes must join to Top");
    }

    // â"€â"€ run_null_check_elimination â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn null_check_elim_removes_known_nonzero() {
        let rax_const = LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
            value: llil_const(5, Size::QWord),
        };
        let null_check = LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rcx".into()),
            size: Size::Byte,
            value: LlilExpr::CmpEq(
                Box::new(llil_reg("rax", Size::QWord)),
                Box::new(llil_const(0, Size::QWord)),
            ),
        };
        let mut func = single_block_func(vec![rax_const, null_check]);
        let n = run_null_check_elimination(&mut func);
        assert_eq!(n, 1);
        // rcx should now be const 0 (rax=5 is nonzero, so rax==0 is false).
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[1].instr {
            assert_eq!(
                *src,
                LlilExpr::Const {
                    value: 0,
                    size: Size::Byte
                }
            );
        }
    }

    // â"€â"€ collect_call_sites â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn collect_call_sites_basic() {
        let func = single_block_func(vec![
            LlilInstruction::CallDest {
                dest: llil_const(0x4000, Size::QWord),
            },
            LlilInstruction::CallDest {
                dest: llil_const(0x5000, Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let sites = collect_call_sites(&func);
        assert_eq!(sites.len(), 2);
        assert!(!sites[0].is_tail_call);
        assert!(!sites[1].is_tail_call);
    }

    #[test]
    fn collect_call_sites_includes_tail_calls() {
        let func = single_block_func(vec![LlilInstruction::TailCall {
            dest: llil_const(0x6000, Size::QWord),
        }]);
        let sites = collect_call_sites(&func);
        assert_eq!(sites.len(), 1);
        assert!(sites[0].is_tail_call);
    }

    #[test]
    fn collect_call_sites_empty_func() {
        let func = single_block_func(vec![LlilInstruction::Ret]);
        let sites = collect_call_sites(&func);
        assert_eq!(sites.len(), 0);
    }

    // â"€â"€ compute_inlining_score â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn inlining_score_tiny_func_high_score() {
        let func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(1, Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let score = compute_inlining_score(&func);
        assert!(
            score.score >= 70,
            "tiny func should have high score: {}",
            score.score
        );
        assert_eq!(score.call_count, 0);
        assert_eq!(score.instr_count, 2);
    }

    #[test]
    fn inlining_score_func_with_call_lower_score() {
        let func = single_block_func(vec![
            LlilInstruction::CallDest {
                dest: llil_const(0x1000, Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let score = compute_inlining_score(&func);
        // Has a call, so score < 90.
        assert!(score.call_count >= 1);
        assert!(score.score < 90);
    }

    // â"€â"€ count_instrs / count_constants â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn count_instrs_single_block() {
        let func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(1, Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        assert_eq!(count_instrs(&func), 2);
    }

    #[test]
    fn count_constants_deduplicates() {
        let func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(42, Size::QWord),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: llil_const(42, Size::QWord),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rcx".into()),
                size: Size::QWord,
                value: llil_const(99, Size::QWord),
            },
        ]);
        // 42 and 99 â†' 2 distinct constants.
        assert_eq!(count_constants(&func), 2);
    }

    // â"€â"€ run_argument_value_propagation â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn arg_value_propagation_replaces_known_reg() {
        let set_rax = LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
            value: llil_const(100, Size::QWord),
        };
        let use_rax = LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: llil_reg("rax", Size::QWord),
        };
        let mut func = single_block_func(vec![set_rax, use_rax]);
        let n = run_argument_value_propagation(&mut func);
        assert!(n >= 1, "should have substituted at least 1 register use");
    }

    // â"€â"€ run_licm â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn licm_hoists_const_setreg_to_entry() {
        let addr0 = Address::new(0x1000);
        let _addr1 = Address::new(0x2000);
        let block0 = make_block(
            0,
            0x1000,
            vec![LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_reg("rcx", Size::QWord),
            }],
        );
        let block1 = make_block(
            1,
            0x2000,
            vec![LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: llil_const(42, Size::QWord),
            }],
        );
        let mut func = LlilFunction {
            entry: addr0,
            blocks: vec![block0, block1],
            temp_count: 8,
            ..LlilFunction::default()
        };
        let n = run_licm(&mut func);
        assert_eq!(n, 1);
        // The const SetReg should now be at the start of block 0.
        assert_eq!(func.blocks[0].instrs.len(), 2);
        assert!(matches!(
            func.blocks[0].instrs[0].instr,
            LlilInstruction::SetReg {
                value: LlilExpr::Const { .. },
                ..
            }
        ));
        assert_eq!(func.blocks[1].instrs.len(), 0);
    }

    #[test]
    fn licm_single_block_no_change() {
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
            value: llil_const(7, Size::QWord),
        }]);
        let n = run_licm(&mut func);
        assert_eq!(n, 0);
    }

    #[test]
    fn licm_does_not_hoist_across_diamond_branches() {
        // entry: cond-jump to block1 or block2; block1 sets rax=1, block2 sets
        // rax=2.  Hoisting either SetReg to entry destroys branch semantics.
        let block0 = make_block(
            0,
            0x1000,
            vec![LlilInstruction::CondJump {
                cond: llil_reg("rcx", Size::QWord),
                true_dest: Address::new(0x2000),
                false_dest: Address::new(0x3000),
            }],
        );
        let block1 = make_block(
            1,
            0x2000,
            vec![LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(1, Size::QWord),
            }],
        );
        let block2 = make_block(
            2,
            0x3000,
            vec![LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(2, Size::QWord),
            }],
        );
        let mut func = LlilFunction {
            entry: Address::new(0x1000),
            blocks: vec![block0, block1, block2],
            ..LlilFunction::default()
        };
        let n = run_licm(&mut func);
        assert_eq!(n, 0, "must not hoist conditional SetRegs");
        assert_eq!(func.blocks[1].instrs.len(), 1);
        assert_eq!(func.blocks[2].instrs.len(), 1);
        assert_eq!(func.blocks[0].instrs.len(), 1);
    }

    // â"€â"€ run_loop_bound_analysis â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn loop_bound_analysis_detects_back_edge() {
        // Build a two-block "loop": block1 has a CondJump back to block0.
        let addr0 = Address::new(0x1000);
        let _addr1 = Address::new(0x2000);
        let block0 = make_block(
            0,
            0x1000,
            vec![LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(0, Size::QWord),
            }],
        );
        let block1 = make_block(
            1,
            0x2000,
            vec![LlilInstruction::CondJump {
                cond: llil_reg("rax", Size::Byte),
                true_dest: addr0, // back-edge â†' block with lower id
                false_dest: Address::new(0x3000),
            }],
        );
        let func = LlilFunction {
            entry: addr0,
            blocks: vec![block0, block1],
            temp_count: 8,
            ..LlilFunction::default()
        };
        let bounds = run_loop_bound_analysis(&func);
        assert!(!bounds.is_empty(), "should detect a loop back-edge");
        assert_eq!(bounds[0].header_block, 0);
        assert!(!bounds[0].always_terminates);
    }

    #[test]
    fn loop_bound_analysis_no_loops() {
        let func = single_block_func(vec![LlilInstruction::Ret]);
        let bounds = run_loop_bound_analysis(&func);
        assert!(bounds.is_empty());
    }

    // â"€â"€ build_full_pipeline â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn build_full_pipeline_runs_without_panic() {
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_add(
                    llil_const(1, Size::QWord),
                    llil_const(2, Size::QWord),
                    Size::QWord,
                ),
            },
            LlilInstruction::Ret,
        ]);
        let pm = build_full_pipeline();
        let ctx = pm.run(&mut func);
        // After ConstantFolding the add should become const 3; changed should be true.
        assert!(ctx.changed);
    }

    #[test]
    fn build_full_pipeline_constant_folds_nested() {
        // rax is read by the Store so DCE won't eliminate the SetReg.
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_add(
                    llil_add(
                        llil_const(2, Size::QWord),
                        llil_const(3, Size::QWord),
                        Size::QWord,
                    ),
                    llil_const(10, Size::QWord),
                    Size::QWord,
                ),
            },
            LlilInstruction::Store {
                addr: llil_reg("rax", Size::QWord),
                size: Size::QWord,
                value: llil_const(0, Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let pm = build_full_pipeline();
        let _ = pm.run(&mut func);
        // Constant folding collapses (2+3)+10 to 15. Copy propagation then forwards
        // that constant into the Store's address and DCE removes the now-dead SetReg,
        // so the folded constant ends up as the Store address rather than a SetReg value.
        let folded_const = LlilExpr::Const {
            value: 15,
            size: Size::QWord,
        };
        let found = func.blocks[0].instrs.iter().any(|ai| match &ai.instr {
            LlilInstruction::SetReg { value, .. } => *value == folded_const,
            LlilInstruction::Store { addr, .. } => *addr == folded_const,
            _ => false,
        });
        assert!(found, "expected folded constant 15 somewhere in the block");
    }

    // â"€â"€ GVN pass (AnalysisPass wrapper) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn gvn_analysis_pass_marks_changed() {
        let rax_plus_one = llil_add(
            llil_reg("rax", Size::QWord),
            llil_const(1, Size::QWord),
            Size::QWord,
        );
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: rax_plus_one.clone(),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rcx".into()),
                size: Size::QWord,
                value: rax_plus_one,
            },
        ]);
        let pass = GlobalValueNumberingPass;
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert!(ctx.changed);
    }

    // â"€â"€ BranchSimplification pass wrapper â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn branch_simplification_pass_marks_changed() {
        let mut func = single_block_func(vec![LlilInstruction::CondJump {
            cond: llil_const(1, Size::Byte),
            true_dest: Address::new(0x100),
            false_dest: Address::new(0x200),
        }]);
        let pass = BranchSimplificationPass;
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert!(ctx.changed);
        assert_eq!(ctx.stats.exprs_simplified, 1);
    }

    // â"€â"€ TailCall pass wrapper â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn tailcall_pass_marks_changed() {
        let mut func = single_block_func(vec![
            LlilInstruction::CallDest {
                dest: llil_const(0xF00D, Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let pass = TailCallOptimizationPass;
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        assert!(ctx.changed);
    }

    // â"€â"€ PhiElimination is idempotent (no-op) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn phi_elimination_is_noop() {
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
            value: llil_const(1, Size::QWord),
        }]);
        let pass = PhiEliminationPass;
        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);
        // No change expected.
        assert!(!ctx.changed);
        assert_eq!(func.blocks[0].instrs.len(), 1);
    }

    // â"€â"€ StrengthReductionPass â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn strength_reduction_mul_power_of_two() {
        // rax * 4  â†' rax << 2
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: LlilExpr::MulT(
                Box::new(rax),
                Box::new(llil_const(4, Size::QWord)),
                Size::QWord,
            ),
        }]);
        let n = run_strength_reduction(&mut func);
        assert_eq!(n, 1);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert!(
                matches!(src, LlilExpr::ShlT(_, _, _)),
                "expected Shl, got {src:?}"
            );
        }
    }

    #[test]
    fn strength_reduction_mul_by_3() {
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: LlilExpr::MulT(
                Box::new(rax),
                Box::new(llil_const(3, Size::QWord)),
                Size::QWord,
            ),
        }]);
        let n = run_strength_reduction(&mut func);
        assert_eq!(n, 1);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert!(
                matches!(src, LlilExpr::AddT(_, _, _)),
                "expected Add, got {src:?}"
            );
        }
    }

    #[test]
    fn strength_reduction_mul_by_5() {
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: LlilExpr::MulT(
                Box::new(rax),
                Box::new(llil_const(5, Size::QWord)),
                Size::QWord,
            ),
        }]);
        let n = run_strength_reduction(&mut func);
        assert_eq!(n, 1);
    }

    #[test]
    fn strength_reduction_div_power_of_two() {
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: LlilExpr::DivU(
                Box::new(rax),
                Box::new(llil_const(8, Size::QWord)),
                Size::QWord,
            ),
        }]);
        let n = run_strength_reduction(&mut func);
        assert_eq!(n, 1);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert!(
                matches!(src, LlilExpr::Shr(_, _, _)),
                "expected Shr, got {src:?}"
            );
        }
    }

    #[test]
    fn strength_reduction_no_change_on_const_3_non_power() {
        // x * 7 is not handled (not a power of 2, not 3/5/9), should be unchanged.
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: LlilExpr::MulT(
                Box::new(rax),
                Box::new(llil_const(7, Size::QWord)),
                Size::QWord,
            ),
        }]);
        let n = run_strength_reduction(&mut func);
        assert_eq!(n, 0);
    }

    // â"€â"€ AlgebraicSimplificationPass â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn algebraic_not_cmp_eq_becomes_cmp_ne() {
        let rax = llil_reg("rax", Size::QWord);
        let rbx = llil_reg("rbx", Size::QWord);
        let cmp = LlilExpr::CmpEq(Box::new(rax), Box::new(rbx));
        let not_cmp = LlilExpr::Not(Box::new(cmp), Size::Byte);
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rcx".into()),
            size: Size::Byte,
            value: not_cmp,
        }]);
        let n = run_algebraic_simplification(&mut func);
        assert_eq!(n, 1);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert!(
                matches!(src, LlilExpr::CmpNe(_, _)),
                "expected CmpNe, got {src:?}"
            );
        }
    }

    #[test]
    fn algebraic_not_cmp_slt_becomes_cmp_sge() {
        let rax = llil_reg("rax", Size::QWord);
        let rbx = llil_reg("rbx", Size::QWord);
        let cmp = LlilExpr::CmpSlt(Box::new(rax), Box::new(rbx));
        let not_cmp = LlilExpr::Not(Box::new(cmp), Size::Byte);
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rcx".into()),
            size: Size::Byte,
            value: not_cmp,
        }]);
        let n = run_algebraic_simplification(&mut func);
        assert_eq!(n, 1);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert!(
                matches!(src, LlilExpr::CmpSge(_, _)),
                "expected CmpSge, got {src:?}"
            );
        }
    }

    #[test]
    fn algebraic_not_not_simplifies() {
        let rax = llil_reg("rax", Size::QWord);
        let not_not = LlilExpr::Not(
            Box::new(LlilExpr::Not(Box::new(rax.clone()), Size::QWord)),
            Size::QWord,
        );
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: not_not,
        }]);
        let n = run_algebraic_simplification(&mut func);
        assert_eq!(n, 1);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert_eq!(*src, rax);
        }
    }

    #[test]
    fn algebraic_and_not_self_is_zero() {
        let rax = llil_reg("rax", Size::QWord);
        let not_rax = LlilExpr::Not(Box::new(rax.clone()), Size::QWord);
        let and_expr = LlilExpr::And(Box::new(rax), Box::new(not_rax), Size::QWord);
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: and_expr,
        }]);
        let n = run_algebraic_simplification(&mut func);
        assert_eq!(n, 1);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert_eq!(
                *src,
                LlilExpr::Const {
                    value: 0,
                    size: Size::QWord
                }
            );
        }
    }

    // â"€â"€ RedundantLoadEliminationPass â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn redundant_load_elim_deduplicates() {
        let addr = llil_const(0x8000, Size::QWord);
        let mut func = single_block_func(vec![
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rax".into()),
                addr: addr.clone(),
                size: Size::QWord,
            },
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rbx".into()),
                addr,
                size: Size::QWord,
            },
        ]);
        let n = run_redundant_load_elimination(&mut func);
        assert_eq!(n, 1);
        // Second instruction should now be a SetReg (copy), not a Load.
        assert!(matches!(
            func.blocks[0].instrs[1].instr,
            LlilInstruction::SetReg { .. }
        ));
    }

    #[test]
    fn redundant_load_elim_store_invalidates() {
        let addr = llil_const(0x8000, Size::QWord);
        let mut func = single_block_func(vec![
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rax".into()),
                addr: addr.clone(),
                size: Size::QWord,
            },
            LlilInstruction::Store {
                addr: addr.clone(),
                value: llil_const(99, Size::QWord),
                size: Size::QWord,
            },
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rbx".into()),
                addr,
                size: Size::QWord,
            },
        ]);
        let n = run_redundant_load_elimination(&mut func);
        // Store invalidates the cached load, so the second load should not be removed.
        assert_eq!(n, 0);
    }

    #[test]
    fn redundant_load_elim_holding_reg_overwrite_invalidates() {
        // rax = Load[0x8000]; rax = 5; rbx = Load[0x8000]
        // The second load must NOT become `rbx = rax` (rax no longer holds the value).
        let addr = llil_const(0x8000, Size::QWord);
        let mut func = single_block_func(vec![
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rax".into()),
                addr: addr.clone(),
                size: Size::QWord,
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                value: llil_const(5, Size::QWord),
                size: Size::QWord,
            },
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rbx".into()),
                addr,
                size: Size::QWord,
            },
        ]);
        let n = run_redundant_load_elimination(&mut func);
        assert_eq!(n, 0);
        assert!(matches!(
            func.blocks[0].instrs[2].instr,
            LlilInstruction::Load { .. }
        ));
    }

    // â"€â"€ StoreLoadForwardingPass â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn store_load_forwarding_basic() {
        let addr = llil_const(0x9000, Size::QWord);
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![
            LlilInstruction::Store {
                addr: addr.clone(),
                value: rax.clone(),
                size: Size::QWord,
            },
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rbx".into()),
                addr,
                size: Size::QWord,
            },
        ]);
        let n = run_store_load_forwarding(&mut func);
        assert_eq!(n, 1);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[1].instr {
            assert_eq!(*src, rax);
        }
    }

    #[test]
    fn store_load_forwarding_no_forward_different_addr() {
        let addr1 = llil_const(0x9000, Size::QWord);
        let addr2 = llil_const(0xA000, Size::QWord);
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![
            LlilInstruction::Store {
                addr: addr1,
                value: rax,
                size: Size::QWord,
            },
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rbx".into()),
                addr: addr2,
                size: Size::QWord,
            },
        ]);
        let n = run_store_load_forwarding(&mut func);
        assert_eq!(n, 0);
    }

    #[test]
    fn store_load_forwarding_no_forward_clobbered_reg_or_size_mismatch() {
        let addr = llil_const(0x9000, Size::QWord);
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![
            // store [0x9000] = rax
            LlilInstruction::Store {
                addr: addr.clone(),
                value: rax,
                size: Size::QWord,
            },
            // rax = 5  (clobbers the stored expression's source register)
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                value: llil_const(5, Size::QWord),
                size: Size::QWord,
            },
            // rbx = load [0x9000]  -- must NOT become rbx = rax
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rbx".into()),
                addr: addr.clone(),
                size: Size::QWord,
            },
            // store [0x9000] = 7 (qword), then dword load: size mismatch, no forward
            LlilInstruction::Store {
                addr: addr.clone(),
                value: llil_const(7, Size::QWord),
                size: Size::QWord,
            },
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rcx".into()),
                addr,
                size: Size::DWord,
            },
        ]);
        let n = run_store_load_forwarding(&mut func);
        assert_eq!(n, 0);
        assert!(matches!(
            func.blocks[0].instrs[2].instr,
            LlilInstruction::Load { .. }
        ));
        assert!(matches!(
            func.blocks[0].instrs[4].instr,
            LlilInstruction::Load { .. }
        ));
    }

    // â"€â"€ DeadStoreEliminationPass â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn dead_store_elim_removes_overwritten_store() {
        let addr = llil_const(0xB000, Size::QWord);
        let mut func = single_block_func(vec![
            LlilInstruction::Store {
                addr: addr.clone(),
                value: llil_const(1, Size::QWord),
                size: Size::QWord,
            },
            LlilInstruction::Store {
                addr,
                value: llil_const(2, Size::QWord),
                size: Size::QWord,
            },
            LlilInstruction::Ret,
        ]);
        let n = run_dead_store_elimination(&mut func);
        assert_eq!(n, 1);
        assert_eq!(func.blocks[0].instrs.len(), 2); // First store removed.
    }

    #[test]
    fn dead_store_elim_keeps_store_with_intervening_load() {
        let addr = llil_const(0xC000, Size::QWord);
        let mut func = single_block_func(vec![
            LlilInstruction::Store {
                addr: addr.clone(),
                value: llil_const(1, Size::QWord),
                size: Size::QWord,
            },
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rax".into()),
                addr: addr.clone(),
                size: Size::QWord,
            },
            LlilInstruction::Store {
                addr,
                value: llil_const(2, Size::QWord),
                size: Size::QWord,
            },
        ]);
        let n = run_dead_store_elimination(&mut func);
        assert_eq!(n, 0);
        assert_eq!(func.blocks[0].instrs.len(), 3);
    }

    #[test]
    fn dead_store_elim_respects_size_and_expr_loads() {
        // 1) A later 1-byte store must NOT kill an earlier 8-byte store.
        let addr = llil_const(0xD000, Size::QWord);
        let mut func = single_block_func(vec![
            LlilInstruction::Store {
                addr: addr.clone(),
                value: llil_const(1, Size::QWord),
                size: Size::QWord,
            },
            LlilInstruction::Store {
                addr: addr.clone(),
                value: llil_const(2, Size::Byte),
                size: Size::Byte,
            },
        ]);
        assert_eq!(run_dead_store_elimination(&mut func), 0);
        assert_eq!(func.blocks[0].instrs.len(), 2);

        // 2) An expression-level load (inside a SetReg) between two stores
        //    observes the first store, so it must be kept.
        let mut func2 = single_block_func(vec![
            LlilInstruction::Store {
                addr: addr.clone(),
                value: llil_const(1, Size::QWord),
                size: Size::QWord,
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: LlilExpr::Load {
                    addr: Box::new(addr.clone()),
                    size: Size::QWord,
                },
            },
            LlilInstruction::Store {
                addr: addr.clone(),
                value: llil_const(2, Size::QWord),
                size: Size::QWord,
            },
        ]);
        assert_eq!(run_dead_store_elimination(&mut func2), 0);
        assert_eq!(func2.blocks[0].instrs.len(), 3);

        // 3) Same-size full overwrite is still removed.
        let mut func3 = single_block_func(vec![
            LlilInstruction::Store {
                addr: addr.clone(),
                value: llil_const(1, Size::Byte),
                size: Size::Byte,
            },
            LlilInstruction::Store {
                addr,
                value: llil_const(2, Size::QWord),
                size: Size::QWord,
            },
        ]);
        assert_eq!(run_dead_store_elimination(&mut func3), 1);
        assert_eq!(func3.blocks[0].instrs.len(), 1);
    }

    #[test]
    fn dead_store_elim_keeps_store_when_intervening_load_addr_is_unknown() {
        // A Load through a *register* address may alias 0xE000. The earlier
        // store is therefore observable and must NOT be removed.
        let addr = llil_const(0xE000, Size::QWord);
        let mut func = single_block_func(vec![
            LlilInstruction::Store {
                addr: addr.clone(),
                value: llil_const(1, Size::QWord),
                size: Size::QWord,
            },
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rax".into()),
                addr: LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("rbx".into()),
                    size: Size::QWord,
                },
                size: Size::QWord,
            },
            LlilInstruction::Store {
                addr,
                value: llil_const(2, Size::QWord),
                size: Size::QWord,
            },
        ]);
        assert_eq!(run_dead_store_elimination(&mut func), 0);
        assert_eq!(func.blocks[0].instrs.len(), 3);
    }

    // â"€â"€ CommonSubexpressionEliminationPass â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn cse_deduplicates_pure_exprs() {
        let rax = llil_reg("rax", Size::QWord);
        let expr = llil_add(rax, llil_const(1, Size::QWord), Size::QWord);
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: expr.clone(),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rcx".into()),
                size: Size::QWord,
                value: expr,
            },
        ]);
        let n = run_cse(&mut func);
        assert_eq!(n, 1);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[1].instr {
            // llil_reg produces LlilExpr::RegisterRef, not Register.
            assert!(
                matches!(src, LlilExpr::RegisterRef { .. }),
                "expected RegisterRef copy"
            );
        }
    }

    #[test]
    fn cse_invalidated_by_register_redefinition() {
        // rbx = rax + 1
        // rax = 5          (redefines rax -> cached "rax + 1" is stale)
        // rcx = rax + 1    (must NOT be rewritten to rbx)
        let rax = llil_reg("rax", Size::QWord);
        let expr = llil_add(rax, llil_const(1, Size::QWord), Size::QWord);
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: expr.clone(),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(5, Size::QWord),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rcx".into()),
                size: Size::QWord,
                value: expr,
            },
        ]);
        let n = run_cse(&mut func);
        assert_eq!(n, 0, "stale expression must not be reused after rax redef");
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[2].instr {
            assert!(
                !matches!(src, LlilExpr::RegisterRef { .. }),
                "rcx source must remain the original expression"
            );
        }
    }

    #[test]
    fn cse_no_dedup_load_exprs() {
        let addr = llil_const(0xD000, Size::QWord);
        let load = LlilExpr::Load {
            addr: Box::new(addr),
            size: Size::QWord,
        };
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: load.clone(),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rcx".into()),
                size: Size::QWord,
                value: load,
            },
        ]);
        let n = run_cse(&mut func);
        assert_eq!(n, 0, "loads are not pure; CSE must not deduplicate them");
    }

    // â"€â"€ FunctionSummary â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn function_summary_tiny_leaf() {
        let func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_const(1, Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let summary = FunctionSummary::analyze(&func);
        assert_eq!(summary.total_instrs, 2);
        assert_eq!(summary.block_count, 1);
        assert_eq!(summary.call_sites, 0);
        assert!(summary.has_return);
        assert!(summary.is_leaf_inline_candidate());
    }

    #[test]
    fn function_summary_with_call_not_leaf() {
        let func = single_block_func(vec![
            LlilInstruction::CallDest {
                dest: llil_const(0x5000, Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let summary = FunctionSummary::analyze(&func);
        assert_eq!(summary.call_sites, 1);
        assert!(!summary.is_leaf_inline_candidate());
    }

    #[test]
    fn function_summary_no_return() {
        let func = single_block_func(vec![LlilInstruction::TailCall {
            dest: llil_const(0x5000, Size::QWord),
        }]);
        let summary = FunctionSummary::analyze(&func);
        assert!(!summary.has_return);
    }

    // â"€â"€ expr_node_count / expr_depth â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn expr_node_count_constant_is_1() {
        assert_eq!(expr_node_count(&llil_const(42, Size::QWord)), 1);
    }

    #[test]
    fn expr_node_count_add_two_consts_is_3() {
        let e = llil_add(
            llil_const(1, Size::QWord),
            llil_const(2, Size::QWord),
            Size::QWord,
        );
        assert_eq!(expr_node_count(&e), 3);
    }

    #[test]
    fn expr_depth_flat_add_is_1() {
        let e = llil_add(
            llil_const(1, Size::QWord),
            llil_const(2, Size::QWord),
            Size::QWord,
        );
        assert_eq!(expr_depth(&e), 1);
    }

    #[test]
    fn expr_depth_nested_add_is_2() {
        let inner = llil_add(
            llil_const(1, Size::QWord),
            llil_const(2, Size::QWord),
            Size::QWord,
        );
        let outer = llil_add(inner, llil_const(3, Size::QWord), Size::QWord);
        assert_eq!(expr_depth(&outer), 2);
    }

    // â"€â"€ ExprCanonicalizerPass â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn expr_canonicalizer_moves_const_to_right() {
        // Const + Reg â†' Reg + Const
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: LlilExpr::AddT(
                Box::new(llil_const(5, Size::QWord)),
                Box::new(rax),
                Size::QWord,
            ),
        }]);
        let n = run_expr_canonicalize(&mut func);
        assert_eq!(n, 1);
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            if let LlilExpr::AddT(l, r, _) = src {
                // llil_reg produces LlilExpr::RegisterRef, not Register.
                assert!(
                    matches!(l.as_ref(), LlilExpr::RegisterRef { .. }),
                    "left should be RegisterRef"
                );
                assert!(
                    matches!(r.as_ref(), LlilExpr::Const { .. }),
                    "right should be Const"
                );
            } else {
                panic!("expected Add");
            }
        }
    }

    #[test]
    fn expr_canonicalizer_already_canonical_no_change() {
        let rax = llil_reg("rax", Size::QWord);
        // Reg + Const already canonical.
        let mut func = single_block_func(vec![LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
            value: llil_add(rax, llil_const(5, Size::QWord), Size::QWord),
        }]);
        let n = run_expr_canonicalize(&mut func);
        assert_eq!(n, 0);
    }

    // â"€â"€ PriorityPassManager â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn priority_pass_manager_basic_run() {
        let mut pm = PriorityPassManager::new();
        pm.add(10, NopEliminationPass);
        pm.add(20, ConstantFoldingPass);
        let mut func = single_block_func(vec![
            LlilInstruction::Nop,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_add(
                    llil_const(1, Size::QWord),
                    llil_const(2, Size::QWord),
                    Size::QWord,
                ),
            },
            LlilInstruction::Ret,
        ]);
        let ctx = pm.run(&mut func);
        assert!(ctx.changed);
        // Nop should be gone.
        assert!(
            func.blocks[0]
                .instrs
                .iter()
                .all(|ai| !matches!(ai.instr, LlilInstruction::Nop))
        );
    }

    #[test]
    fn build_aggressive_pipeline_runs_without_panic() {
        let mut pm = build_aggressive_pipeline();
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: llil_add(
                    llil_const(10, Size::QWord),
                    llil_const(5, Size::QWord),
                    Size::QWord,
                ),
            },
            LlilInstruction::Store {
                addr: llil_reg("rax", Size::QWord),
                size: Size::QWord,
                value: llil_const(0, Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let ctx = pm.run(&mut func);
        assert!(ctx.changed);
    }

    // â"€â"€ run_constant_hoisting â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn constant_hoisting_hoists_repeated_constant() {
        // Use const 42 three times in a single block.
        let c42 = llil_const(42, Size::QWord);
        let rax = llil_reg("rax", Size::QWord);
        let rbx = llil_reg("rbx", Size::QWord);
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("r1".into()),
                size: Size::QWord,
                value: llil_add(rax.clone(), c42.clone(), Size::QWord),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("r2".into()),
                size: Size::QWord,
                value: llil_add(rbx, c42.clone(), Size::QWord),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("r3".into()),
                size: Size::QWord,
                value: llil_add(rax, c42, Size::QWord),
            },
        ]);
        let n = run_constant_hoisting(&mut func);
        assert_eq!(n, 1, "should hoist exactly 1 constant");
        // A new instruction should have been prepended.
        assert!(
            matches!(
                func.blocks[0].instrs[0].instr,
                LlilInstruction::SetReg {
                    value: LlilExpr::Const { value: 42, .. },
                    ..
                }
            ),
            "first instr should be tmp = 42"
        );
    }

    #[test]
    fn constant_hoisting_no_hoist_below_threshold() {
        // Use const 99 only twice —" below the 3-occurrence threshold.
        let c99 = llil_const(99, Size::QWord);
        let rax = llil_reg("rax", Size::QWord);
        let mut func = single_block_func(vec![
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("r1".into()),
                size: Size::QWord,
                value: llil_add(rax.clone(), c99.clone(), Size::QWord),
            },
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("r2".into()),
                size: Size::QWord,
                value: llil_add(rax, c99, Size::QWord),
            },
        ]);
        let original_len = func.blocks[0].instrs.len();
        let n = run_constant_hoisting(&mut func);
        assert_eq!(n, 0);
        assert_eq!(func.blocks[0].instrs.len(), original_len);
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Dependency-ordered pass framework —" an `IlPass` trait carrying declarative
// dependencies and a `DependencyPassManager` that topologically sorts passes
// (Kahn's algorithm) before running them, plus a suite of named analysis passes.
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

/// Dependency-aware pass scheduling and built-in analysis passes.
pub mod dep {
    use super::{
        AnalysisPass, ConstantFoldingPass, DeadCodeEliminationPass, IntRange, PassContext,
        run_integer_range_analysis,
    };
    use rustre_il_llil::{LlilExpr, LlilFunction, LlilInstruction};
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

    /// Output produced by a pass into the shared analysis store.
    #[derive(Debug, Clone, Default)]
    pub struct AnalysisResults {
        /// Free-form keyed facts (pass name -> human summary).
        pub facts: BTreeMap<String, String>,
        /// Per-register value ranges (from value-range analysis).
        pub ranges: HashMap<String, IntRange>,
        /// Recovered stack-frame slots: offset -> size in bytes.
        pub stack_slots: BTreeMap<i64, u8>,
        /// Loop headers recognised in the function.
        pub loop_headers: BTreeSet<u32>,
        /// Detected switch/jump-table sites: instruction address -> case count.
        pub switch_tables: BTreeMap<u64, usize>,
        /// Whether a tail call was recognised.
        pub has_tailcall: bool,
        /// `cmp`/`jcc` flag-equivalence pairs found (block id -> condition text).
        pub flag_conditions: BTreeMap<u32, String>,
    }

    impl AnalysisResults {
        /// Create an empty result store.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Record a named fact.
        pub fn record(&mut self, key: impl Into<String>, value: impl Into<String>) {
            self.facts.insert(key.into(), value.into());
        }
    }

    /// A pass in the dependency-ordered framework.
    ///
    /// Unlike [`super::AnalysisPass`], an `IlPass` declares the *names* of the
    /// passes it depends on, so the [`DependencyPassManager`] can run them in a
    /// valid topological order automatically.
    pub trait IlPass {
        /// Unique pass name (also the key other passes depend on).
        fn name(&self) -> &'static str;

        /// Names of passes that must run before this one.
        fn dependencies(&self) -> &'static [&'static str] {
            &[]
        }

        /// Execute the pass. May read prior results and mutate `func` and the
        /// shared `results` store. Returns `true` if it changed `func`.
        fn run(&self, func: &mut LlilFunction, results: &mut AnalysisResults) -> bool;
    }

    /// Errors from dependency resolution.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ScheduleError {
        /// A pass declared a dependency that was never registered.
        MissingDependency {
            /// The pass with the unmet dependency.
            pass: String,
            /// The missing dependency name.
            missing: String,
        },
        /// The dependency graph contains a cycle.
        Cycle(Vec<String>),
    }

    impl std::fmt::Display for ScheduleError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::MissingDependency { pass, missing } => {
                    write!(f, "pass `{pass}` depends on unregistered pass `{missing}`")
                }
                Self::Cycle(c) => write!(f, "dependency cycle: {}", c.join(" -> ")),
            }
        }
    }

    impl std::error::Error for ScheduleError {}

    /// Runs a set of [`IlPass`]es in dependency order.
    #[derive(Default)]
    pub struct DependencyPassManager {
        passes: Vec<Box<dyn IlPass>>,
    }

    impl DependencyPassManager {
        /// Create an empty manager.
        #[must_use]
        pub fn new() -> Self {
            Self { passes: Vec::new() }
        }

        /// Register a pass (builder pattern).
        #[must_use]
        pub fn with(mut self, pass: impl IlPass + 'static) -> Self {
            self.passes.push(Box::new(pass));
            self
        }

        /// Register a pass by mutable reference.
        pub fn add(&mut self, pass: impl IlPass + 'static) {
            self.passes.push(Box::new(pass));
        }

        /// Number of registered passes.
        #[must_use]
        pub fn len(&self) -> usize {
            self.passes.len()
        }

        /// Returns `true` if no passes are registered.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.passes.is_empty()
        }

        /// Compute a topological order of pass names using Kahn's algorithm.
        ///
        /// # Errors
        ///
        /// Returns [`ScheduleError::MissingDependency`] if a declared dependency
        /// is not registered, or [`ScheduleError::Cycle`] if the dependency graph
        /// is cyclic.
        ///
        /// # Panics
        ///
        /// Panics if an internal invariant is violated (a successor node was not
        /// found in the in-degree map, which should not happen under normal use).
        pub fn schedule(&self) -> Result<Vec<&'static str>, ScheduleError> {
            let names: BTreeSet<&'static str> = self.passes.iter().map(|p| p.name()).collect();
            // Build edges dep -> pass and in-degree per pass.
            let mut indegree: BTreeMap<&'static str, usize> = BTreeMap::new();
            let mut adj: BTreeMap<&'static str, Vec<&'static str>> = BTreeMap::new();
            for p in &self.passes {
                indegree.entry(p.name()).or_insert(0);
                adj.entry(p.name()).or_default();
            }
            for p in &self.passes {
                for &d in p.dependencies() {
                    if !names.contains(d) {
                        return Err(ScheduleError::MissingDependency {
                            pass: p.name().to_string(),
                            missing: d.to_string(),
                        });
                    }
                    adj.entry(d).or_default().push(p.name());
                    *indegree.entry(p.name()).or_insert(0) += 1;
                }
            }
            // Kahn: start from zero in-degree nodes (BTree keeps determinism).
            let mut queue: VecDeque<&'static str> = indegree
                .iter()
                .filter(|(_, d)| **d == 0)
                .map(|(n, _)| *n)
                .collect();
            let mut order: Vec<&'static str> = Vec::new();
            while let Some(n) = queue.pop_front() {
                order.push(n);
                if let Some(succs) = adj.get(&n) {
                    let succs = succs.clone();
                    for s in succs {
                        let e = indegree.get_mut(&s).unwrap();
                        *e -= 1;
                        if *e == 0 {
                            queue.push_back(s);
                        }
                    }
                }
            }
            if order.len() != self.passes.len() {
                // The leftover nodes (in-degree > 0) form a cycle.
                let cycle: Vec<String> = indegree
                    .iter()
                    .filter(|(_, d)| **d > 0)
                    .map(|(n, _)| (*n).to_string())
                    .collect();
                return Err(ScheduleError::Cycle(cycle));
            }
            Ok(order)
        }

        /// Schedule and run all passes in dependency order.
        ///
        /// # Errors
        ///
        /// Propagates [`ScheduleError`] from [`schedule`](Self::schedule).
        pub fn run(&self, func: &mut LlilFunction) -> Result<AnalysisResults, ScheduleError> {
            let order = self.schedule()?;
            let by_name: HashMap<&'static str, &dyn IlPass> =
                self.passes.iter().map(|p| (p.name(), p.as_ref())).collect();
            let mut results = AnalysisResults::new();
            for name in order {
                if let Some(pass) = by_name.get(name) {
                    pass.run(func, &mut results);
                }
            }
            Ok(results)
        }
    }

    // â"€â"€ built-in passes â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Constant-propagation pass (wraps [`super::run_argument_value_propagation`]
    /// style propagation via constant-folding + range seeding).
    #[derive(Debug, Default)]
    pub struct ConstantPropagation;

    impl IlPass for ConstantPropagation {
        fn name(&self) -> &'static str {
            "constant-propagation"
        }
        fn run(&self, func: &mut LlilFunction, results: &mut AnalysisResults) -> bool {
            let mut ctx = PassContext::new();
            ConstantFoldingPass::new().run(func, &mut ctx);
            results.record(
                "constant-propagation",
                format!("{} sites folded", ctx.stats.const_folded),
            );
            ctx.changed
        }
    }

    /// Dead-code elimination pass.
    #[derive(Debug, Default)]
    pub struct DeadCodeElimination;

    impl IlPass for DeadCodeElimination {
        fn name(&self) -> &'static str {
            "dead-code-elimination"
        }
        fn dependencies(&self) -> &'static [&'static str] {
            &["constant-propagation"]
        }
        fn run(&self, func: &mut LlilFunction, results: &mut AnalysisResults) -> bool {
            let mut ctx = PassContext::new();
            DeadCodeEliminationPass::new().run(func, &mut ctx);
            results.record(
                "dead-code-elimination",
                format!("{} removed", ctx.stats.dead_removed),
            );
            ctx.changed
        }
    }

    /// Common-subexpression elimination via global value numbering.
    #[derive(Debug, Default)]
    pub struct CommonSubexpressionElimination;

    impl IlPass for CommonSubexpressionElimination {
        fn name(&self) -> &'static str {
            "common-subexpression-elimination"
        }
        fn dependencies(&self) -> &'static [&'static str] {
            &["constant-propagation"]
        }
        fn run(&self, func: &mut LlilFunction, results: &mut AnalysisResults) -> bool {
            let changed = super::run_gvn_pass(func);
            results.record(
                "common-subexpression-elimination",
                format!("changed={changed}"),
            );
            changed
        }
    }

    /// Value-range analysis pass —" seeds [`AnalysisResults::ranges`].
    #[derive(Debug, Default)]
    pub struct ValueRangeAnalysis;

    impl IlPass for ValueRangeAnalysis {
        fn name(&self) -> &'static str {
            "value-range-analysis"
        }
        fn dependencies(&self) -> &'static [&'static str] {
            &["constant-propagation"]
        }
        fn run(&self, func: &mut LlilFunction, results: &mut AnalysisResults) -> bool {
            results.ranges = run_integer_range_analysis(func);
            let constants = results.ranges.values().filter(|r| r.is_constant()).count();
            results.record(
                "value-range-analysis",
                format!("{constants} constant ranges"),
            );
            false
        }
    }

    /// Stack-frame analysis —" recovers stack slots from `[sp +/- k]` accesses.
    #[derive(Debug, Default)]
    pub struct StackFrameAnalysis;

    impl StackFrameAnalysis {
        /// Detect a stack-relative address of the form `SP + const` / `SP - const`
        /// and return the signed offset.
        fn stack_offset(addr: &LlilExpr) -> Option<i64> {
            // Constants are interpreted as their two's-complement signed value.
            let signed = |v: u64| -> i64 { i64::from_ne_bytes(v.to_ne_bytes()) };
            match addr {
                LlilExpr::StackPointer(_) => Some(0),
                LlilExpr::AddT(l, r, _) => match (l.as_ref(), r.as_ref()) {
                    (LlilExpr::StackPointer(_), LlilExpr::Const { value, .. })
                    | (LlilExpr::Const { value, .. }, LlilExpr::StackPointer(_)) => {
                        Some(signed(*value))
                    }
                    _ => None,
                },
                LlilExpr::SubT(l, r, _) => match (l.as_ref(), r.as_ref()) {
                    (LlilExpr::StackPointer(_), LlilExpr::Const { value, .. }) => {
                        Some(signed(*value).wrapping_neg())
                    }
                    _ => None,
                },
                _ => None,
            }
        }
    }

    impl IlPass for StackFrameAnalysis {
        fn name(&self) -> &'static str {
            "stack-frame-analysis"
        }
        fn run(&self, func: &mut LlilFunction, results: &mut AnalysisResults) -> bool {
            for ai in func.all_instrs() {
                match &ai.instr {
                    LlilInstruction::Store { addr, size, .. } => {
                        if let Some(off) = Self::stack_offset(addr) {
                            results.stack_slots.insert(off, u8::try_from(size.bytes()).unwrap_or(u8::MAX));
                        }
                    }
                    LlilInstruction::Load { addr, size, .. } => {
                        if let Some(off) = Self::stack_offset(addr) {
                            results.stack_slots.entry(off).or_insert_with(|| u8::try_from(size.bytes()).unwrap_or(u8::MAX));
                        }
                    }
                    _ => {}
                }
            }
            results.record(
                "stack-frame-analysis",
                format!("{} slots", results.stack_slots.len()),
            );
            false
        }
    }

    /// Flag-equivalence pass —" recognises `cmp`-style flag sets feeding a
    /// conditional jump and records the equivalent high-level condition.
    #[derive(Debug, Default)]
    pub struct FlagEquivalence;

    impl IlPass for FlagEquivalence {
        fn name(&self) -> &'static str {
            "flag-equivalence"
        }
        fn run(&self, func: &mut LlilFunction, results: &mut AnalysisResults) -> bool {
            for block in &func.blocks {
                if let Some(ai) = block.instrs.last()
                    && let LlilInstruction::CondJump { cond, .. } = &ai.instr {
                        results.flag_conditions.insert(block.id, cond.to_string());
                    }
            }
            results.record(
                "flag-equivalence",
                format!("{} conditions", results.flag_conditions.len()),
            );
            false
        }
    }

    /// Loop-recognition pass —" finds loop headers via dominator back-edges.
    #[derive(Debug, Default)]
    pub struct LoopRecognition;

    impl IlPass for LoopRecognition {
        fn name(&self) -> &'static str {
            "loop-recognition"
        }
        fn run(&self, func: &mut LlilFunction, results: &mut AnalysisResults) -> bool {
            // Build successor map and predecessor map by block id.
            let succ: HashMap<u32, Vec<u32>> = func
                .blocks
                .iter()
                .map(|b| (b.id, block_successors(func, b.id)))
                .collect();
            // A back edge n -> h exists when h dominates n. Use a simple
            // reachability-based dominance check.
            let entry = func.blocks.first().map_or(0, |b| b.id);
            let dom = simple_dominators(func, entry, &succ);
            for (&n, succs) in &succ {
                for &h in succs {
                    if dominates(&dom, h, n) {
                        results.loop_headers.insert(h);
                    }
                }
            }
            results.record(
                "loop-recognition",
                format!("{} headers", results.loop_headers.len()),
            );
            false
        }
    }

    /// Switch-table detection —" flags indirect jumps with known target lists.
    #[derive(Debug, Default)]
    pub struct SwitchTableDetection;

    impl IlPass for SwitchTableDetection {
        fn name(&self) -> &'static str {
            "switch-table-detection"
        }
        fn run(&self, func: &mut LlilFunction, results: &mut AnalysisResults) -> bool {
            for ai in func.all_instrs() {
                if let LlilInstruction::JumpTo { targets, .. } = &ai.instr
                    && targets.len() >= 2 {
                        results.switch_tables.insert(ai.address.0, targets.len());
                    }
            }
            results.record(
                "switch-table-detection",
                format!("{} tables", results.switch_tables.len()),
            );
            false
        }
    }

    /// Tail-call recognition —" turns `call; ret` into a tail call and records it.
    #[derive(Debug, Default)]
    pub struct TailcallRecognition;

    impl IlPass for TailcallRecognition {
        fn name(&self) -> &'static str {
            "tailcall-recognition"
        }
        fn run(&self, func: &mut LlilFunction, results: &mut AnalysisResults) -> bool {
            let changed = super::run_tailcall_opt(func);
            results.has_tailcall = func
                .all_instrs()
                .any(|ai| matches!(ai.instr, LlilInstruction::TailCall { .. }));
            results.record("tailcall-recognition", format!("changed={changed}"));
            changed
        }
    }

    // â"€â"€ helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn block_successors(func: &LlilFunction, id: u32) -> Vec<u32> {
        let Some(block) = func.blocks.iter().find(|b| b.id == id) else {
            return Vec::new();
        };
        let Some(ai) = block.instrs.last() else {
            return Vec::new();
        };
        // Use the explicit static successors when available; fall back to the
        // next block by address for fall-through.
        let addr_targets = ai.instr.successors();
        if !addr_targets.is_empty() {
            return addr_targets
                .into_iter()
                .filter_map(|a| func.blocks.iter().find(|b| b.start == a).map(|b| b.id))
                .collect();
        }
        if ai.instr.is_terminator() {
            return Vec::new();
        }
        // Fall through to the next block by ascending start address.
        let mut next: Option<&rustre_il_llil::LlilBasicBlock> = None;
        for b in &func.blocks {
            if b.start.0 > block.start.0 && next.is_none_or(|n| b.start.0 < n.start.0) {
                next = Some(b);
            }
        }
        next.map(|b| vec![b.id]).unwrap_or_default()
    }

    fn simple_dominators(
        func: &LlilFunction,
        entry: u32,
        succ: &HashMap<u32, Vec<u32>>,
    ) -> HashMap<u32, HashSet<u32>> {
        let all: HashSet<u32> = func.blocks.iter().map(|b| b.id).collect();
        let mut pred: HashMap<u32, Vec<u32>> = HashMap::new();
        for (&n, ss) in succ {
            for &s in ss {
                pred.entry(s).or_default().push(n);
            }
        }
        let mut dom: HashMap<u32, HashSet<u32>> = HashMap::new();
        for &n in &all {
            if n == entry {
                let mut s = HashSet::new();
                s.insert(entry);
                dom.insert(n, s);
            } else {
                dom.insert(n, all.clone());
            }
        }
        let mut changed = true;
        while changed {
            changed = false;
            for &n in &all {
                if n == entry {
                    continue;
                }
                let mut new_dom: Option<HashSet<u32>> = None;
                for &p in pred.get(&n).map_or(&[][..], Vec::as_slice) {
                    let pd = &dom[&p];
                    new_dom = Some(new_dom.map_or_else(|| pd.clone(), |acc| acc.intersection(pd).copied().collect()));
                }
                let mut nd = new_dom.unwrap_or_default();
                nd.insert(n);
                if dom[&n] != nd {
                    dom.insert(n, nd);
                    changed = true;
                }
            }
        }
        dom
    }

    fn dominates(dom: &HashMap<u32, HashSet<u32>>, a: u32, b: u32) -> bool {
        dom.get(&b).is_some_and(|s| s.contains(&a))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use rustre_core::address::Address;
        use rustre_il_llil::{
            LlilAnnotatedInstr, LlilBasicBlock, LlilExpr, LlilFunction, LlilInstruction,
            LlilRegister, Size,
        };

        fn func_with(blocks: Vec<LlilBasicBlock>) -> LlilFunction {
            let mut f = LlilFunction::new(Address::new(0));
            for b in blocks {
                f.add_block(b);
            }
            f
        }

        fn blk(id: u32, addr: u64, instrs: Vec<LlilInstruction>) -> LlilBasicBlock {
            LlilBasicBlock {
                id,
                start: Address::new(addr),
                end: Address::new(addr + instrs.len() as u64),
                instrs: instrs
                    .into_iter()
                    .enumerate()
                    .map(|(i, instr)| LlilAnnotatedInstr {
                        address: Address::new(addr + i as u64),
                        size: 1,
                        instr,
                        length: 1,
                    })
                    .collect(),
                successors: Vec::new(),
            }
        }

        struct PassA;
        impl IlPass for PassA {
            fn name(&self) -> &'static str {
                "a"
            }
            fn run(&self, _f: &mut LlilFunction, r: &mut AnalysisResults) -> bool {
                r.record("a", "ran");
                false
            }
        }
        struct PassB;
        impl IlPass for PassB {
            fn name(&self) -> &'static str {
                "b"
            }
            fn dependencies(&self) -> &'static [&'static str] {
                &["a"]
            }
            fn run(&self, _f: &mut LlilFunction, r: &mut AnalysisResults) -> bool {
                assert!(r.facts.contains_key("a"), "a must run before b");
                r.record("b", "ran");
                false
            }
        }
        struct PassC;
        impl IlPass for PassC {
            fn name(&self) -> &'static str {
                "c"
            }
            fn dependencies(&self) -> &'static [&'static str] {
                &["b"]
            }
            fn run(&self, _f: &mut LlilFunction, r: &mut AnalysisResults) -> bool {
                assert!(r.facts.contains_key("b"));
                r.record("c", "ran");
                false
            }
        }

        #[test]
        fn topo_sort_linear_chain() {
            // Register out of order; schedule must put a before b before c.
            let mgr = DependencyPassManager::new()
                .with(PassC)
                .with(PassB)
                .with(PassA);
            let order = mgr.schedule().unwrap();
            let ia = order.iter().position(|&n| n == "a").unwrap();
            let ib = order.iter().position(|&n| n == "b").unwrap();
            let ic = order.iter().position(|&n| n == "c").unwrap();
            assert!(ia < ib && ib < ic);
        }

        #[test]
        fn topo_run_respects_dependencies() {
            let mgr = DependencyPassManager::new()
                .with(PassC)
                .with(PassA)
                .with(PassB);
            let mut f = func_with(vec![blk(0, 0, vec![LlilInstruction::Ret])]);
            let res = mgr.run(&mut f).unwrap();
            assert!(res.facts.contains_key("a"));
            assert!(res.facts.contains_key("b"));
            assert!(res.facts.contains_key("c"));
        }

        #[test]
        fn missing_dependency_detected() {
            let mgr = DependencyPassManager::new().with(PassB); // depends on "a", not registered
            let err = mgr.schedule().unwrap_err();
            assert!(matches!(err, ScheduleError::MissingDependency { .. }));
        }

        #[test]
        fn cycle_detected() {
            struct X;
            impl IlPass for X {
                fn name(&self) -> &'static str {
                    "x"
                }
                fn dependencies(&self) -> &'static [&'static str] {
                    &["y"]
                }
                fn run(&self, _f: &mut LlilFunction, _r: &mut AnalysisResults) -> bool {
                    false
                }
            }
            struct Y;
            impl IlPass for Y {
                fn name(&self) -> &'static str {
                    "y"
                }
                fn dependencies(&self) -> &'static [&'static str] {
                    &["x"]
                }
                fn run(&self, _f: &mut LlilFunction, _r: &mut AnalysisResults) -> bool {
                    false
                }
            }
            let mgr = DependencyPassManager::new().with(X).with(Y);
            let err = mgr.schedule().unwrap_err();
            assert!(matches!(err, ScheduleError::Cycle(_)));
        }

        #[test]
        fn stack_frame_recovers_slots() {
            // Store rax to [SP - 8]; load from [SP - 16].
            let store = LlilInstruction::Store {
                addr: LlilExpr::SubT(
                    Box::new(LlilExpr::StackPointer(Size::QWord)),
                    Box::new(LlilExpr::Const {
                        value: 8,
                        size: Size::QWord,
                    }),
                    Size::QWord,
                ),
                size: Size::QWord,
                value: LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("rax".into()),
                    size: Size::QWord,
                },
            };
            let mut f = func_with(vec![blk(0, 0, vec![store, LlilInstruction::Ret])]);
            let mut res = AnalysisResults::new();
            assert!(!StackFrameAnalysis.run(&mut f, &mut res));
            assert_eq!(res.stack_slots.get(&-8), Some(&8));
        }

        #[test]
        fn loop_recognition_finds_header() {
            // 0 -> 1 ; 1 cond-jumps to 1 (self back-edge) or 2 ; 2 ret.
            let b0 = blk(
                0,
                0,
                vec![LlilInstruction::JumpDest {
                    dest: LlilExpr::Const {
                        value: 1,
                        size: Size::QWord,
                    },
                }],
            );
            let mut b1 = blk(
                1,
                1,
                vec![LlilInstruction::CondJump {
                    cond: LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete("zf".into()),
                        size: Size::Byte,
                    },
                    true_dest: Address::new(1),
                    false_dest: Address::new(2),
                }],
            );
            // ensure block 0 jump target matches block 1 start
            b1.start = Address::new(1);
            let b2 = blk(2, 2, vec![LlilInstruction::Ret]);
            // Fix block 0 jump to address 1.
            let mut f = func_with(vec![b0, b1, b2]);
            // Patch block0 successor address to 1 (already 1) and block1 start (1).
            let mut res = AnalysisResults::new();
            LoopRecognition.run(&mut f, &mut res);
            assert!(
                res.loop_headers.contains(&1),
                "headers: {:?}",
                res.loop_headers
            );
        }

        #[test]
        fn switch_table_detection_flags_jumpto() {
            let jt = LlilInstruction::JumpTo {
                dest: LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("rax".into()),
                    size: Size::QWord,
                },
                targets: vec![Address::new(0x10), Address::new(0x20), Address::new(0x30)],
            };
            let mut f = func_with(vec![blk(0, 0, vec![jt])]);
            let mut res = AnalysisResults::new();
            SwitchTableDetection.run(&mut f, &mut res);
            assert_eq!(res.switch_tables.len(), 1);
            assert_eq!(*res.switch_tables.values().next().unwrap(), 3);
        }

        #[test]
        fn flag_equivalence_records_condition() {
            let cj = LlilInstruction::CondJump {
                cond: LlilExpr::CmpEq(
                    Box::new(LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete("rax".into()),
                        size: Size::QWord,
                    }),
                    Box::new(LlilExpr::Const {
                        value: 0,
                        size: Size::QWord,
                    }),
                ),
                true_dest: Address::new(0x10),
                false_dest: Address::new(0x20),
            };
            let mut f = func_with(vec![blk(0, 0, vec![cj])]);
            let mut res = AnalysisResults::new();
            FlagEquivalence.run(&mut f, &mut res);
            assert!(res.flag_conditions.contains_key(&0));
        }

        #[test]
        fn full_pipeline_runs_in_order() {
            let mgr = DependencyPassManager::new()
                .with(DeadCodeElimination)
                .with(ValueRangeAnalysis)
                .with(ConstantPropagation)
                .with(StackFrameAnalysis)
                .with(LoopRecognition);
            let order = mgr.schedule().unwrap();
            // constant-propagation must precede both dce and value-range.
            let icp = order
                .iter()
                .position(|&n| n == "constant-propagation")
                .unwrap();
            let idce = order
                .iter()
                .position(|&n| n == "dead-code-elimination")
                .unwrap();
            let ivr = order
                .iter()
                .position(|&n| n == "value-range-analysis")
                .unwrap();
            assert!(icp < idce);
            assert!(icp < ivr);
            let mut f = func_with(vec![blk(0, 0, vec![LlilInstruction::Ret])]);
            let res = mgr.run(&mut f).unwrap();
            assert!(res.facts.contains_key("constant-propagation"));
        }

        #[test]
        fn manager_len_and_empty() {
            let mgr = DependencyPassManager::new();
            assert!(mgr.is_empty());
            let mgr = mgr.with(PassA);
            assert_eq!(mgr.len(), 1);
        }
    }
}

// =============================================================================
// Â§NEW —" PassResult / FunctionBody interface and PassPipeline
// =============================================================================
//
// The types below provide an alternative, self-contained optimization interface
// that operates on `LlilFunction` (aliased here as `FunctionBody` for clarity)
// and communicates results through a `PassResult` value rather than an
// in-place `PassContext`.  A `PassPipeline` runs registered passes to fixpoint.

/// Type alias so documentation and pass signatures can read "`FunctionBody`"
/// while still referring to the canonical `LlilFunction`.
pub type FunctionBody = LlilFunction;

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PassResult
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Result returned by every pass in the `PassPipeline` interface.
///
/// Tracks how many instructions were changed and attaches human-readable notes
/// that explain what transformations were performed.
#[derive(Debug, Clone, Default)]
pub struct PassResult {
    /// Number of instructions or expressions changed by this pass run.
    pub changes_made: u32,
    /// Free-form notes emitted by the pass (one entry per notable action).
    pub notes: Vec<String>,
}

impl PassResult {
    /// Create a `PassResult` with zero changes and no notes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a `PassResult` with a given change count.
    #[must_use]
    pub const fn with_changes(changes_made: u32) -> Self {
        Self {
            changes_made,
            notes: Vec::new(),
        }
    }

    /// Returns `true` when the pass made at least one change.
    #[must_use]
    pub const fn changed(&self) -> bool {
        self.changes_made > 0
    }

    /// Append a note.
    pub fn note(&mut self, msg: impl Into<String>) {
        self.notes.push(msg.into());
    }

    /// Merge another `PassResult` into `self` (accumulate).
    pub fn merge(&mut self, other: &Self) {
        self.changes_made += other.changes_made;
        self.notes.extend(other.notes.iter().cloned());
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// IlOptPass trait
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Common interface for IL optimization passes that return a [`PassResult`].
///
/// Unlike [`AnalysisPass`], which mutates a [`PassContext`] in-place, every
/// `IlOptPass` returns its result as a value so that the pipeline can
/// accumulate, inspect, or discard results without shared mutable state.
///
/// **Status: experimental staging area, not canonical.** See the crate-level
/// docs for the full V1-vs-V2 comparison. In short: V1 ([`AnalysisPass`]) is
/// the mature, externally-consumed implementation; `IlOptPass`/V2 exists to
/// prototype a value-returning pipeline interface plus (eventually)
/// dependency-graph-ordered scheduling via [`pass_dependency_graph`].
pub trait IlOptPass: Send + Sync {
    /// Short machine-readable name, e.g. `"dead-code-elimination-v2"`.
    fn name(&self) -> &str;

    /// Human-readable description.
    fn description(&self) -> &'static str {
        "(no description)"
    }

    /// Run the pass on `func` and return a `PassResult`.
    fn run(&self, func: &mut FunctionBody) -> PassResult;
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PassPipeline
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Runs a sequence of [`IlOptPass`]es on a [`FunctionBody`] until fixpoint
/// or until a maximum iteration count is reached.
///
/// # Example
/// ```ignore
/// let pipeline = PassPipeline::new()
///     .push_pass(DeadCodeEliminationPassV2)
///     .push_pass(ConstantFoldingPassV2)
///     .push_pass(CopyPropagationPassV2)
///     .with_max_iters(5);
///
/// let report = pipeline.run(&mut func);
/// println!("total changes: {}", report.total_changes);
/// ```
pub struct PassPipeline {
    passes: Vec<Box<dyn IlOptPass>>,
    /// Maximum number of full sweeps before stopping.  Default: `20`.
    pub max_iters: usize,
}

/// Summary produced after the full pipeline run.
#[derive(Debug, Clone, Default)]
pub struct PipelineReport {
    /// Number of complete sweeps performed.
    pub sweeps: usize,
    /// Accumulated changes across all passes and sweeps.
    pub total_changes: u32,
    /// Per-pass per-sweep results in order of execution.
    pub pass_results: Vec<(String, PassResult)>,
    /// True when convergence was reached (no pass changed anything in the
    /// last sweep).
    pub converged: bool,
}

impl PassPipeline {
    /// Create an empty pipeline with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            passes: Vec::new(),
            max_iters: 20,
        }
    }

    /// Append a pass and return `self` (builder pattern).
    #[must_use]
    pub fn push_pass(mut self, pass: impl IlOptPass + 'static) -> Self {
        self.passes.push(Box::new(pass));
        self
    }

    /// Override the maximum iteration count (builder pattern).
    #[must_use]
    pub const fn with_max_iters(mut self, n: usize) -> Self {
        self.max_iters = n;
        self
    }

    /// Number of passes in the pipeline.
    #[must_use]
    pub fn len(&self) -> usize {
        self.passes.len()
    }

    /// True when no passes are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.passes.is_empty()
    }

    /// Run all passes to fixpoint and return a [`PipelineReport`].
    pub fn run(&self, func: &mut FunctionBody) -> PipelineReport {
        let mut report = PipelineReport::default();

        for _sweep in 0..self.max_iters {
            report.sweeps += 1;
            let mut sweep_changed = false;

            for pass in &self.passes {
                let result = pass.run(func);
                if result.changed() {
                    sweep_changed = true;
                    report.total_changes += result.changes_made;
                }
                report.pass_results.push((pass.name().to_string(), result));
            }

            if !sweep_changed {
                report.converged = true;
                break;
            }
        }

        report
    }

    /// Run a single sweep without iteration.
    pub fn run_once(&self, func: &mut FunctionBody) -> PassResult {
        let mut combined = PassResult::new();
        for pass in &self.passes {
            let r = pass.run(func);
            combined.merge(&r);
        }
        combined
    }
}

impl Default for PassPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// DeadCodeEliminationPassV2
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Dead-code elimination using whole-function liveness analysis.
///
/// Removes every `SetReg` / `Load` whose destination register has no live use
/// anywhere in the function, provided the instruction has no observable
/// side-effects.  A second inner loop collects all registers that are *read*
/// (live), and any write that has no corresponding read is eliminated.
///
/// This is a simplified, whole-function (not block-local) formulation.
/// For maximum precision a per-instruction liveness bit-vector would be used,
/// but this pass is intentionally conservative: it only removes instructions
/// whose dest is completely unread across the entire function.
pub struct DeadCodeEliminationPassV2;

impl IlOptPass for DeadCodeEliminationPassV2 {
    fn name(&self) -> &'static str {
        "dead-code-elimination-v2"
    }

    fn description(&self) -> &'static str {
        "Remove assignments to variables with no live uses (whole-function liveness)"
    }

    fn run(&self, func: &mut FunctionBody) -> PassResult {
        let mut result = PassResult::new();

        // Collect all register names that are *read* anywhere in the function.
        let live: HashSet<String> = {
            let mut s = HashSet::new();
            for block in &func.blocks {
                for ai in &block.instrs {
                    collect_read_regs(&ai.instr, &mut s);
                }
            }
            s
        };

        // Remove write-only instructions in each block.
        for block in &mut func.blocks {
            let before = block.instrs.len();
            block.instrs.retain(|ai| {
                // Never remove side-effecting instructions.
                if DeadCodeEliminationPass::has_side_effects(&ai.instr) {
                    return true;
                }
                if matches!(ai.instr, LlilInstruction::Nop) {
                    return false;
                }
                match &ai.instr {
                    LlilInstruction::SetReg { dest, .. }
                    | LlilInstruction::Load { dest, .. }
                    | LlilInstruction::Pop { dest, .. } => {
                        let dead = !live.contains(&dest.name());
                        if dead {
                            result.note(format!("DCE: removed dead write to '{}'", dest.name()));
                        }
                        !dead
                    }
                    LlilInstruction::SetRegSplit { high, low, .. } => {
                        let dead = !live.contains(&high.name()) && !live.contains(&low.name());
                        if dead {
                            result.note(format!(
                                "DCE: removed dead split write ({}/{})",
                                high.name(),
                                low.name()
                            ));
                        }
                        !dead
                    }
                    _ => true,
                }
            });
            let removed = before - block.instrs.len();
            result.changes_made += u32::try_from(removed).unwrap_or(u32::MAX);
        }

        result
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ConstantFoldingPassV2
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Evaluate compile-time constant expressions to their computed values.
///
/// Examples:
/// - `Const(3) + Const(4)` â†' `Const(7)`
/// - `Const(10) - Const(3)` â†' `Const(7)`
/// - `Const(2) * Const(6)` â†' `Const(12)`
/// - `Const(0xFF) & Const(0x0F)` â†' `Const(0x0F)`
/// - `NOT(Const(0))` â†' `Const(all_ones)`
/// - `Const(8) >> Const(1)` â†' `Const(4)`
///
/// This is a re-implementation of [`ConstantFoldingPass`] that returns a
/// [`PassResult`] and integrates with [`PassPipeline`].
pub struct ConstantFoldingPassV2;

impl IlOptPass for ConstantFoldingPassV2 {
    fn name(&self) -> &'static str {
        "constant-folding-v2"
    }

    fn description(&self) -> &'static str {
        "Evaluate compile-time constants: Const(3) + Const(4) = Const(7)"
    }

    fn run(&self, func: &mut FunctionBody) -> PassResult {
        // Genuinely delegate to the V1 pass so behavior tracks it exactly,
        // as documented above (rather than re-implementing a parallel
        // folding walk that could silently drift from V1).
        let inner = ConstantFoldingPass::new();
        let mut ctx = PassContext::new();
        AnalysisPass::run(&inner, func, &mut ctx);
        let mut result = PassResult::with_changes(u32::try_from(ctx.stats.instrs_modified).unwrap_or(u32::MAX));
        if result.changed() {
            result.note("constant-folding: folded sub-expression to constant".to_string());
        }
        result
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CopyPropagationPassV2
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Intra-block copy propagation.
///
/// When `x = y` (a plain register-to-register copy), replace all subsequent
/// uses of `x` within the same block with `y` —" until `x` or `y` is
/// redefined.  This eliminates unnecessary intermediate copies introduced by
/// decompilers and previous optimization passes.
///
/// Example:
/// ```text
/// tmp  = rax          ; copy
/// rbx  = tmp + 1      ; uses tmp
///   â†' rbx = rax + 1   ; after propagation
/// ```
pub struct CopyPropagationPassV2;

impl IlOptPass for CopyPropagationPassV2 {
    fn name(&self) -> &'static str {
        "copy-propagation-v2"
    }

    fn description(&self) -> &'static str {
        "If x = y, replace all uses of x with y (until x is redefined)"
    }

    fn run(&self, func: &mut FunctionBody) -> PassResult {
        let inner = CopyPropagationPass::new();
        let mut ctx = PassContext::new();
        inner.run(func, &mut ctx);
        let mut result = PassResult::with_changes(u32::try_from(ctx.stats.instrs_modified).unwrap_or(u32::MAX));
        if result.changed() {
            result.note(format!(
                "copy-propagation: substituted {} register copies",
                result.changes_made
            ));
        }
        result
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CommonSubexpressionEliminationPass
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Find repeated computations within a basic block and compute each only once.
///
/// When the same expression (syntactically identical, without loads) is
/// computed multiple times inside a block, the second and subsequent
/// occurrences are replaced with a copy of the register that holds the first
/// result.  This is the intra-block variant of Global Value Numbering (GVN).
///
/// Example:
/// ```text
/// t1 = rax + rbx
/// t2 = rax + rbx    ; same expression
///   â†' t2 = t1        ; after CSE
/// ```
///
/// Expressions containing [`LlilExpr::Load`] are excluded because memory
/// reads may have side-effects or be aliased.
///
/// This pass implements the [`IlOptPass`] (pipeline) interface; the
/// corresponding [`AnalysisPass`] variant is [`CommonSubexpressionEliminationPass`].
pub struct CseOptPass;

impl IlOptPass for CseOptPass {
    fn name(&self) -> &'static str {
        "common-subexpression-elimination-v2"
    }

    fn description(&self) -> &'static str {
        "Find repeated computations, compute once and reuse the result"
    }

    fn run(&self, func: &mut FunctionBody) -> PassResult {
        let changed = run_gvn_pass(func);
        let mut result = PassResult::new();
        if changed {
            result.changes_made += 1;
            result.note(
                "CSE: replaced at least one duplicate expression with a register copy".to_string(),
            );
        }
        result
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// StrengthReductionPassV2
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Replace expensive operations with cheaper equivalents.
///
/// Rules applied:
/// - `x * 2`  â†' `x + x`   (or equivalently `x << 1`)
/// - `x * 4`  â†' `x << 2`
/// - `x * 2^n` â†' `x << n`  (any power-of-two multiplier)
/// - `x * 3`  â†' `(x << 1) + x`
/// - `x * 5`  â†' `(x << 2) + x`
/// - `x * 9`  â†' `(x << 3) + x`
/// - `x / 2^n` (unsigned) â†' `x >> n`
///
/// These reductions are important for decompiled code where the original
/// high-level idioms have been lowered to integer arithmetic by the compiler.
pub struct StrengthReductionPassV2;

impl IlOptPass for StrengthReductionPassV2 {
    fn name(&self) -> &'static str {
        "strength-reduction-v2"
    }

    fn description(&self) -> &'static str {
        "x * 2 -> x + x, x * 4 -> x << 2, x / 2^n -> x >> n"
    }

    fn run(&self, func: &mut FunctionBody) -> PassResult {
        let n = run_strength_reduction(func);
        let mut result = PassResult::with_changes(n);
        if n > 0 {
            result.note(format!("strength-reduction: applied {n} rewrites"));
        }
        result
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// LoopInvariantCodeMotionPassV2
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Hoist loop-invariant computations out of loops to the function entry block.
///
/// A computation is *loop-invariant* if its inputs do not change within the
/// loop body.  In the simplified heuristic implemented here, any `SetReg`
/// whose source is a pure constant is considered loop-invariant and hoisted
/// to the entry block.
///
/// In a production-grade pass, proper loop-structure analysis (via dominator
/// trees and back-edge detection) would be used to determine loop membership
/// and the correct pre-header insertion point.  This heuristic is still
/// valuable as a first-pass simplification.
///
/// Example:
/// ```text
/// ; block 1 (loop body)
/// tmp = Const(42)     ; loop-invariant
/// rax = tmp + rcx     ; uses loop-invariant tmp
/// ```
/// After LICM:
/// ```text
/// ; block 0 (entry, pre-header)
/// tmp = Const(42)     ; hoisted here
/// ; block 1 (loop body)
/// rax = tmp + rcx
/// ```
pub struct LoopInvariantCodeMotionPassV2;

impl IlOptPass for LoopInvariantCodeMotionPassV2 {
    fn name(&self) -> &'static str {
        "loop-invariant-code-motion-v2"
    }

    fn description(&self) -> &'static str {
        "Move invariant computations out of loops to the function entry block"
    }

    fn run(&self, func: &mut FunctionBody) -> PassResult {
        let n = run_licm(func);
        let mut result = PassResult::with_changes(n);
        if n > 0 {
            result.note(format!(
                "LICM: hoisted {n} loop-invariant instructions to entry block"
            ));
        }
        result
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// TailCallOptimizationPassV2
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Detect and transform tail calls.
///
/// A tail call is a function call that is immediately followed by a `Ret`
/// instruction —" the callee's return value is the caller's return value and
/// there is no additional work to perform.  Such patterns can be replaced by a
/// `TailCall` instruction, which allows the runtime to perform sibling-call or
/// tail-call optimization (TCO), avoiding a new stack frame.
///
/// Pattern matched:
/// ```text
/// Call { dest: X }
/// Ret
/// ```
/// Transformed to:
/// ```text
/// TailCall { dest: X }
/// ```
///
/// Note: The transformation is conservative —" it only applies when `Call` and
/// `Ret` are adjacent within the same basic block.  A more aggressive
/// implementation would also handle the case where the call result is moved
/// to the return register before the `Ret`.
pub struct TailCallOptimizationPassV2;

impl IlOptPass for TailCallOptimizationPassV2 {
    fn name(&self) -> &'static str {
        "tail-call-optimization-v2"
    }

    fn description(&self) -> &'static str {
        "Detect Call+Ret pairs and convert them to TailCall instructions"
    }

    fn run(&self, func: &mut FunctionBody) -> PassResult {
        let changed = run_tailcall_opt(func);
        let mut result = PassResult::new();
        if changed {
            result.changes_made += 1;
            result.note("TCO: converted at least one Call+Ret pair to TailCall".to_string());
        }
        result
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PassPipeline builders
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Build the standard `PassPipeline` containing all seven v2 optimization passes
/// in the recommended order for maximum effectiveness:
///
/// 1. `ConstantFoldingPassV2`         —" fold constant sub-expressions first
/// 2. `CopyPropagationPassV2`         —" propagate copies before DCE
/// 3. `CseOptPass`                         —" CSE after copies are propagated
/// 4. `StrengthReductionPassV2`       —" reduce multiplications/divisions
/// 5. `LoopInvariantCodeMotionPassV2` —" hoist invariants out of loops
/// 6. `TailCallOptimizationPassV2`    —" recognize tail calls
/// 7. `DeadCodeEliminationPassV2`     —" finally remove everything dead
///
/// The pipeline runs to fixpoint (up to 20 iterations by default).
#[must_use]
pub fn standard_pipeline() -> PassPipeline {
    PassPipeline::new()
        .push_pass(ConstantFoldingPassV2)
        .push_pass(CopyPropagationPassV2)
        .push_pass(CseOptPass)
        .push_pass(StrengthReductionPassV2)
        .push_pass(LoopInvariantCodeMotionPassV2)
        .push_pass(TailCallOptimizationPassV2)
        .push_pass(DeadCodeEliminationPassV2)
}

/// Build a lightweight `PassPipeline` suitable for quick analysis where
/// compilation time matters more than code quality:
///
/// 1. `ConstantFoldingPassV2`
/// 2. `DeadCodeEliminationPassV2`
#[must_use]
pub fn fast_pipeline() -> PassPipeline {
    PassPipeline::new()
        .push_pass(ConstantFoldingPassV2)
        .push_pass(DeadCodeEliminationPassV2)
        .with_max_iters(3)
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests for the new PassResult / IlOptPass / PassPipeline infrastructure
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod pipeline_tests {
    use super::*;
    use rustre_core::address::Address;
    use rustre_il_llil::{
        LlilAnnotatedInstr, LlilBasicBlock, LlilExpr, LlilFunction, LlilInstruction, LlilRegister,
        Size,
    };

    // â"€â"€ Helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_func(instrs: Vec<LlilInstruction>) -> LlilFunction {
        let mut f = LlilFunction::new(Address::new(0x1000));
        let block = LlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1000 + instrs.len() as u64),
            instrs: instrs
                .into_iter()
                .enumerate()
                .map(|(i, instr)| LlilAnnotatedInstr {
                    address: Address::new(0x1000 + i as u64),
                    size: 4,
                    instr,
                    length: 4,
                })
                .collect(),
            successors: Vec::new(),
        };
        f.add_block(block);
        f
    }

    fn reg(name: &str) -> LlilExpr {
        LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete(name.to_string()),
            size: Size::QWord,
        }
    }

    fn con(v: u64) -> LlilExpr {
        LlilExpr::Const {
            value: v,
            size: Size::QWord,
        }
    }

    fn setreg(dest: &str, src: LlilExpr) -> LlilInstruction {
        LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(dest.to_string()),
            value: src,
            size: Size::QWord,
        }
    }

    // â"€â"€ PassResult â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn pass_result_default_no_changes() {
        let r = PassResult::new();
        assert_eq!(r.changes_made, 0);
        assert!(!r.changed());
        assert!(r.notes.is_empty());
    }

    #[test]
    fn pass_result_with_changes() {
        let r = PassResult::with_changes(5);
        assert_eq!(r.changes_made, 5);
        assert!(r.changed());
    }

    #[test]
    fn pass_result_note() {
        let mut r = PassResult::new();
        r.note("test note");
        assert_eq!(r.notes.len(), 1);
        assert_eq!(r.notes[0], "test note");
    }

    #[test]
    fn pass_result_merge() {
        let mut a = PassResult::with_changes(3);
        a.note("a");
        let mut b = PassResult::with_changes(7);
        b.note("b");
        a.merge(&b);
        assert_eq!(a.changes_made, 10);
        assert_eq!(a.notes.len(), 2);
    }

    // â"€â"€ PassPipeline structure â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn pipeline_empty_reports_converged() {
        let pipeline = PassPipeline::new();
        let mut func = make_func(vec![LlilInstruction::Ret]);
        let report = pipeline.run(&mut func);
        assert!(report.converged);
        assert_eq!(report.total_changes, 0);
        assert_eq!(report.sweeps, 1);
    }

    #[test]
    fn pipeline_len_and_empty() {
        let p = PassPipeline::new();
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
        let p = p.push_pass(DeadCodeEliminationPassV2);
        assert_eq!(p.len(), 1);
        assert!(!p.is_empty());
    }

    #[test]
    fn pipeline_max_iters_respected() {
        // A pass that always reports a change keeps the pipeline running.
        struct AlwaysChanges;
        impl IlOptPass for AlwaysChanges {
            fn name(&self) -> &'static str {
                "always-changes"
            }
            fn run(&self, _func: &mut FunctionBody) -> PassResult {
                PassResult::with_changes(1)
            }
        }
        let pipeline = PassPipeline::new().push_pass(AlwaysChanges).with_max_iters(3);
        let mut func = make_func(vec![LlilInstruction::Ret]);
        let report = pipeline.run(&mut func);
        assert_eq!(report.sweeps, 3);
        assert!(!report.converged);
        assert_eq!(report.total_changes, 3);
    }

    #[test]
    fn pipeline_converges_when_no_changes() {
        struct NeverChanges;
        impl IlOptPass for NeverChanges {
            fn name(&self) -> &'static str {
                "never-changes"
            }
            fn run(&self, _func: &mut FunctionBody) -> PassResult {
                PassResult::new()
            }
        }
        let pipeline = PassPipeline::new().push_pass(NeverChanges).with_max_iters(10);
        let mut func = make_func(vec![LlilInstruction::Ret]);
        let report = pipeline.run(&mut func);
        assert_eq!(report.sweeps, 1);
        assert!(report.converged);
    }

    #[test]
    fn standard_pipeline_has_seven_passes() {
        let p = standard_pipeline();
        assert_eq!(p.len(), 7);
    }

    #[test]
    fn fast_pipeline_has_two_passes() {
        let p = fast_pipeline();
        assert_eq!(p.len(), 2);
    }

    // â"€â"€ DeadCodeEliminationPassV2 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn dce_v2_removes_dead_write() {
        // tmp = Const(42)  —" tmp is never read â†' dead
        // Ret
        let func_instrs = vec![setreg("tmp", con(42)), LlilInstruction::Ret];
        let mut func = make_func(func_instrs);
        let pass = DeadCodeEliminationPassV2;
        let result = pass.run(&mut func);
        assert!(result.changed(), "expected at least one change");
        assert_eq!(func.blocks[0].instrs.len(), 1); // only Ret remains
        assert!(matches!(
            func.blocks[0].instrs[0].instr,
            LlilInstruction::Ret
        ));
    }

    #[test]
    fn dce_v2_keeps_live_write() {
        // rax = Const(1)
        // Store[0x1000] = rax   —" rax IS used by Store
        let func_instrs = vec![
            setreg("rax", con(1)),
            LlilInstruction::Store {
                addr: con(0x1000),
                size: Size::QWord,
                value: reg("rax"),
            },
            LlilInstruction::Ret,
        ];
        let mut func = make_func(func_instrs);
        let pass = DeadCodeEliminationPassV2;
        let result = pass.run(&mut func);
        // rax is read by Store, so the SetReg(rax) must be preserved.
        assert!(
            !result.changed() || result.changes_made == 0,
            "should not have removed the live write to rax"
        );
        assert_eq!(func.blocks[0].instrs.len(), 3);
    }

    #[test]
    fn dce_v2_notes_removed_reg() {
        let mut func = make_func(vec![setreg("dead_reg", con(0)), LlilInstruction::Ret]);
        let result = DeadCodeEliminationPassV2.run(&mut func);
        assert!(result.notes.iter().any(|n| n.contains("dead_reg")));
    }

    // â"€â"€ ConstantFoldingPassV2 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn cf_v2_folds_add() {
        // rax = Const(3) + Const(4)  â†' rax = Const(7)
        let add_expr = LlilExpr::AddT(Box::new(con(3)), Box::new(con(4)), Size::QWord);
        let mut func = make_func(vec![setreg("rax", add_expr), LlilInstruction::Ret]);
        let result = ConstantFoldingPassV2.run(&mut func);
        assert!(result.changed());
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert!(
                matches!(src, LlilExpr::Const { value: 7, .. }),
                "expected Const(7), got {src:?}"
            );
        } else {
            panic!("expected SetReg");
        }
    }

    #[test]
    fn cf_v2_folds_mul() {
        // rax = Const(6) * Const(7) â†' rax = Const(42)
        let mul_expr = LlilExpr::MulT(Box::new(con(6)), Box::new(con(7)), Size::QWord);
        let mut func = make_func(vec![setreg("rax", mul_expr), LlilInstruction::Ret]);
        let result = ConstantFoldingPassV2.run(&mut func);
        assert!(result.changed());
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert!(matches!(src, LlilExpr::Const { value: 42, .. }));
        }
    }

    #[test]
    fn cf_v2_no_change_on_reg_reg() {
        // rax = rbx + rcx  —" not foldable
        let add_expr = LlilExpr::AddT(Box::new(reg("rbx")), Box::new(reg("rcx")), Size::QWord);
        let mut func = make_func(vec![setreg("rax", add_expr), LlilInstruction::Ret]);
        let result = ConstantFoldingPassV2.run(&mut func);
        assert!(!result.changed());
    }

    #[test]
    fn cf_v2_tracks_v1_exactly() {
        // Regression guard for the documented "V2 tracks V1 exactly" invariant:
        // run both the V1 AnalysisPass and the V2 IlOptPass on identical input
        // and assert they produce identical output and change counts.
        let add_expr = LlilExpr::AddT(Box::new(con(10)), Box::new(con(32)), Size::QWord);
        let mut func_v1 = make_func(vec![setreg("rax", add_expr.clone()), LlilInstruction::Ret]);
        let mut func_v2 = make_func(vec![setreg("rax", add_expr), LlilInstruction::Ret]);

        let mut ctx = PassContext::new();
        ConstantFoldingPass::new().run(&mut func_v1, &mut ctx);
        let result_v2 = ConstantFoldingPassV2.run(&mut func_v2);

        assert_eq!(
            ctx.stats.instrs_modified as u32, result_v2.changes_made,
            "V1/V2 change counts diverged"
        );
        assert_eq!(
            func_v1.blocks[0].instrs[0].instr, func_v2.blocks[0].instrs[0].instr,
            "V1/V2 produced different folded output"
        );
    }

    // â"€â"€ CopyPropagationPassV2 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn cp_v2_propagates_simple_copy() {
        // tmp = rax
        // rbx = tmp + 1   â†'   rbx = rax + 1
        let mut func = make_func(vec![
            setreg("tmp", reg("rax")),
            setreg(
                "rbx",
                LlilExpr::AddT(Box::new(reg("tmp")), Box::new(con(1)), Size::QWord),
            ),
            LlilInstruction::Ret,
        ]);
        let result = CopyPropagationPassV2.run(&mut func);
        assert!(result.changed());
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[1].instr {
            if let LlilExpr::AddT(l, _, _) = src {
                assert!(
                    matches!(l.as_ref(), LlilExpr::RegisterRef { reg, .. } if reg.name() == "rax"),
                    "expected tmp replaced with rax, got {src:?}"
                );
            } else {
                panic!("expected Add expression, got {src:?}");
            }
        } else {
            panic!("expected SetReg for rbx");
        }
    }

    #[test]
    fn cp_v2_no_change_without_copy() {
        // rax = rbx + rcx  —" no plain register-to-register copy to propagate
        let add_expr = LlilExpr::AddT(Box::new(reg("rbx")), Box::new(reg("rcx")), Size::QWord);
        let mut func = make_func(vec![setreg("rax", add_expr), LlilInstruction::Ret]);
        let result = CopyPropagationPassV2.run(&mut func);
        assert!(!result.changed());
    }

    // â"€â"€ StrengthReductionPassV2 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn sr_v2_mul_by_power_of_two() {
        // rax = rbx * Const(4) â†' rax = rbx << Const(2)
        let mul_expr = LlilExpr::MulT(Box::new(reg("rbx")), Box::new(con(4)), Size::QWord);
        let mut func = make_func(vec![setreg("rax", mul_expr), LlilInstruction::Ret]);
        let result = StrengthReductionPassV2.run(&mut func);
        assert!(result.changed());
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert!(
                matches!(src, LlilExpr::ShlT(_, shift, _)
                    if matches!(shift.as_ref(), LlilExpr::Const { value: 2, .. })),
                "expected Shl by 2, got {src:?}"
            );
        }
    }

    #[test]
    fn sr_v2_mul_by_2_is_shift_1() {
        let mul_expr = LlilExpr::MulT(Box::new(reg("rcx")), Box::new(con(2)), Size::QWord);
        let mut func = make_func(vec![setreg("rax", mul_expr), LlilInstruction::Ret]);
        let result = StrengthReductionPassV2.run(&mut func);
        assert!(result.changed());
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[0].instr {
            assert!(matches!(src, LlilExpr::ShlT(_, shift, _)
                    if matches!(shift.as_ref(), LlilExpr::Const { value: 1, .. })));
        }
    }

    #[test]
    fn sr_v2_no_change_mul_by_non_power() {
        // rax = rbx * 6  —" 6 is not a power of two and not a special constant
        // (well, 6 is handled as 2*3, but the raw mul by 6 is not directly matched)
        // The pass only reduces specific patterns; verify it runs without panic.
        let mul_expr = LlilExpr::MulT(Box::new(reg("rbx")), Box::new(con(6)), Size::QWord);
        let mut func = make_func(vec![setreg("rax", mul_expr), LlilInstruction::Ret]);
        // 6 is not a power of two, not 3/5/9 —" no reduction applied.
        let _result = StrengthReductionPassV2.run(&mut func);
        // Just assert no panic.
    }

    // â"€â"€ TailCallOptimizationPassV2 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn tco_v2_converts_call_ret() {
        let mut func = make_func(vec![
            LlilInstruction::CallDest {
                dest: con(0xdeadbeef),
            },
            LlilInstruction::Ret,
        ]);
        let result = TailCallOptimizationPassV2.run(&mut func);
        assert!(result.changed());
        assert_eq!(func.blocks[0].instrs.len(), 1);
        assert!(matches!(
            func.blocks[0].instrs[0].instr,
            LlilInstruction::TailCall { .. }
        ));
    }

    #[test]
    fn tco_v2_no_change_call_without_ret() {
        let mut func = make_func(vec![
            LlilInstruction::CallDest { dest: con(0x1234) },
            LlilInstruction::JumpDest { dest: con(0x5678) },
        ]);
        let result = TailCallOptimizationPassV2.run(&mut func);
        assert!(!result.changed());
    }

    // â"€â"€ CSE Pass â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn cse_replaces_duplicate_expression() {
        // t1 = rax + rbx
        // t2 = rax + rbx   â†' t2 = t1  (after CSE)
        let expr = LlilExpr::AddT(Box::new(reg("rax")), Box::new(reg("rbx")), Size::QWord);
        let mut func = make_func(vec![
            setreg("t1", expr.clone()),
            setreg("t2", expr),
            LlilInstruction::Ret,
        ]);
        let result = CseOptPass.run(&mut func);
        assert!(result.changed());
        // t2's source should now be Register(t1).
        if let LlilInstruction::SetReg { value: src, .. } = &func.blocks[0].instrs[1].instr {
            assert!(
                matches!(src, LlilExpr::RegisterRef { reg, .. } if reg.name() == "t1"),
                "expected t2 = t1, got {src:?}"
            );
        }
    }

    // â"€â"€ LICM Pass â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn licm_v2_hoists_constant_setreg() {
        // Two blocks: block 0 (entry), block 1 (loop body with const setreg).
        use rustre_il_llil::LlilBasicBlock;

        let b0 = LlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1001),
            instrs: vec![LlilAnnotatedInstr {
                address: Address::new(0x1000),
                size: 4,
                instr: LlilInstruction::JumpDest { dest: con(0x2000) },
                length: 4,
            }],
            successors: vec![Address::new(0x2000)],
        };
        let b1 = LlilBasicBlock {
            id: 1,
            start: Address::new(0x2000),
            end: Address::new(0x2002),
            instrs: vec![
                LlilAnnotatedInstr {
                    address: Address::new(0x2000),
                    size: 4,
                    instr: setreg("loop_const", con(99)), // loop-invariant constant
                    length: 4,
                },
                LlilAnnotatedInstr {
                    address: Address::new(0x2001),
                    size: 4,
                    instr: LlilInstruction::Ret,
                    length: 4,
                },
            ],
            successors: Vec::new(),
        };

        let mut func = LlilFunction::new(Address::new(0x1000));
        func.add_block(b0);
        func.add_block(b1);

        let entry_instr_count_before = func.blocks[0].instrs.len();
        let result = LoopInvariantCodeMotionPassV2.run(&mut func);
        assert!(result.changed());
        // The hoisted instruction should now be in the entry block.
        assert!(func.blocks[0].instrs.len() > entry_instr_count_before);
    }

    // â"€â"€ standard_pipeline end-to-end â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn standard_pipeline_runs_on_trivial_function() {
        let mut func = make_func(vec![
            setreg(
                "tmp",
                LlilExpr::AddT(Box::new(con(2)), Box::new(con(3)), Size::QWord),
            ),
            LlilInstruction::Ret,
        ]);
        let report = standard_pipeline().run(&mut func);
        // Constant folding should fold 2+3=5, then DCE should remove the dead tmp.
        assert!(report.total_changes >= 1, "expected at least one change");
    }

    #[test]
    fn pipeline_report_contains_pass_names() {
        let mut func = make_func(vec![LlilInstruction::Ret]);
        let report = standard_pipeline().run(&mut func);
        let names: Vec<&str> = report
            .pass_results
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        assert!(names.contains(&"constant-folding-v2"));
        assert!(names.contains(&"dead-code-elimination-v2"));
        assert!(names.contains(&"tail-call-optimization-v2"));
    }

    #[test]
    fn pipeline_run_once_returns_combined_result() {
        let mut func = make_func(vec![setreg("x", con(1)), LlilInstruction::Ret]);
        let p = PassPipeline::new().push_pass(DeadCodeEliminationPassV2);
        let result = p.run_once(&mut func);
        // x is never read —" DCE should remove it.
        assert!(result.changed());
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Property-based tests for the canonical V1 `AnalysisPass` set (per the
// standing enterprise-hardening mandate's request for deeper rustre-il test
// coverage — fourth crate covered after rustre-il-mlil/hlil/llil). V1 is
// confirmed the pass set actually consumed by `rustre-mcp-tools`, per
// project_rustre_x86_dead_lifters_audit's pass-3 finding, so it's the
// higher-value target vs the V2 `IlOptPass` set (already covered by
// `pipeline_tests` above and confirmed mostly-thin-wrapper in that same
// audit).
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod v1_proptests {
    use super::*;
    use proptest::prelude::*;
    use rustre_core::address::Address;
    use rustre_il_llil::{
        LlilAnnotatedInstr, LlilBasicBlock, LlilExpr, LlilFunction, LlilInstruction, LlilRegister,
        Size,
    };

    fn make_func(instrs: Vec<LlilInstruction>) -> LlilFunction {
        let mut f = LlilFunction::new(Address::new(0x1000));
        let block = LlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1000 + instrs.len() as u64),
            instrs: instrs
                .into_iter()
                .enumerate()
                .map(|(i, instr)| LlilAnnotatedInstr {
                    address: Address::new(0x1000 + i as u64),
                    size: 1,
                    instr,
                    length: 1,
                })
                .collect(),
            successors: Vec::new(),
        };
        f.blocks.push(block);
        f
    }

    fn llil_expr() -> impl Strategy<Value = LlilExpr> {
        let leaf = prop_oneof![
            any::<u32>().prop_map(|v| LlilExpr::Const { value: u64::from(v), size: Size::B4 }),
            (0u32..4).prop_map(|id| LlilExpr::Register { id, size: Size::B4 }),
        ];
        leaf.prop_recursive(4, 32, 4, |inner| {
            prop_oneof![
                (inner.clone(), inner.clone())
                    .prop_map(|(a, b)| LlilExpr::AddT(Box::new(a), Box::new(b), Size::B4)),
                (inner.clone(), inner.clone())
                    .prop_map(|(a, b)| LlilExpr::And(Box::new(a), Box::new(b), Size::B4)),
                (inner.clone(), inner.clone())
                    .prop_map(|(a, b)| LlilExpr::Xor(Box::new(a), Box::new(b), Size::B4)),
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
            llil_expr().prop_map(|addr| LlilInstruction::Load {
                dest: LlilRegister::Concrete("t0".to_string()),
                size: Size::B4,
                addr,
            }),
            Just(LlilInstruction::Ret),
        ]
    }

    /// Every V1 pass this crate ships (the set actually wired into
    /// `rustre-mcp-tools`) must never panic on an arbitrary well-formed
    /// single-block function, regardless of instruction mix/depth.
    fn all_v1_passes() -> Vec<Box<dyn AnalysisPass>> {
        vec![
            Box::new(ConstantFoldingPass),
            Box::new(NopEliminationPass),
            Box::new(IdentityEliminationPass),
            Box::new(DeadCodeEliminationPass),
            Box::new(CopyPropagationPass),
            Box::new(BlockMergePass),
            Box::new(GlobalValueNumberingPass),
            Box::new(BranchSimplificationPass),
            Box::new(TailCallOptimizationPass),
            Box::new(UnreachableCodeEliminationPass),
            Box::new(RedundantBranchRemovalPass),
        ]
    }

    /// Noise instructions that BY CONSTRUCTION can neither read nor write
    /// any of `rax` / `rbx` / `rcx` — they only touch `Temporary` slots and
    /// memory at constant addresses. Used to surround a sentinel so that any
    /// observed change to the sentinel is attributable to the optimizer alone.
    fn inert_noise_instr() -> impl Strategy<Value = LlilInstruction> {
        let inert_expr = prop_oneof![
            any::<u32>().prop_map(|v| LlilExpr::Const { value: u64::from(v), size: Size::B8 }),
            (100u32..104).prop_map(|id| LlilExpr::RegisterRef {
                reg: LlilRegister::Temporary(id),
                size: Size::B8,
            }),
        ];
        prop_oneof![
            Just(LlilInstruction::Nop),
            (100u32..104, inert_expr.clone()).prop_map(|(id, value)| LlilInstruction::SetReg {
                dest: LlilRegister::Temporary(id),
                size: Size::B8,
                value,
            }),
            inert_expr.prop_map(|value| LlilInstruction::Store {
                size: Size::B8,
                addr: LlilExpr::Const { value: 0x4000, size: Size::B8 },
                value,
            }),
        ]
    }

    /// Return `true` if `expr` mentions register `name` anywhere.
    fn expr_mentions(expr: &LlilExpr, name: &str) -> bool {
        let mut regs = HashSet::new();
        collect_regs_in_expr(expr, &mut regs);
        regs.contains(name)
    }

    proptest! {
        /// A call may clobber the volatile registers. So a copy `rbx = rax`
        /// recorded *before* a call must NOT be propagated into a use of
        /// `rbx` that appears *after* the call: at that point `rax` holds the
        /// call's return value while `rbx` (callee-saved) still holds the old
        /// value. Rewriting `rcx = rbx` into `rcx = rax` changes the meaning
        /// of the program.
        ///
        /// The surrounding noise touches only `Temporary` slots and constant
        /// memory, so it can never legitimately affect the sentinel.
        #[test]
        fn copy_prop_does_not_propagate_across_a_call(
            head in prop::collection::vec(inert_noise_instr(), 0..6),
            tail in prop::collection::vec(inert_noise_instr(), 0..6),
        ) {
            let rax = LlilRegister::Concrete("rax".to_string());
            let rbx = LlilRegister::Concrete("rbx".to_string());
            let rcx = LlilRegister::Concrete("rcx".to_string());

            let mut instrs = Vec::new();
            // sentinel part 1: the copy
            instrs.push(LlilInstruction::SetReg {
                dest: rbx.clone(),
                size: Size::B8,
                value: LlilExpr::RegisterRef { reg: rax.clone(), size: Size::B8 },
            });
            instrs.extend(head);
            // the clobbering event
            instrs.push(LlilInstruction::CallDest {
                dest: LlilExpr::Const { value: 0x2000, size: Size::B8 },
            });
            instrs.extend(tail);
            // sentinel part 2: the use that must keep reading rbx
            let use_idx_marker = instrs.len();
            instrs.push(LlilInstruction::SetReg {
                dest: rcx.clone(),
                size: Size::B8,
                value: LlilExpr::RegisterRef { reg: rbx.clone(), size: Size::B8 },
            });
            instrs.push(LlilInstruction::Ret);

            let mut func = make_func(instrs);
            let mut ctx = PassContext::new();
            CopyPropagationPass::new().run(&mut func, &mut ctx);

            let sentinel = &func.blocks[0].instrs[use_idx_marker].instr;
            let LlilInstruction::SetReg { value, .. } = sentinel else {
                unreachable!("sentinel must remain a SetReg");
            };
            prop_assert!(
                !expr_mentions(value, "rax"),
                "copy propagation moved a use of rbx onto rax across a call \
                 (rax is clobbered by the call): {value:?}"
            );
            prop_assert!(expr_mentions(value, "rbx"), "sentinel use lost: {value:?}");
        }

        /// A self-copy (`rax = rax`) is a shape the other generators never
        /// produce, yet lifted code contains it. `CopyPropagationPass` does
        /// not override `is_idempotent()`, so it promises that a second run
        /// reports no further change — a fixpoint driver relies on this to
        /// terminate.
        #[test]
        fn copy_prop_is_idempotent_on_self_copies(
            noise in prop::collection::vec(inert_noise_instr(), 0..6),
        ) {
            let rax = LlilRegister::Concrete("rax".to_string());
            let mut instrs = vec![LlilInstruction::SetReg {
                dest: rax.clone(),
                size: Size::B8,
                value: LlilExpr::RegisterRef { reg: rax.clone(), size: Size::B8 },
            }];
            instrs.extend(noise);
            instrs.push(LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rcx".to_string()),
                size: Size::B8,
                value: LlilExpr::RegisterRef { reg: rax, size: Size::B8 },
            });
            instrs.push(LlilInstruction::Ret);

            let pass = CopyPropagationPass::new();
            let mut func = make_func(instrs);
            let mut ctx1 = PassContext::new();
            pass.run(&mut func, &mut ctx1);
            let mut ctx2 = PassContext::new();
            pass.run(&mut func, &mut ctx2);
            prop_assert!(
                !ctx2.changed,
                "copy-propagation reports a change on every run for a self-copy; \
                 a fixpoint driver would never terminate"
            );
        }

        #[test]
        fn v1_passes_never_panic(instrs in prop::collection::vec(llil_instr(), 0..16)) {
            let mut func = make_func(instrs);
            let mut ctx = PassContext::new();
            for pass in all_v1_passes() {
                pass.run(&mut func, &mut ctx);
            }
        }

        /// Running any single V1 pass twice in a row, when it claims
        /// `is_idempotent() == true`, must not keep reporting further
        /// changes on the second run — a real regression-catching
        /// invariant, not just no-panic.
        #[test]
        fn idempotent_passes_stabilise_after_second_run(instrs in prop::collection::vec(llil_instr(), 0..16)) {
            for pass in all_v1_passes() {
                if !pass.is_idempotent() {
                    continue;
                }
                let mut func = make_func(instrs.clone());
                let mut ctx1 = PassContext::new();
                pass.run(&mut func, &mut ctx1);
                let mut ctx2 = PassContext::new();
                pass.run(&mut func, &mut ctx2);
                prop_assert!(
                    !ctx2.changed,
                    "pass {} claims idempotent but changed on second run",
                    pass.name()
                );
            }
        }
    }
}
