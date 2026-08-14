//! IL optimization pipeline for `rustre-il-passes`.
//!
//! Provides an optimization pipeline with multiple levels (O0–O3), pass groups,
//! inlining, loop optimization, tail-call optimization, and dead store elimination.

use std::collections::HashMap;
use std::fmt;

use rustre_il_llil::{LlilAnnotatedInstr, LlilExpr, LlilFunction, LlilInstruction};

pub use rustre_core::address::Address;
pub use rustre_il_llil::{LlilRegister, Size};

// ---------------------------------------------------------------------------
// OptimizationLevel
// ---------------------------------------------------------------------------

/// Optimization level, analogous to -O0 through -O3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OptimizationLevel {
    /// No optimization. Useful for debugging decompiled output.
    O0,
    /// Minimal optimizations: dead code, constant folding.
    O1,
    /// Standard optimizations: all O1 passes plus CSE, strength reduction.
    O2,
    /// Aggressive optimization: all O2 passes plus inlining, loop opts.
    O3,
}

impl OptimizationLevel {
    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::O0 => "O0",
            Self::O1 => "O1",
            Self::O2 => "O2",
            Self::O3 => "O3",
        }
    }

    /// Whether inlining is enabled at this level.
    #[must_use]
    pub fn inlining_enabled(self) -> bool {
        self >= Self::O3
    }

    /// Whether loop optimizations are enabled.
    #[must_use]
    pub fn loop_opt_enabled(self) -> bool {
        self >= Self::O2
    }

    /// Whether tail-call optimization is enabled.
    #[must_use]
    pub fn tco_enabled(self) -> bool {
        self >= Self::O2
    }
}

impl fmt::Display for OptimizationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// PassGroup
// ---------------------------------------------------------------------------

/// A named group of related optimization passes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PassGroup {
    Canonicalization,
    Cleanup,
    StrengthReduction,
    Inlining,
    LoopOpt,
    TailCallOpt,
    DeadStoreElim,
    Custom(String),
}

impl fmt::Display for PassGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Canonicalization => "canonicalization",
            Self::Cleanup => "cleanup",
            Self::StrengthReduction => "strength_reduction",
            Self::Inlining => "inlining",
            Self::LoopOpt => "loop_opt",
            Self::TailCallOpt => "tail_call_opt",
            Self::DeadStoreElim => "dead_store_elim",
            Self::Custom(n) => n.as_str(),
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// PassResult
// ---------------------------------------------------------------------------

/// The result of running one pass.
#[derive(Debug, Clone, Default)]
pub struct PassResult {
    pub pass_name: String,
    pub group: Option<PassGroup>,
    pub changes: usize,
    pub elapsed_us: u64,
}

impl PassResult {
    #[must_use]
    pub fn new(pass_name: impl Into<String>, changes: usize) -> Self {
        Self {
            pass_name: pass_name.into(),
            changes,
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// InliningPass
// ---------------------------------------------------------------------------

/// Inline small functions at call sites.
#[derive(Debug, Clone, Default)]
pub struct InliningPass {
    pub max_inline_size: usize,
    pub inlined_count: usize,
}

impl InliningPass {
    #[must_use]
    pub const fn new(max_inline_size: usize) -> Self {
        Self {
            max_inline_size,
            inlined_count: 0,
        }
    }

    /// Attempt to inline functions from `callees` at call sites in `func`.
    /// Returns the number of inlining replacements performed.
    pub fn run(&mut self, func: &mut LlilFunction, callees: &HashMap<u64, &LlilFunction>) -> usize {
        let mut changes = 0;
        let mut new_instrs: Vec<LlilAnnotatedInstr> = Vec::with_capacity(func.instructions.len());
        for ai in func.instructions.drain(..) {
            let target_opt = match &ai.instr {
                LlilInstruction::Call(target) => Some(target.clone()),
                LlilInstruction::CallDest { dest } => Some(dest.clone()),
                _ => None,
            };
            if let Some(target) = target_opt
                && let LlilExpr::Const { value: addr, .. } = target
                    && let Some(callee) = callees.get(&{ addr })
                        && callee.instructions.len() <= self.max_inline_size {
                            new_instrs.extend(callee.instructions.iter().cloned());
                            changes += 1;
                            self.inlined_count += 1;
                            continue;
                        }
            new_instrs.push(ai);
        }
        func.instructions = new_instrs;
        changes
    }
}

// ---------------------------------------------------------------------------
// LoopOptimization
// ---------------------------------------------------------------------------

/// Detects and optimizes loop constructs.
#[derive(Debug, Clone, Default)]
pub struct LoopOptimization {
    pub loops_detected: usize,
    pub hoisted_invariants: usize,
    pub unrolled_loops: usize,
}

impl LoopOptimization {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Detect simple back-edge loops in a function.
    /// Returns the number of loops found.
    pub fn detect_loops(&mut self, func: &LlilFunction) -> usize {
        // Simplified heuristic: count back edges (Jump to an earlier address).
        let mut loops = 0;
        let base = func.address;
        for (i, ai) in func.instructions.iter().enumerate() {
            let target_opt = match &ai.instr {
                LlilInstruction::Jump(t) => Some(t),
                LlilInstruction::JumpDest { dest } => Some(dest),
                _ => None,
            };
            if let Some(target) = target_opt
                && let LlilExpr::Const { value, .. } = target {
                    // If jump target is before the current position.
                    if *value < base.as_u64().saturating_add(i as u64) {
                        loops += 1;
                    }
                }
        }
        self.loops_detected += loops;
        loops
    }

    /// Hoist loop-invariant stores (stub).
    pub const fn hoist_invariants(&mut self, _func: &mut LlilFunction) -> usize {
        0
    }

    /// Unroll small loops up to `max_iters` times (stub).
    pub const fn unroll(&mut self, _func: &mut LlilFunction, _max_iters: usize) -> usize {
        0
    }
}

// ---------------------------------------------------------------------------
// TailCallOptimization
// ---------------------------------------------------------------------------

/// Replaces tail calls with jumps.
#[derive(Debug, Clone, Default)]
pub struct TailCallOptimization {
    pub transformed_count: usize,
}

impl TailCallOptimization {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Transform tail calls: `call f; ret` → `jump f`.
    /// Returns the number of tail calls transformed.
    pub fn run(&mut self, func: &mut LlilFunction) -> usize {
        let n = func.instructions.len();
        if n < 2 {
            return 0;
        }
        let mut changes = 0;
        for i in 0..n - 1 {
            let is_call = matches!(
                &func.instructions[i].instr,
                LlilInstruction::Call(_) | LlilInstruction::CallDest { .. }
            );
            let is_ret = matches!(
                &func.instructions[i + 1].instr,
                LlilInstruction::Ret | LlilInstruction::Return { .. }
            );
            if is_call && is_ret {
                let new_jump = match func.instructions[i].instr.clone() {
                    LlilInstruction::Call(t) => Some(LlilInstruction::Jump(t)),
                    LlilInstruction::CallDest { dest } => Some(LlilInstruction::JumpDest { dest }),
                    _ => None,
                };
                if let Some(jump) = new_jump {
                    func.instructions[i].instr = jump;
                    changes += 1;
                    self.transformed_count += 1;
                }
            }
        }
        changes
    }
}

// ---------------------------------------------------------------------------
// DeadStoreElimination
// ---------------------------------------------------------------------------

/// Eliminates stores to memory locations that are never subsequently read.
#[derive(Debug, Clone, Default)]
pub struct DeadStoreElimination {
    pub eliminated: usize,
}

impl DeadStoreElimination {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove stores to addresses that are immediately overwritten before being read.
    /// Returns the number of dead stores removed.
    pub fn run(&mut self, func: &mut LlilFunction) -> usize {
        // Simplified: remove consecutive stores to the same constant address.
        // Single-pass O(n) using retain_mut with a lookahead via prev_addr.
        let before = func.instructions.len();
        let mut prev_addr: Option<u64> = None;
        // We want to drop the *earlier* of two consecutive same-address stores.
        // Iterate in reverse: keep the last store in any run, drop earlier ones.
        let mut keep: Vec<bool> = Vec::with_capacity(before);
        keep.resize(before, true);
        for i in (0..before).rev() {
            let addr_i = Self::get_const_store_addr(&func.instructions[i].instr);
            match (addr_i, prev_addr) {
                (Some(a), Some(b)) if a == b => keep[i] = false,
                _ => {}
            }
            prev_addr = addr_i;
        }
        let mut idx = 0;
        func.instructions.retain(|_| {
            let k = keep[idx];
            idx += 1;
            k
        });
        let changes = before - func.instructions.len();
        self.eliminated += changes;
        changes
    }

    const fn get_const_store_addr(instr: &LlilInstruction) -> Option<u64> {
        if let LlilInstruction::Store {
            addr: LlilExpr::Const { value, .. },
            ..
        } = instr
        {
            Some(*value)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// PipelineStats
// ---------------------------------------------------------------------------

/// Statistics from the full optimization pipeline run.
#[derive(Debug, Clone, Default)]
pub struct PipelineStats {
    pub passes_run: usize,
    pub total_changes: usize,
    pub elapsed_us: u64,
    pub per_pass: Vec<PassResult>,
}

impl PipelineStats {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, result: PassResult) {
        self.total_changes += result.changes;
        self.passes_run += 1;
        self.per_pass.push(result);
    }
}

impl fmt::Display for PipelineStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PipelineStats: {} passes, {} total changes",
            self.passes_run, self.total_changes
        )
    }
}

// ---------------------------------------------------------------------------
// OptimizationPipeline
// ---------------------------------------------------------------------------

/// A configurable optimization pipeline.
pub struct OptimizationPipeline {
    pub level: OptimizationLevel,
    pub inliner: InliningPass,
    pub loop_opt: LoopOptimization,
    pub tco: TailCallOptimization,
    pub dse: DeadStoreElimination,
    pub stats: PipelineStats,
    /// Registered pass names (in order).
    pass_names: Vec<String>,
    /// Pass group membership.
    pass_groups: HashMap<String, PassGroup>,
}

impl OptimizationPipeline {
    /// Create a pipeline at the given optimization level.
    #[must_use]
    pub fn new(level: OptimizationLevel) -> Self {
        let mut pipeline = Self {
            level,
            inliner: InliningPass::new(20),
            loop_opt: LoopOptimization::new(),
            tco: TailCallOptimization::new(),
            dse: DeadStoreElimination::new(),
            stats: PipelineStats::new(),
            pass_names: Vec::new(),
            pass_groups: HashMap::new(),
        };
        pipeline.configure_for_level(level);
        pipeline
    }

    fn configure_for_level(&mut self, level: OptimizationLevel) {
        // O1+: cleanup passes.
        if level >= OptimizationLevel::O1 {
            self.register_pass("dead_code_elimination", PassGroup::Cleanup);
            self.register_pass("constant_folding", PassGroup::Cleanup);
            self.register_pass("nop_elimination", PassGroup::Canonicalization);
        }
        // O2+: strength reduction, TCO, DSE.
        if level >= OptimizationLevel::O2 {
            self.register_pass("strength_reduction", PassGroup::StrengthReduction);
            self.register_pass("tail_call_optimization", PassGroup::TailCallOpt);
            self.register_pass("dead_store_elimination", PassGroup::DeadStoreElim);
            self.register_pass("loop_invariant_hoisting", PassGroup::LoopOpt);
        }
        // O3+: inlining, aggressive loop opts.
        if level >= OptimizationLevel::O3 {
            self.register_pass("function_inlining", PassGroup::Inlining);
            self.register_pass("loop_unrolling", PassGroup::LoopOpt);
            self.register_pass("aggressive_dce", PassGroup::Cleanup);
        }
    }

    /// Register a pass by name into a group.
    pub fn register_pass(&mut self, name: impl Into<String>, group: PassGroup) {
        let name = name.into();
        if !self.pass_names.contains(&name) {
            self.pass_names.push(name.clone());
            self.pass_groups.insert(name, group);
        }
    }

    /// Names of all registered passes.
    #[must_use]
    pub fn pass_names(&self) -> &[String] {
        &self.pass_names
    }

    /// Number of registered passes.
    #[must_use]
    pub const fn pass_count(&self) -> usize {
        self.pass_names.len()
    }

    /// Group of the given pass.
    #[must_use]
    pub fn group_of(&self, pass_name: &str) -> Option<&PassGroup> {
        self.pass_groups.get(pass_name)
    }

    /// Run the full pipeline on `func`.
    pub fn run(&mut self, func: &mut LlilFunction) -> usize {
        let mut total = 0;

        // Dead code / NOP elimination.
        if self.level >= OptimizationLevel::O1 {
            let before = func.instructions.len();
            func.instructions
                .retain(|i| !matches!(i.instr, LlilInstruction::Nop));
            let removed = before - func.instructions.len();
            if removed > 0 {
                total += removed;
                self.stats
                    .record(PassResult::new("nop_elimination", removed));
            }
        }

        // Dead store elimination.
        if self.level >= OptimizationLevel::O2 {
            let n = self.dse.run(func);
            if n > 0 {
                total += n;
                self.stats
                    .record(PassResult::new("dead_store_elimination", n));
            }
        }

        // Tail-call optimization.
        if self.level.tco_enabled() {
            let n = self.tco.run(func);
            if n > 0 {
                total += n;
                self.stats
                    .record(PassResult::new("tail_call_optimization", n));
            }
        }

        // Loop detection.
        if self.level.loop_opt_enabled() {
            self.loop_opt.detect_loops(func);
        }

        total
    }

    /// Run the pipeline on multiple functions.
    pub fn run_all(&mut self, functions: &mut [LlilFunction]) -> usize {
        functions.iter_mut().map(|f| self.run(f)).sum()
    }

    /// Create an O0 (no-op) pipeline.
    #[must_use]
    pub fn no_opt() -> Self {
        Self::new(OptimizationLevel::O0)
    }

    /// Create an O3 pipeline.
    #[must_use]
    pub fn aggressive() -> Self {
        Self::new(OptimizationLevel::O3)
    }
}

impl fmt::Debug for OptimizationPipeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OptimizationPipeline({}, {} passes)",
            self.level,
            self.pass_count()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func_with_nops(count: usize) -> LlilFunction {
        let mut func = LlilFunction::new(Address::new(0x1000));
        for _ in 0..count {
            func.instructions.push(LlilInstruction::Nop.into());
        }
        func
    }

    fn make_func_with_double_store() -> LlilFunction {
        let mut func = LlilFunction::new(Address::new(0x1000));
        let store_instr: LlilAnnotatedInstr = LlilInstruction::Store {
            addr: LlilExpr::Const {
                value: 0x2000,
                size: Size::B8,
            },
            value: LlilExpr::Const {
                value: 1,
                size: Size::B4,
            },
            size: Size::B4,
        }
        .into();
        func.instructions.push(store_instr.clone());
        func.instructions.push(store_instr);
        func
    }

    fn make_func_with_tail_call() -> LlilFunction {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.instructions.push(
            LlilInstruction::Call(LlilExpr::Const {
                value: 0x5000,
                size: Size::B8,
            })
            .into(),
        );
        func.instructions
            .push(LlilInstruction::Return { value: None }.into());
        func
    }

    // ── OptimizationLevel ─────────────────────────────────────────────────

    #[test]
    fn opt_level_ordering() {
        assert!(OptimizationLevel::O3 > OptimizationLevel::O0);
        assert!(OptimizationLevel::O1 < OptimizationLevel::O2);
    }

    #[test]
    fn opt_level_inlining() {
        assert!(!OptimizationLevel::O2.inlining_enabled());
        assert!(OptimizationLevel::O3.inlining_enabled());
    }

    #[test]
    fn opt_level_display() {
        assert_eq!(OptimizationLevel::O2.to_string(), "O2");
    }

    // ── InliningPass ──────────────────────────────────────────────────────

    #[test]
    fn inlining_inline_small_function() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.instructions.push(
            LlilInstruction::Call(LlilExpr::Const {
                value: 0x2000,
                size: Size::B8,
            })
            .into(),
        );

        let mut callee = LlilFunction::new(Address::new(0x2000));
        callee.instructions.push(LlilInstruction::Nop.into());

        let mut callees: HashMap<u64, &LlilFunction> = HashMap::new();
        callees.insert(0x2000, &callee);

        let mut inliner = InliningPass::new(10);
        let n = inliner.run(&mut func, &callees);
        assert_eq!(n, 1);
        assert_eq!(inliner.inlined_count, 1);
    }

    #[test]
    fn inlining_skip_large_function() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.instructions.push(
            LlilInstruction::Call(LlilExpr::Const {
                value: 0x2000,
                size: Size::B8,
            })
            .into(),
        );

        let mut callee = LlilFunction::new(Address::new(0x2000));
        for _ in 0..100 {
            callee.instructions.push(LlilInstruction::Nop.into());
        }

        let mut callees: HashMap<u64, &LlilFunction> = HashMap::new();
        callees.insert(0x2000, &callee);

        let mut inliner = InliningPass::new(5);
        let n = inliner.run(&mut func, &callees);
        assert_eq!(n, 0);
    }

    // ── LoopOptimization ──────────────────────────────────────────────────

    #[test]
    fn loop_detect_back_edge() {
        let mut func = LlilFunction::new(Address::new(0x1010));
        // Jump back to before the function start (simulated back edge).
        func.instructions.push(
            LlilInstruction::Jump(LlilExpr::Const {
                value: 0x1000,
                size: Size::B8,
            })
            .into(),
        );
        let mut lo = LoopOptimization::new();
        let count = lo.detect_loops(&func);
        assert_eq!(count, 1);
    }

    #[test]
    fn loop_detect_no_loops() {
        let func = make_func_with_nops(3);
        let mut lo = LoopOptimization::new();
        let count = lo.detect_loops(&func);
        assert_eq!(count, 0);
    }

    // ── TailCallOptimization ──────────────────────────────────────────────

    #[test]
    fn tco_transforms_tail_call() {
        let mut func = make_func_with_tail_call();
        let mut tco = TailCallOptimization::new();
        let n = tco.run(&mut func);
        assert_eq!(n, 1);
        assert!(matches!(func.instructions[0].instr, LlilInstruction::Jump(_)));
    }

    #[test]
    fn tco_no_transform_without_ret() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.instructions.push(LlilInstruction::Nop.into());
        let mut tco = TailCallOptimization::new();
        let n = tco.run(&mut func);
        assert_eq!(n, 0);
    }

    // ── DeadStoreElimination ──────────────────────────────────────────────

    #[test]
    fn dse_removes_consecutive_stores() {
        let mut func = make_func_with_double_store();
        let mut dse = DeadStoreElimination::new();
        let n = dse.run(&mut func);
        assert_eq!(n, 1);
        assert_eq!(func.instructions.len(), 1);
    }

    #[test]
    fn dse_keeps_distinct_stores() {
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.instructions.push(
            LlilInstruction::Store {
                addr: LlilExpr::Const {
                    value: 0x2000,
                    size: Size::B8,
                },
                value: LlilExpr::Const {
                    value: 1,
                    size: Size::B4,
                },
                size: Size::B4,
            }
            .into(),
        );
        func.instructions.push(
            LlilInstruction::Store {
                addr: LlilExpr::Const {
                    value: 0x3000,
                    size: Size::B8,
                },
                value: LlilExpr::Const {
                    value: 2,
                    size: Size::B4,
                },
                size: Size::B4,
            }
            .into(),
        );
        let mut dse = DeadStoreElimination::new();
        let n = dse.run(&mut func);
        assert_eq!(n, 0);
        assert_eq!(func.instructions.len(), 2);
    }

    // ── PipelineStats ─────────────────────────────────────────────────────

    #[test]
    fn pipeline_stats_record() {
        let mut s = PipelineStats::new();
        s.record(PassResult::new("test_pass", 5));
        assert_eq!(s.passes_run, 1);
        assert_eq!(s.total_changes, 5);
    }

    #[test]
    fn pipeline_stats_display() {
        let s = PipelineStats::new();
        let d = s.to_string();
        assert!(d.contains("PipelineStats"));
    }

    // ── OptimizationPipeline ──────────────────────────────────────────────

    #[test]
    fn pipeline_o0_no_passes() {
        let p = OptimizationPipeline::new(OptimizationLevel::O0);
        assert_eq!(p.pass_count(), 0);
    }

    #[test]
    fn pipeline_o1_has_passes() {
        let p = OptimizationPipeline::new(OptimizationLevel::O1);
        assert!(p.pass_count() > 0);
    }

    #[test]
    fn pipeline_o3_more_passes_than_o1() {
        let p1 = OptimizationPipeline::new(OptimizationLevel::O1);
        let p3 = OptimizationPipeline::new(OptimizationLevel::O3);
        assert!(p3.pass_count() > p1.pass_count());
    }

    #[test]
    fn pipeline_run_o1_removes_nops() {
        let mut p = OptimizationPipeline::new(OptimizationLevel::O1);
        let mut func = make_func_with_nops(5);
        let changes = p.run(&mut func);
        assert_eq!(changes, 5);
        assert_eq!(func.instructions.len(), 0);
    }

    #[test]
    fn pipeline_run_o2_removes_dead_stores() {
        let mut p = OptimizationPipeline::new(OptimizationLevel::O2);
        let mut func = make_func_with_double_store();
        let changes = p.run(&mut func);
        assert!(changes >= 1);
    }

    #[test]
    fn pipeline_run_all() {
        let mut p = OptimizationPipeline::new(OptimizationLevel::O1);
        let mut funcs = vec![make_func_with_nops(3), make_func_with_nops(2)];
        let changes = p.run_all(&mut funcs);
        assert_eq!(changes, 5);
    }

    #[test]
    fn pipeline_register_custom_pass() {
        let mut p = OptimizationPipeline::new(OptimizationLevel::O0);
        p.register_pass("my_custom_pass", PassGroup::Custom("custom".to_string()));
        assert_eq!(p.pass_count(), 1);
    }

    #[test]
    fn pipeline_group_of() {
        let p = OptimizationPipeline::new(OptimizationLevel::O1);
        let group = p.group_of("nop_elimination");
        assert!(group.is_some());
    }

    #[test]
    fn pipeline_no_opt() {
        let p = OptimizationPipeline::no_opt();
        assert_eq!(p.level, OptimizationLevel::O0);
    }

    #[test]
    fn pipeline_aggressive() {
        let p = OptimizationPipeline::aggressive();
        assert_eq!(p.level, OptimizationLevel::O3);
    }

    #[test]
    fn pipeline_debug() {
        let p = OptimizationPipeline::new(OptimizationLevel::O2);
        let s = format!("{p:?}");
        assert!(s.contains("OptimizationPipeline"));
        assert!(s.contains("O2"));
    }

    // ── PassGroup display ─────────────────────────────────────────────────

    #[test]
    fn pass_group_display() {
        assert_eq!(PassGroup::Cleanup.to_string(), "cleanup");
        assert_eq!(
            PassGroup::Custom("my_pass".to_string()).to_string(),
            "my_pass"
        );
    }
}
