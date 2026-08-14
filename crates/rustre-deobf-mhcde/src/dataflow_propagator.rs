//! Dataflow propagation for deobfuscation: forward/backward analysis,
//! def-use chains, reaching definitions, and available expressions.

use std::collections::{BTreeSet, HashSet, VecDeque};
use ahash::AHashMap as HashMap;
use serde::{Deserialize, Serialize};

use crate::control_flow_graph_builder::{Addr, ControlFlowGraph};

// ─── Variable / Expression abstractions ──────────────────────────────────────

/// An abstract variable identifier (register name or stack-slot offset).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VarId {
    /// Named register, e.g. "eax", "rbx".
    Reg(String),
    /// Stack slot at byte offset from RSP/ESP base.
    Stack(i64),
    /// Heap address (base address).
    Heap(u64),
    /// Symbolic name for unknown memory location.
    Sym(String),
}

impl VarId {
    pub fn reg(name: impl Into<String>) -> Self {
        Self::Reg(name.into())
    }

    pub fn stack(off: i64) -> Self {
        Self::Stack(off)
    }
}

impl std::fmt::Display for VarId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reg(r) => write!(f, "%{r}"),
            Self::Stack(o) => write!(f, "[rsp{o:+}]"),
            Self::Heap(a) => write!(f, "[{a:#x}]"),
            Self::Sym(s) => write!(f, "sym({s})"),
        }
    }
}

/// A simple constant-or-unknown value lattice element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Lattice {
    /// No information yet (⊥).
    Bottom,
    /// Concrete 64-bit constant.
    Const(u64),
    /// Multiple possible values (⊤).
    Top,
}

impl Lattice {
    /// Lattice meet: Bottom ⊓ x = x; Const(a) ⊓ Const(b) = Const(a) if a==b else Top.
    pub fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => x,
            (Self::Const(a), Self::Const(b)) if a == b => Self::Const(a),
            _ => Self::Top,
        }
    }

    pub fn is_const(self) -> bool {
        matches!(self, Self::Const(_))
    }

    pub fn const_val(self) -> Option<u64> {
        if let Self::Const(v) = self { Some(v) } else { None }
    }
}

// ─── Def-Use chain types ──────────────────────────────────────────────────────

/// A single definition of a variable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Def {
    /// Block start address where this definition occurs.
    pub block: Addr,
    /// Byte offset within the block's byte range (heuristic).
    pub insn_offset: usize,
    /// Variable defined.
    pub var: VarId,
    /// Optional constant value (if statically known).
    pub value: Option<u64>,
}

/// A single use of a variable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Use {
    pub block: Addr,
    pub insn_offset: usize,
    pub var: VarId,
}

/// Complete def-use web for a single variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefUseChain {
    pub var: VarId,
    pub defs: Vec<Def>,
    pub uses: Vec<Use>,
}

impl DefUseChain {
    pub fn new(var: VarId) -> Self {
        Self { var, defs: Vec::new(), uses: Vec::new() }
    }

    /// True if the variable has exactly one definition (SSA-like).
    pub fn is_single_def(&self) -> bool {
        self.defs.len() == 1
    }

    /// True if the variable has no uses (dead variable).
    pub fn is_dead(&self) -> bool {
        self.uses.is_empty()
    }

    /// Return the constant value when all definitions agree on the same constant.
    pub fn constant_value(&self) -> Option<u64> {
        if self.defs.is_empty() {
            return None;
        }
        let val = self.defs[0].value?;
        if self.defs.iter().all(|d| d.value == Some(val)) {
            Some(val)
        } else {
            None
        }
    }
}

// ─── Reaching Definitions ─────────────────────────────────────────────────────

/// Reaching-definitions analysis result for a single block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReachingDefs {
    /// Definitions reaching the block entry: var → set of def block addresses.
    pub in_set: HashMap<VarId, BTreeSet<Addr>>,
    /// Definitions reaching the block exit.
    pub out_set: HashMap<VarId, BTreeSet<Addr>>,
    /// Definitions generated inside this block (last def per var).
    pub generator: HashMap<VarId, Addr>,
    /// Variables killed (redefined) in this block.
    pub kill: HashSet<VarId>,
}

impl ReachingDefs {
    /// Compute OUT = GEN ∪ (IN \ KILL).
    pub fn compute_out(&mut self) {
        self.out_set = self.in_set.clone();
        // Remove killed vars from in_set contribution.
        for var in &self.kill {
            self.out_set.remove(var);
        }
        // Add generated defs.
        for (var, block) in &self.generator {
            self.out_set
                .entry(var.clone())
                .or_default()
                .insert(*block);
        }
    }

    /// Merge another `out_set` into `in_set`. Returns `true` if changed.
    pub fn merge_predecessor(&mut self, pred_out: &HashMap<VarId, BTreeSet<Addr>>) -> bool {
        let mut changed = false;
        for (var, blocks) in pred_out {
            let entry: &mut BTreeSet<Addr> = self.in_set.entry(var.clone()).or_default();
            for &b in blocks {
                if entry.insert(b) {
                    changed = true;
                }
            }
        }
        changed
    }
}

/// Whole-program reaching-definitions analysis.
#[derive(Debug, Clone, Default)]
pub struct ReachingDefsAnalysis {
    /// Per-block results.
    pub block_data: HashMap<Addr, ReachingDefs>,
}

impl ReachingDefsAnalysis {
    /// Run the analysis on `cfg`.  `block_defs` maps block start → list of
    /// `(var, optional_const)` pairs for definitions generated in that block.
    pub fn analyze(
        cfg: &ControlFlowGraph,
        block_defs: &HashMap<Addr, Vec<(VarId, Option<u64>)>>,
    ) -> Self {
        let mut analysis = Self::default();

        // Initialize gen/kill sets.
        for block in cfg.iter_blocks() {
            let mut rd = ReachingDefs::default();
            if let Some(defs) = block_defs.get(&block.start) {
                for (var, _val) in defs {
                    rd.kill.insert(var.clone());
                    rd.generator.insert(var.clone(), block.start);
                }
            }
            analysis.block_data.insert(block.start, rd);
        }

        // Iterative worklist over RPO.
        let rpo = cfg.reverse_post_order();
        let mut worklist: VecDeque<Addr> = rpo.iter().copied().collect();
        let mut in_worklist: HashSet<Addr> = worklist.iter().copied().collect();

        while let Some(block_addr) = worklist.pop_front() {
            in_worklist.remove(&block_addr);

            let block = match cfg.block(block_addr) {
                Some(b) => b,
                None => continue,
            };

            // Collect predecessor out-sets.
            let pred_outs: Vec<HashMap<VarId, BTreeSet<Addr>>> = block
                .preds
                .iter()
                .filter_map(|pred| analysis.block_data.get(pred).map(|rd| rd.out_set.clone()))
                .collect();

            // Merge into in_set.
            let rd = analysis.block_data.get_mut(&block_addr).unwrap();
            let mut changed = false;
            for pred_out in &pred_outs {
                if rd.merge_predecessor(pred_out) {
                    changed = true;
                }
            }

            if changed {
                let old_out = rd.out_set.clone();
                rd.compute_out();
                if rd.out_set != old_out {
                    for &succ in &block.succs {
                        if in_worklist.insert(succ) {
                            worklist.push_back(succ);
                        }
                    }
                }
            } else {
                // First pass: still need to compute out.
                rd.compute_out();
            }
        }

        analysis
    }

    /// Return all definitions of `var` that reach the entry of `block`.
    pub fn reaching_defs_at(&self, block: Addr, var: &VarId) -> BTreeSet<Addr> {
        self.block_data
            .get(&block)
            .and_then(|rd| rd.in_set.get(var).cloned())
            .unwrap_or_default()
    }
}

// ─── Available Expressions ────────────────────────────────────────────────────

/// An abstract expression (LHS op RHS, or single operand).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Expr {
    /// Left-hand operand.
    pub lhs: VarId,
    /// Operator string ("+", "-", "xor", "and", "or", "<<", ">>").
    pub op: String,
    /// Right-hand operand (optional for unary).
    pub rhs: Option<VarId>,
    /// Optional constant folded value.
    pub folded: Option<u64>,
}

impl Expr {
    pub fn binary(lhs: VarId, op: impl Into<String>, rhs: VarId) -> Self {
        Self { lhs, op: op.into(), rhs: Some(rhs), folded: None }
    }

    pub fn unary(lhs: VarId, op: impl Into<String>) -> Self {
        Self { lhs, op: op.into(), rhs: None, folded: None }
    }

    pub fn with_folded(mut self, val: u64) -> Self {
        self.folded = Some(val);
        self
    }

    /// True if this expression is trivially constant-foldable.
    pub fn is_constant(&self) -> bool {
        self.folded.is_some()
    }

    /// Return the variables referenced by this expression.
    pub fn vars(&self) -> Vec<&VarId> {
        let mut v = vec![&self.lhs];
        if let Some(r) = &self.rhs {
            v.push(r);
        }
        v
    }
}

/// Available-expressions analysis result for one block.
#[derive(Debug, Clone, Default)]
pub struct AvailExprs {
    /// Expressions available at block entry.
    pub in_set: HashSet<Expr>,
    /// Expressions available at block exit.
    pub out_set: HashSet<Expr>,
    /// Expressions generated (computed and not subsequently killed) in this block.
    pub generator: HashSet<Expr>,
    /// Expressions killed (at least one operand redefined) in this block.
    pub killed_vars: HashSet<VarId>,
}

impl AvailExprs {
    /// Compute out_set = gen ∪ (in_set − killed).
    pub fn compute_out(&mut self) {
        self.out_set = self.generator.clone();
        for expr in &self.in_set {
            let killed = expr.vars().iter().any(|v: &&VarId| self.killed_vars.contains(*v));
            if !killed {
                self.out_set.insert(expr.clone());
            }
        }
    }
}

/// Whole-program available-expressions analysis (forward, intersection).
pub struct AvailExprsAnalysis {
    pub block_data: HashMap<Addr, AvailExprs>,
}

impl AvailExprsAnalysis {
    /// Run the analysis.  `block_exprs` maps block → list of expressions computed
    /// in that block; `block_kills` maps block → vars redefined in that block.
    pub fn analyze(
        cfg: &ControlFlowGraph,
        block_exprs: &HashMap<Addr, Vec<Expr>>,
        block_kills: &HashMap<Addr, HashSet<VarId>>,
    ) -> Self {
        let mut data: HashMap<Addr, AvailExprs> = HashMap::new();

        // Initialize gen/kill.
        for block in cfg.iter_blocks() {
            let mut ae = AvailExprs::default();
            if let Some(exprs) = block_exprs.get(&block.start) {
                // Expressions are processed left-to-right: kill before gen.
                for expr in exprs {
                    ae.generator.retain(|e: &Expr| {
                        !e.vars().iter().any(|v: &&VarId| ae.killed_vars.contains(*v))
                    });
                    ae.generator.insert(expr.clone());
                }
            }
            if let Some(kills) = block_kills.get(&block.start) {
                ae.killed_vars = kills.clone();
            }
            data.insert(block.start, ae);
        }

        // Worklist iteration (forward, intersection).
        let rpo = cfg.reverse_post_order();
        let mut worklist: VecDeque<Addr> = rpo.iter().copied().collect();
        let mut in_wl: HashSet<Addr> = worklist.iter().copied().collect();

        while let Some(addr) = worklist.pop_front() {
            in_wl.remove(&addr);

            let block = match cfg.block(addr) {
                Some(b) => b,
                None => continue,
            };

            // in_set = intersection of all predecessor out_sets.
            let pred_outs: Vec<HashSet<Expr>> = block
                .preds
                .iter()
                .filter_map(|p| data.get(p).map(|ae| ae.out_set.clone()))
                .collect();

            let new_in = if pred_outs.is_empty() {
                HashSet::new()
            } else {
                let mut inter = pred_outs[0].clone();
                for other in &pred_outs[1..] {
                    inter.retain(|e| other.contains(e));
                }
                inter
            };

            let ae = data.get_mut(&addr).unwrap();
            let changed = new_in != ae.in_set;
            ae.in_set = new_in;
            if changed {
                let old_out = ae.out_set.clone();
                ae.compute_out();
                if ae.out_set != old_out {
                    for &succ in &block.succs {
                        if in_wl.insert(succ) {
                            worklist.push_back(succ);
                        }
                    }
                }
            } else if ae.out_set.is_empty() {
                ae.compute_out();
            }
        }

        Self { block_data: data }
    }

    pub fn available_at(&self, block: Addr) -> &HashSet<Expr> {
        self.block_data
            .get(&block)
            .map(|ae| &ae.in_set)
            .unwrap_or_else(|| &EMPTY_EXPR_SET)
    }
}

static EMPTY_EXPR_SET: std::sync::LazyLock<HashSet<Expr>> =
    std::sync::LazyLock::new(HashSet::new);

// ─── Constant Propagation ─────────────────────────────────────────────────────

/// Per-block constant propagation state (var → lattice value).
#[derive(Debug, Clone, Default)]
pub struct ConstantPropState {
    /// Map from variable to its lattice value at block entry.
    pub values: HashMap<VarId, Lattice>,
}

impl ConstantPropState {
    /// Meet two states together (pairwise meet over all vars).
    pub fn meet(&self, other: &Self) -> Self {
        // At a control-flow join, a variable only carries a useful lattice
        // value if BOTH predecessors agree on it. If a var is defined on one
        // side but not the other, the value on the missing side is unknown,
        // so the merged result must be Bottom (no usable info).
        let mut result: HashMap<VarId, Lattice> = HashMap::new();
        for (var, val) in &self.values {
            if let Some(other_val) = other.values.get(var) {
                result.insert(var.clone(), val.meet(*other_val));
            } else {
                result.insert(var.clone(), Lattice::Bottom);
            }
        }
        for var in other.values.keys() {
            if !self.values.contains_key(var) {
                result.insert(var.clone(), Lattice::Bottom);
            }
        }
        Self { values: result }
    }

    pub fn set(&mut self, var: VarId, val: Lattice) {
        self.values.insert(var, val);
    }

    pub fn get(&self, var: &VarId) -> Lattice {
        self.values.get(var).copied().unwrap_or(Lattice::Bottom)
    }
}

/// Instruction-level constant propagation hint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstPropHint {
    /// Block containing the instruction.
    pub block: Addr,
    /// Instruction offset within the block.
    pub insn_off: usize,
    /// Variable that became constant.
    pub var: VarId,
    /// The constant value.
    pub value: u64,
    /// True if this constant was propagated into a branch condition (opaque predicate candidate).
    pub is_branch_cond: bool,
}

/// Forward constant propagation analysis.
#[derive(Debug)]
pub struct ConstantPropagation {
    /// Per-block entry state.
    pub entry_states: HashMap<Addr, ConstantPropState>,
    /// Per-block exit state.
    pub exit_states: HashMap<Addr, ConstantPropState>,
    /// Propagation hints (foldable constants).
    pub hints: Vec<ConstPropHint>,
}

impl ConstantPropagation {
    /// Run sparse conditional constant propagation.
    /// `assignments` maps block → list of `(insn_off, dest_var, src_var_or_none, const_or_none)`.
    pub fn run(
        cfg: &ControlFlowGraph,
        assignments: &HashMap<Addr, Vec<(usize, VarId, Option<VarId>, Option<u64>)>>,
    ) -> Self {
        let mut entry_states: HashMap<Addr, ConstantPropState> = HashMap::new();
        let mut exit_states: HashMap<Addr, ConstantPropState> = HashMap::new();
        let mut hints = Vec::new();

        for addr in cfg.blocks.keys() {
            entry_states.insert(*addr, ConstantPropState::default());
            exit_states.insert(*addr, ConstantPropState::default());
        }

        let rpo = cfg.reverse_post_order();
        let mut worklist: VecDeque<Addr> = rpo.iter().copied().collect();
        let mut in_wl: HashSet<Addr> = worklist.iter().copied().collect();

        while let Some(addr) = worklist.pop_front() {
            in_wl.remove(&addr);

            let block = match cfg.block(addr) {
                Some(b) => b,
                None => continue,
            };

            // Meet predecessor exit states.
            let new_entry = block
                .preds
                .iter()
                .filter_map(|p| exit_states.get(p))
                .fold(ConstantPropState::default(), |acc, s| acc.meet(s));

            let old_entry = entry_states.get(&addr).cloned().unwrap_or_default();
            let changed_entry = new_entry.values != old_entry.values;
            entry_states.insert(addr, new_entry.clone());

            // Propagate through block assignments.
            let mut state = new_entry;
            if let Some(assigns) = assignments.get(&addr) {
                for (insn_off, dest, src_var, const_val) in assigns {
                    let val = if let Some(c) = const_val {
                        Lattice::Const(*c)
                    } else if let Some(sv) = src_var {
                        state.get(sv)
                    } else {
                        Lattice::Top
                    };
                    state.set(dest.clone(), val);
                    if let Lattice::Const(c) = val {
                        hints.push(ConstPropHint {
                            block: addr,
                            insn_off: *insn_off,
                            var: dest.clone(),
                            value: c,
                            is_branch_cond: false,
                        });
                    }
                }
            }

            let old_exit = exit_states.get(&addr).cloned().unwrap_or_default();
            let changed_exit = state.values != old_exit.values;
            exit_states.insert(addr, state);

            if changed_entry || changed_exit {
                for &succ in &block.succs {
                    if in_wl.insert(succ) {
                        worklist.push_back(succ);
                    }
                }
            }
        }

        Self { entry_states, exit_states, hints }
    }

    /// Return all variables with constant values at the entry of `block`.
    pub fn constants_at_entry(&self, block: Addr) -> Vec<(VarId, u64)> {
        self.entry_states
            .get(&block)
            .map(|s| {
                s.values
                    .iter()
                    .filter_map(|(v, l)| l.const_val().map(|c| (v.clone(), c)))
                    .collect()
            })
            .unwrap_or_default()
    }
}

// ─── Backward liveness analysis ───────────────────────────────────────────────

/// Per-block liveness data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LivenessData {
    /// Variables live at block entry.
    pub live_in: BTreeSet<VarId>,
    /// Variables live at block exit.
    pub live_out: BTreeSet<VarId>,
    /// Variables used before being defined (upward-exposed uses).
    pub ue_var: BTreeSet<VarId>,
    /// Variables defined in this block.
    pub var_kill: BTreeSet<VarId>,
}

impl LivenessData {
    /// Compute live_in = ue_var ∪ (live_out − var_kill).
    pub fn compute_live_in(&mut self) {
        self.live_in = self.ue_var.clone();
        for v in &self.live_out {
            if !self.var_kill.contains(v) {
                self.live_in.insert(v.clone());
            }
        }
    }
}

/// Backward liveness analysis over a CFG.
#[derive(Debug)]
pub struct LivenessAnalysis {
    pub block_data: HashMap<Addr, LivenessData>,
}

impl LivenessAnalysis {
    /// Run backward liveness analysis.
    /// `block_info` maps block → `(uses_before_def, defs)`.
    pub fn analyze(
        cfg: &ControlFlowGraph,
        block_info: &HashMap<Addr, (Vec<VarId>, Vec<VarId>)>,
    ) -> Self {
        let mut data: HashMap<Addr, LivenessData> = HashMap::new();

        for block in cfg.iter_blocks() {
            let mut ld = LivenessData::default();
            if let Some((uses, defs)) = block_info.get(&block.start) {
                for u in uses { ld.ue_var.insert(u.clone()); }
                for d in defs { ld.var_kill.insert(d.clone()); }
            }
            data.insert(block.start, ld);
        }

        // Iterative backward pass.
        // Process in reverse RPO (i.e., RPO reversed = post-order).
        let mut rpo = cfg.reverse_post_order();
        rpo.reverse(); // Now it's post-order

        let mut worklist: VecDeque<Addr> = rpo.iter().copied().collect();
        let mut in_wl: HashSet<Addr> = worklist.iter().copied().collect();

        while let Some(addr) = worklist.pop_front() {
            in_wl.remove(&addr);

            let block = match cfg.block(addr) {
                Some(b) => b,
                None => continue,
            };

            // live_out = ∪ live_in of all successors.
            let new_live_out: BTreeSet<VarId> = block
                .succs
                .iter()
                .filter_map(|s| data.get(s))
                .flat_map(|ld| ld.live_in.iter().cloned())
                .collect();

            let ld = data.get_mut(&addr).unwrap();
            let changed = new_live_out != ld.live_out;
            ld.live_out = new_live_out;
            if changed {
                ld.compute_live_in();
                for &pred in &block.preds {
                    if in_wl.insert(pred) {
                        worklist.push_back(pred);
                    }
                }
            } else if ld.live_in.is_empty() && !ld.ue_var.is_empty() {
                ld.compute_live_in();
            }
        }

        Self { block_data: data }
    }

    /// Return variables live at block `addr` entry.
    pub fn live_in(&self, addr: Addr) -> BTreeSet<VarId> {
        self.block_data
            .get(&addr)
            .map(|ld| ld.live_in.clone())
            .unwrap_or_default()
    }

    /// Return dead variable defs (defined but never used after this block).
    pub fn dead_defs_in(&self, addr: Addr) -> Vec<VarId> {
        self.block_data
            .get(&addr)
            .map(|ld| {
                ld.var_kill
                    .iter()
                    .filter(|v| !ld.live_out.contains(*v))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

// ─── DataflowPropagator facade ────────────────────────────────────────────────

/// Aggregated dataflow analysis results.
#[derive(Debug)]
pub struct DataflowResults {
    pub reaching_defs: ReachingDefsAnalysis,
    pub constants: ConstantPropagation,
    pub liveness: LivenessAnalysis,
    /// Number of potential dead defs across the whole function.
    pub dead_def_count: usize,
    /// Variables that have constant values throughout (pure compile-time constants).
    pub global_constants: HashMap<VarId, u64>,
}

/// Facade that runs all dataflow passes over a CFG.
pub struct DataflowPropagator;

impl DataflowPropagator {
    /// Run all analyses and return aggregated results.
    ///
    /// # Arguments
    /// * `cfg`         — control flow graph
    /// * `block_defs`  — per-block variable definitions (var, optional_const)
    /// * `block_uses`  — per-block (upward-exposed uses, killed vars) for liveness
    /// * `block_exprs` — per-block expressions for available-expressions analysis
    pub fn run(
        cfg: &ControlFlowGraph,
        block_defs: &HashMap<Addr, Vec<(VarId, Option<u64>)>>,
        block_uses: &HashMap<Addr, (Vec<VarId>, Vec<VarId>)>,
    ) -> DataflowResults {
        // Build assignment list for constant propagation from block_defs.
        let assignments: HashMap<Addr, Vec<(usize, VarId, Option<VarId>, Option<u64>)>> =
            block_defs
                .iter()
                .map(|(&addr, defs)| {
                    let assigns = defs
                        .iter()
                        .enumerate()
                        .map(|(i, (var, val))| (i, var.clone(), None, *val))
                        .collect();
                    (addr, assigns)
                })
                .collect();

        let reaching_defs = ReachingDefsAnalysis::analyze(cfg, block_defs);
        let constants = ConstantPropagation::run(cfg, &assignments);
        let liveness = LivenessAnalysis::analyze(cfg, block_uses);

        // Aggregate dead defs.
        let dead_def_count: usize = cfg
            .blocks
            .keys()
            .map(|&addr| liveness.dead_defs_in(addr).len())
            .sum();

        // Global constants: vars that are Const at all uses (intersection of const hints).
        let mut global_constants: HashMap<VarId, u64> = HashMap::new();
        for hint in &constants.hints {
            let entry = global_constants.entry(hint.var.clone()).or_insert(hint.value);
            if *entry != hint.value {
                global_constants.remove(&hint.var);
            }
        }

        DataflowResults {
            reaching_defs,
            constants,
            liveness,
            dead_def_count,
            global_constants,
        }
    }
}

// ─── DefUseBuilder ────────────────────────────────────────────────────────────

/// Builds def-use chains from reaching-def analysis results.
pub struct DefUseBuilder;

impl DefUseBuilder {
    /// Build def-use chains for all variables mentioned in `block_defs` and
    /// `block_uses`.
    pub fn build(
        _cfg: &ControlFlowGraph,
        block_defs: &HashMap<Addr, Vec<(VarId, Option<u64>)>>,
        block_uses: &HashMap<Addr, Vec<VarId>>,
    ) -> HashMap<VarId, DefUseChain> {
        let mut chains: HashMap<VarId, DefUseChain> = HashMap::new();

        for (block, defs) in block_defs {
            for (i, (var, val)) in defs.iter().enumerate() {
                let chain = chains
                    .entry(var.clone())
                    .or_insert_with(|| DefUseChain::new(var.clone()));
                chain.defs.push(Def {
                    block: *block,
                    insn_offset: i,
                    var: var.clone(),
                    value: *val,
                });
            }
        }

        for (block, uses) in block_uses {
            for (i, var) in uses.iter().enumerate() {
                let chain = chains
                    .entry(var.clone())
                    .or_insert_with(|| DefUseChain::new(var.clone()));
                chain.uses.push(Use {
                    block: *block,
                    insn_offset: i,
                    var: var.clone(),
                });
            }
        }

        chains
    }

    /// Return variables that are defined but never used.
    pub fn dead_variables(chains: &HashMap<VarId, DefUseChain>) -> Vec<&VarId> {
        chains
            .values()
            .filter(|c| c.is_dead() && !c.defs.is_empty())
            .map(|c| &c.var)
            .collect()
    }

    /// Return variables with a single constant definition.
    pub fn single_const_defs(chains: &HashMap<VarId, DefUseChain>) -> Vec<(&VarId, u64)> {
        chains
            .values()
            .filter_map(|c| {
                if c.is_single_def() {
                    c.constant_value().map(|v| (&c.var, v))
                } else {
                    None
                }
            })
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lattice_meet() {
        assert_eq!(Lattice::Bottom.meet(Lattice::Const(42)), Lattice::Const(42));
        assert_eq!(Lattice::Const(1).meet(Lattice::Const(1)), Lattice::Const(1));
        assert_eq!(Lattice::Const(1).meet(Lattice::Const(2)), Lattice::Top);
        assert_eq!(Lattice::Top.meet(Lattice::Const(5)), Lattice::Top);
    }

    #[test]
    fn test_def_use_chain_dead() {
        let var = VarId::reg("eax");
        let mut chain = DefUseChain::new(var.clone());
        chain.defs.push(Def {
            block: 0x1000,
            insn_offset: 0,
            var: var.clone(),
            value: Some(42),
        });
        assert!(chain.is_dead());
        assert_eq!(chain.constant_value(), Some(42));
    }

    #[test]
    fn test_reaching_defs_merge() {
        let mut rd = ReachingDefs::default();
        rd.in_set
            .insert(VarId::reg("eax"), BTreeSet::from([0x1000]));
        let pred_out: HashMap<VarId, BTreeSet<Addr>> =
            [(VarId::reg("eax"), BTreeSet::from([0x2000]))]
                .into_iter()
                .collect();
        rd.merge_predecessor(&pred_out);
        assert_eq!(rd.in_set[&VarId::reg("eax")].len(), 2);
    }

    #[test]
    fn test_liveness_compute() {
        let mut ld = LivenessData {
            live_out: BTreeSet::from([VarId::reg("rax"), VarId::reg("rbx")]),
            var_kill: BTreeSet::from([VarId::reg("rax")]),
            ue_var: BTreeSet::from([VarId::reg("rcx")]),
            live_in: BTreeSet::new(),
        };
        ld.compute_live_in();
        assert!(ld.live_in.contains(&VarId::reg("rcx")));
        assert!(ld.live_in.contains(&VarId::reg("rbx")));
        assert!(!ld.live_in.contains(&VarId::reg("rax")));
    }

    /// Build a 3-block CFG:
    ///   A(0x1000): a = 0        (def a)          -> B
    ///   B(0x2000): a = a + 1    (use a, def a)   -> C
    ///   C(0x3000): print(a)     (use a)
    /// This is the read-modify-write / accumulator shape. `a` MUST be live at
    /// the entry of B, otherwise A's defining store looks dead and gets
    /// deleted, leaving B reading an uninitialised value.
    fn accumulator_cfg() -> (ControlFlowGraph, HashMap<Addr, (Vec<VarId>, Vec<VarId>)>) {
        use crate::control_flow_graph_builder::{BasicBlock, TermKind};
        use std::collections::BTreeMap;

        let mut a = BasicBlock::new(0x1000, 0x2000, TermKind::FallThrough);
        a.succs = vec![0x2000];
        let mut b = BasicBlock::new(0x2000, 0x3000, TermKind::FallThrough);
        b.preds = vec![0x1000];
        b.succs = vec![0x3000];
        let mut c = BasicBlock::new(0x3000, 0x4000, TermKind::Return);
        c.preds = vec![0x2000];

        let blocks: BTreeMap<Addr, BasicBlock> =
            [(0x1000, a), (0x2000, b), (0x3000, c)].into_iter().collect();
        let cfg = ControlFlowGraph {
            blocks,
            entry: 0x1000,
            loops: Vec::new(),
            idom: [(0x2000, 0x1000), (0x3000, 0x2000)].into_iter().collect(),
        };

        let var = VarId::reg("rax");
        let info: HashMap<Addr, (Vec<VarId>, Vec<VarId>)> = [
            (0x1000, (vec![], vec![var.clone()])),
            (0x2000, (vec![var.clone()], vec![var.clone()])),
            (0x3000, (vec![var.clone()], vec![])),
        ]
        .into_iter()
        .collect();

        (cfg, info)
    }

    #[test]
    fn test_liveness_accumulator_use_survives_own_def() {
        let (cfg, info) = accumulator_cfg();
        let la = LivenessAnalysis::analyze(&cfg, &info);
        let var = VarId::reg("rax");

        // B reads `a` before writing it: `a` is live on entry to B.
        // Under the buggy `(live_out ∪ use) − def` the statement's own use is
        // killed by its own def and this set comes back empty.
        assert!(
            la.live_in(0x2000).contains(&var),
            "rax must be live-in at the read-modify-write block"
        );

        // Consequently A's def of `a` is NOT dead: B reads it.
        assert!(
            !la.dead_defs_in(0x1000).contains(&var),
            "A's definition of rax feeds B's read and must not be reported dead"
        );
    }

    #[test]
    fn test_liveness_compute_rmw_var_in_both_sets() {
        // A var that is both used-before-def and defined in the same block
        // stays live-in; the def must not kill the block's own upward use.
        let mut ld = LivenessData {
            live_out: BTreeSet::new(),
            var_kill: BTreeSet::from([VarId::reg("rax")]),
            ue_var: BTreeSet::from([VarId::reg("rax")]),
            live_in: BTreeSet::new(),
        };
        ld.compute_live_in();
        assert!(ld.live_in.contains(&VarId::reg("rax")));
    }

    #[test]
    fn test_expr_vars() {
        let e = Expr::binary(VarId::reg("eax"), "+", VarId::reg("ecx"));
        assert_eq!(e.vars().len(), 2);
    }

    #[test]
    fn test_constant_state_meet() {
        let mut s1 = ConstantPropState::default();
        s1.set(VarId::reg("eax"), Lattice::Const(5));
        let mut s2 = ConstantPropState::default();
        s2.set(VarId::reg("eax"), Lattice::Const(5));
        s2.set(VarId::reg("ebx"), Lattice::Const(10));
        let m = s1.meet(&s2);
        assert_eq!(m.get(&VarId::reg("eax")), Lattice::Const(5));
        assert_eq!(m.get(&VarId::reg("ebx")), Lattice::Bottom);
    }
}
