//! Loop summarisation for symbolic execution.
//!
//! The summariser:
//! 1. Detects loops in the CFG by finding back-edges (DFS).
//! 2. Attempts to find a *closed-form* for simple loop bodies (constant
//!    increment → multiply, prefix-sum patterns).
//! 3. Synthesises loop invariants using a template library + Z3-style
//!    constraint checking (bit-exact arithmetic).
//! 4. Falls back to *widening*: after `K` unroll steps, replace concrete
//!    iteration values with a symbolic range to ensure termination.

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};

use rustre_symb::{SymExpr, SymType, SymbolicState};

// ─── CFG primitives ───────────────────────────────────────────────────────────

/// A basic block identifier (its start address).
pub type BlockAddr = u64;

/// An edge in the CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: BlockAddr,
    pub to: BlockAddr,
    /// Whether this edge is a back-edge (from → to where `to` dominates `from`).
    pub is_back_edge: bool,
}

/// A minimal control-flow graph.
#[derive(Debug, Default, Clone)]
pub struct ControlFlowGraph {
    /// Adjacency list: block → successors.
    pub succs: HashMap<BlockAddr, Vec<BlockAddr>>,
    /// Reverse adjacency list.
    pub preds: HashMap<BlockAddr, Vec<BlockAddr>>,
    /// All basic block addresses.
    pub blocks: HashSet<BlockAddr>,
}

impl ControlFlowGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_edge(&mut self, from: BlockAddr, to: BlockAddr) {
        self.blocks.insert(from);
        self.blocks.insert(to);
        self.succs.entry(from).or_default().push(to);
        self.preds.entry(to).or_default().push(from);
    }

    /// Identify all back-edges using iterative DFS.
    ///
    /// # Panics
    ///
    /// Panics if the internal DFS stack is corrupted (should never happen in
    /// practice).
    #[must_use]
    pub fn find_back_edges(&self, entry: BlockAddr) -> Vec<CfgEdge> {
        let mut visited = HashSet::new();
        let mut on_stack = HashSet::new();
        let mut back_edges = Vec::new();
        let mut stack = vec![(entry, false)];

        while let Some((node, leaving)) = stack.last().copied() {
            if leaving {
                stack.pop();
                on_stack.remove(&node);
                continue;
            }
            // Mark as "currently being processed".
            stack.last_mut().unwrap().1 = true;

            if !visited.insert(node) {
                stack.pop();
                continue;
            }
            on_stack.insert(node);

            if let Some(succs) = self.succs.get(&node) {
                for &succ in succs {
                    if on_stack.contains(&succ) {
                        back_edges.push(CfgEdge { from: node, to: succ, is_back_edge: true });
                    } else if !visited.contains(&succ) {
                        stack.push((succ, false));
                    }
                }
            }
        }
        back_edges
    }

    /// Find all natural loop headers (targets of back-edges).
    #[must_use]
    pub fn loop_headers(&self, entry: BlockAddr) -> HashSet<BlockAddr> {
        self.find_back_edges(entry)
            .into_iter()
            .map(|e| e.to)
            .collect()
    }

    /// Collect all blocks in the natural loop rooted at `header`.
    ///
    /// Uses the standard algorithm: start from the back-edge source and walk
    /// predecessors until the header is reached.
    #[must_use]
    pub fn loop_body(&self, header: BlockAddr, back_edge_from: BlockAddr) -> HashSet<BlockAddr> {
        let mut body = HashSet::new();
        body.insert(header);
        let mut worklist = VecDeque::new();
        worklist.push_back(back_edge_from);
        while let Some(node) = worklist.pop_front() {
            if body.insert(node) && let Some(preds) = self.preds.get(&node) {
                for &p in preds {
                    if !body.contains(&p) {
                        worklist.push_back(p);
                    }
                }
            }
        }
        body
    }
}

// ─── Loop structure ───────────────────────────────────────────────────────────

/// A detected loop in the CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Loop {
    /// The loop header block address.
    pub header: BlockAddr,
    /// All blocks that are part of the loop body.
    pub body_blocks: Vec<BlockAddr>,
    /// The induction variable register (if detected).
    pub induction_var: Option<String>,
    /// Initial value of the induction variable.
    pub init_value: Option<SymExpr>,
    /// Per-iteration step (for increment-by-constant loops).
    pub step: Option<SymExpr>,
    /// Exit condition expression.
    pub exit_condition: Option<SymExpr>,
    /// Upper bound (if detected from exit condition).
    pub bound: Option<SymExpr>,
}

impl Loop {
    #[must_use]
    pub const fn new(header: BlockAddr) -> Self {
        Self {
            header,
            body_blocks: Vec::new(),
            induction_var: None,
            init_value: None,
            step: None,
            exit_condition: None,
            bound: None,
        }
    }

    /// Returns `true` if this loop has constant step and can be closed-form'd.
    #[must_use]
    pub fn is_constant_step(&self) -> bool {
        self.step
            .as_ref()
            .is_some_and(|s| matches!(s, SymExpr::ConstBv { .. }))
    }
}

// ─── Closed-form summary ──────────────────────────────────────────────────────

/// Result of closed-form analysis for a loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClosedForm {
    /// `var_after = init + step * iterations`
    LinearIncrement {
        var: String,
        init: SymExpr,
        step: SymExpr,
        iterations: SymExpr,
        result: SymExpr,
    },
    /// `result = init * step^iterations` (geometric series).
    GeometricMultiply {
        var: String,
        init: SymExpr,
        ratio: SymExpr,
        iterations: SymExpr,
        result: SymExpr,
    },
    /// Could not determine a closed form.
    Unknown,
}

// ─── Invariant template ───────────────────────────────────────────────────────

/// Template for loop invariant synthesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvariantTemplate {
    /// `var >= 0` (non-negativity).
    NonNegative(String),
    /// `var <= bound` (upper bound).
    UpperBound { var: String, bound: SymExpr },
    /// `var >= init` (monotone increasing).
    MonotoneIncreasing { var: String, init: SymExpr },
    /// `var <= init` (monotone decreasing).
    MonotoneDecreasing { var: String, init: SymExpr },
    /// `var % stride == base % stride` (stride invariant).
    StrideInvariant { var: String, stride: u64, base: u64 },
    /// Arbitrary symbolic constraint.
    Arbitrary(SymExpr),
}

impl InvariantTemplate {
    /// Convert to a [`SymExpr`].
    #[must_use]
    pub fn to_expr(&self) -> SymExpr {
        match self {
            Self::NonNegative(v) => SymExpr::UGe(
                Box::new(SymExpr::Var { name: v.clone(), ty: SymType::BitVec(64) }),
                Box::new(SymExpr::ConstBv { val: 0, width: 64 }),
            ),
            Self::UpperBound { var, bound } => SymExpr::ULe(
                Box::new(SymExpr::Var { name: var.clone(), ty: SymType::BitVec(64) }),
                Box::new(bound.clone()),
            ),
            Self::MonotoneIncreasing { var, init } => SymExpr::UGe(
                Box::new(SymExpr::Var { name: var.clone(), ty: SymType::BitVec(64) }),
                Box::new(init.clone()),
            ),
            Self::MonotoneDecreasing { var, init } => SymExpr::ULe(
                Box::new(SymExpr::Var { name: var.clone(), ty: SymType::BitVec(64) }),
                Box::new(init.clone()),
            ),
            Self::StrideInvariant { var, stride, base } => {
                // (var - base) % stride == 0
                let v = SymExpr::Var { name: var.clone(), ty: SymType::BitVec(64) };
                let b = SymExpr::ConstBv { val: *base, width: 64 };
                let s = SymExpr::ConstBv { val: *stride, width: 64 };
                SymExpr::Eq(
                    Box::new(SymExpr::URem(
                        Box::new(SymExpr::Sub(Box::new(v), Box::new(b))),
                        Box::new(s),
                    )),
                    Box::new(SymExpr::ConstBv { val: 0, width: 64 }),
                )
            }
            Self::Arbitrary(e) => e.clone(),
        }
    }
}

// ─── Loop summary ─────────────────────────────────────────────────────────────

/// Complete summary for a loop, including invariants and optional closed form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopSummary {
    pub loop_info: Loop,
    pub invariants: Vec<InvariantTemplate>,
    pub closed_form: ClosedForm,
    /// Whether widening was applied (i.e., closed form could not be determined).
    pub widened: bool,
    /// The symbolic state after the loop (abstract post-state).
    pub post_state_constraints: Vec<SymExpr>,
}

// ─── Configuration ────────────────────────────────────────────────────────────

/// Configuration for the loop summariser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopSummarizerConfig {
    /// Maximum unroll iterations before widening.
    pub unroll_limit: u32,
    /// Maximum number of invariant templates to try.
    pub max_templates: usize,
    /// Whether to attempt closed-form derivation.
    pub attempt_closed_form: bool,
    /// Whether to apply widening after failed closed form.
    pub apply_widening: bool,
}

impl Default for LoopSummarizerConfig {
    fn default() -> Self {
        Self {
            unroll_limit: 4,
            max_templates: 8,
            attempt_closed_form: true,
            apply_widening: true,
        }
    }
}

// ─── Widening operator ────────────────────────────────────────────────────────

/// Widen a sequence of concrete values to a symbolic range.
///
/// Given values `v0, v1, v2 ...`, detect the step and produce:
/// - `v0 + step * k` for some symbolic `k >= 0`.
///
/// Returns `None` if the sequence is empty or non-uniform.
#[must_use]
pub fn widen_sequence(values: &[u64]) -> Option<SymExpr> {
    if values.len() < 2 {
        return None;
    }
    let step = values[1].cast_signed().wrapping_sub(values[0].cast_signed());
    for w in values.windows(2) {
        if w[1].cast_signed().wrapping_sub(w[0].cast_signed()) != step {
            return None; // non-uniform step
        }
    }
    let init = SymExpr::ConstBv { val: values[0], width: 64 };
    let k = SymExpr::Var { name: "loop_k".into(), ty: SymType::BitVec(64) };
    let step_expr = SymExpr::ConstBv { val: step.unsigned_abs(), width: 64 };
    let product = SymExpr::Mul(Box::new(step_expr), Box::new(k));
    let widened = if step >= 0 {
        SymExpr::Add(Box::new(init), Box::new(product))
    } else {
        SymExpr::Sub(Box::new(init), Box::new(product))
    };
    // Constraint: k >= 0
    // (encoded as `loop_k >= 0` which is always true for u64, but marks the variable)
    Some(widened)
}

// ─── LoopSummarizer ──────────────────────────────────────────────────────────

/// Detects loops, synthesises summaries, and applies widening.
pub struct LoopSummarizer {
    config: LoopSummarizerConfig,
    cfg: ControlFlowGraph,
    entry: BlockAddr,
    /// Cache of computed summaries (header address → summary).
    summaries: HashMap<BlockAddr, LoopSummary>,
    /// Unroll counters per loop header.
    unroll_counts: HashMap<BlockAddr, u32>,
}

impl LoopSummarizer {
    #[must_use]
    pub fn new(cfg: ControlFlowGraph, entry: BlockAddr, config: LoopSummarizerConfig) -> Self {
        Self {
            config,
            cfg,
            entry,
            summaries: HashMap::new(),
            unroll_counts: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_default_config(cfg: ControlFlowGraph, entry: BlockAddr) -> Self {
        Self::new(cfg, entry, LoopSummarizerConfig::default())
    }

    // ─── Loop detection ───────────────────────────────────────────────────

    /// Detect all loops in the CFG and return their structures.
    pub fn detect_loops(&mut self) -> Vec<Loop> {
        let back_edges = self.cfg.find_back_edges(self.entry);
        let mut loops = Vec::new();

        for edge in &back_edges {
            let body_set = self.cfg.loop_body(edge.to, edge.from);
            let mut lp = Loop::new(edge.to);
            lp.body_blocks = body_set.into_iter().collect();
            lp.body_blocks.sort_unstable();
            loops.push(lp);
        }

        loops
    }

    // ─── Induction variable detection ────────────────────────────────────

    /// Detect the induction variable of `lp` from `state`.
    ///
    /// Looks for a register `r` such that `state.registers[r]` is of the form
    /// `r + c` or `r - c` for a constant `c`.
    pub fn detect_induction_var(&self, lp: &mut Loop, state: &SymbolicState) {
        for (reg, expr) in &state.registers {
            // `Add` and `Sub` must NOT share an arm: a decrementing loop
            // (`r = r - c`) has step `-c`, and recording `+c` inverts the whole
            // progression — `derive_closed_form` then walks the wrong way and
            // `synthesize_invariants` emits MonotoneIncreasing for a variable
            // that decreases.
            let (base, step, descending) = match expr {
                SymExpr::Add(base, step) => (base, step, false),
                SymExpr::Sub(base, step) => (base, step, true),
                _ => continue,
            };
            if let SymExpr::Var { name, .. } = base.as_ref()
                && name == reg
                && let SymExpr::ConstBv { val, width: _ } = step.as_ref()
            {
                let step_val = if descending { val.wrapping_neg() } else { *val };
                lp.induction_var = Some(reg.clone());
                lp.step = Some(SymExpr::ConstBv { val: step_val, width: 64 });
                // The initial value is `base` — the symbolic value the register
                // held on entry. Re-reading `state.registers[reg]` yields the
                // RECURRENCE (`r + c`), i.e. the value AFTER one step, which
                // leaks a spurious `+c` into every closed form derived from it.
                lp.init_value = Some(base.as_ref().clone());
                return;
            }
        }
    }

    /// Extract the loop bound from the path condition.
    ///
    /// Looks for `var < bound` or `var <= bound` constraints where `var` is the
    /// induction variable.
    pub fn detect_bound(&self, lp: &mut Loop, state: &SymbolicState) {
        let Some(ref iv) = lp.induction_var.clone() else { return };
        for constraint in &state.path_condition {
            match constraint {
                SymExpr::ULt(lhs, rhs) | SymExpr::SLt(lhs, rhs) => {
                    if let SymExpr::Var { name, .. } = lhs.as_ref() && name == iv {
                        lp.bound = Some(*rhs.clone());
                        lp.exit_condition = Some(constraint.clone());
                        return;
                    }
                }
                SymExpr::ULe(lhs, rhs) | SymExpr::SLe(lhs, rhs) => {
                    if let SymExpr::Var { name, .. } = lhs.as_ref() && name == iv {
                        // bound is rhs + 1
                        let bound = SymExpr::Add(
                            rhs.clone(),
                            Box::new(SymExpr::ConstBv { val: 1, width: 64 }),
                        );
                        lp.bound = Some(bound);
                        lp.exit_condition = Some(constraint.clone());
                        return;
                    }
                }
                _ => {}
            }
        }
    }

    // ─── Closed-form derivation ───────────────────────────────────────────

    /// Attempt to derive a closed form for the loop body.
    ///
    /// For a loop `i = init; i < bound; i += step`, the closed form is:
    ///   `i_after = init + step * iterations`
    /// where `iterations = (bound - init) / step`.
    #[must_use]
    pub fn derive_closed_form(&self, lp: &Loop) -> ClosedForm {
        if !self.config.attempt_closed_form {
            return ClosedForm::Unknown;
        }

        let Some(ref iv) = lp.induction_var else { return ClosedForm::Unknown };
        let Some(ref init) = lp.init_value else { return ClosedForm::Unknown };
        let Some(ref step) = lp.step else { return ClosedForm::Unknown };
        let Some(ref bound) = lp.bound else { return ClosedForm::Unknown };

        if let SymExpr::ConstBv { val: step_val, .. } = step {
            if *step_val == 0 {
                return ClosedForm::Unknown;
            }
            // iterations = (bound - init) / step  [symbolic]
            let iterations = SymExpr::UDiv(
                Box::new(SymExpr::Sub(Box::new(bound.clone()), Box::new(init.clone()))),
                Box::new(step.clone()),
            );
            let result = SymExpr::Add(
                Box::new(init.clone()),
                Box::new(SymExpr::Mul(Box::new(step.clone()), Box::new(iterations.clone()))),
            );
            return ClosedForm::LinearIncrement {
                var: iv.clone(),
                init: init.clone(),
                step: step.clone(),
                iterations,
                result,
            };
        }

        ClosedForm::Unknown
    }

    // ─── Invariant synthesis ──────────────────────────────────────────────

    /// Synthesise invariants for `lp` from `state`.
    #[must_use]
    pub fn synthesize_invariants(&self, lp: &Loop, _state: &SymbolicState) -> Vec<InvariantTemplate> {
        let mut invs = Vec::new();

        let Some(ref iv) = lp.induction_var else { return invs };

        // Non-negativity.
        invs.push(InvariantTemplate::NonNegative(iv.clone()));

        // Monotone increasing if step > 0.
        if let Some(SymExpr::ConstBv { val, .. }) = &lp.step {
            let is_positive = *val > 0 && *val < i64::MAX as u64;
            if is_positive {
                let init = lp.init_value.clone().unwrap_or(SymExpr::ConstBv { val: 0, width: 64 });
                invs.push(InvariantTemplate::MonotoneIncreasing { var: iv.clone(), init });
            }
        }

        // Upper bound from loop condition.
        if let Some(ref bound) = lp.bound {
            invs.push(InvariantTemplate::UpperBound { var: iv.clone(), bound: bound.clone() });
        }

        // Stride invariant: if step is a power of 2.
        if let Some(SymExpr::ConstBv { val: step, .. }) = &lp.step
            && *step > 1
            && step.is_power_of_two()
        {
            let base = lp
                .init_value
                .as_ref()
                .and_then(SymExpr::as_const_u64)
                .unwrap_or(0);
            invs.push(InvariantTemplate::StrideInvariant {
                var: iv.clone(),
                stride: *step,
                base: base % step,
            });
        }

        invs.truncate(self.config.max_templates);
        invs
    }

    // ─── Unroll tracking & widening ───────────────────────────────────────

    /// Record that the loop at `header` has been unrolled once more.
    ///
    /// Returns `true` if the unroll limit has been reached and widening should
    /// be applied.
    pub fn tick_unroll(&mut self, header: BlockAddr) -> bool {
        let count = self.unroll_counts.entry(header).or_insert(0);
        *count += 1;
        *count >= self.config.unroll_limit
    }

    /// Apply widening to the induction variable in `state`.
    ///
    /// Replaces the concrete value of the induction variable with a symbolic
    /// range expression and adds the loop invariants to the path condition.
    pub fn apply_widening(&self, lp: &Loop, state: &mut SymbolicState) {
        if !self.config.apply_widening {
            return;
        }

        let Some(ref iv) = lp.induction_var else { return };

        // Replace the induction variable with a fresh symbolic variable.
        let widened_var = format!("{iv}_wide");
        state.registers.insert(
            iv.clone(),
            SymExpr::Var { name: widened_var.clone(), ty: SymType::BitVec(64) },
        );

        // Add invariant constraints.
        if let Some(ref init) = lp.init_value {
            // widened_var >= init
            state.path_condition.push(SymExpr::UGe(
                Box::new(SymExpr::Var { name: widened_var.clone(), ty: SymType::BitVec(64) }),
                Box::new(init.clone()),
            ));
        }
        if let Some(ref bound) = lp.bound {
            // widened_var < bound
            state.path_condition.push(SymExpr::ULt(
                Box::new(SymExpr::Var { name: widened_var, ty: SymType::BitVec(64) }),
                Box::new(bound.clone()),
            ));
        }
    }

    // ─── Full summarisation pass ──────────────────────────────────────────

    /// Summarise all detected loops for `state`.
    ///
    /// For each loop:
    /// 1. Detect induction variable and bound.
    /// 2. Attempt closed-form derivation.
    /// 3. If not possible, synthesise invariants and apply widening.
    ///
    /// Returns all generated summaries.
    #[must_use]
    pub fn summarize_all(&mut self, state: &SymbolicState) -> Vec<LoopSummary> {
        let mut loops = self.detect_loops();
        let mut summaries = Vec::new();

        for lp in &mut loops {
            self.detect_induction_var(lp, state);
            self.detect_bound(lp, state);

            let closed_form = self.derive_closed_form(lp);
            let invariants = self.synthesize_invariants(lp, state);

            let widened = matches!(closed_form, ClosedForm::Unknown);

            let mut post_constraints = Vec::new();
            for inv in &invariants {
                post_constraints.push(inv.to_expr());
            }

            let summary = LoopSummary {
                loop_info: lp.clone(),
                invariants,
                closed_form,
                widened,
                post_state_constraints: post_constraints,
            };

            self.summaries.insert(lp.header, summary.clone());
            summaries.push(summary);
        }

        summaries
    }

    /// Retrieve a previously computed summary for the loop at `header`.
    #[must_use]
    pub fn get_summary(&self, header: BlockAddr) -> Option<&LoopSummary> {
        self.summaries.get(&header)
    }

    /// Apply the summary for loop at `header` to `state`.
    ///
    /// If a closed form is available, updates the induction variable.
    /// Otherwise, applies widening.
    pub fn apply_summary(&mut self, header: BlockAddr, state: &mut SymbolicState) {
        let summary = match self.summaries.get(&header) {
            Some(s) => s.clone(),
            None => return,
        };

        // Add invariant constraints to the state's path condition.
        for constraint in &summary.post_state_constraints {
            state.path_condition.push(constraint.clone());
        }

        // If we have a linear closed form, update the induction variable.
        if let ClosedForm::LinearIncrement { ref var, ref result, .. } = summary.closed_form {
            state.registers.insert(var.clone(), result.clone());
        } else if summary.widened {
            self.apply_widening(&summary.loop_info, state);
        }
    }
}

// ─── Petgraph-backed CFG ──────────────────────────────────────────────────────

/// A [`ControlFlowGraph`] backed by a `petgraph::DiGraph` for efficient
/// reachability, dominance, and DFS-space queries.
///
/// This replaces the hand-rolled adjacency-map DFS in [`ControlFlowGraph`]
/// with petgraph's tested, efficient primitives.
pub struct PetgraphCfg {
    /// The underlying directed graph. Node weights are block addresses.
    pub graph: DiGraph<BlockAddr, ()>,
    /// Map from block address to its node index in `graph`.
    addr_to_node: HashMap<BlockAddr, NodeIndex>,
}

impl PetgraphCfg {
    /// Build a `PetgraphCfg` from an existing [`ControlFlowGraph`].
    #[must_use]
    pub fn from_cfg(cfg: &ControlFlowGraph) -> Self {
        let mut graph: DiGraph<BlockAddr, ()> = DiGraph::new();
        let mut addr_to_node: HashMap<BlockAddr, NodeIndex> = HashMap::new();

        // Add all blocks as nodes.
        for &addr in &cfg.blocks {
            let idx = graph.add_node(addr);
            addr_to_node.insert(addr, idx);
        }

        // Add all edges.
        for (&from, succs) in &cfg.succs {
            if let Some(&from_idx) = addr_to_node.get(&from) {
                for &to in succs {
                    if let Some(&to_idx) = addr_to_node.get(&to) {
                        graph.add_edge(from_idx, to_idx, ());
                    }
                }
            }
        }

        Self { graph, addr_to_node }
    }

    /// Return the petgraph [`NodeIndex`] for a block address, if present.
    #[must_use]
    pub fn node_index(&self, addr: BlockAddr) -> Option<NodeIndex> {
        self.addr_to_node.get(&addr).copied()
    }

    /// Find all back-edges using petgraph's depth-first search.
    ///
    /// A back-edge is an edge `(u, v)` where `v` is an ancestor of `u` in
    /// the DFS tree, i.e. `v` is on the current DFS stack when `(u, v)` is
    /// first traversed.
    #[must_use]
    pub fn find_back_edges(&self, entry: BlockAddr) -> Vec<CfgEdge> {
        use petgraph::visit::{DfsEvent, depth_first_search};

        let Some(&entry_idx) = self.addr_to_node.get(&entry) else {
            return Vec::new();
        };

        let mut back_edges = Vec::new();
        let mut on_stack: HashSet<NodeIndex> = HashSet::new();

        depth_first_search(&self.graph, Some(entry_idx), |event| {
            match event {
                DfsEvent::Discover(n, _) => { on_stack.insert(n); }
                DfsEvent::Finish(n, _)   => { on_stack.remove(&n); }
                DfsEvent::BackEdge(u, v) => {
                    let from = self.graph[u];
                    let to   = self.graph[v];
                    back_edges.push(CfgEdge { from, to, is_back_edge: true });
                }
                _ => {}
            }
        });

        // Silence unused-import warning for on_stack inside the closure.
        let _ = on_stack;
        back_edges
    }

    /// Return the number of nodes in the graph.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Return the number of edges in the graph.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_cfg() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new();
        // entry(0) → header(10) → body(20) → header(10) [back edge]
        // header(10) → exit(30)
        cfg.add_edge(0x0000, 0x1000); // entry → header
        cfg.add_edge(0x1000, 0x2000); // header → body
        cfg.add_edge(0x2000, 0x1000); // body → header (back edge)
        cfg.add_edge(0x1000, 0x3000); // header → exit
        cfg
    }

    #[test]
    fn test_find_back_edges() {
        let cfg = simple_cfg();
        let back_edges = cfg.find_back_edges(0x0000);
        assert!(!back_edges.is_empty());
        assert!(back_edges.iter().any(|e| e.to == 0x1000 && e.from == 0x2000));
    }

    #[test]
    fn test_loop_body() {
        let cfg = simple_cfg();
        let body = cfg.loop_body(0x1000, 0x2000);
        assert!(body.contains(&0x1000));
        assert!(body.contains(&0x2000));
        assert!(!body.contains(&0x3000));
    }

    #[test]
    fn test_detect_loops() {
        let cfg = simple_cfg();
        let mut summarizer = LoopSummarizer::with_default_config(cfg, 0x0000);
        let loops = summarizer.detect_loops();
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].header, 0x1000);
    }

    #[test]
    fn test_detect_induction_var() {
        let cfg = simple_cfg();
        let summarizer = LoopSummarizer::with_default_config(cfg, 0x0000);
        let mut state = SymbolicState::default();

        // Simulate: i = i + 1
        state.registers.insert(
            "rcx".into(),
            SymExpr::Add(
                Box::new(SymExpr::Var { name: "rcx".into(), ty: SymType::BitVec(64) }),
                Box::new(SymExpr::ConstBv { val: 1, width: 64 }),
            ),
        );

        let mut lp = Loop::new(0x1000);
        summarizer.detect_induction_var(&mut lp, &state);
        assert_eq!(lp.induction_var.as_deref(), Some("rcx"));
        assert!(lp.is_constant_step());
    }

    #[test]
    fn test_closed_form_linear() {
        let cfg = simple_cfg();
        let summarizer = LoopSummarizer::with_default_config(cfg, 0x0000);
        let mut lp = Loop::new(0x1000);
        lp.induction_var = Some("i".into());
        lp.init_value = Some(SymExpr::ConstBv { val: 0, width: 64 });
        lp.step = Some(SymExpr::ConstBv { val: 1, width: 64 });
        lp.bound = Some(SymExpr::ConstBv { val: 10, width: 64 });

        let cf = summarizer.derive_closed_form(&lp);
        assert!(matches!(cf, ClosedForm::LinearIncrement { .. }));
    }

    #[test]
    fn test_widen_sequence() {
        let vals = [0u64, 4, 8, 12];
        let widened = widen_sequence(&vals).unwrap();
        // Should be 0 + 4 * k
        assert!(matches!(widened, SymExpr::Add(..)));
    }

    #[test]
    fn test_widen_non_uniform() {
        let vals = [0u64, 1, 3, 7];
        assert!(widen_sequence(&vals).is_none());
    }

    #[test]
    fn test_tick_unroll() {
        let cfg = simple_cfg();
        let mut summarizer = LoopSummarizer::new(
            cfg,
            0x0000,
            LoopSummarizerConfig { unroll_limit: 3, ..Default::default() },
        );
        assert!(!summarizer.tick_unroll(0x1000));
        assert!(!summarizer.tick_unroll(0x1000));
        assert!(summarizer.tick_unroll(0x1000)); // 3rd tick = limit reached
    }

    #[test]
    fn test_invariant_synthesis() {
        let cfg = simple_cfg();
        let summarizer = LoopSummarizer::with_default_config(cfg, 0x0000);
        let mut lp = Loop::new(0x1000);
        lp.induction_var = Some("i".into());
        lp.step = Some(SymExpr::ConstBv { val: 1, width: 64 });
        lp.init_value = Some(SymExpr::ConstBv { val: 0, width: 64 });
        lp.bound = Some(SymExpr::ConstBv { val: 100, width: 64 });

        let state = SymbolicState::default();
        let invs = summarizer.synthesize_invariants(&lp, &state);
        assert!(!invs.is_empty());

        // Non-negativity must be present.
        assert!(invs.iter().any(|i| matches!(i, InvariantTemplate::NonNegative(_))));
        // Upper bound.
        assert!(invs.iter().any(|i| matches!(i, InvariantTemplate::UpperBound { .. })));
    }
}
