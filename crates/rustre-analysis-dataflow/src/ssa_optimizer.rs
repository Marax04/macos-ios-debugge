//! SSA-based optimizer for `rustre-analysis-dataflow`.
//!
//! # Overview
//!
//! Audit note (dataflow-crate iteration 5): grepped the whole workspace for
//! `rustre_analysis_dataflow::` usage — nothing outside this crate calls into
//! this module. Note its `SsaFunction`/`SsaBlock`/etc. are a *separate*,
//! self-contained model from [`crate::ssa::SsaFunction`] (used by
//! `live_ranges`/`value_range`); the two are not interchangeable. Only this
//! module's own unit tests exercise it — treat it as orphaned library code
//! until a real consumer shows up.
//!
//! This module implements several classical SSA optimization passes.  All
//! passes operate on the [`SsaFunction`] model, which is a simplified
//! intermediate representation designed to be both easy to generate from real
//! IL and easy to test in isolation.
//!
//! ## Pass Order
//!
//! The recommended pass order (implemented by [`SsaOptimizer`]) is:
//!
//! 1. **SCCP** ([`SparseConditionalConst`]) — propagates constant values along
//!    the SSA def-use graph.  The "sparse conditional" variant avoids
//!    evaluating instructions in blocks that SCCP proves unreachable.
//!
//! 2. **Branch Elimination** ([`BranchElimination`]) — converts conditional
//!    branches whose condition SCCP proved constant into unconditional jumps.
//!
//! 3. **GVN** ([`GvnPass`]) — replaces duplicate computations with references
//!    to the first SSA variable that computed the same expression.
//!
//! 4. **Copy Folding** ([`CopyFolding`]) — eliminates trivial copies `x = y`
//!    by substituting all uses of `x` with `y`.
//!
//! 5. **Phi Elimination** ([`PhiElimination`]) — removes φ-functions by
//!    inserting parallel copies along predecessors.  Must run last because it
//!    introduces new assignments that would confuse earlier passes.
//!
//! ## Verification
//!
//! Use [`SsaVerifier`] after each pass to catch regressions (duplicate
//! definitions, uses without definitions, etc.).
//!
//! ## Liveness
//!
//! [`LivenessAnalysis`] computes live-in / live-out sets for each block.
//! This is needed for register allocation (out of scope here) and dead-code
//! elimination ([`SsaDeadCodeEliminator`]).
//!
//! Implements several classic SSA optimizations:
//!
//! * [`SparseConditionalConst`] — sparse conditional constant propagation (SCCP).
//! * [`GvnPass`] — global value numbering.
//! * [`CopyFolding`] — copy folding / coalescing.
//! * [`PhiElimination`] — φ-function elimination (required before register
//!   allocation or when lowering back to non-SSA form).
//! * [`BranchElimination`] — remove unreachable branches discovered by SCCP.
//!
//! All passes operate on a generic [`SsaFunction`] model that is independent
//! of any particular IL.

use std::collections::{HashMap, HashSet, VecDeque};
use rustc_hash::FxHashMap;
use std::fmt;
use std::hash::Hash;

// ---------------------------------------------------------------------------
// Well-known constants
// ---------------------------------------------------------------------------

/// Maximum SCCP iterations before giving up.
pub const MAX_SCCP_ITERS: usize = 1_000;

/// Maximum GVN hash-table capacity before switching to fallback.
pub const MAX_GVN_TABLE: usize = 65_536;

// ---------------------------------------------------------------------------
// SsaOptLevel — configuration for pass aggressiveness
// ---------------------------------------------------------------------------

/// How aggressively to run the SSA optimizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum SsaOptLevel {
    /// Only constant folding and obvious copies.
    Quick,
    /// Full pass pipeline (SCCP + GVN + copy folding + phi elim).
    #[default]
    Full,
    /// Full + dead-code elimination.
    Aggressive,
}


// ---------------------------------------------------------------------------
// SsaOptConfig — tuning for the optimizer
// ---------------------------------------------------------------------------

/// Tuning parameters for [`SsaOptimizer`].
#[derive(Debug, Clone)]
pub struct SsaOptConfig {
    pub level: SsaOptLevel,
    pub max_iterations: usize,
}

impl Default for SsaOptConfig {
    fn default() -> Self {
        Self {
            level: SsaOptLevel::Full,
            max_iterations: 20,
        }
    }
}

// ---------------------------------------------------------------------------
// SsaFunctionPrinter — simple textual dump of SSA form
// ---------------------------------------------------------------------------

/// Prints an [`SsaFunction`] as plain text for debugging.
#[derive(Debug, Default)]
pub struct SsaFunctionPrinter;

impl SsaFunctionPrinter {
    /// Produce a text dump of `func`.
    #[must_use] 
    pub fn print(func: &SsaFunction) -> String {
        use std::fmt::Write as _;
        let mut out = format!("fn {} (entry bb{}) {{\n", func.name, func.entry);
        for block in &func.blocks {
            let _ = writeln!(out, "  bb{}:", block.id);
            for instr in &block.instrs {
                let def_s = instr
                    .def
                    .as_ref()
                    .map(|d| format!("{d} = "))
                    .unwrap_or_default();
                let _ = writeln!(out, "    {def_s}{:?}", instr.expr);
            }
            let term_s = match &block.term {
                SsaTerm::Return(None) => "return".into(),
                SsaTerm::Return(Some(r)) => format!("return {r}"),
                SsaTerm::Jump(t) => format!("goto bb{t}"),
                SsaTerm::Branch(c, t, f) => format!("if {c} goto bb{t} else bb{f}"),
                SsaTerm::Unreachable => "unreachable".into(),
            };
            let _ = writeln!(out, "    {term_s}");
        }
        out.push_str("}\n");
        out
    }
}

// ---------------------------------------------------------------------------
// Generic SSA IR model
// ---------------------------------------------------------------------------

/// An SSA variable reference (name + version).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SsaRef {
    pub name: String,
    pub version: u32,
}

impl SsaRef {
    #[must_use]
    pub fn new(name: impl Into<String>, version: u32) -> Self {
        Self {
            name: name.into(),
            version,
        }
    }
}

impl fmt::Display for SsaRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.name, self.version)
    }
}

/// A constant value in the abstract domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConstVal {
    Int(i64),
    Bool(bool),
    Unknown,
}

impl ConstVal {
    #[must_use]
    pub const fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// A simple SSA expression.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SsaExpr {
    Const(ConstVal),
    Var(SsaRef),
    Add(SsaRef, SsaRef),
    Sub(SsaRef, SsaRef),
    Mul(SsaRef, SsaRef),
    And(SsaRef, SsaRef),
    Or(SsaRef, SsaRef),
    Xor(SsaRef, SsaRef),
    Neg(SsaRef),
    Not(SsaRef),
    CmpEq(SsaRef, SsaRef),
    CmpLt(SsaRef, SsaRef),
    Phi(Vec<(u32, SsaRef)>), // (predecessor block id, source var)
    Call { name: String, args: Vec<SsaRef> },
}

impl SsaExpr {
    /// True if this expression may have observable side effects.
    #[must_use]
    pub const fn has_side_effects(&self) -> bool {
        matches!(self, Self::Call { .. })
    }

    /// Collect all [`SsaRef`] uses.
    #[must_use] 
    pub fn uses(&self) -> Vec<&SsaRef> {
        match self {
            Self::Const(_) => vec![],
            Self::Var(v) | Self::Neg(v) | Self::Not(v) => vec![v],
            Self::Add(l, r)
            | Self::Sub(l, r)
            | Self::Mul(l, r)
            | Self::And(l, r)
            | Self::Or(l, r)
            | Self::Xor(l, r)
            | Self::CmpEq(l, r)
            | Self::CmpLt(l, r) => vec![l, r],
            Self::Phi(srcs) => srcs.iter().map(|(_, r)| r).collect(),
            Self::Call { args, .. } => args.iter().collect(),
        }
    }
}

/// A single SSA instruction: optional definition + expression.
#[derive(Debug, Clone)]
pub struct SsaInstr {
    pub def: Option<SsaRef>,
    pub expr: SsaExpr,
}

impl SsaInstr {
    #[must_use]
    pub const fn assign(def: SsaRef, expr: SsaExpr) -> Self {
        Self {
            def: Some(def),
            expr,
        }
    }

    #[must_use]
    pub const fn effect(expr: SsaExpr) -> Self {
        Self { def: None, expr }
    }
}

/// Terminal instruction of a basic block.
#[derive(Debug, Clone)]
pub enum SsaTerm {
    Return(Option<SsaRef>),
    Jump(u32),                // unconditional to block id
    Branch(SsaRef, u32, u32), // cond, true_id, false_id
    Unreachable,
}

/// A basic block in SSA form.
#[derive(Debug, Clone)]
pub struct SsaBlock {
    pub id: u32,
    pub instrs: Vec<SsaInstr>,
    pub term: SsaTerm,
}

impl SsaBlock {
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self {
            id,
            instrs: vec![],
            term: SsaTerm::Unreachable,
        }
    }

    /// Successor block ids.
    #[must_use]
    pub fn successors(&self) -> Vec<u32> {
        match &self.term {
            SsaTerm::Return(_) | SsaTerm::Unreachable => vec![],
            SsaTerm::Jump(t) => vec![*t],
            SsaTerm::Branch(_, t, f) => vec![*t, *f],
        }
    }
}

/// A complete function in SSA form.
#[derive(Debug, Clone)]
pub struct SsaFunction {
    pub name: String,
    pub blocks: Vec<SsaBlock>,
    pub entry: u32,
}

impl SsaFunction {
    /// Look up a block by id.
    #[must_use]
    pub fn block(&self, id: u32) -> Option<&SsaBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }

    /// Mutable lookup.
    pub fn block_mut(&mut self, id: u32) -> Option<&mut SsaBlock> {
        self.blocks.iter_mut().find(|b| b.id == id)
    }

    /// Collect all predecessors for each block id.
    #[must_use]
    pub fn predecessors(&self) -> HashMap<u32, Vec<u32>> {
        let mut map: HashMap<u32, Vec<u32>> = HashMap::new();
        for b in &self.blocks {
            for s in b.successors() {
                map.entry(s).or_default().push(b.id);
            }
        }
        map
    }
}

// ---------------------------------------------------------------------------
// SsaOptStats
// ---------------------------------------------------------------------------

/// Accumulated statistics from all SSA optimization passes.
#[derive(Debug, Clone, Default)]
pub struct SsaOptStats {
    pub const_propagated: usize,
    pub copies_folded: usize,
    pub phis_eliminated: usize,
    pub branches_removed: usize,
    pub gvn_replacements: usize,
    pub dead_defs_removed: usize,
}

impl SsaOptStats {
    #[must_use]
    pub const fn total(&self) -> usize {
        self.const_propagated
            + self.copies_folded
            + self.phis_eliminated
            + self.branches_removed
            + self.gvn_replacements
            + self.dead_defs_removed
    }
}

// ---------------------------------------------------------------------------
// SparseConditionalConst (SCCP)
// ---------------------------------------------------------------------------

/// Lattice element for SCCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScccLat {
    Top, // uninitialised / unreachable
    Const(ConstVal),
    Bottom, // multiple values (unknown)
}

impl ScccLat {
    fn meet(a: &Self, b: &Self) -> Self {
        match (a, b) {
            (Self::Top, x) | (x, Self::Top) => x.clone(),
            (Self::Const(ca), Self::Const(cb)) if ca == cb => Self::Const(ca.clone()),
            _ => Self::Bottom,
        }
    }
}

/// Sparse Conditional Constant Propagation.
#[derive(Debug, Default)]
pub struct SparseConditionalConst {
    pub stats: SsaOptStats,
}

impl SparseConditionalConst {
    /// Run SCCP on `func`, returning a map of var → constant value for all
    /// variables proven constant.
    pub fn run(&mut self, func: &mut SsaFunction) -> HashMap<SsaRef, ConstVal> {
        let mut lattice: HashMap<SsaRef, ScccLat> = HashMap::new();
        let mut exec: HashSet<u32> = HashSet::new();
        let mut work: VecDeque<u32> = VecDeque::new();

        work.push_back(func.entry);
        exec.insert(func.entry);

        // Initialise all vars to Top, and precompute a use-index (var ->
        // block ids that use it) so that propagating a lattice change to
        // "users" is an O(1) lookup instead of an O(blocks * instrs) rescan
        // of the whole function on every single lattice update. Without this
        // index, SCCP degenerates to O(iterations * blocks * instrs) work,
        // which is quadratic-or-worse in function size.
        let mut use_index: HashMap<SsaRef, Vec<u32>> = HashMap::new();
        for block in &func.blocks {
            for instr in &block.instrs {
                if let Some(def) = &instr.def {
                    lattice.insert(def.clone(), ScccLat::Top);
                }
                for used in instr.expr.uses() {
                    let users = use_index.entry(used.clone()).or_default();
                    if users.last() != Some(&block.id) {
                        users.push(block.id);
                    }
                }
            }
        }

        // Also index blocks by id for O(1) lookup in the worklist loop
        // below (replacing the previous O(blocks) linear `func.block()`
        // scan on every iteration).
        let block_index: HashMap<u32, usize> =
            func.blocks.iter().enumerate().map(|(i, b)| (b.id, i)).collect();

        while let Some(bid) = work.pop_front() {
            let block = match block_index.get(&bid).map(|&i| &func.blocks[i]) {
                Some(b) => b.clone(),
                None => continue,
            };
            for instr in &block.instrs {
                let new_lat = Self::eval_expr(&instr.expr, &lattice);
                if let Some(def) = &instr.def {
                    let current = lattice.get(def).cloned().unwrap_or(ScccLat::Top);
                    let merged = ScccLat::meet(&current, &new_lat);
                    if merged != current {
                        lattice.insert(def.clone(), merged);
                        // Propagate to users via the precomputed index.
                        if let Some(users) = use_index.get(def) {
                            for &b_id in users {
                                if !work.contains(&b_id) {
                                    work.push_back(b_id);
                                }
                            }
                        }
                    }
                }
            }
            // Evaluate terminator.
            match &block.term {
                SsaTerm::Branch(cond, t, f) => {
                    let lat = lattice.get(cond).cloned().unwrap_or(ScccLat::Bottom);
                    match lat {
                        ScccLat::Const(ConstVal::Bool(true)) => {
                            if exec.insert(*t) {
                                work.push_back(*t);
                            }
                        }
                        ScccLat::Const(ConstVal::Bool(false)) => {
                            if exec.insert(*f) {
                                work.push_back(*f);
                            }
                        }
                        ScccLat::Top
                        | ScccLat::Bottom
                        | ScccLat::Const(ConstVal::Int(_) | ConstVal::Unknown) => {
                            if exec.insert(*t) {
                                work.push_back(*t);
                            }
                            if exec.insert(*f) {
                                work.push_back(*f);
                            }
                        }
                    }
                }
                SsaTerm::Jump(t)
                    if exec.insert(*t) => {
                        work.push_back(*t);
                    }
                SsaTerm::Jump(_) | SsaTerm::Return(_) | SsaTerm::Unreachable => {}
            }
        }

        // Extract constants.
        let mut result = HashMap::new();
        for (var, lat) in &lattice {
            if let ScccLat::Const(cv) = lat {
                result.insert(var.clone(), cv.clone());
                self.stats.const_propagated += 1;
            }
        }

        // Rewrite function: replace var refs with constants.
        Self::apply_constants(func, &result);
        result
    }

    fn eval_expr(expr: &SsaExpr, lattice: &HashMap<SsaRef, ScccLat>) -> ScccLat {
        match expr {
            SsaExpr::Const(cv) => ScccLat::Const(cv.clone()),
            SsaExpr::Var(v) => lattice.get(v).cloned().unwrap_or(ScccLat::Bottom),
            SsaExpr::Add(l, r) => {
                let lv = Self::get_int(l, lattice);
                let rv = Self::get_int(r, lattice);
                match (lv, rv) {
                    (Some(a), Some(b)) => ScccLat::Const(ConstVal::Int(a.wrapping_add(b))),
                    _ => ScccLat::Bottom,
                }
            }
            SsaExpr::Sub(l, r) => match (Self::get_int(l, lattice), Self::get_int(r, lattice)) {
                (Some(a), Some(b)) => ScccLat::Const(ConstVal::Int(a.wrapping_sub(b))),
                _ => ScccLat::Bottom,
            },
            SsaExpr::Mul(l, r) => match (Self::get_int(l, lattice), Self::get_int(r, lattice)) {
                (Some(a), Some(b)) => ScccLat::Const(ConstVal::Int(a.wrapping_mul(b))),
                _ => ScccLat::Bottom,
            },
            SsaExpr::CmpEq(l, r) => match (Self::get_int(l, lattice), Self::get_int(r, lattice)) {
                (Some(a), Some(b)) => ScccLat::Const(ConstVal::Bool(a == b)),
                _ => ScccLat::Bottom,
            },
            SsaExpr::CmpLt(l, r) => match (Self::get_int(l, lattice), Self::get_int(r, lattice)) {
                (Some(a), Some(b)) => ScccLat::Const(ConstVal::Bool(a < b)),
                _ => ScccLat::Bottom,
            },
            SsaExpr::Phi(srcs) => {
                if srcs.is_empty() {
                    return ScccLat::Bottom;
                }
                let mut acc = ScccLat::Top;
                for (_, r) in srcs {
                    let lat = lattice.get(r).cloned().unwrap_or(ScccLat::Bottom);
                    acc = ScccLat::meet(&acc, &lat);
                }
                acc
            }
            _ => ScccLat::Bottom,
        }
    }

    fn get_int(v: &SsaRef, lattice: &HashMap<SsaRef, ScccLat>) -> Option<i64> {
        if let Some(ScccLat::Const(ConstVal::Int(n))) = lattice.get(v) {
            Some(*n)
        } else {
            None
        }
    }

    fn apply_constants(func: &mut SsaFunction, consts: &HashMap<SsaRef, ConstVal>) {
        for block in &mut func.blocks {
            for instr in &mut block.instrs {
                substitute_ssa_refs_in_expr(&mut instr.expr, consts);
            }
        }
    }
}

fn substitute_ssa_refs_in_expr(expr: &mut SsaExpr, consts: &HashMap<SsaRef, ConstVal>) {
    if let SsaExpr::Var(v) = expr
        && let Some(cv) = consts.get(v)
    {
        *expr = SsaExpr::Const(cv.clone());
    }
}

// ---------------------------------------------------------------------------
// GvnPass — Global Value Numbering
// ---------------------------------------------------------------------------

/// Assigns value numbers to expressions and replaces duplicates.
#[derive(Debug, Default)]
pub struct GvnPass {
    pub stats: SsaOptStats,
}

impl GvnPass {
    pub fn run(&mut self, func: &mut SsaFunction) {
        // Map expression key → (first defining var, defining block id).
        // FxHashMap prevents hash-collision DoS when expression keys are
        // derived from attacker-controlled operand names in parsed binary input.
        let mut table: FxHashMap<&SsaExpr, (SsaRef, u32)> = FxHashMap::default();
        let mut replacements: HashMap<SsaRef, SsaRef> = HashMap::new();

        // Dominators are required for soundness: replacing `y = e` with a
        // reference to an earlier `x = e` is only valid if `x`'s definition
        // dominates `y`'s (in SSA, every use of `y` is dominated by `y`'s
        // def, so dominance of the def suffices).  Without this check, two
        // sibling branch arms computing the same expression would be merged,
        // leaving one path using a variable it never defines.
        let idom = compute_idom_ssa(func);

        for block in &func.blocks {
            for instr in &block.instrs {
                if let Some(def) = &instr.def
                    && !instr.expr.has_side_effects()
                    // φ-values depend on the incoming CFG edge, not just on
                    // their textual operands, so they must never be merged
                    // across blocks by a syntactic table.
                    && !matches!(instr.expr, SsaExpr::Phi(_)) {
                        let key = &instr.expr;
                        match table.get(key) {
                            // Same block: the earlier instruction (inserted
                            // first, in program order) trivially dominates.
                            Some((prev, prev_bid))
                                if *prev_bid == block.id
                                    || dominates(*prev_bid, block.id, func.entry, &idom) =>
                            {
                                replacements.insert(def.clone(), prev.clone());
                                self.stats.gvn_replacements += 1;
                            }
                            Some(_) => {} // no dominance — keep both defs
                            None => {
                                table.insert(key, (def.clone(), block.id));
                            }
                        }
                    }
            }
        }

        // Apply replacements.
        for block in &mut func.blocks {
            for instr in &mut block.instrs {
                apply_ssa_ref_replacements(&mut instr.expr, &replacements);
            }
        }
    }
}

/// Immediate-dominator computation (Cooper–Harvey–Kennedy over RPO indices),
/// replacing the earlier dominator-SET fixpoint which allocated an O(n)
/// `HashSet` per block per sweep (O(n²) memory and time).  The GVN consumer
/// only ever asks "does `a` dominate `b`" — answered by walking `b`'s idom
/// chain in [`dominates`].  Blocks unreachable from the entry get no idom
/// entry, so they dominate nothing and are dominated by nothing, which is
/// conservative for GVN (no merges), matching the old self-only-set behavior.
fn compute_idom_ssa(func: &SsaFunction) -> HashMap<u32, u32> {
    let preds = func.predecessors();
    // RPO over reachable blocks via iterative DFS on successors.
    let succs: HashMap<u32, Vec<u32>> = {
        let mut s: HashMap<u32, Vec<u32>> = HashMap::new();
        for (to, ps) in &preds {
            for &p in ps {
                s.entry(p).or_default().push(*to);
            }
        }
        s
    };
    let mut post: Vec<u32> = Vec::new();
    let mut state: HashMap<u32, usize> = HashMap::new(); // next-successor cursor
    let mut stack: Vec<u32> = vec![func.entry];
    state.insert(func.entry, 0);
    while let Some(&b) = stack.last() {
        let cursor = state.get_mut(&b).expect("on stack implies state entry");
        let next = succs.get(&b).and_then(|ss| ss.get(*cursor).copied());
        *cursor += 1;
        match next {
            Some(s) => {
                if !state.contains_key(&s) {
                    state.insert(s, 0);
                    stack.push(s);
                }
            }
            None => {
                stack.pop();
                post.push(b);
            }
        }
    }
    let rpo: Vec<u32> = post.into_iter().rev().collect();
    let rpo_num: HashMap<u32, usize> = rpo.iter().enumerate().map(|(i, &b)| (b, i)).collect();

    let mut idom: HashMap<u32, u32> = HashMap::new();
    idom.insert(func.entry, func.entry);
    let intersect = |mut a: u32, mut b: u32, idom: &HashMap<u32, u32>| -> u32 {
        while a != b {
            while rpo_num[&a] > rpo_num[&b] {
                a = idom[&a];
            }
            while rpo_num[&b] > rpo_num[&a] {
                b = idom[&b];
            }
        }
        a
    };
    let mut changed = true;
    while changed {
        changed = false;
        for &b in &rpo {
            if b == func.entry {
                continue;
            }
            let mut new_idom: Option<u32> = None;
            for p in preds.get(&b).map_or(&[][..], Vec::as_slice) {
                if !idom.contains_key(p) || !rpo_num.contains_key(p) {
                    continue;
                }
                new_idom = Some(match new_idom {
                    None => *p,
                    Some(cur) => intersect(*p, cur, &idom),
                });
            }
            if let Some(new) = new_idom
                && idom.get(&b) != Some(&new)
            {
                idom.insert(b, new);
                changed = true;
            }
        }
    }
    idom
}

/// True iff `a` strictly dominates `b` (walks `b`'s idom chain; `a == b` is
/// handled by the same-block arm at the call site, never here).
fn dominates(a: u32, b: u32, entry: u32, idom: &HashMap<u32, u32>) -> bool {
    let mut cur = b;
    loop {
        let Some(&d) = idom.get(&cur) else { return false };
        if d == a {
            return true;
        }
        if cur == entry || d == cur {
            return false;
        }
        cur = d;
    }
}

fn apply_ssa_ref_replacements(expr: &mut SsaExpr, map: &HashMap<SsaRef, SsaRef>) {
    match expr {
        SsaExpr::Var(v) | SsaExpr::Neg(v) | SsaExpr::Not(v) => {
            if let Some(r) = map.get(v) {
                *v = r.clone();
            }
        }
        SsaExpr::Add(l, r)
        | SsaExpr::Sub(l, r)
        | SsaExpr::Mul(l, r)
        | SsaExpr::And(l, r)
        | SsaExpr::Or(l, r)
        | SsaExpr::Xor(l, r)
        | SsaExpr::CmpEq(l, r)
        | SsaExpr::CmpLt(l, r) => {
            if let Some(r2) = map.get(l) {
                *l = r2.clone();
            }
            if let Some(r2) = map.get(r) {
                *r = r2.clone();
            }
        }
        SsaExpr::Call { args, .. } => {
            for a in args {
                if let Some(r2) = map.get(a) {
                    *a = r2.clone();
                }
            }
        }
        SsaExpr::Phi(srcs) => {
            for (_, r) in srcs {
                if let Some(r2) = map.get(r) {
                    *r = r2.clone();
                }
            }
        }
        SsaExpr::Const(_) => {}
    }
}

// ---------------------------------------------------------------------------
// CopyFolding
// ---------------------------------------------------------------------------

/// Eliminates trivial copy assignments `x = y` by substituting all uses of
/// `x` with `y`.
#[derive(Debug, Default)]
pub struct CopyFolding {
    pub stats: SsaOptStats,
}

impl CopyFolding {
    pub fn run(&mut self, func: &mut SsaFunction) {
        let mut copies: HashMap<SsaRef, SsaRef> = HashMap::new();
        for block in &func.blocks {
            for instr in &block.instrs {
                if let (Some(def), SsaExpr::Var(src)) = (&instr.def, &instr.expr) {
                    copies.insert(def.clone(), src.clone());
                    self.stats.copies_folded += 1;
                }
            }
        }
        if copies.is_empty() {
            return;
        }
        for block in &mut func.blocks {
            for instr in &mut block.instrs {
                apply_ssa_ref_replacements(&mut instr.expr, &copies);
            }
            if let SsaTerm::Branch(cond, _, _) = &mut block.term
                && let Some(r) = copies.get(cond) {
                    *cond = r.clone();
                }
        }
    }
}

// ---------------------------------------------------------------------------
// PhiElimination
// ---------------------------------------------------------------------------

/// Removes φ-functions by inserting parallel copies along predecessors.
///
/// This is a simplified (non-parallel-copy-aware) version sufficient for
/// single-entry SSA with no critical edges.
#[derive(Debug, Default)]
pub struct PhiElimination {
    pub stats: SsaOptStats,
}

impl PhiElimination {
    pub fn run(&mut self, func: &mut SsaFunction) {
        let preds = func.predecessors();
        let mut copies_to_insert: HashMap<u32, Vec<SsaInstr>> = HashMap::new();

        // Scan every block for φ-functions at the top.
        for block in &func.blocks {
            for instr in &block.instrs {
                if let (Some(def), SsaExpr::Phi(srcs)) = (&instr.def, &instr.expr) {
                    for (pred_id, src_var) in srcs {
                        // Verify the φ source really is a CFG predecessor of
                        // this block; mismatches indicate a malformed SSA form.
                        debug_assert!(
                            preds.get(&block.id).is_none_or(|p| p.contains(pred_id)),
                            "φ in block {} references non-predecessor {pred_id}",
                            block.id
                        );
                        let copy = SsaInstr::assign(def.clone(), SsaExpr::Var(src_var.clone()));
                        copies_to_insert.entry(*pred_id).or_default().push(copy);
                    }
                    self.stats.phis_eliminated += 1;
                }
            }
        }

        // Remove φ-instructions.
        for block in &mut func.blocks {
            block.instrs.retain(|i| !matches!(i.expr, SsaExpr::Phi(_)));
        }

        // Append copies to predecessors.
        for block in &mut func.blocks {
            if let Some(copies) = copies_to_insert.remove(&block.id) {
                block.instrs.extend(copies);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BranchElimination
// ---------------------------------------------------------------------------

/// Removes branches that SCCP proved are never taken.
#[derive(Default)]
pub struct BranchElimination {
    pub stats: SsaOptStats,
}


impl fmt::Debug for BranchElimination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BranchElimination").finish_non_exhaustive()
    }
}

impl BranchElimination {
    /// Using `consts` from SCCP, convert proven constant branches to
    /// unconditional jumps.
    pub fn run(&mut self, func: &mut SsaFunction, consts: &HashMap<SsaRef, ConstVal>) {
        for block in &mut func.blocks {
            if let SsaTerm::Branch(cond, t, f) = block.term.clone()
                && let Some(cv) = consts.get(&cond) {
                    match cv {
                        ConstVal::Bool(true) => {
                            block.term = SsaTerm::Jump(t);
                            self.stats.branches_removed += 1;
                        }
                        ConstVal::Bool(false) => {
                            block.term = SsaTerm::Jump(f);
                            self.stats.branches_removed += 1;
                        }
                        ConstVal::Int(_) | ConstVal::Unknown => {}
                    }
                }
        }
    }
}

// ---------------------------------------------------------------------------
// SsaOptimizer — orchestrates all passes
// ---------------------------------------------------------------------------

/// Orchestrates SCCP → GVN → copy-folding → branch elimination → φ-elim.
#[derive(Debug, Default)]
pub struct SsaOptimizer {
    pub stats: SsaOptStats,
}

impl SsaOptimizer {
    /// Run the full SSA optimization pipeline on `func`.
    pub fn optimize(&mut self, func: &mut SsaFunction) {
        // 1. SCCP
        let mut sccp = SparseConditionalConst::default();
        let consts = sccp.run(func);
        self.stats.const_propagated += sccp.stats.const_propagated;

        // 2. Branch elimination
        let mut be = BranchElimination::default();
        be.run(func, &consts);
        self.stats.branches_removed += be.stats.branches_removed;

        // 3. GVN
        let mut gvn = GvnPass::default();
        gvn.run(func);
        self.stats.gvn_replacements += gvn.stats.gvn_replacements;

        // 4. Copy folding
        let mut cf = CopyFolding::default();
        cf.run(func);
        self.stats.copies_folded += cf.stats.copies_folded;

        // 5. φ-elimination (last, after all value rewrites)
        let mut pe = PhiElimination::default();
        pe.run(func);
        self.stats.phis_eliminated += pe.stats.phis_eliminated;
    }
}

// ---------------------------------------------------------------------------
// SsaFunctionBuilder — convenience builder for tests and transformations
// ---------------------------------------------------------------------------

/// Fluent builder for constructing [`SsaFunction`] values.
#[derive(Debug, Default)]
pub struct SsaFunctionBuilder {
    name: String,
    blocks: Vec<SsaBlock>,
    entry: u32,
}

impl SsaFunctionBuilder {
    /// Create a builder for a function named `name`.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            blocks: Vec::new(),
            entry: 0,
        }
    }

    /// Set the entry block id.
    #[must_use]
    pub const fn entry(mut self, id: u32) -> Self {
        self.entry = id;
        self
    }

    /// Add a block.
    #[must_use]
    pub fn block(mut self, b: SsaBlock) -> Self {
        self.blocks.push(b);
        self
    }

    /// Finalise.
    #[must_use]
    pub fn build(self) -> SsaFunction {
        SsaFunction {
            name: self.name,
            blocks: self.blocks,
            entry: self.entry,
        }
    }
}

// ---------------------------------------------------------------------------
// SsaVerifier — basic well-formedness checker
// ---------------------------------------------------------------------------

/// Checks an [`SsaFunction`] for basic well-formedness (every use has a def,
/// no duplicate definitions, etc.).
#[derive(Debug, Default)]
pub struct SsaVerifier;

/// A well-formedness issue.
#[derive(Debug, Clone)]
pub struct SsaIssue {
    pub block_id: u32,
    pub description: String,
}

impl SsaVerifier {
    /// Verify `func` and return any issues found.
    #[must_use] 
    pub fn verify(func: &SsaFunction) -> Vec<SsaIssue> {
        let mut issues = Vec::new();
        let mut defined: std::collections::HashSet<SsaRef> = std::collections::HashSet::new();

        // Collect all definitions.
        for block in &func.blocks {
            for instr in &block.instrs {
                if let Some(def) = &instr.def
                    && !defined.insert(def.clone()) {
                        issues.push(SsaIssue {
                            block_id: block.id,
                            description: format!("duplicate definition of {def}"),
                        });
                    }
            }
        }

        // Check that all uses are defined (excluding phi sources which may come from predecessors).
        for block in &func.blocks {
            for instr in &block.instrs {
                if matches!(instr.expr, SsaExpr::Phi(_)) {
                    continue;
                }
                for u in instr.expr.uses() {
                    if !defined.contains(u) {
                        issues.push(SsaIssue {
                            block_id: block.id,
                            description: format!("use of undefined SSA variable {u}"),
                        });
                    }
                }
            }
        }
        issues
    }
}

// ---------------------------------------------------------------------------
// LivenessAnalysis — simple liveness for SSA
// ---------------------------------------------------------------------------

/// Computes which SSA variables are live at the exit of each block.
#[derive(Debug, Default)]
pub struct LivenessAnalysis;

impl LivenessAnalysis {
    /// Compute live-out sets for each block in `func`.
    ///
    /// This is a proper backward dataflow fixpoint: `live_out[b] = ∪ live_in[s]`
    /// over successors `s` of `b`, and `live_in[b] = gen_set[b] ∪ (live_out[b] \ kill[b])`.
    /// A single backward pass over blocks (as opposed to a fixpoint) would miss
    /// variables that are live into a block only because of a successor's needs
    /// — e.g. a value defined in a predecessor block and used only in a
    /// successor block, with nothing referencing it in between.
    #[must_use]
    pub fn compute(
        func: &SsaFunction,
    ) -> std::collections::HashMap<u32, std::collections::HashSet<SsaRef>> {
        use std::collections::{HashMap, HashSet};

        // Per-block gen_set (upward-exposed uses) and kill (locally defined) sets.
        let mut gen_set: HashMap<u32, HashSet<SsaRef>> = HashMap::new();
        let mut kill: HashMap<u32, HashSet<SsaRef>> = HashMap::new();
        for block in &func.blocks {
            let mut g: HashSet<SsaRef> = HashSet::new();
            let mut k: HashSet<SsaRef> = HashSet::new();
            if let SsaTerm::Branch(cond, _, _) = &block.term
                && !k.contains(cond) {
                    g.insert(cond.clone());
                }
            if let SsaTerm::Return(Some(r)) = &block.term
                && !k.contains(r) {
                    g.insert(r.clone());
                }
            for instr in block.instrs.iter().rev() {
                if let Some(def) = &instr.def {
                    k.insert(def.clone());
                    g.remove(def);
                }
                for u in instr.expr.uses() {
                    if !k.contains(u) {
                        g.insert(u.clone());
                    }
                }
            }
            gen_set.insert(block.id, g);
            kill.insert(block.id, k);
        }

        let mut live_in: HashMap<u32, HashSet<SsaRef>> = func
            .blocks
            .iter()
            .map(|b| (b.id, HashSet::new()))
            .collect();
        let mut live_out: HashMap<u32, HashSet<SsaRef>> = func
            .blocks
            .iter()
            .map(|b| (b.id, HashSet::new()))
            .collect();

        // Iterate to a fixpoint (bounded by block count to guarantee
        // termination even on malformed/cyclic input).
        let max_iters = func.blocks.len().max(1) * 2 + 4;
        for _ in 0..max_iters {
            let mut changed = false;
            for block in &func.blocks {
                let mut out: HashSet<SsaRef> = HashSet::new();
                for succ in block.successors() {
                    if let Some(s_in) = live_in.get(&succ) {
                        out.extend(s_in.iter().cloned());
                    }
                }
                let k = &kill[&block.id];
                let g = &gen_set[&block.id];
                let mut inn: HashSet<SsaRef> = out.difference(k).cloned().collect();
                inn.extend(g.iter().cloned());

                if live_out[&block.id] != out {
                    live_out.insert(block.id, out);
                    changed = true;
                }
                if live_in[&block.id] != inn {
                    live_in.insert(block.id, inn);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        live_out
    }
}

// ---------------------------------------------------------------------------
// DeadCodeEliminator — removes unused SSA definitions
// ---------------------------------------------------------------------------

/// Removes SSA assignments whose defined variable is never used after
/// all optimization passes.
#[derive(Debug, Default)]
pub struct SsaDeadCodeEliminator {
    pub removed: usize,
}

impl SsaDeadCodeEliminator {
    /// Collect all referenced SSA variables across all blocks.
    fn collect_uses(func: &SsaFunction) -> std::collections::HashSet<SsaRef> {
        let mut uses = std::collections::HashSet::new();
        for block in &func.blocks {
            for instr in &block.instrs {
                for u in instr.expr.uses() {
                    uses.insert(u.clone());
                }
            }
            if let SsaTerm::Return(Some(r)) = &block.term {
                uses.insert(r.clone());
            }
            if let SsaTerm::Branch(c, _, _) = &block.term {
                uses.insert(c.clone());
            }
        }
        uses
    }

    /// Remove dead assignments from `func`.
    pub fn run(&mut self, func: &mut SsaFunction) {
        let uses = Self::collect_uses(func);
        for block in &mut func.blocks {
            let before = block.instrs.len();
            block.instrs.retain(|i| match &i.def {
                Some(def) if !i.expr.has_side_effects() => uses.contains(def),
                _ => true,
            });
            self.removed += before - block.instrs.len();
        }
    }
}

// ---------------------------------------------------------------------------
// ConstantMap — a convenience alias for the SCCP output
// ---------------------------------------------------------------------------

/// A mapping from SSA variables to their known constant values.
pub type ConstantMap = HashMap<SsaRef, ConstVal>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sref(name: &str, v: u32) -> SsaRef {
        SsaRef::new(name, v)
    }
    fn cint(v: i64) -> SsaExpr {
        SsaExpr::Const(ConstVal::Int(v))
    }
    fn cbool(v: bool) -> SsaExpr {
        SsaExpr::Const(ConstVal::Bool(v))
    }
    fn var_expr(name: &str, v: u32) -> SsaExpr {
        SsaExpr::Var(sref(name, v))
    }

    fn simple_func(entry_instrs: Vec<SsaInstr>, term: SsaTerm) -> SsaFunction {
        SsaFunction {
            name: "test".into(),
            blocks: vec![SsaBlock {
                id: 0,
                instrs: entry_instrs,
                term,
            }],
            entry: 0,
        }
    }

    // --- SsaRef ---

    #[test]
    fn ssa_ref_display() {
        let r = sref("x", 3);
        assert_eq!(format!("{r}"), "x#3");
    }

    #[test]
    fn ssa_ref_equality() {
        assert_eq!(sref("a", 1), sref("a", 1));
        assert_ne!(sref("a", 1), sref("a", 2));
    }

    // --- ScccLat::meet ---

    #[test]
    fn sccc_meet_top_with_const() {
        let l = ScccLat::meet(&ScccLat::Top, &ScccLat::Const(ConstVal::Int(5)));
        assert_eq!(l, ScccLat::Const(ConstVal::Int(5)));
    }

    #[test]
    fn sccc_meet_same_const() {
        let l = ScccLat::meet(
            &ScccLat::Const(ConstVal::Int(7)),
            &ScccLat::Const(ConstVal::Int(7)),
        );
        assert_eq!(l, ScccLat::Const(ConstVal::Int(7)));
    }

    #[test]
    fn sccc_meet_diff_const_is_bottom() {
        let l = ScccLat::meet(
            &ScccLat::Const(ConstVal::Int(1)),
            &ScccLat::Const(ConstVal::Int(2)),
        );
        assert_eq!(l, ScccLat::Bottom);
    }

    #[test]
    fn sccc_meet_bottom_absorbs() {
        let l = ScccLat::meet(&ScccLat::Bottom, &ScccLat::Const(ConstVal::Int(5)));
        assert_eq!(l, ScccLat::Bottom);
    }

    // --- SparseConditionalConst ---

    #[test]
    fn sccp_constant_def() {
        let mut f = simple_func(
            vec![SsaInstr::assign(sref("x", 1), cint(42))],
            SsaTerm::Return(Some(sref("x", 1))),
        );
        let mut pass = SparseConditionalConst::default();
        let consts = pass.run(&mut f);
        assert_eq!(consts.get(&sref("x", 1)), Some(&ConstVal::Int(42)));
    }

    #[test]
    fn sccp_add_two_consts() {
        let mut f = simple_func(
            vec![
                SsaInstr::assign(sref("a", 1), cint(3)),
                SsaInstr::assign(sref("b", 1), cint(7)),
                SsaInstr::assign(sref("c", 1), SsaExpr::Add(sref("a", 1), sref("b", 1))),
            ],
            SsaTerm::Return(Some(sref("c", 1))),
        );
        let mut pass = SparseConditionalConst::default();
        let consts = pass.run(&mut f);
        assert_eq!(consts.get(&sref("c", 1)), Some(&ConstVal::Int(10)));
    }

    #[test]
    fn sccp_propagates_across_multiple_user_blocks() {
        // block 0 defines x = 5 and jumps to block 1, which jumps to block 2.
        // Both block 1 and block 2 use x, exercising the use-index that
        // replaces the old O(blocks*instrs) rescan on every lattice update:
        // a def with multiple users spread across multiple blocks must still
        // get every one of those blocks re-queued and re-evaluated.
        let f = SsaFunction {
            name: "multi".into(),
            entry: 0,
            blocks: vec![
                SsaBlock {
                    id: 0,
                    instrs: vec![SsaInstr::assign(sref("x", 1), cint(5))],
                    term: SsaTerm::Jump(1),
                },
                SsaBlock {
                    id: 1,
                    instrs: vec![SsaInstr::assign(
                        sref("y", 1),
                        SsaExpr::Add(sref("x", 1), sref("x", 1)),
                    )],
                    term: SsaTerm::Jump(2),
                },
                SsaBlock {
                    id: 2,
                    instrs: vec![SsaInstr::assign(
                        sref("z", 1),
                        SsaExpr::Add(sref("x", 1), sref("y", 1)),
                    )],
                    term: SsaTerm::Return(Some(sref("z", 1))),
                },
            ],
        };
        let mut f = f;
        let mut pass = SparseConditionalConst::default();
        let consts = pass.run(&mut f);
        assert_eq!(consts.get(&sref("x", 1)), Some(&ConstVal::Int(5)));
        assert_eq!(consts.get(&sref("y", 1)), Some(&ConstVal::Int(10)));
        assert_eq!(consts.get(&sref("z", 1)), Some(&ConstVal::Int(15)));
    }

    #[test]
    fn sccp_empty_function() {
        let mut f = simple_func(vec![], SsaTerm::Return(None));
        let mut pass = SparseConditionalConst::default();
        let consts = pass.run(&mut f);
        assert!(consts.is_empty());
    }

    // --- GvnPass ---

    #[test]
    fn gvn_replaces_duplicate() {
        let mut f = simple_func(
            vec![
                SsaInstr::assign(sref("t1", 1), SsaExpr::Add(sref("a", 0), sref("b", 0))),
                SsaInstr::assign(sref("t2", 1), SsaExpr::Add(sref("a", 0), sref("b", 0))),
            ],
            SsaTerm::Return(Some(sref("t2", 1))),
        );
        let mut gvn = GvnPass::default();
        gvn.run(&mut f);
        assert!(gvn.stats.gvn_replacements > 0);
    }

    #[test]
    fn gvn_no_dup_no_replacement() {
        let mut f = simple_func(
            vec![
                SsaInstr::assign(sref("t1", 1), SsaExpr::Add(sref("a", 0), sref("b", 0))),
                SsaInstr::assign(sref("t2", 1), SsaExpr::Add(sref("a", 0), sref("c", 0))),
            ],
            SsaTerm::Return(None),
        );
        let mut gvn = GvnPass::default();
        gvn.run(&mut f);
        assert_eq!(gvn.stats.gvn_replacements, 0);
    }

    #[test]
    fn gvn_does_not_merge_across_sibling_branch_arms() {
        // Regression test (found by prop_soundness randomized testing,
        // minimized): both arms of a diamond compute the textually identical
        // expression `x + y`.  Neither arm dominates the other, so GVN must
        // NOT rewrite the second arm's phi input to reference the first
        // arm's def — on the path through the second arm, that variable is
        // never defined, and the join-block phi would read an undefined var.
        let x = sref("x", 0);
        let y = sref("y", 0);
        let mut entry = SsaBlock::new(0);
        entry.instrs.push(SsaInstr::assign(x.clone(), cint(1)));
        entry.instrs.push(SsaInstr::assign(y.clone(), cint(2)));
        entry
            .instrs
            .push(SsaInstr::assign(sref("c", 0), SsaExpr::Const(ConstVal::Unknown)));
        entry.term = SsaTerm::Branch(sref("c", 0), 1, 2);
        let mut arm_t = SsaBlock::new(1);
        arm_t.instrs.push(SsaInstr::assign(
            sref("a", 0),
            SsaExpr::Add(x.clone(), y.clone()),
        ));
        arm_t.term = SsaTerm::Jump(3);
        let mut arm_f = SsaBlock::new(2);
        arm_f.instrs.push(SsaInstr::assign(
            sref("b", 0),
            SsaExpr::Add(x.clone(), y.clone()),
        ));
        arm_f.term = SsaTerm::Jump(3);
        let mut join = SsaBlock::new(3);
        join.instrs.push(SsaInstr::assign(
            sref("p", 0),
            SsaExpr::Phi(vec![(1, sref("a", 0)), (2, sref("b", 0))]),
        ));
        join.term = SsaTerm::Return(Some(sref("p", 0)));
        let mut f = SsaFunction {
            name: "diamond".into(),
            blocks: vec![entry, arm_t, arm_f, join],
            entry: 0,
        };

        let mut gvn = GvnPass::default();
        gvn.run(&mut f);
        assert_eq!(
            gvn.stats.gvn_replacements, 0,
            "sibling arms must not be value-numbered together"
        );
        // The phi must still reference each arm's own definition.
        let join = f.block(3).unwrap();
        match &join.instrs[0].expr {
            SsaExpr::Phi(srcs) => {
                assert_eq!(srcs[0].1, sref("a", 0));
                assert_eq!(srcs[1].1, sref("b", 0));
            }
            other => panic!("expected phi, got {other:?}"),
        }
    }

    #[test]
    fn gvn_still_merges_when_def_dominates() {
        // Entry-block def dominates a successor block computing the same
        // expression — this merge is sound and must still happen.
        let x = sref("x", 0);
        let y = sref("y", 0);
        let mut b0 = SsaBlock::new(0);
        b0.instrs.push(SsaInstr::assign(x.clone(), cint(1)));
        b0.instrs.push(SsaInstr::assign(y.clone(), cint(2)));
        b0.instrs.push(SsaInstr::assign(
            sref("t1", 0),
            SsaExpr::Add(x.clone(), y.clone()),
        ));
        b0.term = SsaTerm::Jump(1);
        let mut b1 = SsaBlock::new(1);
        b1.instrs.push(SsaInstr::assign(
            sref("t2", 0),
            SsaExpr::Add(x.clone(), y.clone()),
        ));
        b1.term = SsaTerm::Return(Some(sref("t2", 0)));
        let mut f = SsaFunction {
            name: "chain".into(),
            blocks: vec![b0, b1],
            entry: 0,
        };
        let mut gvn = GvnPass::default();
        gvn.run(&mut f);
        assert_eq!(gvn.stats.gvn_replacements, 1);
    }

    // --- CopyFolding ---

    #[test]
    fn copy_folding_simple() {
        let mut f = simple_func(
            vec![
                SsaInstr::assign(sref("y", 1), var_expr("x", 0)),
                SsaInstr::assign(sref("z", 1), SsaExpr::Add(sref("y", 1), sref("y", 1))),
            ],
            SsaTerm::Return(Some(sref("z", 1))),
        );
        let mut cf = CopyFolding::default();
        cf.run(&mut f);
        assert!(cf.stats.copies_folded > 0);
    }

    #[test]
    fn copy_folding_branch_cond() {
        let mut f = SsaFunction {
            name: "t".into(),
            entry: 0,
            blocks: vec![SsaBlock {
                id: 0,
                instrs: vec![SsaInstr::assign(sref("c", 1), var_expr("flag", 0))],
                term: SsaTerm::Branch(sref("c", 1), 1, 2),
            }],
        };
        let mut cf = CopyFolding::default();
        cf.run(&mut f);
        // The branch condition should now be "flag#0" directly.
        if let SsaTerm::Branch(cond, _, _) = &f.blocks[0].term {
            assert_eq!(*cond, sref("flag", 0));
        }
    }

    // --- PhiElimination ---

    #[test]
    fn phi_elimination_removes_phi() {
        let mut f = SsaFunction {
            name: "t".into(),
            entry: 0,
            blocks: vec![
                SsaBlock {
                    id: 0,
                    instrs: vec![SsaInstr::assign(sref("x", 1), cint(1))],
                    term: SsaTerm::Jump(1),
                },
                SsaBlock {
                    id: 1,
                    instrs: vec![SsaInstr::assign(
                        sref("x", 2),
                        SsaExpr::Phi(vec![(0, sref("x", 1))]),
                    )],
                    term: SsaTerm::Return(Some(sref("x", 2))),
                },
            ],
        };
        let mut pe = PhiElimination::default();
        pe.run(&mut f);
        assert_eq!(pe.stats.phis_eliminated, 1);
        // Block 1 should have no Phi instruction.
        let b1 = f.block(1).unwrap();
        assert!(b1.instrs.iter().all(|i| !matches!(i.expr, SsaExpr::Phi(_))));
    }

    // --- BranchElimination ---

    #[test]
    fn branch_elim_true_branch() {
        let mut f = SsaFunction {
            name: "t".into(),
            entry: 0,
            blocks: vec![SsaBlock {
                id: 0,
                instrs: vec![],
                term: SsaTerm::Branch(sref("c", 1), 1, 2),
            }],
        };
        let mut consts = HashMap::new();
        consts.insert(sref("c", 1), ConstVal::Bool(true));
        let mut be = BranchElimination::default();
        be.run(&mut f, &consts);
        assert!(matches!(f.blocks[0].term, SsaTerm::Jump(1)));
        assert_eq!(be.stats.branches_removed, 1);
    }

    #[test]
    fn branch_elim_false_branch() {
        let mut f = SsaFunction {
            name: "t".into(),
            entry: 0,
            blocks: vec![SsaBlock {
                id: 0,
                instrs: vec![],
                term: SsaTerm::Branch(sref("c", 1), 10, 20),
            }],
        };
        let mut consts = HashMap::new();
        consts.insert(sref("c", 1), ConstVal::Bool(false));
        let mut be = BranchElimination::default();
        be.run(&mut f, &consts);
        assert!(matches!(f.blocks[0].term, SsaTerm::Jump(20)));
    }

    #[test]
    fn branch_elim_no_constant_unchanged() {
        let mut f = SsaFunction {
            name: "t".into(),
            entry: 0,
            blocks: vec![SsaBlock {
                id: 0,
                instrs: vec![],
                term: SsaTerm::Branch(sref("c", 1), 10, 20),
            }],
        };
        let consts = HashMap::new();
        let mut be = BranchElimination::default();
        be.run(&mut f, &consts);
        assert_eq!(be.stats.branches_removed, 0);
    }

    // --- SsaFunction helpers ---

    #[test]
    fn ssa_function_predecessors() {
        let f = SsaFunction {
            name: "t".into(),
            entry: 0,
            blocks: vec![
                SsaBlock {
                    id: 0,
                    instrs: vec![],
                    term: SsaTerm::Jump(1),
                },
                SsaBlock {
                    id: 1,
                    instrs: vec![],
                    term: SsaTerm::Return(None),
                },
            ],
        };
        let preds = f.predecessors();
        assert!(preds[&1].contains(&0));
    }

    #[test]
    fn ssa_block_successors() {
        let b = SsaBlock {
            id: 0,
            instrs: vec![],
            term: SsaTerm::Branch(sref("c", 0), 1, 2),
        };
        let succs = b.successors();
        assert!(succs.contains(&1));
        assert!(succs.contains(&2));
    }

    // --- SsaOptimizer ---

    #[test]
    fn optimizer_full_pipeline() {
        let mut f = simple_func(
            vec![
                SsaInstr::assign(sref("k", 1), cint(3)),
                SsaInstr::assign(sref("x", 1), cint(5)),
                SsaInstr::assign(sref("y", 1), SsaExpr::Add(sref("x", 1), sref("k", 1))),
            ],
            SsaTerm::Return(Some(sref("y", 1))),
        );
        let mut opt = SsaOptimizer::default();
        opt.optimize(&mut f);
        // After SCCP, y#1 should be a constant 8.
    }

    #[test]
    fn optimizer_stats_default_zero() {
        let s = SsaOptStats::default();
        assert_eq!(s.total(), 0);
    }

    #[test]
    fn ssa_expr_uses_add() {
        let e = SsaExpr::Add(sref("a", 1), sref("b", 2));
        let uses = e.uses();
        assert_eq!(uses.len(), 2);
    }

    #[test]
    fn ssa_expr_has_side_effects_call() {
        let e = SsaExpr::Call {
            name: "foo".into(),
            args: vec![],
        };
        assert!(e.has_side_effects());
    }

    #[test]
    fn ssa_expr_no_side_effects_add() {
        let e = SsaExpr::Add(sref("a", 1), sref("b", 1));
        assert!(!e.has_side_effects());
    }

    #[test]
    fn const_val_is_known() {
        assert!(ConstVal::Int(1).is_known());
        assert!(ConstVal::Bool(false).is_known());
        assert!(!ConstVal::Unknown.is_known());
    }

    // --- Additional SCCP tests ---

    #[test]
    fn sccp_sub_consts() {
        let mut f = simple_func(
            vec![
                SsaInstr::assign(sref("a", 1), cint(10)),
                SsaInstr::assign(sref("b", 1), cint(3)),
                SsaInstr::assign(sref("c", 1), SsaExpr::Sub(sref("a", 1), sref("b", 1))),
            ],
            SsaTerm::Return(Some(sref("c", 1))),
        );
        let mut pass = SparseConditionalConst::default();
        let consts = pass.run(&mut f);
        assert_eq!(consts.get(&sref("c", 1)), Some(&ConstVal::Int(7)));
    }

    #[test]
    fn sccp_mul_consts() {
        let mut f = simple_func(
            vec![
                SsaInstr::assign(sref("x", 1), cint(6)),
                SsaInstr::assign(sref("y", 1), cint(7)),
                SsaInstr::assign(sref("z", 1), SsaExpr::Mul(sref("x", 1), sref("y", 1))),
            ],
            SsaTerm::Return(Some(sref("z", 1))),
        );
        let mut pass = SparseConditionalConst::default();
        let consts = pass.run(&mut f);
        assert_eq!(consts.get(&sref("z", 1)), Some(&ConstVal::Int(42)));
    }

    #[test]
    fn sccp_cmpeq_same_const() {
        let mut f = simple_func(
            vec![
                SsaInstr::assign(sref("a", 1), cint(5)),
                SsaInstr::assign(sref("b", 1), cint(5)),
                SsaInstr::assign(sref("eq", 1), SsaExpr::CmpEq(sref("a", 1), sref("b", 1))),
            ],
            SsaTerm::Return(Some(sref("eq", 1))),
        );
        let mut pass = SparseConditionalConst::default();
        let consts = pass.run(&mut f);
        assert_eq!(consts.get(&sref("eq", 1)), Some(&ConstVal::Bool(true)));
    }

    #[test]
    fn sccp_cmplt_consts() {
        let mut f = simple_func(
            vec![
                SsaInstr::assign(sref("a", 1), cint(2)),
                SsaInstr::assign(sref("b", 1), cint(5)),
                SsaInstr::assign(sref("lt", 1), SsaExpr::CmpLt(sref("a", 1), sref("b", 1))),
            ],
            SsaTerm::Return(Some(sref("lt", 1))),
        );
        let mut pass = SparseConditionalConst::default();
        let consts = pass.run(&mut f);
        assert_eq!(consts.get(&sref("lt", 1)), Some(&ConstVal::Bool(true)));
    }

    // --- GVN additional ---

    #[test]
    fn gvn_call_not_deduped() {
        let mut f = simple_func(
            vec![
                SsaInstr::assign(
                    sref("r1", 1),
                    SsaExpr::Call {
                        name: "rand".into(),
                        args: vec![],
                    },
                ),
                SsaInstr::assign(
                    sref("r2", 1),
                    SsaExpr::Call {
                        name: "rand".into(),
                        args: vec![],
                    },
                ),
            ],
            SsaTerm::Return(None),
        );
        let mut gvn = GvnPass::default();
        gvn.run(&mut f);
        // Calls have side effects, must NOT be deduplicated.
        assert_eq!(gvn.stats.gvn_replacements, 0);
    }

    // --- SsaOptStats ---

    #[test]
    fn ssa_opt_stats_total() {
        let s = SsaOptStats {
            const_propagated: 3,
            copies_folded: 2,
            phis_eliminated: 1,
            branches_removed: 4,
            gvn_replacements: 5,
            dead_defs_removed: 0,
        };
        assert_eq!(s.total(), 15);
    }

    // --- SsaRef ordering ---

    #[test]
    fn ssa_ref_ordering() {
        let a = sref("a", 1);
        let b = sref("b", 1);
        assert!(a < b);
    }

    // --- SsaBlock ---

    #[test]
    fn ssa_block_return_no_successors() {
        let b = SsaBlock {
            id: 0,
            instrs: vec![],
            term: SsaTerm::Return(None),
        };
        assert!(b.successors().is_empty());
    }

    #[test]
    fn ssa_block_unreachable_no_successors() {
        let b = SsaBlock {
            id: 0,
            instrs: vec![],
            term: SsaTerm::Unreachable,
        };
        assert!(b.successors().is_empty());
    }

    #[test]
    fn ssa_block_jump_single_successor() {
        let b = SsaBlock {
            id: 0,
            instrs: vec![],
            term: SsaTerm::Jump(42),
        };
        assert_eq!(b.successors(), vec![42]);
    }

    // --- PhiElimination with no phis ---

    #[test]
    fn phi_elim_no_phis_unchanged() {
        let mut f = simple_func(
            vec![SsaInstr::assign(sref("x", 1), cint(1))],
            SsaTerm::Return(Some(sref("x", 1))),
        );
        let mut pe = PhiElimination::default();
        pe.run(&mut f);
        assert_eq!(pe.stats.phis_eliminated, 0);
    }

    // --- CopyFolding no-op ---

    #[test]
    fn copy_folding_no_copies_unchanged() {
        let mut f = simple_func(
            vec![SsaInstr::assign(sref("x", 1), cint(7))],
            SsaTerm::Return(Some(sref("x", 1))),
        );
        let mut cf = CopyFolding::default();
        cf.run(&mut f);
        assert_eq!(cf.stats.copies_folded, 0);
    }

    // --- SsaExpr uses coverage ---

    #[test]
    fn ssa_expr_uses_phi() {
        let e = SsaExpr::Phi(vec![(0, sref("a", 1)), (1, sref("b", 1))]);
        let uses = e.uses();
        assert_eq!(uses.len(), 2);
    }

    #[test]
    fn ssa_expr_uses_call_with_args() {
        let e = SsaExpr::Call {
            name: "foo".into(),
            args: vec![sref("x", 1), sref("y", 1)],
        };
        let uses = e.uses();
        assert_eq!(uses.len(), 2);
    }

    #[test]
    fn ssa_expr_uses_neg() {
        let e = SsaExpr::Neg(sref("x", 1));
        assert_eq!(e.uses().len(), 1);
    }

    #[test]
    fn ssa_expr_uses_const_empty() {
        let e = SsaExpr::Const(ConstVal::Int(0));
        assert!(e.uses().is_empty());
    }

    // --- SsaFunctionBuilder tests ---

    #[test]
    fn builder_creates_function() {
        let f = SsaFunctionBuilder::new("my_func")
            .entry(0)
            .block(SsaBlock {
                id: 0,
                instrs: vec![],
                term: SsaTerm::Return(None),
            })
            .build();
        assert_eq!(f.name, "my_func");
        assert_eq!(f.entry, 0);
        assert_eq!(f.blocks.len(), 1);
    }

    #[test]
    fn builder_default_entry_zero() {
        let f = SsaFunctionBuilder::new("f").build();
        assert_eq!(f.entry, 0);
    }

    // --- SsaVerifier tests ---

    #[test]
    fn verifier_valid_function() {
        let f = simple_func(
            vec![SsaInstr::assign(sref("x", 1), cint(5))],
            SsaTerm::Return(Some(sref("x", 1))),
        );
        let issues = SsaVerifier::verify(&f);
        assert!(issues.is_empty());
    }

    #[test]
    fn verifier_duplicate_def() {
        let f = simple_func(
            vec![
                SsaInstr::assign(sref("x", 1), cint(1)),
                SsaInstr::assign(sref("x", 1), cint(2)), // duplicate
            ],
            SsaTerm::Return(None),
        );
        let issues = SsaVerifier::verify(&f);
        assert!(!issues.is_empty());
    }

    #[test]
    fn verifier_use_without_def() {
        let f = simple_func(
            vec![SsaInstr::assign(
                sref("y", 1),
                SsaExpr::Add(sref("x", 1), sref("z", 1)),
            )],
            SsaTerm::Return(None),
        );
        // x#1 is used but not defined → issue
        let issues = SsaVerifier::verify(&f);
        assert!(!issues.is_empty());
    }

    // --- LivenessAnalysis tests ---

    #[test]
    fn liveness_single_block() {
        let f = simple_func(
            vec![SsaInstr::assign(sref("x", 1), cint(1))],
            SsaTerm::Return(Some(sref("x", 1))),
        );
        let live = LivenessAnalysis::compute(&f);
        assert!(live.contains_key(&0));
    }

    #[test]
    fn liveness_empty_function() {
        let f = simple_func(vec![], SsaTerm::Return(None));
        let live = LivenessAnalysis::compute(&f);
        assert!(live.contains_key(&0));
    }

    #[test]
    fn liveness_propagates_across_blocks() {
        // block0: x#1 = 1; jump to block1.
        // block1: return x#1.
        // x#1 must be live-out of block0 even though block0 itself never
        // uses it — it's needed by the successor.
        let f = SsaFunction {
            name: "t".into(),
            entry: 0,
            blocks: vec![
                SsaBlock {
                    id: 0,
                    instrs: vec![SsaInstr::assign(sref("x", 1), cint(1))],
                    term: SsaTerm::Jump(1),
                },
                SsaBlock {
                    id: 1,
                    instrs: vec![],
                    term: SsaTerm::Return(Some(sref("x", 1))),
                },
            ],
        };
        let live_out = LivenessAnalysis::compute(&f);
        assert!(
            live_out[&0].contains(&sref("x", 1)),
            "x#1 should be live-out of block0 (needed by block1): {live_out:?}"
        );
        // block1 has no successors, so live-out of block1 is empty.
        assert!(live_out[&1].is_empty());
    }

    #[test]
    fn liveness_dead_var_not_propagated() {
        // block0 defines y#1 which nothing ever uses.
        let f = SsaFunction {
            name: "t".into(),
            entry: 0,
            blocks: vec![
                SsaBlock {
                    id: 0,
                    instrs: vec![SsaInstr::assign(sref("y", 1), cint(1))],
                    term: SsaTerm::Jump(1),
                },
                SsaBlock {
                    id: 1,
                    instrs: vec![],
                    term: SsaTerm::Return(None),
                },
            ],
        };
        let live_out = LivenessAnalysis::compute(&f);
        assert!(!live_out[&0].contains(&sref("y", 1)));
    }

    // --- SsaFunctionPrinter ---

    #[test]
    fn printer_dumps_function_text() {
        let f = simple_func(
            vec![SsaInstr::assign(sref("x", 1), cint(5))],
            SsaTerm::Return(Some(sref("x", 1))),
        );
        let text = SsaFunctionPrinter::print(&f);
        assert!(text.contains("fn test"));
        assert!(text.contains("bb0"));
        assert!(text.contains("return x#1"));
    }

    #[test]
    fn printer_dumps_branch_and_jump_terms() {
        let f = SsaFunction {
            name: "t".into(),
            entry: 0,
            blocks: vec![
                SsaBlock {
                    id: 0,
                    instrs: vec![],
                    term: SsaTerm::Branch(sref("c", 1), 1, 2),
                },
                SsaBlock {
                    id: 1,
                    instrs: vec![],
                    term: SsaTerm::Jump(2),
                },
                SsaBlock {
                    id: 2,
                    instrs: vec![],
                    term: SsaTerm::Unreachable,
                },
            ],
        };
        let text = SsaFunctionPrinter::print(&f);
        assert!(text.contains("if c#1 goto bb1 else bb2"));
        assert!(text.contains("goto bb2"));
        assert!(text.contains("unreachable"));
    }

    // --- PhiNode::defined_arg_count (via ssa module re-export style test) ---

    #[test]
    fn ssa_opt_config_default_is_full() {
        let cfg = SsaOptConfig::default();
        assert_eq!(cfg.level, SsaOptLevel::Full);
        assert_eq!(cfg.max_iterations, 20);
    }

    #[test]
    fn ssa_opt_level_default_is_full() {
        assert_eq!(SsaOptLevel::default(), SsaOptLevel::Full);
    }

    // --- SsaOptimizer stats after no-op ---

    #[test]
    fn optimizer_no_changes_zero_stats() {
        let mut f = simple_func(vec![], SsaTerm::Return(None));
        let mut opt = SsaOptimizer::default();
        opt.optimize(&mut f);
        assert_eq!(opt.stats.branches_removed, 0);
    }

    // --- SsaBlock::new helper ---

    #[test]
    fn ssa_block_new() {
        let b = SsaBlock::new(42);
        assert_eq!(b.id, 42);
        assert!(b.instrs.is_empty());
    }

    // --- SsaFunction block lookup ---

    #[test]
    fn ssa_function_block_lookup() {
        let f = SsaFunction {
            name: "t".into(),
            entry: 0,
            blocks: vec![SsaBlock::new(0), SsaBlock::new(1)],
        };
        assert!(f.block(0).is_some());
        assert!(f.block(99).is_none());
    }

    #[test]
    fn ssa_function_block_mut() {
        let mut f = SsaFunction {
            name: "t".into(),
            entry: 0,
            blocks: vec![SsaBlock::new(0)],
        };
        let b = f.block_mut(0).unwrap();
        b.instrs.push(SsaInstr::assign(sref("x", 1), cint(42)));
        assert_eq!(f.blocks[0].instrs.len(), 1);
    }

    // --- SsaDeadCodeEliminator tests ---

    #[test]
    fn dce_removes_unused_def() {
        let mut f = simple_func(
            vec![
                SsaInstr::assign(sref("dead", 1), cint(99)), // unused
                SsaInstr::assign(sref("live", 1), cint(1)),
            ],
            SsaTerm::Return(Some(sref("live", 1))),
        );
        let mut dce = SsaDeadCodeEliminator::default();
        dce.run(&mut f);
        assert!(dce.removed > 0);
    }

    #[test]
    fn dce_keeps_used_def() {
        let mut f = simple_func(
            vec![SsaInstr::assign(sref("x", 1), cint(5))],
            SsaTerm::Return(Some(sref("x", 1))),
        );
        let before = f.blocks[0].instrs.len();
        let mut dce = SsaDeadCodeEliminator::default();
        dce.run(&mut f);
        assert_eq!(f.blocks[0].instrs.len(), before);
    }

    #[test]
    fn dce_keeps_calls_despite_unused_def() {
        let mut f = simple_func(
            vec![SsaInstr::assign(
                sref("r", 1),
                SsaExpr::Call {
                    name: "side_effect".into(),
                    args: vec![],
                },
            )],
            SsaTerm::Return(None),
        );
        let before = f.blocks[0].instrs.len();
        let mut dce = SsaDeadCodeEliminator::default();
        dce.run(&mut f);
        assert_eq!(f.blocks[0].instrs.len(), before);
    }

    // --- ConstantMap type alias ---

    #[test]
    fn constant_map_insert_get() {
        let mut m: ConstantMap = ConstantMap::new();
        m.insert(sref("x", 1), ConstVal::Int(42));
        assert_eq!(m.get(&sref("x", 1)), Some(&ConstVal::Int(42)));
    }

    // --- SsaOptimizer comprehensive ---

    #[test]
    fn optimizer_sccp_then_branch_elim() {
        let mut f = SsaFunction {
            name: "t".into(),
            entry: 0,
            blocks: vec![
                SsaBlock {
                    id: 0,
                    instrs: vec![SsaInstr::assign(sref("c", 1), cbool(true))],
                    term: SsaTerm::Branch(sref("c", 1), 1, 2),
                },
                SsaBlock {
                    id: 1,
                    instrs: vec![],
                    term: SsaTerm::Return(None),
                },
                SsaBlock {
                    id: 2,
                    instrs: vec![],
                    term: SsaTerm::Return(None),
                },
            ],
        };
        let mut opt = SsaOptimizer::default();
        opt.optimize(&mut f);
        // Branch to block 2 should be eliminated since c is always true.
        assert!(matches!(f.blocks[0].term, SsaTerm::Jump(1)));
    }
}
