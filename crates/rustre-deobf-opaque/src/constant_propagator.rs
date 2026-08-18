//! `constant_propagator.rs` — Lattice-based constant propagation for opaque predicate resolution.
//!
//! Implements a forward dataflow constant propagation analysis over a simplified
//! IR: lattice (bottom/constant/top), phi node handling, arithmetic/logical/comparison
//! folding, and invariant condition detection.

use std::collections::{HashMap, VecDeque};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// ConstLattice — three-point lattice for constant analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Three-point constant lattice element.
///
/// - `Bottom` (⊥): not yet analysed / unreachable.
/// - `Const(c)`: known constant value `c`.
/// - `Top` (⊤): value is not constant (varies at runtime).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstLattice {
    /// Not yet reached or initialised.
    Bottom,
    /// Known constant integer value.
    Const(i64),
    /// Non-constant (multiple possible values).
    Top,
}

impl ConstLattice {
    /// Return `true` if this element is `Const`.
    #[must_use]
    pub const fn is_const(self) -> bool { matches!(self, Self::Const(_)) }

    /// Extract the constant value, if any.
    #[must_use]
    pub const fn as_i64(self) -> Option<i64> {
        if let Self::Const(c) = self { Some(c) } else { None }
    }

    /// Lattice join (least upper bound).
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => x,
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Const(a), Self::Const(b)) => {
                if a == b { Self::Const(a) } else { Self::Top }
            }
        }
    }

    /// Lattice meet (greatest lower bound).
    #[must_use]
    pub const fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Top, x) | (x, Self::Top) => x,
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Const(a), Self::Const(b)) => {
                if a == b { Self::Const(a) } else { Self::Bottom }
            }
        }
    }

    /// Whether this element is strictly "less than" `other` in the lattice order.
    #[must_use]
    pub fn is_less_than(self, other: Self) -> bool {
        self.join(other) == other && self != other
    }
}

impl fmt::Display for ConstLattice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bottom => write!(f, "⊥"),
            Self::Const(c) => write!(f, "{c}"),
            Self::Top => write!(f, "⊤"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IR value types for the propagation pass
// ─────────────────────────────────────────────────────────────────────────────

/// An SSA-like variable id.
pub type VarId = u32;

/// Simple IR instruction.
#[derive(Debug, Clone)]
pub enum IrInstr {
    /// `dst = const c`
    Const { dst: VarId, value: i64 },
    /// `dst = phi(src1, src2, ...)`
    Phi { dst: VarId, srcs: Vec<VarId> },
    /// `dst = src1 op src2`
    BinOp { dst: VarId, op: BinOpKind, lhs: VarId, rhs: VarId },
    /// `dst = op src`
    UnOp { dst: VarId, op: UnOpKind, src: VarId },
    /// `dst = cmp(lhs, op, rhs)` — produces 0 or 1.
    Cmp { dst: VarId, op: CmpKind, lhs: VarId, rhs: VarId },
    /// Conditional branch: `if cond goto true_block else false_block`.
    CondBr { cond: VarId, true_block: u32, false_block: u32 },
    /// Unconditional branch.
    Jump { target: u32 },
    /// Return.
    Ret,
}

/// Binary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOpKind {
    Add, Sub, Mul, Div, Mod, And, Or, Xor, Shl, Shr,
}

impl fmt::Display for BinOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Add => "+", Self::Sub => "-", Self::Mul => "*",
            Self::Div => "/", Self::Mod => "%", Self::And => "&",
            Self::Or => "|", Self::Xor => "^", Self::Shl => "<<", Self::Shr => ">>",
        };
        write!(f, "{s}")
    }
}

/// Unary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOpKind { Neg, Not, Abs, PopCnt }

/// Comparison operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpKind { Eq, Ne, Lt, Le, Gt, Ge }

impl CmpKind {
    const fn eval(self, a: i64, b: i64) -> bool {
        match self {
            Self::Eq => a == b, Self::Ne => a != b,
            Self::Lt => a < b,  Self::Le => a <= b,
            Self::Gt => a > b,  Self::Ge => a >= b,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FoldResult — outcome of folding a single instruction
// ─────────────────────────────────────────────────────────────────────────────

/// Result of constant-folding a single IR instruction.
#[derive(Debug, Clone)]
pub enum FoldResult {
    /// Instruction was folded to a constant.
    Folded(i64),
    /// Instruction could not be folded (non-constant operands).
    NotFolded,
    /// Division by zero encountered.
    DivByZero,
    /// Instruction has no value (branch, ret).
    NoValue,
}

// ─────────────────────────────────────────────────────────────────────────────
// InvariantCond — a branch condition proven invariant
// ─────────────────────────────────────────────────────────────────────────────

/// A conditional branch whose condition was proven constant by the propagation pass.
#[derive(Debug, Clone)]
pub struct InvariantCond {
    /// Block index containing the branch.
    pub block_idx: u32,
    /// The condition variable.
    pub cond_var: VarId,
    /// The constant value (0 or 1).
    pub const_value: i64,
    /// True if the true-branch is always taken.
    pub always_true: bool,
    /// True if the false-branch is always taken.
    pub always_false: bool,
    /// Address hint for the containing branch instruction (if available).
    pub address_hint: Option<u64>,
}

impl InvariantCond {
    #[must_use]
    pub const fn is_opaque_true(&self)  -> bool { self.always_true }
    #[must_use]
    pub const fn is_opaque_false(&self) -> bool { self.always_false }
}

impl fmt::Display for InvariantCond {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = if self.always_true { "AlwaysTrue" } else { "AlwaysFalse" };
        write!(f, "InvariantCond @ block {} cond=v{} {}", self.block_idx, self.cond_var, tag)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Basic block abstraction
// ─────────────────────────────────────────────────────────────────────────────

/// A basic block in the IR.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Block index.
    pub id: u32,
    /// Instructions in this block.
    pub instrs: Vec<IrInstr>,
    /// Predecessor block ids.
    pub preds: Vec<u32>,
    /// Successor block ids.
    pub succs: Vec<u32>,
    /// Optional address hint for the block entry.
    pub address: Option<u64>,
}

impl BasicBlock {
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self { id, instrs: Vec::new(), preds: Vec::new(), succs: Vec::new(), address: None }
    }

    pub fn add_instr(&mut self, instr: IrInstr) {
        self.instrs.push(instr);
    }

    #[must_use]
    pub const fn with_address(mut self, addr: u64) -> Self { self.address = Some(addr); self }
}

// ─────────────────────────────────────────────────────────────────────────────
// PropState — per-block propagation state
// ─────────────────────────────────────────────────────────────────────────────

/// Propagation state: a mapping from variable id to lattice element.
#[derive(Debug, Clone, PartialEq)]
pub struct PropState {
    pub values: HashMap<VarId, ConstLattice>,
}

impl PropState {
    #[must_use]
    pub fn new() -> Self { Self { values: HashMap::new() } }

    #[must_use]
    pub fn get(&self, v: VarId) -> ConstLattice {
        self.values.get(&v).copied().unwrap_or(ConstLattice::Bottom)
    }

    pub fn set(&mut self, v: VarId, l: ConstLattice) {
        self.values.insert(v, l);
    }

    /// Join another state into this one (in-place). Returns true if anything changed.
    pub fn join_with(&mut self, other: &Self) -> bool {
        let mut changed = false;
        for (&var, &other_lat) in &other.values {
            let cur = self.get(var);
            let joined = cur.join(other_lat);
            if joined != cur {
                self.values.insert(var, joined);
                changed = true;
            }
        }
        changed
    }

    /// Number of known-constant variables.
    #[must_use]
    pub fn const_count(&self) -> usize {
        self.values.values().filter(|v| v.is_const()).count()
    }
}

impl Default for PropState {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstPropPass — the main analysis pass
// ─────────────────────────────────────────────────────────────────────────────

/// Constant propagation pass over a CFG.
///
/// Implements a worklist-based forward dataflow analysis.
/// Phi nodes are handled by joining lattice values from all predecessor states.
pub struct ConstPropPass {
    /// Initial values for function parameters / globals.
    pub initial_values: HashMap<VarId, ConstLattice>,
    /// Maximum number of worklist iterations (cycle guard).
    pub max_iterations: usize,
}

impl ConstPropPass {
    #[must_use]
    pub fn new() -> Self {
        Self { initial_values: HashMap::new(), max_iterations: 1000 }
    }

    #[must_use]
    pub fn with_initial(mut self, var: VarId, val: i64) -> Self {
        self.initial_values.insert(var, ConstLattice::Const(val));
        self
    }

    #[must_use]
    pub const fn with_max_iterations(mut self, n: usize) -> Self {
        self.max_iterations = n;
        self
    }

    /// Run the constant propagation pass over `blocks`.
    /// Returns per-block exit states and any invariant conditions detected.
    #[must_use]
    pub fn run(&self, blocks: &[BasicBlock]) -> ConstPropResult {
        if blocks.is_empty() {
            return ConstPropResult::empty();
        }

        let n = blocks.len();
        // Map block id to index.
        let id_to_idx: HashMap<u32, usize> = blocks.iter().enumerate()
            .map(|(i, b)| (b.id, i))
            .collect();

        // Initialise entry state for block 0.
        let mut exit_states: Vec<PropState> = vec![PropState::new(); n];
        let mut entry_states: Vec<PropState> = vec![PropState::new(); n];

        // Seed entry state with initial values.
        for (&var, &val) in &self.initial_values {
            entry_states[0].set(var, val);
        }

        // Worklist: process blocks in order initially.
        let mut worklist: VecDeque<usize> = (0..n).collect();
        let mut in_worklist: Vec<bool> = vec![true; n];
        let mut iterations = 0usize;

        while let Some(idx) = worklist.pop_front() {
            in_worklist[idx] = false;
            iterations += 1;
            if iterations > self.max_iterations { break; }

            let block = &blocks[idx];

            // Compute entry state = join of all predecessor exit states.
            let mut entry = entry_states[idx].clone();
            for &pred_id in &block.preds {
                if let Some(&pred_idx) = id_to_idx.get(&pred_id) {
                    entry.join_with(&exit_states[pred_idx]);
                }
            }
            entry_states[idx] = entry.clone();

            // Execute the block instructions.
            let mut state = entry;
            for instr in &block.instrs {
                self.transfer_instr(instr, &mut state);
            }

            // If exit state changed, re-add successors to worklist.
            if state != exit_states[idx] {
                exit_states[idx] = state;
                for &succ_id in &block.succs {
                    if let Some(&succ_idx) = id_to_idx.get(&succ_id) {
                        if !in_worklist[succ_idx] {
                            worklist.push_back(succ_idx);
                            in_worklist[succ_idx] = true;
                        }
                    }
                }
            }
        }

        // Detect invariant conditions.
        let mut invariants: Vec<InvariantCond> = Vec::new();
        for (idx, block) in blocks.iter().enumerate() {
            let state = &exit_states[idx];
            for instr in &block.instrs {
                if let IrInstr::CondBr { cond, true_block: _, false_block: _ } = instr {
                    if let ConstLattice::Const(c) = state.get(*cond) {
                        invariants.push(InvariantCond {
                            block_idx: block.id,
                            cond_var: *cond,
                            const_value: c,
                            always_true: c != 0,
                            always_false: c == 0,
                            address_hint: block.address,
                        });
                    }
                }
            }
        }

        let blocks_reached = blocks.iter().enumerate()
            .filter(|&(i, _)| !exit_states[i].values.is_empty())
            .count();

        ConstPropResult {
            exit_states,
            entry_states,
            invariant_conds: invariants,
            iterations,
            blocks_reached,
        }
    }

    /// Transfer function for a single instruction.
    fn transfer_instr(&self, instr: &IrInstr, state: &mut PropState) {
        match instr {
            IrInstr::Const { dst, value } => {
                state.set(*dst, ConstLattice::Const(*value));
            }
            IrInstr::Phi { dst, srcs } => {
                let joined = srcs.iter().fold(ConstLattice::Bottom, |acc, &v| {
                    acc.join(state.get(v))
                });
                state.set(*dst, joined);
            }
            IrInstr::BinOp { dst, op, lhs, rhs } => {
                let result = self.fold_binop(*op, state.get(*lhs), state.get(*rhs));
                state.set(*dst, result);
            }
            IrInstr::UnOp { dst, op, src } => {
                let result = self.fold_unop(*op, state.get(*src));
                state.set(*dst, result);
            }
            IrInstr::Cmp { dst, op, lhs, rhs } => {
                let result = self.fold_cmp(*op, state.get(*lhs), state.get(*rhs), lhs == rhs);
                state.set(*dst, result);
            }
            IrInstr::CondBr { .. } | IrInstr::Jump { .. } | IrInstr::Ret => {}
        }
    }

    fn fold_binop(&self, op: BinOpKind, lhs: ConstLattice, rhs: ConstLattice) -> ConstLattice {
        match (lhs, rhs) {
            (ConstLattice::Bottom, _) | (_, ConstLattice::Bottom) => ConstLattice::Bottom,
            (ConstLattice::Const(a), ConstLattice::Const(b)) => {
                let result = match op {
                    BinOpKind::Add => Some(a.wrapping_add(b)),
                    BinOpKind::Sub => Some(a.wrapping_sub(b)),
                    BinOpKind::Mul => Some(a.wrapping_mul(b)),
                    BinOpKind::Div => if b == 0 { None } else { Some(a.wrapping_div(b)) },
                    BinOpKind::Mod => if b == 0 { None } else { Some(a.wrapping_rem(b)) },
                    BinOpKind::And => Some(a & b),
                    BinOpKind::Or  => Some(a | b),
                    BinOpKind::Xor => Some(a ^ b),
                    BinOpKind::Shl => {
                        if b < 0 || b >= 64 { None } else { Some(a.wrapping_shl(b as u32)) }
                    }
                    BinOpKind::Shr => {
                        if b < 0 || b >= 64 { None } else { Some(a.wrapping_shr(b as u32)) }
                    }
                };
                result.map_or(ConstLattice::Top, ConstLattice::Const)
            }
            // Identities that allow partial evaluation:
            (ConstLattice::Const(0), _) if op == BinOpKind::Mul => ConstLattice::Const(0),
            (_, ConstLattice::Const(0)) if op == BinOpKind::Mul => ConstLattice::Const(0),
            (ConstLattice::Const(0), _) if op == BinOpKind::And => ConstLattice::Const(0),
            (_, ConstLattice::Const(0)) if op == BinOpKind::And => ConstLattice::Const(0),
            (ConstLattice::Const(-1), _) if op == BinOpKind::Or => ConstLattice::Const(-1),
            (_, ConstLattice::Const(-1)) if op == BinOpKind::Or => ConstLattice::Const(-1),
            _ => ConstLattice::Top,
        }
    }

    fn fold_unop(&self, op: UnOpKind, src: ConstLattice) -> ConstLattice {
        match src {
            ConstLattice::Bottom => ConstLattice::Bottom,
            ConstLattice::Const(c) => {
                match op {
                    UnOpKind::Neg => ConstLattice::Const(c.wrapping_neg()),
                    UnOpKind::Not => ConstLattice::Const(!c),
                    // Use checked_abs: for i64::MIN, wrapping_abs() returns i64::MIN
                    // (negative), which is incorrect. Treat i64::MIN abs as Top (unknown).
                    UnOpKind::Abs => c.checked_abs().map_or(ConstLattice::Top, ConstLattice::Const),
                    UnOpKind::PopCnt => ConstLattice::Const(i64::from(c.count_ones())),
                }
            }
            ConstLattice::Top => ConstLattice::Top,
        }
    }

    /// Fold a comparison.
    ///
    /// `same_var` says whether the two operands are the SAME variable, which is
    /// what makes `x == x` true whatever `x` holds. It has to be passed in:
    /// the guard used to read `lhs == rhs` on the LATTICE VALUES, and two
    /// DISTINCT unknown variables are both `Top` and therefore equal as values
    /// — so `Eq` folded to 1, asserting that two unrelated unknowns are the
    /// same number. The identity of the operands simply does not survive into
    /// the lattice, and cannot be recovered from it.
    fn fold_cmp(
        &self,
        op: CmpKind,
        lhs: ConstLattice,
        rhs: ConstLattice,
        same_var: bool,
    ) -> ConstLattice {
        match (lhs, rhs) {
            (ConstLattice::Bottom, _) | (_, ConstLattice::Bottom) => ConstLattice::Bottom,
            (ConstLattice::Const(a), ConstLattice::Const(b)) => {
                ConstLattice::Const(i64::from(op.eval(a, b)))
            }
            // A variable compared with ITSELF: true for Eq/Le/Ge, false for the
            // strict and negated forms, whatever the value is.
            _ if same_var => match op {
                CmpKind::Eq | CmpKind::Le | CmpKind::Ge => ConstLattice::Const(1),
                CmpKind::Ne | CmpKind::Lt | CmpKind::Gt => ConstLattice::Const(0),
            },
            _ => ConstLattice::Top,
        }
    }

    /// Fold a single instruction given the current state — convenience method.
    #[must_use]
    pub fn fold_instruction(&self, instr: &IrInstr, state: &PropState) -> FoldResult {
        let tmp = state.clone();
        match instr {
            IrInstr::Const { value, .. } => FoldResult::Folded(*value),
            IrInstr::BinOp { op, lhs, rhs, .. } => {
                match self.fold_binop(*op, state.get(*lhs), state.get(*rhs)) {
                    ConstLattice::Const(c) => FoldResult::Folded(c),
                    ConstLattice::Top | ConstLattice::Bottom => FoldResult::NotFolded,
                }
            }
            IrInstr::Cmp { op, lhs, rhs, .. } => {
                match self.fold_cmp(*op, state.get(*lhs), state.get(*rhs), lhs == rhs) {
                    ConstLattice::Const(c) => FoldResult::Folded(c),
                    _ => FoldResult::NotFolded,
                }
            }
            IrInstr::UnOp { op, src, .. } => {
                match self.fold_unop(*op, state.get(*src)) {
                    ConstLattice::Const(c) => FoldResult::Folded(c),
                    _ => FoldResult::NotFolded,
                }
            }
            IrInstr::Phi { srcs, .. } => {
                let joined = srcs.iter().fold(ConstLattice::Bottom, |acc, &v| {
                    acc.join(tmp.get(v))
                });
                match joined {
                    ConstLattice::Const(c) => FoldResult::Folded(c),
                    _ => FoldResult::NotFolded,
                }
            }
            IrInstr::CondBr { .. } | IrInstr::Jump { .. } | IrInstr::Ret => FoldResult::NoValue,
        }
    }
}

impl Default for ConstPropPass {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstPropResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of running `ConstPropPass::run`.
#[derive(Debug)]
pub struct ConstPropResult {
    /// Per-block exit states (indexed by position in the `blocks` slice).
    pub exit_states: Vec<PropState>,
    /// Per-block entry states.
    pub entry_states: Vec<PropState>,
    /// Detected invariant (opaque) conditional branches.
    pub invariant_conds: Vec<InvariantCond>,
    /// Number of worklist iterations performed.
    pub iterations: usize,
    /// Number of blocks that were reached (non-empty exit state).
    pub blocks_reached: usize,
}

impl ConstPropResult {
    const fn empty() -> Self {
        Self {
            exit_states: Vec::new(),
            entry_states: Vec::new(),
            invariant_conds: Vec::new(),
            iterations: 0,
            blocks_reached: 0,
        }
    }

    /// Look up the exit-state lattice value for `var` in block `block_idx`.
    #[must_use]
    pub fn value_at_exit(&self, block_pos: usize, var: VarId) -> ConstLattice {
        self.exit_states.get(block_pos).map_or(ConstLattice::Bottom, |s| s.get(var))
    }

    /// Look up the entry-state lattice value for `var` in block `block_pos`.
    #[must_use]
    pub fn value_at_entry(&self, block_pos: usize, var: VarId) -> ConstLattice {
        self.entry_states.get(block_pos).map_or(ConstLattice::Bottom, |s| s.get(var))
    }

    /// All variables that have constant values at block exit.
    #[must_use]
    pub fn constants_at_exit(&self, block_pos: usize) -> Vec<(VarId, i64)> {
        self.exit_states.get(block_pos)
            .map(|s| s.values.iter().filter_map(|(&v, &l)| l.as_i64().map(|c| (v, c))).collect())
            .unwrap_or_default()
    }

    /// Number of always-true opaque predicates.
    #[must_use]
    pub fn opaque_true_count(&self) -> usize {
        self.invariant_conds.iter().filter(|c| c.is_opaque_true()).count()
    }

    /// Number of always-false opaque predicates.
    #[must_use]
    pub fn opaque_false_count(&self) -> usize {
        self.invariant_conds.iter().filter(|c| c.is_opaque_false()).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: build a simple CFG from a linear instruction sequence
// ─────────────────────────────────────────────────────────────────────────────

/// Build a trivial single-block CFG from a flat list of IR instructions.
#[must_use]
pub fn single_block_cfg(instrs: Vec<IrInstr>) -> Vec<BasicBlock> {
    let mut block = BasicBlock::new(0);
    block.instrs = instrs;
    vec![block]
}

/// Link predecessor/successor edges in a block list (by scanning branch instructions).
pub fn link_cfg(blocks: &mut Vec<BasicBlock>) {
    let id_to_idx: HashMap<u32, usize> = blocks.iter().enumerate()
        .map(|(i, b)| (b.id, i))
        .collect();

    let mut succ_map: Vec<Vec<u32>> = vec![Vec::new(); blocks.len()];
    for (idx, block) in blocks.iter().enumerate() {
        for instr in &block.instrs {
            match instr {
                IrInstr::Jump { target } => succ_map[idx].push(*target),
                IrInstr::CondBr { true_block, false_block, .. } => {
                    succ_map[idx].push(*true_block);
                    succ_map[idx].push(*false_block);
                }
                _ => {}
            }
        }
    }

    // Assign succs and preds.
    let mut pred_map: Vec<Vec<u32>> = vec![Vec::new(); blocks.len()];
    for (idx, succs) in succ_map.iter().enumerate() {
        let block_id = blocks[idx].id;
        for &succ_id in succs {
            if let Some(&succ_idx) = id_to_idx.get(&succ_id) {
                pred_map[succ_idx].push(block_id);
            }
        }
        blocks[idx].succs = succs.clone();
    }
    for (idx, preds) in pred_map.into_iter().enumerate() {
        blocks[idx].preds = preds;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lattice_join() {
        assert_eq!(ConstLattice::Bottom.join(ConstLattice::Const(5)), ConstLattice::Const(5));
        assert_eq!(ConstLattice::Const(5).join(ConstLattice::Const(5)), ConstLattice::Const(5));
        assert_eq!(ConstLattice::Const(5).join(ConstLattice::Const(6)), ConstLattice::Top);
        assert_eq!(ConstLattice::Top.join(ConstLattice::Const(5)), ConstLattice::Top);
    }

    #[test]
    fn test_lattice_meet() {
        assert_eq!(ConstLattice::Top.meet(ConstLattice::Const(3)), ConstLattice::Const(3));
        assert_eq!(ConstLattice::Bottom.meet(ConstLattice::Const(3)), ConstLattice::Bottom);
    }

    #[test]
    fn test_lattice_display() {
        assert_eq!(ConstLattice::Bottom.to_string(), "⊥");
        assert_eq!(ConstLattice::Top.to_string(), "⊤");
        assert_eq!(ConstLattice::Const(42).to_string(), "42");
    }

    #[test]
    fn test_simple_const_prop() {
        let instrs = vec![
            IrInstr::Const { dst: 0, value: 10 },
            IrInstr::Const { dst: 1, value: 5 },
            IrInstr::BinOp { dst: 2, op: BinOpKind::Add, lhs: 0, rhs: 1 },
            IrInstr::Const { dst: 3, value: 0 },
            IrInstr::Cmp { dst: 4, op: CmpKind::Eq, lhs: 2, rhs: 3 },
        ];
        let blocks = single_block_cfg(instrs);
        let pass = ConstPropPass::new();
        let result = pass.run(&blocks);

        assert_eq!(result.value_at_exit(0, 2), ConstLattice::Const(15));
        assert_eq!(result.value_at_exit(0, 4), ConstLattice::Const(0));
    }

    #[test]
    fn test_phi_node_join() {
        // Two predecessors set v0 to 5 and 7 respectively → phi = Top.
        let instrs = vec![
            IrInstr::Const { dst: 0, value: 5 },
            IrInstr::Const { dst: 1, value: 7 },
            IrInstr::Phi { dst: 2, srcs: vec![0, 1] },
        ];
        let blocks = single_block_cfg(instrs);
        let pass = ConstPropPass::new();
        let result = pass.run(&blocks);
        // 0 and 1 are different constants → phi = Top.
        assert_eq!(result.value_at_exit(0, 2), ConstLattice::Top);
    }

    #[test]
    fn test_phi_node_same_value() {
        let instrs = vec![
            IrInstr::Const { dst: 0, value: 42 },
            IrInstr::Const { dst: 1, value: 42 },
            IrInstr::Phi { dst: 2, srcs: vec![0, 1] },
        ];
        let blocks = single_block_cfg(instrs);
        let pass = ConstPropPass::new();
        let result = pass.run(&blocks);
        assert_eq!(result.value_at_exit(0, 2), ConstLattice::Const(42));
    }

    #[test]
    fn test_invariant_cond_detected() {
        let instrs = vec![
            IrInstr::Const { dst: 0, value: 1 },
            IrInstr::CondBr { cond: 0, true_block: 1, false_block: 2 },
        ];
        let mut blocks = vec![
            { let mut b = BasicBlock::new(0); b.instrs = instrs; b },
            BasicBlock::new(1),
            BasicBlock::new(2),
        ];
        link_cfg(&mut blocks);
        let pass = ConstPropPass::new();
        let result = pass.run(&blocks);
        assert_eq!(result.invariant_conds.len(), 1);
        assert!(result.invariant_conds[0].always_true);
    }

    #[test]
    fn test_fold_instruction_direct() {
        let pass = ConstPropPass::new();
        let mut state = PropState::new();
        state.set(0, ConstLattice::Const(6));
        state.set(1, ConstLattice::Const(7));
        let instr = IrInstr::BinOp { dst: 2, op: BinOpKind::Mul, lhs: 0, rhs: 1 };
        let fold = pass.fold_instruction(&instr, &state);
        assert!(matches!(fold, FoldResult::Folded(42)));
    }

    #[test]
    fn test_self_comparison_top_vars() {
        // This test used to read "lhs == rhs in lattice identity, so expect
        // Const(1)" — which is the confusion itself: it calls the case a SELF
        // comparison while passing two lattice values that carry no variable
        // identity at all. Two DIFFERENT unknown variables are both `Top`, so
        // "equal lattice values" does not mean "the same variable".
        let pass = ConstPropPass::new();

        // The same variable compared with itself: folds, whatever it holds.
        assert_eq!(
            pass.fold_cmp(CmpKind::Eq, ConstLattice::Top, ConstLattice::Top, true),
            ConstLattice::Const(1)
        );
        assert_eq!(
            pass.fold_cmp(CmpKind::Ne, ConstLattice::Top, ConstLattice::Top, true),
            ConstLattice::Const(0)
        );

        // Two distinct unknown variables: their equality is data-dependent.
        assert_eq!(
            pass.fold_cmp(CmpKind::Eq, ConstLattice::Top, ConstLattice::Top, false),
            ConstLattice::Top
        );
    }
}
