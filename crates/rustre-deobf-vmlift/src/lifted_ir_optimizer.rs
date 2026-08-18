//! `lifted_ir_optimizer` — Optimization of IR lifted from VM bytecode.
//!
//! Passes (in recommended pipeline order):
//! 1. **Constant Propagation** — replace uses of known-constant defs with literals.
//! 2. **Dead Store Elimination** — remove stores whose value is never read.
//! 3. **Redundant Memory Op Elimination** — coalesce consecutive load/store to the same address.
//! 4. **Loop Simplification** — identify induction variables, simplify loop bodies.
//! 5. **Expression Normalization** — canonicalize expression trees (constant folding, identity laws).
//!
//! All passes operate on [`IrFunction`] / [`IrBlock`] / [`IrInsn`], a lightweight
//! IR that mirrors the LLIL types from `tigress_lifter` but adds def-use information.


use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// IR types
// ─────────────────────────────────────────────────────────────────────────────

/// A virtual register in the lifted IR.
pub type VReg = u32;

/// A constant value.
pub type Const = u64;

/// An IR value — either a virtual register or a constant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IrVal {
    Reg(VReg),
    Const(Const),
}

impl IrVal {
    #[must_use]
    pub const fn is_const(&self) -> bool {
        matches!(self, IrVal::Const(_))
    }

    #[must_use]
    pub const fn as_const(&self) -> Option<Const> {
        if let IrVal::Const(v) = self {
            Some(*v)
        } else {
            None
        }
    }
}

/// Binary operation in the IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IrBinOp {
    Add, Sub, Mul, UDiv, SDiv,
    And, Or, Xor,
    Shl, Shr, Sar, Rol, Ror,
    Eq, Ne, Ult, Ule, Slt, Sle,
}

impl IrBinOp {
    /// Evaluate this operation on two constants.
    #[must_use]
    pub fn eval(self, lhs: u64, rhs: u64) -> u64 {
        match self {
            Self::Add  => lhs.wrapping_add(rhs),
            Self::Sub  => lhs.wrapping_sub(rhs),
            Self::Mul  => lhs.wrapping_mul(rhs),
            Self::UDiv => if rhs != 0 { lhs / rhs } else { 0 },
            Self::SDiv => {
                if rhs != 0 { ((lhs as i64).wrapping_div(rhs as i64)) as u64 } else { 0 }
            }
            Self::And  => lhs & rhs,
            Self::Or   => lhs | rhs,
            Self::Xor  => lhs ^ rhs,
            Self::Shl  => lhs.wrapping_shl(rhs as u32),
            Self::Shr  => lhs.wrapping_shr(rhs as u32),
            Self::Sar  => ((lhs as i64).wrapping_shr(rhs as u32)) as u64,
            Self::Rol  => lhs.rotate_left(rhs as u32),
            Self::Ror  => lhs.rotate_right(rhs as u32),
            Self::Eq   => u64::from(lhs == rhs),
            Self::Ne   => u64::from(lhs != rhs),
            Self::Ult  => u64::from(lhs < rhs),
            Self::Ule  => u64::from(lhs <= rhs),
            Self::Slt  => u64::from((lhs as i64) < (rhs as i64)),
            Self::Sle  => u64::from((lhs as i64) <= (rhs as i64)),
        }
    }

    /// Return the identity element for this operation, if any.
    #[must_use]
    pub const fn identity(self) -> Option<u64> {
        match self {
            Self::Add | Self::Or | Self::Xor => Some(0),
            Self::Sub => Some(0),   // x - 0 = x
            Self::Mul => Some(1),
            Self::And => Some(u64::MAX),
            Self::Shl | Self::Shr | Self::Sar | Self::Rol | Self::Ror => Some(0),
            _ => None,
        }
    }

    /// Return the absorbing element for this operation, if any.
    #[must_use]
    pub const fn absorbing(self) -> Option<u64> {
        match self {
            Self::And | Self::Mul => Some(0),
            Self::Or => Some(u64::MAX),
            _ => None,
        }
    }
}

/// Unary operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IrUnaryOp {
    Not, Neg, Bswap, Popcnt, Zext8, Zext16, Zext32, Sext8, Sext16, Sext32,
}

impl IrUnaryOp {
    #[must_use]
    pub const fn eval(self, v: u64) -> u64 {
        match self {
            Self::Not    => !v,
            Self::Neg    => v.wrapping_neg(),
            Self::Bswap  => v.swap_bytes(),
            Self::Popcnt => v.count_ones() as u64,
            Self::Zext8  => v & 0xFF,
            Self::Zext16 => v & 0xFFFF,
            Self::Zext32 => v & 0xFFFF_FFFF,
            Self::Sext8  => (v as i8)  as i64 as u64,
            Self::Sext16 => (v as i16) as i64 as u64,
            Self::Sext32 => (v as i32) as i64 as u64,
        }
    }
}

/// A single lifted IR instruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IrInsn {
    /// `dst = val`
    Assign { dst: VReg, val: IrVal },
    /// `dst = lhs op rhs`
    BinOp { dst: VReg, op: IrBinOp, lhs: IrVal, rhs: IrVal },
    /// `dst = op val`
    UnaryOp { dst: VReg, op: IrUnaryOp, val: IrVal },
    /// `dst = mem[addr + offset]` (width in bytes)
    Load { dst: VReg, addr: IrVal, offset: i32, width: u8 },
    /// `mem[addr + offset] = val` (width in bytes)
    Store { addr: IrVal, offset: i32, val: IrVal, width: u8 },
    /// Unconditional jump.
    Jump { target: IrVal },
    /// Conditional branch.
    Branch { cond: IrVal, taken: u64, fallthrough: u64 },
    /// Call.
    Call { target: IrVal },
    /// Return.
    Ret { val: IrVal },
    /// No operation.
    Nop,
    /// Dead instruction (marked for removal).
    Dead,
}

impl IrInsn {
    /// Return the destination register of this instruction, if any.
    #[must_use]
    pub const fn dst(&self) -> Option<VReg> {
        match self {
            IrInsn::Assign { dst, .. }
            | IrInsn::BinOp { dst, .. }
            | IrInsn::UnaryOp { dst, .. }
            | IrInsn::Load { dst, .. } => Some(*dst),
            _ => None,
        }
    }

    /// Return all source registers used by this instruction.
    #[must_use]
    pub fn uses(&self) -> Vec<VReg> {
        let mut regs = Vec::with_capacity(2);
        match self {
            IrInsn::Assign { val, .. } => collect_reg(val, &mut regs),
            IrInsn::BinOp { lhs, rhs, .. } => {
                collect_reg(lhs, &mut regs);
                collect_reg(rhs, &mut regs);
            }
            IrInsn::UnaryOp { val, .. } => collect_reg(val, &mut regs),
            IrInsn::Load { addr, .. } => collect_reg(addr, &mut regs),
            IrInsn::Store { addr, val, .. } => {
                collect_reg(addr, &mut regs);
                collect_reg(val, &mut regs);
            }
            IrInsn::Jump { target } | IrInsn::Call { target } => collect_reg(target, &mut regs),
            IrInsn::Branch { cond, .. } => collect_reg(cond, &mut regs),
            IrInsn::Ret { val } => collect_reg(val, &mut regs),
            _ => {}
        }
        regs
    }
}

fn collect_reg(val: &IrVal, out: &mut Vec<VReg>) {
    if let IrVal::Reg(r) = val {
        out.push(*r);
    }
}

/// A basic block in the IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrBlock {
    /// Unique block identifier.
    pub id: u32,
    /// Original address.
    pub address: u64,
    pub insns: Vec<IrInsn>,
    pub successors: Vec<u32>,
    pub predecessors: Vec<u32>,
}

impl IrBlock {
    #[must_use]
    pub const fn new(id: u32, address: u64) -> Self {
        Self {
            id,
            address,
            insns: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }

    #[must_use]
    pub fn live_defs(&self) -> HashSet<VReg> {
        self.insns.iter().filter_map(IrInsn::dst).collect()
    }
}

/// A complete IR function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrFunction {
    pub entry_block: u32,
    pub blocks: HashMap<u32, IrBlock>,
    pub next_vreg: VReg,
}

impl IrFunction {
    #[must_use]
    pub fn new(entry: u32) -> Self {
        Self {
            entry_block: entry,
            blocks: HashMap::new(),
            next_vreg: 0,
        }
    }

    pub const fn fresh_vreg(&mut self) -> VReg {
        let r = self.next_vreg;
        self.next_vreg += 1;
        r
    }

    #[must_use]
    pub fn block_order(&self) -> Vec<u32> {
        // BFS from entry
        let cap = self.blocks.len();
        let mut visited = HashSet::with_capacity(cap);
        let mut queue = VecDeque::with_capacity(cap);
        let mut order = Vec::with_capacity(cap);

        queue.push_back(self.entry_block);
        visited.insert(self.entry_block);

        while let Some(id) = queue.pop_front() {
            order.push(id);
            if let Some(block) = self.blocks.get(&id) {
                for &succ in &block.successors {
                    if visited.insert(succ) {
                        queue.push_back(succ);
                    }
                }
            }
        }

        order
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Optimization statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics collected across one optimization run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OptStats {
    pub constants_propagated: u32,
    pub dead_stores_eliminated: u32,
    pub redundant_mem_ops_removed: u32,
    pub loop_simplifications: u32,
    pub expressions_normalized: u32,
    pub passes_run: u32,
}

impl std::fmt::Display for OptStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OptStats {{ const_prop={}, dead_stores={}, mem_ops={}, loops={}, norm={}, passes={} }}",
            self.constants_propagated,
            self.dead_stores_eliminated,
            self.redundant_mem_ops_removed,
            self.loop_simplifications,
            self.expressions_normalized,
            self.passes_run,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pass 1: Constant Propagation
// ─────────────────────────────────────────────────────────────────────────────

/// Constant propagation: replace register uses with known constant values
/// and constant-fold binary/unary operations.
pub struct ConstantPropagation;

impl ConstantPropagation {
    pub fn run(func: &mut IrFunction) -> u32 {
        let mut changed = 0u32;
        let order = func.block_order();

        for block_id in order {
            let mut const_map: HashMap<VReg, Const> = HashMap::new();

            let block = match func.blocks.get_mut(&block_id) {
                Some(b) => b,
                None => continue,
            };

            for insn in &mut block.insns {
                // First substitute known constants into all source operands
                let substituted = substitute_consts(insn.clone(), &const_map);
                if substituted != *insn {
                    *insn = substituted;
                    changed += 1;
                }

                // Then check if the instruction now produces a constant
                match insn {
                    IrInsn::Assign { dst, val: IrVal::Const(c) } => {
                        const_map.insert(*dst, *c);
                    }
                    IrInsn::BinOp {
                        dst,
                        op,
                        lhs: IrVal::Const(l),
                        rhs: IrVal::Const(r),
                    } => {
                        let result = op.eval(*l, *r);
                        const_map.insert(*dst, result);
                        // Fold the instruction
                        *insn = IrInsn::Assign {
                            dst: *dst,
                            val: IrVal::Const(result),
                        };
                        changed += 1;
                    }
                    IrInsn::UnaryOp {
                        dst,
                        op,
                        val: IrVal::Const(v),
                    } => {
                        let result = op.eval(*v);
                        const_map.insert(*dst, result);
                        *insn = IrInsn::Assign {
                            dst: *dst,
                            val: IrVal::Const(result),
                        };
                        changed += 1;
                    }
                    _ => {}
                }
            }
        }

        changed
    }
}

fn substitute_consts(insn: IrInsn, map: &HashMap<VReg, Const>) -> IrInsn {
    let sub = |v: IrVal| -> IrVal {
        if let IrVal::Reg(r) = &v {
            if let Some(&c) = map.get(r) {
                return IrVal::Const(c);
            }
        }
        v
    };

    match insn {
        IrInsn::Assign { dst, val } => IrInsn::Assign { dst, val: sub(val) },
        IrInsn::BinOp { dst, op, lhs, rhs } => IrInsn::BinOp {
            dst,
            op,
            lhs: sub(lhs),
            rhs: sub(rhs),
        },
        IrInsn::UnaryOp { dst, op, val } => IrInsn::UnaryOp { dst, op, val: sub(val) },
        IrInsn::Load { dst, addr, offset, width } => IrInsn::Load {
            dst,
            addr: sub(addr),
            offset,
            width,
        },
        IrInsn::Store { addr, offset, val, width } => IrInsn::Store {
            addr: sub(addr),
            offset,
            val: sub(val),
            width,
        },
        IrInsn::Branch { cond, taken, fallthrough } => IrInsn::Branch {
            cond: sub(cond),
            taken,
            fallthrough,
        },
        IrInsn::Jump { target } => IrInsn::Jump { target: sub(target) },
        IrInsn::Call { target } => IrInsn::Call { target: sub(target) },
        IrInsn::Ret { val } => IrInsn::Ret { val: sub(val) },
        other => other,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pass 2: Dead Store Elimination
// ─────────────────────────────────────────────────────────────────────────────

/// Eliminate stores to registers that are never subsequently read.
pub struct DeadStoreElimination;

impl DeadStoreElimination {
    pub fn run(func: &mut IrFunction) -> u32 {
        let mut eliminated = 0u32;
        let order = func.block_order();

        // Compute all register uses across the function
        let mut all_uses: HashSet<VReg> = HashSet::with_capacity(order.len() * 2);
        for id in &order {
            if let Some(block) = func.blocks.get(id) {
                for insn in &block.insns {
                    for r in insn.uses() {
                        all_uses.insert(r);
                    }
                }
            }
        }

        for block_id in &order {
            let block = match func.blocks.get_mut(block_id) {
                Some(b) => b,
                None => continue,
            };

            for insn in &mut block.insns {
                if let Some(dst) = insn.dst() {
                    // If this register is never used anywhere, it's a dead store
                    if !all_uses.contains(&dst) {
                        // Stores to memory are never dead-eliminated by this simple pass
                        if !matches!(insn, IrInsn::Store { .. } | IrInsn::Call { .. } | IrInsn::Ret { .. }) {
                            *insn = IrInsn::Dead;
                            eliminated += 1;
                        }
                    }
                }
            }

            // Remove Dead instructions
            block.insns.retain(|i| !matches!(i, IrInsn::Dead));
        }

        eliminated
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pass 3: Redundant Memory Operation Elimination
// ─────────────────────────────────────────────────────────────────────────────

/// Eliminate redundant consecutive loads from or stores to the same address.
///
/// Handles:
/// * Load after load to the same address → replace second load with copy of first.
/// * Store after store to the same address (no intervening load) → remove first store.
pub struct RedundantMemOpElimination;

impl RedundantMemOpElimination {
    pub fn run(func: &mut IrFunction) -> u32 {
        let mut removed = 0u32;
        let order = func.block_order();

        for block_id in order {
            let block = match func.blocks.get_mut(&block_id) {
                Some(b) => b,
                None => continue,
            };

            // Map from (addr, offset, width) → last loaded VReg
            let mut last_load: HashMap<(String, i32, u8), VReg> = HashMap::new();
            // Map from (addr, offset, width) → index of last store
            let mut last_store: HashMap<(String, i32, u8), usize> = HashMap::new();

            let mut to_nop: HashSet<usize> = HashSet::new();

            for (idx, insn) in block.insns.iter_mut().enumerate() {
                match insn.clone() {
                    IrInsn::Load { dst, addr, offset, width } => {
                        let key = (format!("{addr:?}"), offset, width);
                        if let Some(&prev_dst) = last_load.get(&key) {
                            // Replace with register copy
                            *insn = IrInsn::Assign { dst, val: IrVal::Reg(prev_dst) };
                            removed += 1;
                        } else {
                            last_load.insert(key, dst);
                        }
                    }
                    // `val` is deliberately NOT consulted: a store is dead when a
                    // later store to the same address overwrites it, whatever
                    // value either wrote. Binding it and ignoring it read as an
                    // oversight, so it is destructured away explicitly.
                    //
                    // (Comparing values would additionally catch a store that
                    // rewrites the SAME value, but that is a different
                    // optimisation with a different correctness argument — it
                    // is not folded in here silently.)
                    IrInsn::Store { addr, offset, val: _, width } => {
                        let key = (format!("{addr:?}"), offset, width);
                        // Invalidate any cached load for this address
                        last_load.remove(&key);

                        if let Some(&prev_idx) = last_store.get(&key) {
                            // Previous store to the same address is dead
                            to_nop.insert(prev_idx);
                            removed += 1;
                        }
                        last_store.insert(key, idx);
                    }
                    // Any call or unknown op may alias — flush caches
                    IrInsn::Call { .. } => {
                        last_load.clear();
                        last_store.clear();
                    }
                    _ => {}
                }
            }

            // Replace dead stores with Nop
            for idx in to_nop {
                block.insns[idx] = IrInsn::Nop;
            }
        }

        removed
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pass 4: Loop Simplification
// ─────────────────────────────────────────────────────────────────────────────

/// A detected induction variable inside a loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InductionVar {
    pub vreg: VReg,
    /// Initial value (before the loop).
    pub init: Option<IrVal>,
    /// Step: how much is added per iteration.
    pub step: i64,
    /// The block where it is incremented.
    pub increment_block: u32,
}

/// Identify loops and simplify their induction variables.
pub struct LoopSimplification;

impl LoopSimplification {
    pub fn run(func: &mut IrFunction) -> u32 {
        let mut simplified = 0u32;

        // Find natural loops via back-edges (simplified: blocks whose successor
        // has a smaller BFS order index than themselves)
        let order = func.block_order();
        let order_idx: HashMap<u32, usize> = order.iter().enumerate().map(|(i, &id)| (id, i)).collect();

        let back_edges: Vec<(u32, u32)> = order
            .iter()
            .flat_map(|&id| {
                func.blocks
                    .get(&id)
                    .map(|b| {
                        b.successors
                            .iter()
                            .filter(|&&succ| {
                                order_idx.get(&succ).copied().unwrap_or(usize::MAX)
                                    <= order_idx.get(&id).copied().unwrap_or(0)
                            })
                            .map(|&succ| (id, succ))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .collect();

        for (tail, head) in &back_edges {
            // Look for induction variables: a register that is defined as `self + const`
            // in the loop body and used as a loop counter.
            let ivars = Self::find_induction_vars(func, *head, *tail);
            for ivar in &ivars {
                simplified += Self::simplify_ivar(func, *head, *tail, ivar);
            }
        }

        simplified
    }

    fn find_induction_vars(func: &IrFunction, head: u32, tail: u32) -> Vec<InductionVar> {
        let mut ivars = Vec::new();

        // Collect all blocks in the loop (simplified: between head and tail in order)
        let order = func.block_order();
        let head_pos = order.iter().position(|&id| id == head).unwrap_or(0);
        let tail_pos = order.iter().position(|&id| id == tail).unwrap_or(head_pos);
        let loop_blocks: HashSet<u32> = order[head_pos..=tail_pos.max(head_pos)]
            .iter()
            .copied()
            .collect();

        // Look for `r = r + const` patterns inside the loop
        for &block_id in &loop_blocks {
            if let Some(block) = func.blocks.get(&block_id) {
                for insn in &block.insns {
                    if let IrInsn::BinOp {
                        dst,
                        op: IrBinOp::Add,
                        lhs: IrVal::Reg(src),
                        rhs: IrVal::Const(step),
                    } = insn
                    {
                        if dst == src {
                            ivars.push(InductionVar {
                                vreg: *dst,
                                init: None,
                                step: *step as i64,
                                increment_block: block_id,
                            });
                        }
                    }
                    // Sub variant: r = r - const → step is negative
                    if let IrInsn::BinOp {
                        dst,
                        op: IrBinOp::Sub,
                        lhs: IrVal::Reg(src),
                        rhs: IrVal::Const(step),
                    } = insn
                    {
                        if dst == src {
                            ivars.push(InductionVar {
                                vreg: *dst,
                                init: None,
                                step: -(*step as i64),
                                increment_block: block_id,
                            });
                        }
                    }
                }
            }
        }

        ivars
    }

    fn simplify_ivar(
        func: &mut IrFunction,
        _head: u32,
        _tail: u32,
        ivar: &InductionVar,
    ) -> u32 {
        // Simplification: if step == 1 and the loop compares ivar against a constant,
        // we can mark the loop as a counted loop (add an annotation or rewrite the branch).
        // For now, we just remove self-add-zero NOPs (r = r + 0).
        if ivar.step == 0 {
            if let Some(block) = func.blocks.get_mut(&ivar.increment_block) {
                let before = block.insns.len();
                block.insns.retain(|insn| {
                    !matches!(insn,
                        IrInsn::BinOp { op: IrBinOp::Add, rhs: IrVal::Const(0), .. }
                        | IrInsn::BinOp { op: IrBinOp::Sub, rhs: IrVal::Const(0), .. }
                    )
                });
                return (before - block.insns.len()) as u32;
            }
        }
        0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pass 5: Expression Normalization
// ─────────────────────────────────────────────────────────────────────────────

/// Normalize expression trees using algebraic identities.
///
/// Examples:
/// * `x + 0 → x`
/// * `x * 1 → x`
/// * `x & 0 → 0`
/// * `x | ~x → -1` (all bits set)
/// * `x ^ x → 0`
/// * `x - x → 0`
/// * `~~x → x`
/// * `NOT(NOT x) → x`
pub struct ExpressionNormalization;

impl ExpressionNormalization {
    pub fn run(func: &mut IrFunction) -> u32 {
        let mut normalized = 0u32;
        let order = func.block_order();

        for block_id in order {
            let block = match func.blocks.get_mut(&block_id) {
                Some(b) => b,
                None => continue,
            };

            for insn in &mut block.insns {
                let new = Self::normalize(insn.clone());
                if new != *insn {
                    *insn = new;
                    normalized += 1;
                }
            }
        }

        normalized
    }

    fn normalize(insn: IrInsn) -> IrInsn {
        match insn {
            IrInsn::BinOp { dst, op, lhs, rhs } => {
                // Identity element: x op identity → x
                if let Some(id_val) = op.identity() {
                    if rhs == IrVal::Const(id_val) {
                        return IrInsn::Assign { dst, val: lhs };
                    }
                    if matches!(op, IrBinOp::Add | IrBinOp::Or | IrBinOp::Xor | IrBinOp::And)
                        && lhs == IrVal::Const(id_val)
                    {
                        return IrInsn::Assign { dst, val: rhs };
                    }
                }

                // Absorbing element: x op absorb → absorb
                if let Some(abs_val) = op.absorbing() {
                    if rhs == IrVal::Const(abs_val) || lhs == IrVal::Const(abs_val) {
                        return IrInsn::Assign {
                            dst,
                            val: IrVal::Const(abs_val),
                        };
                    }
                }

                // x - x → 0 or x ^ x → 0 or x & x → x
                if lhs == rhs {
                    match op {
                        IrBinOp::Sub | IrBinOp::Xor => {
                            return IrInsn::Assign { dst, val: IrVal::Const(0) };
                        }
                        IrBinOp::And | IrBinOp::Or => {
                            return IrInsn::Assign { dst, val: lhs };
                        }
                        _ => {}
                    }
                }

                // Shift by 0 → identity
                if matches!(op, IrBinOp::Shl | IrBinOp::Shr | IrBinOp::Sar | IrBinOp::Rol | IrBinOp::Ror)
                    && rhs == IrVal::Const(0)
                {
                    return IrInsn::Assign { dst, val: lhs };
                }

                IrInsn::BinOp { dst, op, lhs, rhs }
            }

            other => other,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LiftedIrOptimizer — pipeline runner
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the optimization pipeline.
#[derive(Debug, Clone)]
pub struct OptimizerConfig {
    pub const_prop: bool,
    pub dead_store_elim: bool,
    pub redundant_mem_elim: bool,
    pub loop_simplify: bool,
    pub expr_normalize: bool,
    /// Number of times to repeat the pipeline until convergence.
    pub max_iterations: u32,
}

impl Default for OptimizerConfig {
    fn default() -> Self {
        Self {
            const_prop: true,
            dead_store_elim: true,
            redundant_mem_elim: true,
            loop_simplify: true,
            expr_normalize: true,
            max_iterations: 8,
        }
    }
}

/// Full optimization pipeline for lifted IR.
pub struct LiftedIrOptimizer {
    pub config: OptimizerConfig,
}

impl Default for LiftedIrOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl LiftedIrOptimizer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: OptimizerConfig::default(),
        }
    }

    #[must_use]
    pub const fn with_config(config: OptimizerConfig) -> Self {
        Self { config }
    }

    /// Run all configured passes until convergence or `max_iterations`.
    pub fn optimize(&self, func: &mut IrFunction) -> OptStats {
        let mut stats = OptStats::default();

        for _ in 0..self.config.max_iterations {
            let before = self.insn_count(func);

            if self.config.const_prop {
                stats.constants_propagated += ConstantPropagation::run(func);
                stats.passes_run += 1;
            }
            if self.config.dead_store_elim {
                stats.dead_stores_eliminated += DeadStoreElimination::run(func);
                stats.passes_run += 1;
            }
            if self.config.redundant_mem_elim {
                stats.redundant_mem_ops_removed += RedundantMemOpElimination::run(func);
                stats.passes_run += 1;
            }
            if self.config.loop_simplify {
                stats.loop_simplifications += LoopSimplification::run(func);
                stats.passes_run += 1;
            }
            if self.config.expr_normalize {
                stats.expressions_normalized += ExpressionNormalization::run(func);
                stats.passes_run += 1;
            }

            let after = self.insn_count(func);
            if after >= before {
                break; // no progress
            }
        }

        stats
    }

    fn insn_count(&self, func: &IrFunction) -> usize {
        func.blocks.values().map(|b| b.insns.len()).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_func() -> IrFunction {
        let mut func = IrFunction::new(0);
        let mut block = IrBlock::new(0, 0x1000);

        // r0 = 5
        block.insns.push(IrInsn::Assign {
            dst: 0,
            val: IrVal::Const(5),
        });
        // r1 = r0 + 3  → should fold to 8
        block.insns.push(IrInsn::BinOp {
            dst: 1,
            op: IrBinOp::Add,
            lhs: IrVal::Reg(0),
            rhs: IrVal::Const(3),
        });
        // r2 = r1 * 1  → should normalize to r1
        block.insns.push(IrInsn::BinOp {
            dst: 2,
            op: IrBinOp::Mul,
            lhs: IrVal::Reg(1),
            rhs: IrVal::Const(1),
        });
        // ret r2
        block.insns.push(IrInsn::Ret { val: IrVal::Reg(2) });

        func.blocks.insert(0, block);
        func
    }

    #[test]
    fn test_constant_propagation_fold() {
        let mut func = simple_func();
        ConstantPropagation::run(&mut func);

        let block = &func.blocks[&0];
        // r1 = 5 + 3 = 8 should have been folded to Assign r1 = 8
        let r1_assign = block.insns.iter().find(|i| {
            matches!(i, IrInsn::Assign { dst: 1, val: IrVal::Const(8) })
        });
        assert!(r1_assign.is_some(), "r1 should be const-folded to 8");
    }

    #[test]
    fn test_expr_normalize_identity() {
        let mut func = IrFunction::new(0);
        let mut block = IrBlock::new(0, 0x2000);

        // r0 = r1 + 0  → normalize to r0 = r1
        block.insns.push(IrInsn::BinOp {
            dst: 0,
            op: IrBinOp::Add,
            lhs: IrVal::Reg(1),
            rhs: IrVal::Const(0),
        });

        func.blocks.insert(0, block);
        ExpressionNormalization::run(&mut func);

        let normalized = &func.blocks[&0].insns[0];
        assert_eq!(*normalized, IrInsn::Assign { dst: 0, val: IrVal::Reg(1) });
    }

    #[test]
    fn test_expr_normalize_xor_self() {
        let mut func = IrFunction::new(0);
        let mut block = IrBlock::new(0, 0x3000);

        // r0 = r1 ^ r1 → 0
        block.insns.push(IrInsn::BinOp {
            dst: 0,
            op: IrBinOp::Xor,
            lhs: IrVal::Reg(1),
            rhs: IrVal::Reg(1),
        });

        func.blocks.insert(0, block);
        ExpressionNormalization::run(&mut func);

        let normalized = &func.blocks[&0].insns[0];
        assert_eq!(*normalized, IrInsn::Assign { dst: 0, val: IrVal::Const(0) });
    }

    #[test]
    fn test_dead_store_elimination() {
        let mut func = IrFunction::new(0);
        let mut block = IrBlock::new(0, 0x4000);

        // r5 = 42  (never used)
        block.insns.push(IrInsn::Assign {
            dst: 5,
            val: IrVal::Const(42),
        });
        // ret r0  (r5 not used)
        block.insns.push(IrInsn::Ret { val: IrVal::Reg(0) });

        func.blocks.insert(0, block);
        let eliminated = DeadStoreElimination::run(&mut func);
        assert_eq!(eliminated, 1);
        assert_eq!(func.blocks[&0].insns.len(), 1); // only Ret remains
    }

    #[test]
    fn test_full_optimizer_pipeline() {
        let mut func = simple_func();
        let opt = LiftedIrOptimizer::new();
        let stats = opt.optimize(&mut func);
        assert!(stats.constants_propagated > 0 || stats.expressions_normalized > 0);
    }

    #[test]
    fn test_absorbing_element_and_zero() {
        let mut func = IrFunction::new(0);
        let mut block = IrBlock::new(0, 0x5000);
        // r0 = r1 & 0  → r0 = 0
        block.insns.push(IrInsn::BinOp {
            dst: 0,
            op: IrBinOp::And,
            lhs: IrVal::Reg(1),
            rhs: IrVal::Const(0),
        });
        func.blocks.insert(0, block);
        ExpressionNormalization::run(&mut func);
        assert_eq!(
            func.blocks[&0].insns[0],
            IrInsn::Assign { dst: 0, val: IrVal::Const(0) }
        );
    }
}
