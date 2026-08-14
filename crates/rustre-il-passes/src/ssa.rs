//! Full SSA construction with proper phi nodes for [`LlilFunction`]s.
//!
//! Built on the dominator-tree infrastructure in [`crate::dominators`]:
//! phi nodes are placed with the classic Cytron iterated-dominance-frontier
//! algorithm, then variables are renamed with a dominator-tree walk.
//!
//! The SSA form is an *overlay*: the original function is not mutated.
//! Each SSA definition/use is a `base#version` name carried in
//! [`rustre_il_llil::LlilRegister::Concrete`], and every SSA instruction
//! remembers the `(block, instr)` position it came from so optimization
//! results can be applied back to the original IL (see [`crate::gvn2`]).
//!
//! Conservative choices (documented, not silent):
//! - Only register-like storage is versioned (concrete registers,
//!   lifter temporaries, and optimizer `Register{id}` reads, keyed as
//!   `vreg{id}`). Flags and memory are not versioned.
//! - Calls are not treated as register definitions; consumers that care
//!   about ABI clobbers must handle calls themselves.

use std::collections::HashMap;

use rustre_il_llil::{LlilExpr, LlilFunction, LlilInstruction, LlilRegister, Size};

use crate::dominators::{Cfg, DomTree};

/// A phi node: `var#dest = phi(pred_block_i: var#version_i, ...)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsaPhi {
    /// The base (un-versioned) variable.
    pub var: LlilRegister,
    /// SSA version defined by this phi.
    pub dest: u32,
    /// One argument per CFG predecessor: `(pred block index, version)`.
    pub args: Vec<(usize, u32)>,
    /// Width of the variable (best-effort; from its first def).
    pub size: Size,
}

impl SsaPhi {
    /// The `base#version` SSA name this phi defines.
    #[must_use]
    pub fn dest_name(&self) -> String {
        ssa_name(&self.var, self.dest)
    }
}

/// An SSA-renamed instruction with a link back to its source position.
#[derive(Debug, Clone, PartialEq)]
pub struct SsaInstr {
    /// `(block index, instruction index)` in the original function.
    pub orig: (usize, usize),
    /// The renamed instruction. Register reads and writes are
    /// `Concrete("base#version")` names.
    pub instr: LlilInstruction,
}

/// One basic block in SSA form.
#[derive(Debug, Clone, Default)]
pub struct SsaBlock {
    /// Phi nodes at the top of the block.
    pub phis: Vec<SsaPhi>,
    /// Renamed instructions in program order.
    pub instrs: Vec<SsaInstr>,
}

/// A function in SSA form (overlay over an [`LlilFunction`]).
#[derive(Debug, Clone)]
pub struct SsaFunction {
    /// Blocks, parallel to the original function's block vector.
    pub blocks: Vec<SsaBlock>,
    /// The CFG the SSA form was built over.
    pub cfg: Cfg,
    /// The dominator tree the SSA form was built over.
    pub dom: DomTree,
}

/// Formats the SSA name for `var` at `version`.
#[must_use]
pub fn ssa_name(var: &LlilRegister, version: u32) -> String {
    format!("{}#{}", var.name(), version)
}

/// Splits an SSA name back into `(base, version)`, if it is one.
#[must_use]
pub fn split_ssa_name(name: &str) -> Option<(&str, u32)> {
    let (base, ver) = name.rsplit_once('#')?;
    ver.parse().ok().map(|v| (base, v))
}

/// The variable key for the optimizer's numeric-register namespace.
fn vreg_key(id: u32) -> LlilRegister {
    LlilRegister::Concrete(format!("vreg{id}"))
}

// ─────────────────────────────────────────────────────────────────────
// def/use collection
// ─────────────────────────────────────────────────────────────────────

/// Returns the variables defined by `instr` (with best-effort sizes).
fn defs_of(instr: &LlilInstruction) -> Vec<(LlilRegister, Size)> {
    match instr {
        LlilInstruction::SetReg { dest, size, .. }
        | LlilInstruction::Load { dest, size, .. }
        | LlilInstruction::Pop { dest, size } => vec![(dest.clone(), *size)],
        LlilInstruction::SetRegSplit { high, low, src } => {
            let s = src.result_size();
            vec![(high.clone(), s), (low.clone(), s)]
        }
        LlilInstruction::SetRegister { dest, size, .. } => vec![(vreg_key(*dest), *size)],
        _ => Vec::new(),
    }
}

/// Collects the base variables *used* by `expr` into `out`.
pub fn collect_expr_uses(expr: &LlilExpr, out: &mut Vec<LlilRegister>) {
    visit_subexprs(expr, &mut |e| {
        match e {
            LlilExpr::RegisterRef { reg, .. } => out.push(reg.clone()),
            LlilExpr::Register { id, .. } => out.push(vreg_key(*id)),
            _ => {}
        }
    });
}

/// Calls `f` on `expr` and every sub-expression.
pub fn visit_subexprs(expr: &LlilExpr, f: &mut impl FnMut(&LlilExpr)) {
    f(expr);
    match expr {
        LlilExpr::Load { addr, .. } => visit_subexprs(addr, f),
        LlilExpr::AddT(a, b, _)
        | LlilExpr::SubT(a, b, _)
        | LlilExpr::MulT(a, b, _)
        | LlilExpr::DivU(a, b, _)
        | LlilExpr::DivS(a, b, _)
        | LlilExpr::ModU(a, b, _)
        | LlilExpr::ModS(a, b, _)
        | LlilExpr::And(a, b, _)
        | LlilExpr::Or(a, b, _)
        | LlilExpr::Xor(a, b, _)
        | LlilExpr::ShlT(a, b, _)
        | LlilExpr::Shr(a, b, _)
        | LlilExpr::Sar(a, b, _)
        | LlilExpr::Rol(a, b, _)
        | LlilExpr::Ror(a, b, _)
        | LlilExpr::FAdd(a, b, _)
        | LlilExpr::FSub(a, b, _)
        | LlilExpr::FMul(a, b, _)
        | LlilExpr::FDiv(a, b, _)
        | LlilExpr::CmpEq(a, b)
        | LlilExpr::CmpNe(a, b)
        | LlilExpr::CmpSlt(a, b)
        | LlilExpr::CmpUlt(a, b)
        | LlilExpr::CmpSle(a, b)
        | LlilExpr::CmpUle(a, b)
        | LlilExpr::CmpSgt(a, b)
        | LlilExpr::CmpUgt(a, b)
        | LlilExpr::CmpSge(a, b)
        | LlilExpr::CmpUge(a, b)
        | LlilExpr::FCmpEq(a, b)
        | LlilExpr::FCmpLt(a, b)
        | LlilExpr::FCmpGt(a, b) => {
            visit_subexprs(a, f);
            visit_subexprs(b, f);
        }
        LlilExpr::Add { left, right, .. }
        | LlilExpr::Sub { left, right, .. }
        | LlilExpr::Mul { left, right, .. } => {
            visit_subexprs(left, f);
            visit_subexprs(right, f);
        }
        LlilExpr::Shl { value, shift, .. } => {
            visit_subexprs(value, f);
            visit_subexprs(shift, f);
        }
        LlilExpr::Neg(a, _) | LlilExpr::Not(a, _) | LlilExpr::FNeg(a, _) => visit_subexprs(a, f),
        LlilExpr::ZeroExtend { expr, .. }
        | LlilExpr::SignExtend { expr, .. }
        | LlilExpr::LowPart { expr, .. }
        | LlilExpr::IntToFloat { expr, .. }
        | LlilExpr::FloatToInt { expr, .. } => visit_subexprs(expr, f),
        LlilExpr::CondExpr {
            cond,
            true_val,
            false_val,
            ..
        } => {
            visit_subexprs(cond, f);
            visit_subexprs(true_val, f);
            visit_subexprs(false_val, f);
        }
        LlilExpr::Intrinsic { args, .. } => {
            for a in args {
                visit_subexprs(a, f);
            }
        }
        LlilExpr::Const { .. }
        | LlilExpr::RegisterRef { .. }
        | LlilExpr::Register { .. }
        | LlilExpr::StackPointer(_)
        | LlilExpr::Flag(_)
        | LlilExpr::Undefined(_) => {}
    }
}

/// Rewrites every register read in `expr` through `rename`, which maps a
/// base variable (and its read size) to a replacement expression.
pub(crate) fn rewrite_expr_uses(
    expr: &LlilExpr,
    rename: &mut dyn FnMut(&LlilRegister, Size) -> LlilExpr,
) -> LlilExpr {
    let rec = |e: &LlilExpr, rename: &mut dyn FnMut(&LlilRegister, Size) -> LlilExpr| {
        rewrite_expr_uses(e, rename)
    };
    match expr {
        LlilExpr::RegisterRef { reg, size } => rename(reg, *size),
        LlilExpr::Register { id, size } => rename(&vreg_key(*id), *size),
        LlilExpr::Load { addr, size } => LlilExpr::Load {
            addr: Box::new(rec(addr, rename)),
            size: *size,
        },
        LlilExpr::AddT(a, b, s) => {
            LlilExpr::AddT(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::SubT(a, b, s) => {
            LlilExpr::SubT(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::MulT(a, b, s) => {
            LlilExpr::MulT(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::Add { left, right, size } => LlilExpr::Add {
            left: Box::new(rec(left, rename)),
            right: Box::new(rec(right, rename)),
            size: *size,
        },
        LlilExpr::Sub { left, right, size } => LlilExpr::Sub {
            left: Box::new(rec(left, rename)),
            right: Box::new(rec(right, rename)),
            size: *size,
        },
        LlilExpr::Mul { left, right, size } => LlilExpr::Mul {
            left: Box::new(rec(left, rename)),
            right: Box::new(rec(right, rename)),
            size: *size,
        },
        LlilExpr::Shl { value, shift, size } => LlilExpr::Shl {
            value: Box::new(rec(value, rename)),
            shift: Box::new(rec(shift, rename)),
            size: *size,
        },
        LlilExpr::DivU(a, b, s) => {
            LlilExpr::DivU(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::DivS(a, b, s) => {
            LlilExpr::DivS(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::ModU(a, b, s) => {
            LlilExpr::ModU(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::ModS(a, b, s) => {
            LlilExpr::ModS(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::Neg(a, s) => LlilExpr::Neg(Box::new(rec(a, rename)), *s),
        LlilExpr::And(a, b, s) => {
            LlilExpr::And(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::Or(a, b, s) => {
            LlilExpr::Or(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::Xor(a, b, s) => {
            LlilExpr::Xor(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::Not(a, s) => LlilExpr::Not(Box::new(rec(a, rename)), *s),
        LlilExpr::ShlT(a, b, s) => {
            LlilExpr::ShlT(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::Shr(a, b, s) => {
            LlilExpr::Shr(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::Sar(a, b, s) => {
            LlilExpr::Sar(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::Rol(a, b, s) => {
            LlilExpr::Rol(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::Ror(a, b, s) => {
            LlilExpr::Ror(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::CmpEq(a, b) => {
            LlilExpr::CmpEq(Box::new(rec(a, rename)), Box::new(rec(b, rename)))
        }
        LlilExpr::CmpNe(a, b) => {
            LlilExpr::CmpNe(Box::new(rec(a, rename)), Box::new(rec(b, rename)))
        }
        LlilExpr::CmpSlt(a, b) => {
            LlilExpr::CmpSlt(Box::new(rec(a, rename)), Box::new(rec(b, rename)))
        }
        LlilExpr::CmpUlt(a, b) => {
            LlilExpr::CmpUlt(Box::new(rec(a, rename)), Box::new(rec(b, rename)))
        }
        LlilExpr::CmpSle(a, b) => {
            LlilExpr::CmpSle(Box::new(rec(a, rename)), Box::new(rec(b, rename)))
        }
        LlilExpr::CmpUle(a, b) => {
            LlilExpr::CmpUle(Box::new(rec(a, rename)), Box::new(rec(b, rename)))
        }
        LlilExpr::CmpSgt(a, b) => {
            LlilExpr::CmpSgt(Box::new(rec(a, rename)), Box::new(rec(b, rename)))
        }
        LlilExpr::CmpUgt(a, b) => {
            LlilExpr::CmpUgt(Box::new(rec(a, rename)), Box::new(rec(b, rename)))
        }
        LlilExpr::CmpSge(a, b) => {
            LlilExpr::CmpSge(Box::new(rec(a, rename)), Box::new(rec(b, rename)))
        }
        LlilExpr::CmpUge(a, b) => {
            LlilExpr::CmpUge(Box::new(rec(a, rename)), Box::new(rec(b, rename)))
        }
        LlilExpr::ZeroExtend { expr, from, to } => LlilExpr::ZeroExtend {
            expr: Box::new(rec(expr, rename)),
            from: *from,
            to: *to,
        },
        LlilExpr::SignExtend { expr, from, to } => LlilExpr::SignExtend {
            expr: Box::new(rec(expr, rename)),
            from: *from,
            to: *to,
        },
        LlilExpr::LowPart { expr, to } => LlilExpr::LowPart {
            expr: Box::new(rec(expr, rename)),
            to: *to,
        },
        LlilExpr::FAdd(a, b, s) => {
            LlilExpr::FAdd(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::FSub(a, b, s) => {
            LlilExpr::FSub(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::FMul(a, b, s) => {
            LlilExpr::FMul(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::FDiv(a, b, s) => {
            LlilExpr::FDiv(Box::new(rec(a, rename)), Box::new(rec(b, rename)), *s)
        }
        LlilExpr::FNeg(a, s) => LlilExpr::FNeg(Box::new(rec(a, rename)), *s),
        LlilExpr::FCmpEq(a, b) => {
            LlilExpr::FCmpEq(Box::new(rec(a, rename)), Box::new(rec(b, rename)))
        }
        LlilExpr::FCmpLt(a, b) => {
            LlilExpr::FCmpLt(Box::new(rec(a, rename)), Box::new(rec(b, rename)))
        }
        LlilExpr::FCmpGt(a, b) => {
            LlilExpr::FCmpGt(Box::new(rec(a, rename)), Box::new(rec(b, rename)))
        }
        LlilExpr::IntToFloat { expr, to } => LlilExpr::IntToFloat {
            expr: Box::new(rec(expr, rename)),
            to: *to,
        },
        LlilExpr::FloatToInt { expr, to } => LlilExpr::FloatToInt {
            expr: Box::new(rec(expr, rename)),
            to: *to,
        },
        LlilExpr::CondExpr {
            cond,
            true_val,
            false_val,
            size,
        } => LlilExpr::CondExpr {
            cond: Box::new(rec(cond, rename)),
            true_val: Box::new(rec(true_val, rename)),
            false_val: Box::new(rec(false_val, rename)),
            size: *size,
        },
        LlilExpr::Intrinsic {
            name,
            args,
            result_size,
        } => LlilExpr::Intrinsic {
            name: name.clone(),
            args: args.iter().map(|a| rec(a, rename)).collect(),
            result_size: *result_size,
        },
        LlilExpr::Const { .. }
        | LlilExpr::StackPointer(_)
        | LlilExpr::Flag(_)
        | LlilExpr::Undefined(_) => expr.clone(),
    }
}

/// Rewrites the *source* expressions of `instr` through `rename`.
pub(crate) fn rewrite_instr_uses(
    instr: &LlilInstruction,
    rename: &mut impl FnMut(&LlilRegister, Size) -> LlilExpr,
) -> LlilInstruction {
    let mut r = |e: &LlilExpr| rewrite_expr_uses(e, rename);
    match instr {
        LlilInstruction::SetReg { dest, size, value } => LlilInstruction::SetReg {
            dest: dest.clone(),
            size: *size,
            value: r(value),
        },
        LlilInstruction::SetRegSplit { high, low, src } => LlilInstruction::SetRegSplit {
            high: high.clone(),
            low: low.clone(),
            src: r(src),
        },
        LlilInstruction::Load { dest, size, addr } => LlilInstruction::Load {
            dest: dest.clone(),
            size: *size,
            addr: r(addr),
        },
        LlilInstruction::Store { addr, size, value } => LlilInstruction::Store {
            addr: r(addr),
            size: *size,
            value: r(value),
        },
        LlilInstruction::SetFlag { name, src } => LlilInstruction::SetFlag {
            name: name.clone(),
            src: r(src),
        },
        LlilInstruction::Push { size, src } => LlilInstruction::Push {
            size: *size,
            src: r(src),
        },
        LlilInstruction::JumpDest { dest } => LlilInstruction::JumpDest { dest: r(dest) },
        LlilInstruction::JumpTo { dest, targets } => LlilInstruction::JumpTo {
            dest: r(dest),
            targets: targets.clone(),
        },
        LlilInstruction::CallDest { dest } => LlilInstruction::CallDest { dest: r(dest) },
        LlilInstruction::Jump(e) => LlilInstruction::Jump(r(e)),
        LlilInstruction::Call(e) => LlilInstruction::Call(r(e)),
        LlilInstruction::ConditionalJump {
            cond,
            true_target,
            false_target,
        } => LlilInstruction::ConditionalJump {
            cond: r(cond),
            true_target: *true_target,
            false_target: *false_target,
        },
        LlilInstruction::SetRegister { dest, value, size } => LlilInstruction::SetRegister {
            dest: *dest,
            value: r(value),
            size: *size,
        },
        LlilInstruction::TailCall { dest } => LlilInstruction::TailCall { dest: r(dest) },
        LlilInstruction::Return { value } => LlilInstruction::Return {
            value: value.as_ref().map(&mut r),
        },
        LlilInstruction::CondJump {
            cond,
            true_dest,
            false_dest,
        } => LlilInstruction::CondJump {
            cond: r(cond),
            true_dest: *true_dest,
            false_dest: *false_dest,
        },
        LlilInstruction::CondCall { cond, dest } => LlilInstruction::CondCall {
            cond: r(cond),
            dest: r(dest),
        },
        LlilInstruction::Intrinsic { name, args } => LlilInstruction::Intrinsic {
            name: name.clone(),
            args: args.iter().map(&mut r).collect(),
        },
        other => other.clone(),
    }
}

/// Replaces the destination registers of `instr` with fresh SSA names via
/// `def`, which receives the base variable and returns the new SSA name.
fn rewrite_instr_defs(
    instr: LlilInstruction,
    def: &mut impl FnMut(&LlilRegister) -> String,
) -> LlilInstruction {
    match instr {
        LlilInstruction::SetReg { dest, size, value } => LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(def(&dest)),
            size,
            value,
        },
        LlilInstruction::Load { dest, size, addr } => LlilInstruction::Load {
            dest: LlilRegister::Concrete(def(&dest)),
            size,
            addr,
        },
        LlilInstruction::Pop { dest, size } => LlilInstruction::Pop {
            dest: LlilRegister::Concrete(def(&dest)),
            size,
        },
        LlilInstruction::SetRegSplit { high, low, src } => LlilInstruction::SetRegSplit {
            high: LlilRegister::Concrete(def(&high)),
            low: LlilRegister::Concrete(def(&low)),
            src,
        },
        LlilInstruction::SetRegister { dest, value, size } => LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(def(&vreg_key(dest))),
            size,
            value,
        },
        other => other,
    }
}

// ─────────────────────────────────────────────────────────────────────
// construction
// ─────────────────────────────────────────────────────────────────────

impl SsaFunction {
    /// Builds SSA form for `func` (minimal SSA via iterated dominance
    /// frontiers + dominator-tree renaming).
    #[must_use]
    pub fn build(func: &LlilFunction) -> Self {
        let cfg = Cfg::build(func);
        let dom = DomTree::build(&cfg);
        let n = cfg.len;

        // 1. Collect def sites and sizes per variable.
        let mut def_blocks: HashMap<LlilRegister, Vec<usize>> = HashMap::new();
        let mut var_size: HashMap<LlilRegister, Size> = HashMap::new();
        for (bi, block) in func.blocks.iter().enumerate() {
            for ai in &block.instrs {
                for (var, size) in defs_of(&ai.instr) {
                    def_blocks.entry(var.clone()).or_default().push(bi);
                    var_size.entry(var).or_insert(size);
                }
            }
        }

        // 2. Phi placement via iterated dominance frontiers.
        let mut blocks: Vec<SsaBlock> = vec![SsaBlock::default(); n];
        let mut vars: Vec<&LlilRegister> = def_blocks.keys().collect();
        vars.sort_by_key(|v| v.name()); // deterministic
        for var in vars {
            let mut has_phi = vec![false; n];
            let mut work: Vec<usize> = def_blocks[var].clone();
            let mut on_work = vec![false; n];
            for &b in &work {
                on_work[b] = true;
            }
            while let Some(b) = work.pop() {
                if dom.idom[b].is_none() && b != dom.entry {
                    continue; // unreachable
                }
                for &f in &dom.frontiers[b] {
                    if !has_phi[f] {
                        has_phi[f] = true;
                        blocks[f].phis.push(SsaPhi {
                            var: var.clone(),
                            dest: 0, // filled during renaming
                            args: Vec::new(),
                            size: var_size.get(var).copied().unwrap_or(Size::QWord),
                        });
                        if !on_work[f] {
                            on_work[f] = true;
                            work.push(f);
                        }
                    }
                }
            }
        }

        // 3. Renaming via dominator-tree DFS.
        //    Version 0 is the implicit "live on entry" definition of every
        //    variable, so uses before any def rename to `base#0`.
        let mut counter: HashMap<LlilRegister, u32> = HashMap::new();
        let mut stacks: HashMap<LlilRegister, Vec<u32>> = HashMap::new();
        let top = |stacks: &HashMap<LlilRegister, Vec<u32>>, v: &LlilRegister| -> u32 {
            stacks.get(v).and_then(|s| s.last().copied()).unwrap_or(0)
        };

        // Iterative DFS: (block, phase). Phase 0 = enter, 1 = exit.
        enum Step {
            Enter(usize),
            Exit(Vec<LlilRegister>), // vars whose stacks to pop (one entry per push)
        }
        let mut agenda = vec![Step::Enter(dom.entry)];
        while let Some(step) = agenda.pop() {
            match step {
                Step::Enter(b) => {
                    let mut pushed: Vec<LlilRegister> = Vec::new();

                    // Phi destinations define new versions.
                    for pi in 0..blocks[b].phis.len() {
                        let var = blocks[b].phis[pi].var.clone();
                        let c = counter.entry(var.clone()).or_insert(0);
                        *c += 1;
                        let ver = *c;
                        blocks[b].phis[pi].dest = ver;
                        stacks.entry(var.clone()).or_default().push(ver);
                        pushed.push(var);
                    }

                    // Instructions: rename uses, then defs.
                    for (ii, ai) in func.blocks[b].instrs.iter().enumerate() {
                        let renamed_uses = rewrite_instr_uses(&ai.instr, &mut |v, size| {
                            LlilExpr::RegisterRef {
                                reg: LlilRegister::Concrete(ssa_name(v, top(&stacks, v))),
                                size,
                            }
                        });
                        let renamed = rewrite_instr_defs(renamed_uses, &mut |v| {
                            let c = counter.entry(v.clone()).or_insert(0);
                            *c += 1;
                            let ver = *c;
                            stacks.entry(v.clone()).or_default().push(ver);
                            pushed.push(v.clone());
                            ssa_name(v, ver)
                        });
                        blocks[b].instrs.push(SsaInstr {
                            orig: (b, ii),
                            instr: renamed,
                        });
                    }

                    // Fill phi args in successors.
                    for &s in &cfg.succs[b] {
                        for phi in &mut blocks[s].phis {
                            let ver = top(&stacks, &phi.var);
                            phi.args.push((b, ver));
                        }
                    }

                    agenda.push(Step::Exit(pushed));
                    for &c in dom.children[b].iter().rev() {
                        agenda.push(Step::Enter(c));
                    }
                }
                Step::Exit(pushed) => {
                    for v in pushed.into_iter().rev() {
                        if let Some(s) = stacks.get_mut(&v) {
                            s.pop();
                        }
                    }
                }
            }
        }

        Self { blocks, cfg, dom }
    }

    /// Total number of phi nodes in the function.
    #[must_use]
    pub fn phi_count(&self) -> usize {
        self.blocks.iter().map(|b| b.phis.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;
    use rustre_il_llil::{LlilAnnotatedInstr, LlilBasicBlock, llil_const, llil_reg};

    fn block(id: u32, start: u64, instrs: Vec<LlilInstruction>) -> LlilBasicBlock {
        LlilBasicBlock {
            start: Address::new(start),
            end: Address::new(start),
            instrs: instrs
                .into_iter()
                .map(|instr| LlilAnnotatedInstr {
                    address: Address::new(start),
                    size: 1,
                    instr,
                    length: 1,
                })
                .collect(),
            id,
            successors: Vec::new(),
        }
    }

    fn set(reg: &str, value: LlilExpr) -> LlilInstruction {
        LlilInstruction::SetReg {
            dest: reg.into(),
            size: Size::QWord,
            value,
        }
    }

    /// Diamond assigning rax differently on each arm, then using it.
    fn diamond_func() -> LlilFunction {
        let mut f = LlilFunction::new(Address::new(0x100));
        f.blocks = vec![
            block(
                0,
                0x100,
                vec![
                    set("rax", llil_const(0, Size::QWord)),
                    LlilInstruction::CondJump {
                        cond: llil_reg("rcx", Size::QWord),
                        true_dest: Address::new(0x200),
                        false_dest: Address::new(0x300),
                    },
                ],
            ),
            block(
                1,
                0x200,
                vec![
                    set("rax", llil_const(1, Size::QWord)),
                    LlilInstruction::JumpDest {
                        dest: llil_const(0x400, Size::QWord),
                    },
                ],
            ),
            block(
                2,
                0x300,
                vec![
                    set("rax", llil_const(2, Size::QWord)),
                    LlilInstruction::JumpDest {
                        dest: llil_const(0x400, Size::QWord),
                    },
                ],
            ),
            block(
                3,
                0x400,
                vec![
                    set("rbx", llil_reg("rax", Size::QWord)),
                    LlilInstruction::Ret,
                ],
            ),
        ];
        f
    }

    #[test]
    fn phi_placed_at_join() {
        let f = diamond_func();
        let ssa = SsaFunction::build(&f);
        assert_eq!(ssa.phi_count(), 1);
        let phi = &ssa.blocks[3].phis[0];
        assert_eq!(phi.var, LlilRegister::Concrete("rax".into()));
        assert_eq!(phi.args.len(), 2);
        // Arms defined versions 2 and 3 (entry def was version 1).
        let mut versions: Vec<u32> = phi.args.iter().map(|&(_, v)| v).collect();
        versions.sort_unstable();
        assert_eq!(versions, vec![2, 3]);
        // The use in block 3 refers to the phi's dest.
        let use_instr = &ssa.blocks[3].instrs[0].instr;
        if let LlilInstruction::SetReg { value, .. } = use_instr {
            assert_eq!(
                *value,
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(phi.dest_name()),
                    size: Size::QWord
                }
            );
        } else {
            panic!("expected SetReg, got {use_instr:?}");
        }
    }

    #[test]
    fn straight_line_versions_increment() {
        let mut f = LlilFunction::new(Address::new(0x0));
        f.blocks = vec![block(
            0,
            0x0,
            vec![
                set("rax", llil_const(1, Size::QWord)),
                set("rax", llil_reg("rax", Size::QWord)),
                LlilInstruction::Ret,
            ],
        )];
        let ssa = SsaFunction::build(&f);
        assert_eq!(ssa.phi_count(), 0);
        let b = &ssa.blocks[0];
        // First def is rax#1; second reads rax#1 and defines rax#2.
        if let LlilInstruction::SetReg { dest, .. } = &b.instrs[0].instr {
            assert_eq!(dest.name(), "rax#1");
        } else {
            panic!()
        }
        if let LlilInstruction::SetReg { dest, value, .. } = &b.instrs[1].instr {
            assert_eq!(dest.name(), "rax#2");
            assert_eq!(
                *value,
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("rax#1".into()),
                    size: Size::QWord
                }
            );
        } else {
            panic!()
        }
    }

    #[test]
    fn use_before_def_gets_version_zero() {
        let mut f = LlilFunction::new(Address::new(0x0));
        f.blocks = vec![block(
            0,
            0x0,
            vec![
                set("rbx", llil_reg("rdi", Size::QWord)), // parameter read
                LlilInstruction::Ret,
            ],
        )];
        let ssa = SsaFunction::build(&f);
        if let LlilInstruction::SetReg { value, .. } = &ssa.blocks[0].instrs[0].instr {
            assert_eq!(
                *value,
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("rdi#0".into()),
                    size: Size::QWord
                }
            );
        } else {
            panic!()
        }
    }

    #[test]
    fn loop_gets_phi_at_header() {
        // 0: i = 0 -> 1 ; 1: i = i + 1, condjump 1 / 2 ; 2: ret.
        let mut f = LlilFunction::new(Address::new(0x0));
        f.blocks = vec![
            block(
                0,
                0x0,
                vec![
                    set("i", llil_const(0, Size::QWord)),
                    LlilInstruction::JumpDest {
                        dest: llil_const(0x10, Size::QWord),
                    },
                ],
            ),
            block(
                1,
                0x10,
                vec![
                    set(
                        "i",
                        LlilExpr::AddT(
                            Box::new(llil_reg("i", Size::QWord)),
                            Box::new(llil_const(1, Size::QWord)),
                            Size::QWord,
                        ),
                    ),
                    LlilInstruction::CondJump {
                        cond: llil_reg("i", Size::QWord),
                        true_dest: Address::new(0x10),
                        false_dest: Address::new(0x20),
                    },
                ],
            ),
            block(2, 0x20, vec![LlilInstruction::Ret]),
        ];
        let ssa = SsaFunction::build(&f);
        assert_eq!(ssa.blocks[1].phis.len(), 1);
        let phi = &ssa.blocks[1].phis[0];
        assert_eq!(phi.var.name(), "i");
        assert_eq!(phi.args.len(), 2);
        // One arg from block 0, one from the latch (block 1 itself).
        let preds: Vec<usize> = phi.args.iter().map(|&(p, _)| p).collect();
        assert!(preds.contains(&0) && preds.contains(&1));
    }

    #[test]
    fn ssa_name_roundtrip() {
        let n = ssa_name(&LlilRegister::Concrete("rax".into()), 7);
        assert_eq!(n, "rax#7");
        assert_eq!(split_ssa_name(&n), Some(("rax", 7)));
        assert_eq!(split_ssa_name("plain"), None);
    }
}
