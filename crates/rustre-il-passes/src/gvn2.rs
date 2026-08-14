//! Global value numbering on SSA form ([`crate::ssa`]), subsuming and
//! rebasing global copy propagation, aggressive constant folding, and
//! common-subexpression elimination on the dominator-tree infrastructure
//! ([`crate::dominators`]).
//!
//! Pipeline:
//! 1. Build SSA ([`SsaFunction::build`]).
//! 2. Walk blocks in reverse postorder assigning value numbers:
//!    - constants get canonical constant value numbers (aggressive folding:
//!      any pure operator over constant operands is evaluated, with proper
//!      width masking);
//!    - copies (`x = y`) reuse the source's value number (global copy prop);
//!    - phis whose arguments all agree collapse to the common value number;
//!    - structurally-congruent pure expressions share a value number, with
//!      commutative operand canonicalization (GVN/CSE).
//! 3. Rewrite the SSA overlay: uses of a value that is known constant become
//!    `Const`; redundant computations are replaced by a reference to the
//!    dominating *leader* definition.
//! 4. [`apply_constants`] copies constant-valued register writes back into
//!    the original (non-SSA) [`LlilFunction`], so the rest of the V1 pass
//!    pipeline benefits without needing SSA destruction.
//!
//! Impure or untracked expressions (`Load`, `Undefined`, `Intrinsic`,
//! `Flag`, `StackPointer`, floating-point ops) get fresh, unique value
//! numbers and are never folded or CSE'd.

use std::collections::HashMap;

use rustre_il_llil::{LlilExpr, LlilFunction, LlilInstruction, LlilRegister, Size};

use crate::ssa::{SsaFunction, rewrite_instr_uses};

/// A value number.
pub type ValueId = usize;

/// Statistics from a [`run_gvn2`] run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Gvn2Stats {
    /// Expressions folded to constants.
    pub const_folded: usize,
    /// Register uses rewritten to a dominating equivalent (copy prop + CSE).
    pub replaced_uses: usize,
    /// Phi nodes collapsed to a single incoming value.
    pub phis_collapsed: usize,
}

/// Result of GVN over one function.
#[derive(Debug)]
pub struct Gvn2Result {
    /// The optimized SSA overlay.
    pub ssa: SsaFunction,
    /// SSA name -> known constant value (masked to `size`).
    pub constants: HashMap<String, (u64, Size)>,
    /// Statistics.
    pub stats: Gvn2Stats,
}

#[derive(Default)]
struct ValueTable {
    /// SSA name -> value number.
    of_name: HashMap<String, ValueId>,
    /// Canonical expression key -> value number.
    of_key: HashMap<String, ValueId>,
    /// value number -> constant, if known.
    consts: Vec<Option<(u64, Size)>>,
    /// value number -> leader `(ssa_name, block, size)` for CSE.
    leaders: Vec<Option<(String, usize, Size)>>,
}

impl ValueTable {
    fn fresh(&mut self) -> ValueId {
        self.consts.push(None);
        self.leaders.push(None);
        self.consts.len() - 1
    }

    fn const_vn(&mut self, value: u64, size: Size) -> ValueId {
        let masked = mask(value, size);
        let key = format!("c:{masked}:{}", size.bytes());
        if let Some(&v) = self.of_key.get(&key) {
            return v;
        }
        let v = self.fresh();
        self.consts[v] = Some((masked, size));
        self.of_key.insert(key, v);
        v
    }

    fn name_vn(&mut self, name: &str) -> ValueId {
        if let Some(&v) = self.of_name.get(name) {
            return v;
        }
        let v = self.fresh();
        self.of_name.insert(name.to_owned(), v);
        v
    }
}

/// Masks `v` to the low bits of `size` (sizes wider than 8 bytes keep all 64
/// tracked bits).
const fn mask(v: u64, size: Size) -> u64 {
    match size.bytes() {
        1 => v & 0xff,
        2 => v & 0xffff,
        4 => v & 0xffff_ffff,
        _ => v,
    }
}

const fn sext(v: u64, size: Size) -> i64 {
    match size.bytes() {
        1 => v as u8 as i8 as i64,
        2 => v as u16 as i16 as i64,
        4 => v as u32 as i32 as i64,
        _ => v as i64,
    }
}

/// Folds a binary integer op over constants. Returns `None` for division by
/// zero or non-integer ops.
#[allow(clippy::too_many_lines)]
fn fold_binop(op: &str, a: u64, b: u64, size: Size) -> Option<u64> {
    let bits = size.bits().min(64) as u32;
    // SHL/SHR/SAR: x86 masks the count with a FIXED 5 bits for every operand
    // width below 64 (6 bits at 64), NOT mod-width — AMD APM vol.3 SHL/SHR/SAR.
    // `shl bl, 12` keeps the count 12 and shifts an 8-bit value clean out
    // (result 0); reducing it mod 8 to a shift-by-4 is the exact defect that
    // `ConstantFoldingPass::shift_count_mask` was introduced to remove. This
    // folder is a SECOND, independent constant folder that kept the old rule.
    // The trailing `mask(r, size)` makes the wide shift collapse correctly:
    // `a << 12` masked back to a byte is 0, matching hardware.
    let shift_amt =
        (b & crate::ConstantFoldingPass::shift_count_mask(size)).min(u64::from(u32::MAX)) as u32;
    // ROL/ROR need a DIFFERENT amount: the rotate below computes
    // `(m << amt) | (m >> (bits - amt))`, which underflows if `amt >= bits`.
    // Rotates are genuinely mod-width, and applying the 5-/6-bit mask first is
    // equivalent to plain mod-width here (32 is a multiple of 8, 16 and 32; 64
    // of itself), so this stays as it was — deliberately NOT unified with
    // `shift_amt`, which would make the rotate arms panic on `bits - amt`.
    let rot_amt = (b % u64::from(bits.max(1))) as u32;
    let r = match op {
        "add" => a.wrapping_add(b),
        "sub" => a.wrapping_sub(b),
        "mul" => a.wrapping_mul(b),
        "divu" => {
            if mask(b, size) == 0 {
                return None;
            }
            mask(a, size) / mask(b, size)
        }
        "divs" => {
            let (sa, sb) = (sext(a, size), sext(b, size));
            if sb == 0 {
                return None;
            }
            sa.wrapping_div(sb) as u64
        }
        "modu" => {
            if mask(b, size) == 0 {
                return None;
            }
            mask(a, size) % mask(b, size)
        }
        "mods" => {
            let (sa, sb) = (sext(a, size), sext(b, size));
            if sb == 0 {
                return None;
            }
            sa.wrapping_rem(sb) as u64
        }
        "and" => a & b,
        "or" => a | b,
        "xor" => a ^ b,
        "shl" => mask(a, size).checked_shl(shift_amt).unwrap_or(0),
        "shr" => mask(a, size).checked_shr(shift_amt).unwrap_or(0),
        "sar" => (sext(a, size) >> shift_amt.min(63)) as u64,
        "rol" => {
            let m = mask(a, size);
            if rot_amt == 0 {
                m
            } else {
                (m << rot_amt) | (m >> (bits - rot_amt))
            }
        }
        "ror" => {
            let m = mask(a, size);
            if rot_amt == 0 {
                m
            } else {
                (m >> rot_amt) | (m << (bits - rot_amt))
            }
        }
        "cmpeq" => u64::from(mask(a, size) == mask(b, size)),
        "cmpne" => u64::from(mask(a, size) != mask(b, size)),
        "cmpslt" => u64::from(sext(a, size) < sext(b, size)),
        "cmpult" => u64::from(mask(a, size) < mask(b, size)),
        "cmpsle" => u64::from(sext(a, size) <= sext(b, size)),
        "cmpule" => u64::from(mask(a, size) <= mask(b, size)),
        "cmpsgt" => u64::from(sext(a, size) > sext(b, size)),
        "cmpugt" => u64::from(mask(a, size) > mask(b, size)),
        "cmpsge" => u64::from(sext(a, size) >= sext(b, size)),
        "cmpuge" => u64::from(mask(a, size) >= mask(b, size)),
        _ => return None,
    };
    Some(mask(r, size))
}

const COMMUTATIVE: &[&str] = &["add", "mul", "and", "or", "xor", "cmpeq", "cmpne"];

/// Recursively computes the value number of `expr`.
///
/// Pure integer expressions are canonicalized/folded; anything impure or
/// untracked yields a fresh unique value number.
fn vn_expr(t: &mut ValueTable, expr: &LlilExpr) -> ValueId {
    // Decompose into (op, operands, size, result_size_for_cmp).
    let (op, operands, size): (&str, Vec<&LlilExpr>, Size) = match expr {
        LlilExpr::Const { value, size } => return t.const_vn(*value, *size),
        LlilExpr::RegisterRef { reg, .. } => return t.name_vn(&reg.name()),
        LlilExpr::Register { id, .. } => return t.name_vn(&format!("vreg{id}")),
        LlilExpr::AddT(a, b, s) | LlilExpr::Add { left: a, right: b, size: s } => {
            ("add", vec![a, b], *s)
        }
        LlilExpr::SubT(a, b, s) | LlilExpr::Sub { left: a, right: b, size: s } => {
            ("sub", vec![a, b], *s)
        }
        LlilExpr::MulT(a, b, s) | LlilExpr::Mul { left: a, right: b, size: s } => {
            ("mul", vec![a, b], *s)
        }
        LlilExpr::DivU(a, b, s) => ("divu", vec![a, b], *s),
        LlilExpr::DivS(a, b, s) => ("divs", vec![a, b], *s),
        LlilExpr::ModU(a, b, s) => ("modu", vec![a, b], *s),
        LlilExpr::ModS(a, b, s) => ("mods", vec![a, b], *s),
        LlilExpr::And(a, b, s) => ("and", vec![a, b], *s),
        LlilExpr::Or(a, b, s) => ("or", vec![a, b], *s),
        LlilExpr::Xor(a, b, s) => ("xor", vec![a, b], *s),
        LlilExpr::ShlT(a, b, s) | LlilExpr::Shl { value: a, shift: b, size: s } => {
            ("shl", vec![a, b], *s)
        }
        LlilExpr::Shr(a, b, s) => ("shr", vec![a, b], *s),
        LlilExpr::Sar(a, b, s) => ("sar", vec![a, b], *s),
        LlilExpr::Rol(a, b, s) => ("rol", vec![a, b], *s),
        LlilExpr::Ror(a, b, s) => ("ror", vec![a, b], *s),
        LlilExpr::CmpEq(a, b) => ("cmpeq", vec![a, b], operand_size(a, b)),
        LlilExpr::CmpNe(a, b) => ("cmpne", vec![a, b], operand_size(a, b)),
        LlilExpr::CmpSlt(a, b) => ("cmpslt", vec![a, b], operand_size(a, b)),
        LlilExpr::CmpUlt(a, b) => ("cmpult", vec![a, b], operand_size(a, b)),
        LlilExpr::CmpSle(a, b) => ("cmpsle", vec![a, b], operand_size(a, b)),
        LlilExpr::CmpUle(a, b) => ("cmpule", vec![a, b], operand_size(a, b)),
        LlilExpr::CmpSgt(a, b) => ("cmpsgt", vec![a, b], operand_size(a, b)),
        LlilExpr::CmpUgt(a, b) => ("cmpugt", vec![a, b], operand_size(a, b)),
        LlilExpr::CmpSge(a, b) => ("cmpsge", vec![a, b], operand_size(a, b)),
        LlilExpr::CmpUge(a, b) => ("cmpuge", vec![a, b], operand_size(a, b)),
        LlilExpr::Neg(a, s) => ("neg", vec![a], *s),
        LlilExpr::Not(a, s) => ("not", vec![a], *s),
        LlilExpr::ZeroExtend { expr, to, .. } => ("zx", vec![expr], *to),
        LlilExpr::SignExtend { expr, from, to } => {
            // Fold immediately if the inner value is a known constant.
            let inner = vn_expr(t, expr);
            if let Some((c, _)) = t.consts[inner] {
                return t.const_vn(sext(c, *from) as u64, *to);
            }
            let key = format!("sx:{}:{}:{inner}", from.bytes(), to.bytes());
            return keyed(t, key, None);
        }
        LlilExpr::LowPart { expr, to } => ("low", vec![expr], *to),
        // Impure / untracked: unique value number.
        _ => return t.fresh(),
    };

    let mut ids: Vec<ValueId> = operands.iter().map(|e| vn_expr(t, e)).collect();

    // Aggressive constant folding.
    let const_ops: Vec<Option<(u64, Size)>> = ids.iter().map(|&i| t.consts[i]).collect();
    if const_ops.iter().all(Option::is_some) {
        let folded = match (op, const_ops.len()) {
            ("neg", 1) => Some(mask((const_ops[0].unwrap().0 as i64).wrapping_neg() as u64, size)),
            ("not", 1) => Some(mask(!const_ops[0].unwrap().0, size)),
            ("zx", 1) => Some(mask(const_ops[0].unwrap().0, size)),
            ("low", 1) => Some(mask(const_ops[0].unwrap().0, size)),
            (_, 2) => fold_binop(op, const_ops[0].unwrap().0, const_ops[1].unwrap().0, size),
            _ => None,
        };
        if let Some(v) = folded {
            let out_size = if op.starts_with("cmp") { Size::Byte } else { size };
            return t.const_vn(v, out_size);
        }
    }

    // Commutative canonicalization.
    if COMMUTATIVE.contains(&op) && ids.len() == 2 && ids[0] > ids[1] {
        ids.swap(0, 1);
    }

    let key = format!(
        "{op}:{}:{}",
        size.bytes(),
        ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
    );
    keyed(t, key, None)
}

fn keyed(t: &mut ValueTable, key: String, konst: Option<(u64, Size)>) -> ValueId {
    if let Some(&v) = t.of_key.get(&key) {
        return v;
    }
    let v = t.fresh();
    t.consts[v] = konst;
    t.of_key.insert(key, v);
    v
}

/// Best-effort operand size for a comparison.
fn operand_size(a: &LlilExpr, b: &LlilExpr) -> Size {
    let sa = a.result_size();
    let sb = b.result_size();
    if sa.bytes() >= sb.bytes() { sa } else { sb }
}

/// Names defined by an SSA-renamed instruction.
fn ssa_defs(instr: &LlilInstruction) -> Vec<(String, Size)> {
    match instr {
        LlilInstruction::SetReg { dest, size, .. }
        | LlilInstruction::Load { dest, size, .. }
        | LlilInstruction::Pop { dest, size } => vec![(dest.name(), *size)],
        LlilInstruction::SetRegSplit { high, low, src } => {
            let s = src.result_size();
            vec![(high.name(), s), (low.name(), s)]
        }
        _ => Vec::new(),
    }
}

/// Runs GVN (with constant folding, copy propagation, and CSE) over `func`.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run_gvn2(func: &LlilFunction) -> Gvn2Result {
    let mut ssa = SsaFunction::build(func);
    let mut t = ValueTable::default();
    let mut stats = Gvn2Stats::default();

    let rpo = ssa.dom.rpo.clone();
    for &b in &rpo {
        // Phis first: collapse if all (known) args agree.
        for pi in 0..ssa.blocks[b].phis.len() {
            let phi = &ssa.blocks[b].phis[pi];
            let dest_name = phi.dest_name();
            let arg_vns: Vec<Option<ValueId>> = phi
                .args
                .iter()
                .map(|&(_, ver)| {
                    let n = crate::ssa::ssa_name(&phi.var, ver);
                    t.of_name.get(&n).copied()
                })
                .collect();
            let vn = if !arg_vns.is_empty()
                && arg_vns.iter().all(|v| v.is_some() && *v == arg_vns[0])
            {
                stats.phis_collapsed += 1;
                arg_vns[0].unwrap()
            } else {
                t.fresh()
            };
            t.of_name.insert(dest_name.clone(), vn);
            if t.leaders[vn].is_none() {
                t.leaders[vn] = Some((dest_name, b, ssa.blocks[b].phis[pi].size));
            }
        }

        for ii in 0..ssa.blocks[b].instrs.len() {
            let instr = ssa.blocks[b].instrs[ii].instr.clone();

            // Rewrite uses: constant values become Const; other values with a
            // dominating leader of a different name become a read of the leader.
            let dom = &ssa.dom;
            let rewritten = rewrite_instr_uses(&instr, &mut |reg, size| {
                let name = reg.name();
                let orig = LlilExpr::RegisterRef {
                    reg: reg.clone(),
                    size,
                };
                let Some(&vn) = t.of_name.get(&name) else {
                    return orig;
                };
                if let Some((c, _)) = t.consts[vn] {
                    stats.const_folded += 1;
                    return LlilExpr::Const {
                        value: mask(c, size),
                        size,
                    };
                }
                if let Some((leader, lb, _)) = &t.leaders[vn]
                    && *leader != name
                    && dom.dominates(*lb, b)
                {
                    stats.replaced_uses += 1;
                    return LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete(leader.clone()),
                        size,
                    };
                }
                orig
            });

            // Value-number and possibly simplify the defining expression.
            let final_instr = if let LlilInstruction::SetReg { dest, size, value } = &rewritten {
                let vn = vn_expr(&mut t, value);
                let dest_name = dest.name();
                t.of_name.insert(dest_name.clone(), vn);
                // A live-on-entry source (version 0) is the natural leader
                // for its value: its "definition" is the function entry,
                // which dominates every block.
                if t.leaders[vn].is_none()
                    && let LlilExpr::RegisterRef { reg, .. } = value
                    && reg.name().ends_with("#0")
                {
                    t.leaders[vn] = Some((reg.name(), ssa.dom.entry, *size));
                }
                let new_value = if let Some((c, _)) = t.consts[vn] {
                    let cexpr = LlilExpr::Const {
                        value: mask(c, *size),
                        size: *size,
                    };
                    if *value != cexpr {
                        stats.const_folded += 1;
                    }
                    cexpr
                } else if let Some((leader, lb, _)) = &t.leaders[vn] {
                    // CSE: reuse the dominating leader if this is a real
                    // recomputation (not already a plain copy of it).
                    let leader_read = LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete(leader.clone()),
                        size: *size,
                    };
                    if *leader != dest_name && ssa.dom.dominates(*lb, b) && *value != leader_read {
                        stats.replaced_uses += 1;
                        leader_read
                    } else {
                        value.clone()
                    }
                } else {
                    value.clone()
                };
                if t.leaders[vn].is_none() {
                    t.leaders[vn] = Some((dest_name, b, *size));
                }
                LlilInstruction::SetReg {
                    dest: dest.clone(),
                    size: *size,
                    value: new_value,
                }
            } else {
                // Other defs (Load/Pop/SetRegSplit) produce opaque values.
                for (name, size) in ssa_defs(&rewritten) {
                    let vn = t.fresh();
                    t.of_name.insert(name.clone(), vn);
                    t.leaders[vn] = Some((name, b, size));
                }
                rewritten
            };
            ssa.blocks[b].instrs[ii].instr = final_instr;
        }
    }

    // Export SSA-name -> constant map.
    let mut constants = HashMap::new();
    for (name, &vn) in &t.of_name {
        if let Some((c, s)) = t.consts[vn] {
            constants.insert(name.clone(), (c, s));
        }
    }

    Gvn2Result {
        ssa,
        constants,
        stats,
    }
}

/// Applies GVN's constant results back onto the original (non-SSA) function:
/// every `SetReg` whose SSA definition was proven constant has its value
/// expression replaced by that constant. Returns the number of rewrites.
pub fn apply_constants(func: &mut LlilFunction, result: &Gvn2Result) -> usize {
    let mut n = 0;
    for block in &result.ssa.blocks {
        for si in &block.instrs {
            let LlilInstruction::SetReg { dest, size, .. } = &si.instr else {
                continue;
            };
            let Some(&(c, _)) = result.constants.get(&dest.name()) else {
                continue;
            };
            let (bi, ii) = si.orig;
            if let Some(orig) = func
                .blocks
                .get_mut(bi)
                .and_then(|blk| blk.instrs.get_mut(ii))
                && let LlilInstruction::SetReg { value, size: osz, .. } = &mut orig.instr
            {
                let cexpr = LlilExpr::Const {
                    value: mask(c, *osz),
                    size: *size,
                };
                if *value != cexpr {
                    *value = LlilExpr::Const {
                        value: mask(c, *osz),
                        size: *osz,
                    };
                    n += 1;
                }
            }
        }
    }
    n
}

/// Convenience wrapper: run GVN and fold proven constants back into `func`.
/// Returns `(stats, constants_applied)`.
pub fn run_gvn2_and_apply(func: &mut LlilFunction) -> (Gvn2Stats, usize) {
    let result = run_gvn2(func);
    let applied = apply_constants(func, &result);
    (result.stats, applied)
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

    fn add(a: LlilExpr, b: LlilExpr) -> LlilExpr {
        LlilExpr::AddT(Box::new(a), Box::new(b), Size::QWord)
    }

    #[test]
    fn folds_constant_chain() {
        // a = 2; b = 3; c = a + b; d = c * c  =>  c = 5, d = 25.
        let mut f = LlilFunction::new(Address::new(0x0));
        f.blocks = vec![block(
            0,
            0x0,
            vec![
                set("a", llil_const(2, Size::QWord)),
                set("b", llil_const(3, Size::QWord)),
                set(
                    "c",
                    add(llil_reg("a", Size::QWord), llil_reg("b", Size::QWord)),
                ),
                set(
                    "d",
                    LlilExpr::MulT(
                        Box::new(llil_reg("c", Size::QWord)),
                        Box::new(llil_reg("c", Size::QWord)),
                        Size::QWord,
                    ),
                ),
                LlilInstruction::Ret,
            ],
        )];
        let (stats, applied) = run_gvn2_and_apply(&mut f);
        assert!(stats.const_folded > 0);
        assert_eq!(applied, 2); // c and d rewritten
        let vals: Vec<&LlilExpr> = f.blocks[0]
            .instrs
            .iter()
            .filter_map(|i| match &i.instr {
                LlilInstruction::SetReg { value, .. } => Some(value),
                _ => None,
            })
            .collect();
        assert_eq!(*vals[2], llil_const(5, Size::QWord));
        assert_eq!(*vals[3], llil_const(25, Size::QWord));
    }

    #[test]
    fn cse_reuses_dominating_computation() {
        // x = p + q; y = p + q  => y = x (SSA-level).
        let mut f = LlilFunction::new(Address::new(0x0));
        f.blocks = vec![block(
            0,
            0x0,
            vec![
                set(
                    "x",
                    add(llil_reg("p", Size::QWord), llil_reg("q", Size::QWord)),
                ),
                set(
                    "y",
                    add(llil_reg("p", Size::QWord), llil_reg("q", Size::QWord)),
                ),
                LlilInstruction::Ret,
            ],
        )];
        let r = run_gvn2(&f);
        assert!(r.stats.replaced_uses >= 1);
        if let LlilInstruction::SetReg { value, .. } = &r.ssa.blocks[0].instrs[1].instr {
            assert_eq!(
                *value,
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("x#1".into()),
                    size: Size::QWord
                }
            );
        } else {
            panic!()
        }
    }

    #[test]
    fn copy_prop_through_chain() {
        // a = p; b = a; c = b  => c's value has same VN as p.
        let mut f = LlilFunction::new(Address::new(0x0));
        f.blocks = vec![block(
            0,
            0x0,
            vec![
                set("a", llil_reg("p", Size::QWord)),
                set("b", llil_reg("a", Size::QWord)),
                set("c", llil_reg("b", Size::QWord)),
                LlilInstruction::Ret,
            ],
        )];
        let r = run_gvn2(&f);
        // b's and c's defs should read the leader (p#0).
        if let LlilInstruction::SetReg { value, .. } = &r.ssa.blocks[0].instrs[2].instr {
            assert_eq!(
                *value,
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("p#0".into()),
                    size: Size::QWord
                }
            );
        } else {
            panic!()
        }
    }

    #[test]
    fn constant_flows_across_blocks() {
        // Block 0: a = 7, jump block 1. Block 1: b = a + 1 => 8.
        let mut f = LlilFunction::new(Address::new(0x0));
        f.blocks = vec![
            block(
                0,
                0x0,
                vec![
                    set("a", llil_const(7, Size::QWord)),
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
                        "b",
                        add(llil_reg("a", Size::QWord), llil_const(1, Size::QWord)),
                    ),
                    LlilInstruction::Ret,
                ],
            ),
        ];
        let (_, applied) = run_gvn2_and_apply(&mut f);
        assert_eq!(applied, 1);
        if let LlilInstruction::SetReg { value, .. } = &f.blocks[1].instrs[0].instr {
            assert_eq!(*value, llil_const(8, Size::QWord));
        } else {
            panic!()
        }
    }

    #[test]
    fn phi_of_equal_values_collapses() {
        // Diamond: both arms set x = 5; join uses x -> constant 5.
        let mut f = LlilFunction::new(Address::new(0x0));
        f.blocks = vec![
            block(
                0,
                0x0,
                vec![LlilInstruction::CondJump {
                    cond: llil_reg("rcx", Size::QWord),
                    true_dest: Address::new(0x10),
                    false_dest: Address::new(0x20),
                }],
            ),
            block(
                1,
                0x10,
                vec![
                    set("x", llil_const(5, Size::QWord)),
                    LlilInstruction::JumpDest {
                        dest: llil_const(0x30, Size::QWord),
                    },
                ],
            ),
            block(
                2,
                0x20,
                vec![
                    set("x", llil_const(5, Size::QWord)),
                    LlilInstruction::JumpDest {
                        dest: llil_const(0x30, Size::QWord),
                    },
                ],
            ),
            block(
                3,
                0x30,
                vec![
                    set(
                        "y",
                        add(llil_reg("x", Size::QWord), llil_const(1, Size::QWord)),
                    ),
                    LlilInstruction::Ret,
                ],
            ),
        ];
        let (stats, applied) = run_gvn2_and_apply(&mut f);
        assert_eq!(stats.phis_collapsed, 1);
        assert_eq!(applied, 1);
        if let LlilInstruction::SetReg { value, .. } = &f.blocks[3].instrs[0].instr {
            assert_eq!(*value, llil_const(6, Size::QWord));
        } else {
            panic!()
        }
    }

    #[test]
    fn phi_of_different_values_does_not_fold() {
        let mut f = LlilFunction::new(Address::new(0x0));
        f.blocks = vec![
            block(
                0,
                0x0,
                vec![LlilInstruction::CondJump {
                    cond: llil_reg("rcx", Size::QWord),
                    true_dest: Address::new(0x10),
                    false_dest: Address::new(0x20),
                }],
            ),
            block(
                1,
                0x10,
                vec![
                    set("x", llil_const(5, Size::QWord)),
                    LlilInstruction::JumpDest {
                        dest: llil_const(0x30, Size::QWord),
                    },
                ],
            ),
            block(
                2,
                0x20,
                vec![
                    set("x", llil_const(9, Size::QWord)),
                    LlilInstruction::JumpDest {
                        dest: llil_const(0x30, Size::QWord),
                    },
                ],
            ),
            block(
                3,
                0x30,
                vec![set("y", llil_reg("x", Size::QWord)), LlilInstruction::Ret],
            ),
        ];
        let (stats, applied) = run_gvn2_and_apply(&mut f);
        assert_eq!(stats.phis_collapsed, 0);
        assert_eq!(applied, 0);
        // y must NOT have been folded to a constant.
        if let LlilInstruction::SetReg { value, .. } = &f.blocks[3].instrs[0].instr {
            assert!(value.is_const().is_none());
        } else {
            panic!()
        }
    }

    #[test]
    fn commutative_canonicalization() {
        // x = p + q; y = q + p  => same value number.
        let mut f = LlilFunction::new(Address::new(0x0));
        f.blocks = vec![block(
            0,
            0x0,
            vec![
                set(
                    "x",
                    add(llil_reg("p", Size::QWord), llil_reg("q", Size::QWord)),
                ),
                set(
                    "y",
                    add(llil_reg("q", Size::QWord), llil_reg("p", Size::QWord)),
                ),
                LlilInstruction::Ret,
            ],
        )];
        let r = run_gvn2(&f);
        assert!(r.stats.replaced_uses >= 1);
    }

    #[test]
    fn width_masking_on_fold() {
        // 8-bit: 200 + 100 = 300 -> 44.
        let mut f = LlilFunction::new(Address::new(0x0));
        f.blocks = vec![block(
            0,
            0x0,
            vec![
                LlilInstruction::SetReg {
                    dest: "al".into(),
                    size: Size::Byte,
                    value: LlilExpr::AddT(
                        Box::new(llil_const(200, Size::Byte)),
                        Box::new(llil_const(100, Size::Byte)),
                        Size::Byte,
                    ),
                },
                LlilInstruction::Ret,
            ],
        )];
        let (_, applied) = run_gvn2_and_apply(&mut f);
        assert_eq!(applied, 1);
        if let LlilInstruction::SetReg { value, .. } = &f.blocks[0].instrs[0].instr {
            assert_eq!(value.is_const(), Some(44));
        } else {
            panic!()
        }
    }

    #[test]
    fn division_by_zero_not_folded() {
        let mut f = LlilFunction::new(Address::new(0x0));
        f.blocks = vec![block(
            0,
            0x0,
            vec![
                set(
                    "x",
                    LlilExpr::DivU(
                        Box::new(llil_const(10, Size::QWord)),
                        Box::new(llil_const(0, Size::QWord)),
                        Size::QWord,
                    ),
                ),
                LlilInstruction::Ret,
            ],
        )];
        let (_, applied) = run_gvn2_and_apply(&mut f);
        assert_eq!(applied, 0);
    }

    #[test]
    fn loads_never_cse() {
        // Two identical loads must stay distinct (memory may change).
        let mem = || LlilExpr::Load {
            addr: Box::new(llil_reg("p", Size::QWord)),
            size: Size::QWord,
        };
        let mut f = LlilFunction::new(Address::new(0x0));
        f.blocks = vec![block(
            0,
            0x0,
            vec![
                set("x", mem()),
                LlilInstruction::Store {
                    addr: llil_reg("p", Size::QWord),
                    size: Size::QWord,
                    value: llil_const(0, Size::QWord),
                },
                set("y", mem()),
                LlilInstruction::Ret,
            ],
        )];
        let r = run_gvn2(&f);
        // y's def must still be a Load, not a copy of x.
        if let LlilInstruction::SetReg { value, .. } = &r.ssa.blocks[0].instrs[2].instr {
            assert!(matches!(value, LlilExpr::Load { .. }));
        } else {
            panic!()
        }
    }

    /// `fold_binop` is a SECOND constant folder, independent of
    /// `ConstantFoldingPass::fold_binop`. It kept the mod-width shift-count
    /// rule that the 2026-07-20 sweep replaced everywhere else, so the two
    /// folders disagreed with each other and with hardware.
    ///
    /// AMD APM vol.3 SHL/SHR/SAR: the count is masked with a FIXED 5 bits at
    /// every operand width below 64 (6 bits at 64) — it is NOT reduced mod the
    /// operand width. Rotates are the opposite: they really are mod-width, and
    /// must stay that way or `bits - amt` underflows.
    #[test]
    fn fold_binop_masks_shift_counts_per_apm_but_keeps_rotates_mod_width() {
        // `shl bl, 12`: count stays 12 (5-bit mask), an 8-bit value shifted by
        // 12 loses every bit. Mod-width would have folded this to `a << 4`.
        assert_eq!(
            fold_binop("shl", 0x41, 12, Size::Byte),
            Some(0),
            "8-bit shl by 12 must clear the value, not wrap to a shift by 4"
        );
        // `shr bl, 12` likewise.
        assert_eq!(fold_binop("shr", 0x80, 12, Size::Byte), Some(0));
        // `sar bl, 12` on a negative byte fills with sign bits.
        assert_eq!(fold_binop("sar", 0x80, 12, Size::Byte), Some(0xff));
        // 32-bit shl by 32 masks to 0 -> value unchanged.
        assert_eq!(
            fold_binop("shl", 0x1234_5678, 32, Size::DWord),
            Some(0x1234_5678),
            "count 32 masks to 0 at 32-bit width"
        );
        // 64-bit uses the 6-bit mask: 64 -> 0.
        assert_eq!(fold_binop("shl", 0xdead_beef, 64, Size::QWord), Some(0xdead_beef));

        // Rotates stay mod-width. `rol bl, 12` == rol by 4, and must not panic
        // on `bits - amt`.
        assert_eq!(
            fold_binop("rol", 0x81, 12, Size::Byte),
            Some(0x18),
            "8-bit rol by 12 is a rotate by 4"
        );
        assert_eq!(fold_binop("ror", 0x81, 12, Size::Byte), Some(0x18));
        // A count far beyond the width must not underflow either.
        assert!(fold_binop("rol", 0x81, 0x21, Size::Byte).is_some());
    }
}
