//! Direct mnemonic → LLIL semantics for `x86_64` opcodes that the upstream
//! `rustre-il-lift` x86 dispatch does not yet model.
//!
//! Each lifter takes already-decoded operands as `LlilExpr` / `LlilRegister`
//! values and emits one or more [`LlilInstruction`]s.  The intent is that the
//! upstream dispatcher (or a future replacement inside this crate) can call
//! these helpers once it has resolved the operand forms for a given encoding.
//!
//! The split between LLIL primitive and `Intrinsic`:
//!   * primitives are used when the operation maps directly onto an existing
//!     [`LlilExpr`] arithmetic / bitwise / shift node
//!     (`bswap`, `xchg`, `xadd`, `cmpxchg`, `bt`/`bts`/`btr`/`btc`, `andn`,
//!     `bextr`, `movbe`, string ops, prefetch as a no-op marker via
//!     intrinsic);
//!   * intrinsics carry the architectural semantics that LLIL cannot express
//!     natively (`popcnt`, `lzcnt`, `tzcnt`, `pdep`, `pext`, `crc32`,
//!     `pextrd`, `pinsrd`).
//!
//! **Status: currently unreferenced.** Reconfirmed by workspace-wide grep
//! (2026-07-12): nothing outside this file calls into these helpers — the
//! upstream `rustre-il-lift` x86 dispatcher has not yet been wired to use
//! them. This module is intentionally kept (not deleted) pending that
//! dispatcher integration; treat it as a staged/pending implementation, not
//! dead code to remove.

use crate::{LlilExpr, LlilInstruction, LlilRegister, Size};

/// Helper: read a register as an expression at the canonical operand size.
#[must_use]
pub fn reg(name: &str, size: Size) -> LlilExpr {
    LlilExpr::RegisterRef {
        reg: LlilRegister::Concrete(name.to_string()),
        size,
    }
}

#[must_use]
const fn cst(v: u64, size: Size) -> LlilExpr {
    LlilExpr::Const { value: v, size }
}

#[must_use]
fn intrinsic_expr(name: &str, args: Vec<LlilExpr>, result_size: Size) -> LlilExpr {
    LlilExpr::Intrinsic {
        name: name.to_string(),
        args,
        result_size,
    }
}

#[must_use]
fn set_reg(dest: &str, size: Size, value: LlilExpr) -> LlilInstruction {
    LlilInstruction::SetReg {
        dest: LlilRegister::Concrete(dest.to_string()),
        size,
        value,
    }
}

#[must_use]
fn set_flag(name: &str, src: LlilExpr) -> LlilInstruction {
    LlilInstruction::SetFlag {
        name: name.to_string(),
        src,
    }
}

// ── bit-test family ─────────────────────────────────────────────────────────

/// Compute the carry-flag source for `BT/BTS/BTR/BTC base, bit`:
/// `CF = (base >> (bit % width)) & 1`.
fn bit_test_cf(base: LlilExpr, bit: LlilExpr, size: Size) -> LlilExpr {
    let width = match size {
        Size::Byte => 8u64,
        Size::Word => 16,
        Size::DWord => 32,
        // bit-test family only ever operates on GPR widths; vector widths
        // (OWord/YWord/ZWord) are not valid operands for BT/BTS/BTR/BTC.
        Size::QWord | Size::OWord | Size::YWord | Size::ZWord => 64,
    };
    let masked = LlilExpr::ModU(
        Box::new(bit),
        Box::new(cst(width, size)),
        size,
    );
    let shifted = LlilExpr::Shr(Box::new(base), Box::new(masked), size);
    LlilExpr::And(Box::new(shifted), Box::new(cst(1, size)), size)
}

#[must_use]
pub fn lift_bt(base_reg: &str, bit: LlilExpr, size: Size) -> Vec<LlilInstruction> {
    vec![set_flag("carry", bit_test_cf(reg(base_reg, size), bit, size))]
}

#[must_use]
pub fn lift_bts(base_reg: &str, bit: LlilExpr, size: Size) -> Vec<LlilInstruction> {
    let width = size_bits(size);
    let bit_idx = LlilExpr::ModU(Box::new(bit.clone()), Box::new(cst(width, size)), size);
    let mask = LlilExpr::ShlT(Box::new(cst(1, size)), Box::new(bit_idx), size);
    vec![
        set_flag("carry", bit_test_cf(reg(base_reg, size), bit, size)),
        set_reg(
            base_reg,
            size,
            LlilExpr::Or(Box::new(reg(base_reg, size)), Box::new(mask), size),
        ),
    ]
}

#[must_use]
pub fn lift_btr(base_reg: &str, bit: LlilExpr, size: Size) -> Vec<LlilInstruction> {
    let width = size_bits(size);
    let bit_idx = LlilExpr::ModU(Box::new(bit.clone()), Box::new(cst(width, size)), size);
    let mask = LlilExpr::ShlT(Box::new(cst(1, size)), Box::new(bit_idx), size);
    let nmask = LlilExpr::Not(Box::new(mask), size);
    vec![
        set_flag("carry", bit_test_cf(reg(base_reg, size), bit, size)),
        set_reg(
            base_reg,
            size,
            LlilExpr::And(Box::new(reg(base_reg, size)), Box::new(nmask), size),
        ),
    ]
}

#[must_use]
pub fn lift_btc(base_reg: &str, bit: LlilExpr, size: Size) -> Vec<LlilInstruction> {
    let width = size_bits(size);
    let bit_idx = LlilExpr::ModU(Box::new(bit.clone()), Box::new(cst(width, size)), size);
    let mask = LlilExpr::ShlT(Box::new(cst(1, size)), Box::new(bit_idx), size);
    vec![
        set_flag("carry", bit_test_cf(reg(base_reg, size), bit, size)),
        set_reg(
            base_reg,
            size,
            LlilExpr::Xor(Box::new(reg(base_reg, size)), Box::new(mask), size),
        ),
    ]
}

const fn size_bits(s: Size) -> u64 {
    match s {
        Size::Byte => 8,
        Size::Word => 16,
        Size::DWord => 32,
        // Only GPR widths reach this helper (BSWAP et al.); vector widths
        // (OWord/YWord/ZWord) are not valid operands here.
        Size::QWord | Size::OWord | Size::YWord | Size::ZWord => 64,
    }
}

// ── byte-swap ───────────────────────────────────────────────────────────────

/// `BSWAP r32/r64` — reverse byte order.  Modelled as an intrinsic because
/// LLIL has no byte-reverse primitive.
#[must_use]
pub fn lift_bswap(target_reg: &str, size: Size) -> Vec<LlilInstruction> {
    vec![set_reg(
        target_reg,
        size,
        intrinsic_expr("bswap", vec![reg(target_reg, size)], size),
    )]
}

// ── xchg / xadd / cmpxchg ───────────────────────────────────────────────────

/// `XCHG a, b` — atomic register exchange.  Pure LLIL primitives.
#[must_use]
pub fn lift_xchg(a: &str, b: &str, size: Size) -> Vec<LlilInstruction> {
    let a_val = reg(a, size);
    let b_val = reg(b, size);
    // Snapshot via a temporary register name to make the semantics correct
    // even if the consumer reorders.
    let tmp = "__xchg_tmp";
    vec![
        set_reg(tmp, size, a_val),
        set_reg(a, size, b_val),
        set_reg(b, size, reg(tmp, size)),
    ]
}

/// `XADD dst, src` — exchange-and-add: `tmp = dst + src; src = dst; dst = tmp`.
#[must_use]
pub fn lift_xadd(dst: &str, src: &str, size: Size) -> Vec<LlilInstruction> {
    let sum = LlilExpr::AddT(Box::new(reg(dst, size)), Box::new(reg(src, size)), size);
    vec![
        set_reg("__xadd_tmp", size, sum),
        set_reg(src, size, reg(dst, size)),
        set_reg(dst, size, reg("__xadd_tmp", size)),
    ]
}

/// `CMPXCHG dst, src` — compare `dst` with the accumulator; if equal, write
/// `src` into `dst` and set ZF, else load `dst` into the accumulator and
/// clear ZF.
#[must_use]
pub fn lift_cmpxchg(dst: &str, src: &str, size: Size) -> Vec<LlilInstruction> {
    let acc = match size {
        Size::Byte => "al",
        Size::Word => "ax",
        Size::DWord => "eax",
        _ => "rax",
    };
    let eq = LlilExpr::CmpEq(Box::new(reg(acc, size)), Box::new(reg(dst, size)));
    vec![
        set_flag("zero", eq.clone()),
        set_reg(
            dst,
            size,
            LlilExpr::CondExpr {
                cond: Box::new(eq.clone()),
                true_val: Box::new(reg(src, size)),
                false_val: Box::new(reg(dst, size)),
                size,
            },
        ),
        set_reg(
            acc,
            size,
            LlilExpr::CondExpr {
                cond: Box::new(eq),
                true_val: Box::new(reg(acc, size)),
                false_val: Box::new(reg(dst, size)),
                size,
            },
        ),
    ]
}

// ── bit counts ──────────────────────────────────────────────────────────────

#[must_use]
pub fn lift_popcnt(dst: &str, src: LlilExpr, size: Size) -> Vec<LlilInstruction> {
    vec![set_reg(dst, size, intrinsic_expr("popcnt", vec![src], size))]
}

#[must_use]
pub fn lift_lzcnt(dst: &str, src: LlilExpr, size: Size) -> Vec<LlilInstruction> {
    vec![set_reg(dst, size, intrinsic_expr("lzcnt", vec![src], size))]
}

#[must_use]
pub fn lift_tzcnt(dst: &str, src: LlilExpr, size: Size) -> Vec<LlilInstruction> {
    vec![set_reg(dst, size, intrinsic_expr("tzcnt", vec![src], size))]
}

// ── BMI ─────────────────────────────────────────────────────────────────────

/// `ANDN dst, src1, src2` — `dst = (~src1) & src2`.  Pure primitives.
#[must_use]
pub fn lift_andn(dst: &str, src1: LlilExpr, src2: LlilExpr, size: Size) -> Vec<LlilInstruction> {
    let nsrc1 = LlilExpr::Not(Box::new(src1), size);
    vec![set_reg(
        dst,
        size,
        LlilExpr::And(Box::new(nsrc1), Box::new(src2), size),
    )]
}

/// `BEXTR dst, src, control` — bit field extract.  Modelled with primitives:
/// `dst = (src >> (control & 0xFF)) & ((1 << ((control >> 8) & 0xFF)) - 1)`.
#[must_use]
pub fn lift_bextr(
    dst: &str,
    src: LlilExpr,
    control: LlilExpr,
    size: Size,
) -> Vec<LlilInstruction> {
    let start = LlilExpr::And(
        Box::new(control.clone()),
        Box::new(cst(0xFF, size)),
        size,
    );
    let len_raw = LlilExpr::Shr(Box::new(control), Box::new(cst(8, size)), size);
    let len = LlilExpr::And(Box::new(len_raw), Box::new(cst(0xFF, size)), size);
    let mask = LlilExpr::SubT(
        Box::new(LlilExpr::ShlT(
            Box::new(cst(1, size)),
            Box::new(len),
            size,
        )),
        Box::new(cst(1, size)),
        size,
    );
    let shifted = LlilExpr::Shr(Box::new(src), Box::new(start), size);
    vec![set_reg(
        dst,
        size,
        LlilExpr::And(Box::new(shifted), Box::new(mask), size),
    )]
}

#[must_use]
pub fn lift_pdep(dst: &str, src: LlilExpr, mask: LlilExpr, size: Size) -> Vec<LlilInstruction> {
    vec![set_reg(
        dst,
        size,
        intrinsic_expr("pdep", vec![src, mask], size),
    )]
}

#[must_use]
pub fn lift_pext(dst: &str, src: LlilExpr, mask: LlilExpr, size: Size) -> Vec<LlilInstruction> {
    vec![set_reg(
        dst,
        size,
        intrinsic_expr("pext", vec![src, mask], size),
    )]
}

// ── crc32 / movbe / prefetch ────────────────────────────────────────────────

#[must_use]
pub fn lift_crc32(dst: &str, src: LlilExpr, size: Size) -> Vec<LlilInstruction> {
    vec![set_reg(
        dst,
        size,
        intrinsic_expr("crc32", vec![reg(dst, size), src], size),
    )]
}

/// `MOVBE dst, src` — move with byte swap.  Pure primitive composition.
#[must_use]
pub fn lift_movbe(dst: &str, src: LlilExpr, size: Size) -> Vec<LlilInstruction> {
    vec![set_reg(
        dst,
        size,
        intrinsic_expr("bswap", vec![src], size),
    )]
}

/// `PREFETCHT0/1/2/NTA` — modelled as a side-effect-only intrinsic so the
/// instruction is not silently dropped.
#[must_use]
pub fn lift_prefetch(level: &str, addr: LlilExpr) -> Vec<LlilInstruction> {
    vec![LlilInstruction::Intrinsic {
        name: format!("prefetch_{level}"),
        args: vec![addr],
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_intrinsic(e: &LlilExpr, expected: &str) -> bool {
        matches!(e, LlilExpr::Intrinsic { name, .. } if name == expected)
    }

    #[test]
    fn bt_emits_carry_flag() {
        let v = lift_bt("rax", cst(3, Size::QWord), Size::QWord);
        assert_eq!(v.len(), 1);
        assert!(matches!(&v[0], LlilInstruction::SetFlag { name, .. } if name == "carry"));
    }

    #[test]
    fn bts_emits_or_mask() {
        let v = lift_bts("rax", cst(5, Size::QWord), Size::QWord);
        assert_eq!(v.len(), 2);
        match &v[1] {
            LlilInstruction::SetReg { value, .. } => assert!(matches!(value, LlilExpr::Or(..))),
            _ => panic!("expected SetReg with Or"),
        }
    }

    #[test]
    fn btr_uses_and_not() {
        let v = lift_btr("rax", cst(5, Size::QWord), Size::QWord);
        match &v[1] {
            LlilInstruction::SetReg { value: LlilExpr::And(_, rhs, _), .. } => {
                assert!(matches!(rhs.as_ref(), LlilExpr::Not(..)));
            }
            _ => panic!("expected AND with NOT mask"),
        }
    }

    #[test]
    fn btc_uses_xor() {
        let v = lift_btc("rax", cst(5, Size::QWord), Size::QWord);
        assert!(matches!(
            &v[1],
            LlilInstruction::SetReg { value: LlilExpr::Xor(..), .. }
        ));
    }

    #[test]
    fn bswap_is_intrinsic() {
        let v = lift_bswap("rax", Size::QWord);
        match &v[0] {
            LlilInstruction::SetReg { value, .. } => assert!(is_intrinsic(value, "bswap")),
            _ => panic!(),
        }
    }

    #[test]
    fn xchg_is_three_moves() {
        let v = lift_xchg("rax", "rbx", Size::QWord);
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn xadd_writes_both_operands() {
        let v = lift_xadd("rax", "rbx", Size::QWord);
        assert_eq!(v.len(), 3);
        let last = match &v[2] {
            LlilInstruction::SetReg { dest, .. } => dest,
            _ => panic!(),
        };
        assert!(matches!(last, LlilRegister::Concrete(s) if s == "rax"));
    }

    #[test]
    fn cmpxchg_sets_zero_flag() {
        let v = lift_cmpxchg("rbx", "rcx", Size::QWord);
        assert!(matches!(&v[0], LlilInstruction::SetFlag { name, .. } if name == "zero"));
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn popcnt_lzcnt_tzcnt_are_intrinsics() {
        for (name, f) in [
            ("popcnt", lift_popcnt as fn(&str, LlilExpr, Size) -> Vec<LlilInstruction>),
            ("lzcnt", lift_lzcnt),
            ("tzcnt", lift_tzcnt),
        ] {
            let v = f("rax", reg("rbx", Size::QWord), Size::QWord);
            match &v[0] {
                LlilInstruction::SetReg { value, .. } => assert!(is_intrinsic(value, name)),
                _ => panic!(),
            }
        }
    }

    #[test]
    fn andn_uses_not_and_and() {
        let v = lift_andn(
            "rax",
            reg("rbx", Size::QWord),
            reg("rcx", Size::QWord),
            Size::QWord,
        );
        match &v[0] {
            LlilInstruction::SetReg { value: LlilExpr::And(lhs, _, _), .. } => {
                assert!(matches!(lhs.as_ref(), LlilExpr::Not(..)));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn bextr_is_pure_primitives() {
        let v = lift_bextr(
            "rax",
            reg("rbx", Size::QWord),
            reg("rcx", Size::QWord),
            Size::QWord,
        );
        match &v[0] {
            LlilInstruction::SetReg { value, .. } => {
                // top-level must be an AND of (Shr ..) & mask
                assert!(matches!(value, LlilExpr::And(..)));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn pdep_pext_are_intrinsics() {
        let p = lift_pdep(
            "rax",
            reg("rbx", Size::QWord),
            reg("rcx", Size::QWord),
            Size::QWord,
        );
        let e = lift_pext(
            "rax",
            reg("rbx", Size::QWord),
            reg("rcx", Size::QWord),
            Size::QWord,
        );
        for (insns, want) in [(p, "pdep"), (e, "pext")] {
            match &insns[0] {
                LlilInstruction::SetReg { value, .. } => assert!(is_intrinsic(value, want)),
                _ => panic!(),
            }
        }
    }

    #[test]
    fn crc32_reads_destination_as_accumulator() {
        let v = lift_crc32("eax", reg("ebx", Size::DWord), Size::DWord);
        match &v[0] {
            LlilInstruction::SetReg {
                value: LlilExpr::Intrinsic { name, args, .. },
                ..
            } => {
                assert_eq!(name, "crc32");
                assert_eq!(args.len(), 2);
                assert!(matches!(&args[0], LlilExpr::RegisterRef { reg, .. }
                    if matches!(reg, LlilRegister::Concrete(s) if s == "eax")));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn movbe_byteswaps() {
        let v = lift_movbe("rax", reg("rbx", Size::QWord), Size::QWord);
        match &v[0] {
            LlilInstruction::SetReg { value, .. } => assert!(is_intrinsic(value, "bswap")),
            _ => panic!(),
        }
    }

    #[test]
    fn prefetch_emits_named_intrinsic() {
        let v = lift_prefetch("t0", reg("rax", Size::QWord));
        assert!(matches!(&v[0], LlilInstruction::Intrinsic { name, .. } if name == "prefetch_t0"));
    }
}
