//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact output the audit predicted.

use rustre_symb::{SpecSymExpr, SymWidth};

fn c(val: u64, width: SymWidth) -> Box<SpecSymExpr> {
    Box::new(SpecSymExpr::Const { val, width })
}

// ── SpecSymExpr::eval_concrete, Concat arm ─────────────────────────────────

/// `Concat(hi, lo)` is `hi ++ lo` everywhere else in this crate, i.e.
/// `(hi << width(lo)) | lo`. Shifting by the HIGH operand's width instead
/// makes the high part land on top of the low bits and disappear.
#[test]
fn concat_shifts_by_the_low_operand_width() {
    // 1 ++ 0xFFFF, with the low part 16 bits wide → 0x1_FFFF.
    let e = SpecSymExpr::Concat(c(1, SymWidth::W8), c(0xFFFF, SymWidth::W16));
    assert_eq!(
        e.eval_concrete(),
        Some(0x1_FFFF),
        "the high byte must sit above the 16-bit low part, not inside it"
    );
}

#[test]
fn concat_of_two_bytes_builds_a_halfword() {
    let e = SpecSymExpr::Concat(c(0xAB, SymWidth::W8), c(0xCD, SymWidth::W8));
    assert_eq!(e.eval_concrete(), Some(0xABCD));
}

/// A zero low part must leave the high part exactly where it belongs.
#[test]
fn concat_with_zero_low_part_places_the_high_part() {
    let e = SpecSymExpr::Concat(c(0xFF, SymWidth::W8), c(0, SymWidth::W32));
    assert_eq!(e.eval_concrete(), Some(0xFF_0000_0000));
}

// ── SpecSymExpr::width ─────────────────────────────────────────────────────

/// `width()` returned the LEFT operand's width for `Concat`, but a
/// concatenation is as wide as both operands together.
#[test]
fn concat_width_is_the_sum_of_both_operands() {
    let e = SpecSymExpr::Concat(c(0, SymWidth::W8), c(0, SymWidth::W8));
    assert_eq!(
        e.width(),
        Some(SymWidth::W16),
        "8 ++ 8 is 16 bits wide, not 8"
    );

    let e = SpecSymExpr::Concat(c(0, SymWidth::W16), c(0, SymWidth::W16));
    assert_eq!(e.width(), Some(SymWidth::W32));

    let e = SpecSymExpr::Concat(c(0, SymWidth::W32), c(0, SymWidth::W32));
    assert_eq!(e.width(), Some(SymWidth::W64));
}

/// A width `SymWidth` cannot express must be reported as unknown rather than
/// as a plausible-looking wrong answer: 8 ++ 16 is 24 bits, which has no
/// variant, and 64 ++ anything overflows the type entirely.
#[test]
fn unrepresentable_concat_widths_are_unknown() {
    let e = SpecSymExpr::Concat(c(0, SymWidth::W8), c(0, SymWidth::W16));
    assert_eq!(e.width(), None, "24 bits is not a SymWidth");

    let e = SpecSymExpr::Concat(c(0, SymWidth::W64), c(0, SymWidth::W8));
    assert_eq!(e.width(), None, "72 bits does not fit");
}

/// Comparisons yield a boolean, not a value as wide as their operands.
/// `SymWidth` has no 1-bit variant, so the honest answer is "unknown".
#[test]
fn comparison_width_is_not_the_operand_width() {
    let eq = SpecSymExpr::Eq(c(0, SymWidth::W32), c(0, SymWidth::W32));
    assert_ne!(
        eq.width(),
        Some(SymWidth::W32),
        "Eq produces a boolean, not a 32-bit value"
    );

    let lt = SpecSymExpr::Lt(c(0, SymWidth::W64), c(0, SymWidth::W64));
    assert_ne!(lt.width(), Some(SymWidth::W64));
}

/// The arms that genuinely do carry the operand width must keep doing so.
#[test]
fn arithmetic_width_still_follows_the_operands() {
    let e = SpecSymExpr::Add(c(1, SymWidth::W32), c(2, SymWidth::W32));
    assert_eq!(e.width(), Some(SymWidth::W32));

    let e = SpecSymExpr::Const {
        val: 0,
        width: SymWidth::W16,
    };
    assert_eq!(e.width(), Some(SymWidth::W16));
}

// ── SymbolicMemory::read_symbolic ──────────────────────────────────────────

use rustre_symb::memory_model::SymbolicMemory;
use rustre_symb::{SymExpr, SymType};

/// `read_symbolic` is documented to "return a symbolic expression of width
/// `size * 8`", and the concrete fast path does exactly that. The symbolic
/// path builds an ITE chain whose branches are single BYTE cells, ignoring
/// `size` entirely — so a 4-byte read of a symbolic address yields an 8-bit
/// expression, and the ITE's own branches disagree in width with its default.
#[test]
fn a_symbolic_read_has_the_requested_width() {
    for size in [1u8, 2, 4, 8] {
        let mut mem = SymbolicMemory::new();
        mem.write_word_concrete(0x1000, 0xAABB_CCDD_1122_3344, size);
        mem.write_word_concrete(0x2000, 0x0102_0304_0506_0708, size);

        let addr = SymExpr::var("a", SymType::BitVec(64));
        let got = mem.read_symbolic(&addr, size);

        assert_eq!(
            got.bit_width(),
            u32::from(size) * 8,
            "read_symbolic(size = {size}) must be {} bits wide, got {}",
            u32::from(size) * 8,
            got.bit_width()
        );
    }
}

/// The concrete fast path and the symbolic path must agree on width — they are
/// the same operation, only the address is known in one case.
#[test]
fn concrete_and_symbolic_reads_agree_on_width() {
    let mut mem = SymbolicMemory::new();
    mem.write_word_concrete(0x1000, 0xAABB_CCDD, 4);

    let concrete = mem.read_symbolic(&SymExpr::bv(0x1000, 64), 4);
    let symbolic = mem.read_symbolic(&SymExpr::var("a", SymType::BitVec(64)), 4);

    assert_eq!(concrete.bit_width(), 32);
    assert_eq!(
        symbolic.bit_width(),
        concrete.bit_width(),
        "the two paths of the same read must produce the same width"
    );
}

/// An address with no known candidates still has to honour the width.
#[test]
fn a_symbolic_read_of_empty_memory_keeps_its_width() {
    let mut mem = SymbolicMemory::new();
    let got = mem.read_symbolic(&SymExpr::var("a", SymType::BitVec(64)), 4);
    assert_eq!(got.bit_width(), 32);
}

// ── SymExpr::evaluate: width masking ───────────────────────────────────────

use std::collections::HashMap;

fn b(val: u64, w: u32) -> Box<SymExpr> {
    Box::new(SymExpr::bv(val, w))
}

/// `evaluate` is a second interpreter for semantics that `SymExprSimplifier`
/// and `formula_simplifier::ConstantFolding` also implement — and those two
/// mask every folded result to the declared width. `evaluate` computed in full
/// 64 bits, so an 8/16/32-bit wraparound was silently reported as a
/// non-wrapping value. It is reached from production code (`ConcolicState::
/// eval_concrete`, model checking in `constraint_solver`), so a model can be
/// scored satisfiable or unsatisfiable on the strength of a wrong number.
#[test]
fn arithmetic_wraps_at_the_declared_width() {
    let env = HashMap::new();

    // 0xFF + 1 in 8 bits is 0, not 0x100.
    let e = SymExpr::Add(b(0xFF, 8), b(1, 8));
    assert_eq!(e.bit_width(), 8);
    assert_eq!(e.evaluate(&env), Some(0), "8-bit add must wrap");

    // 0xFFFF + 1 in 16 bits is 0.
    let e = SymExpr::Add(b(0xFFFF, 16), b(1, 16));
    assert_eq!(e.evaluate(&env), Some(0), "16-bit add must wrap");

    // 0x100 * 0x100 in 16 bits is 0.
    let e = SymExpr::Mul(b(0x100, 16), b(0x100, 16));
    assert_eq!(e.evaluate(&env), Some(0), "16-bit multiply must wrap");

    // 0 - 1 in 8 bits is 0xFF.
    let e = SymExpr::Sub(b(0, 8), b(1, 8));
    assert_eq!(e.evaluate(&env), Some(0xFF), "8-bit subtract must wrap");
}

/// Bitwise NOT of an 8-bit zero is 0xFF, not 64 bits of ones.
#[test]
fn bitwise_not_stays_inside_the_declared_width() {
    let env = HashMap::new();

    let e = SymExpr::Not(b(0, 8));
    assert_eq!(e.evaluate(&env), Some(0xFF), "!0u8 is 0xFF");

    let e = SymExpr::Not(b(0, 16));
    assert_eq!(e.evaluate(&env), Some(0xFFFF));

    let e = SymExpr::Neg(b(1, 8));
    assert_eq!(e.evaluate(&env), Some(0xFF), "-1 in 8 bits is 0xFF");
}

/// A left shift must drop the bits that leave the declared width.
#[test]
fn left_shift_discards_bits_past_the_width() {
    let env = HashMap::new();

    let e = SymExpr::Shl(b(0x80, 8), b(1, 8));
    assert_eq!(e.evaluate(&env), Some(0), "0x80 << 1 in 8 bits is 0");

    let e = SymExpr::Shl(b(1, 16), b(15, 16));
    assert_eq!(e.evaluate(&env), Some(0x8000));

    let e = SymExpr::Shl(b(1, 16), b(16, 16));
    assert_eq!(e.evaluate(&env), Some(0), "shifting past the width clears it");
}

/// No result may ever exceed the mask of its own declared width — the general
/// property behind all of the above.
#[test]
fn no_result_exceeds_its_declared_width() {
    let env = HashMap::new();
    let mask = |w: u32| if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };

    for w in [8u32, 16, 32, 64] {
        let hi = mask(w);
        for e in [
            SymExpr::Add(b(hi, w), b(hi, w)),
            SymExpr::Sub(b(0, w), b(hi, w)),
            SymExpr::Mul(b(hi, w), b(hi, w)),
            SymExpr::Not(b(0, w)),
            SymExpr::Neg(b(1, w)),
            SymExpr::Shl(b(hi, w), b(3, w)),
            SymExpr::And(b(hi, w), b(hi, w)),
            SymExpr::Or(b(hi, w), b(0, w)),
            SymExpr::Xor(b(hi, w), b(0, w)),
        ] {
            let v = e.evaluate(&env).expect("concrete");
            assert!(
                v <= mask(w),
                "width {w}: {e:?} evaluated to {v:#x}, above the {:#x} mask",
                mask(w)
            );
        }
    }
}

/// 64-bit behaviour must be unchanged — the mask is a no-op there.
#[test]
fn sixty_four_bit_arithmetic_is_untouched() {
    let env = HashMap::new();
    let e = SymExpr::Add(b(u64::MAX, 64), b(1, 64));
    assert_eq!(e.evaluate(&env), Some(0));
    let e = SymExpr::Not(b(0, 64));
    assert_eq!(e.evaluate(&env), Some(u64::MAX));
}
