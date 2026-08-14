//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! These cover "wrong but plausible" results — the code does not crash, it
//! answers incorrectly — so they are asserted against the mathematical
//! definition of the operation, not against whatever the code happened to do.

use rustre_symb::{SymExpr, SymType, SymbolicState};
use rustre_symb_engine::loop_summarizer::{Loop, LoopSummarizer, LoopSummarizerConfig};
use rustre_symb_engine::path_condition::{Constraint, ConstraintKind};
use rustre_symb_engine::path_explorer::{ExplorationLimits, ExplorationStrategy, PathExplorer};
use rustre_symb_engine::symbolic_memory::SymbolicMemory;

fn bv(val: u64, width: u32) -> SymExpr {
    SymExpr::ConstBv { val, width }
}

fn cmp(kind: ConstraintKind, lhs: SymExpr, rhs: SymExpr) -> Constraint {
    Constraint {
        kind,
        lhs,
        rhs,
        polarity: true,
        source_addr: 0,
        label: String::new(),
    }
}

/// NOT(a < b) must be `a >= b`, i.e. `b <= a` — flipping only the kind leaves a
/// constraint that is still true for a < b, so the "false" branch of a compare
/// was never recognised as infeasible.
#[test]
fn negating_unsigned_lt_swaps_operands() {
    let c = cmp(ConstraintKind::UnsignedLt, bv(1, 64), bv(2, 64));
    assert!(c.is_tautology(), "1 <u 2 holds");

    let n = c.negate();
    assert!(
        n.is_contradiction(),
        "NOT(1 <u 2) must be unsatisfiable, got {n}"
    );
    assert!(!n.is_tautology());
}

#[test]
fn negating_unsigned_le_swaps_operands() {
    let c = cmp(ConstraintKind::UnsignedLe, bv(5, 64), bv(5, 64));
    assert!(c.is_tautology());
    assert!(c.negate().is_contradiction());
}

#[test]
fn negation_is_involutive_on_orderings() {
    for kind in [
        ConstraintKind::UnsignedLt,
        ConstraintKind::UnsignedLe,
        ConstraintKind::SignedLt,
        ConstraintKind::SignedLe,
    ] {
        let c = cmp(kind, bv(3, 64), bv(9, 64));
        let twice = c.negate().negate();
        assert_eq!(twice.kind, c.kind, "double negation must restore the kind");
        assert_eq!(
            twice.is_tautology(),
            c.is_tautology(),
            "double negation must restore the verdict for {kind:?}"
        );
    }
}

/// Exactly one of tautology/contradiction must hold for a constraint over two
/// concrete constants — never both, never neither.
#[test]
fn concrete_orderings_are_decided_exactly_once() {
    let vals = [0u64, 1, 2, 0x7FFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0000, u64::MAX];
    for kind in [
        ConstraintKind::UnsignedLt,
        ConstraintKind::UnsignedLe,
        ConstraintKind::SignedLt,
        ConstraintKind::SignedLe,
    ] {
        for &a in &vals {
            for &b in &vals {
                let c = cmp(kind, bv(a, 64), bv(b, 64));
                assert_ne!(
                    c.is_tautology(),
                    c.is_contradiction(),
                    "{kind:?} {a:#x} {b:#x} must be decided exactly once"
                );
            }
        }
    }
}

/// `SignedLt` was evaluated with the unsigned comparison of the raw u64, so
/// every negative operand produced the opposite verdict and real paths were
/// discarded as infeasible.
#[test]
fn signed_lt_treats_high_bit_as_negative() {
    let minus_one = bv(u64::MAX, 64);
    let c = cmp(ConstraintKind::SignedLt, minus_one.clone(), bv(1, 64));
    assert!(c.is_tautology(), "-1 <s 1 is true");
    assert!(!c.is_contradiction());

    let d = cmp(ConstraintKind::SignedLt, bv(1, 64), minus_one);
    assert!(d.is_contradiction(), "1 <s -1 is false");
}

#[test]
fn signed_le_respects_sign_at_narrow_widths() {
    // 0xFF at width 8 is -1, not 255.
    let c = cmp(ConstraintKind::SignedLe, bv(0xFF, 8), bv(0, 8));
    assert!(c.is_tautology(), "-1 <=s 0 at width 8");

    // The same payload read as unsigned must go the other way.
    let u = cmp(ConstraintKind::UnsignedLe, bv(0xFF, 8), bv(0, 8));
    assert!(u.is_contradiction(), "255 <=u 0 is false");
}

#[test]
fn signed_and_unsigned_disagree_where_they_must() {
    // 0x8000_0000_0000_0000 is i64::MIN signed, but the largest-but-one unsigned.
    let big = bv(0x8000_0000_0000_0000, 64);
    let one = bv(1, 64);

    assert!(cmp(ConstraintKind::SignedLt, big.clone(), one.clone()).is_tautology());
    assert!(cmp(ConstraintKind::UnsignedLt, big, one).is_contradiction());
}

// ── SymbolicMemory::write_le_concrete ──────────────────────────────────────

/// `val` is a u64, so widths past 8 shifted by 64+ bits: panic in debug,
/// silently recycled bytes in release. `read_le` right next to it already
/// clamped; the write path did not.
#[test]
fn oversized_write_width_does_not_panic() {
    for width in 0u8..=u8::MAX {
        let mut mem = SymbolicMemory::new();
        mem.map_stack(0, 0x100);
        // Must not panic for any width, including the whole u8 range.
        let _ = mem.write_le_concrete(0, 0x00FF_0000_0000_0011, width);
    }
}

/// A write wider than 8 must not corrupt the bytes past the 8th with recycled
/// low-order bytes of `val`.
#[test]
fn oversized_write_leaves_trailing_bytes_untouched() {
    let mut mem = SymbolicMemory::new();
    mem.map_stack(0, 0x100);
    mem.write_le_concrete(0, 0xAABB_CCDD_EEFF_0011, 9)
        .expect("stack is mapped");

    // Byte 8 must not have been written with a recycled byte of `val`.
    let b8 = mem.read_le(8, 1).expect("mapped");
    if let SymExpr::ConstBv { val, .. } = b8 {
        assert_ne!(val, 0x11, "byte 8 got the low byte of val recycled");
    }
}

#[test]
fn write_then_read_round_trips_for_every_valid_width() {
    for width in 1u8..=8 {
        let mut mem = SymbolicMemory::new();
        mem.map_stack(0, 0x100);
        let val = 0x0123_4567_89AB_CDEFu64;
        mem.write_le_concrete(0, val, width).expect("mapped");
        let got = mem.read_le(0, width).expect("mapped");
        let mask = if width >= 8 { u64::MAX } else { (1u64 << (width * 8)) - 1 };
        if let SymExpr::ConstBv { val: v, .. } = got {
            assert_eq!(v, val & mask, "round trip failed at width {width}");
        } else {
            panic!("expected a concrete read back at width {width}");
        }
    }
}

// ── PathExplorer, Interleaved strategy ─────────────────────────────────────

/// The alternation toggle must express a PREFERENCE, never gate reachability:
/// after an odd number of pushes it pointed at the empty structure and the
/// engine reported no work while live paths were queued.
#[test]
fn interleaved_pop_never_starves_while_paths_are_live() {
    let mut e = PathExplorer::new(
        ExplorationStrategy::Interleaved,
        ExplorationLimits::default(),
    );
    e.seed(0x1000);

    assert_eq!(e.live_count(), 1);
    assert!(!e.is_exhausted());
    assert!(
        e.pop_next().is_some(),
        "a live path must be poppable regardless of toggle parity"
    );
    assert!(e.is_exhausted());
}

/// The invariant, over every push count: live_count() > 0 implies pop_next()
/// yields something, and draining returns exactly as many paths as were seeded.
#[test]
fn interleaved_drains_every_seeded_path() {
    for n in 1..=17u64 {
        let mut e = PathExplorer::new(
            ExplorationStrategy::Interleaved,
            ExplorationLimits::default(),
        );
        for i in 0..n {
            e.seed(0x1000 + i * 0x10);
        }
        let mut drained = 0u64;
        while !e.is_exhausted() {
            assert!(
                e.pop_next().is_some(),
                "not exhausted but pop_next() returned None (n = {n})"
            );
            drained += 1;
            assert!(drained <= n, "drained more paths than seeded (n = {n})");
        }
        assert_eq!(drained, n, "lost live paths with {n} seeded");
    }
}

// ── LoopSummarizer::detect_induction_var ───────────────────────────────────

fn detect(recurrence: SymExpr, reg: &str) -> Loop {
    let mut state = SymbolicState::new();
    state.registers.insert(reg.to_string(), recurrence);
    let s = LoopSummarizer::new(
        Default::default(),
        0,
        LoopSummarizerConfig::default(),
    );
    let mut lp = Loop::new(0);
    s.detect_induction_var(&mut lp, &state);
    lp
}

fn var(name: &str) -> SymExpr {
    SymExpr::Var {
        name: name.to_string(),
        ty: SymType::BitVec(64),
    }
}

/// `r = r - 1` is a DECREMENTING loop: recording step `+1` inverts the whole
/// progression, so every derived closed form and monotonicity invariant is false.
#[test]
fn decrementing_loop_records_a_negative_step() {
    let lp = detect(
        SymExpr::Sub(
            Box::new(var("rcx")),
            Box::new(SymExpr::ConstBv { val: 1, width: 64 }),
        ),
        "rcx",
    );
    assert_eq!(lp.induction_var.as_deref(), Some("rcx"));
    match lp.step {
        Some(SymExpr::ConstBv { val, .. }) => assert_eq!(
            val,
            1u64.wrapping_neg(),
            "step for `rcx - 1` must be -1, not +1"
        ),
        other => panic!("expected a constant step, got {other:?}"),
    }
}

#[test]
fn incrementing_loop_keeps_a_positive_step() {
    let lp = detect(
        SymExpr::Add(
            Box::new(var("rax")),
            Box::new(SymExpr::ConstBv { val: 4, width: 64 }),
        ),
        "rax",
    );
    match lp.step {
        Some(SymExpr::ConstBv { val, .. }) => assert_eq!(val, 4),
        other => panic!("expected a constant step, got {other:?}"),
    }
}

/// `init_value` is documented as the value on ENTRY. Re-reading the register
/// yields the recurrence `r + c` instead, leaking a spurious `+c` into every
/// closed form derived from it.
#[test]
fn init_value_is_the_entry_value_not_the_recurrence() {
    let recurrence = SymExpr::Add(
        Box::new(var("rax")),
        Box::new(SymExpr::ConstBv { val: 4, width: 64 }),
    );
    let lp = detect(recurrence.clone(), "rax");

    assert_ne!(
        lp.init_value.as_ref(),
        Some(&recurrence),
        "init_value must not be the recurrence itself"
    );
    assert_eq!(
        lp.init_value,
        Some(var("rax")),
        "init_value must be the symbolic entry value of the register"
    );
}
