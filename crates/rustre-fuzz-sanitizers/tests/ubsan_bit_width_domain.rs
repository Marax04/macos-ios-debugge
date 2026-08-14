//! `bit_width` is an unvalidated `u8` on every public UBSan overflow check.
//!
//! The whole domain is only 256 values, so it is enumerated exhaustively rather
//! than sampled. The expectations are derived from the definition of a signed
//! `w`-bit range — `[-2^(w-1), 2^(w-1)-1]` — not copied from the implementation.

use rustre_fuzz_sanitizers::ubsan_checks::{RecoveryMode, SourceLocation, UbsanRuntime};

fn rt() -> UbsanRuntime {
    UbsanRuntime::new(RecoveryMode::Continue)
}

fn loc() -> SourceLocation {
    SourceLocation::new("t.c", 1, 1)
}

#[test]
fn no_bit_width_in_the_whole_u8_domain_is_rejected() {
    // Every one of the 256 values must be survivable on every check. A width
    // outside 1..=128 is degenerate, but it must not make the checker diverge
    // by build profile: `128 - bit_width` underflows above 128, which panics
    // under overflow checks and wraps silently without them.
    let mut exercised = 0usize;
    for w in 0u8..=255 {
        let r = rt();
        r.check_signed_add_overflow(loc(), 1, 1, w);
        r.check_signed_sub_overflow(loc(), 1, 1, w);
        r.check_signed_mul_overflow(loc(), 2, 3, w);
        r.check_signed_negate_overflow(loc(), 1, w);
        r.check_unsigned_add_overflow(loc(), 1, 1, w);
        r.check_unsigned_mul_overflow(loc(), 2, 3, w);
        exercised += 1;
    }
    assert_eq!(exercised, 256, "anti-vacuity: the full u8 domain must be walked");
}

#[test]
fn signed_boundary_is_exact_for_every_representable_width() {
    // For width w the largest representable value is 2^(w-1)-1: it must NOT be
    // reported, and one past it MUST be. Restricted to w <= 63 so that both the
    // boundary and boundary+1 fit in the i64 parameter type.
    let mut checked = 0usize;
    for w in 2u8..=63 {
        let max: i64 = (1i64 << (w - 1)) - 1;

        let r = rt();
        r.check_signed_add_overflow(loc(), max, 0, w);
        assert_eq!(
            r.violation_count(),
            0,
            "w={w}: 2^(w-1)-1 = {max} is representable and must not be flagged"
        );

        let r = rt();
        r.check_signed_add_overflow(loc(), max, 1, w);
        assert_eq!(
            r.violation_count(),
            1,
            "w={w}: 2^(w-1) = {} overflows a {w}-bit signed integer and must be flagged",
            max as i128 + 1
        );

        checked += 1;
    }
    assert_eq!(checked, 62, "anti-vacuity: expected widths 2..=63 to be checked");
}

#[test]
fn unsigned_boundary_is_exact_for_every_representable_width() {
    // For width w the largest representable value is 2^w - 1.
    let mut checked = 0usize;
    for w in 1u8..=63 {
        let max: u64 = (1u64 << w) - 1;

        let r = rt();
        r.check_unsigned_add_overflow(loc(), max, 0, w);
        assert_eq!(
            r.violation_count(),
            0,
            "w={w}: 2^w-1 = {max} is representable and must not be flagged"
        );

        let r = rt();
        r.check_unsigned_add_overflow(loc(), max, 1, w);
        assert_eq!(
            r.violation_count(),
            1,
            "w={w}: 2^w = {} overflows a {w}-bit unsigned integer and must be flagged",
            u128::from(max) + 1
        );

        checked += 1;
    }
    assert_eq!(checked, 63, "anti-vacuity: expected widths 1..=63 to be checked");
}

#[test]
fn widening_the_type_never_turns_a_non_overflow_into_an_overflow() {
    // Monotonicity, derived from the ranges being nested: if a value fits in w
    // bits it fits in every wider type, so the overflow verdict can only go
    // from true to false as w grows — never back.
    let mut transitions = 0usize;
    for &(lhs, rhs) in &[(1i64, 1i64), (127, 1), (32767, 1), (i32::MAX as i64, 1)] {
        let mut seen_ok = false;
        for w in 2u8..=64 {
            let r = rt();
            r.check_signed_add_overflow(loc(), lhs, rhs, w);
            let overflowed = r.violation_count() == 1;
            if overflowed {
                assert!(
                    !seen_ok,
                    "{lhs}+{rhs} was representable in a narrower type but overflows at w={w}"
                );
            } else if !seen_ok {
                seen_ok = true;
                transitions += 1;
            }
        }
        assert!(seen_ok, "{lhs}+{rhs} never fit in any width up to 64");
    }
    assert_eq!(
        transitions, 4,
        "anti-vacuity: each case must cross from overflow to representable exactly once"
    );
}
