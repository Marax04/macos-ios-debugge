//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact output the audit predicted.

use rustre_analysis_typerecov::type_constraint_generator::{
    IlInstr, IlValue, TypeConstraintGenerator,
};
use rustre_analysis_typerecov::{RecoveredType, TypeUnifier};

// ── RecoveredType::display_name: width overflow ────────────────────────────

/// `width * 8` multiplies two `u8`s, so any type wider than 31 bytes
/// overflows: in release the bit count wraps (a 32-byte type prints as `u0`),
/// in an overflow-checked build it panics outright. SIMD and large structs
/// routinely exceed 31 bytes.
#[test]
fn wide_integer_types_report_their_real_bit_width() {
    assert_eq!(
        RecoveredType::Int {
            width: 32,
            signed: false
        }
        .display_name(),
        "u256"
    );
    assert_eq!(
        RecoveredType::Int {
            width: 64,
            signed: true
        }
        .display_name(),
        "i512"
    );
}

#[test]
fn wide_float_types_report_their_real_bit_width() {
    assert_eq!(RecoveredType::Float { width: 32 }.display_name(), "f256");
}

/// No width in the whole `u8` range may produce a wrong or absurd name.
#[test]
fn no_width_wraps_around() {
    for w in 1u8..=u8::MAX {
        let name = RecoveredType::Int {
            width: w,
            signed: false,
        }
        .display_name();
        let expected = format!("u{}", u32::from(w) * 8);
        assert_eq!(name, expected, "width {w} printed as {name}");
    }
}

/// The common widths were already right and must stay right.
#[test]
fn ordinary_widths_are_unchanged() {
    assert_eq!(
        RecoveredType::Int {
            width: 4,
            signed: true
        }
        .display_name(),
        "i32"
    );
    assert_eq!(RecoveredType::Float { width: 8 }.display_name(), "f64");
}

// ── type_var_of: signedness of a non-negative literal ──────────────────────

/// A NON-NEGATIVE integer literal is compatible with both signed and unsigned
/// types — it is evidence of nothing. Emitting `signed: Some(false)` treats it
/// as positive proof of unsignedness, so a variable assigned both `-1` and `5`
/// produces a `SignednessConflict` and the whole unification fails, taking
/// every unrelated type in the function down with it.
#[test]
fn a_variable_assigned_both_signs_of_literal_still_unifies() {
    let prog = [
        IlInstr::Assign {
            dst: IlValue::Temp(0),
            src: IlValue::Const(-1),
            addr: 0,
        },
        IlInstr::Assign {
            dst: IlValue::Temp(0),
            src: IlValue::Const(5),
            addr: 4,
        },
    ];

    let mut g = TypeConstraintGenerator::new_64bit();
    g.process_all(&prog);
    let n = g.type_var_count();
    let constraints = g.into_constraints();

    let result = TypeUnifier::new(n).solve(&constraints);
    assert!(
        result.is_ok(),
        "`x = -1; x = 5` is ordinary signed code and must unify, got {:?}",
        result.err()
    );
}

/// A NEGATIVE literal is still real evidence of signedness and must keep
/// conflicting with something genuinely unsigned.
#[test]
fn negative_literals_remain_evidence_of_signedness() {
    let prog = [IlInstr::Assign {
        dst: IlValue::Temp(0),
        src: IlValue::Const(-7),
        addr: 0,
    }];

    let mut g = TypeConstraintGenerator::new_64bit();
    g.process_all(&prog);
    let n = g.type_var_count();
    let constraints = g.into_constraints();

    // The negative literal must have produced a signed constraint somewhere.
    let has_signed_evidence = constraints.iter().any(|c| {
        format!("{:?}", c.kind).contains("signed: Some(true)")
    });
    assert!(
        has_signed_evidence,
        "a negative literal is evidence of signedness: {constraints:?}"
    );

    assert!(TypeUnifier::new(n).solve(&constraints).is_ok());
}

/// Several non-negative literals assigned to the same variable never conflict.
#[test]
fn many_non_negative_literals_never_conflict() {
    let prog: Vec<IlInstr> = [0i64, 1, 42, i64::MAX]
        .iter()
        .enumerate()
        .map(|(i, &c)| IlInstr::Assign {
            dst: IlValue::Temp(0),
            src: IlValue::Const(c),
            addr: i as u64 * 4,
        })
        .collect();

    let mut g = TypeConstraintGenerator::new_64bit();
    g.process_all(&prog);
    let n = g.type_var_count();
    assert!(TypeUnifier::new(n).solve(&g.into_constraints()).is_ok());
}
