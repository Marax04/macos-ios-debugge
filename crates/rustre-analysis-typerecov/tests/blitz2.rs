//! Deep adversarial tests for rustre-analysis-typerecov.
//!
//! Covers RecoveredType, TypeVar, constraint generator, type unifier,
//! struct recovery engine and database.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

use rustre_analysis_typerecov::{
    ConstraintKind, FieldAccess, RecoveredStruct, RecoveredType, StructRecoveryEngine,
    TypeConstraint, TypeConstraintGenerator, TypeVar,
};
use rustre_analysis_typerecov::type_constraint_generator::{
    AbstractBinOp, ConstraintSet, IlInstr, IlValue, Provenance,
};
use rustre_analysis_typerecov::struct_recovery_engine::{
    merge_structs, recover_structs, ConflictKind, StructDatabase,
};
use rustre_analysis_typerecov::type_unifier::{unify_types, TypeUnifier, UnifyError};

// ─────────────────────────────────────────────────────────────────────────────
// LCG helper
// ─────────────────────────────────────────────────────────────────────────────

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        s
    }
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeVar tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn typevar_display_and_eq() {
    let a = TypeVar::new(0);
    let b = TypeVar::new(0);
    let c = TypeVar::new(1);
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(format!("{a}"), "τ0");
    assert_eq!(format!("{c}"), "τ1");
}

#[test]
fn typevar_hash_consistency_30_pairs() {
    for i in 0..30u32 {
        let a = TypeVar::new(i);
        let b = TypeVar::new(i);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
}

#[test]
fn typevar_ord() {
    let mut v = vec![TypeVar::new(5), TypeVar::new(1), TypeVar::new(9), TypeVar::new(0)];
    v.sort();
    assert_eq!(v, vec![TypeVar::new(0), TypeVar::new(1), TypeVar::new(5), TypeVar::new(9)]);
}

#[test]
fn typevar_boundary_ids() {
    let zero = TypeVar::new(0);
    let one = TypeVar::new(1);
    let big = TypeVar::new(u32::MAX);
    assert_eq!(zero.0, 0);
    assert_eq!(one.0, 1);
    assert_eq!(big.0, u32::MAX);
    assert_eq!(format!("{big}"), format!("τ{}", u32::MAX));
}

#[test]
fn typevar_serde_roundtrip() {
    for i in [0u32, 1, 7, 255, 65535, u32::MAX / 2, u32::MAX] {
        let v = TypeVar::new(i);
        let s = serde_json::to_string(&v).unwrap();
        let v2: TypeVar = serde_json::from_str(&s).unwrap();
        assert_eq!(v, v2);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RecoveredType tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn recovered_type_default_is_unknown() {
    let d: RecoveredType = Default::default();
    assert_eq!(d, RecoveredType::Unknown);
}

#[test]
fn recovered_type_is_pointer_and_pointee() {
    let p = RecoveredType::Pointer(Box::new(RecoveredType::Int { width: 4, signed: true }));
    assert!(p.is_pointer());
    assert!(!p.is_struct());
    assert_eq!(
        p.pointee(),
        Some(&RecoveredType::Int { width: 4, signed: true })
    );

    let s = RecoveredType::Struct { name: "Foo".into() };
    assert!(!s.is_pointer());
    assert!(s.is_struct());
    assert_eq!(s.pointee(), None);
}

#[test]
fn recovered_type_display_names_50_inputs() {
    let cases: Vec<(RecoveredType, &str)> = vec![
        (RecoveredType::Var(TypeVar::new(0)), "τ0"),
        (RecoveredType::Var(TypeVar::new(42)), "τ42"),
        (RecoveredType::Int { width: 1, signed: false }, "u8"),
        (RecoveredType::Int { width: 1, signed: true }, "i8"),
        (RecoveredType::Int { width: 2, signed: false }, "u16"),
        (RecoveredType::Int { width: 2, signed: true }, "i16"),
        (RecoveredType::Int { width: 4, signed: false }, "u32"),
        (RecoveredType::Int { width: 4, signed: true }, "i32"),
        (RecoveredType::Int { width: 8, signed: false }, "u64"),
        (RecoveredType::Int { width: 8, signed: true }, "i64"),
        (RecoveredType::Float { width: 4 }, "f32"),
        (RecoveredType::Float { width: 8 }, "f64"),
        (RecoveredType::Struct { name: "S".into() }, "S"),
        (RecoveredType::FnPtr { param_count: 0 }, "fn(0)"),
        (RecoveredType::FnPtr { param_count: 7 }, "fn(7)"),
        (RecoveredType::Unknown, "?"),
    ];
    for (t, want) in &cases {
        assert_eq!(&t.display_name(), want, "for {t:?}");
    }
    // 50+ deterministic display calls — exercise nesting.
    let mut g = lcg();
    for _ in 0..40 {
        let w = ((g() % 4) + 1) as u8;
        let s = (g() & 1) == 1;
        let t = RecoveredType::Pointer(Box::new(RecoveredType::Int { width: w, signed: s }));
        let prefix = if s { "i" } else { "u" };
        assert_eq!(t.display_name(), format!("*{prefix}{}", w * 8));
    }
}

#[test]
fn recovered_type_array_display() {
    let t = RecoveredType::Array {
        element: Box::new(RecoveredType::Int { width: 4, signed: true }),
        count: 16,
    };
    assert_eq!(t.display_name(), "[i32; 16]");
}

#[test]
fn recovered_type_hash_consistency() {
    let pairs = [
        RecoveredType::Unknown,
        RecoveredType::Int { width: 4, signed: true },
        RecoveredType::Float { width: 8 },
        RecoveredType::Pointer(Box::new(RecoveredType::Unknown)),
        RecoveredType::Struct { name: "X".into() },
        RecoveredType::FnPtr { param_count: 2 },
        RecoveredType::Var(TypeVar::new(7)),
        RecoveredType::Array {
            element: Box::new(RecoveredType::Int { width: 1, signed: false }),
            count: 4,
        },
    ];
    for t in &pairs {
        let a = t.clone();
        let b = t.clone();
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
    // Make 30+ pairs by combining.
    for i in 0..30u32 {
        let t = RecoveredType::Int { width: ((i % 8) + 1) as u8, signed: (i & 1) == 1 };
        assert_eq!(hash_of(&t.clone()), hash_of(&t));
    }
}

#[test]
fn recovered_type_serde_roundtrip() {
    let cases = [
        RecoveredType::Unknown,
        RecoveredType::Int { width: 4, signed: false },
        RecoveredType::Float { width: 8 },
        RecoveredType::Pointer(Box::new(RecoveredType::Int { width: 2, signed: true })),
        RecoveredType::Struct { name: "MyStruct".into() },
        RecoveredType::FnPtr { param_count: 3 },
        RecoveredType::Array {
            element: Box::new(RecoveredType::Int { width: 4, signed: false }),
            count: 8,
        },
        RecoveredType::Var(TypeVar::new(42)),
    ];
    for c in &cases {
        let j = serde_json::to_string(c).unwrap();
        let back: RecoveredType = serde_json::from_str(&j).unwrap();
        assert_eq!(c, &back);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintGenerator tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctor_pointer_width_preserved() {
    let g64 = TypeConstraintGenerator::new_64bit();
    assert_eq!(g64.pointer_width, 8);
    let g32 = TypeConstraintGenerator::new_32bit();
    assert_eq!(g32.pointer_width, 4);
    let g16 = TypeConstraintGenerator::new(2);
    assert_eq!(g16.pointer_width, 2);
}

#[test]
fn type_var_reuse_for_non_const() {
    let mut g = TypeConstraintGenerator::new_64bit();
    let a = g.type_var_of(&IlValue::Temp(3));
    let b = g.type_var_of(&IlValue::Temp(3));
    assert_eq!(a, b);
    let c = g.type_var_of(&IlValue::Temp(4));
    assert_ne!(a, c);
    let p = g.type_var_of(&IlValue::Param(0));
    let p2 = g.type_var_of(&IlValue::Param(0));
    assert_eq!(p, p2);
    assert_ne!(p, a);
    let r = g.type_var_of(&IlValue::RetVal);
    let r2 = g.type_var_of(&IlValue::RetVal);
    assert_eq!(r, r2);
}

#[test]
fn constants_get_fresh_var_each_call_and_emit_integer_constraint() {
    let mut g = TypeConstraintGenerator::new_64bit();
    let v1 = g.type_var_of(&IlValue::Const(7));
    let v2 = g.type_var_of(&IlValue::Const(7));
    assert_ne!(v1, v2, "constants must get fresh vars each time");
    let cs = g.into_constraints();
    let int_count = cs
        .iter()
        .filter(|c| matches!(c.kind, ConstraintKind::IsInteger { .. }))
        .count();
    assert!(int_count >= 2);
}

#[test]
fn const_widths_classified_correctly() {
    let cases: [(i64, u8); 9] = [
        (0, 1),
        (1, 1),
        (127, 1),
        (255, 1),
        (256, 2),
        (65535, 2),
        (65536, 4),
        (i64::from(u32::MAX), 4),
        (i64::from(u32::MAX) + 1, 8),
    ];
    for (c, expected_w) in cases {
        let mut g = TypeConstraintGenerator::new_64bit();
        g.type_var_of(&IlValue::Const(c));
        let cs = g.into_constraints();
        let found = cs.iter().any(|cn| matches!(
            cn.kind,
            ConstraintKind::IsInteger { min_width, .. } if min_width == expected_w
        ));
        assert!(found, "const {c} expected width {expected_w}, cs={cs:?}");
    }
}

#[test]
fn const_negative_signedness() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.type_var_of(&IlValue::Const(-1));
    let cs = g.into_constraints();
    assert!(cs.iter().any(|c| matches!(
        c.kind,
        ConstraintKind::IsInteger { signed: Some(true), .. }
    )));
}

#[test]
fn lookup_returns_var_for_known_il_value() {
    let mut g = TypeConstraintGenerator::new_64bit();
    let v = g.type_var_of(&IlValue::Temp(11));
    assert_eq!(g.lookup(&IlValue::Temp(11)), Some(v));
    assert_eq!(g.lookup(&IlValue::Temp(12)), None);
}

#[test]
fn process_assign_emits_one_equality() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::Assign {
        dst: IlValue::Temp(0),
        src: IlValue::Temp(1),
        addr: 0x10,
    });
    let cs = g.into_constraints();
    let eqs: Vec<_> = cs.iter().filter(|c| matches!(c.kind, ConstraintKind::Equal { .. })).collect();
    assert_eq!(eqs.len(), 1);
}

#[test]
fn process_load_emits_pointer_int_int() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::Load {
        dst: IlValue::Temp(0),
        ptr: IlValue::Temp(1),
        size_bytes: 4,
        addr: 0x10,
    });
    let cs = g.into_constraints();
    assert!(cs.iter().any(|c| matches!(c.kind, ConstraintKind::IsPointerTo { .. })));
    let int_count = cs
        .iter()
        .filter(|c| matches!(c.kind, ConstraintKind::IsInteger { .. }))
        .count();
    assert_eq!(int_count, 2);
}

#[test]
fn process_store_mirrors_load() {
    let mut g = TypeConstraintGenerator::new_32bit();
    g.process(&IlInstr::Store {
        ptr: IlValue::Temp(0),
        src: IlValue::Temp(1),
        size_bytes: 2,
        addr: 0x100,
    });
    let cs = g.into_constraints();
    let ptr_w = cs.iter().find_map(|c| match &c.kind {
        ConstraintKind::IsInteger { var: _, min_width, .. } if *min_width == 4 => Some(*min_width),
        _ => None,
    });
    assert_eq!(ptr_w, Some(4));
}

#[test]
fn process_address_of_emits_pointer_arithmetic_and_pointer_int() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::AddressOf {
        dst: IlValue::Temp(0),
        base: IlValue::Temp(1),
        offset: IlValue::Temp(2),
        scale: 4,
        addr: 0x200,
    });
    let cs = g.into_constraints();
    assert!(cs.iter().any(|c| matches!(c.kind, ConstraintKind::PointerArithmetic { .. })));
}

#[test]
fn process_call_with_and_without_return() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::Call {
        dst: None,
        callee: IlValue::Temp(0),
        args: vec![IlValue::Temp(1), IlValue::Temp(2), IlValue::Temp(3)],
        addr: 0,
    });
    let cs = g.constraints().to_vec();
    assert!(cs.iter().any(|c| matches!(
        c.kind,
        ConstraintKind::IsCallable { param_count: 3, .. }
    )));
    assert!(!cs.iter().any(|c| matches!(c.kind, ConstraintKind::IsReturnOf { .. })));

    let mut g2 = TypeConstraintGenerator::new_64bit();
    g2.process(&IlInstr::Call {
        dst: Some(IlValue::Temp(99)),
        callee: IlValue::Temp(0),
        args: vec![],
        addr: 0,
    });
    let cs2 = g2.into_constraints();
    assert!(cs2.iter().any(|c| matches!(
        c.kind,
        ConstraintKind::IsCallable { param_count: 0, .. }
    )));
    assert!(cs2.iter().any(|c| matches!(c.kind, ConstraintKind::IsReturnOf { .. })));
}

#[test]
fn binop_categories_produce_distinct_constraints() {
    let ops = [
        AbstractBinOp::Add,
        AbstractBinOp::Sub,
        AbstractBinOp::Mul,
        AbstractBinOp::Div,
        AbstractBinOp::Mod,
        AbstractBinOp::And,
        AbstractBinOp::Or,
        AbstractBinOp::Xor,
        AbstractBinOp::Shl,
        AbstractBinOp::Shr,
        AbstractBinOp::Cmp,
    ];
    for op in ops {
        let mut g = TypeConstraintGenerator::new_64bit();
        g.process(&IlInstr::BinOp {
            dst: IlValue::Temp(0),
            lhs: IlValue::Temp(1),
            rhs: IlValue::Temp(2),
            op,
            addr: 0,
        });
        let cs = g.into_constraints();
        assert!(!cs.is_empty(), "op {op:?} produced no constraints");
    }
}

#[test]
fn process_cast_signed_and_unsigned() {
    for signed in [true, false] {
        for w in [1u8, 2, 4, 8] {
            let mut g = TypeConstraintGenerator::new_64bit();
            g.process(&IlInstr::Cast {
                dst: IlValue::Temp(0),
                src: IlValue::Temp(1),
                to_width: w,
                signed,
                addr: 0,
            });
            let cs = g.into_constraints();
            assert!(cs.iter().any(|c| matches!(
                c.kind,
                ConstraintKind::IsInteger { min_width, signed: Some(s), .. } if min_width == w && s == signed
            )));
        }
    }
}

#[test]
fn process_return_with_and_without_val() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::Return { val: None, addr: 0 });
    assert!(g.constraints().is_empty());
    g.process(&IlInstr::Return { val: Some(IlValue::Temp(7)), addr: 0 });
    // Return registers the var but emits no constraint per source.
    assert_eq!(g.lookup(&IlValue::Temp(7)).is_some(), true);
}

#[test]
fn type_var_count_grows_monotonically() {
    let mut g = TypeConstraintGenerator::new_64bit();
    let mut last = g.type_var_count();
    for i in 0..50u32 {
        g.type_var_of(&IlValue::Temp(i));
        let now = g.type_var_count();
        assert!(now > last);
        last = now;
    }
}

#[test]
fn process_all_handles_long_sequence() {
    let mut g = TypeConstraintGenerator::new_64bit();
    let instrs: Vec<IlInstr> = (0..50u32)
        .map(|i| IlInstr::Assign {
            dst: IlValue::Temp(i),
            src: IlValue::Const(i as i64),
            addr: u64::from(i) * 4,
        })
        .collect();
    g.process_all(&instrs);
    assert!(g.constraints().len() >= 50);
    assert!(g.type_var_count() >= 50);
}

#[test]
fn fuzz_constraint_generator_never_panics() {
    let mut g_rand = lcg();
    let mut tcg = TypeConstraintGenerator::new_64bit();
    for _ in 0..400 {
        let kind = g_rand() % 8;
        let a = (g_rand() & 0xFF) as u32;
        let b = (g_rand() & 0xFF) as u32;
        let val_a = match g_rand() % 4 {
            0 => IlValue::Temp(a),
            1 => IlValue::Param(a & 0x3F),
            2 => IlValue::Const(g_rand() as i64),
            _ => IlValue::Global(g_rand()),
        };
        let val_b = match g_rand() % 4 {
            0 => IlValue::Temp(b),
            1 => IlValue::Param(b & 0x3F),
            2 => IlValue::Const(g_rand() as i64),
            _ => IlValue::Global(g_rand()),
        };
        let instr = match kind {
            0 => IlInstr::Assign { dst: val_a.clone(), src: val_b.clone(), addr: g_rand() },
            1 => IlInstr::Load {
                dst: val_a.clone(),
                ptr: val_b.clone(),
                size_bytes: ((g_rand() % 8) + 1) as u8,
                addr: g_rand(),
            },
            2 => IlInstr::Store {
                ptr: val_a.clone(),
                src: val_b.clone(),
                size_bytes: ((g_rand() % 8) + 1) as u8,
                addr: g_rand(),
            },
            3 => IlInstr::BinOp {
                dst: val_a.clone(),
                lhs: val_b.clone(),
                rhs: IlValue::Temp((g_rand() & 0xFF) as u32),
                op: match g_rand() % 11 {
                    0 => AbstractBinOp::Add,
                    1 => AbstractBinOp::Sub,
                    2 => AbstractBinOp::Mul,
                    3 => AbstractBinOp::Div,
                    4 => AbstractBinOp::Mod,
                    5 => AbstractBinOp::And,
                    6 => AbstractBinOp::Or,
                    7 => AbstractBinOp::Xor,
                    8 => AbstractBinOp::Shl,
                    9 => AbstractBinOp::Shr,
                    _ => AbstractBinOp::Cmp,
                },
                addr: g_rand(),
            },
            4 => IlInstr::Cast {
                dst: val_a.clone(),
                src: val_b.clone(),
                to_width: ((g_rand() % 8) + 1) as u8,
                signed: (g_rand() & 1) == 1,
                addr: g_rand(),
            },
            5 => IlInstr::Call {
                dst: if (g_rand() & 1) == 0 { Some(val_a.clone()) } else { None },
                callee: val_b.clone(),
                args: vec![],
                addr: g_rand(),
            },
            6 => IlInstr::AddressOf {
                dst: val_a.clone(),
                base: val_b.clone(),
                offset: IlValue::Const((g_rand() as i64) & 0xFF),
                scale: (g_rand() & 0xF) as u32,
                addr: g_rand(),
            },
            _ => IlInstr::Return {
                val: if (g_rand() & 1) == 0 { Some(val_a.clone()) } else { None },
                addr: g_rand(),
            },
        };
        tcg.process(&instr);
    }
    // Final assertion: still in a consistent state.
    assert!(tcg.type_var_count() > 0);
    let _ = tcg.into_constraints();
}

#[test]
fn provenance_basic() {
    let p = Provenance::new(0x1234, "note");
    assert_eq!(p.address, 0x1234);
    assert_eq!(p.note, "note");
    assert_eq!(p, Provenance::new(0x1234, "note".to_string()));
}

#[test]
fn constraint_certain_has_full_confidence() {
    let c = TypeConstraint::certain(
        0,
        ConstraintKind::Equal { lhs: TypeVar::new(0), rhs: TypeVar::new(1) },
        Provenance::new(0, ""),
    );
    assert_eq!(c.confidence, 1.0);
}

#[test]
fn constraint_heuristic_clamps_confidence() {
    let lo = TypeConstraint::heuristic(
        0,
        ConstraintKind::Equal { lhs: TypeVar::new(0), rhs: TypeVar::new(1) },
        Provenance::new(0, ""),
        -1.0,
    );
    assert!((lo.confidence - 0.0).abs() < f32::EPSILON);
    let hi = TypeConstraint::heuristic(
        0,
        ConstraintKind::Equal { lhs: TypeVar::new(0), rhs: TypeVar::new(1) },
        Provenance::new(0, ""),
        5.0,
    );
    assert!((hi.confidence - 1.0).abs() < f32::EPSILON);
}

#[test]
fn constraint_kind_display_all_arms() {
    let arms = [
        ConstraintKind::Equal { lhs: TypeVar::new(0), rhs: TypeVar::new(1) },
        ConstraintKind::IsPointerTo { ptr: TypeVar::new(0), pointee: TypeVar::new(1) },
        ConstraintKind::HasType { var: TypeVar::new(0), ty: RecoveredType::Int { width: 4, signed: true } },
        ConstraintKind::IsInteger { var: TypeVar::new(0), min_width: 4, signed: Some(true) },
        ConstraintKind::IsInteger { var: TypeVar::new(0), min_width: 4, signed: Some(false) },
        ConstraintKind::IsInteger { var: TypeVar::new(0), min_width: 4, signed: None },
        ConstraintKind::IsFloat { var: TypeVar::new(0), width: 4 },
        ConstraintKind::PointerArithmetic { result: TypeVar::new(0), base: TypeVar::new(1), offset: TypeVar::new(2) },
        ConstraintKind::FieldAccess { struct_var: TypeVar::new(0), field_var: TypeVar::new(1), byte_offset: 8 },
        ConstraintKind::IsCallable { callee: TypeVar::new(0), param_count: 2 },
        ConstraintKind::IsReturnOf { var: TypeVar::new(0), func: TypeVar::new(1) },
        ConstraintKind::IsArray { arr: TypeVar::new(0), elem: TypeVar::new(1), min_count: 4 },
    ];
    for a in &arms {
        let s = format!("{a}");
        assert!(!s.is_empty());
    }
}

#[test]
fn constraint_set_filter_and_views() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::BinOp {
        dst: IlValue::Temp(0),
        lhs: IlValue::Temp(1),
        rhs: IlValue::Temp(2),
        op: AbstractBinOp::Add,
        addr: 0,
    });
    g.process(&IlInstr::Load {
        dst: IlValue::Temp(3),
        ptr: IlValue::Temp(4),
        size_bytes: 4,
        addr: 4,
    });
    let cs = ConstraintSet::new(g.into_constraints());
    assert!(!cs.is_empty());
    let lo = cs.clone().filter_by_confidence(0.5);
    for c in &lo.constraints {
        assert!(c.confidence >= 0.5);
    }
    assert!(!cs.pointer_constraints().is_empty());
    assert!(!cs.equalities().is_empty());
    let empty = ConstraintSet::default();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Unifier tests
// ─────────────────────────────────────────────────────────────────────────────

fn eq_c(id: u32, a: u32, b: u32) -> TypeConstraint {
    TypeConstraint::certain(
        id,
        ConstraintKind::Equal { lhs: TypeVar::new(a), rhs: TypeVar::new(b) },
        Provenance::new(0, ""),
    )
}

fn int_c(id: u32, v: u32, w: u8, signed: Option<bool>) -> TypeConstraint {
    TypeConstraint::certain(
        id,
        ConstraintKind::IsInteger { var: TypeVar::new(v), min_width: w, signed },
        Provenance::new(0, ""),
    )
}

#[test]
fn unifier_empty() {
    let mut u = TypeUnifier::new(4);
    let r = u.solve(&[]).unwrap();
    assert_eq!(r.class_count, 4);
}

#[test]
fn unifier_basic_eq_propagation() {
    let cs = vec![eq_c(0, 0, 1), int_c(1, 1, 4, Some(true))];
    let r = unify_types(&cs, 2).unwrap();
    assert!(matches!(
        r.get(TypeVar::new(0)),
        RecoveredType::Int { width: 4, signed: true }
    ));
}

#[test]
fn unifier_width_accumulates_to_max() {
    let cs = vec![
        int_c(0, 0, 1, Some(false)),
        int_c(1, 0, 2, Some(false)),
        int_c(2, 0, 8, Some(false)),
        int_c(3, 0, 4, Some(false)),
    ];
    let r = unify_types(&cs, 1).unwrap();
    assert!(matches!(
        r.get(TypeVar::new(0)),
        RecoveredType::Int { width: 8, signed: false }
    ));
}

#[test]
fn unifier_signedness_conflict() {
    let cs = vec![int_c(0, 0, 4, Some(true)), int_c(1, 0, 4, Some(false))];
    let err = unify_types(&cs, 1).unwrap_err();
    assert!(matches!(err, UnifyError::SignednessConflict { .. }));
}

#[test]
fn unifier_float_width_conflict() {
    let cs = vec![
        TypeConstraint::certain(
            0,
            ConstraintKind::IsFloat { var: TypeVar::new(0), width: 4 },
            Provenance::new(0, ""),
        ),
        TypeConstraint::certain(
            1,
            ConstraintKind::IsFloat { var: TypeVar::new(0), width: 8 },
            Provenance::new(0, ""),
        ),
    ];
    let err = unify_types(&cs, 1).unwrap_err();
    assert!(matches!(err, UnifyError::TypeConflict { .. }));
}

#[test]
fn unifier_pointer_constraint_marks_pointer() {
    let cs = vec![TypeConstraint::certain(
        0,
        ConstraintKind::IsPointerTo { ptr: TypeVar::new(0), pointee: TypeVar::new(1) },
        Provenance::new(0, ""),
    )];
    let r = unify_types(&cs, 2).unwrap();
    assert!(r.get(TypeVar::new(0)).is_pointer());
}

#[test]
fn unifier_array_constraint() {
    let cs = vec![TypeConstraint::certain(
        0,
        ConstraintKind::IsArray { arr: TypeVar::new(0), elem: TypeVar::new(1), min_count: 7 },
        Provenance::new(0, ""),
    )];
    let r = unify_types(&cs, 2).unwrap();
    assert!(matches!(
        r.get(TypeVar::new(0)),
        RecoveredType::Array { count: 7, .. }
    ));
}

#[test]
fn unifier_callable_constraint() {
    let cs = vec![TypeConstraint::certain(
        0,
        ConstraintKind::IsCallable { callee: TypeVar::new(0), param_count: 4 },
        Provenance::new(0, ""),
    )];
    let r = unify_types(&cs, 1).unwrap();
    assert!(matches!(
        r.get(TypeVar::new(0)),
        RecoveredType::FnPtr { param_count: 4 }
    ));
}

#[test]
fn unifier_transitive_eq_50_vars() {
    let mut cs = vec![];
    let n = 50u32;
    for i in 0..(n - 1) {
        cs.push(eq_c(i, i, i + 1));
    }
    cs.push(int_c(n, n - 1, 4, Some(true)));
    let r = unify_types(&cs, n).unwrap();
    for i in 0..n {
        assert!(matches!(
            r.get(TypeVar::new(i)),
            RecoveredType::Int { width: 4, signed: true }
        ));
    }
}

#[test]
fn unifier_resolved_and_unresolved() {
    let mut u = TypeUnifier::new(4);
    let cs = vec![int_c(0, 0, 4, Some(false))];
    let r = u.solve(&cs).unwrap();
    let res = r.resolved_vars();
    assert!(res.contains(&TypeVar::new(0)));
    assert!(!res.contains(&TypeVar::new(1)));
}

#[test]
fn unifier_pointers_helper() {
    let mut u = TypeUnifier::new(2);
    let cs = vec![TypeConstraint::certain(
        0,
        ConstraintKind::IsPointerTo { ptr: TypeVar::new(0), pointee: TypeVar::new(1) },
        Provenance::new(0, ""),
    )];
    let r = u.solve(&cs).unwrap();
    let ps = r.pointers();
    assert!(ps.iter().any(|(v, _)| *v == TypeVar::new(0)));
}

#[test]
fn unifier_grows_for_unseen_vars() {
    // var_count = 2 but constraint references var 5 — ensure() must grow.
    let cs = vec![int_c(0, 5, 4, Some(true))];
    let r = unify_types(&cs, 2).unwrap();
    assert!(matches!(
        r.get(TypeVar::new(5)),
        RecoveredType::Int { width: 4, signed: true }
    ));
}

#[test]
fn unifier_pointer_then_concrete_int_conflict() {
    // Set concrete int type first via HasType, then mark as pointer → conflict.
    let cs = vec![
        TypeConstraint::certain(
            0,
            ConstraintKind::HasType {
                var: TypeVar::new(0),
                ty: RecoveredType::Int { width: 4, signed: false },
            },
            Provenance::new(0, ""),
        ),
        TypeConstraint::certain(
            1,
            ConstraintKind::IsPointerTo { ptr: TypeVar::new(0), pointee: TypeVar::new(1) },
            Provenance::new(0, ""),
        ),
    ];
    let err = unify_types(&cs, 2).unwrap_err();
    assert!(matches!(err, UnifyError::PointerConflict { .. }));
}

#[test]
fn unifier_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = ((g() % 30) + 1) as u32;
        let cnum = (g() % 60) + 1;
        let mut cs = vec![];
        for i in 0..cnum {
            let kind = g() % 6;
            let a = (g() as u32) % n;
            let b = (g() as u32) % n;
            let c = match kind {
                0 => eq_c(i as u32, a, b),
                1 => int_c(i as u32, a, ((g() % 8) + 1) as u8, Some((g() & 1) == 1)),
                2 => int_c(i as u32, a, ((g() % 8) + 1) as u8, None),
                3 => TypeConstraint::certain(
                    i as u32,
                    ConstraintKind::IsPointerTo {
                        ptr: TypeVar::new(a),
                        pointee: TypeVar::new(b),
                    },
                    Provenance::new(0, ""),
                ),
                4 => TypeConstraint::certain(
                    i as u32,
                    ConstraintKind::IsArray {
                        arr: TypeVar::new(a),
                        elem: TypeVar::new(b),
                        min_count: (g() % 8) as usize,
                    },
                    Provenance::new(0, ""),
                ),
                _ => TypeConstraint::certain(
                    i as u32,
                    ConstraintKind::IsCallable {
                        callee: TypeVar::new(a),
                        param_count: (g() % 4) as usize,
                    },
                    Provenance::new(0, ""),
                ),
            };
            cs.push(c);
        }
        let _ = unify_types(&cs, n);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Struct recovery tests
// ─────────────────────────────────────────────────────────────────────────────

fn tv(n: u32) -> TypeVar {
    TypeVar::new(n)
}

#[test]
fn field_access_constructors_and_range() {
    let r = FieldAccess::read(tv(0), 4, 4, 0x10);
    assert!(!r.is_write);
    assert_eq!(r.range(), (4, 8));
    let w = FieldAccess::write(tv(0), 0, 8, 0);
    assert!(w.is_write);
    assert_eq!(w.range(), (0, 8));
}

#[test]
fn field_access_with_name() {
    let f = FieldAccess::read(tv(0), 0, 4, 0).with_name("foo");
    assert_eq!(f.hint_name.as_deref(), Some("foo"));
}

#[test]
fn field_access_overlaps_50_inputs() {
    let mut g = lcg();
    for _ in 0..50 {
        let off1 = (g() & 0xFF) as u32;
        let sz1 = ((g() % 8) + 1) as u8;
        let off2 = (g() & 0xFF) as u32;
        let sz2 = ((g() % 8) + 1) as u8;
        let a = FieldAccess::read(tv(0), off1, sz1, 0);
        let b = FieldAccess::read(tv(0), off2, sz2, 0);
        let want = (off1 < off2.saturating_add(sz2 as u32)) && (off2 < off1.saturating_add(sz1 as u32));
        assert_eq!(a.overlaps(&b), want);
        assert_eq!(b.overlaps(&a), want); // symmetric
    }
}

#[test]
fn field_access_range_saturates_on_overflow() {
    let f = FieldAccess::read(tv(0), u32::MAX, 8, 0);
    assert_eq!(f.range(), (u32::MAX, u32::MAX));
}

#[test]
fn recover_empty_accesses() {
    let r = recover_structs(&[], 8, 1, false);
    assert!(r.is_empty());
}

#[test]
fn recover_single_access() {
    let r = recover_structs(&[FieldAccess::read(tv(0), 0, 4, 0)], 8, 1, false);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].fields.len(), 1);
    assert_eq!(r[0].total_size, 4);
}

#[test]
fn recover_min_access_filter() {
    let r = recover_structs(&[FieldAccess::read(tv(0), 0, 4, 0)], 8, 2, false);
    assert!(r.is_empty());
}

#[test]
fn recover_deduplicates_identical_accesses() {
    let accesses: Vec<FieldAccess> = (0..10)
        .map(|i| FieldAccess::read(tv(0), 0, 4, i))
        .collect();
    let r = recover_structs(&accesses, 8, 1, false);
    assert_eq!(r[0].fields.len(), 1);
    assert_eq!(r[0].fields[0].access_count, 10);
}

#[test]
fn recover_write_propagates_has_write() {
    let accesses = vec![
        FieldAccess::read(tv(0), 0, 4, 0),
        FieldAccess::write(tv(0), 0, 4, 1),
    ];
    let r = recover_structs(&accesses, 8, 1, false);
    assert!(r[0].fields[0].has_write);
}

#[test]
fn recover_pointer_sized_field_typed_as_pointer() {
    let r = recover_structs(&[FieldAccess::read(tv(0), 0, 8, 0)], 8, 1, false);
    assert!(r[0].fields[0].ty.is_pointer());
}

#[test]
fn recover_non_pointer_sized_field_typed_as_int() {
    let r = recover_structs(&[FieldAccess::read(tv(0), 0, 4, 0)], 8, 1, false);
    assert!(matches!(
        r[0].fields[0].ty,
        RecoveredType::Int { width: 4, .. }
    ));
}

#[test]
fn recover_padding_detection() {
    let accesses = vec![
        FieldAccess::read(tv(0), 0, 4, 0),
        FieldAccess::read(tv(0), 16, 4, 1),
    ];
    let r = recover_structs(&accesses, 8, 1, false);
    assert!(r[0].has_padding);
}

#[test]
fn recover_no_padding_for_contiguous_fields() {
    let accesses = vec![
        FieldAccess::read(tv(0), 0, 4, 0),
        FieldAccess::read(tv(0), 4, 4, 1),
    ];
    let r = recover_structs(&accesses, 8, 1, false);
    assert!(!r[0].has_padding);
}

#[test]
fn recover_sorts_by_base_var() {
    let accesses = vec![
        FieldAccess::read(tv(5), 0, 4, 0),
        FieldAccess::read(tv(2), 0, 4, 1),
        FieldAccess::read(tv(8), 0, 4, 2),
    ];
    let r = recover_structs(&accesses, 8, 1, false);
    assert_eq!(r[0].base_var, tv(2));
    assert_eq!(r[1].base_var, tv(5));
    assert_eq!(r[2].base_var, tv(8));
}

#[test]
fn recover_total_size_is_max_offset_plus_size() {
    let accesses = vec![
        FieldAccess::read(tv(0), 0, 4, 0),
        FieldAccess::read(tv(0), 8, 8, 1),
    ];
    let r = recover_structs(&accesses, 8, 1, false);
    assert_eq!(r[0].total_size, 16);
}

#[test]
fn recover_field_at_and_has_fields() {
    let r = recover_structs(&[FieldAccess::read(tv(0), 12, 4, 0)], 8, 1, false);
    assert!(r[0].has_fields());
    assert!(r[0].field_at(12).is_some());
    assert!(r[0].field_at(0).is_none());
}

#[test]
fn recover_c_decl_contains_braces_and_size() {
    let accesses = vec![
        FieldAccess::read(tv(0), 0, 8, 0).with_name("link"),
        FieldAccess::read(tv(0), 8, 4, 0).with_name("val"),
    ];
    let r = recover_structs(&accesses, 8, 1, true);
    let decl = r[0].to_c_decl();
    assert!(decl.contains("struct"));
    assert!(decl.contains("link"));
    assert!(decl.contains("val"));
    assert!(decl.contains("size = 12"));
}

#[test]
fn recover_overlap_detection_via_engine() {
    let mut engine = StructRecoveryEngine::new_64bit();
    engine.record(FieldAccess::read(tv(0), 0, 8, 0));
    engine.record(FieldAccess::read(tv(0), 4, 4, 0));
    let conflicts = engine.find_conflicts(tv(0));
    assert!(!conflicts.is_empty());
    assert!(conflicts.iter().any(|c| matches!(c.kind, ConflictKind::Overlap)));
}

#[test]
fn recover_size_mismatch_at_same_offset() {
    let mut engine = StructRecoveryEngine::new_64bit();
    engine.record(FieldAccess::read(tv(0), 0, 4, 0));
    engine.record(FieldAccess::read(tv(0), 0, 8, 1));
    let conflicts = engine.find_conflicts(tv(0));
    assert!(conflicts.iter().any(|c| matches!(c.kind, ConflictKind::SizeMismatch { .. })));
}

#[test]
fn recover_union_candidate() {
    // Same-offset accesses of differing size (4 and 8 bytes at offset 0).
    //
    // NOTE — the previous expectation here ("SizeMismatch is not Overlap, so
    // has_overlaps stays false") described an OLD `detect_conflicts`. The engine
    // now counts a same-offset `SizeMismatch` as an overlap on purpose, because
    // the two accesses provably share bytes; that is the union signal, and it is
    // what `is_union_candidate`'s documented contract asks for. Test updated to
    // the intended semantics rather than the engine reverted to the old ones.
    let accesses = vec![
        FieldAccess::read(tv(0), 0, 4, 0),
        FieldAccess::read(tv(0), 0, 8, 1),
    ];
    let r = recover_structs(&accesses, 8, 1, false);
    assert!(r[0].has_overlaps, "same-offset accesses share memory");
    assert!(r[0].is_union_candidate(), "offset 0 + differing sizes = union candidate");
    // Manually construct a struct that satisfies both conditions to exercise
    // the true branch of is_union_candidate.
    let s = RecoveredStruct {
        base_var: tv(0),
        name: "u".into(),
        fields: vec![],
        total_size: 0,
        has_padding: false,
        has_overlaps: true,
    };
    assert!(s.is_union_candidate());
}

#[test]
fn merge_structs_dedupes_fields() {
    let a = recover_structs(&[FieldAccess::read(tv(0), 0, 4, 0)], 8, 1, false).remove(0);
    let b = recover_structs(&[FieldAccess::write(tv(0), 0, 4, 1)], 8, 1, false).remove(0);
    let m = merge_structs(&a, &b);
    assert_eq!(m.fields.len(), 1);
    assert!(m.fields[0].has_write);
}

#[test]
fn struct_db_insert_lookup_names() {
    let mut db = StructDatabase::new();
    assert!(db.is_empty());
    let s = recover_structs(&[FieldAccess::read(tv(7), 0, 4, 0)], 8, 1, false).remove(0);
    db.insert(s);
    assert_eq!(db.len(), 1);
    assert!(db.get(tv(7)).is_some());
    assert!(db.get(tv(8)).is_none());
    let names = db.names();
    assert!(names.iter().any(|n| n.contains("struct_")));
    let all = db.all_structs();
    assert_eq!(all.len(), 1);
}

#[test]
fn struct_db_merge_on_duplicate_insert() {
    let mut db = StructDatabase::new();
    let a = recover_structs(&[FieldAccess::read(tv(0), 0, 4, 0)], 8, 1, false).remove(0);
    let b = recover_structs(&[FieldAccess::read(tv(0), 8, 4, 0)], 8, 1, false).remove(0);
    db.insert(a);
    db.insert(b);
    assert_eq!(db.len(), 1);
    assert_eq!(db.get(tv(0)).unwrap().fields.len(), 2);
}

#[test]
fn recover_fuzz_never_panics() {
    let mut g = lcg();
    let mut accesses = vec![];
    for _ in 0..500 {
        let base = (g() & 0xF) as u32;
        let off = (g() & 0xFF) as u32;
        let sz = ((g() % 8) + 1) as u8;
        if (g() & 1) == 0 {
            accesses.push(FieldAccess::read(tv(base), off, sz, g()));
        } else {
            accesses.push(FieldAccess::write(tv(base), off, sz, g()));
        }
    }
    let r = recover_structs(&accesses, 8, 1, false);
    assert!(!r.is_empty());
}

#[test]
fn engine_record_all_increases_count() {
    let mut e = StructRecoveryEngine::new_32bit();
    let n_before = e.access_count();
    e.record_all((0..10u32).map(|i| FieldAccess::read(tv(0), i, 4, 0)));
    assert_eq!(e.access_count(), n_before + 10);
}

#[test]
fn engine_recover_for_filters_by_base() {
    let mut e = StructRecoveryEngine::new_64bit();
    e.record(FieldAccess::read(tv(0), 0, 4, 0));
    e.record(FieldAccess::read(tv(1), 0, 8, 0));
    let s = e.recover_for(tv(1)).unwrap();
    assert_eq!(s.base_var, tv(1));
    assert_eq!(s.fields.len(), 1);
}

#[test]
fn engine_recover_for_respects_min_access() {
    let mut e = StructRecoveryEngine::new_64bit();
    e.min_access_count = 3;
    e.record(FieldAccess::read(tv(0), 0, 4, 0));
    e.record(FieldAccess::read(tv(0), 4, 4, 0));
    assert!(e.recover_for(tv(0)).is_none());
    e.record(FieldAccess::read(tv(0), 8, 4, 0));
    assert!(e.recover_for(tv(0)).is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// Send/Sync threaded stress
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn typevar_send_sync_threaded() {
    let v = Arc::new(TypeVar::new(7));
    let mut handles = vec![];
    for _ in 0..4 {
        let v = Arc::clone(&v);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                assert_eq!(v.0, 7);
                let s = format!("{}", *v);
                assert_eq!(s, "τ7");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn recovered_type_send_sync_threaded() {
    let t = Arc::new(RecoveredType::Pointer(Box::new(RecoveredType::Int {
        width: 4,
        signed: true,
    })));
    let mut handles = vec![];
    for _ in 0..4 {
        let t = Arc::clone(&t);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                assert!(t.is_pointer());
                let _ = t.display_name();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
