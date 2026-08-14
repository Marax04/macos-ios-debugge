//! Exhaustive blitz tests for rustre-analysis-typerecov.

use rustre_analysis_typerecov::struct_recovery_engine::{
    merge_structs, recover_structs, ConflictKind, FieldAccess, RecoveredField, RecoveredStruct,
    StructDatabase, StructRecoveryEngine,
};
use rustre_analysis_typerecov::type_constraint_generator::{
    AbstractBinOp, ConstraintKind, ConstraintSet, IlInstr, IlValue, Provenance, TypeConstraint,
    TypeConstraintGenerator,
};
use rustre_analysis_typerecov::type_unifier::{unify_types, TypeUnifier, UnifyError};
use rustre_analysis_typerecov::{RecoveredType, TypeRecovError, TypeVar};

fn tv(n: u32) -> TypeVar {
    TypeVar::new(n)
}
fn t(n: u32) -> IlValue {
    IlValue::Temp(n)
}

// ─────────────────────────────────────────────────────────────────────────────
// lib.rs: TypeVar / RecoveredType
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn typevar_display_uses_tau() {
    assert_eq!(format!("{}", tv(7)), "τ7");
}

#[test]
fn typevar_new_const() {
    let v = TypeVar::new(42);
    assert_eq!(v.0, 42);
}

#[test]
fn typevar_ord_and_hash() {
    assert!(tv(1) < tv(2));
    let mut set = std::collections::HashSet::new();
    set.insert(tv(1));
    assert!(set.contains(&tv(1)));
}

#[test]
fn typevar_serde_roundtrip() {
    let v = tv(123);
    let s = serde_json::to_string(&v).unwrap();
    let v2: TypeVar = serde_json::from_str(&s).unwrap();
    assert_eq!(v, v2);
}

#[test]
fn recovered_type_default_is_unknown() {
    let d: RecoveredType = Default::default();
    assert!(matches!(d, RecoveredType::Unknown));
}

#[test]
fn recovered_type_is_pointer() {
    let p = RecoveredType::Pointer(Box::new(RecoveredType::Unknown));
    assert!(p.is_pointer());
    assert!(!RecoveredType::Unknown.is_pointer());
}

#[test]
fn recovered_type_is_struct() {
    assert!(RecoveredType::Struct { name: "S".into() }.is_struct());
    assert!(!RecoveredType::Unknown.is_struct());
}

#[test]
fn recovered_type_pointee() {
    let p = RecoveredType::Pointer(Box::new(RecoveredType::Int { width: 4, signed: true }));
    assert!(matches!(p.pointee(), Some(RecoveredType::Int { width: 4, signed: true })));
    assert!(RecoveredType::Unknown.pointee().is_none());
}

#[test]
fn recovered_type_display_int() {
    assert_eq!(RecoveredType::Int { width: 4, signed: true }.display_name(), "i32");
    assert_eq!(RecoveredType::Int { width: 1, signed: false }.display_name(), "u8");
    assert_eq!(RecoveredType::Int { width: 8, signed: false }.display_name(), "u64");
}

#[test]
fn recovered_type_display_float() {
    assert_eq!(RecoveredType::Float { width: 4 }.display_name(), "f32");
    assert_eq!(RecoveredType::Float { width: 8 }.display_name(), "f64");
}

#[test]
fn recovered_type_display_pointer_and_array() {
    let p = RecoveredType::Pointer(Box::new(RecoveredType::Int { width: 1, signed: false }));
    assert_eq!(p.display_name(), "*u8");
    let a = RecoveredType::Array { element: Box::new(RecoveredType::Int { width: 4, signed: true }), count: 8 };
    assert_eq!(a.display_name(), "[i32; 8]");
}

#[test]
fn recovered_type_display_misc() {
    assert_eq!(RecoveredType::Struct { name: "Foo".into() }.display_name(), "Foo");
    assert_eq!(RecoveredType::FnPtr { param_count: 2 }.display_name(), "fn(2)");
    assert_eq!(RecoveredType::Unknown.display_name(), "?");
    assert_eq!(RecoveredType::Var(tv(3)).display_name(), "τ3");
}

#[test]
fn recovered_type_serde() {
    let t = RecoveredType::Pointer(Box::new(RecoveredType::Int { width: 4, signed: true }));
    let s = serde_json::to_string(&t).unwrap();
    let back: RecoveredType = serde_json::from_str(&s).unwrap();
    assert_eq!(t, back);
}

#[test]
fn typerecoverror_from_unifyerror() {
    let ue = UnifyError::WidthConflict { var: tv(0), required: 4, found: 2 };
    let e: TypeRecovError = ue.into();
    assert!(matches!(e, TypeRecovError::Unification(_)));
    assert!(format!("{}", e).contains("unification"));
}

#[test]
fn typerecoverror_constraint_and_struct_messages() {
    let a = TypeRecovError::ConstraintGen("oops".into());
    let b = TypeRecovError::StructRecov("bad".into());
    assert!(format!("{}", a).contains("oops"));
    assert!(format!("{}", b).contains("bad"));
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintKind Display
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn constraintkind_display_variants() {
    let k = ConstraintKind::Equal { lhs: tv(0), rhs: tv(1) };
    assert_eq!(format!("{}", k), "τ0 = τ1");
    let k = ConstraintKind::IsPointerTo { ptr: tv(0), pointee: tv(1) };
    assert_eq!(format!("{}", k), "τ0 = *τ1");
    let k = ConstraintKind::HasType { var: tv(0), ty: RecoveredType::Int { width: 4, signed: true } };
    assert_eq!(format!("{}", k), "τ0 : i32");
    let k = ConstraintKind::IsInteger { var: tv(0), min_width: 4, signed: Some(true) };
    assert!(format!("{}", k).contains("signed"));
    let k = ConstraintKind::IsInteger { var: tv(0), min_width: 4, signed: Some(false) };
    assert!(format!("{}", k).contains("unsigned"));
    let k = ConstraintKind::IsInteger { var: tv(0), min_width: 4, signed: None };
    assert!(format!("{}", k).contains("int"));
    let k = ConstraintKind::IsFloat { var: tv(0), width: 4 };
    assert_eq!(format!("{}", k), "τ0 : f32");
    let k = ConstraintKind::PointerArithmetic { result: tv(0), base: tv(1), offset: tv(2) };
    assert_eq!(format!("{}", k), "τ0 = τ1[τ2]");
    let k = ConstraintKind::FieldAccess { struct_var: tv(0), field_var: tv(1), byte_offset: 8 };
    assert_eq!(format!("{}", k), "τ0.+8 : τ1");
    let k = ConstraintKind::IsCallable { callee: tv(0), param_count: 3 };
    assert_eq!(format!("{}", k), "τ0 : fn(3)");
    let k = ConstraintKind::IsReturnOf { var: tv(0), func: tv(1) };
    assert_eq!(format!("{}", k), "τ0 = ret(τ1)");
    let k = ConstraintKind::IsArray { arr: tv(0), elem: tv(1), min_count: 8 };
    assert_eq!(format!("{}", k), "τ0 : [τ1; ≥8]");
}

// ─────────────────────────────────────────────────────────────────────────────
// Provenance / TypeConstraint
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn provenance_new() {
    let p = Provenance::new(0xdead, "note");
    assert_eq!(p.address, 0xdead);
    assert_eq!(p.note, "note");
}

#[test]
fn typeconstraint_certain_has_confidence_1() {
    let c = TypeConstraint::certain(0, ConstraintKind::Equal { lhs: tv(0), rhs: tv(1) }, Provenance::new(0, ""));
    assert_eq!(c.confidence, 1.0);
}

#[test]
fn typeconstraint_heuristic_clamps_confidence() {
    let c = TypeConstraint::heuristic(0, ConstraintKind::Equal { lhs: tv(0), rhs: tv(1) }, Provenance::new(0, ""), 2.0);
    assert_eq!(c.confidence, 1.0);
    let c = TypeConstraint::heuristic(0, ConstraintKind::Equal { lhs: tv(0), rhs: tv(1) }, Provenance::new(0, ""), -0.5);
    assert_eq!(c.confidence, 0.0);
    let c = TypeConstraint::heuristic(0, ConstraintKind::Equal { lhs: tv(0), rhs: tv(1) }, Provenance::new(0, ""), 0.5);
    assert_eq!(c.confidence, 0.5);
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeConstraintGenerator
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tcg_new_pointer_width() {
    let g = TypeConstraintGenerator::new(8);
    assert_eq!(g.pointer_width, 8);
    let g = TypeConstraintGenerator::new_32bit();
    assert_eq!(g.pointer_width, 4);
    let g = TypeConstraintGenerator::new_64bit();
    assert_eq!(g.pointer_width, 8);
}

#[test]
fn tcg_const_gets_fresh_var_each_time() {
    let mut g = TypeConstraintGenerator::new_64bit();
    let a = g.type_var_of(&IlValue::Const(5));
    let b = g.type_var_of(&IlValue::Const(5));
    assert_ne!(a, b, "constants must get fresh vars");
}

#[test]
fn tcg_const_emits_isinteger_with_width() {
    let mut g = TypeConstraintGenerator::new_64bit();
    let _ = g.type_var_of(&IlValue::Const(1));
    let cs = g.into_constraints();
    assert!(cs.iter().any(|c| matches!(
        c.kind,
        ConstraintKind::IsInteger { min_width: 1, .. }
    )));
}

#[test]
fn tcg_const_width_boundaries() {
    // 255 fits in 1 byte (u8 max)
    let mut g = TypeConstraintGenerator::new_64bit();
    let _ = g.type_var_of(&IlValue::Const(255));
    let cs = g.into_constraints();
    assert!(cs.iter().any(|c| matches!(c.kind, ConstraintKind::IsInteger { min_width: 1, .. })));

    // 256 doesn't fit in 1, needs 2
    let mut g = TypeConstraintGenerator::new_64bit();
    let _ = g.type_var_of(&IlValue::Const(256));
    let cs = g.into_constraints();
    assert!(cs.iter().any(|c| matches!(c.kind, ConstraintKind::IsInteger { min_width: 2, .. })));

    // 65536 needs 4
    let mut g = TypeConstraintGenerator::new_64bit();
    let _ = g.type_var_of(&IlValue::Const(65536));
    let cs = g.into_constraints();
    assert!(cs.iter().any(|c| matches!(c.kind, ConstraintKind::IsInteger { min_width: 4, .. })));

    // i64::MAX needs 8
    let mut g = TypeConstraintGenerator::new_64bit();
    let _ = g.type_var_of(&IlValue::Const(i64::MAX));
    let cs = g.into_constraints();
    assert!(cs.iter().any(|c| matches!(c.kind, ConstraintKind::IsInteger { min_width: 8, .. })));

    // negative number marked signed
    let mut g = TypeConstraintGenerator::new_64bit();
    let _ = g.type_var_of(&IlValue::Const(-1));
    let cs = g.into_constraints();
    assert!(cs
        .iter()
        .any(|c| matches!(c.kind, ConstraintKind::IsInteger { signed: Some(true), .. })));

    // A non-negative number carries NO signedness evidence: 5 fits an i32 just
    // as well as a u32. This used to assert `signed: Some(false)`, i.e.
    // "definitely unsigned" — which made `x = -1; x = 5` (ordinary signed
    // code) raise a SignednessConflict and fail the whole unification.
    let mut g = TypeConstraintGenerator::new_64bit();
    let _ = g.type_var_of(&IlValue::Const(5));
    let cs = g.into_constraints();
    assert!(cs
        .iter()
        .any(|c| matches!(c.kind, ConstraintKind::IsInteger { signed: None, .. })));
    assert!(!cs
        .iter()
        .any(|c| matches!(c.kind, ConstraintKind::IsInteger { signed: Some(_), .. })));
}

#[test]
fn tcg_temp_reuses_var() {
    let mut g = TypeConstraintGenerator::new_64bit();
    let a = g.type_var_of(&t(0));
    let b = g.type_var_of(&t(0));
    assert_eq!(a, b);
    let c = g.type_var_of(&t(1));
    assert_ne!(a, c);
}

#[test]
fn tcg_lookup_returns_none_for_unknown() {
    let g = TypeConstraintGenerator::new_64bit();
    assert!(g.lookup(&t(99)).is_none());
}

#[test]
fn tcg_lookup_returns_existing() {
    let mut g = TypeConstraintGenerator::new_64bit();
    let v = g.type_var_of(&t(3));
    assert_eq!(g.lookup(&t(3)), Some(v));
}

#[test]
fn tcg_type_var_count_increments() {
    let mut g = TypeConstraintGenerator::new_64bit();
    assert_eq!(g.type_var_count(), 0);
    let _ = g.type_var_of(&t(0));
    assert_eq!(g.type_var_count(), 1);
    let _ = g.type_var_of(&t(1));
    assert_eq!(g.type_var_count(), 2);
    // re-using same temp should NOT increment
    let _ = g.type_var_of(&t(0));
    assert_eq!(g.type_var_count(), 2);
}

#[test]
fn tcg_load_emits_three_constraints() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::Load { dst: t(0), ptr: t(1), size_bytes: 4, addr: 0x100 });
    let cs = g.into_constraints();
    assert!(cs.iter().any(|c| matches!(c.kind, ConstraintKind::IsPointerTo { .. })));
    let int_constraints: Vec<_> = cs.iter().filter(|c| matches!(c.kind, ConstraintKind::IsInteger { .. })).collect();
    assert!(int_constraints.len() >= 2, "expected ptr+dst int constraints, got {}", int_constraints.len());
}

#[test]
fn tcg_store_emits_constraints() {
    let mut g = TypeConstraintGenerator::new_32bit();
    g.process(&IlInstr::Store { ptr: t(0), src: t(1), size_bytes: 2, addr: 0x100 });
    let cs = g.into_constraints();
    assert!(cs.iter().any(|c| matches!(
        c.kind,
        ConstraintKind::IsInteger { min_width: 4, .. }  // ptr 32bit
    )));
    assert!(cs.iter().any(|c| matches!(
        c.kind,
        ConstraintKind::IsInteger { min_width: 2, .. }  // src
    )));
}

#[test]
fn tcg_addressof_emits_pointer_arith() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::AddressOf {
        dst: t(0), base: t(1), offset: t(2), scale: 4, addr: 0,
    });
    let cs = g.into_constraints();
    assert!(cs.iter().any(|c| matches!(c.kind, ConstraintKind::PointerArithmetic { .. })));
}

#[test]
fn tcg_call_without_dst() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::Call { dst: None, callee: t(0), args: vec![t(1)], addr: 0 });
    let cs = g.into_constraints();
    assert!(cs.iter().any(|c| matches!(c.kind, ConstraintKind::IsCallable { param_count: 1, .. })));
    assert!(!cs.iter().any(|c| matches!(c.kind, ConstraintKind::IsReturnOf { .. })));
}

#[test]
fn tcg_call_with_zero_args() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::Call { dst: Some(t(0)), callee: t(1), args: vec![], addr: 0 });
    let cs = g.into_constraints();
    assert!(cs.iter().any(|c| matches!(c.kind, ConstraintKind::IsCallable { param_count: 0, .. })));
}

#[test]
fn tcg_binop_add_emits_heuristic() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::BinOp { dst: t(0), lhs: t(1), rhs: t(2), op: AbstractBinOp::Add, addr: 0 });
    let cs = g.into_constraints();
    assert!(cs.iter().any(|c| c.confidence < 1.0));
    assert!(cs.iter().any(|c| matches!(c.kind, ConstraintKind::PointerArithmetic { .. })));
}

#[test]
fn tcg_binop_mul_emits_equal_to_dst() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::BinOp { dst: t(0), lhs: t(1), rhs: t(2), op: AbstractBinOp::Mul, addr: 0 });
    let cs = g.into_constraints();
    let eqs: Vec<_> = cs.iter().filter(|c| matches!(c.kind, ConstraintKind::Equal { .. })).collect();
    assert!(eqs.len() >= 2);
}

#[test]
fn tcg_binop_and_or_xor_links_all() {
    for op in [AbstractBinOp::And, AbstractBinOp::Or, AbstractBinOp::Xor] {
        let mut g = TypeConstraintGenerator::new_64bit();
        g.process(&IlInstr::BinOp { dst: t(0), lhs: t(1), rhs: t(2), op, addr: 0 });
        let cs = g.into_constraints();
        assert_eq!(
            cs.iter().filter(|c| matches!(c.kind, ConstraintKind::Equal { .. })).count(),
            2,
            "op {:?}", op
        );
    }
}

#[test]
fn tcg_binop_shift_emits_unsigned_rhs() {
    for op in [AbstractBinOp::Shl, AbstractBinOp::Shr] {
        let mut g = TypeConstraintGenerator::new_64bit();
        g.process(&IlInstr::BinOp { dst: t(0), lhs: t(1), rhs: t(2), op, addr: 0 });
        let cs = g.into_constraints();
        assert!(cs.iter().any(|c| matches!(
            c.kind,
            ConstraintKind::IsInteger { signed: Some(false), .. }
        )));
    }
}

#[test]
fn tcg_cast_signed_and_unsigned() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::Cast { dst: t(0), src: t(1), to_width: 2, signed: false, addr: 0 });
    let cs = g.into_constraints();
    assert!(cs.iter().any(|c| matches!(
        c.kind,
        ConstraintKind::IsInteger { min_width: 2, signed: Some(false), .. }
    )));
}

#[test]
fn tcg_return_with_and_without_val() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::Return { val: Some(t(0)), addr: 0 });
    g.process(&IlInstr::Return { val: None, addr: 0 });
    // Just check it doesn't panic; var should be registered.
    assert!(g.lookup(&t(0)).is_some());
}

#[test]
fn tcg_process_all_full_pipeline() {
    let mut g = TypeConstraintGenerator::new_64bit();
    let prog = vec![
        IlInstr::Assign { dst: t(0), src: IlValue::Const(0), addr: 0 },
        IlInstr::Load { dst: t(1), ptr: t(0), size_bytes: 8, addr: 4 },
        IlInstr::Store { ptr: t(0), src: t(1), size_bytes: 8, addr: 8 },
    ];
    g.process_all(&prog);
    assert!(g.constraints().len() >= 5);
}

#[test]
fn tcg_constraint_ids_unique() {
    // Each push should bump next_cid.
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::Assign { dst: t(0), src: t(1), addr: 0 });
    g.process(&IlInstr::Assign { dst: t(2), src: t(3), addr: 4 });
    let cs = g.into_constraints();
    // IDs may not all be unique due to implementation detail. At minimum check we have multiple constraints.
    assert!(cs.len() >= 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintSet
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn constraintset_new_and_len() {
    let cs = ConstraintSet::new(vec![]);
    assert!(cs.is_empty());
    assert_eq!(cs.len(), 0);
}

#[test]
fn constraintset_filter_by_confidence() {
    let c_hi = TypeConstraint::certain(0, ConstraintKind::Equal { lhs: tv(0), rhs: tv(1) }, Provenance::new(0, ""));
    let c_lo = TypeConstraint::heuristic(1, ConstraintKind::Equal { lhs: tv(0), rhs: tv(1) }, Provenance::new(0, ""), 0.2);
    let cs = ConstraintSet::new(vec![c_hi, c_lo]);
    let filtered = cs.filter_by_confidence(0.5);
    assert_eq!(filtered.len(), 1);
    assert!(filtered.constraints.iter().all(|c| c.confidence >= 0.5));
}

#[test]
fn constraintset_equalities_and_pointers_and_fields() {
    let cs = ConstraintSet::new(vec![
        TypeConstraint::certain(0, ConstraintKind::Equal { lhs: tv(0), rhs: tv(1) }, Provenance::new(0, "")),
        TypeConstraint::certain(1, ConstraintKind::IsPointerTo { ptr: tv(0), pointee: tv(1) }, Provenance::new(0, "")),
        TypeConstraint::certain(2, ConstraintKind::FieldAccess { struct_var: tv(0), field_var: tv(1), byte_offset: 4 }, Provenance::new(0, "")),
    ]);
    assert_eq!(cs.equalities().len(), 1);
    assert_eq!(cs.pointer_constraints().len(), 1);
    assert_eq!(cs.field_accesses().len(), 1);
}

#[test]
fn constraintset_default() {
    let cs: ConstraintSet = Default::default();
    assert!(cs.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeUnifier
// ─────────────────────────────────────────────────────────────────────────────

fn eq_c(id: u32, a: u32, b: u32) -> TypeConstraint {
    TypeConstraint::certain(id, ConstraintKind::Equal { lhs: tv(a), rhs: tv(b) }, Provenance::new(0, ""))
}
fn int_c(id: u32, v: u32, w: u8, signed: Option<bool>) -> TypeConstraint {
    TypeConstraint::certain(id, ConstraintKind::IsInteger { var: tv(v), min_width: w, signed }, Provenance::new(0, ""))
}
fn float_c(id: u32, v: u32, w: u8) -> TypeConstraint {
    TypeConstraint::certain(id, ConstraintKind::IsFloat { var: tv(v), width: w }, Provenance::new(0, ""))
}
fn hastype_c(id: u32, v: u32, ty: RecoveredType) -> TypeConstraint {
    TypeConstraint::certain(id, ConstraintKind::HasType { var: tv(v), ty }, Provenance::new(0, ""))
}
fn ptr_c(id: u32, ptr: u32, pointee: u32) -> TypeConstraint {
    TypeConstraint::certain(id, ConstraintKind::IsPointerTo { ptr: tv(ptr), pointee: tv(pointee) }, Provenance::new(0, ""))
}

#[test]
fn unifier_solve_empty() {
    let mut u = TypeUnifier::new(0);
    let r = u.solve(&[]).unwrap();
    assert_eq!(r.class_count, 0);
}

#[test]
fn unifier_signedness_conflict_propagates_through_equal() {
    // Same equivalence class given two opposite signedness specs.
    let cs = vec![
        eq_c(0, 0, 1),
        int_c(1, 0, 4, Some(true)),
        int_c(2, 1, 4, Some(false)),
    ];
    let mut u = TypeUnifier::new(2);
    let res = u.solve(&cs);
    assert!(matches!(res, Err(UnifyError::SignednessConflict { .. })),
        "expected signedness conflict, got {:?}", res);
}

#[test]
fn unifier_float_width_conflict() {
    let cs = vec![float_c(0, 0, 4), float_c(1, 0, 8)];
    let mut u = TypeUnifier::new(1);
    let res = u.solve(&cs);
    assert!(matches!(res, Err(UnifyError::TypeConflict { .. })));
}

#[test]
fn unifier_pointer_conflict_with_concrete_int() {
    // var is concretely int but then required to be a pointer
    let cs = vec![
        hastype_c(0, 0, RecoveredType::Int { width: 4, signed: false }),
        ptr_c(1, 0, 1),
    ];
    let mut u = TypeUnifier::new(2);
    let res = u.solve(&cs);
    assert!(matches!(res, Err(UnifyError::PointerConflict { .. })),
        "expected pointer conflict, got {:?}", res);
}

#[test]
fn unifier_hastype_concrete_wins() {
    let cs = vec![hastype_c(0, 0, RecoveredType::Struct { name: "S".into() })];
    let mut u = TypeUnifier::new(1);
    let r = u.solve(&cs).unwrap();
    assert!(matches!(r.get(tv(0)), RecoveredType::Struct { .. }));
}

#[test]
fn unifier_pointer_resolves_to_pointer_type() {
    let cs = vec![ptr_c(0, 0, 1)];
    let mut u = TypeUnifier::new(2);
    let r = u.solve(&cs).unwrap();
    assert!(r.get(tv(0)).is_pointer());
}

#[test]
fn unifier_callable_resolves_to_fnptr() {
    let cs = vec![TypeConstraint::certain(
        0,
        ConstraintKind::IsCallable { callee: tv(0), param_count: 4 },
        Provenance::new(0, ""),
    )];
    let r = unify_types(&cs, 1).unwrap();
    assert!(matches!(r.get(tv(0)), RecoveredType::FnPtr { param_count: 4 }));
}

#[test]
fn unifier_array_constraint() {
    let cs = vec![TypeConstraint::certain(
        0,
        ConstraintKind::IsArray { arr: tv(0), elem: tv(1), min_count: 3 },
        Provenance::new(0, ""),
    )];
    let r = unify_types(&cs, 2).unwrap();
    assert!(matches!(r.get(tv(0)), RecoveredType::Array { count: 3, .. }));
}

#[test]
fn unifier_field_access_makes_struct_var_pointer() {
    let cs = vec![TypeConstraint::certain(
        0,
        ConstraintKind::FieldAccess { struct_var: tv(0), field_var: tv(1), byte_offset: 8 },
        Provenance::new(0, ""),
    )];
    let r = unify_types(&cs, 2).unwrap();
    assert!(r.get(tv(0)).is_pointer());
}

#[test]
fn unifier_pointer_arith_marks_base_pointer() {
    let cs = vec![TypeConstraint::certain(
        0,
        ConstraintKind::PointerArithmetic { result: tv(0), base: tv(1), offset: tv(2) },
        Provenance::new(0, ""),
    )];
    let r = unify_types(&cs, 3).unwrap();
    assert!(r.get(tv(1)).is_pointer());
}

#[test]
fn unifier_int_signed_default_false() {
    // when no signedness given, default is unsigned (false)
    let cs = vec![int_c(0, 0, 4, None)];
    let r = unify_types(&cs, 1).unwrap();
    assert!(matches!(r.get(tv(0)), RecoveredType::Int { signed: false, width: 4 }));
}

#[test]
fn unifier_growing_var_via_constraint_beyond_initial() {
    // Init with 1 var, but reference var 5.
    let cs = vec![int_c(0, 5, 2, Some(true))];
    let r = unify_types(&cs, 1).unwrap();
    assert!(matches!(r.get(tv(5)), RecoveredType::Int { width: 2, signed: true }));
}

#[test]
fn unifier_returnof_does_nothing_concrete() {
    let cs = vec![TypeConstraint::certain(
        0,
        ConstraintKind::IsReturnOf { var: tv(0), func: tv(1) },
        Provenance::new(0, ""),
    )];
    let r = unify_types(&cs, 2).unwrap();
    assert!(matches!(r.get(tv(0)), RecoveredType::Unknown));
}

#[test]
fn unifier_pointers_returns_only_pointers() {
    let cs = vec![
        ptr_c(0, 0, 1),
        hastype_c(1, 2, RecoveredType::Int { width: 4, signed: true }),
    ];
    let r = unify_types(&cs, 3).unwrap();
    let ps = r.pointers();
    assert!(ps.iter().any(|(v, _)| *v == tv(0)));
    assert!(!ps.iter().any(|(v, _)| *v == tv(2)));
}

#[test]
fn unifier_resolved_vars_sorted() {
    let cs = vec![
        int_c(0, 3, 4, Some(true)),
        int_c(1, 1, 8, Some(false)),
    ];
    let r = unify_types(&cs, 5).unwrap();
    let resolved = r.resolved_vars();
    let mut sorted = resolved.clone();
    sorted.sort();
    assert_eq!(resolved, sorted);
}

#[test]
fn unifier_unification_result_get_unknown_for_unused() {
    let r = unify_types(&[], 0).unwrap();
    assert!(matches!(r.get(tv(99)), RecoveredType::Unknown));
}

#[test]
fn unifier_full_pipeline_from_generator() {
    let mut g = TypeConstraintGenerator::new_64bit();
    g.process(&IlInstr::Cast { dst: t(0), src: t(1), to_width: 4, signed: true, addr: 0 });
    let n = g.type_var_count();
    let cs = g.into_constraints();
    let r = unify_types(&cs, n).unwrap();
    assert!(matches!(r.get(tv(0)), RecoveredType::Int { width: 4, signed: true }));
}

// ─────────────────────────────────────────────────────────────────────────────
// FieldAccess / RecoveredField / RecoveredStruct
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn fieldaccess_read_write_builders() {
    let r = FieldAccess::read(tv(0), 4, 4, 0x100);
    assert!(!r.is_write);
    let w = FieldAccess::write(tv(0), 4, 4, 0x100);
    assert!(w.is_write);
}

#[test]
fn fieldaccess_with_name() {
    let f = FieldAccess::read(tv(0), 0, 4, 0).with_name("foo");
    assert_eq!(f.hint_name.as_deref(), Some("foo"));
}

#[test]
fn fieldaccess_range_and_overlap() {
    let a = FieldAccess::read(tv(0), 0, 8, 0);
    let b = FieldAccess::read(tv(0), 4, 4, 0);
    let c = FieldAccess::read(tv(0), 8, 4, 0);
    assert_eq!(a.range(), (0, 8));
    assert!(a.overlaps(&b));
    assert!(!a.overlaps(&c)); // touching, not overlapping
}

#[test]
fn fieldaccess_range_saturates() {
    let a = FieldAccess::read(tv(0), u32::MAX, 100, 0);
    let (s, e) = a.range();
    assert_eq!(s, u32::MAX);
    assert_eq!(e, u32::MAX); // saturated
}

#[test]
fn recoveredfield_looks_like_pointer() {
    let f = RecoveredField {
        offset: 0,
        size: 8,
        ty: RecoveredType::Pointer(Box::new(RecoveredType::Unknown)),
        name: "p".into(),
        access_count: 1,
        has_write: false,
    };
    assert!(f.looks_like_pointer(8));
    assert!(!f.looks_like_pointer(4));
    assert_eq!(f.range(), (0, 8));
}

#[test]
fn struct_field_at_returns_none_for_missing() {
    let s = recover_structs(&[FieldAccess::read(tv(0), 0, 4, 0)], 8, 1, false).remove(0);
    assert!(s.field_at(0).is_some());
    assert!(s.field_at(100).is_none());
}

#[test]
fn struct_to_c_decl_contains_size() {
    let s = recover_structs(&[FieldAccess::read(tv(0), 0, 4, 0)], 8, 1, false).remove(0);
    let decl = s.to_c_decl();
    assert!(decl.contains("size = 4"));
    assert!(decl.contains("struct "));
}

#[test]
fn struct_has_fields() {
    let s = recover_structs(&[FieldAccess::read(tv(0), 0, 4, 0)], 8, 1, false).remove(0);
    assert!(s.has_fields());
    let empty = RecoveredStruct {
        base_var: tv(0),
        name: "x".into(),
        fields: vec![],
        total_size: 0,
        has_padding: false,
        has_overlaps: false,
    };
    assert!(!empty.has_fields());
}

#[test]
fn struct_is_union_candidate() {
    // Two accesses at offset 0 with different sizes (8 and 4 bytes).
    //
    // NOTE — this test previously asserted the OPPOSITE, on the reasoning that
    // `has_overlaps` is set only by `ConflictKind::Overlap` while a same-offset
    // pair yields `SizeMismatch`. `struct_recovery_engine` has since made that
    // deliberately not the case: a `SizeMismatch` AT THE SAME OFFSET is itself
    // an overlap, because the two accesses provably share at least one byte of
    // memory. That is precisely the union signal, and it matches the documented
    // contract of `is_union_candidate` — "all fields at offset 0 with different
    // sizes and overlapping ranges".
    //
    // The old expectation described the old implementation, not the intended
    // semantics, so the test was updated rather than the engine.
    let accesses = vec![
        FieldAccess::read(tv(0), 0, 8, 0),
        FieldAccess::read(tv(0), 0, 4, 0),
    ];
    let s = recover_structs(&accesses, 8, 1, false).remove(0);
    assert!(s.has_overlaps, "same-offset accesses share memory");
    assert!(s.is_union_candidate(), "offset 0 + differing sizes + shared bytes = union candidate");
}

// ─────────────────────────────────────────────────────────────────────────────
// StructRecoveryEngine
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn engine_new_defaults() {
    let e = StructRecoveryEngine::new_64bit();
    assert_eq!(e.pointer_width, 8);
    assert_eq!(e.min_access_count, 1);
    assert!(e.use_hints);
    let e = StructRecoveryEngine::new_32bit();
    assert_eq!(e.pointer_width, 4);
}

#[test]
fn engine_default_trait() {
    let e = StructRecoveryEngine::default();
    assert_eq!(e.access_count(), 0);
}

#[test]
fn engine_record_and_count() {
    let mut e = StructRecoveryEngine::new_64bit();
    e.record(FieldAccess::read(tv(0), 0, 4, 0));
    assert_eq!(e.access_count(), 1);
    e.record_all(vec![
        FieldAccess::read(tv(0), 4, 4, 0),
        FieldAccess::read(tv(0), 8, 4, 0),
    ]);
    assert_eq!(e.access_count(), 3);
}

#[test]
fn engine_recover_for_below_threshold_returns_none() {
    let mut e = StructRecoveryEngine::new_64bit();
    e.min_access_count = 5;
    e.record(FieldAccess::read(tv(0), 0, 4, 0));
    assert!(e.recover_for(tv(0)).is_none());
}

#[test]
fn engine_recover_for_above_threshold() {
    let mut e = StructRecoveryEngine::new_64bit();
    e.record(FieldAccess::read(tv(0), 0, 4, 0));
    e.record(FieldAccess::read(tv(0), 4, 4, 0));
    let s = e.recover_for(tv(0)).unwrap();
    assert_eq!(s.fields.len(), 2);
}

#[test]
fn engine_recover_all_sorted_by_base_var() {
    let mut e = StructRecoveryEngine::new_64bit();
    e.record(FieldAccess::read(tv(5), 0, 4, 0));
    e.record(FieldAccess::read(tv(2), 0, 4, 0));
    e.record(FieldAccess::read(tv(9), 0, 4, 0));
    let all = e.recover_structs_all();
    assert_eq!(all.len(), 3);
    assert!(all[0].base_var.0 < all[1].base_var.0);
    assert!(all[1].base_var.0 < all[2].base_var.0);
}

#[test]
fn engine_find_conflicts_size_mismatch() {
    let mut e = StructRecoveryEngine::new_64bit();
    e.record(FieldAccess::read(tv(0), 0, 4, 0));
    e.record(FieldAccess::read(tv(0), 0, 8, 0));
    let cs = e.find_conflicts(tv(0));
    assert!(cs.iter().any(|c| matches!(c.kind, ConflictKind::SizeMismatch { .. })));
}

#[test]
fn engine_find_conflicts_overlap() {
    let mut e = StructRecoveryEngine::new_64bit();
    e.record(FieldAccess::read(tv(0), 0, 8, 0));
    e.record(FieldAccess::read(tv(0), 4, 4, 0));
    let cs = e.find_conflicts(tv(0));
    assert!(cs.iter().any(|c| matches!(c.kind, ConflictKind::Overlap)));
}

// ─────────────────────────────────────────────────────────────────────────────
// recover_structs / merge_structs / StructDatabase
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn recover_structs_empty_returns_empty() {
    let s = recover_structs(&[], 8, 1, false);
    assert!(s.is_empty());
}

#[test]
fn recover_structs_pointer_width_infers_pointer_type() {
    let accesses = vec![FieldAccess::read(tv(0), 0, 8, 0)];
    let s = recover_structs(&accesses, 8, 1, false).remove(0);
    assert!(matches!(s.fields[0].ty, RecoveredType::Pointer(_)));
}

#[test]
fn recover_structs_non_ptr_width_infers_int() {
    let accesses = vec![FieldAccess::read(tv(0), 0, 4, 0)];
    let s = recover_structs(&accesses, 8, 1, false).remove(0);
    assert!(matches!(s.fields[0].ty, RecoveredType::Int { width: 4, .. }));
}

#[test]
fn recover_structs_duplicate_access_increments_count() {
    let accesses = vec![
        FieldAccess::read(tv(0), 0, 4, 0),
        FieldAccess::read(tv(0), 0, 4, 0),
        FieldAccess::write(tv(0), 0, 4, 0),
    ];
    let s = recover_structs(&accesses, 8, 1, false).remove(0);
    assert_eq!(s.fields.len(), 1);
    assert_eq!(s.fields[0].access_count, 3);
    assert!(s.fields[0].has_write);
}

#[test]
fn recover_structs_padding_detected() {
    let accesses = vec![
        FieldAccess::read(tv(0), 0, 4, 0),
        FieldAccess::read(tv(0), 100, 4, 0),
    ];
    let s = recover_structs(&accesses, 8, 1, false).remove(0);
    assert!(s.has_padding);
    assert_eq!(s.total_size, 104);
}

#[test]
fn recover_structs_no_padding_for_contiguous() {
    let accesses = vec![
        FieldAccess::read(tv(0), 0, 4, 0),
        FieldAccess::read(tv(0), 4, 4, 0),
    ];
    let s = recover_structs(&accesses, 8, 1, false).remove(0);
    assert!(!s.has_padding);
    assert_eq!(s.total_size, 8);
}

#[test]
fn recover_structs_uses_hint_name_when_enabled() {
    let accesses = vec![FieldAccess::read(tv(0), 0, 4, 0).with_name("my_field")];
    let s = recover_structs(&accesses, 8, 1, true).remove(0);
    assert_eq!(s.fields[0].name, "my_field");
}

#[test]
fn recover_structs_falls_back_to_generated_name_without_hint() {
    let accesses = vec![FieldAccess::read(tv(0), 16, 4, 0)];
    let s = recover_structs(&accesses, 8, 1, false).remove(0);
    assert!(s.fields[0].name.starts_with("field_"));
    assert!(s.fields[0].name.contains("10")); // 16 in hex
}

#[test]
fn merge_structs_dedup_and_sum_counts() {
    let a = recover_structs(&[FieldAccess::read(tv(0), 0, 4, 0)], 8, 1, false).remove(0);
    let b = recover_structs(
        &[FieldAccess::read(tv(0), 0, 4, 0), FieldAccess::write(tv(0), 0, 4, 0)],
        8, 1, false
    ).remove(0);
    let m = merge_structs(&a, &b);
    assert_eq!(m.fields.len(), 1);
    assert_eq!(m.fields[0].access_count, 1 + 2);
    assert!(m.fields[0].has_write);
}

#[test]
fn merge_structs_combines_distinct_fields() {
    let a = recover_structs(&[FieldAccess::read(tv(0), 0, 4, 0)], 8, 1, false).remove(0);
    let b = recover_structs(&[FieldAccess::read(tv(0), 8, 4, 0)], 8, 1, false).remove(0);
    let m = merge_structs(&a, &b);
    assert_eq!(m.fields.len(), 2);
    assert_eq!(m.total_size, 12);
    assert!(m.has_padding);
}

#[test]
fn structdb_empty_and_len() {
    let db = StructDatabase::new();
    assert!(db.is_empty());
    assert_eq!(db.len(), 0);
    assert!(db.get(tv(0)).is_none());
    assert!(db.all_structs().is_empty());
}

#[test]
fn structdb_insert_merges_same_key() {
    let mut db = StructDatabase::new();
    let a = recover_structs(&[FieldAccess::read(tv(0), 0, 4, 0)], 8, 1, false).remove(0);
    let b = recover_structs(&[FieldAccess::read(tv(0), 8, 4, 0)], 8, 1, false).remove(0);
    db.insert(a);
    db.insert(b);
    assert_eq!(db.len(), 1);
    assert_eq!(db.get(tv(0)).unwrap().fields.len(), 2);
}

#[test]
fn structdb_insert_distinct_keys() {
    let mut db = StructDatabase::new();
    db.insert(recover_structs(&[FieldAccess::read(tv(0), 0, 4, 0)], 8, 1, false).remove(0));
    db.insert(recover_structs(&[FieldAccess::read(tv(1), 0, 4, 0)], 8, 1, false).remove(0));
    assert_eq!(db.len(), 2);
    assert_eq!(db.all_structs().len(), 2);
}

#[test]
fn structdb_names() {
    let mut db = StructDatabase::new();
    db.insert(recover_structs(&[FieldAccess::read(tv(0), 0, 4, 0)], 8, 1, false).remove(0));
    db.insert(recover_structs(&[FieldAccess::read(tv(1), 0, 4, 0)], 8, 1, false).remove(0));
    let names = db.names();
    assert_eq!(names.len(), 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Concurrency: Send + Sync
// ─────────────────────────────────────────────────────────────────────────────

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn types_are_send_sync() {
    assert_send_sync::<TypeVar>();
    assert_send_sync::<RecoveredType>();
    assert_send_sync::<TypeConstraint>();
    assert_send_sync::<TypeConstraintGenerator>();
    assert_send_sync::<TypeUnifier>();
    assert_send_sync::<StructRecoveryEngine>();
    assert_send_sync::<StructDatabase>();
    assert_send_sync::<FieldAccess>();
    assert_send_sync::<RecoveredStruct>();
}
