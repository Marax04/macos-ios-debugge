//! Deep adversarial test suite for rustre-analysis-type.
//!
//! Round-trip, boundary, LCG-fuzz, state-machine, overflow, hash/Eq,
//! Display/format, and threaded-Send/Sync tests for the public API.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

use rustre_analysis_type::{
    collect_constraints, ArrayDetector, CallGraph, CallingConvention, FieldAccess,
    InstrKind, InstrRefKind, InstructionRef, LibraryTypeImporter,
    ParamInfo, StructRecovery, TypeConstraint, TypeEnvironment, TypeError, TypeFact,
    TypeInferenceEngine, TypePropagator, TypeVar, TypedInstr, WinApiTypeDb,
};

// ── seeded LCG (no rand crate) ─────────────────────────────────────────────
fn lcg(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed;
    move || {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        s
    }
}

fn default_hash<T: Hash>(v: &T) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

// ──────────────────────────────────────────────────────────────────────────
// TypeFact: Display, byte_size, is_known, join
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn display_signed_unsigned_float_show_bit_width() {
    assert_eq!(TypeFact::SignedInt(1).to_string(), "i8");
    assert_eq!(TypeFact::SignedInt(2).to_string(), "i16");
    assert_eq!(TypeFact::SignedInt(4).to_string(), "i32");
    assert_eq!(TypeFact::SignedInt(8).to_string(), "i64");
    assert_eq!(TypeFact::UnsignedInt(1).to_string(), "u8");
    assert_eq!(TypeFact::UnsignedInt(8).to_string(), "u64");
    assert_eq!(TypeFact::Float(4).to_string(), "f32");
    assert_eq!(TypeFact::Float(8).to_string(), "f64");
    assert_eq!(TypeFact::Bool.to_string(), "bool");
    assert_eq!(TypeFact::Char.to_string(), "char");
    assert_eq!(TypeFact::Unknown.to_string(), "?");
    assert_eq!(TypeFact::Sized(16).to_string(), "sized(16)");
}

#[test]
fn display_pointer_and_array_and_struct() {
    let p = TypeFact::Pointer(Box::new(TypeFact::SignedInt(4)));
    assert_eq!(p.to_string(), "*i32");
    let arr = TypeFact::Array { element: Box::new(TypeFact::Bool), length: Some(7) };
    assert_eq!(arr.to_string(), "[bool; 7]");
    let arr_un = TypeFact::Array { element: Box::new(TypeFact::Char), length: None };
    assert_eq!(arr_un.to_string(), "[char]");
    let s = TypeFact::Struct {
        fields: vec![(0, TypeFact::SignedInt(4)), (8, TypeFact::Bool)],
    };
    assert_eq!(s.to_string(), "struct{+0: i32, +8: bool}");
}

#[test]
fn byte_size_at_boundaries() {
    assert_eq!(TypeFact::SignedInt(0).byte_size(), Some(0));
    assert_eq!(TypeFact::UnsignedInt(1).byte_size(), Some(1));
    assert_eq!(TypeFact::Float(8).byte_size(), Some(8));
    assert_eq!(TypeFact::Sized(usize::MAX).byte_size(), Some(usize::MAX));
    assert_eq!(TypeFact::Bool.byte_size(), Some(1));
    assert_eq!(TypeFact::Char.byte_size(), Some(1));
    assert_eq!(TypeFact::Unknown.byte_size(), None);
    assert_eq!(
        TypeFact::Pointer(Box::new(TypeFact::Bool)).byte_size(),
        None,
        "pointers don't report a byte size",
    );
}

#[test]
fn byte_size_array_known_length_multiplies() {
    let arr = TypeFact::Array { element: Box::new(TypeFact::UnsignedInt(4)), length: Some(10) };
    assert_eq!(arr.byte_size(), Some(40));
    let arr_un = TypeFact::Array { element: Box::new(TypeFact::UnsignedInt(4)), length: None };
    assert_eq!(arr_un.byte_size(), None);
}

#[test]
fn byte_size_array_overflow_returns_none() {
    let arr = TypeFact::Array {
        element: Box::new(TypeFact::Sized(usize::MAX / 2 + 1)),
        length: Some(4),
    };
    // multiplication should overflow → None
    assert_eq!(arr.byte_size(), None);
}

#[test]
fn is_known_classification() {
    assert!(!TypeFact::Unknown.is_known());
    for t in [
        TypeFact::Bool,
        TypeFact::Char,
        TypeFact::SignedInt(4),
        TypeFact::UnsignedInt(8),
        TypeFact::Float(4),
        TypeFact::Sized(1),
        TypeFact::Pointer(Box::new(TypeFact::Unknown)),
    ] {
        assert!(t.is_known(), "{t} should be known");
    }
}

#[test]
fn join_idempotent_on_50_concrete_inputs() {
    let candidates = vec![
        TypeFact::Bool,
        TypeFact::Char,
        TypeFact::Unknown,
        TypeFact::SignedInt(1),
        TypeFact::SignedInt(2),
        TypeFact::SignedInt(4),
        TypeFact::SignedInt(8),
        TypeFact::UnsignedInt(1),
        TypeFact::UnsignedInt(2),
        TypeFact::UnsignedInt(4),
        TypeFact::UnsignedInt(8),
        TypeFact::Float(4),
        TypeFact::Float(8),
        TypeFact::Sized(1),
        TypeFact::Sized(2),
        TypeFact::Sized(4),
        TypeFact::Sized(8),
        TypeFact::Sized(16),
        TypeFact::Pointer(Box::new(TypeFact::Unknown)),
        TypeFact::Pointer(Box::new(TypeFact::Bool)),
        TypeFact::Pointer(Box::new(TypeFact::SignedInt(4))),
        TypeFact::Pointer(Box::new(TypeFact::Pointer(Box::new(TypeFact::Char)))),
        TypeFact::Array { element: Box::new(TypeFact::Bool), length: Some(0) },
        TypeFact::Array { element: Box::new(TypeFact::Bool), length: Some(1) },
        TypeFact::Array { element: Box::new(TypeFact::Bool), length: None },
        TypeFact::Struct { fields: vec![] },
        TypeFact::Struct { fields: vec![(0, TypeFact::SignedInt(4))] },
    ];
    // Pad with reps so >=50 inputs are checked.
    let mut all = Vec::new();
    while all.len() < 50 {
        all.extend(candidates.iter().cloned());
    }
    for t in &all[..50] {
        assert_eq!(t.join(t), t.clone(), "join is idempotent: {t}");
    }
}

#[test]
fn join_commutative_on_lcg_pairs() {
    let mut g = lcg(0xDEAD_BEEF_CAFE_BABE);
    let candidates = [
        TypeFact::Bool,
        TypeFact::Char,
        TypeFact::Unknown,
        TypeFact::SignedInt(4),
        TypeFact::UnsignedInt(4),
        TypeFact::Float(4),
        TypeFact::Sized(4),
        TypeFact::Pointer(Box::new(TypeFact::Unknown)),
    ];
    for _ in 0..200 {
        let a = candidates[(g() as usize) % candidates.len()].clone();
        let b = candidates[(g() as usize) % candidates.len()].clone();
        assert_eq!(a.join(&b), b.join(&a), "join not commutative for {a} / {b}");
    }
}

#[test]
fn join_unknown_is_identity() {
    let inputs = vec![
        TypeFact::Bool,
        TypeFact::Char,
        TypeFact::SignedInt(4),
        TypeFact::Float(8),
        TypeFact::Sized(2),
        TypeFact::Pointer(Box::new(TypeFact::Bool)),
    ];
    for t in inputs {
        assert_eq!(TypeFact::Unknown.join(&t), t.clone());
        assert_eq!(t.join(&TypeFact::Unknown), t);
    }
}

#[test]
fn join_sized_refines_to_concrete_of_same_size() {
    // sized(4) ⊓ i32 = i32  (because i32.byte_size() == Some(4))
    assert_eq!(
        TypeFact::Sized(4).join(&TypeFact::SignedInt(4)),
        TypeFact::SignedInt(4)
    );
    assert_eq!(
        TypeFact::UnsignedInt(8).join(&TypeFact::Sized(8)),
        TypeFact::UnsignedInt(8)
    );
    assert_eq!(
        TypeFact::Float(4).join(&TypeFact::Sized(4)),
        TypeFact::Float(4)
    );
    // sized(1) ⊓ bool — bool's byte_size is 1 — must refine.
    assert_eq!(TypeFact::Sized(1).join(&TypeFact::Bool), TypeFact::Bool);
}

#[test]
fn join_conflicting_sizes_widens_to_unknown() {
    assert_eq!(
        TypeFact::SignedInt(4).join(&TypeFact::SignedInt(8)),
        TypeFact::Unknown
    );
    assert_eq!(
        TypeFact::Float(4).join(&TypeFact::Float(8)),
        TypeFact::Unknown
    );
}

#[test]
fn join_pointer_recurses_into_pointee() {
    let p1 = TypeFact::Pointer(Box::new(TypeFact::Unknown));
    let p2 = TypeFact::Pointer(Box::new(TypeFact::SignedInt(4)));
    let joined = p1.join(&p2);
    if let TypeFact::Pointer(inner) = joined {
        assert_eq!(*inner, TypeFact::SignedInt(4));
    } else {
        panic!("expected pointer");
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Hash / Eq consistency
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn hash_eq_consistency_typefact_30_pairs() {
    let mut g = lcg(0x1234_5678_9ABC_DEF0);
    let pool = vec![
        TypeFact::Bool,
        TypeFact::Char,
        TypeFact::Unknown,
        TypeFact::SignedInt(4),
        TypeFact::UnsignedInt(4),
        TypeFact::Float(4),
        TypeFact::Sized(8),
        TypeFact::Pointer(Box::new(TypeFact::Bool)),
        TypeFact::Pointer(Box::new(TypeFact::Pointer(Box::new(TypeFact::Char)))),
        TypeFact::Struct { fields: vec![(0, TypeFact::Bool)] },
        TypeFact::Array { element: Box::new(TypeFact::Bool), length: Some(4) },
    ];
    for _ in 0..30 {
        let a = pool[(g() as usize) % pool.len()].clone();
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(default_hash(&a), default_hash(&b));
    }
}

#[test]
fn hash_eq_typevar_pairs() {
    for i in 0..30u32 {
        let a = TypeVar(i);
        let b = TypeVar(i);
        assert_eq!(a, b);
        assert_eq!(default_hash(&a), default_hash(&b));
    }
}

#[test]
fn typevar_display_format() {
    assert_eq!(TypeVar(0).to_string(), "τ0");
    assert_eq!(TypeVar(42).to_string(), "τ42");
    assert_eq!(TypeVar(u32::MAX).to_string(), format!("τ{}", u32::MAX));
}

// ──────────────────────────────────────────────────────────────────────────
// TypeInferenceEngine — basic + adversarial + LCG fuzz
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn engine_default_solve_empty() {
    let mut e = TypeInferenceEngine::default();
    let a = e.solve().expect("infallible");
    assert!(a.is_empty());
}

#[test]
fn engine_fresh_allocates_distinct_vars() {
    let mut e = TypeInferenceEngine::new();
    let mut seen = HashSet::new();
    for _ in 0..50 {
        let v = e.fresh();
        assert!(seen.insert(v.0), "fresh returned duplicate {v}");
    }
}

#[test]
fn engine_var_for_returns_same_id_for_same_name() {
    let mut e = TypeInferenceEngine::new();
    let a1 = e.var_for("alpha");
    let a2 = e.var_for("alpha");
    let b = e.var_for("beta");
    assert_eq!(a1, a2);
    assert_ne!(a1, b);
}

#[test]
fn engine_handles_out_of_range_user_constructed_typevar() {
    // Adversarial: caller constructs TypeVar(99) without fresh().
    let mut e = TypeInferenceEngine::new();
    let _ = e.var_for("x"); // var 0
    let big = TypeVar(99);
    e.add_constraint(TypeConstraint::HasType(big, TypeFact::Bool));
    let assignment = e.solve().expect("engine must size for user-supplied TypeVars");
    assert_eq!(assignment.get(&99), Some(&TypeFact::Bool));
}

#[test]
fn engine_arithmetic_unifies_lhs_rhs_result() {
    let mut e = TypeInferenceEngine::new();
    let l = e.var_for("l");
    let r = e.var_for("r");
    let d = e.var_for("d");
    e.add_constraint(TypeConstraint::HasType(l, TypeFact::SignedInt(4)));
    e.add_constraint(TypeConstraint::Add { lhs: l, rhs: r, result: d });
    let a = e.solve().unwrap();
    assert_eq!(e.type_of("d", &a).unwrap(), TypeFact::SignedInt(4));
    assert_eq!(e.type_of("r", &a).unwrap(), TypeFact::SignedInt(4));
}

#[test]
fn engine_sub_and_bitwise_unify() {
    let mut e = TypeInferenceEngine::new();
    let a = e.var_for("a");
    let b = e.var_for("b");
    let c = e.var_for("c");
    e.add_constraint(TypeConstraint::HasType(c, TypeFact::UnsignedInt(8)));
    e.add_constraint(TypeConstraint::Sub { lhs: a, rhs: b, result: c });
    let asn = e.solve().unwrap();
    assert_eq!(e.type_of("a", &asn).unwrap(), TypeFact::UnsignedInt(8));

    let mut e2 = TypeInferenceEngine::new();
    let x = e2.var_for("x");
    let y = e2.var_for("y");
    let z = e2.var_for("z");
    e2.add_constraint(TypeConstraint::HasType(y, TypeFact::UnsignedInt(4)));
    e2.add_constraint(TypeConstraint::Bitwise { lhs: x, rhs: y, result: z });
    let asn = e2.solve().unwrap();
    assert_eq!(e2.type_of("x", &asn).unwrap(), TypeFact::UnsignedInt(4));
    assert_eq!(e2.type_of("z", &asn).unwrap(), TypeFact::UnsignedInt(4));
}

#[test]
fn engine_deref_pointer_inner_resolved_in_second_pass() {
    // pointee's HasType comes AFTER the Deref — first pass would see Unknown,
    // the second pass must fix that.
    let mut e = TypeInferenceEngine::new();
    let p = e.var_for("p");
    let v = e.var_for("v");
    e.add_constraint(TypeConstraint::Deref { ptr: p, pointee: v });
    e.add_constraint(TypeConstraint::HasType(v, TypeFact::SignedInt(4)));
    let a = e.solve().unwrap();
    match e.type_of("p", &a).unwrap() {
        TypeFact::Pointer(inner) => assert_eq!(*inner, TypeFact::SignedInt(4)),
        other => panic!("expected pointer, got {other}"),
    }
}

#[test]
fn engine_conflicting_facts_widen_to_unknown() {
    let mut e = TypeInferenceEngine::new();
    let v = e.var_for("v");
    e.add_constraint(TypeConstraint::HasType(v, TypeFact::SignedInt(4)));
    e.add_constraint(TypeConstraint::HasType(v, TypeFact::UnsignedInt(4)));
    let a = e.solve().unwrap();
    // sized(4)? no — conflicting concrete types of equal size → Unknown via join.
    assert_eq!(e.type_of("v", &a).unwrap(), TypeFact::Unknown);
}

#[test]
fn engine_long_equality_chain_no_stack_overflow() {
    // Build a 50k-long chain of Equal constraints. The recursive path-compression
    // would overflow; the iterative one must not.
    let mut e = TypeInferenceEngine::new();
    let first = e.var_for("v0");
    let mut prev = first;
    for i in 1..50_000u32 {
        let cur = e.var_for(&format!("v{i}"));
        e.add_constraint(TypeConstraint::Equal(prev, cur));
        prev = cur;
    }
    e.add_constraint(TypeConstraint::HasType(first, TypeFact::Bool));
    let asn = e.solve().expect("solve must not overflow");
    assert_eq!(e.type_of("v49999", &asn).unwrap(), TypeFact::Bool);
}

#[test]
fn engine_lcg_fuzz_never_panics() {
    let mut g = lcg(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let mut e = TypeInferenceEngine::new();
        let n_vars = ((g() % 20) as u32) + 1;
        let vars: Vec<TypeVar> = (0..n_vars).map(|_| e.fresh()).collect();
        let n_constraints = (g() % 60) as usize;
        for _ in 0..n_constraints {
            let pick = g() % 8;
            let v1 = vars[(g() as usize) % vars.len()];
            let v2 = vars[(g() as usize) % vars.len()];
            let v3 = vars[(g() as usize) % vars.len()];
            let bytes = ((g() % 8) + 1) as usize;
            match pick {
                0 => e.add_constraint(TypeConstraint::HasType(
                    v1,
                    TypeFact::SignedInt(bytes),
                )),
                1 => e.add_constraint(TypeConstraint::HasType(
                    v1,
                    TypeFact::UnsignedInt(bytes),
                )),
                2 => e.add_constraint(TypeConstraint::HasType(v1, TypeFact::Bool)),
                3 => e.add_constraint(TypeConstraint::Equal(v1, v2)),
                4 => e.add_constraint(TypeConstraint::Deref { ptr: v1, pointee: v2 }),
                5 => e.add_constraint(TypeConstraint::Add {
                    lhs: v1,
                    rhs: v2,
                    result: v3,
                }),
                6 => e.add_constraint(TypeConstraint::IsCondition(v1)),
                _ => e.add_constraint(TypeConstraint::Bitwise {
                    lhs: v1,
                    rhs: v2,
                    result: v3,
                }),
            }
        }
        let asn = e.solve().expect("fuzz solve must not panic");
        // every var has SOME assignment
        for v in &vars {
            assert!(asn.contains_key(&v.0));
        }
    }
}

#[test]
fn engine_isolated_var_remains_unknown() {
    let mut e = TypeInferenceEngine::new();
    let _ = e.var_for("a");
    let asn = e.solve().unwrap();
    assert_eq!(e.type_of("a", &asn).unwrap(), TypeFact::Unknown);
}

#[test]
fn engine_unknown_variable_error() {
    let e = TypeInferenceEngine::new();
    let asn: HashMap<u32, TypeFact> = HashMap::new();
    let err = e.type_of("ghost", &asn).unwrap_err();
    assert!(matches!(err, TypeError::UnknownVariable(_)));
    assert!(err.to_string().contains("ghost"));
}

#[test]
fn engine_iscondition_does_not_override_known_type() {
    let mut e = TypeInferenceEngine::new();
    let c = e.var_for("c");
    e.add_constraint(TypeConstraint::HasType(c, TypeFact::UnsignedInt(4)));
    e.add_constraint(TypeConstraint::IsCondition(c));
    let asn = e.solve().unwrap();
    // IsCondition only fills Unknown — must not overwrite the u32.
    assert_eq!(e.type_of("c", &asn).unwrap(), TypeFact::UnsignedInt(4));
}

#[test]
fn engine_returnof_and_argumentof_currently_no_solo_effect() {
    // These constraints exist but the basic engine does not propagate them
    // by themselves; they should not panic and should leave Unknown.
    let mut e = TypeInferenceEngine::new();
    let v = e.var_for("r");
    e.add_constraint(TypeConstraint::ReturnOf { var: v, function: "f".into() });
    let w = e.var_for("a");
    e.add_constraint(TypeConstraint::ArgumentOf { var: w, function: "f".into(), index: 0 });
    let asn = e.solve().unwrap();
    assert_eq!(e.type_of("r", &asn).unwrap(), TypeFact::Unknown);
    assert_eq!(e.type_of("a", &asn).unwrap(), TypeFact::Unknown);
}

#[test]
fn engine_all_types_yields_every_named_var() {
    let mut e = TypeInferenceEngine::new();
    let a = e.var_for("a");
    let b = e.var_for("b");
    let c = e.var_for("c");
    e.add_constraint(TypeConstraint::HasType(a, TypeFact::Bool));
    e.add_constraint(TypeConstraint::HasType(b, TypeFact::Char));
    e.add_constraint(TypeConstraint::HasType(c, TypeFact::Float(4)));
    let asn = e.solve().unwrap();
    let collected: HashMap<_, _> = e.all_types(&asn).collect();
    assert_eq!(collected.len(), 3);
    assert_eq!(collected.get("a"), Some(&&TypeFact::Bool));
    assert_eq!(collected.get("c"), Some(&&TypeFact::Float(4)));
}

// ──────────────────────────────────────────────────────────────────────────
// collect_constraints — full instruction kinds, boundary inputs
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn collect_load_makes_destination_pointee_of_pointer() {
    let mut e = TypeInferenceEngine::new();
    let instrs = vec![
        TypedInstr { kind: InstrKind::Const { dst: "v".into(), bytes: 4, signed: true } },
        TypedInstr { kind: InstrKind::Load { dst: "v".into(), ptr: "p".into() } },
    ];
    collect_constraints(&mut e, &instrs);
    let a = e.solve().unwrap();
    match e.type_of("p", &a).unwrap() {
        TypeFact::Pointer(inner) => assert_eq!(*inner, TypeFact::SignedInt(4)),
        other => panic!("expected pointer, got {other}"),
    }
}

#[test]
fn collect_store_makes_pointer_from_src() {
    let mut e = TypeInferenceEngine::new();
    let instrs = vec![
        TypedInstr { kind: InstrKind::Const { dst: "s".into(), bytes: 8, signed: false } },
        TypedInstr { kind: InstrKind::Store { ptr: "p".into(), src: "s".into() } },
    ];
    collect_constraints(&mut e, &instrs);
    let a = e.solve().unwrap();
    match e.type_of("p", &a).unwrap() {
        TypeFact::Pointer(inner) => assert_eq!(*inner, TypeFact::UnsignedInt(8)),
        other => panic!("expected pointer got {other}"),
    }
}

#[test]
fn collect_call_with_return_and_args() {
    let mut e = TypeInferenceEngine::new();
    let instrs = vec![TypedInstr {
        kind: InstrKind::Call {
            dst: Some("rv".into()),
            function: "f".into(),
            args: vec!["a0".into(), "a1".into()],
        },
    }];
    collect_constraints(&mut e, &instrs);
    let a = e.solve().unwrap();
    // ReturnOf / ArgumentOf currently leave Unknown but must not error
    assert_eq!(e.type_of("rv", &a).unwrap(), TypeFact::Unknown);
    assert_eq!(e.type_of("a0", &a).unwrap(), TypeFact::Unknown);
    assert_eq!(e.type_of("a1", &a).unwrap(), TypeFact::Unknown);
}

#[test]
fn collect_return_some_registers_variable() {
    let mut e = TypeInferenceEngine::new();
    let instrs = vec![TypedInstr {
        kind: InstrKind::Return { val: Some("r".into()) },
    }];
    collect_constraints(&mut e, &instrs);
    let a = e.solve().unwrap();
    assert_eq!(e.type_of("r", &a).unwrap(), TypeFact::Unknown);
}

#[test]
fn collect_return_none_is_noop() {
    let mut e = TypeInferenceEngine::new();
    let instrs = vec![TypedInstr { kind: InstrKind::Return { val: None } }];
    collect_constraints(&mut e, &instrs);
    let a = e.solve().unwrap();
    assert!(a.is_empty() || a.values().all(|t| matches!(t, TypeFact::Unknown)));
}

#[test]
fn collect_constraints_lcg_fuzz_no_panic() {
    let mut g = lcg(0xCAFE_F00D_DEAD_BEEF);
    let names = ["a", "b", "c", "d", "e", "f"];
    for _ in 0..30 {
        let mut e = TypeInferenceEngine::new();
        let n = (g() % 40) as usize;
        let mut instrs = Vec::with_capacity(n);
        for _ in 0..n {
            let pick = g() % 8;
            let nm = |i: u64| names[(i as usize) % names.len()].to_string();
            let v1 = nm(g());
            let v2 = nm(g());
            let v3 = nm(g());
            let bytes = ((g() % 8) + 1) as usize;
            instrs.push(TypedInstr {
                kind: match pick {
                    0 => InstrKind::Assign { dst: v1, src: v2 },
                    1 => InstrKind::Const { dst: v1, bytes, signed: g() & 1 == 0 },
                    2 => InstrKind::Load { dst: v1, ptr: v2 },
                    3 => InstrKind::Store { ptr: v1, src: v2 },
                    4 => InstrKind::Add { dst: v1, lhs: v2, rhs: v3 },
                    5 => InstrKind::Sub { dst: v1, lhs: v2, rhs: v3 },
                    6 => InstrKind::Branch { cond: v1 },
                    _ => InstrKind::Call {
                        dst: Some(v1),
                        function: format!("fn{}", g() % 5),
                        args: vec![v2, v3],
                    },
                },
            });
        }
        collect_constraints(&mut e, &instrs);
        let _ = e.solve().expect("must not error");
    }
}

// ──────────────────────────────────────────────────────────────────────────
// TypeEnvironment
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn env_default_returns_unknown_for_missing() {
    let e = TypeEnvironment::default();
    assert_eq!(e.get("nope"), &TypeFact::Unknown);
    assert!(e.types.is_empty());
    assert!(e.arg_types.is_empty());
    assert_eq!(e.return_type, TypeFact::Unknown);
}

#[test]
fn env_set_overwrite() {
    let mut e = TypeEnvironment::new();
    e.set("x", TypeFact::Bool);
    e.set("x", TypeFact::Char);
    assert_eq!(e.get("x"), &TypeFact::Char);
}

#[test]
fn env_merge_extends_arg_types_to_longest() {
    let mut a = TypeEnvironment::new();
    a.arg_types = vec![TypeFact::Bool];
    let mut b = TypeEnvironment::new();
    b.arg_types = vec![TypeFact::Bool, TypeFact::Char, TypeFact::SignedInt(4)];
    a.merge(&b);
    assert_eq!(a.arg_types.len(), 3);
    assert_eq!(a.arg_types[0], TypeFact::Bool);
    assert_eq!(a.arg_types[1], TypeFact::Char);
    assert_eq!(a.arg_types[2], TypeFact::SignedInt(4));
}

#[test]
fn env_merge_joins_return_type() {
    let mut a = TypeEnvironment::new();
    a.return_type = TypeFact::SignedInt(4);
    let mut b = TypeEnvironment::new();
    b.return_type = TypeFact::SignedInt(4);
    a.merge(&b);
    assert_eq!(a.return_type, TypeFact::SignedInt(4));

    let mut c = TypeEnvironment::new();
    c.return_type = TypeFact::Float(8);
    a.merge(&c);
    assert_eq!(a.return_type, TypeFact::Unknown);
}

// ──────────────────────────────────────────────────────────────────────────
// CallGraph
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn callgraph_add_function_idempotent() {
    let mut g = CallGraph::new();
    g.add_function("a");
    g.add_function("a");
    assert_eq!(g.nodes.len(), 1);
}

#[test]
fn callgraph_add_call_dedups() {
    let mut g = CallGraph::new();
    g.add_function("caller");
    g.add_function("callee");
    g.add_call("caller", "callee");
    g.add_call("caller", "callee");
    assert_eq!(g.nodes.get("caller").unwrap().callees.len(), 1);
}

#[test]
fn callgraph_add_call_to_unknown_caller_is_silent() {
    let mut g = CallGraph::new();
    g.add_call("nope", "x");
    assert!(g.nodes.is_empty());
}

#[test]
fn callgraph_topological_order_places_callee_before_caller() {
    let mut g = CallGraph::new();
    g.add_function("main");
    g.add_function("util");
    g.add_function("leaf");
    g.add_call("main", "util");
    g.add_call("util", "leaf");
    let order = g.topological_order();
    let pos = |n: &str| order.iter().position(|x| x == n).unwrap();
    assert!(pos("leaf") < pos("util"));
    assert!(pos("util") < pos("main"));
}

#[test]
fn callgraph_topological_order_handles_cycle_without_overflow() {
    // Mutual recursion shouldn't infinite-loop or stack-overflow.
    let mut g = CallGraph::new();
    g.add_function("a");
    g.add_function("b");
    g.add_call("a", "b");
    g.add_call("b", "a");
    let order = g.topological_order();
    assert_eq!(order.len(), 2);
}

#[test]
fn callgraph_topological_order_deep_chain_no_stack_overflow() {
    let mut g = CallGraph::new();
    for i in 0..20_000 {
        g.add_function(format!("f{i}"));
        if i > 0 {
            g.add_call(&format!("f{}", i - 1), &format!("f{i}"));
        }
    }
    let order = g.topological_order();
    assert_eq!(order.len(), 20_000);
}

// ──────────────────────────────────────────────────────────────────────────
// TypePropagator
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn propagator_propagates_callee_return_type_to_caller_var() {
    let mut cg = CallGraph::new();
    cg.add_function("caller");
    cg.add_function("callee");
    cg.add_call("caller", "callee");
    let mut p = TypePropagator::new(cg);
    let mut callee_env = TypeEnvironment::new();
    callee_env.return_type = TypeFact::SignedInt(4);
    p.set_initial_env("callee", callee_env);
    p.set_initial_env("caller", TypeEnvironment::new());
    p.propagate();
    let caller_env = p.env_for("caller").unwrap();
    assert_eq!(caller_env.get("callee"), &TypeFact::SignedInt(4));
}

#[test]
fn propagator_terminates_on_cycle() {
    let mut cg = CallGraph::new();
    cg.add_function("a");
    cg.add_function("b");
    cg.add_call("a", "b");
    cg.add_call("b", "a");
    let mut p = TypePropagator::new(cg);
    let mut env_a = TypeEnvironment::new();
    env_a.return_type = TypeFact::Bool;
    p.set_initial_env("a", env_a);
    p.set_initial_env("b", TypeEnvironment::new());
    p.propagate();
    // Must not hang — just confirm a value made it across.
    let b_env = p.env_for("b").unwrap();
    assert_eq!(b_env.get("a"), &TypeFact::Bool);
}

#[test]
fn propagator_env_for_missing_returns_none() {
    let p = TypePropagator::new(CallGraph::new());
    assert!(p.env_for("ghost").is_none());
}

// ──────────────────────────────────────────────────────────────────────────
// StructRecovery
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn struct_recovery_groups_by_base() {
    let accesses = vec![
        FieldAccess { base: "p".into(), offset: 0, access_size: 4 },
        FieldAccess { base: "p".into(), offset: 4, access_size: 4 },
        FieldAccess { base: "q".into(), offset: 0, access_size: 8 },
    ];
    let result = StructRecovery::recover(&accesses);
    assert_eq!(result.len(), 2);
}

#[test]
fn struct_recovery_sorts_fields_by_offset() {
    let accesses = vec![
        FieldAccess { base: "p".into(), offset: 16, access_size: 8 },
        FieldAccess { base: "p".into(), offset: 0, access_size: 4 },
        FieldAccess { base: "p".into(), offset: 8, access_size: 8 },
    ];
    let result = StructRecovery::recover(&accesses);
    if let TypeFact::Struct { fields } = result.get("p").unwrap() {
        let offs: Vec<usize> = fields.iter().map(|(o, _)| *o).collect();
        assert_eq!(offs, vec![0, 8, 16]);
    } else {
        panic!("expected Struct");
    }
}

#[test]
fn struct_recovery_handles_empty_input() {
    let result = StructRecovery::recover(&[]);
    assert!(result.is_empty());
}

#[test]
fn struct_recovery_boundary_max_offset() {
    let accesses = vec![FieldAccess {
        base: "p".into(),
        offset: usize::MAX,
        access_size: 1,
    }];
    let result = StructRecovery::recover(&accesses);
    if let TypeFact::Struct { fields } = result.get("p").unwrap() {
        assert_eq!(fields[0].0, usize::MAX);
    } else {
        panic!("expected struct");
    }
}

// ──────────────────────────────────────────────────────────────────────────
// FunctionSignature / WinApiTypeDb / LibraryTypeImporter
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn winapi_db_has_25_signatures() {
    let sigs = WinApiTypeDb::all_signatures();
    assert_eq!(sigs.len(), 25, "doc claims 25 signatures");
}

#[test]
fn winapi_db_lookup_case_insensitive() {
    let a = WinApiTypeDb::lookup("ReadFile", "kernel32.dll").unwrap();
    let b = WinApiTypeDb::lookup("readfile", "KERNEL32.DLL").unwrap();
    assert_eq!(a, b);
    assert_eq!(a.arity(), 5);
}

#[test]
fn winapi_db_lookup_unknown_returns_none() {
    assert!(WinApiTypeDb::lookup("NotARealFn", "nowhere.dll").is_none());
    assert!(WinApiTypeDb::lookup_by_name("not_a_real_function").is_none());
}

#[test]
fn winapi_signature_param_type_index_bounds() {
    let sig = WinApiTypeDb::lookup_by_name("CreateFileA").unwrap();
    assert_eq!(sig.arity(), 7);
    assert!(sig.param_type(0).is_some());
    assert!(sig.param_type(6).is_some());
    assert!(sig.param_type(7).is_none());
    assert!(sig.param_type(usize::MAX).is_none());
}

#[test]
fn winapi_printf_is_variadic() {
    let sig = WinApiTypeDb::lookup_by_name("printf").unwrap();
    assert!(sig.is_variadic);
    assert_eq!(sig.calling_convention, CallingConvention::Variadic);
    assert_eq!(sig.arity(), 1, "fixed prefix is just fmt");
}

#[test]
fn calling_convention_hash_eq_consistency() {
    let cs = [
        CallingConvention::MicrosoftX64,
        CallingConvention::SysVAmd64,
        CallingConvention::StdCall32,
        CallingConvention::CDecl32,
        CallingConvention::Variadic,
    ];
    for c in &cs {
        let a = *c;
        let b = *c;
        assert_eq!(a, b);
        assert_eq!(default_hash(&a), default_hash(&b));
    }
}

#[test]
fn library_importer_falls_back_to_name_only() {
    let sig = LibraryTypeImporter::from_import_name("memcpy", "wrongdll.dll");
    assert!(sig.is_some(), "should fall back to name-only lookup");
    assert_eq!(sig.unwrap().name, "memcpy");
}

#[test]
fn library_importer_propagates_per_callsite() {
    let sig = WinApiTypeDb::lookup_by_name("CloseHandle").unwrap();
    let sites = vec![0x1000, 0x2000, 0x3000];
    let facts = LibraryTypeImporter::propagate_to_callers(&sig, &sites);
    // 1 param + 1 return = 2 facts per site, but only if return is "known".
    // CloseHandle returns BOOL = SignedInt(4) — known. So 2 * 3 = 6.
    assert_eq!(facts.len(), 6);
    let return_facts: Vec<_> = facts.iter().filter(|f| f.param_index.is_none()).collect();
    assert_eq!(return_facts.len(), 3);
}

#[test]
fn library_importer_skips_unknown_return() {
    // `free` returns void → Unknown → no return-value PropagatedTypeFact.
    let sig = WinApiTypeDb::lookup_by_name("free").unwrap();
    let facts = LibraryTypeImporter::propagate_to_callers(&sig, &[0xdead]);
    let returns: Vec<_> = facts.iter().filter(|f| f.param_index.is_none()).collect();
    assert_eq!(returns.len(), 0);
}

#[test]
fn library_importer_propagate_import_table_skips_unknown() {
    let imports: &[(&str, &str, Vec<u64>)] = &[
        ("CloseHandle", "kernel32.dll", vec![0x100]),
        ("NotARealFunction", "fake.dll", vec![0x200]),
    ];
    let facts = LibraryTypeImporter::propagate_import_table(imports);
    assert!(facts.iter().all(|f| f.source_function == "CloseHandle"));
}

#[test]
fn library_importer_apply_to_engine_emits_has_type() {
    let sig = WinApiTypeDb::lookup_by_name("CloseHandle").unwrap();
    let facts = LibraryTypeImporter::propagate_to_callers(&sig, &[0x4000]);
    let mut var_map: HashMap<(u64, Option<usize>), String> = HashMap::new();
    var_map.insert((0x4000, None), "rv".to_string());
    var_map.insert((0x4000, Some(0)), "h".to_string());
    let mut e = TypeInferenceEngine::new();
    LibraryTypeImporter::apply_to_engine(&mut e, &facts, &var_map);
    let a = e.solve().unwrap();
    assert_eq!(e.type_of("rv", &a).unwrap(), TypeFact::SignedInt(4));
    assert_eq!(e.type_of("h", &a).unwrap(), TypeFact::UnsignedInt(8));
}

// ──────────────────────────────────────────────────────────────────────────
// ArrayDetector
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn array_detector_requires_two_distinct_indices() {
    let one = vec![InstructionRef {
        address: 0x1,
        kind: InstrRefKind::IndexedLoad {
            base: "b".into(),
            index: None,
            scale: 4,
            displacement: 0,
            dst: "x".into(),
        },
    }];
    assert!(ArrayDetector::detect(&one).is_empty(), "1 access → no pattern");

    let two = vec![
        InstructionRef {
            address: 0x1,
            kind: InstrRefKind::IndexedLoad {
                base: "b".into(),
                index: None,
                scale: 4,
                displacement: 0,
                dst: "x".into(),
            },
        },
        InstructionRef {
            address: 0x2,
            kind: InstrRefKind::IndexedLoad {
                base: "b".into(),
                index: None,
                scale: 4,
                displacement: 8,
                dst: "y".into(),
            },
        },
    ];
    let pats = ArrayDetector::detect(&two);
    assert_eq!(pats.len(), 1);
    let p = &pats[0];
    assert_eq!(p.base_var, "b");
    assert_eq!(p.stride, 4);
    assert_eq!(p.min_index, 0);
    assert_eq!(p.max_index, 2);
    assert!(!p.has_write);
}

#[test]
fn array_detector_marks_write_when_store_present() {
    let instrs = vec![
        InstructionRef {
            address: 0x1,
            kind: InstrRefKind::IndexedLoad {
                base: "a".into(),
                index: None,
                scale: 8,
                displacement: 0,
                dst: "x".into(),
            },
        },
        InstructionRef {
            address: 0x2,
            kind: InstrRefKind::IndexedStore {
                base: "a".into(),
                index: None,
                scale: 8,
                displacement: 16,
                src: "y".into(),
            },
        },
    ];
    let pats = ArrayDetector::detect(&instrs);
    assert_eq!(pats.len(), 1);
    assert!(pats[0].has_write);
}

#[test]
fn array_detector_scale_zero_falls_back_to_raw_displacement() {
    let instrs = vec![
        InstructionRef {
            address: 1,
            kind: InstrRefKind::IndexedLoad {
                base: "b".into(),
                index: None,
                scale: 0,
                displacement: 1,
                dst: "x".into(),
            },
        },
        InstructionRef {
            address: 2,
            kind: InstrRefKind::IndexedLoad {
                base: "b".into(),
                index: None,
                scale: 0,
                displacement: 2,
                dst: "y".into(),
            },
        },
    ];
    let pats = ArrayDetector::detect(&instrs);
    assert_eq!(pats.len(), 1);
    assert_eq!(pats[0].min_index, 1);
    assert_eq!(pats[0].max_index, 2);
}

#[test]
fn array_detector_ignores_other_and_bound() {
    let instrs = vec![
        InstructionRef { address: 1, kind: InstrRefKind::Other },
        InstructionRef {
            address: 2,
            kind: InstrRefKind::BoundCheck { index: "i".into(), bound: 10 },
        },
    ];
    assert!(ArrayDetector::detect(&instrs).is_empty());
}

#[test]
fn array_detector_ptr_increment_tracks_offsets() {
    let instrs = vec![
        InstructionRef { address: 1, kind: InstrRefKind::PtrIncrement { ptr: "p".into(), stride: 4 } },
        InstructionRef { address: 2, kind: InstrRefKind::PtrIncrement { ptr: "p".into(), stride: 4 } },
    ];
    let pats = ArrayDetector::detect(&instrs);
    assert_eq!(pats.len(), 1);
    assert_eq!(pats[0].stride, 4);
}

#[test]
fn array_pattern_min_element_count_max_index_plus_one() {
    let pat = rustre_analysis_type::ArrayAccessPattern {
        base_ptr: 0,
        stride: 4,
        min_index: 0,
        max_index: 9,
        base_var: "b".into(),
        access_count: 10,
        has_write: false,
    };
    assert_eq!(pat.min_element_count(), 10);
    assert_eq!(pat.element_type(), TypeFact::Sized(4));
    let arr = pat.to_array_type(None);
    if let TypeFact::Array { length, .. } = arr {
        assert_eq!(length, Some(10));
    } else {
        panic!("expected array");
    }
    let with_hint = pat.to_array_type(Some(100));
    if let TypeFact::Array { length, .. } = with_hint {
        assert_eq!(length, Some(100));
    } else {
        panic!("expected array");
    }
}

#[test]
fn array_pattern_negative_max_index_yields_zero_count() {
    let pat = rustre_analysis_type::ArrayAccessPattern {
        base_ptr: 0,
        stride: 1,
        min_index: -10,
        max_index: -1,
        base_var: "b".into(),
        access_count: 1,
        has_write: false,
    };
    assert_eq!(pat.min_element_count(), 0);
    let arr = pat.to_array_type(None);
    if let TypeFact::Array { length, .. } = arr {
        assert_eq!(length, None);
    } else {
        panic!("expected array");
    }
}

#[test]
fn array_detector_apply_to_engine_emits_constraints() {
    let instrs = vec![
        InstructionRef {
            address: 1,
            kind: InstrRefKind::IndexedLoad {
                base: "buf".into(),
                index: None,
                scale: 4,
                displacement: 0,
                dst: "x".into(),
            },
        },
        InstructionRef {
            address: 2,
            kind: InstrRefKind::IndexedLoad {
                base: "buf".into(),
                index: None,
                scale: 4,
                displacement: 4,
                dst: "y".into(),
            },
        },
    ];
    let mut e = TypeInferenceEngine::new();
    ArrayDetector::apply_to_engine(&mut e, &instrs);
    let a = e.solve().unwrap();
    let t = e.type_of("buf", &a).unwrap();
    assert!(matches!(t, TypeFact::Array { .. }));
}

#[test]
fn array_detector_lcg_fuzz_does_not_panic() {
    let mut g = lcg(0x0123_4567_89AB_CDEF);
    let bases = ["b0", "b1", "b2"];
    for _ in 0..30 {
        let mut instrs = Vec::new();
        let n = (g() % 30) as usize;
        for i in 0..n {
            let kind = match g() % 5 {
                0 => InstrRefKind::IndexedLoad {
                    base: bases[(g() as usize) % bases.len()].into(),
                    index: None,
                    scale: (g() % 8) as usize,
                    displacement: (g() % 256) as i64,
                    dst: format!("d{i}"),
                },
                1 => InstrRefKind::IndexedStore {
                    base: bases[(g() as usize) % bases.len()].into(),
                    index: None,
                    scale: (g() % 8) as usize,
                    displacement: (g() % 256) as i64,
                    src: format!("s{i}"),
                },
                2 => InstrRefKind::PtrIncrement {
                    ptr: bases[(g() as usize) % bases.len()].into(),
                    stride: (g() % 16) as usize,
                },
                3 => InstrRefKind::BoundCheck {
                    index: "i".into(),
                    bound: (g() % 1000) as i64,
                },
                _ => InstrRefKind::Other,
            };
            instrs.push(InstructionRef { address: i as u64, kind });
        }
        let _ = ArrayDetector::detect(&instrs);
        let _ = ArrayDetector::detect_as_facts(&instrs);
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Send/Sync threaded stress
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn typefact_send_sync_threaded_reads() {
    let v = Arc::new(TypeFact::Pointer(Box::new(TypeFact::SignedInt(4))));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let v = Arc::clone(&v);
        handles.push(thread::spawn(move || {
            let mut acc = 0usize;
            for _ in 0..100 {
                if v.is_known() {
                    acc = acc.wrapping_add(1);
                }
                let _ = v.byte_size();
                let _ = v.to_string();
            }
            acc
        }));
    }
    for h in handles {
        assert_eq!(h.join().unwrap(), 100);
    }
}

#[test]
fn function_signature_send_sync_threaded_reads() {
    let sig = Arc::new(WinApiTypeDb::lookup_by_name("ReadFile").unwrap());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let sig = Arc::clone(&sig);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                assert_eq!(sig.arity(), 5);
                assert_eq!(sig.name, "ReadFile");
                let _ = sig.param_type(0);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn typepropagator_rwlock_concurrent_reads() {
    let mut cg = CallGraph::new();
    cg.add_function("a");
    cg.add_function("b");
    cg.add_call("a", "b");
    let mut p = TypePropagator::new(cg);
    let mut env_b = TypeEnvironment::new();
    env_b.return_type = TypeFact::Bool;
    p.set_initial_env("b", env_b);
    p.set_initial_env("a", TypeEnvironment::new());
    p.propagate();
    let p = Arc::new(p);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let p = Arc::clone(&p);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let e = p.env_for("a").unwrap();
                assert_eq!(e.get("b"), &TypeFact::Bool);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Serde / Display round-trips
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn type_fact_serde_round_trip_50_values() {
    let pool = vec![
        TypeFact::Bool,
        TypeFact::Char,
        TypeFact::Unknown,
        TypeFact::SignedInt(1),
        TypeFact::SignedInt(2),
        TypeFact::SignedInt(4),
        TypeFact::SignedInt(8),
        TypeFact::UnsignedInt(1),
        TypeFact::UnsignedInt(8),
        TypeFact::Float(4),
        TypeFact::Float(8),
        TypeFact::Sized(0),
        TypeFact::Sized(usize::MAX),
        TypeFact::Pointer(Box::new(TypeFact::Bool)),
        TypeFact::Pointer(Box::new(TypeFact::Pointer(Box::new(TypeFact::Char)))),
        TypeFact::Array { element: Box::new(TypeFact::Bool), length: Some(0) },
        TypeFact::Array { element: Box::new(TypeFact::Bool), length: None },
        TypeFact::Struct { fields: vec![] },
        TypeFact::Struct {
            fields: vec![(0, TypeFact::Bool), (8, TypeFact::SignedInt(4))],
        },
    ];
    let mut all = Vec::new();
    while all.len() < 50 {
        all.extend(pool.iter().cloned());
    }
    for t in &all[..50] {
        let s = serde_json::to_string(t).expect("serialize");
        let back: TypeFact = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(*t, back);
    }
}

#[test]
fn type_constraint_serde_round_trip() {
    let cs = vec![
        TypeConstraint::HasType(TypeVar(0), TypeFact::Bool),
        TypeConstraint::Equal(TypeVar(1), TypeVar(2)),
        TypeConstraint::Deref { ptr: TypeVar(3), pointee: TypeVar(4) },
        TypeConstraint::Add { lhs: TypeVar(5), rhs: TypeVar(6), result: TypeVar(7) },
        TypeConstraint::Sub { lhs: TypeVar(5), rhs: TypeVar(6), result: TypeVar(7) },
        TypeConstraint::Bitwise { lhs: TypeVar(5), rhs: TypeVar(6), result: TypeVar(7) },
        TypeConstraint::IsCondition(TypeVar(8)),
        TypeConstraint::ReturnOf { var: TypeVar(9), function: "f".into() },
        TypeConstraint::ArgumentOf { var: TypeVar(10), function: "f".into(), index: 0 },
    ];
    for c in &cs {
        let s = serde_json::to_string(c).expect("ser");
        let back: TypeConstraint = serde_json::from_str(&s).expect("de");
        assert_eq!(*c, back);
    }
}

// ──────────────────────────────────────────────────────────────────────────
// ParamInfo / FunctionSignature semantics
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn function_signature_equality_and_hash() {
    let a = WinApiTypeDb::lookup_by_name("CloseHandle").unwrap();
    let b = WinApiTypeDb::lookup_by_name("CloseHandle").unwrap();
    assert_eq!(a, b);
    // hash from cloned identical structs must match
    assert_eq!(default_hash(&a.calling_convention), default_hash(&b.calling_convention));
}

#[test]
fn param_info_equality() {
    let p1 = ParamInfo { name: "x".into(), ty: TypeFact::Bool };
    let p2 = ParamInfo { name: "x".into(), ty: TypeFact::Bool };
    assert_eq!(p1, p2);
}

// ──────────────────────────────────────────────────────────────────────────
// TypeError display
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn type_error_display_messages() {
    let e1 = TypeError::UnificationConflict("a".into(), "b".into());
    assert!(e1.to_string().contains("a") && e1.to_string().contains("b"));
    let e2 = TypeError::UnknownVariable("v".into());
    assert!(e2.to_string().contains("v"));
    let e3 = TypeError::CyclicConstraint("v".into());
    assert!(e3.to_string().contains("v"));
}
