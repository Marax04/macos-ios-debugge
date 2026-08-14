//! Blitz test suite for rustre-analysis-type.
//!
//! Targets adversarial edge cases on public APIs that are *not* covered by
//! the in-crate `mod tests` and `mod enterprise_battery` modules: boundary
//! conditions on `TypeFact`, the `lattice` module, `CallGraph`, `TypeEnvironment`,
//! `StructRecovery`, `StructBuilder`, and `BinaryView`.

use std::collections::HashMap;

use rustre_analysis_type::{
    CallGraph, CallGraphNode, FieldAccess, InstrKind, StructRecovery, TypeEnvironment, TypeFact,
    TypeInferenceEngine, TypePropagator, TypedInstr, collect_constraints,
};
use rustre_analysis_type::TypeConstraint;
use rustre_analysis_type::lattice::{RefinementCell, TypeClass, TypeLevel};
use rustre_analysis_type::struct_builder::StructBuilder;
use rustre_analysis_type::constraints::Address;
use rustre_analysis_type::vtable::{BinaryView, SectionDesc};

// ──────────────────────────────────────────────────────────────────────────────
// TypeFact: byte_size / Display / join boundaries
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn byte_size_unknown_is_none() {
    assert_eq!(TypeFact::Unknown.byte_size(), None);
}

#[test]
fn byte_size_pointer_is_none() {
    // Pointers do not return a size despite being a known type.
    let p = TypeFact::Pointer(Box::new(TypeFact::SignedInt(4)));
    assert_eq!(p.byte_size(), None);
}

#[test]
fn byte_size_struct_is_none() {
    let s = TypeFact::Struct {
        fields: vec![(0, TypeFact::SignedInt(4)), (4, TypeFact::SignedInt(4))],
    };
    assert_eq!(s.byte_size(), None);
}

#[test]
fn byte_size_array_with_length_multiplies() {
    let a = TypeFact::Array {
        element: Box::new(TypeFact::SignedInt(4)),
        length: Some(8),
    };
    assert_eq!(a.byte_size(), Some(32));
}

#[test]
fn byte_size_array_overflow_saturates_to_none() {
    // element 8 × length usize::MAX overflows -> None (checked_mul).
    let a = TypeFact::Array {
        element: Box::new(TypeFact::SignedInt(8)),
        length: Some(usize::MAX),
    };
    assert_eq!(a.byte_size(), None);
}

#[test]
fn byte_size_array_no_length_is_none() {
    let a = TypeFact::Array {
        element: Box::new(TypeFact::SignedInt(4)),
        length: None,
    };
    assert_eq!(a.byte_size(), None);
}

#[test]
fn byte_size_bool_and_char_are_one() {
    assert_eq!(TypeFact::Bool.byte_size(), Some(1));
    assert_eq!(TypeFact::Char.byte_size(), Some(1));
}

#[test]
fn is_known_for_all_variants() {
    assert!(!TypeFact::Unknown.is_known());
    assert!(TypeFact::Bool.is_known());
    assert!(TypeFact::Sized(0).is_known());
    assert!(TypeFact::Pointer(Box::new(TypeFact::Unknown)).is_known());
}

#[test]
fn display_pointer_nested() {
    let p = TypeFact::Pointer(Box::new(TypeFact::Pointer(Box::new(TypeFact::Bool))));
    assert_eq!(format!("{p}"), "**bool");
}

#[test]
fn display_array_with_and_without_length() {
    let a1 = TypeFact::Array {
        element: Box::new(TypeFact::SignedInt(4)),
        length: Some(3),
    };
    assert_eq!(format!("{a1}"), "[i32; 3]");
    let a2 = TypeFact::Array {
        element: Box::new(TypeFact::SignedInt(4)),
        length: None,
    };
    assert_eq!(format!("{a2}"), "[i32]");
}

#[test]
fn display_struct_with_multiple_fields() {
    let s = TypeFact::Struct {
        fields: vec![(0, TypeFact::Bool), (4, TypeFact::Char)],
    };
    let out = format!("{s}");
    assert!(out.starts_with("struct{"));
    assert!(out.contains("+0: bool"));
    assert!(out.contains("+4: char"));
}

#[test]
fn display_signed_unsigned_uses_bit_width() {
    assert_eq!(format!("{}", TypeFact::SignedInt(4)), "i32");
    assert_eq!(format!("{}", TypeFact::UnsignedInt(8)), "u64");
    assert_eq!(format!("{}", TypeFact::Float(4)), "f32");
}

#[test]
fn join_pointer_with_unknown_inner_refines() {
    let pa = TypeFact::Pointer(Box::new(TypeFact::Unknown));
    let pb = TypeFact::Pointer(Box::new(TypeFact::SignedInt(4)));
    assert_eq!(pa.join(&pb), pb);
}

#[test]
fn join_two_unknowns_is_unknown() {
    assert_eq!(TypeFact::Unknown.join(&TypeFact::Unknown), TypeFact::Unknown);
}

#[test]
fn join_sized_with_pointer_does_not_widen_when_size_unknown() {
    // Pointer has no byte_size, so Sized(8) join Pointer is Unknown (no refinement match).
    let s = TypeFact::Sized(8);
    let p = TypeFact::Pointer(Box::new(TypeFact::Unknown));
    assert_eq!(s.join(&p), TypeFact::Unknown);
}

#[test]
fn join_different_sized_widens_to_unknown() {
    assert_eq!(
        TypeFact::Sized(4).join(&TypeFact::Sized(8)),
        TypeFact::Unknown
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// TypeInferenceEngine
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn engine_var_for_returns_same_var_for_same_name() {
    let mut e = TypeInferenceEngine::new();
    let v1 = e.var_for("x");
    let v2 = e.var_for("x");
    assert_eq!(v1, v2);
    let v3 = e.var_for("y");
    assert_ne!(v1, v3);
}

#[test]
fn engine_type_of_unknown_variable_errors() {
    let e = TypeInferenceEngine::new();
    let assignment = HashMap::new();
    let r = e.type_of("nope", &assignment);
    assert!(matches!(
        r,
        Err(rustre_analysis_type::TypeError::UnknownVariable(_))
    ));
}

#[test]
fn engine_empty_solve_returns_empty_assignment() {
    let mut e = TypeInferenceEngine::new();
    let sol = e.solve().unwrap();
    assert!(sol.is_empty());
}

#[test]
fn engine_deref_forward_then_back() {
    // ptr -> pointee with pointee typed AFTER deref constraint: second pass should fix.
    let mut e = TypeInferenceEngine::new();
    let ptr = e.fresh();
    let pointee = e.fresh();
    e.add_constraint(TypeConstraint::Deref { ptr, pointee });
    e.add_constraint(TypeConstraint::HasType(pointee, TypeFact::SignedInt(4)));
    let sol = e.solve().unwrap();
    assert_eq!(
        sol.get(&ptr.0),
        Some(&TypeFact::Pointer(Box::new(TypeFact::SignedInt(4))))
    );
}

#[test]
fn engine_is_condition_assigns_bool() {
    let mut e = TypeInferenceEngine::new();
    let v = e.fresh();
    e.add_constraint(TypeConstraint::IsCondition(v));
    let sol = e.solve().unwrap();
    assert_eq!(sol.get(&v.0), Some(&TypeFact::Bool));
}

#[test]
fn engine_is_condition_does_not_override_existing() {
    let mut e = TypeInferenceEngine::new();
    let v = e.fresh();
    e.add_constraint(TypeConstraint::HasType(v, TypeFact::SignedInt(4)));
    e.add_constraint(TypeConstraint::IsCondition(v));
    let sol = e.solve().unwrap();
    assert_eq!(sol.get(&v.0), Some(&TypeFact::SignedInt(4)));
}

#[test]
fn engine_add_constraint_unions_lhs_rhs_result() {
    let mut e = TypeInferenceEngine::new();
    let a = e.fresh();
    let b = e.fresh();
    let c = e.fresh();
    e.add_constraint(TypeConstraint::Add {
        lhs: a,
        rhs: b,
        result: c,
    });
    e.add_constraint(TypeConstraint::HasType(a, TypeFact::SignedInt(4)));
    let sol = e.solve().unwrap();
    assert_eq!(sol.get(&a.0), sol.get(&b.0));
    assert_eq!(sol.get(&b.0), sol.get(&c.0));
    assert_eq!(sol.get(&c.0), Some(&TypeFact::SignedInt(4)));
}

#[test]
fn engine_all_types_iterates_registered_names() {
    let mut e = TypeInferenceEngine::new();
    let _ = e.var_for("a");
    let _ = e.var_for("b");
    let sol = e.solve().unwrap();
    let names: std::collections::HashSet<&str> = e.all_types(&sol).map(|(n, _)| n).collect();
    assert!(names.contains("a"));
    assert!(names.contains("b"));
}

// ──────────────────────────────────────────────────────────────────────────────
// collect_constraints + InstrKind round-trip
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn collect_const_signed_and_unsigned() {
    let mut e = TypeInferenceEngine::new();
    let instrs = vec![
        TypedInstr {
            kind: InstrKind::Const {
                dst: "s".into(),
                bytes: 4,
                signed: true,
            },
        },
        TypedInstr {
            kind: InstrKind::Const {
                dst: "u".into(),
                bytes: 2,
                signed: false,
            },
        },
    ];
    collect_constraints(&mut e, &instrs);
    let sol = e.solve().unwrap();
    assert_eq!(e.type_of("s", &sol).unwrap(), TypeFact::SignedInt(4));
    assert_eq!(e.type_of("u", &sol).unwrap(), TypeFact::UnsignedInt(2));
}

#[test]
fn collect_assign_unifies_dst_src() {
    let mut e = TypeInferenceEngine::new();
    collect_constraints(
        &mut e,
        &[
            TypedInstr {
                kind: InstrKind::Const {
                    dst: "src".into(),
                    bytes: 8,
                    signed: true,
                },
            },
            TypedInstr {
                kind: InstrKind::Assign {
                    dst: "dst".into(),
                    src: "src".into(),
                },
            },
        ],
    );
    let sol = e.solve().unwrap();
    assert_eq!(e.type_of("dst", &sol).unwrap(), TypeFact::SignedInt(8));
}

#[test]
fn collect_branch_marks_condition_as_bool() {
    let mut e = TypeInferenceEngine::new();
    collect_constraints(
        &mut e,
        &[TypedInstr {
            kind: InstrKind::Branch { cond: "c".into() },
        }],
    );
    let sol = e.solve().unwrap();
    assert_eq!(e.type_of("c", &sol).unwrap(), TypeFact::Bool);
}

#[test]
fn collect_load_creates_pointer_type() {
    let mut e = TypeInferenceEngine::new();
    collect_constraints(
        &mut e,
        &[
            TypedInstr {
                kind: InstrKind::Const {
                    dst: "v".into(),
                    bytes: 4,
                    signed: true,
                },
            },
            TypedInstr {
                kind: InstrKind::Load {
                    dst: "v".into(),
                    ptr: "p".into(),
                },
            },
        ],
    );
    let sol = e.solve().unwrap();
    assert_eq!(
        e.type_of("p", &sol).unwrap(),
        TypeFact::Pointer(Box::new(TypeFact::SignedInt(4)))
    );
}

#[test]
fn collect_return_with_no_value_does_not_crash() {
    let mut e = TypeInferenceEngine::new();
    collect_constraints(
        &mut e,
        &[TypedInstr {
            kind: InstrKind::Return { val: None },
        }],
    );
    let _ = e.solve().unwrap();
}

#[test]
fn collect_call_with_no_dst_only_registers_args() {
    let mut e = TypeInferenceEngine::new();
    collect_constraints(
        &mut e,
        &[TypedInstr {
            kind: InstrKind::Call {
                dst: None,
                function: "foo".into(),
                args: vec!["a0".into(), "a1".into()],
            },
        }],
    );
    let sol = e.solve().unwrap();
    // a0 and a1 should be registered (no concrete type).
    assert_eq!(e.type_of("a0", &sol).unwrap(), TypeFact::Unknown);
    assert_eq!(e.type_of("a1", &sol).unwrap(), TypeFact::Unknown);
}

// ──────────────────────────────────────────────────────────────────────────────
// CallGraph
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn callgraph_add_call_to_unknown_caller_is_noop() {
    let mut cg = CallGraph::new();
    cg.add_call("ghost", "callee");
    assert!(cg.nodes.get("ghost").is_none());
}

#[test]
fn callgraph_add_call_dedupes_callees() {
    let mut cg = CallGraph::new();
    cg.add_function("a");
    cg.add_call("a", "b");
    cg.add_call("a", "b");
    cg.add_call("a", "b");
    assert_eq!(cg.nodes["a"].callees.len(), 1);
}

#[test]
fn callgraph_topological_order_includes_all_nodes() {
    let mut cg = CallGraph::new();
    cg.add_function("a");
    cg.add_function("b");
    cg.add_function("c");
    cg.add_call("a", "b");
    cg.add_call("b", "c");
    let order = cg.topological_order();
    assert_eq!(order.len(), 3);
    let pos = |s: &str| order.iter().position(|n| n == s).unwrap();
    // callees come before callers in post-order DFS.
    assert!(pos("c") < pos("b"));
    assert!(pos("b") < pos("a"));
}

#[test]
fn callgraph_topological_order_handles_cycle_without_overflow() {
    let mut cg = CallGraph::new();
    cg.add_function("a");
    cg.add_function("b");
    cg.add_call("a", "b");
    cg.add_call("b", "a");
    let order = cg.topological_order();
    // Both must appear; algorithm must terminate.
    assert_eq!(order.len(), 2);
}

#[test]
fn callgraph_topological_handles_deep_chain() {
    let mut cg = CallGraph::new();
    const N: usize = 5_000;
    for i in 0..N {
        cg.add_function(format!("f{i}"));
    }
    for i in 0..N - 1 {
        cg.add_call(&format!("f{i}"), &format!("f{}", i + 1));
    }
    let order = cg.topological_order();
    assert_eq!(order.len(), N);
}

// ──────────────────────────────────────────────────────────────────────────────
// TypePropagator
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn propagator_env_for_unknown_is_none() {
    let cg = CallGraph::new();
    let p = TypePropagator::new(cg);
    assert!(p.env_for("nope").is_none());
}

#[test]
fn propagator_set_initial_env_round_trips() {
    let cg = CallGraph::new();
    let mut p = TypePropagator::new(cg);
    let mut env = TypeEnvironment::new();
    env.set("x", TypeFact::Bool);
    p.set_initial_env("f", env);
    let got = p.env_for("f").unwrap();
    assert_eq!(got.get("x"), &TypeFact::Bool);
}

#[test]
fn propagator_propagates_return_type_to_caller() {
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
    let caller = p.env_for("caller").unwrap();
    assert_eq!(caller.get("callee"), &TypeFact::SignedInt(4));
}

// ──────────────────────────────────────────────────────────────────────────────
// TypeEnvironment
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn env_get_missing_returns_unknown() {
    let env = TypeEnvironment::new();
    assert_eq!(env.get("ghost"), &TypeFact::Unknown);
}

#[test]
fn env_merge_joins_arg_types() {
    let mut a = TypeEnvironment::new();
    a.arg_types = vec![TypeFact::Sized(4)];
    let mut b = TypeEnvironment::new();
    b.arg_types = vec![TypeFact::SignedInt(4), TypeFact::Bool];
    a.merge(&b);
    // arg 0 refines to SignedInt(4); arg 1 added from b.
    assert_eq!(a.arg_types.len(), 2);
    assert_eq!(a.arg_types[0], TypeFact::SignedInt(4));
    assert_eq!(a.arg_types[1], TypeFact::Bool);
}

#[test]
fn env_merge_refines_return_type() {
    let mut a = TypeEnvironment::new();
    a.return_type = TypeFact::Sized(4);
    let mut b = TypeEnvironment::new();
    b.return_type = TypeFact::SignedInt(4);
    a.merge(&b);
    assert_eq!(a.return_type, TypeFact::SignedInt(4));
}

// ──────────────────────────────────────────────────────────────────────────────
// StructRecovery
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn struct_recovery_empty_input() {
    let result = StructRecovery::recover(&[]);
    assert!(result.is_empty());
}

#[test]
fn struct_recovery_groups_by_base() {
    let accesses = vec![
        FieldAccess {
            base: "obj".into(),
            offset: 0,
            access_size: 4,
        },
        FieldAccess {
            base: "obj".into(),
            offset: 8,
            access_size: 8,
        },
        FieldAccess {
            base: "other".into(),
            offset: 0,
            access_size: 1,
        },
    ];
    let result = StructRecovery::recover(&accesses);
    assert_eq!(result.len(), 2);
    if let TypeFact::Struct { fields } = &result["obj"] {
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].0, 0);
        assert_eq!(fields[1].0, 8);
    } else {
        panic!("expected struct");
    }
}

#[test]
fn struct_recovery_dedups_identical_accesses() {
    let accesses = vec![
        FieldAccess {
            base: "o".into(),
            offset: 0,
            access_size: 4,
        },
        FieldAccess {
            base: "o".into(),
            offset: 0,
            access_size: 4,
        },
    ];
    let result = StructRecovery::recover(&accesses);
    if let TypeFact::Struct { fields } = &result["o"] {
        assert_eq!(fields.len(), 1);
    } else {
        panic!();
    }
}

#[test]
fn struct_recovery_keeps_distinct_sizes_at_same_offset() {
    let accesses = vec![
        FieldAccess {
            base: "o".into(),
            offset: 0,
            access_size: 4,
        },
        FieldAccess {
            base: "o".into(),
            offset: 0,
            access_size: 8,
        },
    ];
    let result = StructRecovery::recover(&accesses);
    if let TypeFact::Struct { fields } = &result["o"] {
        assert_eq!(fields.len(), 2);
    } else {
        panic!();
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// lattice: TypeLevel boundaries
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn typelevel_meet_conflict_absorbs() {
    let c = TypeLevel::Conflict;
    let w = TypeLevel::Width(4);
    assert_eq!(c.meet(&w), TypeLevel::Conflict);
    assert_eq!(w.meet(&c), TypeLevel::Conflict);
}

#[test]
fn typelevel_meet_two_unequal_widths_conflicts() {
    let a = TypeLevel::Width(4);
    let b = TypeLevel::Width(8);
    assert_eq!(a.meet(&b), TypeLevel::Conflict);
}

#[test]
fn typelevel_meet_two_unequal_classes_conflicts() {
    let a = TypeLevel::Class(TypeClass::Integer(4));
    let b = TypeLevel::Class(TypeClass::Float(4));
    assert_eq!(a.meet(&b), TypeLevel::Conflict);
}

#[test]
fn typelevel_join_top_dominates() {
    let a = TypeLevel::Width(4);
    let b = TypeLevel::Top;
    assert_eq!(a.join(&b), TypeLevel::Top);
}

#[test]
fn typelevel_join_conflict_returns_other() {
    let a = TypeLevel::Conflict;
    let b = TypeLevel::Width(4);
    assert_eq!(a.join(&b), b);
}

#[test]
fn typelevel_width_method_for_each_variant() {
    assert_eq!(TypeLevel::Top.width(), None);
    assert_eq!(TypeLevel::Conflict.width(), None);
    assert_eq!(TypeLevel::LibrarySignature.width(), None);
    assert_eq!(TypeLevel::Width(8).width(), Some(8));
    assert_eq!(
        TypeLevel::Class(TypeClass::Integer(4)).width(),
        Some(4)
    );
    assert_eq!(
        TypeLevel::Concrete(TypeFact::SignedInt(2)).width(),
        Some(2)
    );
}

#[test]
fn typeclass_width_boolean_and_character_are_one() {
    assert_eq!(TypeClass::Boolean.width(), Some(1));
    assert_eq!(TypeClass::Character.width(), Some(1));
}

#[test]
fn refinement_cell_starts_at_top_zero_observations() {
    let cell = RefinementCell::new();
    assert_eq!(cell.observation_count(), 0);
    assert_eq!(cell.level(), &TypeLevel::Top);
    assert!(!cell.is_conflict());
}

#[test]
fn refinement_cell_observe_increments_counter_even_on_conflict() {
    let mut cell = RefinementCell::new();
    cell.observe_fact(&TypeFact::SignedInt(4));
    cell.observe_fact(&TypeFact::Float(8));
    assert!(cell.is_conflict());
    assert_eq!(cell.observation_count(), 2);
    // Once in Conflict, additional observations stay in Conflict.
    cell.observe_fact(&TypeFact::Bool);
    assert!(cell.is_conflict());
    assert_eq!(cell.observation_count(), 3);
}

// ──────────────────────────────────────────────────────────────────────────────
// StructBuilder
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn struct_builder_empty_state() {
    let b = StructBuilder::new();
    assert!(b.is_empty());
    assert_eq!(b.field_count(), 0);
    assert!(b.offsets().is_empty());
    let st = b.build_struct("E");
    assert_eq!(st.min_size, 0);
    assert!(st.fields.is_empty());
}

#[test]
fn struct_builder_to_c_decl_contains_braces() {
    let mut b = StructBuilder::new();
    b.record_access(0, 4, true, Address(0x100));
    let s = b.build_struct("Foo");
    let decl = s.to_c_decl();
    assert!(decl.contains("typedef struct Foo {"));
    assert!(decl.contains("}"));
}

#[test]
fn struct_builder_distinct_accessors_counted() {
    let mut b = StructBuilder::new();
    b.record_access(0, 4, true, Address(0x100));
    b.record_access(0, 4, true, Address(0x200));
    b.record_access(0, 4, true, Address(0x300));
    let s = b.build_struct("X");
    assert_eq!(s.fields[0].accessor_count, 3);
}

#[test]
fn struct_builder_infer_padding_no_gaps() {
    let mut b = StructBuilder::new();
    b.record_access(0, 4, true, Address(0));
    b.record_access(4, 4, true, Address(0));
    let pad = b.infer_padding();
    assert!(pad.is_empty());
}

#[test]
fn struct_builder_merge_preserves_counts() {
    let mut a = StructBuilder::new();
    a.record_access(0, 4, true, Address(0x100));
    a.record_access(0, 4, true, Address(0x100));
    let mut b = StructBuilder::new();
    b.record_access(0, 4, true, Address(0x100));
    a.merge_with(&b);
    let s = a.build_struct("M");
    assert_eq!(s.fields[0].access_count, 3);
}

// ──────────────────────────────────────────────────────────────────────────────
// vtable::BinaryView + SectionDesc
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn section_desc_is_rodata_only_when_readonly_nonexec() {
    let s = SectionDesc {
        name: ".rdata".into(),
        start: 0,
        size: 0x100,
        is_executable: false,
        is_readable: true,
        is_writable: false,
    };
    assert!(s.is_rodata());

    let bad = SectionDesc {
        name: ".rdata".into(),
        start: 0,
        size: 0x100,
        is_executable: false,
        is_readable: true,
        is_writable: true,
    };
    assert!(!bad.is_rodata());
}

#[test]
fn section_desc_contains_boundary() {
    let s = SectionDesc {
        name: ".text".into(),
        start: 0x1000,
        size: 0x100,
        is_executable: true,
        is_readable: true,
        is_writable: false,
    };
    assert!(s.contains(0x1000));
    assert!(s.contains(0x10FF));
    assert!(!s.contains(0x1100)); // strict upper bound
    assert!(!s.contains(0xFFF));
}

#[test]
fn binary_view_read_below_image_base_returns_none() {
    let bv = BinaryView::new(vec![0u8; 16], 0x1000, vec![], 8);
    // rva < image_base — checked_sub returns None.
    assert!(bv.read_u32(0x0FF0).is_none());
}

#[test]
fn binary_view_read_past_end_returns_none() {
    let bv = BinaryView::new(vec![0u8; 4], 0x1000, vec![], 8);
    assert!(bv.read_u64(0x1000).is_none());
    assert!(bv.read_u32(0x1003).is_none()); // would need 4 bytes; only 1 left
}

#[test]
fn binary_view_read_u32_little_endian() {
    let bv = BinaryView::new(vec![0x78, 0x56, 0x34, 0x12], 0x1000, vec![], 8);
    assert_eq!(bv.read_u32(0x1000), Some(0x1234_5678));
}

#[test]
fn binary_view_read_u64_little_endian() {
    let mut data = Vec::new();
    for i in 0..8u8 {
        data.push(i);
    }
    let bv = BinaryView::new(data, 0, vec![], 8);
    assert_eq!(bv.read_u64(0), Some(0x0706_0504_0302_0100));
}

// ──────────────────────────────────────────────────────────────────────────────
// CallGraphNode serialization smoke (Serialize/Deserialize derives)
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn call_graph_node_is_constructible_and_clone_equals() {
    let n = CallGraphNode {
        name: "f".into(),
        callees: vec!["g".into(), "h".into()],
    };
    let n2 = n.clone();
    assert_eq!(n.name, n2.name);
    assert_eq!(n.callees, n2.callees);
}

