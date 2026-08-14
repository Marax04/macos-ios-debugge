//! blitz2: deep adversarial tests for rustre-decompiler-type.

use rustre_decompiler_expr::{BinOp, Expr, IntWidth, UnOp};
use rustre_decompiler_type::*;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

const fn all_widths() -> [IntWidth; 8] {
    [
        IntWidth::I8,
        IntWidth::I16,
        IntWidth::I32,
        IntWidth::I64,
        IntWidth::U8,
        IntWidth::U16,
        IntWidth::U32,
        IntWidth::U64,
    ]
}

// ──────────────────────────────────────────────────────────────
// DecompType basics
// ──────────────────────────────────────────────────────────────

#[test]
fn t01_byte_size_int_widths() {
    for w in all_widths() {
        let bs = DecompType::Int(w).byte_size().unwrap();
        assert_eq!(bs * 8, u64::from(w.bits()));
    }
}

#[test]
fn t02_byte_size_unknown() {
    assert_eq!(DecompType::Unknown.byte_size(), None);
}

#[test]
fn t03_byte_size_ptr_widths() {
    let p = DecompType::Ptr(Box::new(DecompType::Void));
    assert_eq!(p.byte_size_with_ptr_width(4), Some(4));
    assert_eq!(p.byte_size_with_ptr_width(8), Some(8));
}

#[test]
fn t04_byte_size_array_overflow() {
    // Array of u64 of huge length should overflow → None.
    let ty = DecompType::Array(Box::new(DecompType::Int(IntWidth::U64)), u64::MAX);
    assert_eq!(ty.byte_size(), None);
}

#[test]
fn t05_byte_size_array_unknown_inner() {
    let ty = DecompType::Array(Box::new(DecompType::Unknown), 10);
    assert_eq!(ty.byte_size(), None);
}

#[test]
fn t06_byte_size_zero_elem_array() {
    let ty = DecompType::Array(Box::new(DecompType::Int(IntWidth::I32)), 0);
    assert_eq!(ty.byte_size(), Some(0));
}

#[test]
fn t07_is_pointer_variants() {
    assert!(DecompType::Ptr(Box::new(DecompType::Void)).is_pointer());
    assert!(DecompType::CStr.is_pointer());
    assert!(
        DecompType::FnPtr {
            ret: Box::new(DecompType::Void),
            params: vec![],
        }
        .is_pointer()
    );
    assert!(!DecompType::Int(IntWidth::I32).is_pointer());
    assert!(!DecompType::Unknown.is_pointer());
    assert!(!DecompType::Bool.is_pointer());
}

#[test]
fn t08_pointee_only_for_ptr() {
    let p = DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32)));
    assert_eq!(p.pointee(), Some(&DecompType::Int(IntWidth::I32)));
    assert_eq!(DecompType::CStr.pointee(), None);
    assert_eq!(DecompType::Int(IntWidth::I32).pointee(), None);
}

#[test]
fn t09_c_name_basic() {
    assert_eq!(DecompType::Void.c_name(), "void");
    assert_eq!(DecompType::Bool.c_name(), "bool");
    assert_eq!(DecompType::Float32.c_name(), "float");
    assert_eq!(DecompType::Float64.c_name(), "double");
    assert_eq!(DecompType::CStr.c_name(), "char *");
    assert_eq!(DecompType::Unknown.c_name(), "void *");
}

#[test]
fn t10_c_name_array_and_struct() {
    let arr = DecompType::Array(Box::new(DecompType::Int(IntWidth::U8)), 16);
    assert_eq!(arr.c_name(), "uint8_t[16]");
    let st = StructType::new("X", vec![], 0);
    assert_eq!(DecompType::Struct(Box::new(st)).c_name(), "struct X");
}

#[test]
fn t11_name_prefix() {
    assert_eq!(DecompType::Bool.name_prefix(), "b_");
    assert_eq!(DecompType::Int(IntWidth::I32).name_prefix(), "i");
    assert_eq!(DecompType::Int(IntWidth::U32).name_prefix(), "u");
    assert_eq!(
        DecompType::Ptr(Box::new(DecompType::Void)).name_prefix(),
        "p_"
    );
    assert_eq!(DecompType::CStr.name_prefix(), "sz_");
    assert_eq!(DecompType::Float64.name_prefix(), "f_");
}

// ──────────────────────────────────────────────────────────────
// StructType lookups
// ──────────────────────────────────────────────────────────────

#[test]
fn t12_struct_field_at_boundary() {
    let st = StructType::new(
        "S",
        vec![
            StructField::new(0, "a", DecompType::Int(IntWidth::I32)),
            StructField::new(4, "b", DecompType::Int(IntWidth::I32)),
        ],
        8,
    );
    assert_eq!(st.field_at(0).map(|f| f.name.as_str()), Some("a"));
    assert_eq!(st.field_at(3).map(|f| f.name.as_str()), Some("a"));
    assert_eq!(st.field_at(4).map(|f| f.name.as_str()), Some("b"));
    assert_eq!(st.field_at(7).map(|f| f.name.as_str()), Some("b"));
    assert!(st.field_at(8).is_none());
}

#[test]
fn t13_struct_field_at_unknown_field_skipped() {
    let st = StructType::new(
        "S",
        vec![StructField::new(0, "u", DecompType::Unknown)],
        8,
    );
    // Unknown-typed fields should be skipped (have no size).
    assert!(st.field_at(0).is_none());
}

#[test]
fn t14_struct_field_exact_misses_inexact() {
    let st = StructType::new(
        "S",
        vec![StructField::new(8, "y", DecompType::Int(IntWidth::I64))],
        16,
    );
    assert!(st.field_exact(4).is_none());
    assert_eq!(st.field_exact(8).map(|f| f.name.as_str()), Some("y"));
}

// ──────────────────────────────────────────────────────────────
// TypeEnvironment
// ──────────────────────────────────────────────────────────────

#[test]
fn t15_type_env_set_get_overwrites() {
    let mut env = TypeEnvironment::new();
    env.set("x", DecompType::Int(IntWidth::I32));
    env.set("x", DecompType::Bool);
    assert_eq!(env.get("x"), Some(&DecompType::Bool));
    assert!(env.get("missing").is_none());
}

#[test]
fn t16_type_env_resolve_struct() {
    let env = TypeEnvironment::new();
    let st = StructType::new("N", vec![], 0);
    let ty = DecompType::Struct(Box::new(st));
    let resolved = env.resolve_struct(&ty).unwrap();
    assert_eq!(resolved.name, "N");
    assert!(env.resolve_struct(&DecompType::Int(IntWidth::I32)).is_none());
}

// ──────────────────────────────────────────────────────────────
// TypedExprEmitter — fuzz / properties
// ──────────────────────────────────────────────────────────────

#[test]
fn t17_emit_var_roundtrip() {
    let env = TypeEnvironment::new();
    let e = TypedExprEmitter::new(&env, 8);
    for i in 0..50 {
        let name = format!("v{i}");
        let out = e.emit(&Expr::Var(name.clone())).unwrap();
        assert_eq!(out, name);
    }
}

#[test]
fn t18_emit_const_fuzz_never_panic() {
    let env = TypeEnvironment::new();
    let e = TypedExprEmitter::new(&env, 8);
    let mut g = lcg();
    for _ in 0..200 {
        let v = g() as i64;
        let widths = all_widths();
        let w = widths[(g() as usize) % widths.len()];
        let _ = e.emit(&Expr::Const(v, w)).unwrap();
    }
}

#[test]
fn t19_emit_const_small_decimal() {
    let env = TypeEnvironment::new();
    let e = TypedExprEmitter::new(&env, 8);
    for v in 0..1000i64 {
        let s = e.emit(&Expr::Const(v, IntWidth::I32)).unwrap();
        assert_eq!(s, v.to_string());
    }
}

#[test]
fn t20_emit_const_large_hex_format() {
    let env = TypeEnvironment::new();
    let e = TypedExprEmitter::new(&env, 8);
    let s = e.emit(&Expr::Const(0x1234, IntWidth::U32)).unwrap();
    assert!(s.starts_with("0x") && s.ends_with('U'));
    let s = e.emit(&Expr::Const(0x1234, IntWidth::U64)).unwrap();
    assert!(s.ends_with("ULL"));
}

#[test]
fn t21_emit_deref_nonpointer_err() {
    let mut env = TypeEnvironment::new();
    env.set("x", DecompType::Int(IntWidth::I32));
    let e = TypedExprEmitter::new(&env, 8);
    let r = e.emit(&Expr::UnOp(UnOp::Deref, Box::new(Expr::Var("x".into()))));
    assert!(matches!(r, Err(TypeError::DerefNonPointer(_))));
}

#[test]
fn t22_emit_deref_pointer_ok() {
    let mut env = TypeEnvironment::new();
    env.set("p", DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32))));
    let e = TypedExprEmitter::new(&env, 8);
    let s = e
        .emit(&Expr::UnOp(UnOp::Deref, Box::new(Expr::Var("p".into()))))
        .unwrap();
    assert_eq!(s, "*p");
}

#[test]
fn t23_emit_field_access_struct_ptr() {
    let st = StructType::new(
        "N",
        vec![
            StructField::new(0, "a", DecompType::Int(IntWidth::I32)),
            StructField::new(8, "b", DecompType::Int(IntWidth::I64)),
        ],
        16,
    );
    let mut env = TypeEnvironment::new();
    env.set(
        "p",
        DecompType::Ptr(Box::new(DecompType::Struct(Box::new(st.clone())))),
    );
    env.add_struct(st);
    let e = TypedExprEmitter::new(&env, 8);
    let expr = Expr::FieldAccess {
        base: Box::new(Expr::Var("p".into())),
        offset: 8,
    };
    assert_eq!(e.emit(&expr).unwrap(), "p->b");
}

#[test]
fn t24_emit_field_access_bad_offset_err() {
    let st = StructType::new(
        "N",
        vec![StructField::new(0, "a", DecompType::Int(IntWidth::I32))],
        4,
    );
    let mut env = TypeEnvironment::new();
    env.set("p", DecompType::Ptr(Box::new(DecompType::Struct(Box::new(st.clone())))));
    env.add_struct(st);
    let e = TypedExprEmitter::new(&env, 8);
    let expr = Expr::FieldAccess {
        base: Box::new(Expr::Var("p".into())),
        offset: 99,
    };
    let r = e.emit(&expr);
    assert!(matches!(r, Err(TypeError::NoFieldAtOffset(_, 99))));
}

#[test]
fn t25_emit_unary_ops() {
    let env = TypeEnvironment::new();
    let e = TypedExprEmitter::new(&env, 8);
    let v = || Box::new(Expr::Var("x".into()));
    assert_eq!(e.emit(&Expr::UnOp(UnOp::Neg, v())).unwrap(), "-x");
    assert_eq!(e.emit(&Expr::UnOp(UnOp::Not, v())).unwrap(), "~x");
    assert_eq!(e.emit(&Expr::UnOp(UnOp::LNot, v())).unwrap(), "!x");
    assert_eq!(e.emit(&Expr::UnOp(UnOp::AddrOf, v())).unwrap(), "&x");
    let cast = Expr::UnOp(UnOp::Cast(IntWidth::U32), v());
    let s = e.emit(&cast).unwrap();
    assert!(s.starts_with("(uint32_t)"));
}

// ──────────────────────────────────────────────────────────────
// TypeAwareRenamer
// ──────────────────────────────────────────────────────────────

#[test]
fn t26_renamer_unique_names_per_type() {
    let mut r = TypeAwareRenamer::new();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..50 {
        let n = r.rename(&DecompType::Int(IntWidth::I32));
        assert!(seen.insert(n));
    }
}

#[test]
fn t27_renamer_hint_arg_preserved() {
    let mut r = TypeAwareRenamer::new();
    assert_eq!(
        r.rename_with_hint("arg0", &DecompType::Int(IntWidth::I32)),
        "arg0"
    );
    assert_eq!(
        r.rename_with_hint("param1", &DecompType::Int(IntWidth::I32)),
        "param1"
    );
}

#[test]
fn t28_renamer_rename_variables_var_prefix() {
    let mut r = TypeAwareRenamer::new();
    let env = TypeEnvironment::new();
    let out = r.rename_variables("int var_1 = 5; var_1 += var_1;", &env);
    assert!(!out.contains("var_1"));
    assert!(out.contains("v_1"));
}

#[test]
fn t29_renamer_word_boundary_substitution() {
    let mut r = TypeAwareRenamer::new();
    let env = TypeEnvironment::new();
    // var_1 should not match inside var_100.
    let code = "x = var_1 + var_100;";
    let out = r.rename_variables(code, &env);
    // var_100 must still be present (as v_100) — not mangled.
    assert!(out.contains("v_100"));
    assert!(out.contains("v_1"));
}

#[test]
fn t30_renamer_malloc_becomes_ptr() {
    let mut r = TypeAwareRenamer::new();
    let env = TypeEnvironment::new();
    let code = "int *var_3 = malloc(16);";
    let out = r.rename_variables(code, &env);
    assert!(out.contains("ptr_"));
}

#[test]
fn t31_renamer_loop_counter_becomes_i() {
    let mut r = TypeAwareRenamer::new();
    let env = TypeEnvironment::new();
    let code = "for (var_2 = 0; var_2 < 10; var_2++) { }";
    let out = r.rename_variables(code, &env);
    // var_2 used as loop counter — should be renamed to short counter name (no var_2 left).
    assert!(!out.contains("var_2"));
}

// ──────────────────────────────────────────────────────────────
// TypeQualifier / QualifiedType
// ──────────────────────────────────────────────────────────────

#[test]
fn t32_type_qualifier_bitset() {
    let q = TypeQualifier::NONE.with_const().with_volatile().with_restrict();
    assert!(q.is_const() && q.is_volatile() && q.is_restrict());
    let none = TypeQualifier::NONE;
    assert!(!none.is_const() && !none.is_volatile() && !none.is_restrict());
}

#[test]
fn t33_type_qualifier_display() {
    let q = TypeQualifier::CONST.with_volatile();
    let s = format!("{q}");
    assert!(s.contains("const") && s.contains("volatile"));
}

#[test]
fn t34_qualified_type_no_quals() {
    let qt = QualifiedType::new(DecompType::Int(IntWidth::I32));
    assert_eq!(qt.c_name(), "int32_t");
}

// ──────────────────────────────────────────────────────────────
// UnionType / FunctionType / CTypeEmitter
// ──────────────────────────────────────────────────────────────

#[test]
fn t35_union_largest_member() {
    let u = UnionType::new(
        "U",
        vec![
            StructField::new(0, "a", DecompType::Int(IntWidth::I8)),
            StructField::new(0, "b", DecompType::Int(IntWidth::I64)),
            StructField::new(0, "c", DecompType::Int(IntWidth::I32)),
        ],
    );
    assert_eq!(u.total_size, 8);
    assert_eq!(u.c_name(), "union U");
    assert!(u.member_named("b").is_some());
    assert!(u.member_named("missing").is_none());
}

#[test]
fn t36_function_type_prototype_and_arity() {
    let mut f = FunctionType::new("fn", DecompType::Int(IntWidth::I32));
    assert_eq!(f.arity(), 0);
    f.add_param("a", DecompType::Int(IntWidth::I32));
    f.add_param("b", DecompType::CStr);
    assert_eq!(f.arity(), 2);
    let p = f.c_prototype();
    assert!(p.contains("__cdecl"));
    assert!(p.contains("int32_t a"));
    assert!(p.contains("char * b"));
}

#[test]
fn t37_calling_convention_as_str() {
    assert_eq!(CallingConvention::FastCall.as_str(), "__fastcall");
    assert_eq!(CallingConvention::ThisCall.as_str(), "__thiscall");
    assert_eq!(CallingConvention::default(), CallingConvention::CDecl);
}

#[test]
fn t38_ctype_emitter_indent() {
    let em = CTypeEmitter::with_indent(2);
    let st = StructType::new(
        "X",
        vec![StructField::new(0, "a", DecompType::Int(IntWidth::I32))],
        4,
    );
    let s = em.emit_struct(&st);
    // 2 levels of 4-space indent → starts with 8 spaces
    assert!(s.starts_with("        struct X"));
}

#[test]
fn t39_typedb_counts_and_lookups() {
    let mut db = TypeDatabase::new();
    db.load_windows_types();
    let n_struct = db.struct_count();
    assert!(n_struct >= 2);
    assert!(db.typedef_count() > 5);
    db.add_struct(StructType::new("Z", vec![], 0));
    assert_eq!(db.struct_count(), n_struct + 1);
    assert!(db.get_struct("Z").is_some());
}

// ──────────────────────────────────────────────────────────────
// TypeUnifier / TypeInference / TypePropagator
// ──────────────────────────────────────────────────────────────

#[test]
fn t40_unifier_transitive_classes() {
    let mut u = TypeUnifier::new();
    u.add_constraint(&TypeConstraint::new("a", "b", "r"));
    u.add_constraint(&TypeConstraint::new("b", "c", "r"));
    u.add_constraint(&TypeConstraint::new("d", "e", "r"));
    assert_eq!(u.canonical("a"), u.canonical("c"));
    assert_ne!(u.canonical("a"), u.canonical("d"));
    let classes = u.equivalence_classes();
    assert!(classes.values().any(|v| v.contains(&"a".to_string()) && v.contains(&"c".to_string())));
}

#[test]
fn t41_unifier_fuzz_no_panic() {
    let mut u = TypeUnifier::new();
    let mut g = lcg();
    for _ in 0..200 {
        let a = format!("v{}", g() % 20);
        let b = format!("v{}", g() % 20);
        u.add_constraint(&TypeConstraint::new(a, b, "fuzz"));
    }
    assert!(u.constraint_count() == 200);
    let _ = u.equivalence_classes();
}

#[test]
fn t42_type_inference_deref_propagation() {
    let mut inf = TypeInference::new();
    inf.set_type("p", DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32))));
    inf.infer_pointer_deref("p", "v");
    assert_eq!(inf.get_type("v"), Some(&DecompType::Int(IntWidth::I32)));
}

#[test]
fn t43_type_propagator_no_overwrite_binop() {
    let mut tp = TypePropagator::new();
    tp.seed("a", DecompType::Int(IntWidth::I32));
    tp.seed("r", DecompType::Bool); // already known
    tp.propagate_through_binop("r", "a", "x");
    // r was already known → not overwritten by binop propagation.
    assert_eq!(tp.get("r"), Some(&DecompType::Bool));
}

// ──────────────────────────────────────────────────────────────
// Compatibility helpers
// ──────────────────────────────────────────────────────────────

#[test]
fn t44_compatible_unknown_with_anything() {
    let unk = DecompType::Unknown;
    for w in all_widths() {
        assert!(are_compatible(&unk, &DecompType::Int(w)));
        assert!(are_compatible(&DecompType::Int(w), &unk));
    }
}

#[test]
fn t45_implicit_convertible_int_widening() {
    assert!(is_implicitly_convertible(
        &DecompType::Int(IntWidth::I8),
        &DecompType::Int(IntWidth::I64)
    ));
    // wider → narrower is NOT implicit (not compatible same width either way).
    // i64 → i8 is still "compatible" because both are Int.
    assert!(are_compatible(
        &DecompType::Int(IntWidth::I64),
        &DecompType::Int(IntWidth::I8)
    ));
}

// ──────────────────────────────────────────────────────────────
// Hash/Eq consistency
// ──────────────────────────────────────────────────────────────

#[test]
fn t46_hash_eq_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    fn h<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }
    let mut pairs = Vec::new();
    for w in all_widths() {
        pairs.push((DecompType::Int(w), DecompType::Int(w)));
    }
    pairs.push((DecompType::Void, DecompType::Void));
    pairs.push((DecompType::Bool, DecompType::Bool));
    pairs.push((DecompType::CStr, DecompType::CStr));
    pairs.push((
        DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32))),
        DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32))),
    ));
    pairs.push((
        DecompType::Array(Box::new(DecompType::Float32), 4),
        DecompType::Array(Box::new(DecompType::Float32), 4),
    ));
    let st = StructType::new("S", vec![StructField::new(0, "x", DecompType::Bool)], 1);
    pairs.push((
        DecompType::Struct(Box::new(st.clone())),
        DecompType::Struct(Box::new(st)),
    ));
    for _ in 0..20 {
        pairs.push((DecompType::Unknown, DecompType::Unknown));
    }
    assert!(pairs.len() >= 30);
    for (a, b) in &pairs {
        assert_eq!(a, b);
        assert_eq!(h(a), h(b));
    }
}

// ──────────────────────────────────────────────────────────────
// LatticeType / TypeRecovery / extras
// ──────────────────────────────────────────────────────────────

#[test]
fn t47_lattice_join_top_identity() {
    let mut g = lcg();
    for _ in 0..30 {
        let t = match g() % 4 {
            0 => LatticeType::Bool,
            1 => LatticeType::Float32,
            2 => LatticeType::Float64,
            _ => LatticeType::Integer {
                width: Some(IntWidth::I32),
            },
        };
        let j = LatticeType::Top.join(&t);
        assert_eq!(j, t);
        let j2 = t.join(&LatticeType::Top);
        assert_eq!(j2, t);
    }
}

#[test]
fn t48_lattice_bottom_absorbs() {
    let t = LatticeType::Integer {
        width: Some(IntWidth::I32),
    };
    assert!(LatticeType::Bottom.join(&t).is_conflict());
    assert!(t.join(&LatticeType::Bottom).is_conflict());
}

#[test]
fn t49_lattice_float_widen() {
    let j = LatticeType::Float32.join(&LatticeType::Float64);
    assert_eq!(j, LatticeType::Float64);
}

#[test]
fn t50_lattice_int_join_picks_wider_and_signed() {
    let j = LatticeType::Integer {
        width: Some(IntWidth::U8),
    }
    .join(&LatticeType::Integer {
        width: Some(IntWidth::I32),
    });
    if let LatticeType::Integer { width: Some(w) } = j {
        assert_eq!(w, IntWidth::I32);
    } else {
        panic!("expected integer");
    }
}

#[test]
fn t51_lattice_from_to_decomp_roundtrip_int() {
    for w in all_widths() {
        let lt = LatticeType::from_decomp(&DecompType::Int(w));
        assert_eq!(lt.to_decomp(), DecompType::Int(w));
    }
}

#[test]
fn t52_access_width_sizer_picks_widest() {
    let mut s = AccessWidthSizer::new();
    s.observe("x", 1);
    s.observe("x", 4);
    s.observe("x", 2);
    s.mark_signed("x");
    let ty = s.infer("x").unwrap();
    assert_eq!(ty, DecompType::Int(IntWidth::I32));
    assert!(s.infer("missing").is_none());
    assert_eq!(s.count(), 1);
}

#[test]
fn t53_pointer_detector_scans_deref_and_index() {
    let mut pd = PointerDetector::new();
    let expr = Expr::UnOp(UnOp::Deref, Box::new(Expr::Var("p".into())));
    pd.scan(&expr);
    assert!(pd.is_pointer("p"));
    let expr2 = Expr::FieldAccess {
        base: Box::new(Expr::Var("q".into())),
        offset: 4,
    };
    pd.scan(&expr2);
    assert!(pd.is_pointer("q"));
    assert!(!pd.is_pointer("not_there"));
}

#[test]
fn t54_struct_clusterer_builds_struct() {
    let mut sc = StructClusterer::new();
    sc.observe("base", 0, 4);
    sc.observe("base", 8, 4);
    sc.observe("base", 8, 2); // widest wins
    let st = sc.build_struct("base", "MyStruct").unwrap();
    assert_eq!(st.name, "MyStruct");
    assert_eq!(st.fields.len(), 2);
    assert!(sc.build_struct("missing", "n").is_none());
    let offs = sc.offsets("base");
    assert_eq!(offs, vec![0, 8]);
}

#[test]
fn t55_array_inference_strides() {
    let expr = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("a".into())),
        Box::new(Expr::BinOp(
            BinOp::Mul,
            Box::new(Expr::Var("i".into())),
            Box::new(Expr::Const(4, IntWidth::I32)),
        )),
    );
    let acc = ArrayInference::match_array_access(&expr).unwrap();
    assert_eq!(acc.base, "a");
    assert_eq!(acc.index, "i");
    assert_eq!(acc.stride, 4);

    // shl variant
    let expr2 = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("a".into())),
        Box::new(Expr::BinOp(
            BinOp::Shl,
            Box::new(Expr::Var("i".into())),
            Box::new(Expr::Const(3, IntWidth::I32)),
        )),
    );
    let acc2 = ArrayInference::match_array_access(&expr2).unwrap();
    assert_eq!(acc2.stride, 8);
}

#[test]
fn t56_constraint_solver_propagates() {
    let mut cs = ConstraintSolver::new();
    cs.add(Constraint::Equal("a".into(), "b".into()));
    cs.add(Constraint::HasType(
        "a".into(),
        LatticeType::Integer {
            width: Some(IntWidth::I32),
        },
    ));
    let res = cs.solve();
    assert_eq!(res.get("a"), Some(&DecompType::Int(IntWidth::I32)));
    assert_eq!(res.get("b"), Some(&DecompType::Int(IntWidth::I32)));
    assert!(cs.same_class("a", "b"));
}

#[test]
fn t57_constraint_solver_fuzz_no_panic() {
    let mut g = lcg();
    let mut cs = ConstraintSolver::new();
    for _ in 0..100 {
        let a = format!("v{}", g() % 10);
        let b = format!("v{}", g() % 10);
        match g() % 3 {
            0 => cs.add(Constraint::Equal(a, b)),
            1 => cs.add(Constraint::HasType(
                a,
                LatticeType::Integer { width: None },
            )),
            _ => cs.add(Constraint::PointsTo {
                ptr: a,
                pointee: b,
            }),
        }
    }
    let _ = cs.solve();
}

// ──────────────────────────────────────────────────────────────
// Send/Sync threaded stress (TypeEnvironment is Send+Sync via HashMap fields)
// ──────────────────────────────────────────────────────────────

#[test]
fn t58_threaded_renamer_send_sync() {
    use std::sync::{Arc, Mutex};
    use std::thread;
    let r = Arc::new(Mutex::new(TypeAwareRenamer::new()));
    let mut handles = vec![];
    for _ in 0..4 {
        let r2 = Arc::clone(&r);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let mut g = r2.lock().unwrap();
                let _ = g.rename(&DecompType::Int(IntWidth::I32));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // 4 * 100 = 400 unique names generated.
}

#[test]
fn t59_threaded_env_reads() {
    use std::sync::Arc;
    use std::thread;
    let mut env = TypeEnvironment::new();
    for i in 0..20 {
        env.set(format!("v{i}"), DecompType::Int(IntWidth::I32));
    }
    let env = Arc::new(env);
    let mut handles = vec![];
    for _ in 0..4 {
        let e = Arc::clone(&env);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let _ = e.get(&format!("v{}", i % 20));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ──────────────────────────────────────────────────────────────
// Serde round-trip
// ──────────────────────────────────────────────────────────────

#[test]
fn t60_serde_roundtrip_decomptype() {
    let samples = vec![
        DecompType::Void,
        DecompType::Bool,
        DecompType::Int(IntWidth::I32),
        DecompType::Float64,
        DecompType::CStr,
        DecompType::Ptr(Box::new(DecompType::Int(IntWidth::U64))),
        DecompType::Array(Box::new(DecompType::Int(IntWidth::U8)), 32),
        DecompType::Unknown,
    ];
    for s in samples {
        let j = serde_json::to_string(&s).unwrap();
        let back: DecompType = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
