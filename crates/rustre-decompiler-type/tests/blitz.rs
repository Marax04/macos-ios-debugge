//! Exhaustive blitz tests for `rustre-decompiler-type`.

use rustre_decompiler_expr::{BinOp, Expr, IntWidth, UnOp};
use rustre_decompiler_type::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn node_struct() -> StructType {
    StructType::new(
        "Node",
        vec![
            StructField::new(0, "value", DecompType::Int(IntWidth::I32)),
            StructField::new(8, "next", DecompType::Ptr(Box::new(DecompType::Unknown))),
        ],
        16,
    )
}

// ---------------------------------------------------------------------------
// DecompType::byte_size / byte_size_with_ptr_width
// ---------------------------------------------------------------------------

#[test]
fn byte_size_all_int_widths() {
    assert_eq!(DecompType::Int(IntWidth::I8).byte_size(), Some(1));
    assert_eq!(DecompType::Int(IntWidth::U8).byte_size(), Some(1));
    assert_eq!(DecompType::Int(IntWidth::I16).byte_size(), Some(2));
    assert_eq!(DecompType::Int(IntWidth::U16).byte_size(), Some(2));
    assert_eq!(DecompType::Int(IntWidth::I32).byte_size(), Some(4));
    assert_eq!(DecompType::Int(IntWidth::U32).byte_size(), Some(4));
    assert_eq!(DecompType::Int(IntWidth::I64).byte_size(), Some(8));
    assert_eq!(DecompType::Int(IntWidth::U64).byte_size(), Some(8));
}

#[test]
fn byte_size_void_bool_floats() {
    assert_eq!(DecompType::Void.byte_size(), Some(0));
    assert_eq!(DecompType::Bool.byte_size(), Some(1));
    assert_eq!(DecompType::Float32.byte_size(), Some(4));
    assert_eq!(DecompType::Float64.byte_size(), Some(8));
}

#[test]
fn byte_size_ptr_width_32_vs_64() {
    let p = DecompType::Ptr(Box::new(DecompType::Void));
    assert_eq!(p.byte_size_with_ptr_width(4), Some(4));
    assert_eq!(p.byte_size_with_ptr_width(8), Some(8));
    assert_eq!(DecompType::CStr.byte_size_with_ptr_width(4), Some(4));
}

#[test]
fn byte_size_nested_array_of_ptrs() {
    // [Ptr<i32>; 5] = 5 * 8 = 40
    let ty = DecompType::Array(
        Box::new(DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32)))),
        5,
    );
    assert_eq!(ty.byte_size(), Some(40));
}

#[test]
fn byte_size_array_zero_len() {
    let ty = DecompType::Array(Box::new(DecompType::Int(IntWidth::I32)), 0);
    assert_eq!(ty.byte_size(), Some(0));
}

#[test]
fn byte_size_array_of_unknown_is_none() {
    let ty = DecompType::Array(Box::new(DecompType::Unknown), 10);
    assert_eq!(ty.byte_size(), None);
}

#[test]
fn byte_size_unknown_is_none() {
    assert_eq!(DecompType::Unknown.byte_size(), None);
}

#[test]
fn byte_size_enum_variants() {
    let e = DecompType::Enum {
        name: "E".into(),
        variants: vec![],
        backing: IntWidth::I16,
    };
    assert_eq!(e.byte_size(), Some(2));
}

#[test]
fn byte_size_fnptr() {
    let f = DecompType::FnPtr {
        ret: Box::new(DecompType::Void),
        params: vec![],
    };
    assert_eq!(f.byte_size_with_ptr_width(4), Some(4));
    assert_eq!(f.byte_size_with_ptr_width(8), Some(8));
}

// ---------------------------------------------------------------------------
// DecompType::c_name
// ---------------------------------------------------------------------------

#[test]
fn c_name_primitives() {
    assert_eq!(DecompType::Void.c_name(), "void");
    assert_eq!(DecompType::Bool.c_name(), "bool");
    assert_eq!(DecompType::Float32.c_name(), "float");
    assert_eq!(DecompType::Float64.c_name(), "double");
    assert_eq!(DecompType::CStr.c_name(), "char *");
    assert_eq!(DecompType::Unknown.c_name(), "void *");
}

#[test]
fn c_name_ptr_to_ptr() {
    let pp = DecompType::Ptr(Box::new(DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32)))));
    assert_eq!(pp.c_name(), "int32_t * *");
}

#[test]
fn c_name_array() {
    let ty = DecompType::Array(Box::new(DecompType::Int(IntWidth::U8)), 16);
    assert_eq!(ty.c_name(), "uint8_t[16]");
}

#[test]
fn c_name_fnptr() {
    let f = DecompType::FnPtr {
        ret: Box::new(DecompType::Int(IntWidth::I32)),
        params: vec![DecompType::Int(IntWidth::I32), DecompType::CStr],
    };
    assert_eq!(f.c_name(), "int32_t(*)(int32_t, char *)");
}

#[test]
fn c_name_enum() {
    let e = DecompType::Enum {
        name: "Color".into(),
        variants: vec![],
        backing: IntWidth::U32,
    };
    assert_eq!(e.c_name(), "enum Color");
}

// ---------------------------------------------------------------------------
// DecompType::is_pointer / pointee / name_prefix
// ---------------------------------------------------------------------------

#[test]
fn is_pointer_matrix() {
    assert!(DecompType::CStr.is_pointer());
    assert!(DecompType::Ptr(Box::new(DecompType::Void)).is_pointer());
    assert!(DecompType::FnPtr {
        ret: Box::new(DecompType::Void),
        params: vec![]
    }
    .is_pointer());
    assert!(!DecompType::Int(IntWidth::I32).is_pointer());
    assert!(!DecompType::Bool.is_pointer());
    assert!(!DecompType::Unknown.is_pointer());
}

#[test]
fn pointee_only_for_ptr() {
    let p = DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32)));
    assert!(matches!(p.pointee(), Some(DecompType::Int(IntWidth::I32))));
    assert!(DecompType::CStr.pointee().is_none());
    assert!(DecompType::Int(IntWidth::I32).pointee().is_none());
}

#[test]
fn name_prefix_signed_vs_unsigned() {
    assert_eq!(DecompType::Int(IntWidth::I32).name_prefix(), "i");
    assert_eq!(DecompType::Int(IntWidth::U32).name_prefix(), "u");
    assert_eq!(DecompType::Bool.name_prefix(), "b_");
    assert_eq!(DecompType::CStr.name_prefix(), "sz_");
    assert_eq!(DecompType::Float32.name_prefix(), "f_");
    assert_eq!(
        DecompType::Ptr(Box::new(DecompType::Void)).name_prefix(),
        "p_"
    );
    assert_eq!(
        DecompType::Array(Box::new(DecompType::Int(IntWidth::I32)), 4).name_prefix(),
        "arr_"
    );
}

// ---------------------------------------------------------------------------
// StructType::field_at / field_exact
// ---------------------------------------------------------------------------

#[test]
fn struct_field_exact_and_at() {
    let st = node_struct();
    assert_eq!(st.field_exact(0).unwrap().name, "value");
    assert_eq!(st.field_exact(8).unwrap().name, "next");
    assert!(st.field_exact(4).is_none());
    // field_at: offset 2 falls inside value (0..4)
    assert_eq!(st.field_at(2).map(|f| f.name.as_str()), Some("value"));
    // offset 4 is past value (size 4, ends at 4 exclusive), and before next (8)
    assert!(st.field_at(4).is_none());
    // offset 10 falls inside next pointer (8..16)
    assert_eq!(st.field_at(10).map(|f| f.name.as_str()), Some("next"));
    // offset 16 is one past last byte
    assert!(st.field_at(16).is_none());
}

#[test]
fn struct_field_at_skips_unknown_sized() {
    let st = StructType::new(
        "S",
        vec![StructField::new(0, "u", DecompType::Unknown)],
        16,
    );
    // Unknown has no known size => predicate must skip it (no infinite-match)
    assert!(st.field_at(0).is_none());
    assert!(st.field_at(4).is_none());
}

// ---------------------------------------------------------------------------
// TypeEnvironment
// ---------------------------------------------------------------------------

#[test]
fn type_env_set_get_overwrites() {
    let mut env = TypeEnvironment::new();
    env.set("x", DecompType::Int(IntWidth::I32));
    assert_eq!(env.get("x"), Some(&DecompType::Int(IntWidth::I32)));
    env.set("x", DecompType::Bool);
    assert_eq!(env.get("x"), Some(&DecompType::Bool));
    assert!(env.get("nope").is_none());
}

#[test]
fn type_env_struct_lookup() {
    let mut env = TypeEnvironment::new();
    env.add_struct(node_struct());
    assert!(env.struct_named("Node").is_some());
    assert!(env.struct_named("Other").is_none());
}

#[test]
fn type_env_resolve_struct_inline() {
    let env = TypeEnvironment::new();
    let st = node_struct();
    let ty = DecompType::Struct(Box::new(st));
    assert_eq!(env.resolve_struct(&ty).map(|s| s.name.as_str()), Some("Node"));
    // For non-struct types returns None
    assert!(env.resolve_struct(&DecompType::Int(IntWidth::I32)).is_none());
}

// ---------------------------------------------------------------------------
// TypedExprEmitter
// ---------------------------------------------------------------------------

fn env_with_node_ptr() -> TypeEnvironment {
    let mut env = TypeEnvironment::new();
    let st = node_struct();
    env.set(
        "node",
        DecompType::Ptr(Box::new(DecompType::Struct(Box::new(st.clone())))),
    );
    env.add_struct(st);
    env
}

#[test]
fn emit_const_small_decimal_large_hex() {
    let env = TypeEnvironment::new();
    let e = TypedExprEmitter::new(&env, 8);
    assert_eq!(e.emit(&Expr::Const(0, IntWidth::I32)).unwrap(), "0");
    assert_eq!(e.emit(&Expr::Const(999, IntWidth::I32)).unwrap(), "999");
    // 1000 is the boundary => hex
    let s = e.emit(&Expr::Const(1000, IntWidth::I32)).unwrap();
    assert!(s.starts_with("0x"), "got {s}");
}

#[test]
fn emit_const_u64_suffix() {
    let env = TypeEnvironment::new();
    let e = TypedExprEmitter::new(&env, 8);
    let s = e.emit(&Expr::Const(0x1_0000, IntWidth::U64)).unwrap();
    assert!(s.ends_with("ULL"), "got {s}");
}

#[test]
fn emit_const_u32_suffix() {
    let env = TypeEnvironment::new();
    let e = TypedExprEmitter::new(&env, 8);
    let s = e.emit(&Expr::Const(0x1234, IntWidth::U32)).unwrap();
    assert!(s.ends_with('U') && !s.ends_with("ULL"), "got {s}");
}

#[test]
fn emit_var_and_unops() {
    let env = TypeEnvironment::new();
    let e = TypedExprEmitter::new(&env, 8);
    assert_eq!(e.emit(&Expr::Var("a".into())).unwrap(), "a");
    let v = Box::new(Expr::Var("a".into()));
    assert_eq!(
        e.emit(&Expr::UnOp(UnOp::Neg, v.clone())).unwrap(),
        "-a"
    );
    assert_eq!(e.emit(&Expr::UnOp(UnOp::Not, v.clone())).unwrap(), "~a");
    assert_eq!(e.emit(&Expr::UnOp(UnOp::LNot, v.clone())).unwrap(), "!a");
    assert_eq!(e.emit(&Expr::UnOp(UnOp::AddrOf, v)).unwrap(), "&a");
}

#[test]
fn emit_cast_unop() {
    let env = TypeEnvironment::new();
    let e = TypedExprEmitter::new(&env, 8);
    let s = e
        .emit(&Expr::UnOp(
            UnOp::Cast(IntWidth::U32),
            Box::new(Expr::Var("a".into())),
        ))
        .unwrap();
    assert_eq!(s, "(uint32_t)a");
}

#[test]
fn emit_field_access_via_ptr_add_known_offset() {
    let env = env_with_node_ptr();
    let e = TypedExprEmitter::new(&env, 8);
    let expr = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("node".into())),
        Box::new(Expr::Const(8, IntWidth::U64)),
    );
    assert_eq!(e.emit(&expr).unwrap(), "node->next");
}

#[test]
fn emit_field_access_zero_offset_first_field() {
    let env = env_with_node_ptr();
    let e = TypedExprEmitter::new(&env, 8);
    let expr = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("node".into())),
        Box::new(Expr::Const(0, IntWidth::U64)),
    );
    // zero offset matches exact (value) OR fallback first
    let s = e.emit(&expr).unwrap();
    assert_eq!(s, "node->value");
}

#[test]
fn emit_array_index_via_scaled_mul() {
    let mut env = TypeEnvironment::new();
    env.set("arr", DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32))));
    let e = TypedExprEmitter::new(&env, 8);
    let expr = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("arr".into())),
        Box::new(Expr::BinOp(
            BinOp::Mul,
            Box::new(Expr::Var("i".into())),
            Box::new(Expr::Const(4, IntWidth::U64)),
        )),
    );
    assert_eq!(e.emit(&expr).unwrap(), "arr[i]");
}

#[test]
fn emit_array_index_via_shl() {
    let mut env = TypeEnvironment::new();
    env.set("arr", DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32))));
    let e = TypedExprEmitter::new(&env, 8);
    // i << 2 => scale 4
    let expr = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("arr".into())),
        Box::new(Expr::BinOp(
            BinOp::Shl,
            Box::new(Expr::Var("i".into())),
            Box::new(Expr::Const(2, IntWidth::U64)),
        )),
    );
    assert_eq!(e.emit(&expr).unwrap(), "arr[i]");
}

#[test]
fn emit_deref_pointer_ok() {
    let mut env = TypeEnvironment::new();
    env.set("p", DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32))));
    let e = TypedExprEmitter::new(&env, 8);
    let s = e
        .emit(&Expr::UnOp(UnOp::Deref, Box::new(Expr::Var("p".into()))))
        .unwrap();
    assert_eq!(s, "*p");
}

#[test]
fn emit_deref_non_pointer_errors() {
    let mut env = TypeEnvironment::new();
    env.set("x", DecompType::Int(IntWidth::I32));
    let e = TypedExprEmitter::new(&env, 8);
    let err = e
        .emit(&Expr::UnOp(UnOp::Deref, Box::new(Expr::Var("x".into()))))
        .unwrap_err();
    match err {
        TypeError::DerefNonPointer(s) => assert!(s.contains("int32_t")),
        other => panic!("expected DerefNonPointer, got {other:?}"),
    }
}

#[test]
fn emit_load_is_deref() {
    let mut env = TypeEnvironment::new();
    env.set("p", DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32))));
    let e = TypedExprEmitter::new(&env, 8);
    let s = e
        .emit(&Expr::Load {
            ptr: Box::new(Expr::Var("p".into())),
            size: 4,
        })
        .unwrap();
    assert_eq!(s, "*p");
}

#[test]
fn emit_field_access_explicit_unknown_struct_fallback() {
    let env = TypeEnvironment::new();
    let e = TypedExprEmitter::new(&env, 8);
    let s = e
        .emit(&Expr::FieldAccess {
            base: Box::new(Expr::Var("x".into())),
            offset: 0x10,
        })
        .unwrap();
    assert!(s.contains("FIELD") && s.contains("0x10"));
}

#[test]
fn emit_field_access_no_field_at_offset_error() {
    let env = env_with_node_ptr();
    let e = TypedExprEmitter::new(&env, 8);
    // node is Ptr<Struct Node>, offset 0x99 not present
    let err = e
        .emit(&Expr::FieldAccess {
            base: Box::new(Expr::Var("node".into())),
            offset: 0x99,
        })
        .unwrap_err();
    match err {
        TypeError::NoFieldAtOffset(n, off) => {
            assert_eq!(n, "Node");
            assert_eq!(off, 0x99);
        }
        other => panic!("got {other:?}"),
    }
}

#[test]
fn emit_call_no_args() {
    let env = TypeEnvironment::new();
    let e = TypedExprEmitter::new(&env, 8);
    let s = e
        .emit(&Expr::Call {
            callee: Box::new(Expr::Var("f".into())),
            args: vec![],
        })
        .unwrap();
    assert_eq!(s, "f()");
}

#[test]
fn emit_ternary_format() {
    let env = TypeEnvironment::new();
    let e = TypedExprEmitter::new(&env, 8);
    let s = e
        .emit(&Expr::Ternary {
            cond: Box::new(Expr::Var("c".into())),
            then_expr: Box::new(Expr::Const(1, IntWidth::I32)),
            else_expr: Box::new(Expr::Const(0, IntWidth::I32)),
        })
        .unwrap();
    assert_eq!(s, "(c ? 1 : 0)");
}

#[test]
fn emit_phi_format() {
    let env = TypeEnvironment::new();
    let e = TypedExprEmitter::new(&env, 8);
    let s = e
        .emit(&Expr::Phi(vec![
            Expr::Var("a".into()),
            Expr::Var("b".into()),
        ]))
        .unwrap();
    assert_eq!(s, "phi(a, b)");
}

#[test]
fn emit_binop_arith() {
    let env = TypeEnvironment::new();
    let e = TypedExprEmitter::new(&env, 8);
    let s = e
        .emit(&Expr::BinOp(
            BinOp::Mul,
            Box::new(Expr::Var("a".into())),
            Box::new(Expr::Var("b".into())),
        ))
        .unwrap();
    assert!(s.contains('a') && s.contains('b'));
}

// ---------------------------------------------------------------------------
// TypeAwareRenamer
// ---------------------------------------------------------------------------

#[test]
fn renamer_counters_per_prefix() {
    let mut r = TypeAwareRenamer::new();
    let a = r.rename(&DecompType::Int(IntWidth::I32));
    let b = r.rename(&DecompType::Int(IntWidth::I32));
    let c = r.rename(&DecompType::Int(IntWidth::U32));
    assert_eq!(a, "i0");
    assert_eq!(b, "i1");
    assert_eq!(c, "ui0");
}

#[test]
fn renamer_struct_ptr_lowercase() {
    let mut r = TypeAwareRenamer::new();
    let st = node_struct();
    let n = r.rename(&DecompType::Ptr(Box::new(DecompType::Struct(Box::new(st)))));
    assert_eq!(n, "p_node_0");
}

#[test]
fn renamer_ptr_to_u8_is_sz() {
    let mut r = TypeAwareRenamer::new();
    let n = r.rename(&DecompType::Ptr(Box::new(DecompType::Int(IntWidth::U8))));
    assert!(n.starts_with("sz_"));
}

#[test]
fn renamer_floats() {
    let mut r = TypeAwareRenamer::new();
    assert!(r.rename(&DecompType::Float32).starts_with('f'));
    assert!(r.rename(&DecompType::Float64).starts_with('d'));
}

#[test]
fn renamer_rename_with_hint_keeps_arg() {
    let mut r = TypeAwareRenamer::new();
    let n = r.rename_with_hint("arg1", &DecompType::Int(IntWidth::I32));
    assert_eq!(n, "arg1");
    let n = r.rename_with_hint("param2", &DecompType::Int(IntWidth::I32));
    assert_eq!(n, "param2");
    // Non-arg/param hint => use type rename
    let n = r.rename_with_hint("foo", &DecompType::Int(IntWidth::I32));
    assert_eq!(n, "i0");
}

#[test]
fn renamer_reset_restarts() {
    let mut r = TypeAwareRenamer::new();
    let a = r.rename(&DecompType::Int(IntWidth::I32));
    r.reset();
    let b = r.rename(&DecompType::Int(IntWidth::I32));
    assert_eq!(a, b);
}

#[test]
fn renamer_variables_var_to_v() {
    let mut r = TypeAwareRenamer::new();
    let env = TypeEnvironment::new();
    let code = "int var_1 = 0; var_1 = var_1 + 1;";
    let out = r.rename_variables(code, &env);
    assert!(out.contains("v_1"), "got {out}");
    assert!(!out.contains("var_1"), "got {out}");
}

#[test]
fn renamer_variables_word_boundary() {
    let mut r = TypeAwareRenamer::new();
    let env = TypeEnvironment::new();
    // var_1 and var_10 share prefix; both should be substituted distinctly.
    let code = "x = var_1 + var_10;";
    let out = r.rename_variables(code, &env);
    assert!(out.contains("v_1"));
    assert!(out.contains("v_10"));
    // ensure no "v_10" got mangled to v_1 + extras
}

#[test]
fn renamer_variables_malloc_becomes_ptr() {
    let mut r = TypeAwareRenamer::new();
    let env = TypeEnvironment::new();
    let code = "int *var_1 = malloc(16); var_1[0] = 0;";
    let out = r.rename_variables(code, &env);
    assert!(out.contains("ptr_0"), "got {out}");
}

#[test]
fn renamer_variables_loop_counter() {
    let mut r = TypeAwareRenamer::new();
    let env = TypeEnvironment::new();
    let code = "for (var_1 = 0; var_1 < 10; var_1++) {}";
    let out = r.rename_variables(code, &env);
    // counter var should become i
    assert!(out.contains('i'));
}

#[test]
fn renamer_variables_typed_env_overrides() {
    let mut r = TypeAwareRenamer::new();
    let mut env = TypeEnvironment::new();
    env.set("var_1", DecompType::Bool);
    let code = "if (var_1) {}";
    let out = r.rename_variables(code, &env);
    assert!(out.contains("b_0"), "got {out}");
}

// ---------------------------------------------------------------------------
// TypeQualifier
// ---------------------------------------------------------------------------

#[test]
fn type_qualifier_default_none() {
    let q = TypeQualifier::default();
    assert!(!q.is_const());
    assert!(!q.is_volatile());
    assert!(!q.is_restrict());
    assert_eq!(q.qualifier_string(), "");
}

#[test]
fn type_qualifier_all_three() {
    let q = TypeQualifier::CONST.with_volatile().with_restrict();
    assert!(q.is_const() && q.is_volatile() && q.is_restrict());
    let s = q.qualifier_string();
    assert!(s.contains("const") && s.contains("volatile") && s.contains("restrict"));
}

#[test]
fn type_qualifier_display() {
    let q = TypeQualifier::CONST;
    assert_eq!(format!("{q}"), "const");
}

#[test]
fn qualified_type_no_qualifier() {
    let qt = QualifiedType::new(DecompType::Int(IntWidth::I32));
    assert_eq!(qt.c_name(), "int32_t");
}

#[test]
fn qualified_type_const_volatile() {
    let qt = QualifiedType::new(DecompType::Int(IntWidth::I32))
        .with_qualifiers(TypeQualifier::CONST.with_volatile());
    let s = qt.c_name();
    assert!(s.contains("const") && s.contains("volatile") && s.contains("int32_t"));
}

// ---------------------------------------------------------------------------
// UnionType
// ---------------------------------------------------------------------------

#[test]
fn union_size_is_max_member() {
    let u = UnionType::new(
        "U",
        vec![
            StructField::new(0, "a", DecompType::Int(IntWidth::I8)),
            StructField::new(0, "b", DecompType::Int(IntWidth::I64)),
            StructField::new(0, "c", DecompType::Int(IntWidth::I32)),
        ],
    );
    assert_eq!(u.total_size, 8);
}

#[test]
fn union_size_empty_is_zero() {
    let u = UnionType::new("E", vec![]);
    assert_eq!(u.total_size, 0);
}

#[test]
fn union_c_name() {
    let u = UnionType::new("Foo", vec![]);
    assert_eq!(u.c_name(), "union Foo");
}

#[test]
fn union_member_named_works() {
    let u = UnionType::new(
        "U",
        vec![StructField::new(0, "x", DecompType::Int(IntWidth::I32))],
    );
    assert_eq!(u.member_named("x").unwrap().name, "x");
    assert!(u.member_named("zzz").is_none());
}

// ---------------------------------------------------------------------------
// FunctionType / CallingConvention
// ---------------------------------------------------------------------------

#[test]
fn function_type_empty_prototype() {
    let f = FunctionType::new("f", DecompType::Void);
    let p = f.c_prototype();
    assert!(p.contains("void") && p.contains('f') && p.contains("()"));
    assert_eq!(f.arity(), 0);
}

#[test]
fn function_type_variadic_renders_dots() {
    let mut f = FunctionType::new("printf", DecompType::Int(IntWidth::I32));
    f.add_param("fmt", DecompType::CStr);
    f.is_variadic = true;
    assert!(f.c_prototype().contains("..."));
    assert_eq!(f.arity(), 1);
}

#[test]
fn calling_convention_all_strings() {
    assert_eq!(CallingConvention::CDecl.as_str(), "__cdecl");
    assert_eq!(CallingConvention::StdCall.as_str(), "__stdcall");
    assert_eq!(CallingConvention::FastCall.as_str(), "__fastcall");
    assert_eq!(CallingConvention::ThisCall.as_str(), "__thiscall");
    assert!(CallingConvention::SysV64.as_str().contains("sysv64"));
    assert!(CallingConvention::MsX64.as_str().contains("ms_x64"));
    assert!(CallingConvention::Custom.as_str().contains("custom"));
}

#[test]
fn calling_convention_default_is_cdecl() {
    assert_eq!(CallingConvention::default(), CallingConvention::CDecl);
}

// ---------------------------------------------------------------------------
// TypeLayout
// ---------------------------------------------------------------------------

#[test]
fn type_layout_padded_size_align_zero_returns_size() {
    let layout = TypeLayout {
        size: 7,
        alignment: 0,
        field_offsets: vec![],
    };
    assert_eq!(layout.padded_size(), 7);
}

#[test]
fn type_layout_padded_size_align_4() {
    let layout = TypeLayout {
        size: 5,
        alignment: 4,
        field_offsets: vec![],
    };
    assert_eq!(layout.padded_size(), 8);
}

#[test]
fn type_layout_padded_size_no_padding_needed() {
    let layout = TypeLayout {
        size: 8,
        alignment: 4,
        field_offsets: vec![],
    };
    assert_eq!(layout.padded_size(), 8);
}

#[test]
fn type_layout_for_struct_records_offsets() {
    let st = node_struct();
    let layout = TypeLayout::for_struct(&st);
    assert_eq!(layout.field_offsets.len(), 2);
    assert_eq!(layout.field_offsets[0], ("value".to_string(), 0));
    assert_eq!(layout.field_offsets[1], ("next".to_string(), 8));
    assert_eq!(layout.size, 16);
    assert!(layout.alignment >= 1 && layout.alignment <= 8);
}

// ---------------------------------------------------------------------------
// TypeUnifier
// ---------------------------------------------------------------------------

#[test]
fn unifier_transitive_classes() {
    let mut u = TypeUnifier::new();
    u.add_constraint(&TypeConstraint::new("a", "b", ""));
    u.add_constraint(&TypeConstraint::new("b", "c", ""));
    u.add_constraint(&TypeConstraint::new("d", "e", ""));
    assert_eq!(u.canonical("a"), u.canonical("c"));
    assert_ne!(u.canonical("a"), u.canonical("d"));
    let cls = u.equivalence_classes();
    // two classes
    assert_eq!(cls.len(), 2);
    assert_eq!(u.constraint_count(), 3);
}

#[test]
fn unifier_singleton_find() {
    let mut u = TypeUnifier::new();
    // canonical of a fresh var = itself
    assert_eq!(u.canonical("solo"), "solo");
}

// ---------------------------------------------------------------------------
// TypeInference
// ---------------------------------------------------------------------------

#[test]
fn type_inference_pointer_deref() {
    let mut inf = TypeInference::new();
    inf.set_type("p", DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32))));
    inf.infer_pointer_deref("p", "v");
    assert_eq!(inf.get_type("v"), Some(&DecompType::Int(IntWidth::I32)));
}

#[test]
fn type_inference_deref_non_pointer_noop() {
    let mut inf = TypeInference::new();
    inf.set_type("x", DecompType::Int(IntWidth::I32));
    inf.infer_pointer_deref("x", "v");
    // v should not get a type since x is not a pointer
    assert!(inf.get_type("v").is_none());
}

#[test]
fn type_inference_count_and_assignment() {
    let mut inf = TypeInference::new();
    inf.infer_assignment("x", DecompType::Bool);
    inf.infer_assignment("y", DecompType::Bool);
    assert_eq!(inf.type_count(), 2);
}

#[test]
fn type_inference_add_constraint_records() {
    let mut inf = TypeInference::new();
    // NB: `TypeInference::add_constraint` takes the constraint BY VALUE, unlike
    // the same-named method on `TypeUnifier`, which borrows it.
    inf.add_constraint(TypeConstraint::new("a", "b", ""));
    // No direct accessor for constraints list, but no panic and types remain empty.
    assert_eq!(inf.type_count(), 0);
}

// ---------------------------------------------------------------------------
// TypePropagator
// ---------------------------------------------------------------------------

#[test]
fn propagator_through_binop_only_when_dst_unknown() {
    let mut tp = TypePropagator::new();
    tp.seed("lhs", DecompType::Int(IntWidth::I32));
    tp.propagate_through_binop("res", "lhs", "rhs");
    assert_eq!(tp.get("res"), Some(&DecompType::Int(IntWidth::I32)));
    // calling again should not increment count (already known)
    let before = tp.propagation_count();
    tp.propagate_through_binop("res", "lhs", "rhs");
    assert_eq!(tp.propagation_count(), before);
}

#[test]
fn propagator_assign_repeats_count() {
    let mut tp = TypePropagator::new();
    tp.seed("a", DecompType::Int(IntWidth::I32));
    tp.propagate_through_assign("b", "a");
    tp.propagate_through_assign("c", "a");
    assert_eq!(tp.propagation_count(), 2);
}

// ---------------------------------------------------------------------------
// TypeRecovery
// ---------------------------------------------------------------------------

#[test]
fn type_recovery_access_size_unknown_for_3() {
    let mut tr = TypeRecovery::new();
    tr.infer_from_access_size(0x100, 3);
    assert_eq!(tr.get(0x100), Some(&DecompType::Unknown));
}

#[test]
fn type_recovery_does_not_overwrite_existing() {
    let mut tr = TypeRecovery::new();
    tr.record(0x100, DecompType::Int(IntWidth::I64));
    tr.infer_from_access_size(0x100, 1);
    // entry should remain i64 because of `or_insert`
    assert_eq!(tr.get(0x100), Some(&DecompType::Int(IntWidth::I64)));
}

#[test]
fn type_recovery_count_after_record() {
    let mut tr = TypeRecovery::new();
    for a in 0..5u64 {
        tr.record(a, DecompType::Int(IntWidth::I8));
    }
    assert_eq!(tr.count(), 5);
}

// ---------------------------------------------------------------------------
// CTypeEmitter
// ---------------------------------------------------------------------------

#[test]
fn ctype_emitter_struct_contains_size_comment() {
    let st = node_struct();
    let out = CTypeEmitter::new().emit_struct(&st);
    assert!(out.contains("struct Node"));
    assert!(out.contains("size = 0x10"));
    assert!(out.contains("offset 0x0"));
    assert!(out.contains("offset 0x8"));
}

#[test]
fn ctype_emitter_indent() {
    let st = node_struct();
    let out = CTypeEmitter::with_indent(2).emit_struct(&st);
    // 2 levels of 4 spaces
    assert!(out.starts_with("        struct"));
}

#[test]
fn ctype_emitter_function() {
    let f = FunctionType::new("foo", DecompType::Void);
    let out = CTypeEmitter::new().emit_function(&f);
    assert!(out.ends_with(';'));
    assert!(out.contains("foo"));
}

// ---------------------------------------------------------------------------
// TypeDatabase / StandardLibTypes
// ---------------------------------------------------------------------------

#[test]
fn typedb_counts_increment_correctly() {
    let mut db = TypeDatabase::new();
    db.add_struct(node_struct());
    db.add_union(UnionType::new("U", vec![]));
    db.add_function(FunctionType::new("f", DecompType::Void));
    db.add_typedef("Alias", DecompType::Int(IntWidth::I32));
    assert_eq!(db.struct_count(), 1);
    assert_eq!(db.union_count(), 1);
    assert_eq!(db.function_count(), 1);
    assert_eq!(db.typedef_count(), 1);
    assert!(db.get_struct("Node").is_some());
    assert!(db.get_union("U").is_some());
    assert!(db.get_function("f").is_some());
    assert_eq!(
        db.resolve_typedef("Alias"),
        Some(&DecompType::Int(IntWidth::I32))
    );
}

#[test]
fn typedb_windows_types_full() {
    let mut db = TypeDatabase::new();
    db.load_windows_types();
    for ty in [
        "DWORD", "WORD", "BYTE", "BOOL", "HANDLE", "LPVOID", "LPCSTR", "LPSTR",
        "HMODULE", "HINSTANCE", "HWND", "UINT", "INT", "LONG", "ULONG", "LONGLONG",
        "ULONGLONG", "ULONG_PTR", "SIZE_T", "PVOID",
    ] {
        assert!(db.resolve_typedef(ty).is_some(), "missing {ty}");
    }
    assert!(db.get_struct("POINT").is_some());
    assert!(db.get_struct("RECT").is_some());
}

#[test]
fn typedb_emit_all_structs_includes_each() {
    let mut db = TypeDatabase::new();
    db.add_struct(StructType::new("A", vec![], 0));
    db.add_struct(StructType::new("B", vec![], 0));
    let s = db.emit_all_structs();
    assert!(s.contains("struct A"));
    assert!(s.contains("struct B"));
}

#[test]
fn stdlib_db_has_expected_functions() {
    let db = StandardLibTypes::stdlib_db();
    for f in ["malloc", "free", "memcpy", "memset", "strlen", "printf"] {
        assert!(db.get_function(f).is_some(), "missing {f}");
    }
    assert!(db.get_function("printf").unwrap().is_variadic);
}

// ---------------------------------------------------------------------------
// are_compatible / is_implicitly_convertible
// ---------------------------------------------------------------------------

#[test]
fn compat_unknown_with_anything() {
    assert!(are_compatible(&DecompType::Unknown, &DecompType::Bool));
    assert!(are_compatible(&DecompType::Bool, &DecompType::Unknown));
    assert!(are_compatible(
        &DecompType::Ptr(Box::new(DecompType::Void)),
        &DecompType::Unknown
    ));
}

#[test]
fn compat_int_int() {
    assert!(are_compatible(
        &DecompType::Int(IntWidth::I8),
        &DecompType::Int(IntWidth::U64)
    ));
}

#[test]
fn compat_bool_int_incompatible() {
    assert!(!are_compatible(
        &DecompType::Bool,
        &DecompType::Int(IntWidth::I32)
    ));
}

#[test]
fn implicit_convert_widening() {
    assert!(is_implicitly_convertible(
        &DecompType::Int(IntWidth::I8),
        &DecompType::Int(IntWidth::I32)
    ));
}

#[test]
fn implicit_convert_float_to_double() {
    assert!(is_implicitly_convertible(
        &DecompType::Float32,
        &DecompType::Float64
    ));
    // Reverse not in the special-case
    assert!(!is_implicitly_convertible(
        &DecompType::Float64,
        &DecompType::Float32
    ));
}

// ---------------------------------------------------------------------------
// PointerAnalysis
// ---------------------------------------------------------------------------

#[test]
fn pa_points_to_multi() {
    let mut pa = PointerAnalysis::new();
    pa.record_points_to("p", "a");
    pa.record_points_to("p", "b");
    let t = pa.points_to_targets("p");
    assert_eq!(t.len(), 2);
    assert!(pa.is_definitely_not_null("p"));
    assert!(!pa.is_definitely_not_null("q"));
}

#[test]
fn pa_may_alias_symmetric_lookup() {
    let mut pa = PointerAnalysis::new();
    pa.record_may_alias("p", "q");
    assert!(pa.may_alias_with("p").contains(&"q"));
    assert!(pa.may_alias_with("q").contains(&"p"));
    assert!(pa.may_alias_with("r").is_empty());
}

#[test]
fn pa_empty_targets() {
    let pa = PointerAnalysis::new();
    assert!(pa.points_to_targets("nope").is_empty());
}

// ---------------------------------------------------------------------------
// LatticeType
// ---------------------------------------------------------------------------

#[test]
fn lattice_join_top_id() {
    let i = LatticeType::Integer { width: Some(IntWidth::I32) };
    assert_eq!(LatticeType::Top.join(&i), i);
    assert_eq!(i.join(&LatticeType::Top), i);
}

#[test]
fn lattice_join_bottom_absorbs() {
    let i = LatticeType::Integer { width: Some(IntWidth::I32) };
    assert!(LatticeType::Bottom.join(&i).is_conflict());
    assert!(i.join(&LatticeType::Bottom).is_conflict());
}

#[test]
fn lattice_join_int_widens() {
    let a = LatticeType::Integer { width: Some(IntWidth::I8) };
    let b = LatticeType::Integer { width: Some(IntWidth::U32) };
    match a.join(&b) {
        LatticeType::Integer { width: Some(w) } => {
            // Widest of 8 vs 32 = 32, signed wins
            assert_eq!(w.bits(), 32);
            assert!(w.is_signed());
        }
        other => panic!("got {other:?}"),
    }
}

#[test]
fn lattice_join_float_widens_to_64() {
    assert_eq!(
        LatticeType::Float32.join(&LatticeType::Float64),
        LatticeType::Float64
    );
    assert_eq!(
        LatticeType::Float64.join(&LatticeType::Float32),
        LatticeType::Float64
    );
}

#[test]
fn lattice_join_int_with_float_conflicts() {
    let i = LatticeType::Integer { width: Some(IntWidth::I32) };
    assert!(i.join(&LatticeType::Float32).is_conflict());
}

#[test]
fn lattice_to_decomp_roundtrip() {
    let cases = vec![
        DecompType::Bool,
        DecompType::Float32,
        DecompType::Float64,
        DecompType::Int(IntWidth::I32),
        DecompType::Ptr(Box::new(DecompType::Int(IntWidth::U8))),
    ];
    for ty in cases {
        let l = LatticeType::from_decomp(&ty);
        assert_eq!(l.to_decomp(), ty);
    }
}

#[test]
fn lattice_from_unknown_is_top() {
    assert_eq!(
        LatticeType::from_decomp(&DecompType::Unknown),
        LatticeType::Top
    );
}

#[test]
fn lattice_from_cstr_is_ptr_i8() {
    let l = LatticeType::from_decomp(&DecompType::CStr);
    match l {
        LatticeType::Pointer(inner) => match *inner {
            LatticeType::Integer { width: Some(w) } => assert_eq!(w, IntWidth::I8),
            other => panic!("got {other:?}"),
        },
        other => panic!("got {other:?}"),
    }
}

#[test]
fn lattice_top_to_decomp_is_unknown() {
    assert_eq!(LatticeType::Top.to_decomp(), DecompType::Unknown);
    assert_eq!(LatticeType::Bottom.to_decomp(), DecompType::Unknown);
}

// ---------------------------------------------------------------------------
// AccessWidthSizer
// ---------------------------------------------------------------------------

#[test]
fn access_width_widest_wins() {
    let mut s = AccessWidthSizer::new();
    s.observe("v", 1);
    s.observe("v", 4);
    s.observe("v", 2);
    let inf = s.infer("v").unwrap();
    assert_eq!(inf, DecompType::Int(IntWidth::U32));
    assert_eq!(s.count(), 1);
    assert_eq!(s.vars(), vec!["v".to_string()]);
}

#[test]
fn access_width_signed_flag_applies() {
    let mut s = AccessWidthSizer::new();
    s.observe("v", 4);
    s.mark_signed("v");
    assert_eq!(s.infer("v"), Some(DecompType::Int(IntWidth::I32)));
}

#[test]
fn access_width_unknown_var() {
    let s = AccessWidthSizer::new();
    assert!(s.infer("missing").is_none());
}

// ---------------------------------------------------------------------------
// PrimitiveInference
// ---------------------------------------------------------------------------

#[test]
fn prim_inf_const_signed_when_negative() {
    let p = PrimitiveInference::new();
    let l = p.infer(&Expr::Const(-1, IntWidth::U32));
    match l {
        LatticeType::Integer { width: Some(w) } => assert!(w.is_signed()),
        other => panic!("got {other:?}"),
    }
}

#[test]
fn prim_inf_comparison_is_bool() {
    let p = PrimitiveInference::new();
    let e = Expr::BinOp(
        BinOp::Eq,
        Box::new(Expr::Var("a".into())),
        Box::new(Expr::Var("b".into())),
    );
    assert_eq!(p.infer(&e), LatticeType::Bool);
}

#[test]
fn prim_inf_sar_implies_signed() {
    let p = PrimitiveInference::new();
    let e = Expr::BinOp(
        BinOp::Sar,
        Box::new(Expr::Const(100, IntWidth::U32)),
        Box::new(Expr::Const(1, IntWidth::U32)),
    );
    match p.infer(&e) {
        LatticeType::Integer { width: Some(w) } => assert!(w.is_signed()),
        other => panic!("got {other:?}"),
    }
}

#[test]
fn prim_inf_addrof_makes_pointer() {
    let p = PrimitiveInference::new();
    let e = Expr::UnOp(UnOp::AddrOf, Box::new(Expr::Const(5, IntWidth::I32)));
    assert!(matches!(p.infer(&e), LatticeType::Pointer(_)));
}

#[test]
fn prim_inf_var_is_top() {
    let p = PrimitiveInference::new();
    assert_eq!(p.infer(&Expr::Var("x".into())), LatticeType::Top);
}

#[test]
fn prim_inf_cast_uses_width() {
    let p = PrimitiveInference::new();
    let e = Expr::UnOp(UnOp::Cast(IntWidth::U16), Box::new(Expr::Var("a".into())));
    assert_eq!(
        p.infer(&e),
        LatticeType::Integer { width: Some(IntWidth::U16) }
    );
}

// ---------------------------------------------------------------------------
// PointerDetector
// ---------------------------------------------------------------------------

#[test]
fn pointer_detector_finds_deref_base() {
    let mut d = PointerDetector::new();
    d.scan(&Expr::UnOp(UnOp::Deref, Box::new(Expr::Var("p".into()))));
    assert!(d.is_pointer("p"));
    let ps = d.pointers();
    assert_eq!(ps, vec!["p".to_string()]);
}

#[test]
fn pointer_detector_finds_add_base() {
    let mut d = PointerDetector::new();
    // *(p + 8)
    let e = Expr::Load {
        ptr: Box::new(Expr::BinOp(
            BinOp::Add,
            Box::new(Expr::Var("p".into())),
            Box::new(Expr::Const(8, IntWidth::U64)),
        )),
        size: 8,
    };
    d.scan(&e);
    assert!(d.is_pointer("p"));
}

#[test]
fn pointer_detector_sorted_unique() {
    let mut d = PointerDetector::new();
    d.scan(&Expr::UnOp(UnOp::Deref, Box::new(Expr::Var("z".into()))));
    d.scan(&Expr::UnOp(UnOp::Deref, Box::new(Expr::Var("a".into()))));
    d.scan(&Expr::UnOp(UnOp::Deref, Box::new(Expr::Var("m".into()))));
    let p = d.pointers();
    assert_eq!(p, vec!["a".to_string(), "m".to_string(), "z".to_string()]);
}

#[test]
fn pointer_detector_no_false_positive_for_const() {
    let mut d = PointerDetector::new();
    d.scan(&Expr::Const(42, IntWidth::I32));
    assert!(d.pointers().is_empty());
}

// ---------------------------------------------------------------------------
// StructClusterer
// ---------------------------------------------------------------------------

#[test]
fn clusterer_observe_and_offsets() {
    let mut c = StructClusterer::new();
    c.observe("p", 0, 4);
    c.observe("p", 4, 4);
    c.observe("p", 8, 8);
    let mut offs = c.offsets("p");
    offs.sort_unstable();
    assert_eq!(offs, vec![0, 4, 8]);
    assert_eq!(c.base_count(), 1);
}

#[test]
fn clusterer_build_struct_merges_widths() {
    let mut c = StructClusterer::new();
    c.observe("p", 0, 1);
    c.observe("p", 0, 4); // widest at 0 wins
    c.observe("p", 8, 8);
    let st = c.build_struct("p", "Inferred").unwrap();
    assert_eq!(st.name, "Inferred");
    assert_eq!(st.fields.len(), 2);
    // first field at offset 0: width 4
    let f0 = st.fields.iter().find(|f| f.offset == 0).unwrap();
    assert_eq!(f0.ty, DecompType::Int(IntWidth::U32));
    // total covers 8+8 = 16
    assert_eq!(st.total_size, 16);
}

#[test]
fn clusterer_build_struct_unknown_base() {
    let c = StructClusterer::new();
    assert!(c.build_struct("nope", "X").is_none());
}

#[test]
fn clusterer_scan_load_records() {
    let mut c = StructClusterer::new();
    // load(p + 16, size=4)
    c.scan(&Expr::Load {
        ptr: Box::new(Expr::BinOp(
            BinOp::Add,
            Box::new(Expr::Var("p".into())),
            Box::new(Expr::Const(16, IntWidth::U64)),
        )),
        size: 4,
    });
    let offs = c.offsets("p");
    assert!(offs.contains(&16));
}

// ---------------------------------------------------------------------------
// StructField::new round-trip
// ---------------------------------------------------------------------------

#[test]
fn struct_field_new_stores_values() {
    let f = StructField::new(0x20, "myfield", DecompType::Float64);
    assert_eq!(f.offset, 0x20);
    assert_eq!(f.name, "myfield");
    assert_eq!(f.ty, DecompType::Float64);
}

// ---------------------------------------------------------------------------
// EnumVariant equality / hashing
// ---------------------------------------------------------------------------

#[test]
fn enum_variant_equality() {
    let a = EnumVariant {
        name: "X".into(),
        value: 1,
    };
    let b = EnumVariant {
        name: "X".into(),
        value: 1,
    };
    assert_eq!(a, b);
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(a);
    assert!(s.contains(&b));
}
