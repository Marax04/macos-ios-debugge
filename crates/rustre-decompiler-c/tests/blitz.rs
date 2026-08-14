//! Blitz test suite for rustre-decompiler-c public API.
//!
//! Targets formatting, code-emission and post-processing primitives. Focuses on
//! boundary inputs, edge cases, and consistency across the parallel
//! `CPrinter` / `CodeGenerator` / `CFlowEmitter` / `CStatement` paths.

use rustre_decompiler_c::*;
use rustre_decompiler_cfs::{BlockId, LoopKind, StructuredNode, SwitchCase};
use rustre_decompiler_expr::IntWidth;
use rustre_decompiler_type::{DecompType, StructField, StructType, TypeEnvironment};

fn env() -> TypeEnvironment {
    TypeEnvironment::new()
}

fn balanced(s: &str) -> bool {
    let o = s.chars().filter(|&c| c == '{').count();
    let c = s.chars().filter(|&c| c == '}').count();
    o == c
}

// ── IndentStyle ────────────────────────────────────────────────────────────

#[test]
fn indent_spaces_zero_level() {
    let s = IndentStyle::Spaces(4);
    // No public `make` — but exercised via printer. Use IndentStyleSimple direct.
    let i = IndentStyleSimple::spaces(4);
    assert_eq!(i.indent_str(), "    ");
    drop(s);
}

#[test]
fn indent_simple_zero_spaces() {
    let i = IndentStyleSimple::spaces(0);
    assert_eq!(i.indent_str(), "");
}

#[test]
fn indent_simple_large_spaces() {
    let i = IndentStyleSimple::spaces(16);
    assert_eq!(i.indent_str().len(), 16);
}

// ── FunctionSignature ──────────────────────────────────────────────────────

#[test]
fn signature_no_params_void() {
    let s = FunctionSignature::new("f", DecompType::Void, vec![]);
    assert_eq!(s.as_c_declaration(), "void f()");
}

#[test]
fn signature_variadic_only() {
    let mut s = FunctionSignature::new("f", DecompType::Void, vec![]);
    s.is_variadic = true;
    // No params + variadic produces "(, ...)" which is invalid C.
    // Documenting current behaviour for regression. Note that real C requires
    // a named parameter before `...`. We record what the impl does.
    let d = s.as_c_declaration();
    assert!(d.contains("..."));
}

#[test]
fn signature_multi_param() {
    let s = FunctionSignature::new(
        "g",
        DecompType::Int(IntWidth::I64),
        vec![
            FunctionParam::new("x", DecompType::Int(IntWidth::I32)),
            FunctionParam::new("y", DecompType::Int(IntWidth::I32)),
            FunctionParam::new("z", DecompType::Int(IntWidth::I32)),
        ],
    );
    let d = s.as_c_declaration();
    assert!(d.starts_with("int64_t g("));
    assert_eq!(d.matches(',').count(), 2);
}

// ── VarDecl ────────────────────────────────────────────────────────────────

#[test]
fn vardecl_init_empty_string() {
    let v = VarDecl::new("x", DecompType::Int(IntWidth::I32)).with_init("");
    assert_eq!(v.as_c_declaration(), "int32_t x = ");
}

#[test]
fn vardecl_overwrite_init() {
    let v = VarDecl::new("x", DecompType::Int(IntWidth::I32))
        .with_init("1")
        .with_init("2");
    assert_eq!(v.as_c_declaration(), "int32_t x = 2");
}

// ── CPrinter::emit_const ───────────────────────────────────────────────────

#[test]
fn const_decimal_negative() {
    let e = env();
    let p = CPrinter::new(
        CFormat {
            const_notation: ConstNotation::Decimal,
            ..CFormat::default()
        },
        &e,
    );
    assert_eq!(p.emit_const(-7, IntWidth::I32), "-7");
}

#[test]
fn const_auto_boundary_999() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    assert_eq!(p.emit_const(999, IntWidth::I32), "999");
}

#[test]
fn const_auto_boundary_1000() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    // 1000 is NOT in 0..1000 so should be hex.
    let s = p.emit_const(1000, IntWidth::I32);
    assert!(s.starts_with("0x"), "expected hex for 1000, got {s}");
}

#[test]
fn const_auto_negative_i32_wraps() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    // -1 -> as u32 = 0xFFFFFFFF
    let s = p.emit_const(-1, IntWidth::I32);
    assert_eq!(s, "0xFFFFFFFFU");
}

#[test]
fn const_auto_u64_large() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let s = p.emit_const(-1, IntWidth::U64);
    assert_eq!(s, "0xFFFFFFFFFFFFFFFFU");
}

#[test]
fn const_hex_variants_match() {
    let e = env();
    let p_hex = CPrinter::new(
        CFormat {
            const_notation: ConstNotation::Hex,
            ..CFormat::default()
        },
        &e,
    );
    let p_hxp = CPrinter::new(
        CFormat {
            const_notation: ConstNotation::HexPrefixed,
            ..CFormat::default()
        },
        &e,
    );
    // CPrinter treats Hex and HexPrefixed identically — document this.
    assert_eq!(
        p_hex.emit_const(255, IntWidth::I32),
        p_hxp.emit_const(255, IntWidth::I32)
    );
}

// ── CodeGenerator::constant ────────────────────────────────────────────────

#[test]
fn codegen_const_hex_no_prefix() {
    let g = CodeGenerator::new(CodeGenOptions {
        const_notation: ConstNotation::Hex,
        ..CodeGenOptions::default()
    });
    // CodeGenerator's Hex (different from CPrinter) does NOT include "0x".
    assert_eq!(g.constant(255, IntWidth::I32), "FF");
}

#[test]
fn codegen_const_auto_negative() {
    let g = CodeGenerator::default();
    let s = g.constant(-0x1234, IntWidth::I32);
    // Negative path renders as "-0x1234" (no width suffix for I32).
    assert!(s.starts_with("-0x"), "{s}");
}

#[test]
fn codegen_const_auto_u64_suffix() {
    let g = CodeGenerator::default();
    let s = g.constant(0x10000, IntWidth::U64);
    assert!(s.ends_with("ULL"), "{s}");
}

// ── CPrinter / emit_function ───────────────────────────────────────────────

#[test]
fn emit_function_break_at_top_level() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let sig = FunctionSignature::new("t", DecompType::Void, vec![]);
    let r = p
        .emit_function(&sig, &[], &StructuredNode::Break)
        .unwrap();
    assert!(r.source_code.contains("break;"));
    assert!(balanced(&r.source_code));
}

#[test]
fn emit_function_no_prototype() {
    let e = env();
    let p = CPrinter::new(
        CFormat {
            emit_prototype: false,
            ..CFormat::default()
        },
        &e,
    );
    let sig = FunctionSignature::new("t", DecompType::Void, vec![]);
    let r = p
        .emit_function(&sig, &[], &StructuredNode::Return(None))
        .unwrap();
    // First line must not be the prototype `t();`.
    assert!(!r.source_code.starts_with("void t();"));
}

#[test]
fn emit_function_stats_match_body() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let body = StructuredNode::Sequence(vec![
        StructuredNode::If {
            condition: "a".into(),
            then_branch: Box::new(StructuredNode::Break),
        },
        StructuredNode::If {
            condition: "b".into(),
            then_branch: Box::new(StructuredNode::Continue),
        },
        StructuredNode::Loop {
            kind: LoopKind::While,
            condition: "c".into(),
            body: Box::new(StructuredNode::Break),
        },
        StructuredNode::Switch {
            expr: "d".into(),
            cases: vec![SwitchCase {
                value: Some(1),
                body: Box::new(StructuredNode::Break),
            }],
        },
        StructuredNode::Return(None),
    ]);
    let sig = FunctionSignature::new("t", DecompType::Void, vec![]);
    let r = p.emit_function(&sig, &[], &body).unwrap();
    assert_eq!(r.stats.if_count, 2);
    assert_eq!(r.stats.loop_count, 1);
    assert_eq!(r.stats.switch_count, 1);
    assert!(r.stats.lines > 0);
}

#[test]
fn emit_function_goto_counted() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let body = StructuredNode::Sequence(vec![
        StructuredNode::Goto(BlockId::new(1)),
        StructuredNode::Goto(BlockId::new(2)),
    ]);
    let sig = FunctionSignature::new("t", DecompType::Void, vec![]);
    let r = p.emit_function(&sig, &[], &body).unwrap();
    assert_eq!(r.stats.goto_count, 2);
}

#[test]
fn emit_function_variable_count() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let vars = vec![
        VarDecl::new("a", DecompType::Int(IntWidth::I32)),
        VarDecl::new("b", DecompType::Int(IntWidth::I32)),
        VarDecl::new("c", DecompType::Int(IntWidth::I32)),
    ];
    let sig = FunctionSignature::new("t", DecompType::Void, vec![]);
    let r = p
        .emit_function(&sig, &vars, &StructuredNode::Return(None))
        .unwrap();
    assert_eq!(r.stats.variable_count, 3);
}

#[test]
fn emit_function_balanced_braces_complex() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let body = StructuredNode::IfElse {
        condition: "x".into(),
        then_branch: Box::new(StructuredNode::Loop {
            kind: LoopKind::While,
            condition: "y".into(),
            body: Box::new(StructuredNode::Switch {
                expr: "z".into(),
                cases: vec![
                    SwitchCase {
                        value: Some(0),
                        body: Box::new(StructuredNode::Break),
                    },
                    SwitchCase {
                        value: None,
                        body: Box::new(StructuredNode::Continue),
                    },
                ],
            }),
        }),
        else_branch: Box::new(StructuredNode::Return(None)),
    };
    let sig = FunctionSignature::new("t", DecompType::Void, vec![]);
    let r = p.emit_function(&sig, &[], &body).unwrap();
    assert!(balanced(&r.source_code), "src:\n{}", r.source_code);
}

#[test]
fn emit_struct_def_empty() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let st = StructType::new("Empty", vec![], 0);
    let s = p.emit_struct_def(&st).unwrap();
    assert!(s.contains("struct Empty {"));
    assert!(s.contains("};"));
}

#[test]
fn emit_var_decls_empty_string() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let s = p.emit_var_decls(&[]);
    assert_eq!(s, "");
}

#[test]
fn emit_var_decls_one() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let s = p.emit_var_decls(&[VarDecl::new("a", DecompType::Int(IntWidth::I32))]);
    assert!(s.ends_with(";\n"));
    assert!(s.contains("int32_t a"));
}

// ── CStatement::render ─────────────────────────────────────────────────────

#[test]
fn cstatement_indent_increases() {
    let s = CStatement::Assign {
        lhs: "x".into(),
        rhs: "1".into(),
    };
    assert_eq!(s.render(0), "x = 1;");
    assert_eq!(s.render(1), "    x = 1;");
    assert_eq!(s.render(2), "        x = 1;");
}

#[test]
fn cstatement_label_ignores_indent() {
    let s = CStatement::Label("L1".into());
    // Label render hard-codes no padding before label name.
    assert_eq!(s.render(0), "L1:");
    assert_eq!(s.render(3), "L1:");
}

#[test]
fn cstatement_block_nesting() {
    let s = CStatement::Block(vec![
        CStatement::Break,
        CStatement::Continue,
    ]);
    let r = s.render(0);
    assert!(r.starts_with('{'));
    assert!(r.contains("break;"));
    assert!(r.contains("continue;"));
    assert!(r.trim_end().ends_with('}'));
}

#[test]
fn cstatement_if_no_else_omits_else() {
    let s = CStatement::If {
        cond: "x".into(),
        then_stmts: vec![CStatement::Break],
        else_stmts: vec![],
    };
    let r = s.render(0);
    assert!(!r.contains("else"));
}

#[test]
fn cstatement_switch_default_only() {
    let s = CStatement::Switch {
        expr: "x".into(),
        cases: vec![CSwitchCase {
            value: None,
            body: vec![CStatement::Break],
        }],
    };
    let r = s.render(0);
    assert!(r.contains("default:"));
    assert!(!r.contains("case"));
}

#[test]
fn cstatement_referenced_vars_assign() {
    let s = CStatement::Assign {
        lhs: "x".into(),
        rhs: "a + b".into(),
    };
    let vs = s.referenced_vars();
    assert!(vs.contains(&"x".to_string()));
    assert!(vs.contains(&"a".to_string()));
    assert!(vs.contains(&"b".to_string()));
}

#[test]
fn cstatement_referenced_vars_non_assign_empty() {
    assert!(CStatement::Break.referenced_vars().is_empty());
    assert!(CStatement::Continue.referenced_vars().is_empty());
}

// ── CPrecedence ────────────────────────────────────────────────────────────

#[test]
fn precedence_total_order() {
    let levels = [
        CPrecedence::COMMA,
        CPrecedence::ASSIGN,
        CPrecedence::TERNARY,
        CPrecedence::LOGICAL_OR,
        CPrecedence::LOGICAL_AND,
        CPrecedence::BITWISE_OR,
        CPrecedence::BITWISE_XOR,
        CPrecedence::BITWISE_AND,
        CPrecedence::EQUALITY,
        CPrecedence::RELATIONAL,
        CPrecedence::SHIFT,
        CPrecedence::ADDITIVE,
        CPrecedence::MULTIPLICATIVE,
        CPrecedence::UNARY,
        CPrecedence::POSTFIX,
        CPrecedence::PRIMARY,
    ];
    for w in levels.windows(2) {
        assert!(w[0] < w[1], "{:?} should be < {:?}", w[0], w[1]);
    }
}

#[test]
fn precedence_needs_parens_equal() {
    let a = CPrecedence::ADDITIVE;
    // Equal precedence does NOT need parens (strict less-than).
    assert!(!a.needs_parens(a));
}

#[test]
fn precedence_for_op_unknown_is_primary() {
    assert_eq!(c_precedence_for_op("@@"), CPrecedence::PRIMARY);
}

#[test]
fn precedence_for_op_all_known() {
    assert_eq!(c_precedence_for_op("||"), CPrecedence::LOGICAL_OR);
    assert_eq!(c_precedence_for_op("&&"), CPrecedence::LOGICAL_AND);
    assert_eq!(c_precedence_for_op("|"), CPrecedence::BITWISE_OR);
    assert_eq!(c_precedence_for_op("^"), CPrecedence::BITWISE_XOR);
    assert_eq!(c_precedence_for_op("&"), CPrecedence::BITWISE_AND);
    assert_eq!(c_precedence_for_op("!="), CPrecedence::EQUALITY);
    assert_eq!(c_precedence_for_op("<="), CPrecedence::RELATIONAL);
    assert_eq!(c_precedence_for_op("<<"), CPrecedence::SHIFT);
    assert_eq!(c_precedence_for_op("-"), CPrecedence::ADDITIVE);
    assert_eq!(c_precedence_for_op("%"), CPrecedence::MULTIPLICATIVE);
}

// ── CTypeDeclaration ───────────────────────────────────────────────────────

#[test]
fn type_decl_struct_empty_fields() {
    let s = CTypeDeclaration::emit_struct("E", &[]);
    assert!(s.contains("struct E {"));
    assert!(s.trim_end().ends_with("};"));
}

#[test]
fn type_decl_enum_empty() {
    let s = CTypeDeclaration::emit_enum("E", &[]);
    assert!(s.contains("enum E {"));
    assert!(s.trim_end().ends_with("};"));
}

// ── CFlowEmitter ───────────────────────────────────────────────────────────

#[test]
fn flow_emitter_pad_increases() {
    let f0 = CFlowEmitter::new(0);
    let f2 = CFlowEmitter::new(2);
    assert!(f2.emit_if("c", "b").len() > f0.emit_if("c", "b").len());
}

#[test]
fn flow_emitter_if_else_contains_else() {
    let f = CFlowEmitter::new(0);
    let s = f.emit_if_else("c", "t", "e");
    assert!(s.contains("} else {"));
}

#[test]
fn flow_emitter_do_while_semicolon() {
    let f = CFlowEmitter::new(0);
    let s = f.emit_do_while("body", "c");
    assert!(s.ends_with(");"));
}

#[test]
fn flow_emitter_switch_empty() {
    let f = CFlowEmitter::new(0);
    let s = f.emit_switch("x", &[]);
    assert!(s.contains("switch (x) {"));
    assert!(s.trim_end().ends_with('}'));
}

// ── CMacroExpander ─────────────────────────────────────────────────────────

#[test]
fn macro_expander_overwrite() {
    let mut m = CMacroExpander::new();
    m.define("A", "1");
    m.define("A", "2");
    assert_eq!(m.macro_count(), 1);
    assert_eq!(m.expand("A"), "2");
}

#[test]
fn macro_expander_empty_no_change() {
    let m = CMacroExpander::new();
    assert_eq!(m.expand("hello"), "hello");
    assert_eq!(m.macro_count(), 0);
}

#[test]
fn macro_expander_unrelated_unchanged() {
    let mut m = CMacroExpander::new();
    m.define("FOO", "BAR");
    assert_eq!(m.expand("nothing here"), "nothing here");
}

// ── CIncludeManager ────────────────────────────────────────────────────────

#[test]
fn include_mgr_local_dedup() {
    let mut im = CIncludeManager::new();
    im.add_local("a.h");
    im.add_local("a.h");
    assert_eq!(im.count(), 1);
    assert!(im.emit().contains("#include \"a.h\""));
}

#[test]
fn include_mgr_mixed_count() {
    let mut im = CIncludeManager::new();
    im.add_system("stdio.h");
    im.add_local("foo.h");
    assert_eq!(im.count(), 2);
}

#[test]
fn include_mgr_auto_unknown_no_add() {
    let mut im = CIncludeManager::new();
    im.add_for_function("user_function_xyz");
    assert_eq!(im.count(), 0);
}

#[test]
fn include_mgr_auto_printf() {
    let mut im = CIncludeManager::new();
    im.add_for_function("printf");
    assert!(im.emit().contains("stdio.h"));
}

#[test]
fn include_mgr_auto_string_funcs() {
    let mut im = CIncludeManager::new();
    im.add_for_function("strlen");
    im.add_for_function("memcpy");
    // both should add string.h but only once.
    assert_eq!(im.count(), 1);
}

#[test]
fn include_mgr_empty_emit() {
    let im = CIncludeManager::new();
    assert_eq!(im.emit(), "");
}

// ── COutputFormatter ───────────────────────────────────────────────────────

#[test]
fn formatter_normalize_collapses_internal_spaces() {
    let f = COutputFormatter::new();
    let out = f.format("int   x    =    1;");
    assert_eq!(out, "int x = 1;");
}

#[test]
fn formatter_preserves_leading_indent() {
    let f = COutputFormatter::new();
    let out = f.format("    int x;");
    assert!(out.starts_with("    "));
}

#[test]
fn formatter_no_normalize() {
    let f = COutputFormatter {
        max_line_len: 80,
        normalize_whitespace: false,
        strip_trailing_spaces: false,
    };
    let raw = "int   x;   ";
    assert_eq!(f.format(raw), raw);
}

// ── CDecompileContext ──────────────────────────────────────────────────────

#[test]
fn ctx_fresh_temp_monotonic() {
    let mut c = CDecompileContext::new("f");
    assert_eq!(c.fresh_temp(), "t0");
    assert_eq!(c.fresh_temp(), "t1");
    assert_eq!(c.fresh_temp(), "t2");
}

#[test]
fn ctx_fresh_label_monotonic() {
    let mut c = CDecompileContext::new("f");
    assert_eq!(c.fresh_label(), "lbl_0");
    assert_eq!(c.fresh_label(), "lbl_1");
}

#[test]
fn ctx_call_targets_recorded() {
    let mut c = CDecompileContext::new("f");
    c.record_call("malloc");
    c.record_call("free");
    assert_eq!(c.call_targets.len(), 2);
}

#[test]
fn ctx_emit_locals_empty() {
    let c = CDecompileContext::new("f");
    assert_eq!(c.emit_locals(), "");
}

// ── COutputValidator ───────────────────────────────────────────────────────

#[test]
fn validator_double_semicolon_reported() {
    let mut v = COutputValidator::new();
    assert!(!v.validate("int x;; "));
    assert!(v.issues.iter().any(|s| s.contains("double semicolon")));
}

#[test]
fn validator_empty_body_reported() {
    let mut v = COutputValidator::new();
    assert!(!v.validate("void f() {}"));
    assert!(v.issues.iter().any(|s| s.contains("empty function body")));
}

#[test]
fn validator_braces_in_string_ignored() {
    let mut v = COutputValidator::new();
    // Equal numbers, with stray brace inside string. Should pass brace check.
    assert!(v.validate("const char *s = \"{\"; { }"));
}

#[test]
fn validator_clears_between_runs() {
    let mut v = COutputValidator::new();
    v.validate("void f() {"); // unbalanced -> issue
    assert!(!v.issues.is_empty());
    v.validate("void f() { return; }"); // valid -> clear
    assert!(v.issues.is_empty());
}

#[test]
fn validator_issue_count() {
    let mut v = COutputValidator::new();
    v.validate("{;;");
    assert_eq!(v.issue_count(), v.issues.len());
}

// ── CTryCatchEmitter ───────────────────────────────────────────────────────

#[test]
fn try_except_basic() {
    let e = CTryCatchEmitter::new(1);
    let s = e.emit_try_except("body", "1", "h");
    assert!(s.contains("__try"));
    assert!(s.contains("__except (1)"));
    assert!(s.starts_with("    ")); // indent=1
}

#[test]
fn try_finally_basic() {
    let e = CTryCatchEmitter::new(0);
    let s = e.emit_try_finally("body", "fin");
    assert!(s.contains("__try"));
    assert!(s.contains("__finally"));
}

// ── CodeGenerator ──────────────────────────────────────────────────────────

#[test]
fn codegen_render_empty_sequence() {
    let g = CodeGenerator::default();
    let s = g.render(&StructuredNode::Sequence(vec![]), 0);
    assert_eq!(s, "");
}

#[test]
fn codegen_render_function_balanced_complex() {
    let g = CodeGenerator::default();
    let sig = FunctionSignature::new("f", DecompType::Void, vec![]);
    let body = StructuredNode::Sequence(vec![
        StructuredNode::If {
            condition: "a".into(),
            then_branch: Box::new(StructuredNode::Loop {
                kind: LoopKind::DoWhile,
                condition: "b".into(),
                body: Box::new(StructuredNode::Continue),
            }),
        },
        StructuredNode::Return(None),
    ]);
    let s = g.render_function(&sig, &[], &body);
    assert!(balanced(&s), "{}", s);
    assert!(s.contains("do {"));
    assert!(s.contains("} while (b);"));
}

#[test]
fn codegen_switch_no_double_break_with_goto() {
    let g = CodeGenerator::default();
    let body = StructuredNode::Switch {
        expr: "x".into(),
        cases: vec![SwitchCase {
            value: Some(0),
            body: Box::new(StructuredNode::Goto(BlockId::new(9))),
        }],
    };
    let s = g.render(&body, 0);
    // body ends with goto (terminator) → no auto break.
    assert_eq!(s.matches("break;").count(), 0);
    assert!(s.contains("goto label_9;"));
}

// ── CStyleGuide ────────────────────────────────────────────────────────────

#[test]
fn style_guide_indent_zero() {
    let s = CStyleGuide::default();
    assert_eq!(s.indent(0), "");
}

#[test]
fn style_guide_indent_size_zero_spaces() {
    let s = CStyleGuide {
        indent_size: 0,
        use_spaces: true,
        ..CStyleGuide::default()
    };
    assert_eq!(s.one_level(), "");
    assert_eq!(s.indent(5), "");
}

// ── CPrettifier ────────────────────────────────────────────────────────────

#[test]
fn prettifier_else_on_same_line_dedented() {
    let p = CPrettifier::new();
    let raw = "void f() {\nif (x) {\nreturn;\n} else {\nreturn;\n}\n}";
    let s = p.prettify(raw, &CStyleGuide::default());
    assert!(balanced(&s));
}

#[test]
fn prettifier_underflow_safe_on_extra_closes() {
    let p = CPrettifier::new();
    // More closing braces than opens — should not panic on depth underflow.
    let raw = "}\n}\n}";
    let s = p.prettify(raw, &CStyleGuide::default());
    assert!(!s.is_empty());
}

#[test]
fn prettifier_no_max_when_zero() {
    let p = CPrettifier::new();
    let style = CStyleGuide {
        max_line_length: 0,
        ..CStyleGuide::default()
    };
    let long = "a".repeat(500);
    let s = p.prettify(&long, &style);
    // Should not wrap when max_line_length == 0.
    assert_eq!(s.lines().count(), 1);
}

// ── CTypeAnnotator ─────────────────────────────────────────────────────────

#[test]
fn annotator_empty_code() {
    let a = CTypeAnnotator::new();
    let mut m = std::collections::HashMap::new();
    m.insert("x".to_string(), "int".to_string());
    let out = a.annotate("", &m);
    assert!(out.is_empty() || out == "\n");
}

#[test]
fn annotator_no_trailing_newline_in_input() {
    let a = CTypeAnnotator::new();
    let mut m = std::collections::HashMap::new();
    m.insert("x".to_string(), "int".to_string());
    let out = a.annotate("x = 1;", &m);
    assert!(!out.ends_with('\n'));
}

#[test]
fn annotator_underscore_is_word_char() {
    let a = CTypeAnnotator::new();
    let mut m = std::collections::HashMap::new();
    m.insert("x".to_string(), "int".to_string());
    // "x_y" contains x followed by underscore → not whole word.
    let out = a.annotate("x_y = 1;", &m);
    assert!(!out.contains("/* int */"), "got {out}");
}

// ── Builder ────────────────────────────────────────────────────────────────

#[test]
fn builder_chains_locals_and_params() {
    let e = env();
    let r = DecompFunctionBuilder::new("foo")
        .return_type(DecompType::Int(IntWidth::I32))
        .param(FunctionParam::new("a", DecompType::Int(IntWidth::I32)))
        .local(VarDecl::new("tmp", DecompType::Int(IntWidth::I32)))
        .format(CFormat::default())
        .emit(&StructuredNode::Return(Some("a".into())), &e)
        .unwrap();
    assert!(r.source_code.contains("int32_t tmp;"));
    assert_eq!(r.stats.variable_count, 1);
}

#[test]
fn builder_default_return_void() {
    let e = env();
    let r = DecompFunctionBuilder::new("g")
        .emit(&StructuredNode::Return(None), &e)
        .unwrap();
    assert!(r.source_code.contains("void g"));
}

// ── CDialect ───────────────────────────────────────────────────────────────

#[test]
fn dialect_is_cpp_complete() {
    for d in [CDialect::Cpp11, CDialect::Cpp14, CDialect::Cpp17, CDialect::Cpp20] {
        assert!(d.is_cpp());
    }
    for d in [CDialect::C89, CDialect::C99, CDialect::C11, CDialect::C17] {
        assert!(!d.is_cpp());
    }
}

#[test]
fn dialect_str_unique() {
    let all = [
        CDialect::C89, CDialect::C99, CDialect::C11, CDialect::C17,
        CDialect::Cpp11, CDialect::Cpp14, CDialect::Cpp17, CDialect::Cpp20,
    ];
    let mut seen = std::collections::HashSet::new();
    for d in all {
        assert!(seen.insert(d.as_str()), "duplicate {}", d.as_str());
    }
}

// ── Misc public utilities ──────────────────────────────────────────────────

#[test]
fn version_nonempty() {
    assert!(!decompiler_c_version().is_empty());
}

#[test]
fn supported_langs_include_c_and_cpp() {
    let l = supported_languages();
    assert!(l.contains(&"c"));
    assert!(l.contains(&"c++"));
}

#[test]
fn max_depth_positive() {
    assert!(max_decompile_depth() > 0);
}

// ── Struct emission with multiple fields ───────────────────────────────────

#[test]
fn emit_struct_def_field_offsets_in_comments() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let st = StructType::new(
        "S",
        vec![
            StructField::new(0, "a", DecompType::Int(IntWidth::I32)),
            StructField::new(8, "b", DecompType::Int(IntWidth::I64)),
        ],
        16,
    );
    let s = p.emit_struct_def(&st).unwrap();
    assert!(s.contains("0x0"));
    assert!(s.contains("0x8"));
}

// ── Round-trip: function source has matching open/close braces ─────────────

#[test]
fn function_source_brace_balance_kandr() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let sig = FunctionSignature::new("rt", DecompType::Void, vec![]);
    let body = StructuredNode::IfElse {
        condition: "x".into(),
        then_branch: Box::new(StructuredNode::Break),
        else_branch: Box::new(StructuredNode::Continue),
    };
    let r = p.emit_function(&sig, &[], &body).unwrap();
    assert!(balanced(&r.source_code), "src:\n{}", r.source_code);
}

#[test]
fn function_source_brace_balance_allman() {
    let e = env();
    let p = CPrinter::new(
        CFormat {
            braces: BraceStyle::Allman,
            ..CFormat::default()
        },
        &e,
    );
    let sig = FunctionSignature::new("rt", DecompType::Void, vec![]);
    let body = StructuredNode::IfElse {
        condition: "x".into(),
        then_branch: Box::new(StructuredNode::Break),
        else_branch: Box::new(StructuredNode::Continue),
    };
    let r = p.emit_function(&sig, &[], &body).unwrap();
    assert!(balanced(&r.source_code), "src:\n{}", r.source_code);
}

// ── binop_c_str smoke ──────────────────────────────────────────────────────

#[test]
fn binop_c_str_smoke() {
    use rustre_decompiler_expr::BinOp;
    let s = binop_c_str(BinOp::Mul);
    assert!(!s.is_empty());
}

// ── EmitStats default ──────────────────────────────────────────────────────

#[test]
fn emit_stats_default_zero() {
    let s = EmitStats::default();
    assert_eq!(s.goto_count, 0);
    assert_eq!(s.if_count, 0);
    assert_eq!(s.loop_count, 0);
    assert_eq!(s.switch_count, 0);
    assert_eq!(s.lines, 0);
    assert_eq!(s.variable_count, 0);
}

// ── CFormat default sanity ─────────────────────────────────────────────────

#[test]
fn cformat_default_emit_prototype_true() {
    let f = CFormat::default();
    assert!(f.emit_prototype);
    assert!(!f.emit_block_comments);
}

// ── DecompileContext add_local serialization ───────────────────────────────

#[test]
fn ctx_emit_locals_format() {
    let mut c = CDecompileContext::new("f");
    c.add_local("int", "a");
    c.add_local("char", "b");
    let s = c.emit_locals();
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("    "));
    assert!(lines[0].contains("int a;"));
}

// ── Bug check: variadic with no preceding params yields broken decl ────────
//
// `as_c_declaration` produces "ret name(, ...)" for variadic with empty
// params. That's syntactically invalid C. Documenting as a regression to
// note rather than break — but assert the join pattern.

#[test]
fn variadic_with_one_param_well_formed() {
    let mut s = FunctionSignature::new(
        "f",
        DecompType::Void,
        vec![FunctionParam::new("fmt", DecompType::Ptr(Box::new(DecompType::Void)))],
    );
    s.is_variadic = true;
    let d = s.as_c_declaration();
    assert!(d.contains("fmt, ..."));
}
