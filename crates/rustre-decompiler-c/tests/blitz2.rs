//! blitz2: adversarial coverage of rustre-decompiler-c public API.

use rustre_decompiler_c::*;
use rustre_decompiler_cfs::{BlockId, LoopKind, StructuredNode, SwitchCase};
use rustre_decompiler_expr::IntWidth;
use rustre_decompiler_type::{DecompType, StructField, StructType, TypeEnvironment};
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

fn env() -> TypeEnvironment {
    TypeEnvironment::new()
}

fn balanced(s: &str) -> bool {
    let o = s.chars().filter(|&c| c == '{').count();
    let c = s.chars().filter(|&c| c == '}').count();
    o == c
}

fn simple_sig() -> FunctionSignature {
    FunctionSignature::new("f", DecompType::Void, vec![])
}

// ── LCG seeded fuzzer helper ──────────────────────────────────────────────
fn make_lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 1. CPrecedence
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn precedence_total_ordering() {
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
        assert!(w[0] < w[1]);
    }
}

#[test]
fn precedence_needs_parens_symmetry() {
    let a = CPrecedence::ADDITIVE;
    let m = CPrecedence::MULTIPLICATIVE;
    assert!(a.needs_parens(m));
    assert!(!m.needs_parens(a));
    assert!(!a.needs_parens(a));
}

#[test]
fn precedence_for_unknown_op_is_primary() {
    assert_eq!(c_precedence_for_op("@@"), CPrecedence::PRIMARY);
    assert_eq!(c_precedence_for_op(""), CPrecedence::PRIMARY);
    assert_eq!(c_precedence_for_op("foo"), CPrecedence::PRIMARY);
}

#[test]
fn precedence_for_all_known_ops() {
    let cases = [
        ("||", CPrecedence::LOGICAL_OR),
        ("&&", CPrecedence::LOGICAL_AND),
        ("|", CPrecedence::BITWISE_OR),
        ("^", CPrecedence::BITWISE_XOR),
        ("&", CPrecedence::BITWISE_AND),
        ("==", CPrecedence::EQUALITY),
        ("!=", CPrecedence::EQUALITY),
        ("<", CPrecedence::RELATIONAL),
        (">", CPrecedence::RELATIONAL),
        ("<=", CPrecedence::RELATIONAL),
        (">=", CPrecedence::RELATIONAL),
        ("<<", CPrecedence::SHIFT),
        (">>", CPrecedence::SHIFT),
        ("+", CPrecedence::ADDITIVE),
        ("-", CPrecedence::ADDITIVE),
        ("*", CPrecedence::MULTIPLICATIVE),
        ("/", CPrecedence::MULTIPLICATIVE),
        ("%", CPrecedence::MULTIPLICATIVE),
    ];
    for (op, lvl) in cases {
        assert_eq!(c_precedence_for_op(op), lvl, "op={op}");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 2. CDialect / CommentMode / IndentStyleSimple
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn dialect_all_strings_unique_and_nonempty() {
    let all = [
        CDialect::C89,
        CDialect::C99,
        CDialect::C11,
        CDialect::C17,
        CDialect::Cpp11,
        CDialect::Cpp14,
        CDialect::Cpp17,
        CDialect::Cpp20,
    ];
    let mut seen = std::collections::HashSet::new();
    for d in all {
        let s = d.as_str();
        assert!(!s.is_empty());
        assert!(seen.insert(s));
        assert_eq!(d.is_cpp(), s.starts_with("c++"));
    }
}

#[test]
fn dialect_hash_eq_consistency() {
    let mut set = std::collections::HashSet::new();
    set.insert(CDialect::C99);
    set.insert(CDialect::C99);
    assert_eq!(set.len(), 1);
    assert!(set.contains(&CDialect::C99));
    assert!(!set.contains(&CDialect::C89));
}

#[test]
fn indent_style_simple_boundary_zero_spaces() {
    let i = IndentStyleSimple::spaces(0);
    assert_eq!(i.indent_str(), "");
}

#[test]
fn indent_style_simple_large_spaces() {
    let i = IndentStyleSimple::spaces(64);
    assert_eq!(i.indent_str().len(), 64);
}

// ─────────────────────────────────────────────────────────────────────────
// 3. FunctionSignature / FunctionParam / VarDecl
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn sig_zero_params_void() {
    let s = FunctionSignature::new("z", DecompType::Void, vec![]);
    assert!(s.as_c_declaration().contains("void z()"));
}

#[test]
fn sig_variadic_no_params() {
    let mut s = FunctionSignature::new("v", DecompType::Void, vec![]);
    s.is_variadic = true;
    let d = s.as_c_declaration();
    assert!(d.contains("..."));
}

#[test]
fn sig_many_params_fuzz() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let n = (g() % 8) as usize;
        let params: Vec<FunctionParam> = (0..n)
            .map(|i| FunctionParam::new(format!("p{i}"), DecompType::Int(IntWidth::I32)))
            .collect();
        let sig = FunctionSignature::new("f", DecompType::Int(IntWidth::I32), params);
        let d = sig.as_c_declaration();
        // Must contain comma exactly n-1 times in params section.
        let commas = d.matches(',').count();
        assert_eq!(commas, n.saturating_sub(1));
    }
}

#[test]
fn vardecl_with_init_roundtrip() {
    let v = VarDecl::new("x", DecompType::Int(IntWidth::I32)).with_init("42");
    let d = v.as_c_declaration();
    assert!(d.contains("= 42"));
    assert!(d.contains('x'));
}

#[test]
fn vardecl_no_init_no_eq() {
    let v = VarDecl::new("y", DecompType::Int(IntWidth::I32));
    assert!(!v.as_c_declaration().contains('='));
}

// ─────────────────────────────────────────────────────────────────────────
// 4. CPrinter
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn printer_goto_count_tracked() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let body = StructuredNode::Sequence(vec![
        StructuredNode::Goto(BlockId::new(1)),
        StructuredNode::Goto(BlockId::new(2)),
        StructuredNode::Goto(BlockId::new(3)),
    ]);
    let r = p.emit_function(&simple_sig(), &[], &body).unwrap();
    assert_eq!(r.stats.goto_count, 3);
    assert!(r.source_code.contains("goto label_1;"));
    assert!(r.source_code.contains("goto label_2;"));
    assert!(r.source_code.contains("goto label_3;"));
}

#[test]
fn printer_nested_if_else_balanced() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let body = StructuredNode::IfElse {
        condition: "a".into(),
        then_branch: Box::new(StructuredNode::If {
            condition: "b".into(),
            then_branch: Box::new(StructuredNode::Return(None)),
        }),
        else_branch: Box::new(StructuredNode::Return(Some("0".into()))),
    };
    let r = p.emit_function(&simple_sig(), &[], &body).unwrap();
    assert!(balanced(&r.source_code));
    assert_eq!(r.stats.if_count, 2);
}

#[test]
fn printer_all_loop_kinds() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    for kind in [LoopKind::While, LoopKind::DoWhile, LoopKind::For] {
        let body = StructuredNode::Loop {
            kind: kind.clone(),
            condition: "c".into(),
            body: Box::new(StructuredNode::Break),
        };
        let r = p.emit_function(&simple_sig(), &[], &body).unwrap();
        assert!(balanced(&r.source_code));
        assert_eq!(r.stats.loop_count, 1);
    }
}

#[test]
fn printer_switch_with_many_cases() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let cases: Vec<SwitchCase> = (0..20)
        .map(|i| SwitchCase {
            value: Some(i),
            body: Box::new(StructuredNode::Break),
        })
        .collect();
    let body = StructuredNode::Switch {
        expr: "x".into(),
        cases,
    };
    let r = p.emit_function(&simple_sig(), &[], &body).unwrap();
    assert_eq!(r.stats.switch_count, 1);
    for i in 0..20 {
        assert!(r.source_code.contains(&format!("case {i}:")));
    }
}

#[test]
fn printer_emit_const_decimal_negative() {
    let e = env();
    let p = CPrinter::new(
        CFormat {
            const_notation: ConstNotation::Decimal,
            ..CFormat::default()
        },
        &e,
    );
    assert_eq!(p.emit_const(-1, IntWidth::I32), "-1");
}

#[test]
fn printer_emit_const_auto_boundaries() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    // 999 is < 1000, decimal
    assert_eq!(p.emit_const(999, IntWidth::I32), "999");
    // 1000 is boundary, hex
    assert!(p.emit_const(1000, IntWidth::I32).starts_with("0x"));
    // 0 decimal
    assert_eq!(p.emit_const(0, IntWidth::I32), "0");
}

#[test]
fn printer_emit_const_auto_widths() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    // Negative i32 wraps to u32
    let s = p.emit_const(-1, IntWidth::I32);
    assert!(s.contains("FFFFFFFF"));
    // U8 truncates: use a value >= 1000 to take the hex branch. 0x10FF & 0xFF == 0xFF
    let s = p.emit_const(0x10FF, IntWidth::U8);
    assert!(s.contains("FF"), "got {s:?}");
}

#[test]
fn printer_struct_def_zero_fields() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let st = StructType::new("Empty", vec![], 0);
    let s = p.emit_struct_def(&st).unwrap();
    assert!(s.contains("struct Empty"));
    assert!(balanced(&s));
}

#[test]
fn printer_struct_def_many_fields() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let fields: Vec<StructField> = (0..10)
        .map(|i| StructField::new(i * 4, format!("f{i}"), DecompType::Int(IntWidth::I32)))
        .collect();
    let st = StructType::new("Big", fields, 40);
    let s = p.emit_struct_def(&st).unwrap();
    for i in 0..10 {
        assert!(s.contains(&format!("f{i}")));
    }
}

#[test]
fn printer_var_decls_empty_returns_empty() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let s = p.emit_var_decls(&[]);
    assert!(s.is_empty());
}

#[test]
fn printer_stats_lines_match_actual() {
    let e = env();
    let p = CPrinter::new(CFormat::default(), &e);
    let body = StructuredNode::Return(None);
    let r = p.emit_function(&simple_sig(), &[], &body).unwrap();
    assert_eq!(r.stats.lines, r.source_code.lines().count());
}

// ─────────────────────────────────────────────────────────────────────────
// 5. CStatement render
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn cstatement_indent_levels() {
    for level in 0..5 {
        let s = CStatement::Break.render(level);
        let pad = "    ".repeat(level);
        assert_eq!(s, format!("{pad}break;"));
    }
}

#[test]
fn cstatement_all_simple_variants() {
    let cases = [
        (
            CStatement::Assign {
                lhs: "a".into(),
                rhs: "b".into(),
            },
            "a = b;",
        ),
        (CStatement::Return(None), "return;"),
        (
            CStatement::Return(Some("x".into())),
            "return x;",
        ),
        (CStatement::ExprStmt("f()".into()), "f();"),
        (CStatement::Break, "break;"),
        (CStatement::Continue, "continue;"),
        (CStatement::Goto("L".into()), "goto L;"),
        (CStatement::Label("L".into()), "L:"),
        (CStatement::Raw("nop".into()), "nop"),
        (
            CStatement::DeclAssign {
                ty: "int".into(),
                name: "x".into(),
                init: "0".into(),
            },
            "int x = 0;",
        ),
    ];
    for (s, expected) in cases {
        assert_eq!(s.render(0), expected);
    }
}

#[test]
fn cstatement_nested_block() {
    let s = CStatement::Block(vec![CStatement::Break, CStatement::Continue]);
    let r = s.render(0);
    assert!(r.contains("break"));
    assert!(r.contains("continue"));
    assert!(balanced(&r));
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
fn cstatement_referenced_vars_assign() {
    let s = CStatement::Assign {
        lhs: "x".into(),
        rhs: "y + z".into(),
    };
    let v = s.referenced_vars();
    assert!(v.contains(&"x".to_string()));
}

#[test]
fn cstatement_referenced_vars_nonassign_empty() {
    let s = CStatement::Break;
    assert!(s.referenced_vars().is_empty());
}

// ─────────────────────────────────────────────────────────────────────────
// 6. CFlowEmitter
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn flow_emitter_indent_propagates() {
    let fe = CFlowEmitter::new(2);
    let r = fe.emit_if("c", "  body");
    assert!(r.starts_with("        if")); // 8 spaces (2 levels * 4)
}

#[test]
fn flow_emitter_do_while_renders() {
    let fe = CFlowEmitter::new(0);
    let r = fe.emit_do_while("body", "c");
    assert!(r.contains("do"));
    assert!(r.contains("while (c)"));
    assert!(balanced(&r));
}

#[test]
fn flow_emitter_empty_switch() {
    let fe = CFlowEmitter::new(0);
    let r = fe.emit_switch("x", &[]);
    assert!(r.contains("switch"));
    assert!(balanced(&r));
}

// ─────────────────────────────────────────────────────────────────────────
// 7. CMacroExpander
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn macro_expander_empty_no_change() {
    let me = CMacroExpander::new();
    assert_eq!(me.expand("x = 1;"), "x = 1;");
    assert_eq!(me.macro_count(), 0);
}

#[test]
fn macro_expander_overwrite() {
    let mut me = CMacroExpander::new();
    me.define("X", "a");
    me.define("X", "b");
    assert_eq!(me.macro_count(), 1);
    assert_eq!(me.expand("X"), "b");
}

#[test]
fn macro_expander_fuzz_no_panic() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let mut me = CMacroExpander::new();
        for _ in 0..(g() % 5) {
            let name = format!("M{}", g() % 100);
            let exp = format!("V{}", g() % 100);
            me.define(name, exp);
        }
        let _ = me.expand("a b c M0 M1 M2");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 8. CIncludeManager
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn include_manager_local_add() {
    let mut im = CIncludeManager::new();
    im.add_local("local.h");
    let s = im.emit();
    assert!(s.contains("#include \"local.h\""));
}

#[test]
fn include_manager_local_dedup() {
    let mut im = CIncludeManager::new();
    im.add_local("a.h");
    im.add_local("a.h");
    assert_eq!(im.count(), 1);
}

#[test]
fn include_manager_unknown_function_no_add() {
    let mut im = CIncludeManager::new();
    im.add_for_function("__totally_unknown_xyz");
    assert_eq!(im.count(), 0);
}

#[test]
fn include_manager_known_funcs_map_to_headers() {
    for (fname, header) in &[
        ("malloc", "stdlib.h"),
        ("printf", "stdio.h"),
        ("strlen", "string.h"),
        ("open", "unistd.h"),
    ] {
        let mut im = CIncludeManager::new();
        im.add_for_function(fname);
        assert!(im.emit().contains(header), "fname={fname}");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 9. COutputFormatter
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn formatter_preserves_indentation() {
    let f = COutputFormatter::new();
    let out = f.format("    int x;");
    assert!(out.starts_with("    "));
}

#[test]
fn formatter_collapses_internal_whitespace() {
    let f = COutputFormatter::new();
    let out = f.format("int   x   =   1;");
    assert_eq!(out, "int x = 1;");
}

#[test]
fn formatter_empty_input() {
    let f = COutputFormatter::new();
    assert_eq!(f.format(""), "");
}

// ─────────────────────────────────────────────────────────────────────────
// 10. CDecompileContext
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn decomp_ctx_temp_counter_monotonic() {
    let mut c = CDecompileContext::new("fn");
    let mut prev: i64 = -1;
    for _ in 0..20 {
        let t = c.fresh_temp();
        let n: i64 = t.trim_start_matches('t').parse().unwrap();
        assert!(n > prev);
        prev = n;
    }
}

#[test]
fn decomp_ctx_label_counter_distinct() {
    let mut c = CDecompileContext::new("fn");
    let labels: Vec<String> = (0..10).map(|_| c.fresh_label()).collect();
    let set: std::collections::HashSet<_> = labels.iter().collect();
    assert_eq!(set.len(), labels.len());
}

#[test]
fn decomp_ctx_record_call() {
    let mut c = CDecompileContext::new("fn");
    c.record_call("foo");
    c.record_call("bar");
    assert_eq!(c.call_targets.len(), 2);
}

#[test]
fn decomp_ctx_emit_locals_empty() {
    let c = CDecompileContext::new("fn");
    assert_eq!(c.emit_locals(), "");
}

// ─────────────────────────────────────────────────────────────────────────
// 11. COutputValidator
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn validator_string_with_braces_ignored() {
    let mut v = COutputValidator::new();
    // Braces inside string literals shouldn't be counted as unbalanced.
    let code = "void f() { const char *s = \"}{\"; }";
    assert!(v.validate(code), "issues: {:?}", v.issues);
}

#[test]
fn validator_char_literal_brace_ignored() {
    let mut v = COutputValidator::new();
    let code = "void f() { char c = '}'; }";
    assert!(v.validate(code), "issues: {:?}", v.issues);
}

#[test]
fn validator_double_semicolon_flagged() {
    let mut v = COutputValidator::new();
    assert!(!v.validate("x = 1;;"));
    assert!(v.issue_count() >= 1);
}

#[test]
fn validator_clears_between_calls() {
    let mut v = COutputValidator::new();
    let _ = v.validate("{{");
    assert!(v.issue_count() > 0);
    let _ = v.validate("void f() { return; }");
    assert_eq!(v.issue_count(), 0);
}

#[test]
fn validator_fuzz_no_panic() {
    let mut g = make_lcg();
    let chars: Vec<char> = "{}()[];\"\\ a1".chars().collect();
    for _ in 0..50 {
        let len = (g() % 60) as usize;
        let s: String = (0..len).map(|_| chars[(g() as usize) % chars.len()]).collect();
        let mut v = COutputValidator::new();
        let _ = v.validate(&s);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 12. CTryCatchEmitter
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn try_catch_indent_levels() {
    let e = CTryCatchEmitter::new(3);
    let r = e.emit_try_except("body", "filter", "handler");
    // 3 * 4 = 12 spaces leading
    assert!(r.starts_with("            __try"), "got {r:?}");
}

#[test]
fn try_finally_balanced() {
    let e = CTryCatchEmitter::new(0);
    let r = e.emit_try_finally("a", "b");
    assert!(balanced(&r));
}

// ─────────────────────────────────────────────────────────────────────────
// 13. CTypeDeclaration
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn ctypedecl_empty_struct() {
    let s = CTypeDeclaration::emit_struct("E", &[]);
    assert!(s.contains("struct E"));
    assert!(balanced(&s));
}

#[test]
fn ctypedecl_enum_empty() {
    let s = CTypeDeclaration::emit_enum("E", &[]);
    assert!(s.contains("enum E"));
    assert!(balanced(&s));
}

#[test]
fn ctypedecl_enum_negative_values() {
    let s = CTypeDeclaration::emit_enum("Sign", &[("NEG", -1), ("ZERO", 0)]);
    assert!(s.contains("NEG = -1"));
    assert!(s.contains("ZERO = 0"));
}

// ─────────────────────────────────────────────────────────────────────────
// 14. CodeGenerator constants and rendering
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn codegen_const_neg_auto() {
    let g = CodeGenerator::default();
    let s = g.constant(-0x2000, IntWidth::I32);
    assert!(s.starts_with("-0x"));
}

#[test]
fn codegen_const_u64_suffix() {
    let g = CodeGenerator::default();
    let s = g.constant(0x0010_0000, IntWidth::U64);
    assert!(s.ends_with("ULL"));
}

#[test]
fn codegen_const_u32_suffix() {
    let g = CodeGenerator::default();
    let s = g.constant(0x10000, IntWidth::U32);
    assert!(s.ends_with('U') && !s.ends_with("ULL"));
}

#[test]
fn codegen_render_returns_balanced_for_all_node_kinds() {
    let g = CodeGenerator::default();
    let nodes = vec![
        StructuredNode::Return(None),
        StructuredNode::Return(Some("0".into())),
        StructuredNode::Break,
        StructuredNode::Continue,
        StructuredNode::Goto(BlockId::new(0)),
        StructuredNode::If {
            condition: "x".into(),
            then_branch: Box::new(StructuredNode::Break),
        },
        StructuredNode::IfElse {
            condition: "x".into(),
            then_branch: Box::new(StructuredNode::Return(None)),
            else_branch: Box::new(StructuredNode::Return(Some("1".into()))),
        },
    ];
    for n in nodes {
        let s = g.render(&n, 0);
        assert!(balanced(&s), "unbalanced: {s:?}");
    }
}

#[test]
fn codegen_fuzz_random_constants() {
    let g = CodeGenerator::default();
    let mut lcg = make_lcg();
    for _ in 0..50 {
        let v = lcg() as i64;
        let widths = [IntWidth::I32, IntWidth::U32, IntWidth::I64, IntWidth::U64];
        let w = widths[(lcg() as usize) % widths.len()];
        let s = g.constant(v, w);
        assert!(!s.is_empty());
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 15. CStyleGuide / CPrettifier
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn prettifier_empty_input() {
    let p = CPrettifier::new();
    let out = p.prettify("", &CStyleGuide::default());
    assert_eq!(out, "");
}

#[test]
fn prettifier_extra_close_brace_no_panic() {
    let p = CPrettifier::new();
    let out = p.prettify("}", &CStyleGuide::default());
    assert!(out.contains('}'));
}

#[test]
fn prettifier_unbalanced_open_no_panic() {
    let p = CPrettifier::new();
    let _ = p.prettify("void f() {\nint x;\n", &CStyleGuide::default());
}

#[test]
fn prettifier_fuzz_brace_lines() {
    let mut g = make_lcg();
    let p = CPrettifier::new();
    for _ in 0..50 {
        let lines = (g() % 10) as usize;
        let mut s = String::new();
        for _ in 0..lines {
            let pick = g() % 4;
            match pick {
                0 => s.push_str("{\n"),
                1 => s.push_str("}\n"),
                2 => s.push_str("x;\n"),
                _ => s.push_str("if (a) {\n"),
            }
        }
        let _ = p.prettify(&s, &CStyleGuide::default());
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 16. CTypeAnnotator
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn annotator_empty_code() {
    let a = CTypeAnnotator::new();
    let mut m = HashMap::new();
    m.insert("x".into(), "int".into());
    assert_eq!(a.annotate("", &m), "");
}

#[test]
fn annotator_underscore_idents() {
    let a = CTypeAnnotator::new();
    let mut m = HashMap::new();
    m.insert("_x".into(), "int".into());
    let out = a.annotate("_x = 1;", &m);
    assert!(out.contains("/* int */"));
}

#[test]
fn annotator_deterministic_order() {
    let a = CTypeAnnotator::new();
    let mut m1 = HashMap::new();
    m1.insert("a".into(), "T1".into());
    m1.insert("b".into(), "T2".into());
    let code = "a = b;";
    let o1 = a.annotate(code, &m1.clone());
    let o2 = a.annotate(code, &m1);
    assert_eq!(o1, o2);
}

// ─────────────────────────────────────────────────────────────────────────
// 17. DecompiledFunction serde round-trip
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn decompiled_function_serde_roundtrip() {
    let df = DecompiledFunction {
        name: "f".into(),
        source_code: "void f() {}".into(),
        stats: EmitStats {
            goto_count: 1,
            variable_count: 2,
            lines: 3,
            if_count: 4,
            loop_count: 5,
            switch_count: 6,
        },
    };
    let j = serde_json::to_string(&df).unwrap();
    let back: DecompiledFunction = serde_json::from_str(&j).unwrap();
    assert_eq!(back.name, df.name);
    assert_eq!(back.stats.goto_count, 1);
    assert_eq!(back.stats.switch_count, 6);
}

#[test]
fn cformat_serde_roundtrip() {
    let f = CFormat {
        indent: IndentStyle::Tabs,
        braces: BraceStyle::Allman,
        const_notation: ConstNotation::Hex,
        var_naming: VarNaming::Sequential,
        emit_block_comments: true,
        emit_prototype: false,
    };
    let j = serde_json::to_string(&f).unwrap();
    let back: CFormat = serde_json::from_str(&j).unwrap();
    assert_eq!(back.indent, IndentStyle::Tabs);
    assert_eq!(back.braces, BraceStyle::Allman);
    assert!(back.emit_block_comments);
    assert!(!back.emit_prototype);
}

// ─────────────────────────────────────────────────────────────────────────
// 18. Threaded stress — Send/Sync types
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn threaded_codegen_const_stress() {
    let g = Arc::new(CodeGenerator::default());
    let mut handles = vec![];
    for t in 0..4 {
        let g = g.clone();
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let v = i64::from(t * 1000 + i);
                let s = g.constant(v, IntWidth::I32);
                assert!(!s.is_empty());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_prettifier_stress() {
    let p = Arc::new(CPrettifier::new());
    let style = Arc::new(CStyleGuide::default());
    let mut handles = vec![];
    for _ in 0..4 {
        let p = p.clone();
        let style = style.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let out = p.prettify("void f() {\nreturn;\n}", &style);
                assert!(balanced(&out));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 19. Standalone helpers
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn helpers_basic() {
    assert!(!decompiler_c_version().is_empty());
    assert!(supported_languages().contains(&"c"));
    assert_eq!(max_decompile_depth(), 32);
}
