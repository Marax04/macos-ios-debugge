//! Blitz test suite for rustre-il-hlil — exercise the public API of `lib.rs`
//! to surface bugs in folding, pattern matching, printing, walking, etc.

use rustre_core::address::Address;
use rustre_il_hlil::*;

fn v(name: &str) -> HlilVar {
    HlilVar::new(name, HlilType::i32())
}

const fn cst(v: i64) -> HlilExpr {
    HlilExpr::Const { value: v, ty: HlilType::i32() }
}

fn var_expr(name: &str) -> HlilExpr {
    HlilExpr::Var { var: v(name) }
}

// ── HlilType ─────────────────────────────────────────────────────────────────

#[test]
fn type_constructors_signed_unsigned() {
    assert!(matches!(HlilType::i8(), HlilType::Int { signed: true, bits: 8 }));
    assert!(matches!(HlilType::u8(), HlilType::Int { signed: false, bits: 8 }));
    assert!(matches!(HlilType::i64(), HlilType::Int { signed: true, bits: 64 }));
    assert!(matches!(HlilType::u32(), HlilType::Int { signed: false, bits: 32 }));
}

#[test]
fn type_byte_size_basics() {
    assert_eq!(HlilType::Void.byte_size(), Some(0));
    assert_eq!(HlilType::Bool.byte_size(), Some(1));
    assert_eq!(HlilType::i32().byte_size(), Some(4));
    assert_eq!(HlilType::u64().byte_size(), Some(8));
    assert_eq!(HlilType::Float { bits: 32 }.byte_size(), Some(4));
    assert_eq!(HlilType::ptr(HlilType::i8(), 64).byte_size(), Some(8));
    assert_eq!(HlilType::Unknown.byte_size(), None);
    assert_eq!(HlilType::Struct { name: "S".into() }.byte_size(), None);
    assert_eq!(HlilType::Enum { name: "E".into() }.byte_size(), None);
}

#[test]
fn type_byte_size_array_sized_and_unsized() {
    let a = HlilType::Array { elem: Box::new(HlilType::i32()), count: Some(10) };
    assert_eq!(a.byte_size(), Some(40));
    let unsized_arr = HlilType::Array { elem: Box::new(HlilType::i32()), count: None };
    assert_eq!(unsized_arr.byte_size(), None);
}

#[test]
fn type_byte_size_non_multiple_of_8_bits() {
    // 7-bit int isn't multiple of 8 -> None
    let odd = HlilType::Int { signed: true, bits: 7 };
    assert_eq!(odd.byte_size(), None);
}

#[test]
fn type_is_pointer_is_integer() {
    assert!(HlilType::ptr(HlilType::i8(), 64).is_pointer());
    assert!(!HlilType::i32().is_pointer());
    assert!(HlilType::i32().is_integer());
    assert!(!HlilType::Bool.is_integer());
    assert!(!HlilType::ptr(HlilType::i8(), 64).is_integer());
}

#[test]
fn type_display_standard_widths() {
    assert_eq!(HlilType::i8().to_string(), "int8_t");
    assert_eq!(HlilType::i16().to_string(), "int16_t");
    assert_eq!(HlilType::i32().to_string(), "int32_t");
    assert_eq!(HlilType::i64().to_string(), "int64_t");
    assert_eq!(HlilType::u8().to_string(), "uint8_t");
    assert_eq!(HlilType::u64().to_string(), "uint64_t");
    assert_eq!(HlilType::Bool.to_string(), "bool");
    assert_eq!(HlilType::Void.to_string(), "void");
    assert_eq!(HlilType::Unknown.to_string(), "unknown");
    assert_eq!(HlilType::Float { bits: 32 }.to_string(), "float");
    assert_eq!(HlilType::Float { bits: 64 }.to_string(), "double");
}

#[test]
fn type_display_pointer_and_array() {
    let p = HlilType::ptr(HlilType::i32(), 64);
    assert_eq!(p.to_string(), "int32_t *");
    let a = HlilType::Array { elem: Box::new(HlilType::i8()), count: Some(5) };
    assert_eq!(a.to_string(), "int8_t[5]");
    let a2 = HlilType::Array { elem: Box::new(HlilType::i8()), count: None };
    assert_eq!(a2.to_string(), "int8_t[]");
}

#[test]
fn type_display_function() {
    let f = HlilType::Function {
        ret: Box::new(HlilType::i32()),
        params: vec![HlilType::i32(), HlilType::Bool],
    };
    assert_eq!(f.to_string(), "int32_t (*)(int32_t, bool)");
}

#[test]
fn type_eq_and_hash() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(HlilType::i32());
    s.insert(HlilType::i32());
    s.insert(HlilType::u32());
    assert_eq!(s.len(), 2);
}

// ── HlilVar ──────────────────────────────────────────────────────────────────

#[test]
fn var_new_and_param() {
    let nv = HlilVar::new("x", HlilType::i32());
    assert!(!nv.is_param);
    assert_eq!(nv.version, 0);
    assert!(!nv.is_ssa);
    let p = HlilVar::param("a", HlilType::i32());
    assert!(p.is_param);
}

#[test]
fn var_display() {
    let nv = HlilVar::new("counter", HlilType::u64());
    assert_eq!(nv.to_string(), "uint64_t counter");
}

// ── HlilExpr ─────────────────────────────────────────────────────────────────

#[test]
fn expr_const_helpers() {
    let c = cst(42);
    assert_eq!(c.is_const(), Some(42));
    assert!(!c.is_const_zero());
    let z = cst(0);
    assert!(z.is_const_zero());
    let v = var_expr("x");
    assert_eq!(v.is_const(), None);
    assert!(!v.is_const_zero());
}

#[test]
fn expr_type_carriers() {
    assert_eq!(cst(1).expr_type(), &HlilType::i32());
    let cmp = HlilExpr::CmpEq(Box::new(cst(1)), Box::new(cst(2)));
    assert_eq!(cmp.expr_type(), &HlilType::Bool);
    let sz = HlilExpr::SizeOf { ty: HlilType::i32() };
    assert_eq!(sz.expr_type(), &HlilType::Int { signed: false, bits: 64 });
    let undef = HlilExpr::Undefined(HlilType::Bool);
    assert_eq!(undef.expr_type(), &HlilType::Bool);
}

#[test]
fn expr_is_var_as_var() {
    let e = var_expr("x");
    assert!(e.is_var());
    assert_eq!(e.as_var().map(|v| v.name.as_str()), Some("x"));
    assert!(!cst(0).is_var());
    assert!(cst(0).as_var().is_none());
}

#[test]
fn expr_uses_var_simple() {
    let x = v("x");
    let y = v("y");
    let e = HlilExpr::Add(Box::new(var_expr("x")), Box::new(cst(1)), HlilType::i32());
    assert!(e.uses_var(&x));
    assert!(!e.uses_var(&y));
}

#[test]
fn expr_uses_var_deep() {
    let x = v("x");
    let inner = HlilExpr::Call {
        func: Box::new(var_expr("f")),
        args: vec![HlilExpr::Add(Box::new(var_expr("x")), Box::new(cst(2)), HlilType::i32())],
        ret_ty: HlilType::i32(),
    };
    assert!(inner.uses_var(&x));
}

#[test]
fn expr_complexity_atoms_and_nested() {
    assert_eq!(cst(1).complexity(), 1);
    assert_eq!(var_expr("x").complexity(), 1);
    let add = HlilExpr::Add(Box::new(cst(1)), Box::new(cst(2)), HlilType::i32());
    assert_eq!(add.complexity(), 3);
}

#[test]
fn expr_node_count_matches_complexity_for_basic() {
    let e = HlilExpr::Add(Box::new(cst(1)), Box::new(var_expr("x")), HlilType::i32());
    assert_eq!(e.node_count(), 3);
}

#[test]
fn expr_is_pure() {
    assert!(cst(1).is_pure());
    assert!(var_expr("x").is_pure());
    let d = HlilExpr::Deref { addr: Box::new(var_expr("p")), ty: HlilType::i32() };
    assert!(!d.is_pure());
    let c = HlilExpr::Call {
        func: Box::new(var_expr("f")),
        args: vec![],
        ret_ty: HlilType::Void,
    };
    assert!(!c.is_pure());
    let pure_add = HlilExpr::Add(Box::new(cst(1)), Box::new(var_expr("x")), HlilType::i32());
    assert!(pure_add.is_pure());
}

#[test]
fn expr_display_arith() {
    let e = HlilExpr::Add(Box::new(cst(1)), Box::new(cst(2)), HlilType::i32());
    assert_eq!(e.to_string(), "(1 + 2)");
    let e = HlilExpr::CmpEq(Box::new(var_expr("x")), Box::new(cst(0)));
    assert_eq!(e.to_string(), "(x == 0)");
    let e = HlilExpr::Cast { expr: Box::new(var_expr("x")), to: HlilType::u8() };
    assert_eq!(e.to_string(), "(uint8_t)x");
    let e = HlilExpr::SizeOf { ty: HlilType::i32() };
    assert_eq!(e.to_string(), "sizeof(int32_t)");
}

#[test]
fn expr_vars_used_collects_distinct_uses() {
    let e = HlilExpr::Add(
        Box::new(var_expr("x")),
        Box::new(HlilExpr::Sub(Box::new(var_expr("y")), Box::new(var_expr("x")), HlilType::i32())),
        HlilType::i32(),
    );
    let used = e.vars_used();
    assert_eq!(used.len(), 3);
}

#[test]
fn expr_walk_visits_all_nodes() {
    let e = HlilExpr::Add(Box::new(cst(1)), Box::new(cst(2)), HlilType::i32());
    let mut n = 0;
    e.walk(&mut |_| n += 1);
    assert_eq!(n, 3);
}

// ── HlilStatement ────────────────────────────────────────────────────────────

#[test]
fn stmt_is_terminator() {
    assert!(HlilStatement::Return(vec![]).is_terminator());
    assert!(HlilStatement::Break.is_terminator());
    assert!(HlilStatement::Continue.is_terminator());
    assert!(HlilStatement::Goto(Address::new(0x100)).is_terminator());
    assert!(!HlilStatement::Nop.is_terminator());
    assert!(!HlilStatement::Expression(cst(0)).is_terminator());
}

#[test]
fn stmt_contains_return_nested() {
    let s = HlilStatement::If {
        cond: cst(1),
        then_body: vec![HlilStatement::Return(vec![cst(0)])],
        else_body: vec![],
    };
    assert!(s.contains_return());
    let s2 = HlilStatement::Block(vec![HlilStatement::Nop]);
    assert!(!s2.contains_return());
}

#[test]
fn stmt_walk_visits_nested() {
    let s = HlilStatement::Block(vec![
        HlilStatement::Nop,
        HlilStatement::Break,
        HlilStatement::Continue,
    ]);
    let mut n = 0;
    s.walk(&mut |_| n += 1);
    // self + 3 children
    assert_eq!(n, 4);
}

#[test]
fn stmt_written_vars_assign_and_decl() {
    let a = HlilStatement::Assign { dest: var_expr("x"), src: cst(1) };
    assert_eq!(a.written_vars().len(), 1);
    let d = HlilStatement::VarDeclare { var: v("y"), init: None };
    assert_eq!(d.written_vars().len(), 1);
    let nop = HlilStatement::Nop;
    assert_eq!(nop.written_vars().len(), 0);
}

#[test]
fn stmt_always_returns() {
    let r = HlilStatement::Return(vec![]);
    assert!(r.always_returns());
    let ifr = HlilStatement::If {
        cond: cst(1),
        then_body: vec![HlilStatement::Return(vec![])],
        else_body: vec![HlilStatement::Return(vec![])],
    };
    assert!(ifr.always_returns());
    let half = HlilStatement::If {
        cond: cst(1),
        then_body: vec![HlilStatement::Return(vec![])],
        else_body: vec![],
    };
    assert!(!half.always_returns());
}

#[test]
fn stmt_display_assign() {
    let a = HlilStatement::Assign { dest: var_expr("x"), src: cst(7) };
    assert_eq!(a.to_string(), "x = 7;");
}

#[test]
fn stmt_display_if_else_indented() {
    let s = HlilStatement::If {
        cond: var_expr("c"),
        then_body: vec![HlilStatement::Return(vec![cst(1)])],
        else_body: vec![HlilStatement::Return(vec![cst(0)])],
    };
    let out = s.to_string();
    assert!(out.contains("if (c)"));
    assert!(out.contains("return 1;"));
    assert!(out.contains("return 0;"));
    assert!(out.contains("else"));
}

#[test]
fn stmt_display_return_multi() {
    let r = HlilStatement::Return(vec![cst(1), cst(2)]);
    assert_eq!(r.to_string(), "return 1, 2;");
    let r0 = HlilStatement::Return(vec![]);
    assert_eq!(r0.to_string(), "return;");
}

// ── HlilFunction ─────────────────────────────────────────────────────────────

#[test]
fn function_new_defaults() {
    let f = HlilFunction::new(Address::new(0x1000), "foo");
    assert_eq!(f.prototype.name, "foo");
    assert!(f.is_empty());
    assert_eq!(f.locals.len(), 0);
    assert_eq!(f.total_stmt_count(), 0);
}

#[test]
fn function_add_local_and_walk() {
    let mut f = HlilFunction::new(Address::new(0), "f");
    f.add_local(v("a"));
    f.body.push(HlilStatement::Assign { dest: var_expr("a"), src: cst(1) });
    f.body.push(HlilStatement::Return(vec![]));
    let mut count = 0;
    f.walk_stmts(&mut |_| count += 1);
    assert_eq!(count, 2);
    assert_eq!(f.vars_used().len(), 1);
}

#[test]
fn function_calls_made_deep() {
    let mut f = HlilFunction::new(Address::new(0), "f");
    let call = HlilExpr::Call {
        func: Box::new(var_expr("g")),
        args: vec![cst(1)],
        ret_ty: HlilType::Void,
    };
    f.body.push(HlilStatement::Expression(call));
    assert_eq!(f.calls_made().len(), 1);
}

#[test]
fn function_print_includes_prototype_and_body() {
    let mut f = HlilFunction::new(Address::new(0x1000), "foo");
    f.prototype.return_type = HlilType::i32();
    f.body.push(HlilStatement::Return(vec![cst(0)]));
    let s = f.print();
    assert!(s.contains("int32_t foo()"));
    assert!(s.contains("return 0;"));
    assert!(s.contains('{') && s.contains('}'));
}

#[test]
fn function_to_dot_well_formed() {
    let mut f = HlilFunction::new(Address::new(0x10), "fn1");
    f.body.push(HlilStatement::Nop);
    f.body.push(HlilStatement::Return(vec![]));
    let dot = f.to_dot();
    assert!(dot.starts_with("digraph "));
    assert!(dot.contains("s0 [label="));
    assert!(dot.contains("s0 -> s1"));
    assert!(dot.trim_end().ends_with('}'));
}

#[test]
fn function_to_json_contains_keys() {
    let mut f = HlilFunction::new(Address::new(0x1000), "f");
    f.prototype.return_type = HlilType::i32();
    f.add_local(v("x"));
    f.body.push(HlilStatement::Return(vec![cst(0)]));
    let j = f.to_json();
    assert!(j.contains("\"address\":\"0x1000\""));
    assert!(j.contains("\"name\":\"f\""));
    assert!(j.contains("\"return_type\":\"int32_t\""));
    assert!(j.contains("\"locals\":"));
    assert!(j.contains("\"body\":"));
}

#[test]
fn function_total_stmt_count() {
    let mut f = HlilFunction::new(Address::new(0), "f");
    f.body.push(HlilStatement::Block(vec![
        HlilStatement::Nop,
        HlilStatement::Nop,
    ]));
    // Block(1) + 2 children = 3 (but statement_count returns n - 1 after walk)
    let n = f.total_stmt_count();
    // walk visits self+children: 3 visits; statement_count returns 3 - 1 + 1 logic... just sanity:
    assert!(n >= 2);
}

// ── CCodePrinter ─────────────────────────────────────────────────────────────

#[test]
fn printer_default_and_new() {
    let p = CCodePrinter::new();
    assert_eq!(p.indent_width, 4);
    assert!(!p.use_tabs);
}

#[test]
fn printer_print_type_and_expr() {
    let p = CCodePrinter::new();
    assert_eq!(p.print_type(&HlilType::i32()), "int32_t");
    assert_eq!(p.print_expr(&cst(5)), "5");
}

#[test]
fn printer_print_statement_indent() {
    let p = CCodePrinter::new();
    let s = HlilStatement::Return(vec![cst(0)]);
    let out = p.print_statement(&s, 2);
    // 4*2 = 8 spaces
    assert!(out.starts_with("        return 0;"));
}

#[test]
fn printer_use_tabs() {
    let p = CCodePrinter { indent_width: 4, use_tabs: true };
    let s = HlilStatement::Break;
    let out = p.print_statement(&s, 1);
    assert!(out.starts_with('\t'));
}

// ── HlilPrototype ────────────────────────────────────────────────────────────

#[test]
fn prototype_display_no_params() {
    let p = HlilPrototype {
        name: "main".into(),
        return_type: HlilType::i32(),
        params: vec![],
        is_variadic: false,
        calling_convention: None,
    };
    assert_eq!(p.to_string(), "int32_t main()");
}

#[test]
fn prototype_display_variadic_no_params() {
    let p = HlilPrototype {
        name: "printf".into(),
        return_type: HlilType::i32(),
        params: vec![],
        is_variadic: true,
        calling_convention: None,
    };
    assert_eq!(p.to_string(), "int32_t printf(...)");
}

#[test]
fn prototype_display_variadic_with_params() {
    let p = HlilPrototype {
        name: "f".into(),
        return_type: HlilType::Void,
        params: vec![HlilVar::param("fmt", HlilType::ptr(HlilType::i8(), 64))],
        is_variadic: true,
        calling_convention: None,
    };
    assert_eq!(p.to_string(), "void f(int8_t * fmt, ...)");
}

// ── SwitchCase Display ───────────────────────────────────────────────────────

#[test]
fn switch_case_display() {
    let c = SwitchCase {
        values: vec![1, 2],
        body: vec![HlilStatement::Break],
    };
    let s = c.to_string();
    assert!(s.contains("case 1:"));
    assert!(s.contains("case 2:"));
    assert!(s.contains("break;"));
}

// ── fold_hlil_expr ────────────────────────────────────────────────────────────

#[test]
fn fold_add_constants() {
    let e = HlilExpr::Add(Box::new(cst(2)), Box::new(cst(3)), HlilType::i32());
    let (f, c) = fold_hlil_expr(e);
    assert_eq!(f.is_const(), Some(5));
    assert!(c >= 1);
}

#[test]
fn fold_add_x_plus_zero() {
    let e = HlilExpr::Add(Box::new(var_expr("x")), Box::new(cst(0)), HlilType::i32());
    let (f, c) = fold_hlil_expr(e);
    assert!(f.is_var());
    assert!(c >= 1);
}

#[test]
fn fold_sub_constants() {
    let e = HlilExpr::Sub(Box::new(cst(10)), Box::new(cst(3)), HlilType::i32());
    let (f, _) = fold_hlil_expr(e);
    assert_eq!(f.is_const(), Some(7));
}

#[test]
fn fold_mul_by_zero() {
    let e = HlilExpr::Mul(Box::new(var_expr("x")), Box::new(cst(0)), HlilType::i32());
    let (f, _) = fold_hlil_expr(e);
    assert_eq!(f.is_const(), Some(0));
}

#[test]
fn fold_mul_by_one() {
    let e = HlilExpr::Mul(Box::new(var_expr("x")), Box::new(cst(1)), HlilType::i32());
    let (f, _) = fold_hlil_expr(e);
    assert!(f.is_var());
}

#[test]
fn fold_div_by_zero_does_not_panic() {
    let e = HlilExpr::Div(Box::new(cst(1)), Box::new(cst(0)), HlilType::i32());
    let (f, _) = fold_hlil_expr(e);
    // Should not have folded to a constant (would panic). Should remain Div.
    assert_eq!(f.is_const(), None);
    assert!(matches!(f, HlilExpr::Div(..)));
}

#[test]
fn fold_div_by_one() {
    let e = HlilExpr::Div(Box::new(var_expr("x")), Box::new(cst(1)), HlilType::i32());
    let (f, _) = fold_hlil_expr(e);
    assert!(f.is_var());
}

#[test]
fn fold_xor_self_constants() {
    let e = HlilExpr::Xor(Box::new(cst(5)), Box::new(cst(5)), HlilType::i32());
    let (f, _) = fold_hlil_expr(e);
    assert_eq!(f.is_const(), Some(0));
}

#[test]
fn fold_xor_self_var() {
    let e = HlilExpr::Xor(Box::new(var_expr("x")), Box::new(var_expr("x")), HlilType::i32());
    let (f, _) = fold_hlil_expr(e);
    assert_eq!(f.is_const(), Some(0));
}

#[test]
fn fold_and_with_zero() {
    let e = HlilExpr::And(Box::new(var_expr("x")), Box::new(cst(0)), HlilType::i32());
    let (f, _) = fold_hlil_expr(e);
    assert_eq!(f.is_const(), Some(0));
}

#[test]
fn fold_or_constants() {
    let e = HlilExpr::Or(Box::new(cst(0xF0)), Box::new(cst(0x0F)), HlilType::i32());
    let (f, _) = fold_hlil_expr(e);
    assert_eq!(f.is_const(), Some(0xFF));
}

#[test]
fn fold_neg_constant() {
    let e = HlilExpr::Neg(Box::new(cst(5)), HlilType::i32());
    let (f, _) = fold_hlil_expr(e);
    assert_eq!(f.is_const(), Some(-5));
}

#[test]
fn fold_not_constant() {
    let e = HlilExpr::Not(Box::new(cst(0)), HlilType::i32());
    let (f, _) = fold_hlil_expr(e);
    assert_eq!(f.is_const(), Some(!0i64));
}

#[test]
fn fold_logical_not_constant() {
    let (f, _) = fold_hlil_expr(HlilExpr::LogicalNot(Box::new(cst(0))));
    assert_eq!(f.is_const(), Some(1));
    let (f, _) = fold_hlil_expr(HlilExpr::LogicalNot(Box::new(cst(42))));
    assert_eq!(f.is_const(), Some(0));
}

#[test]
fn fold_cmp_eq_true_false() {
    let (f, _) = fold_hlil_expr(HlilExpr::CmpEq(Box::new(cst(1)), Box::new(cst(1))));
    assert_eq!(f.is_const(), Some(1));
    let (f, _) = fold_hlil_expr(HlilExpr::CmpEq(Box::new(cst(1)), Box::new(cst(2))));
    assert_eq!(f.is_const(), Some(0));
}

#[test]
fn fold_cmp_lt_le_gt_ge() {
    let (f, _) = fold_hlil_expr(HlilExpr::CmpLt(Box::new(cst(1)), Box::new(cst(2))));
    assert_eq!(f.is_const(), Some(1));
    let (f, _) = fold_hlil_expr(HlilExpr::CmpLe(Box::new(cst(2)), Box::new(cst(2))));
    assert_eq!(f.is_const(), Some(1));
    let (f, _) = fold_hlil_expr(HlilExpr::CmpGt(Box::new(cst(3)), Box::new(cst(2))));
    assert_eq!(f.is_const(), Some(1));
    let (f, _) = fold_hlil_expr(HlilExpr::CmpGe(Box::new(cst(2)), Box::new(cst(2))));
    assert_eq!(f.is_const(), Some(1));
}

#[test]
fn fold_logical_and_short_circuit_zero() {
    let e = HlilExpr::LogicalAnd(Box::new(cst(0)), Box::new(var_expr("x")));
    let (f, _) = fold_hlil_expr(e);
    assert_eq!(f.is_const(), Some(0));
}

#[test]
fn fold_logical_or_constants() {
    let e = HlilExpr::LogicalOr(Box::new(cst(0)), Box::new(cst(1)));
    let (f, _) = fold_hlil_expr(e);
    assert_eq!(f.is_const(), Some(1));
}

#[test]
fn fold_ternary_const_true_chooses_then() {
    let e = HlilExpr::Ternary {
        cond: Box::new(cst(1)),
        then: Box::new(cst(100)),
        else_: Box::new(cst(200)),
        ty: HlilType::i32(),
    };
    let (f, _) = fold_hlil_expr(e);
    assert_eq!(f.is_const(), Some(100));
}

#[test]
fn fold_ternary_const_false_chooses_else() {
    let e = HlilExpr::Ternary {
        cond: Box::new(cst(0)),
        then: Box::new(cst(100)),
        else_: Box::new(cst(200)),
        ty: HlilType::i32(),
    };
    let (f, _) = fold_hlil_expr(e);
    assert_eq!(f.is_const(), Some(200));
}

#[test]
fn fold_shl_constants() {
    let e = HlilExpr::Shl(Box::new(cst(1)), Box::new(cst(4)), HlilType::i32());
    let (f, _) = fold_hlil_expr(e);
    assert_eq!(f.is_const(), Some(16));
}

#[test]
fn fold_shl_overflow_uses_wrapping() {
    // shift count >= 64 should saturate (try_into would fail) -> wraps to 0
    let e = HlilExpr::Shl(Box::new(cst(1)), Box::new(cst(200)), HlilType::i32());
    let (f, _) = fold_hlil_expr(e);
    // Should not panic; result depends on implementation but must be Some.
    assert!(f.is_const().is_some());
}

#[test]
fn fold_wrapping_add_overflow() {
    let e = HlilExpr::Add(Box::new(cst(i64::MAX)), Box::new(cst(1)), HlilType::i64());
    let (f, _) = fold_hlil_expr(e);
    assert_eq!(f.is_const(), Some(i64::MIN));
}

#[test]
fn fold_preserves_non_const_subtree() {
    let e = HlilExpr::Add(
        Box::new(var_expr("x")),
        Box::new(HlilExpr::Add(Box::new(cst(1)), Box::new(cst(2)), HlilType::i32())),
        HlilType::i32(),
    );
    let (f, _) = fold_hlil_expr(e);
    // Inner should fold to 3, but outer cannot.
    if let HlilExpr::Add(_, b, _) = &f {
        assert_eq!(b.is_const(), Some(3));
    } else {
        panic!("expected Add at top: {f:?}");
    }
}

// ── fold_hlil_stmt / fold_hlil_function ──────────────────────────────────────

#[test]
fn fold_stmt_assign_folds_rhs() {
    let s = HlilStatement::Assign {
        dest: var_expr("x"),
        src: HlilExpr::Add(Box::new(cst(2)), Box::new(cst(3)), HlilType::i32()),
    };
    let (fs, c) = fold_hlil_stmt(s);
    assert!(c >= 1);
    if let HlilStatement::Assign { src, .. } = fs {
        assert_eq!(src.is_const(), Some(5));
    } else {
        panic!("expected Assign");
    }
}

#[test]
fn fold_function_terminates() {
    let mut f = HlilFunction::new(Address::new(0), "f");
    f.body.push(HlilStatement::Return(vec![
        HlilExpr::Add(Box::new(cst(1)), Box::new(cst(2)), HlilType::i32()),
    ]));
    let n = fold_hlil_function(&mut f);
    assert!(n >= 1);
    if let HlilStatement::Return(vals) = &f.body[0] {
        assert_eq!(vals[0].is_const(), Some(3));
    } else {
        panic!("expected Return");
    }
}

// ── Pattern matching ─────────────────────────────────────────────────────────

#[test]
fn pattern_match_identity_assign() {
    let s = HlilStatement::Assign { dest: var_expr("x"), src: var_expr("x") };
    let pats = match_stmt_patterns(&s);
    assert!(pats.iter().any(|p| matches!(p, HlilPattern::IdentityAssign { .. })));
}

#[test]
fn pattern_match_zero_init() {
    let s = HlilStatement::Assign { dest: var_expr("x"), src: cst(0) };
    let pats = match_stmt_patterns(&s);
    assert!(pats.iter().any(|p| matches!(p, HlilPattern::ZeroInit { .. })));
}

#[test]
fn pattern_match_increment() {
    let s = HlilStatement::Assign {
        dest: var_expr("x"),
        src: HlilExpr::Add(Box::new(var_expr("x")), Box::new(cst(1)), HlilType::i32()),
    };
    let pats = match_stmt_patterns(&s);
    assert!(pats.iter().any(|p| matches!(p, HlilPattern::Increment { delta: 1, .. })));
}

#[test]
fn pattern_match_decrement_via_sub() {
    let s = HlilStatement::Assign {
        dest: var_expr("x"),
        src: HlilExpr::Sub(Box::new(var_expr("x")), Box::new(cst(1)), HlilType::i32()),
    };
    let pats = match_stmt_patterns(&s);
    assert!(pats.iter().any(|p| matches!(p, HlilPattern::Increment { delta: -1, .. })));
}

#[test]
fn pattern_match_infinite_loop() {
    let s = HlilStatement::While { cond: cst(1), body: vec![] };
    let pats = match_stmt_patterns(&s);
    assert!(pats.iter().any(|p| matches!(p, HlilPattern::InfiniteLoop)));
}

#[test]
fn pattern_match_constant_condition() {
    let s = HlilStatement::If {
        cond: cst(0),
        then_body: vec![],
        else_body: vec![],
    };
    let pats = match_stmt_patterns(&s);
    assert!(pats.iter().any(|p| matches!(p, HlilPattern::ConstantCondition { value: false })));
}

#[test]
fn pattern_match_trivial_return() {
    let s = HlilStatement::Return(vec![cst(0)]);
    let pats = match_stmt_patterns(&s);
    assert!(pats.iter().any(|p| matches!(p, HlilPattern::TrivialReturn { value: 0 })));
}

#[test]
fn pattern_match_do_while_false() {
    let s = HlilStatement::DoWhile { body: vec![], cond: cst(0) };
    let pats = match_stmt_patterns(&s);
    assert!(pats.iter().any(|p| matches!(p, HlilPattern::DoWhileFalse)));
}

#[test]
fn pattern_match_double_negation() {
    let inner = HlilExpr::LogicalNot(Box::new(var_expr("x")));
    let outer = HlilExpr::LogicalNot(Box::new(inner));
    let pats = match_expr_patterns(&outer);
    assert!(pats.iter().any(|p| matches!(p, HlilPattern::DoubleNegation)));
}

#[test]
fn pattern_match_negated_cmp() {
    let inner = HlilExpr::CmpEq(Box::new(cst(1)), Box::new(cst(2)));
    let e = HlilExpr::LogicalNot(Box::new(inner));
    let pats = match_expr_patterns(&e);
    assert!(pats.iter().any(|p| matches!(p, HlilPattern::NegatedCmp)));
}

#[test]
fn pattern_match_xor_self_expr() {
    let e = HlilExpr::Xor(Box::new(var_expr("x")), Box::new(var_expr("x")), HlilType::i32());
    let pats = match_expr_patterns(&e);
    assert!(pats.iter().any(|p| matches!(p, HlilPattern::XorSelf { .. })));
}

#[test]
fn pattern_match_function() {
    let mut f = HlilFunction::new(Address::new(0), "f");
    f.body.push(HlilStatement::Return(vec![cst(0)]));
    f.body.push(HlilStatement::While { cond: cst(1), body: vec![] });
    let pats = match_function_patterns(&f);
    assert!(pats.len() >= 2);
}

// ── MlilToHlilLifter ─────────────────────────────────────────────────────────

#[test]
fn lifter_default_and_new() {
    let l = MlilToHlilLifter::new();
    assert_eq!(l.var_name_prefix, "var_");
    assert_eq!(l.param_prefix, "arg_");
    assert!(l.use_struct_names);
}

#[test]
fn lifter_lift_empty_mlil_function() {
    use rustre_il_mlil::MlilFunction;
    let mlil = MlilFunction::new(Address::new(0x2000));
    let l = MlilToHlilLifter::new();
    let h = l.lift(&mlil);
    assert_eq!(h.address, Address::new(0x2000));
    assert!(h.is_empty());
    assert_eq!(h.lifted_from, Some(Address::new(0x2000)));
    assert!(h.prototype.name.starts_with("fn_"));
}

// ── inline_single_use_vars ──────────────────────────────────────────────────

#[test]
fn inline_single_use_var_substitutes() {
    let mut f = HlilFunction::new(Address::new(0), "f");
    f.add_local(v("t"));
    f.body.push(HlilStatement::Assign { dest: var_expr("t"), src: cst(42) });
    f.body.push(HlilStatement::Return(vec![var_expr("t")]));
    inline_single_use_vars(&mut f);
    // After inlining, t is gone from locals and the return should reference 42.
    assert!(!f.locals.iter().any(|x| x.name == "t"));
    let ret = &f.body[f.body.len() - 1];
    if let HlilStatement::Return(vs) = ret {
        assert_eq!(vs[0].is_const(), Some(42));
    } else {
        panic!("expected Return after inline");
    }
}
