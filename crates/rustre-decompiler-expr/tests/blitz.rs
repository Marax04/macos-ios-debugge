//! External integration tests targeting the public API of
//! `rustre-decompiler-expr`. Aim: surface bugs in simplification,
//! folding, evaluation, pattern matching, and printing.

use std::collections::HashMap;

use rustre_decompiler_expr::*;

const fn c(v: i64) -> Expr { Expr::Const(v, IntWidth::I64) }
const fn cw(v: i64, w: IntWidth) -> Expr { Expr::Const(v, w) }
fn var(n: &str) -> Expr { Expr::Var(n.to_string()) }
fn bo(op: BinOp, a: Expr, b: Expr) -> Expr { Expr::BinOp(op, Box::new(a), Box::new(b)) }
fn uo(op: UnOp, e: Expr) -> Expr { Expr::UnOp(op, Box::new(e)) }

// ── IntWidth boundaries ───────────────────────────────────────────────────

#[test]
fn intwidth_bits_byte_relation() {
    for w in [IntWidth::I8, IntWidth::I16, IntWidth::I32, IntWidth::I64,
              IntWidth::U8, IntWidth::U16, IntWidth::U32, IntWidth::U64] {
        assert_eq!(w.bits(), w.bytes() * 8);
    }
}

#[test]
fn intwidth_to_signed_unsigned_roundtrip() {
    for w in [IntWidth::I8, IntWidth::I16, IntWidth::I32, IntWidth::I64] {
        assert_eq!(w.to_unsigned().to_signed(), w);
    }
    for w in [IntWidth::U8, IntWidth::U16, IntWidth::U32, IntWidth::U64] {
        assert_eq!(w.to_signed().to_unsigned(), w);
    }
}

#[test]
fn intwidth_max_u64_exact_for_u64() {
    assert_eq!(IntWidth::U64.max_value_u64(), u64::MAX);
    assert_eq!(IntWidth::U32.max_value_u64(), u64::from(u32::MAX));
}

#[test]
fn intwidth_max_value_clamps_u64() {
    // Documented behavior: max_value clamps U64 to i64::MAX.
    assert_eq!(IntWidth::U64.max_value(), i64::MAX);
    assert_eq!(IntWidth::I64.max_value(), i64::MAX);
}

#[test]
fn intwidth_min_value_unsigned_is_zero() {
    for w in [IntWidth::U8, IntWidth::U16, IntWidth::U32, IntWidth::U64] {
        assert_eq!(w.min_value(), 0);
    }
}

#[test]
fn intwidth_cname_all_variants() {
    assert_eq!(int_width_cname(IntWidth::I8), "int8_t");
    assert_eq!(int_width_cname(IntWidth::I16), "int16_t");
    assert_eq!(int_width_cname(IntWidth::I32), "int32_t");
    assert_eq!(int_width_cname(IntWidth::I64), "int64_t");
    assert_eq!(int_width_cname(IntWidth::U8), "uint8_t");
    assert_eq!(int_width_cname(IntWidth::U16), "uint16_t");
    assert_eq!(int_width_cname(IntWidth::U32), "uint32_t");
    assert_eq!(int_width_cname(IntWidth::U64), "uint64_t");
}

// ── BinOp invariants ──────────────────────────────────────────────────────

#[test]
fn binop_negated_round_trip() {
    for op in [BinOp::Eq, BinOp::Ne, BinOp::Lt, BinOp::Le, BinOp::Gt, BinOp::Ge] {
        let n = op.negated().unwrap();
        assert_eq!(n.negated().unwrap(), op, "double-negate failed for {op:?}");
    }
}

#[test]
fn binop_swapped_round_trip() {
    for op in [BinOp::Lt, BinOp::Le, BinOp::Gt, BinOp::Ge] {
        let s = op.swapped().unwrap();
        assert_eq!(s.swapped().unwrap(), op);
    }
}

#[test]
fn binop_non_swappable() {
    for op in [BinOp::Add, BinOp::Sub, BinOp::Mul, BinOp::Eq, BinOp::Ne, BinOp::LAnd, BinOp::LOr] {
        assert!(op.swapped().is_none() || !matches!(op, BinOp::Eq | BinOp::Ne));
    }
    // Add explicitly cannot be swapped (it returns None even though it IS commutative).
    assert_eq!(BinOp::Add.swapped(), None);
}

#[test]
fn binop_arith_bitwise_logical_disjoint() {
    for op in [BinOp::Add, BinOp::Sub, BinOp::Mul, BinOp::Div, BinOp::Mod,
               BinOp::And, BinOp::Or, BinOp::Xor, BinOp::Shl, BinOp::Shr, BinOp::Sar,
               BinOp::Eq, BinOp::Ne, BinOp::Lt, BinOp::Le, BinOp::Gt, BinOp::Ge,
               BinOp::LAnd, BinOp::LOr] {
        let arith = op.is_arithmetic();
        let bit = op.is_bitwise();
        let log = op.is_logical();
        let cmp = op.is_comparison();
        let count = [arith, bit, log, cmp].iter().filter(|x| **x).count();
        assert!(count <= 1, "op {op:?} classified as multiple categories");
    }
}

#[test]
fn binop_display_matches_as_str() {
    for op in [BinOp::Add, BinOp::Mul, BinOp::Eq, BinOp::LAnd] {
        assert_eq!(op.to_string(), op.as_str());
    }
}

// ── Constant folding edge cases ───────────────────────────────────────────

#[test]
fn simplify_div_by_zero_not_folded() {
    let e = bo(BinOp::Div, c(10), c(0));
    let r = ExprSimplifier::new().simplify(e);
    // Should NOT fold to a panic or bogus const; should remain as-is or be a BinOp.
    assert!(matches!(r, Expr::BinOp(BinOp::Div, _, _)),
            "div-by-zero must not be constant-folded, got {r:?}");
}

#[test]
fn simplify_mod_by_zero_not_folded() {
    let e = bo(BinOp::Mod, c(10), c(0));
    let r = ExprSimplifier::new().simplify(e);
    assert!(matches!(r, Expr::BinOp(BinOp::Mod, _, _)));
}

#[test]
fn simplify_shift_out_of_range_not_folded() {
    let e = bo(BinOp::Shl, c(1), c(64));
    let r = ExprSimplifier::new().simplify(e);
    assert!(matches!(r, Expr::BinOp(BinOp::Shl, _, _)),
            "shift >= 64 must not be folded, got {r:?}");
}

#[test]
fn simplify_negative_shift_not_folded() {
    let e = bo(BinOp::Shr, c(8), c(-1));
    let r = ExprSimplifier::new().simplify(e);
    assert!(matches!(r, Expr::BinOp(BinOp::Shr, _, _)));
}

#[test]
fn simplify_wrapping_add_overflow() {
    let e = bo(BinOp::Add, c(i64::MAX), c(1));
    let r = ExprSimplifier::new().simplify(e);
    assert_eq!(r.as_const(), Some(i64::MIN));
}

#[test]
fn simplify_wrapping_mul_overflow() {
    let e = bo(BinOp::Mul, c(i64::MAX), c(2));
    let r = ExprSimplifier::new().simplify(e);
    assert_eq!(r.as_const(), Some(-2));
}

// ── Algebraic identities ──────────────────────────────────────────────────

#[test]
fn simplify_add_zero_left() {
    let e = bo(BinOp::Add, c(0), var("x"));
    assert_eq!(ExprSimplifier::new().simplify(e), var("x"));
}

#[test]
fn simplify_mul_zero_left() {
    let e = bo(BinOp::Mul, c(0), var("x"));
    let r = ExprSimplifier::new().simplify(e);
    assert_eq!(r.as_const(), Some(0));
}

#[test]
fn simplify_and_all_ones() {
    let e = bo(BinOp::And, var("x"), c(-1));
    assert_eq!(ExprSimplifier::new().simplify(e), var("x"));
}

#[test]
fn simplify_or_all_ones() {
    let e = bo(BinOp::Or, var("x"), c(-1));
    assert_eq!(ExprSimplifier::new().simplify(e).as_const(), Some(-1));
}

#[test]
fn simplify_xor_all_ones_becomes_not() {
    let e = bo(BinOp::Xor, var("x"), c(-1));
    let r = ExprSimplifier::new().simplify(e);
    assert_eq!(r, uo(UnOp::Not, var("x")));
}

#[test]
fn simplify_shift_zero_amount() {
    let e = bo(BinOp::Shl, var("x"), c(0));
    assert_eq!(ExprSimplifier::new().simplify(e), var("x"));
}

// ── Mul-by-side-effect must not annihilate to 0 ────────────────────────────

#[test]
fn simplify_mul_zero_with_call_side_effect_preserved() {
    // f() * 0 must not become 0 because the call has side effects.
    let call = Expr::Call { callee: Box::new(var("f")), args: vec![] };
    let e = bo(BinOp::Mul, call, c(0));
    let r = ExprSimplifier::new().simplify(e);
    // Currently the implementation drops the call. This is a real semantic bug.
    let dropped_call = matches!(r, Expr::Const(0, _));
    assert!(!dropped_call,
            "BUG: x*0 dropped side-effecting call. Got {r:?}");
}

#[test]
fn simplify_and_zero_with_load_side_effect_preserved() {
    let load = Expr::Load { ptr: Box::new(var("p")), size: 4 };
    let e = bo(BinOp::And, load, c(0));
    let r = ExprSimplifier::new().simplify(e);
    let dropped = matches!(r, Expr::Const(0, _));
    assert!(!dropped, "BUG: x&0 dropped side-effecting load. Got {r:?}");
}

// ── Unary fold ────────────────────────────────────────────────────────────

#[test]
fn simplify_neg_i64_min() {
    let e = uo(UnOp::Neg, c(i64::MIN));
    let r = ExprSimplifier::new().simplify(e);
    // wrapping_neg(i64::MIN) == i64::MIN
    assert_eq!(r.as_const(), Some(i64::MIN));
}

#[test]
fn simplify_not_const() {
    let e = uo(UnOp::Not, c(0));
    assert_eq!(ExprSimplifier::new().simplify(e).as_const(), Some(-1));
}

#[test]
fn simplify_lnot_nonzero() {
    let e = uo(UnOp::LNot, c(42));
    assert_eq!(ExprSimplifier::new().simplify(e).as_const(), Some(0));
}

#[test]
fn simplify_cast_truncate_u8() {
    // 0x1FF cast to U8 should become 0xFF.
    let e = uo(UnOp::Cast(IntWidth::U8), c(0x1FF));
    let r = ExprSimplifier::new().simplify(e);
    assert_eq!(r.as_const(), Some(0xFF));
}

#[test]
fn simplify_cast_truncate_i8_sign_extend() {
    // 0xFF cast to I8 should sign-extend to -1.
    let e = uo(UnOp::Cast(IntWidth::I8), c(0xFF));
    let r = ExprSimplifier::new().simplify(e);
    assert_eq!(r.as_const(), Some(-1));
}

// ── De Morgan ─────────────────────────────────────────────────────────────

#[test]
fn demorgan_disabled_preserves() {
    let e = bo(BinOp::LOr, uo(UnOp::LNot, var("a")), uo(UnOp::LNot, var("b")));
    let s = ExprSimplifier::without_demorgan().simplify(e);
    assert!(matches!(s, Expr::BinOp(BinOp::LOr, _, _)));
}

// ── ExprFolder ────────────────────────────────────────────────────────────

#[test]
fn folder_propagates_through_multiple_levels() {
    let assigns = vec![
        SsaAssign::new("a", c(1)),
        SsaAssign::new("b", bo(BinOp::Add, var("a"), c(2))),
        SsaAssign::new("c", bo(BinOp::Mul, var("b"), c(3))),
    ];
    let f = ExprFolder::with_assignments(&assigns);
    let result = f.fold_expressions(&assigns).unwrap();
    // c should still exist (it's the final result), but a and b may be inlined.
    assert!(result.iter().any(|a| a.name == "c"));
}

#[test]
fn folder_phi_in_nested_position() {
    let assigns = vec![SsaAssign::new(
        "x",
        bo(BinOp::Add, Expr::Phi(vec![c(0), c(1)]), c(2)),
    )];
    let f = ExprFolder::with_assignments(&assigns);
    let r = f.fold_expressions(&assigns);
    assert!(matches!(r, Err(ExprError::PhiNotEliminated)));
}

#[test]
fn folder_empty_input() {
    let f = ExprFolder::new();
    let r = f.fold_expressions(&[]).unwrap();
    assert!(r.is_empty());
}

// ── ExprNormalizer ────────────────────────────────────────────────────────

#[test]
fn normalizer_idempotent() {
    let n = ExprNormalizer::new();
    let e = bo(BinOp::Add, c(5), var("x"));
    let once = n.normalize(e);
    let twice = n.normalize(once.clone());
    assert_eq!(once, twice);
}

#[test]
fn normalizer_ge_to_le() {
    let n = ExprNormalizer::new();
    let e = bo(BinOp::Ge, var("x"), var("y"));
    assert_eq!(n.normalize(e), bo(BinOp::Le, var("y"), var("x")));
}

// ── ExprComparator ────────────────────────────────────────────────────────

#[test]
fn comparator_similarity_disjoint() {
    let cmp = ExprComparator::new();
    let a = var("x");
    let b = var("y");
    let s = cmp.similarity(&a, &b);
    assert!((0.0..=1.0).contains(&s));
}

#[test]
fn comparator_equivalent_commutative() {
    let cmp = ExprComparator::new();
    let a = bo(BinOp::Add, c(5), var("x"));
    let b = bo(BinOp::Add, var("x"), c(5));
    assert!(cmp.equivalent(&a, &b));
}

// ── ExprPrinter ───────────────────────────────────────────────────────────

#[test]
fn printer_full_parens() {
    let opts = ExprPrintOptions { full_parens: true, emit_casts: true };
    let p = ExprPrinter::with_options(opts);
    let e = bo(BinOp::Add, var("a"), var("b"));
    let s = p.print(&e);
    assert!(s.contains('(') && s.contains(')'));
}

#[test]
fn printer_precedence_no_parens_for_mul_in_add() {
    let p = ExprPrinter::new();
    // a + b * c — no parens around b*c needed
    let e = bo(BinOp::Add, var("a"), bo(BinOp::Mul, var("b"), var("c")));
    let s = p.print(&e);
    assert_eq!(s, "a + b * c");
}

#[test]
fn printer_precedence_parens_for_add_in_mul() {
    let p = ExprPrinter::new();
    // (a + b) * c — parens needed
    let e = bo(BinOp::Mul, bo(BinOp::Add, var("a"), var("b")), var("c"));
    let s = p.print(&e);
    assert!(s.contains('('), "expected parens for low-prec child of *, got {s}");
}

#[test]
fn printer_const_negative_large() {
    let p = ExprPrinter::new();
    let s = p.print(&cw(-0x10000, IntWidth::I64));
    assert!(s.contains("-0x"));
}

#[test]
fn printer_cast_emit() {
    let p = ExprPrinter::new();
    let s = p.print(&uo(UnOp::Cast(IntWidth::U32), var("x")));
    assert_eq!(s, "(uint32_t)x");
}

#[test]
fn printer_cast_suppress() {
    let opts = ExprPrintOptions { full_parens: false, emit_casts: false };
    let p = ExprPrinter::with_options(opts);
    let s = p.print(&uo(UnOp::Cast(IntWidth::U32), var("x")));
    assert_eq!(s, "x");
}

#[test]
fn printer_ternary() {
    let p = ExprPrinter::new();
    let e = Expr::Ternary {
        cond: Box::new(var("c")),
        then_expr: Box::new(var("t")),
        else_expr: Box::new(var("e")),
    };
    let s = p.print(&e);
    assert!(s.contains('?') && s.contains(':'));
}

#[test]
fn printer_phi() {
    let p = ExprPrinter::new();
    let e = Expr::Phi(vec![var("a"), var("b")]);
    let s = p.print(&e);
    assert!(s.starts_with("phi("));
}

#[test]
fn printer_load() {
    let p = ExprPrinter::new();
    let e = Expr::Load { ptr: Box::new(var("p")), size: 4 };
    let s = p.print(&e);
    assert!(s.contains("uint32_t"));
}

// ── ExprPattern ───────────────────────────────────────────────────────────

#[test]
fn pattern_extract_array_index_shl() {
    let e = bo(BinOp::Add, var("arr"), bo(BinOp::Shl, var("i"), c(3)));
    let r = ExprPattern::extract_array_index(&e);
    let (_, _, scale) = r.unwrap();
    assert_eq!(scale, 8);
}

#[test]
fn pattern_extract_array_index_no_match() {
    let e = bo(BinOp::Sub, var("a"), var("b"));
    assert!(ExprPattern::extract_array_index(&e).is_none());
}

#[test]
fn pattern_is_deref_load() {
    let e = Expr::Load { ptr: Box::new(var("p")), size: 4 };
    assert!(ExprPattern::is_deref(&e));
}

#[test]
fn pattern_is_binop_var_const_negative() {
    let e = bo(BinOp::Add, c(1), var("x")); // reversed
    assert!(!ExprPattern::is_binop_var_const(&e));
}

// ── DefUseChain ───────────────────────────────────────────────────────────

#[test]
fn defuse_unknown_var() {
    let c = DefUseChain::new();
    assert_eq!(c.def_count("nope"), 0);
    assert_eq!(c.use_count("nope"), 0);
    assert!(!c.is_dead("nope"));
}

#[test]
fn defuse_dead_with_undefined_use() {
    let assigns = vec![SsaAssign::new("x", var("y"))]; // y referenced, never defined
    let chain = DefUseChain::from_assignments(&assigns);
    assert_eq!(chain.use_count("y"), 1);
    assert_eq!(chain.def_count("y"), 0);
}

// ── ExprEvaluator ─────────────────────────────────────────────────────────

#[test]
fn evaluator_div_by_zero() {
    let ev = ExprEvaluator::new();
    let e = bo(BinOp::Div, c(1), c(0));
    let r = ev.eval(&e, &HashMap::new());
    assert!(matches!(r, Err(ExprError::DivisionByZero)));
}

#[test]
fn evaluator_unop_cast_truncates() {
    let ev = ExprEvaluator::new();
    let e = uo(UnOp::Cast(IntWidth::U8), c(0x1FF));
    assert_eq!(ev.eval(&e, &HashMap::new()).unwrap(), 0xFF);
}

#[test]
fn evaluator_unop_lnot_zero() {
    let ev = ExprEvaluator::new();
    assert_eq!(ev.eval(&uo(UnOp::LNot, c(0)), &HashMap::new()).unwrap(), 1);
}

#[test]
fn evaluator_nested() {
    let ev = ExprEvaluator::new();
    let e = bo(BinOp::Add, bo(BinOp::Mul, c(3), c(4)), c(5));
    assert_eq!(ev.eval(&e, &HashMap::new()).unwrap(), 17);
}

// ── ExprRewriter ──────────────────────────────────────────────────────────

#[test]
fn rewriter_default_no_rules() {
    let rw = ExprRewriter::default();
    assert_eq!(rw.rule_count(), 0);
}

#[test]
fn rewriter_recurses_into_children() {
    let mut rw = ExprRewriter::new();
    rw.add_rule(|e| {
        if let Expr::Const(v, w) = e { Some(Expr::Const(v + 1, *w)) } else { None }
    });
    let e = bo(BinOp::Add, c(1), c(2));
    let r = rw.rewrite(e);
    if let Expr::BinOp(_, a, b) = r {
        assert_eq!(a.as_const(), Some(2));
        assert_eq!(b.as_const(), Some(3));
    } else { panic!("expected binop"); }
}

#[test]
fn rewriter_debug_contains_count() {
    let mut rw = ExprRewriter::new();
    rw.add_rule(|_| None);
    let s = format!("{rw:?}");
    assert!(s.contains('1'));
}

// ── has_side_effects / is_safe_to_inline ─────────────────────────────────

#[test]
fn side_effects_through_binop() {
    let load = Expr::Load { ptr: Box::new(var("p")), size: 4 };
    let e = bo(BinOp::Add, var("x"), load);
    assert!(has_side_effects(&e));
}

#[test]
fn side_effects_phi_false() {
    let e = Expr::Phi(vec![var("a"), var("b")]);
    assert!(!has_side_effects(&e));
}

#[test]
fn safe_to_inline_zero_uses() {
    let assigns = vec![SsaAssign::new("t", c(42))];
    let chain = DefUseChain::from_assignments(&assigns);
    assert!(is_safe_to_inline(&c(42), "t", &chain));
}

#[test]
fn safe_to_inline_multi_use_with_side_effects() {
    // Define t with a Load (side effects), and use it twice. Must NOT inline.
    let load = Expr::Load { ptr: Box::new(var("p")), size: 4 };
    let assigns = vec![
        SsaAssign::new("t", load.clone()),
        SsaAssign::new("a", var("t")),
        SsaAssign::new("b", var("t")),
    ];
    let chain = DefUseChain::from_assignments(&assigns);
    assert!(!is_safe_to_inline(&load, "t", &chain));
}

// ── Substitution ──────────────────────────────────────────────────────────

#[test]
fn substitute_in_call_args() {
    let e = Expr::Call { callee: Box::new(var("f")), args: vec![var("x"), c(1)] };
    let r = e.substitute("x", &c(99));
    if let Expr::Call { args, .. } = r {
        assert_eq!(args[0].as_const(), Some(99));
    } else { panic!(); }
}

#[test]
fn substitute_no_match_unchanged() {
    let e = bo(BinOp::Add, var("a"), var("b"));
    assert_eq!(e.clone().substitute("z", &c(0)), e);
}

#[test]
fn substitute_in_phi() {
    let e = Expr::Phi(vec![var("x"), c(1)]);
    let r = e.substitute("x", &c(42));
    if let Expr::Phi(items) = r {
        assert_eq!(items[0].as_const(), Some(42));
    } else { panic!(); }
}

// ── Round trips ───────────────────────────────────────────────────────────

#[test]
fn serde_roundtrip_expr() {
    let e = bo(BinOp::Add, var("x"), c(42));
    let s = serde_json::to_string(&e).unwrap();
    let back: Expr = serde_json::from_str(&s).unwrap();
    assert_eq!(e, back);
}

#[test]
fn const_width_preserved_in_clone() {
    let e = cw(7, IntWidth::U16);
    let cloned = e;
    assert_eq!(cloned.const_width(), Some(IntWidth::U16));
}

// ── Hash/Eq invariants ────────────────────────────────────────────────────

#[test]
fn intwidth_hash_eq_consistency() {
    use std::collections::HashSet;
    let mut s: HashSet<IntWidth> = HashSet::new();
    s.insert(IntWidth::I32);
    assert!(s.contains(&IntWidth::I32));
    assert!(!s.contains(&IntWidth::U32));
}

// ── Send + Sync ───────────────────────────────────────────────────────────

#[test]
fn rewriter_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ExprRewriteRule>();
}

// ── Ternary corner cases ──────────────────────────────────────────────────

#[test]
fn ternary_negative_cond_truthy() {
    // C semantics: nonzero is truthy. -1 should pick then-branch.
    let e = Expr::Ternary {
        cond: Box::new(c(-1)),
        then_expr: Box::new(var("a")),
        else_expr: Box::new(var("b")),
    };
    assert_eq!(ExprSimplifier::new().simplify(e), var("a"));
}

// ── ConstantFolder / StrengthReducer (free functions) ────────────────────

#[test]
fn constant_folder_fold_count() {
    let mut f = ConstantFolder::new();
    let e = bo(BinOp::Add, c(1), c(2));
    let r = f.fold(e);
    assert_eq!(r.as_const(), Some(3));
    assert_eq!(f.fold_count(), 1);
}

#[test]
fn strength_reducer_mul_to_shl() {
    let mut sr = StrengthReducer::new();
    let e = bo(BinOp::Mul, var("x"), c(8));
    let r = sr.reduce(e);
    assert!(matches!(r, Expr::BinOp(BinOp::Shl, _, _)));
    assert_eq!(sr.reductions(), 1);
}

#[test]
fn strength_reducer_div_to_shr() {
    let mut sr = StrengthReducer::new();
    let e = bo(BinOp::Div, var("x"), c(16));
    let r = sr.reduce(e);
    assert!(matches!(r, Expr::BinOp(BinOp::Shr, _, _)));
}

#[test]
fn strength_reducer_mod_to_and() {
    let mut sr = StrengthReducer::new();
    let e = bo(BinOp::Mod, var("x"), c(8));
    let r = sr.reduce(e);
    if let Expr::BinOp(BinOp::And, _, mask) = r {
        assert_eq!(mask.as_const(), Some(7));
    } else { panic!("expected And, got something else"); }
}

#[test]
fn strength_reducer_non_power_of_two_unchanged() {
    let mut sr = StrengthReducer::new();
    let e = bo(BinOp::Mul, var("x"), c(3));
    let r = sr.reduce(e);
    assert!(matches!(r, Expr::BinOp(BinOp::Mul, _, _)));
}

// ── BitwidthAnalyzer ──────────────────────────────────────────────────────

#[test]
fn bitwidth_zero_const() {
    let bwa = BitwidthAnalyzer::new();
    assert_eq!(bwa.min_bits(&c(0)), 1);
}

#[test]
fn bitwidth_and_with_mask() {
    let bwa = BitwidthAnalyzer::new();
    let e = bo(BinOp::And, var("x"), c(0xFF));
    assert_eq!(bwa.min_bits(&e), 8);
}

#[test]
fn bitwidth_infer_width_u8() {
    let bwa = BitwidthAnalyzer::new();
    let e = bo(BinOp::And, var("x"), c(0xFF));
    assert_eq!(bwa.infer_width(&e), IntWidth::U8);
}

#[test]
fn bitwidth_var_full_width() {
    let bwa = BitwidthAnalyzer::new();
    assert_eq!(bwa.min_bits(&var("x")), 64);
}

// ── SignednessInference ───────────────────────────────────────────────────

#[test]
fn signedness_negative_const() {
    let s = SignednessInference::new();
    assert!(s.is_likely_signed(&c(-1)));
}

#[test]
fn signedness_sar_is_signed() {
    let s = SignednessInference::new();
    let e = bo(BinOp::Sar, var("x"), c(2));
    assert!(s.is_likely_signed(&e));
}

#[test]
fn signedness_unsigned_default() {
    let s = SignednessInference::new();
    assert!(!s.is_likely_signed(&var("x")));
}

#[test]
fn signedness_infer_returns_signed_for_neg_const() {
    let s = SignednessInference::new();
    let w = s.infer_signedness(&c(-1));
    assert!(w.is_signed());
}

// ── CommonSubexprElim ─────────────────────────────────────────────────────

#[test]
fn cse_dedupe_same_expression() {
    let mut cse = CommonSubexprElim::new();
    let e1 = bo(BinOp::Add, var("a"), var("b"));
    let e2 = bo(BinOp::Add, var("a"), var("b"));
    let n1 = cse.register(&e1);
    let n2 = cse.register(&e2);
    assert_eq!(n1, n2);
    assert_eq!(cse.substitutions(), 1);
    assert_eq!(cse.cse_count(), 1);
}

#[test]
fn cse_distinct_expressions_get_distinct_names() {
    let mut cse = CommonSubexprElim::new();
    let n1 = cse.register(&var("a"));
    let n2 = cse.register(&var("b"));
    assert_ne!(n1, n2);
    assert_eq!(cse.cse_count(), 2);
}

// ── CopyPropagation ───────────────────────────────────────────────────────

#[test]
fn copyprop_replaces_var() {
    let mut cp = CopyPropagation::new();
    cp.record_copy("x", var("y"));
    let r = cp.propagate(bo(BinOp::Add, var("x"), c(1)));
    assert_eq!(r, bo(BinOp::Add, var("y"), c(1)));
}

#[test]
fn copyprop_count() {
    let mut cp = CopyPropagation::new();
    cp.record_copy("a", var("b"));
    cp.record_copy("c", var("d"));
    assert_eq!(cp.copy_count(), 2);
}

#[test]
fn copyprop_no_match_unchanged() {
    let cp = CopyPropagation::new();
    let e = bo(BinOp::Add, var("a"), c(1));
    assert_eq!(cp.propagate(e.clone()), e);
}

// ── ExprCanonicalizer ─────────────────────────────────────────────────────

#[test]
fn canonicalizer_const_right() {
    let canon = ExprCanonicalizer;
    let e = bo(BinOp::Add, c(5), var("x"));
    let r = canon.canonicalize(e);
    assert_eq!(r, bo(BinOp::Add, var("x"), c(5)));
}

#[test]
fn canonicalizer_vars_sorted() {
    let canon = ExprCanonicalizer;
    let e = bo(BinOp::Add, var("z"), var("a"));
    let r = canon.canonicalize(e);
    if let Expr::BinOp(_, a, b) = r {
        assert_eq!(a.as_var(), Some("a"));
        assert_eq!(b.as_var(), Some("z"));
    } else { panic!(); }
}

// ── expr_precedence module ────────────────────────────────────────────────

#[test]
fn precedence_table_nonempty() {
    let t = expr_precedence::precedence_table();
    assert!(!t.is_empty());
}

#[test]
fn precedence_binop_precedence_consistent_with_binop() {
    // Mul > Add
    let (mul_prec, _) = expr_precedence::binop_precedence(BinOp::Mul);
    let (add_prec, _) = expr_precedence::binop_precedence(BinOp::Add);
    assert!(mul_prec.0 > add_prec.0);
}

#[test]
fn precedence_can_reorder_pure_exprs() {
    let a = bo(BinOp::Add, var("x"), c(1));
    let b = bo(BinOp::Mul, var("y"), c(2));
    assert!(expr_precedence::can_reorder(&a, &b));
}

#[test]
fn precedence_cannot_reorder_call() {
    let a = Expr::Call { callee: Box::new(var("f")), args: vec![] };
    let b = var("y");
    assert!(!expr_precedence::can_reorder(&a, &b));
}

// ── pattern_library ───────────────────────────────────────────────────────

#[test]
fn pattern_descriptors_nonempty() {
    let ds = pattern_library::all_pattern_descriptors();
    assert!(!ds.is_empty());
}

#[test]
fn pattern_matcher_constructible() {
    let _ = pattern_library::PatternMatcher::default();
}

// ── peephole_optimizer ────────────────────────────────────────────────────

#[test]
fn peephole_default_rules_nonempty() {
    let rules = peephole_optimizer::default_rules();
    assert!(!rules.is_empty());
}
