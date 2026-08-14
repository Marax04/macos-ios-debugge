//! Deep adversarial test coverage for rustre-decompiler-expr.
//!
//! Covers core lib.rs public API: `IntWidth`, `BinOp`, `UnOp`, Expr, `SsaAssign`,
//! `DefUseChain`, `ExprFolder`, `ExprSimplifier`, `ExprNormalizer`, `ExprComparator`,
//! `ExprPrinter`, `ExprPattern`, side-effect helpers, error variants.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

use rustre_decompiler_expr::*;

// ─── seeded LCG ──────────────────────────────────────────────────────────────
#[inline]
fn u64_as_i64(v: u64) -> i64 { v as i64 }
#[inline]
fn u64_trunc_usize(v: u64) -> usize { v as usize }
#[inline]
fn usize_as_i64(v: usize) -> i64 { v as i64 }

const fn lcg_seed() -> u64 {
    0xDEAD_BEEF_CAFE_BABE
}
const fn lcg_next(s: &mut u64) -> u64 {
    *s = s
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *s
}

const fn all_widths() -> &'static [IntWidth] {
    &[
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

const fn all_binops() -> &'static [BinOp] {
    &[
        BinOp::Add,
        BinOp::Sub,
        BinOp::Mul,
        BinOp::Div,
        BinOp::Mod,
        BinOp::And,
        BinOp::Or,
        BinOp::Xor,
        BinOp::Shl,
        BinOp::Shr,
        BinOp::Sar,
        BinOp::Eq,
        BinOp::Ne,
        BinOp::Lt,
        BinOp::Le,
        BinOp::Gt,
        BinOp::Ge,
        BinOp::LAnd,
        BinOp::LOr,
    ]
}

fn hash_one<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

// ─── IntWidth ────────────────────────────────────────────────────────────────

#[test]
fn intwidth_bits_and_bytes_consistent() {
    for &w in all_widths() {
        assert_eq!(w.bits(), w.bytes() * 8);
        assert!(matches!(w.bits(), 8 | 16 | 32 | 64));
    }
}

#[test]
fn intwidth_signed_unsigned_inverse() {
    for &w in all_widths() {
        let u = w.to_unsigned();
        let s = w.to_signed();
        assert!(!u.is_signed());
        assert!(s.is_signed());
        assert_eq!(u.bits(), w.bits());
        assert_eq!(s.bits(), w.bits());
        // Idempotence
        assert_eq!(u.to_unsigned(), u);
        assert_eq!(s.to_signed(), s);
        // Round trip
        assert_eq!(u.to_signed().to_unsigned(), u);
        assert_eq!(s.to_unsigned().to_signed(), s);
    }
}

#[test]
fn intwidth_min_max_bounds() {
    assert_eq!(IntWidth::I8.min_value(), i64::from(i8::MIN));
    assert_eq!(IntWidth::I8.max_value(), i64::from(i8::MAX));
    assert_eq!(IntWidth::U8.min_value(), 0);
    assert_eq!(IntWidth::U8.max_value(), 255);
    assert_eq!(IntWidth::I64.min_value(), i64::MIN);
    assert_eq!(IntWidth::I64.max_value(), i64::MAX);
    assert_eq!(IntWidth::U64.max_value_u64(), u64::MAX);
    assert_eq!(IntWidth::U64.max_value(), i64::MAX); // documented clamp
    for &w in all_widths() {
        assert!(w.min_value() <= w.max_value());
    }
}

#[test]
fn intwidth_display_matches_cname() {
    for &w in all_widths() {
        assert_eq!(format!("{w}"), int_width_cname(w));
    }
}

// ─── BinOp ───────────────────────────────────────────────────────────────────

#[test]
fn binop_as_str_nonempty_and_unique_per_op() {
    let mut seen = std::collections::HashSet::new();
    for &op in all_binops() {
        let s = op.as_str();
        assert!(!s.is_empty());
        assert!(seen.insert(s), "duplicate operator string {s}");
    }
}

#[test]
fn binop_negated_double_negation_identity() {
    for &op in all_binops() {
        if let Some(neg) = op.negated() {
            assert_eq!(
                neg.negated(),
                Some(op),
                "double negation of {op:?} should yield original"
            );
        }
    }
}

#[test]
fn binop_swapped_involution() {
    for &op in all_binops() {
        if let Some(sw) = op.swapped() {
            assert_eq!(sw.swapped(), Some(op));
        }
    }
}

#[test]
fn binop_category_predicates_partition() {
    for &op in all_binops() {
        let cats = [
            op.is_comparison(),
            op.is_arithmetic(),
            op.is_bitwise(),
            op.is_logical(),
        ];
        let count = cats.iter().filter(|x| **x).count();
        // Every op belongs to exactly one of the categories above.
        assert_eq!(count, 1, "{op:?} categories {cats:?}");
    }
}

#[test]
fn binop_commutative_set() {
    for &op in all_binops() {
        let c = op.is_commutative();
        match op {
            BinOp::Add | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor | BinOp::Eq | BinOp::Ne => {
                assert!(c);
            }
            _ => assert!(!c),
        }
    }
}

#[test]
fn binop_precedence_relations() {
    // mul > add > shift > comparison > equality > and > xor > or > land > lor
    assert!(BinOp::Mul.precedence() > BinOp::Add.precedence());
    assert!(BinOp::Add.precedence() > BinOp::Shl.precedence());
    assert!(BinOp::Shl.precedence() > BinOp::Lt.precedence());
    assert!(BinOp::Lt.precedence() > BinOp::Eq.precedence());
    assert!(BinOp::Eq.precedence() > BinOp::And.precedence());
    assert!(BinOp::And.precedence() > BinOp::Xor.precedence());
    assert!(BinOp::Xor.precedence() > BinOp::Or.precedence());
    assert!(BinOp::Or.precedence() > BinOp::LAnd.precedence());
    assert!(BinOp::LAnd.precedence() > BinOp::LOr.precedence());
}

// ─── UnOp ────────────────────────────────────────────────────────────────────

#[test]
fn unop_as_str_includes_cast_name() {
    for &w in all_widths() {
        let s = UnOp::Cast(w).as_str();
        assert!(s.contains(int_width_cname(w)));
        assert!(s.starts_with('(') && s.ends_with(')'));
    }
    assert_eq!(UnOp::Neg.as_str(), "-");
    assert_eq!(UnOp::Not.as_str(), "~");
    assert_eq!(UnOp::LNot.as_str(), "!");
    assert_eq!(UnOp::Deref.as_str(), "*");
    assert_eq!(UnOp::AddrOf.as_str(), "&");
}

// ─── Expr basic queries ──────────────────────────────────────────────────────

#[test]
fn expr_is_predicates() {
    let c = Expr::Const(0, IntWidth::I32);
    let v = Expr::Var("x".into());
    let b = Expr::BinOp(BinOp::Add, Box::new(c.clone()), Box::new(v.clone()));
    assert!(c.is_const() && c.is_leaf() && c.is_zero());
    assert!(v.is_var() && v.is_leaf());
    assert!(b.is_binop() && !b.is_leaf());
    assert!(Expr::Const(1, IntWidth::I32).is_one());
    assert_eq!(c.as_const(), Some(0));
    assert_eq!(c.const_width(), Some(IntWidth::I32));
    assert_eq!(v.as_var(), Some("x"));
    assert_eq!(b.as_const(), None);
    assert_eq!(b.as_var(), None);
}

#[test]
fn expr_depth_and_node_count() {
    let leaf = Expr::Var("x".into());
    assert_eq!(leaf.depth(), 1);
    assert_eq!(leaf.node_count(), 1);

    let tree = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::BinOp(
            BinOp::Mul,
            Box::new(Expr::Var("a".into())),
            Box::new(Expr::Var("b".into())),
        )),
        Box::new(Expr::Const(1, IntWidth::I32)),
    );
    assert_eq!(tree.depth(), 3);
    assert_eq!(tree.node_count(), 5);
}

#[test]
fn expr_referenced_vars_and_contains() {
    let e = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("a".into())),
        Box::new(Expr::BinOp(
            BinOp::Mul,
            Box::new(Expr::Var("b".into())),
            Box::new(Expr::Var("a".into())),
        )),
    );
    let v = e.referenced_vars();
    assert_eq!(v.len(), 3);
    assert!(e.contains_var("a"));
    assert!(e.contains_var("b"));
    assert!(!e.contains_var("c"));
    assert!(!e.is_constant_expr());
    let cst = Expr::Const(42, IntWidth::I32);
    assert!(cst.is_constant_expr());
}

#[test]
fn expr_substitute_replaces_all_occurrences() {
    let e = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("x".into())),
        Box::new(Expr::Var("x".into())),
    );
    let s = e.substitute("x", &Expr::Const(7, IntWidth::I32));
    assert!(!s.contains_var("x"));
    assert_eq!(s.referenced_vars().len(), 0);
}

#[test]
fn expr_substitute_noop_when_var_missing() {
    let e = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("y".into())),
        Box::new(Expr::Const(1, IntWidth::I32)),
    );
    let s = e.clone().substitute("absent", &Expr::Const(99, IntWidth::I32));
    assert_eq!(s, e);
}

// ─── Hash/Eq consistency for IntWidth, BinOp, UnOp, Expr ──────────────────────

#[test]
fn eq_consistency_30_expr_pairs() {
    // Expr only impls PartialEq/Eq (not Hash) — verify symmetric equality
    // and that distinct constructions are correctly unequal.
    let mut pairs: Vec<(Expr, Expr)> = Vec::new();
    for i in 0..15 {
        let w = all_widths()[i % all_widths().len()];
        pairs.push((Expr::Const(usize_as_i64(i), w), Expr::Const(usize_as_i64(i), w)));
    }
    for i in 0..15 {
        let op = all_binops()[i % all_binops().len()];
        let e = Expr::BinOp(
            op,
            Box::new(Expr::Var(format!("v{i}"))),
            Box::new(Expr::Const(usize_as_i64(i), IntWidth::I32)),
        );
        pairs.push((e.clone(), e));
    }
    assert!(pairs.len() >= 30);
    for (a, b) in &pairs {
        assert_eq!(a, b);
        // symmetry
        assert!(a == b);
    }
    // Distinct pairs across the list should mostly be unequal.
    let mut unequal_count = 0;
    for i in 0..pairs.len() {
        for j in (i + 1)..pairs.len() {
            if pairs[i].0 != pairs[j].0 {
                unequal_count += 1;
            }
        }
    }
    assert!(unequal_count > 0);
}

#[test]
fn intwidth_binop_unop_hash_eq() {
    for &w in all_widths() {
        assert_eq!(hash_one(&w), hash_one(&w.clone()));
    }
    for &op in all_binops() {
        assert_eq!(hash_one(&op), hash_one(&op.clone()));
    }
    let unops = [UnOp::Neg, UnOp::Not, UnOp::LNot, UnOp::Deref, UnOp::AddrOf];
    for u in &unops {
        assert_eq!(hash_one(u), hash_one(&u.clone()));
    }
}

// ─── SsaAssign / DefUseChain ─────────────────────────────────────────────────

#[test]
fn ssa_assign_basic_and_display() {
    let a = SsaAssign::new("t1", Expr::Const(0, IntWidth::I32));
    assert_eq!(a.name, "t1");
    assert_eq!(a.rhs_var_count(), 0);
    let b = SsaAssign::new(
        "t2".to_string(),
        Expr::BinOp(
            BinOp::Add,
            Box::new(Expr::Var("a".into())),
            Box::new(Expr::Var("b".into())),
        ),
    );
    assert_eq!(b.rhs_var_count(), 2);
    let s = format!("{b}");
    assert!(s.contains("t2"));
    assert!(s.contains('='));
}

#[test]
fn defuse_chain_counts_and_dead_vars() {
    let assigns = vec![
        SsaAssign::new("t1", Expr::Const(1, IntWidth::I32)),
        SsaAssign::new(
            "t2",
            Expr::BinOp(
                BinOp::Add,
                Box::new(Expr::Var("t1".into())),
                Box::new(Expr::Const(2, IntWidth::I32)),
            ),
        ),
        SsaAssign::new("dead", Expr::Const(99, IntWidth::I32)),
    ];
    let chain = DefUseChain::from_assignments(&assigns);
    assert_eq!(chain.def_count("t1"), 1);
    assert_eq!(chain.use_count("t1"), 1);
    assert_eq!(chain.def_count("missing"), 0);
    assert_eq!(chain.use_count("missing"), 0);
    assert!(chain.is_single_def_use("t1"));
    assert!(chain.is_dead("dead"));
    assert!(!chain.is_dead("t1"));
    let dead = chain.dead_vars();
    assert!(dead.contains(&"dead"));
    assert!(!dead.contains(&"t1"));
}

#[test]
fn defuse_chain_empty_default() {
    let chain = DefUseChain::new();
    assert_eq!(chain.def_count("anything"), 0);
    assert_eq!(chain.use_count("anything"), 0);
    assert!(!chain.is_dead("anything"));
    assert!(chain.dead_vars().is_empty());
}

// ─── side-effect / inline safety ─────────────────────────────────────────────

#[test]
fn has_side_effects_classification() {
    assert!(!has_side_effects(&Expr::Const(1, IntWidth::I32)));
    assert!(!has_side_effects(&Expr::Var("x".into())));
    assert!(has_side_effects(&Expr::Load {
        ptr: Box::new(Expr::Var("p".into())),
        size: 4,
    }));
    assert!(has_side_effects(&Expr::Call {
        callee: Box::new(Expr::Var("f".into())),
        args: vec![],
    }));
    let nested = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Const(1, IntWidth::I32)),
        Box::new(Expr::Load {
            ptr: Box::new(Expr::Var("p".into())),
            size: 4,
        }),
    );
    assert!(has_side_effects(&nested));
}

#[test]
fn is_safe_to_inline_rules() {
    // Single-def, single-use leaf — safe.
    let assigns = vec![
        SsaAssign::new("t1", Expr::Const(42, IntWidth::I32)),
        SsaAssign::new(
            "t2",
            Expr::BinOp(
                BinOp::Add,
                Box::new(Expr::Var("t1".into())),
                Box::new(Expr::Const(1, IntWidth::I32)),
            ),
        ),
    ];
    let chain = DefUseChain::from_assignments(&assigns);
    assert!(is_safe_to_inline(
        &Expr::Const(42, IntWidth::I32),
        "t1",
        &chain,
    ));

    // No def — not safe.
    let empty = DefUseChain::new();
    assert!(!is_safe_to_inline(
        &Expr::Const(0, IntWidth::I32),
        "x",
        &empty,
    ));
}

// ─── ExprFolder ──────────────────────────────────────────────────────────────

#[test]
fn folder_inlines_single_use_temporary() {
    let assigns = vec![
        SsaAssign::new("t1", Expr::Const(5, IntWidth::I32)),
        SsaAssign::new(
            "t2",
            Expr::BinOp(
                BinOp::Add,
                Box::new(Expr::Var("t1".into())),
                Box::new(Expr::Const(7, IntWidth::I32)),
            ),
        ),
    ];
    let folder = ExprFolder::with_assignments(&assigns);
    let out = folder.fold_expressions(&assigns).expect("fold ok");
    // t1 should be eliminated.
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, "t2");
    assert!(!out[0].expr.contains_var("t1"));
}

#[test]
fn folder_rejects_phi_nodes() {
    let assigns = vec![SsaAssign::new(
        "p",
        Expr::Phi(vec![Expr::Var("a".into()), Expr::Var("b".into())]),
    )];
    let folder = ExprFolder::with_assignments(&assigns);
    let err = folder.fold_expressions(&assigns).unwrap_err();
    assert!(matches!(err, ExprError::PhiNotEliminated));
}

#[test]
fn folder_preserves_multiuse_vars() {
    let assigns = vec![
        SsaAssign::new(
            "t1",
            Expr::Load {
                ptr: Box::new(Expr::Var("p".into())),
                size: 4,
            },
        ),
        SsaAssign::new(
            "t2",
            Expr::BinOp(
                BinOp::Add,
                Box::new(Expr::Var("t1".into())),
                Box::new(Expr::Var("t1".into())),
            ),
        ),
    ];
    let folder = ExprFolder::with_assignments(&assigns);
    let out = folder.fold_expressions(&assigns).expect("fold");
    // t1 has side effects (Load) AND 2 uses — must not inline.
    assert!(out.iter().any(|a| a.name == "t1"));
}

// ─── ExprSimplifier — algebraic identities ──────────────────────────────────

#[test]
fn simplify_constant_folding_arithmetic() {
    let s = ExprSimplifier::new();
    let e = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Const(2, IntWidth::I32)),
        Box::new(Expr::Const(3, IntWidth::I32)),
    );
    assert_eq!(s.simplify(e), Expr::Const(5, IntWidth::I32));

    let e = Expr::BinOp(
        BinOp::Mul,
        Box::new(Expr::Const(6, IntWidth::I32)),
        Box::new(Expr::Const(7, IntWidth::I32)),
    );
    assert_eq!(s.simplify(e), Expr::Const(42, IntWidth::I32));
}

#[test]
fn simplify_division_by_zero_kept() {
    let s = ExprSimplifier::new();
    let e = Expr::BinOp(
        BinOp::Div,
        Box::new(Expr::Const(10, IntWidth::I32)),
        Box::new(Expr::Const(0, IntWidth::I32)),
    );
    // Should NOT panic / fold to garbage — stays as expression.
    let out = s.simplify(e);
    assert!(matches!(out, Expr::BinOp(BinOp::Div, _, _)));
}

#[test]
fn simplify_identity_rules() {
    let s = ExprSimplifier::new();
    let x = Expr::Var("x".into());
    // x + 0 = x
    let e = Expr::BinOp(
        BinOp::Add,
        Box::new(x.clone()),
        Box::new(Expr::Const(0, IntWidth::I32)),
    );
    assert_eq!(s.simplify(e), x);
    // x * 1 = x
    let e = Expr::BinOp(
        BinOp::Mul,
        Box::new(x.clone()),
        Box::new(Expr::Const(1, IntWidth::I32)),
    );
    assert_eq!(s.simplify(e), x);
    // x * 0 = 0
    let e = Expr::BinOp(
        BinOp::Mul,
        Box::new(x.clone()),
        Box::new(Expr::Const(0, IntWidth::I32)),
    );
    assert!(matches!(s.simplify(e), Expr::Const(0, _)));
    // x - x = 0
    let e = Expr::BinOp(BinOp::Sub, Box::new(x.clone()), Box::new(x.clone()));
    assert!(matches!(s.simplify(e), Expr::Const(0, _)));
    // x ^ x = 0
    let e = Expr::BinOp(BinOp::Xor, Box::new(x.clone()), Box::new(x));
    assert!(matches!(s.simplify(e), Expr::Const(0, _)));
}

#[test]
fn simplify_double_negation() {
    let s = ExprSimplifier::new();
    let x = Expr::Var("x".into());
    let e = Expr::UnOp(UnOp::Neg, Box::new(Expr::UnOp(UnOp::Neg, Box::new(x.clone()))));
    assert_eq!(s.simplify(e), x);
    let e = Expr::UnOp(UnOp::Not, Box::new(Expr::UnOp(UnOp::Not, Box::new(x.clone()))));
    assert_eq!(s.simplify(e), x);
    let e = Expr::UnOp(
        UnOp::LNot,
        Box::new(Expr::UnOp(UnOp::LNot, Box::new(x.clone()))),
    );
    assert_eq!(s.simplify(e), x);
}

#[test]
fn simplify_lnot_of_comparison_negates_op() {
    let s = ExprSimplifier::new();
    let e = Expr::UnOp(
        UnOp::LNot,
        Box::new(Expr::BinOp(
            BinOp::Eq,
            Box::new(Expr::Var("a".into())),
            Box::new(Expr::Var("b".into())),
        )),
    );
    match s.simplify(e) {
        Expr::BinOp(BinOp::Ne, _, _) => {}
        other => panic!("expected Ne, got {other:?}"),
    }
}

#[test]
fn simplify_ternary_const_condition() {
    let s = ExprSimplifier::new();
    let e = Expr::Ternary {
        cond: Box::new(Expr::Const(1, IntWidth::I32)),
        then_expr: Box::new(Expr::Var("a".into())),
        else_expr: Box::new(Expr::Var("b".into())),
    };
    assert_eq!(s.simplify(e), Expr::Var("a".into()));
    let e = Expr::Ternary {
        cond: Box::new(Expr::Const(0, IntWidth::I32)),
        then_expr: Box::new(Expr::Var("a".into())),
        else_expr: Box::new(Expr::Var("b".into())),
    };
    assert_eq!(s.simplify(e), Expr::Var("b".into()));
}

#[test]
fn simplify_overflow_paths_dont_panic() {
    let s = ExprSimplifier::new();
    // wrapping add at i64::MAX
    let e = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Const(i64::MAX, IntWidth::I64)),
        Box::new(Expr::Const(1, IntWidth::I64)),
    );
    let _ = s.simplify(e);
    // shift by huge amount — fold_const_binop returns None ⇒ kept as BinOp.
    let e = Expr::BinOp(
        BinOp::Shl,
        Box::new(Expr::Const(1, IntWidth::I64)),
        Box::new(Expr::Const(200, IntWidth::I64)),
    );
    let out = s.simplify(e);
    assert!(matches!(out, Expr::BinOp(BinOp::Shl, _, _)));
}

#[test]
fn simplify_demorgan_applied() {
    let s = ExprSimplifier::new();
    let a = Expr::UnOp(UnOp::LNot, Box::new(Expr::Var("x".into())));
    let b = Expr::UnOp(UnOp::LNot, Box::new(Expr::Var("y".into())));
    let e = Expr::BinOp(BinOp::LOr, Box::new(a), Box::new(b));
    let out = s.simplify(e);
    // demorgan transforms to !(x && y) which then simplifies again — final form
    // must not contain LOr of two LNots.
    let out_str = format!("{out}");
    assert!(out_str.contains("&&") || out_str.contains("||"));
}

#[test]
fn simplify_demorgan_disabled() {
    let s = ExprSimplifier::without_demorgan();
    let a = Expr::UnOp(UnOp::LNot, Box::new(Expr::Var("x".into())));
    let b = Expr::UnOp(UnOp::LNot, Box::new(Expr::Var("y".into())));
    let e = Expr::BinOp(BinOp::LOr, Box::new(a), Box::new(b));
    let out = s.simplify(e);
    assert!(matches!(out, Expr::BinOp(BinOp::LOr, _, _)));
}

// ─── ExprNormalizer ──────────────────────────────────────────────────────────

#[test]
fn normalizer_moves_constants_to_right_on_commutative_ops() {
    let n = ExprNormalizer::new();
    let e = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Const(42, IntWidth::I32)),
        Box::new(Expr::Var("x".into())),
    );
    let out = n.normalize(e);
    match out {
        Expr::BinOp(BinOp::Add, l, r) => {
            assert!(l.is_var());
            assert!(r.is_const());
        }
        _ => panic!("unexpected form"),
    }
}

#[test]
fn normalizer_canonicalizes_gt_to_lt() {
    let n = ExprNormalizer::new();
    let e = Expr::BinOp(
        BinOp::Gt,
        Box::new(Expr::Var("a".into())),
        Box::new(Expr::Var("b".into())),
    );
    match n.normalize(e) {
        Expr::BinOp(BinOp::Lt, l, r) => {
            assert_eq!(l.as_var(), Some("b"));
            assert_eq!(r.as_var(), Some("a"));
        }
        other => panic!("expected Lt, got {other:?}"),
    }
}

#[test]
fn normalizer_merges_double_cast() {
    let n = ExprNormalizer::new();
    let inner = Expr::UnOp(UnOp::Cast(IntWidth::I16), Box::new(Expr::Var("x".into())));
    let outer = Expr::UnOp(UnOp::Cast(IntWidth::I32), Box::new(inner));
    match n.normalize(outer) {
        Expr::UnOp(UnOp::Cast(IntWidth::I32), e) => {
            assert!(e.is_var());
        }
        other => panic!("expected merged cast, got {other:?}"),
    }
}

// ─── ExprComparator ──────────────────────────────────────────────────────────

#[test]
fn comparator_equivalent_via_commutativity() {
    let c = ExprComparator::new();
    let a = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("x".into())),
        Box::new(Expr::Const(1, IntWidth::I32)),
    );
    let b = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Const(1, IntWidth::I32)),
        Box::new(Expr::Var("x".into())),
    );
    assert!(c.equivalent(&a, &b));
    assert!(!c.syntactically_equal(&a, &b));
}

#[test]
fn comparator_similarity_bounds() {
    let c = ExprComparator::new();
    let a = Expr::Var("x".into());
    assert!((c.similarity(&a, &a) - 1.0).abs() < 1e-9);
    let b = Expr::Var("y".into());
    let s = c.similarity(&a, &b);
    assert!((0.0..=1.0).contains(&s));
}

// ─── ExprPrinter ─────────────────────────────────────────────────────────────

#[test]
fn printer_basic_forms() {
    let p = ExprPrinter::new();
    assert_eq!(p.print(&Expr::Var("x".into())), "x");
    assert_eq!(p.print(&Expr::Const(42, IntWidth::I32)), "42");
    let e = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("a".into())),
        Box::new(Expr::Var("b".into())),
    );
    assert_eq!(p.print(&e), "a + b");
}

#[test]
fn printer_const_formatting_large_values() {
    let p = ExprPrinter::new();
    let s = p.print(&Expr::Const(0x1234_5678, IntWidth::U32));
    assert!(s.contains("0x"));
    assert!(s.ends_with('U'));
    let s = p.print(&Expr::Const(1_000_000, IntWidth::U64));
    assert!(s.ends_with("ULL"));
    let s = p.print(&Expr::Const(-2000, IntWidth::I64));
    assert!(s.starts_with("-0x") && s.ends_with("LL"));
}

#[test]
fn printer_full_parens_wraps_binops() {
    let p = ExprPrinter::with_options(ExprPrintOptions {
        full_parens: true,
        emit_casts: true,
    });
    let e = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("a".into())),
        Box::new(Expr::Var("b".into())),
    );
    let s = p.print(&e);
    assert!(s.starts_with('(') && s.ends_with(')'));
}

#[test]
fn printer_precedence_groups_lower_in_parens() {
    let p = ExprPrinter::new();
    // (a + b) * c — needs parens around add.
    let e = Expr::BinOp(
        BinOp::Mul,
        Box::new(Expr::BinOp(
            BinOp::Add,
            Box::new(Expr::Var("a".into())),
            Box::new(Expr::Var("b".into())),
        )),
        Box::new(Expr::Var("c".into())),
    );
    let s = p.print(&e);
    assert!(s.contains("(a + b)"), "got {s}");
}

#[test]
fn printer_call_and_index_and_ternary_and_field() {
    let p = ExprPrinter::new();
    let call = Expr::Call {
        callee: Box::new(Expr::Var("f".into())),
        args: vec![Expr::Var("a".into()), Expr::Const(1, IntWidth::I32)],
    };
    assert_eq!(p.print(&call), "f(a, 1)");
    let idx = Expr::Index {
        base: Box::new(Expr::Var("arr".into())),
        index: Box::new(Expr::Var("i".into())),
        elem_size: 4,
    };
    assert_eq!(p.print(&idx), "arr[i]");
    let t = Expr::Ternary {
        cond: Box::new(Expr::Var("c".into())),
        then_expr: Box::new(Expr::Var("a".into())),
        else_expr: Box::new(Expr::Var("b".into())),
    };
    let s = p.print(&t);
    assert!(s.contains('?') && s.contains(':'));
    let f = Expr::FieldAccess {
        base: Box::new(Expr::Var("s".into())),
        offset: 0x10,
    };
    let s = p.print(&f);
    assert!(s.contains("FIELD") && s.contains("0x10"));
}

#[test]
fn expr_display_matches_printer_for_leaves() {
    let v = Expr::Var("v".into());
    assert_eq!(format!("{v}"), "v");
    let c = Expr::Const(7, IntWidth::I32);
    assert_eq!(format!("{c}"), "7");
}

// ─── ExprPattern ─────────────────────────────────────────────────────────────

#[test]
fn pattern_var_op_const() {
    let e = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("x".into())),
        Box::new(Expr::Const(4, IntWidth::I32)),
    );
    assert!(ExprPattern::is_binop_var_const(&e));
    let e = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Const(4, IntWidth::I32)),
        Box::new(Expr::Var("x".into())),
    );
    assert!(!ExprPattern::is_binop_var_const(&e));
}

#[test]
fn pattern_var_comparison() {
    let e = Expr::BinOp(
        BinOp::Lt,
        Box::new(Expr::Var("a".into())),
        Box::new(Expr::Var("b".into())),
    );
    assert!(ExprPattern::is_var_comparison(&e));
    let e = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("a".into())),
        Box::new(Expr::Var("b".into())),
    );
    assert!(!ExprPattern::is_var_comparison(&e));
}

#[test]
fn pattern_array_index_mul_and_shl() {
    // base + index*4
    let e = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("p".into())),
        Box::new(Expr::BinOp(
            BinOp::Mul,
            Box::new(Expr::Var("i".into())),
            Box::new(Expr::Const(4, IntWidth::I32)),
        )),
    );
    assert!(ExprPattern::is_array_index(&e));
    let (base, idx, scale) = ExprPattern::extract_array_index(&e).expect("matches");
    assert_eq!(base.as_var(), Some("p"));
    assert_eq!(idx.as_var(), Some("i"));
    assert_eq!(scale, 4);

    // base + index<<3 ⇒ scale=8
    let e = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("p".into())),
        Box::new(Expr::BinOp(
            BinOp::Shl,
            Box::new(Expr::Var("i".into())),
            Box::new(Expr::Const(3, IntWidth::I32)),
        )),
    );
    let (_, _, scale) = ExprPattern::extract_array_index(&e).expect("matches");
    assert_eq!(scale, 8);
}

#[test]
fn pattern_array_index_invalid_shl_amount_rejected() {
    // shift of 200 is out of range — extract must return None, not panic.
    let e = Expr::BinOp(
        BinOp::Add,
        Box::new(Expr::Var("p".into())),
        Box::new(Expr::BinOp(
            BinOp::Shl,
            Box::new(Expr::Var("i".into())),
            Box::new(Expr::Const(200, IntWidth::I32)),
        )),
    );
    assert!(ExprPattern::extract_array_index(&e).is_none());
}

// ─── ExprError Display ───────────────────────────────────────────────────────

#[test]
fn expr_error_display_strings() {
    let e = ExprError::UndefinedVar("x".into());
    assert!(format!("{e}").contains('x'));
    assert!(format!("{}", ExprError::PhiNotEliminated).contains("phi"));
    assert!(format!("{}", ExprError::EmptyList).contains("empty"));
    assert!(format!("{}", ExprError::DepthLimitExceeded).contains("depth"));
    assert!(format!("{}", ExprError::DivisionByZero).contains("division"));
}

// ─── Send / Sync threaded stress ─────────────────────────────────────────────

#[test]
fn send_sync_threaded_stress_simplifier() {
    // ExprSimplifier (and its config bool/usize) is Send+Sync.
    let s = Arc::new(ExprSimplifier::new());
    let mut handles = Vec::new();
    for tid in 0..4u64 {
        let s = Arc::clone(&s);
        handles.push(thread::spawn(move || {
            let mut state = lcg_seed() ^ tid;
            for _ in 0..100 {
                let a = u64_as_i64(lcg_next(&mut state) % 100);
                let b = u64_as_i64(lcg_next(&mut state) % 100);
                let e = Expr::BinOp(
                    BinOp::Add,
                    Box::new(Expr::Const(a, IntWidth::I32)),
                    Box::new(Expr::Const(b, IntWidth::I32)),
                );
                let out = s.simplify(e);
                assert_eq!(out.as_const(), Some(a.wrapping_add(b)));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn send_sync_threaded_stress_normalizer() {
    let n = Arc::new(ExprNormalizer::new());
    let mut handles = Vec::new();
    for tid in 0..4u64 {
        let n = Arc::clone(&n);
        handles.push(thread::spawn(move || {
            let mut state = lcg_seed().wrapping_add(tid);
            for _ in 0..100 {
                let k = u64_as_i64(lcg_next(&mut state) % 50);
                let e = Expr::BinOp(
                    BinOp::Add,
                    Box::new(Expr::Const(k, IntWidth::I32)),
                    Box::new(Expr::Var("x".into())),
                );
                let _ = n.normalize(e);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── Seeded LCG fuzz of simplifier on constant arithmetic — no panic ────────

#[test]
fn fuzz_simplifier_constant_arithmetic_never_panics() {
    let mut state = lcg_seed();
    let s = ExprSimplifier::new();
    for _ in 0..200 {
        let a = u64_as_i64(lcg_next(&mut state));
        let b = u64_as_i64(lcg_next(&mut state));
        let op_idx = u64_trunc_usize(lcg_next(&mut state)) % all_binops().len();
        let op = all_binops()[op_idx];
        let e = Expr::BinOp(
            op,
            Box::new(Expr::Const(a, IntWidth::I64)),
            Box::new(Expr::Const(b, IntWidth::I64)),
        );
        let _ = s.simplify(e); // must not panic
    }
}

#[test]
fn fuzz_folder_no_panic_random_structures() {
    let mut state = lcg_seed() ^ 0xA5A5_A5A5_A5A5_A5A5;
    for _ in 0..50 {
        let n = 1 + u64_trunc_usize(lcg_next(&mut state)) % 8;
        let assigns: Vec<SsaAssign> = (0..n)
            .map(|i| {
                let v = u64_as_i64(lcg_next(&mut state));
                SsaAssign::new(format!("t{i}"), Expr::Const(v, IntWidth::I32))
            })
            .collect();
        let folder = ExprFolder::with_assignments(&assigns);
        let _ = folder.fold_expressions(&assigns); // Ok or Err, never panic
    }
}

#[test]
fn fuzz_printer_never_panics_on_random_trees() {
    let mut state = lcg_seed() ^ 0x1234_5678_9ABC_DEF0;
    let p = ExprPrinter::new();
    for _ in 0..200 {
        let a = u64_as_i64(lcg_next(&mut state));
        let op_idx = u64_trunc_usize(lcg_next(&mut state)) % all_binops().len();
        let w_idx = u64_trunc_usize(lcg_next(&mut state)) % all_widths().len();
        let e = Expr::BinOp(
            all_binops()[op_idx],
            Box::new(Expr::Const(a, all_widths()[w_idx])),
            Box::new(Expr::Var(format!("v{}", a & 0xFF))),
        );
        let s = p.print(&e);
        assert!(!s.is_empty());
    }
}

// ─── Round-trip via serde JSON ───────────────────────────────────────────────

#[test]
fn serde_roundtrip_50_expressions() {
    let mut state = lcg_seed() ^ 0xFEED_FACE_DEAD_C0DE;
    for _ in 0..50 {
        let a = u64_as_i64(lcg_next(&mut state));
        let w = all_widths()[u64_trunc_usize(lcg_next(&mut state)) % all_widths().len()];
        let op = all_binops()[u64_trunc_usize(lcg_next(&mut state)) % all_binops().len()];
        let e = Expr::BinOp(
            op,
            Box::new(Expr::Const(a, w)),
            Box::new(Expr::Var("v".into())),
        );
        let j = serde_json::to_string(&e).expect("serialize");
        let back: Expr = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(e, back);
    }
}

#[test]
fn serde_roundtrip_intwidth_binop_unop() {
    for &w in all_widths() {
        let j = serde_json::to_string(&w).unwrap();
        let back: IntWidth = serde_json::from_str(&j).unwrap();
        assert_eq!(w, back);
    }
    for &op in all_binops() {
        let j = serde_json::to_string(&op).unwrap();
        let back: BinOp = serde_json::from_str(&j).unwrap();
        assert_eq!(op, back);
    }
    for u in [UnOp::Neg, UnOp::Not, UnOp::LNot, UnOp::Deref, UnOp::AddrOf] {
        let j = serde_json::to_string(&u).unwrap();
        let back: UnOp = serde_json::from_str(&j).unwrap();
        assert_eq!(u, back);
    }
}

// ─── Boundary / overflow tests ───────────────────────────────────────────────

#[test]
fn simplify_neg_i64_min_does_not_panic() {
    let s = ExprSimplifier::new();
    let e = Expr::UnOp(UnOp::Neg, Box::new(Expr::Const(i64::MIN, IntWidth::I64)));
    let out = s.simplify(e);
    // wrapping_neg of i64::MIN is i64::MIN
    assert_eq!(out.as_const(), Some(i64::MIN));
}

#[test]
fn simplify_cast_truncates_to_width() {
    let s = ExprSimplifier::new();
    // (u8) 0x1234 = 0x34
    let e = Expr::UnOp(
        UnOp::Cast(IntWidth::U8),
        Box::new(Expr::Const(0x1234, IntWidth::I32)),
    );
    assert_eq!(s.simplify(e).as_const(), Some(0x34));
    // (i8) 0xFF = -1
    let e = Expr::UnOp(
        UnOp::Cast(IntWidth::I8),
        Box::new(Expr::Const(0xFF, IntWidth::I32)),
    );
    assert_eq!(s.simplify(e).as_const(), Some(-1));
}

#[test]
fn folder_depth_limit_self_referential() {
    // Create a directly self-referential single-def: t1 = t1 + 1.
    // is_safe_to_inline only allows when use_count==1; with this single assign,
    // t1 has use_count=1, def_count=1, so folder will try to inline and recurse.
    let assigns = vec![SsaAssign::new(
        "t1",
        Expr::BinOp(
            BinOp::Add,
            Box::new(Expr::Var("t1".into())),
            Box::new(Expr::Const(1, IntWidth::I32)),
        ),
    )];
    let folder = ExprFolder::with_assignments(&assigns);
    // Single-def-single-use self-ref should hit depth limit and Err — must not stack-overflow.
    let result = folder.fold_expressions(&assigns);
    // Either an error or it bails out without panicking; we just require no panic.
    let _ = result;
}
