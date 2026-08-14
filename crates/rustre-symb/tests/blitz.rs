//! Exhaustive test suite for rustre-symb's core public API surface.
//!
//! Focus: SymExpr, SymExprSimplifier, SymbolicState, PathConstraint, SymMemory,
//! eval_concrete / evaluate, SpecSymExpr, SymState, SmtFormula / ExprToSmtLib,
//! SymWidth and the convenience constructors.

use std::collections::HashMap;

use rustre_symb::smt_formula::{
    sym_type_to_sort, ExprToSmtLib, SmtFormula, SmtLogic, SmtSort,
};
use rustre_symb::{
    eval_concrete, expr_width, sym_add, sym_and, sym_mul, sym_not, sym_or, sym_sub, sym_xor,
    PathConstraint, SpecSymExpr, SymConstraint, SymExpr, SymExprSimplifier, SymId, SymMemory,
    SymState, SymType, SymWidth, SymbolicState, SymbolicValue, Unsat,
};

// ───────── helpers ─────────
fn bv(val: u64, w: u32) -> SymExpr {
    SymExpr::ConstBv { val, width: w }
}
fn var(n: &str) -> SymExpr {
    SymExpr::var(n, SymType::BitVec(64))
}
fn s() -> SymExprSimplifier {
    SymExprSimplifier::new()
}

// ───────── SymType ─────────

#[test]
fn symtype_widths() {
    assert_eq!(SymType::BitVec(1).width(), Some(1));
    assert_eq!(SymType::BitVec(8).width(), Some(8));
    assert_eq!(SymType::BitVec(64).width(), Some(64));
    assert_eq!(SymType::Pointer.width(), Some(64));
    assert_eq!(SymType::Bool.width(), None);
    assert_eq!(
        SymType::Array {
            elem_ty: Box::new(SymType::BitVec(8)),
            len: Some(16),
        }
        .width(),
        None
    );
}

#[test]
fn symtype_equality_and_hash() {
    use std::collections::HashSet;
    let mut h = HashSet::new();
    assert!(h.insert(SymType::BitVec(8)));
    assert!(!h.insert(SymType::BitVec(8)));
    assert!(h.insert(SymType::BitVec(16)));
    assert!(h.insert(SymType::Bool));
}

// ───────── SymWidth ─────────

#[test]
fn symwidth_bits_and_bytes() {
    assert_eq!(SymWidth::W8.bits(), 8);
    assert_eq!(SymWidth::W16.bits(), 16);
    assert_eq!(SymWidth::W32.bits(), 32);
    assert_eq!(SymWidth::W64.bits(), 64);
    assert_eq!(SymWidth::W8.bytes(), 1);
    assert_eq!(SymWidth::W16.bytes(), 2);
    assert_eq!(SymWidth::W32.bytes(), 4);
    assert_eq!(SymWidth::W64.bytes(), 8);
}

#[test]
fn symwidth_display() {
    assert_eq!(format!("{}", SymWidth::W32), "32");
    assert_eq!(format!("{}", SymWidth::W8), "8");
}

// ───────── SymExpr constructors ─────────

#[test]
fn symexpr_bv_constructor() {
    let e = SymExpr::bv(42, 32);
    assert_eq!(e.as_const_u64(), Some(42));
    assert_eq!(e.bit_width(), 32);
}

#[test]
fn symexpr_const_aliases_equal() {
    assert_eq!(SymExpr::bv(7, 16), SymExpr::Const(7, 16));
    assert_eq!(SymExpr::bv(7, 16), SymExpr::constant(16, 7));
}

#[test]
fn symexpr_symbol_encodes_id_in_name() {
    let s = SymExpr::Symbol(42, 64, "rax");
    if let SymExpr::Var { name, ty } = s {
        assert_eq!(name, "rax_42");
        assert_eq!(ty, SymType::BitVec(64));
    } else {
        panic!("not a Var");
    }
}

#[test]
fn symexpr_is_const() {
    assert!(bv(1, 1).is_const());
    assert!(SymExpr::ConstBool(false).is_const());
    assert!(!var("x").is_const());
    assert!(!SymExpr::add_expr(bv(1, 32), bv(2, 32)).is_const());
}

#[test]
fn symexpr_as_const_bool() {
    assert_eq!(SymExpr::ConstBool(true).as_const_bool(), Some(true));
    assert_eq!(SymExpr::ConstBool(false).as_const_bool(), Some(false));
    assert_eq!(bv(0, 1).as_const_bool(), None);
}

#[test]
fn symexpr_ops_overload() {
    let r = bv(2, 32) + bv(3, 32);
    assert_eq!(r.simplify(), bv(5, 32));
    let r2 = bv(10, 32) - bv(4, 32);
    assert_eq!(r2.simplify(), bv(6, 32));
}

// ───────── bit_width ─────────

#[test]
fn bit_width_basic() {
    assert_eq!(bv(0, 32).bit_width(), 32);
    assert_eq!(SymExpr::ConstBool(true).bit_width(), 1);
    assert_eq!(var("x").bit_width(), 64);
    assert_eq!(
        SymExpr::var("b", SymType::Bool).bit_width(),
        1
    );
}

#[test]
fn bit_width_extract() {
    let e = SymExpr::extract(bv(0xff, 32), 0, 7);
    // hi=7, lo=0 → 8 bits
    assert_eq!(e.bit_width(), 8);
}

#[test]
fn bit_width_concat_is_sum() {
    let e = SymExpr::Concat(Box::new(bv(1, 16)), Box::new(bv(2, 32)));
    assert_eq!(e.bit_width(), 48);
}

#[test]
fn bit_width_zext_and_sext() {
    let e = SymExpr::ZExt {
        expr: Box::new(bv(0, 8)),
        target_width: 32,
    };
    assert_eq!(e.bit_width(), 32);
    let e2 = SymExpr::SExt {
        expr: Box::new(bv(0, 8)),
        target_width: 64,
    };
    assert_eq!(e2.bit_width(), 64);
}

#[test]
fn bit_width_load() {
    let e = SymExpr::Load {
        addr: Box::new(bv(0x1000, 64)),
        size: 4,
    };
    assert_eq!(e.bit_width(), 32);
}

#[test]
fn bit_width_comparison_is_one() {
    let e = SymExpr::eq(var("x"), bv(0, 64));
    assert_eq!(e.bit_width(), 1);
}

// ───────── Simplifier: constant folding ─────────

#[test]
fn simp_add_const() {
    assert_eq!(
        s().simplify(SymExpr::Add(Box::new(bv(7, 32)), Box::new(bv(8, 32)))),
        bv(15, 32)
    );
}

#[test]
fn simp_add_wraps_on_overflow_within_width() {
    // 32-bit: 0xFFFFFFFF + 1 = 0
    let e = SymExpr::Add(Box::new(bv(0xFFFF_FFFF, 32)), Box::new(bv(1, 32)));
    assert_eq!(s().simplify(e), bv(0, 32));
}

#[test]
fn simp_sub_const() {
    assert_eq!(
        s().simplify(SymExpr::Sub(Box::new(bv(20, 32)), Box::new(bv(5, 32)))),
        bv(15, 32)
    );
}

#[test]
fn simp_mul_const_wraps() {
    let e = SymExpr::Mul(Box::new(bv(0xFFFF, 16)), Box::new(bv(2, 16)));
    // 0xFFFF*2 = 0x1FFFE; masked to 16 bits → 0xFFFE
    assert_eq!(s().simplify(e), bv(0xFFFE, 16));
}

#[test]
fn simp_and_or_xor_const() {
    assert_eq!(
        s().simplify(SymExpr::And(Box::new(bv(0xF0, 8)), Box::new(bv(0x0F, 8)))),
        bv(0x00, 8)
    );
    assert_eq!(
        s().simplify(SymExpr::Or(Box::new(bv(0xF0, 8)), Box::new(bv(0x0F, 8)))),
        bv(0xFF, 8)
    );
    assert_eq!(
        s().simplify(SymExpr::Xor(Box::new(bv(0xFF, 8)), Box::new(bv(0x0F, 8)))),
        bv(0xF0, 8)
    );
}

#[test]
fn simp_not_const_masked() {
    let e = SymExpr::Not(Box::new(bv(0x0F, 8)));
    assert_eq!(s().simplify(e), bv(0xF0, 8));
}

#[test]
fn simp_not_not_identity() {
    let e = SymExpr::Not(Box::new(SymExpr::Not(Box::new(var("x")))));
    assert_eq!(s().simplify(e), var("x"));
}

#[test]
fn simp_neg_const() {
    let e = SymExpr::Neg(Box::new(bv(1, 8)));
    assert_eq!(s().simplify(e), bv(0xFF, 8));
}

#[test]
fn simp_neg_neg_identity() {
    let e = SymExpr::Neg(Box::new(SymExpr::Neg(Box::new(var("x")))));
    assert_eq!(s().simplify(e), var("x"));
}

#[test]
fn simp_shl_const() {
    let e = SymExpr::Shl(Box::new(bv(1, 32)), Box::new(bv(4, 32)));
    assert_eq!(s().simplify(e), bv(0x10, 32));
}

#[test]
fn simp_lshr_const() {
    let e = SymExpr::LShr(Box::new(bv(0x80, 8)), Box::new(bv(1, 8)));
    assert_eq!(s().simplify(e), bv(0x40, 8));
}

#[test]
fn simp_ashr_const_sign_fills() {
    // 8-bit signed: 0x80 (-128) >> 1 = 0xC0 (-64)
    let e = SymExpr::AShr(Box::new(bv(0x80, 8)), Box::new(bv(1, 8)));
    assert_eq!(s().simplify(e), bv(0xC0, 8));
}

#[test]
fn simp_concat_const() {
    let e = SymExpr::Concat(Box::new(bv(0xAB, 8)), Box::new(bv(0xCD, 8)));
    assert_eq!(s().simplify(e), bv(0xABCD, 16));
}

#[test]
fn simp_extract_const() {
    let e = SymExpr::Extract {
        expr: Box::new(bv(0xABCD, 16)),
        hi: 7,
        lo: 0,
    };
    assert_eq!(s().simplify(e), bv(0xCD, 8));
}

#[test]
fn simp_zext_const_widens() {
    let e = SymExpr::ZExt {
        expr: Box::new(bv(0xFF, 8)),
        target_width: 32,
    };
    assert_eq!(s().simplify(e), bv(0xFF, 32));
}

#[test]
fn simp_sext_const_sign_extends() {
    let e = SymExpr::SExt {
        expr: Box::new(bv(0xFF, 8)),
        target_width: 32,
    };
    // 0xFF in 8-bit = -1 → sign-extend to 32-bit → 0xFFFFFFFF
    assert_eq!(s().simplify(e), bv(0xFFFF_FFFF, 32));
}

#[test]
fn simp_eq_const_true_and_false() {
    assert_eq!(
        s().simplify(SymExpr::Eq(Box::new(bv(1, 8)), Box::new(bv(1, 8)))),
        SymExpr::ConstBool(true)
    );
    assert_eq!(
        s().simplify(SymExpr::Eq(Box::new(bv(1, 8)), Box::new(bv(2, 8)))),
        SymExpr::ConstBool(false)
    );
}

#[test]
fn simp_cmps_unsigned_and_signed() {
    assert_eq!(
        s().simplify(SymExpr::ULt(Box::new(bv(1, 8)), Box::new(bv(2, 8)))),
        SymExpr::ConstBool(true)
    );
    assert_eq!(
        s().simplify(SymExpr::SLt(Box::new(bv(0xFF, 8)), Box::new(bv(1, 8)))),
        SymExpr::ConstBool(true) // -1 < 1
    );
    assert_eq!(
        s().simplify(SymExpr::SGt(Box::new(bv(0x7F, 8)), Box::new(bv(0x80, 8)))),
        SymExpr::ConstBool(true) // 127 > -128
    );
}

#[test]
fn simp_udiv_by_zero_does_not_fold() {
    let e = SymExpr::UDiv(Box::new(bv(10, 32)), Box::new(bv(0, 32)));
    let r = s().simplify(e);
    // Must NOT fold to a const; must remain a UDiv node.
    assert!(matches!(r, SymExpr::UDiv(_, _)));
}

#[test]
fn simp_udiv_const() {
    let e = SymExpr::UDiv(Box::new(bv(20, 32)), Box::new(bv(4, 32)));
    assert_eq!(s().simplify(e), bv(5, 32));
}

#[test]
fn simp_urem_const() {
    let e = SymExpr::URem(Box::new(bv(20, 32)), Box::new(bv(7, 32)));
    assert_eq!(s().simplify(e), bv(6, 32));
}

#[test]
fn simp_sdiv_const_negative() {
    // -10 / 3 in 8-bit signed = -3 → 0xFD
    let e = SymExpr::SDiv(Box::new(bv(0xF6, 8)), Box::new(bv(3, 8)));
    assert_eq!(s().simplify(e), bv(0xFD, 8));
}

#[test]
fn simp_srem_const() {
    // -10 % 3 = -1 → 0xFF in 8-bit
    let e = SymExpr::SRem(Box::new(bv(0xF6, 8)), Box::new(bv(3, 8)));
    assert_eq!(s().simplify(e), bv(0xFF, 8));
}

#[test]
fn simp_ite_true_picks_then() {
    let e = SymExpr::ite(SymExpr::ConstBool(true), bv(1, 8), bv(2, 8));
    assert_eq!(s().simplify(e), bv(1, 8));
}

#[test]
fn simp_ite_false_picks_else() {
    let e = SymExpr::ite(SymExpr::ConstBool(false), bv(1, 8), bv(2, 8));
    assert_eq!(s().simplify(e), bv(2, 8));
}

#[test]
fn simp_ite_same_branches_collapses() {
    let e = SymExpr::ite(var("c"), bv(7, 8), bv(7, 8));
    assert_eq!(s().simplify(e), bv(7, 8));
}

#[test]
fn simp_bool_and_short_circuit_false() {
    let e = SymExpr::BoolAnd(Box::new(SymExpr::ConstBool(false)), Box::new(var("p")));
    assert_eq!(s().simplify(e), SymExpr::ConstBool(false));
}

#[test]
fn simp_bool_or_short_circuit_true() {
    let e = SymExpr::BoolOr(Box::new(SymExpr::ConstBool(true)), Box::new(var("p")));
    assert_eq!(s().simplify(e), SymExpr::ConstBool(true));
}

#[test]
fn simp_bool_not_double_negation() {
    let e = SymExpr::BoolNot(Box::new(SymExpr::BoolNot(Box::new(var("p")))));
    assert_eq!(s().simplify(e), var("p"));
}

// ───────── Documented identity rules (potential bugs) ─────────
//
// The doc-comment on SymExprSimplifier explicitly lists these rules.
// Each test below pins a documented identity. If the rule is not actually
// implemented, the test will fail and the failure is a real bug.

#[test]
fn doc_rule_add_zero_identity() {
    let e = SymExpr::Add(Box::new(var("x")), Box::new(bv(0, 64)));
    assert_eq!(s().simplify(e), var("x"));
}

#[test]
fn doc_rule_sub_zero_identity() {
    let e = SymExpr::Sub(Box::new(var("x")), Box::new(bv(0, 64)));
    assert_eq!(s().simplify(e), var("x"));
}

#[test]
fn doc_rule_sub_self_zero() {
    let e = SymExpr::Sub(Box::new(var("x")), Box::new(var("x")));
    assert_eq!(s().simplify(e), bv(0, 64));
}

#[test]
fn doc_rule_mul_zero_zero() {
    let e = SymExpr::Mul(Box::new(var("x")), Box::new(bv(0, 64)));
    assert_eq!(s().simplify(e), bv(0, 64));
}

#[test]
fn doc_rule_mul_one_identity() {
    let e = SymExpr::Mul(Box::new(var("x")), Box::new(bv(1, 64)));
    assert_eq!(s().simplify(e), var("x"));
}

#[test]
fn doc_rule_and_zero_zero() {
    let e = SymExpr::And(Box::new(var("x")), Box::new(bv(0, 64)));
    assert_eq!(s().simplify(e), bv(0, 64));
}

#[test]
fn doc_rule_and_self_identity() {
    let e = SymExpr::And(Box::new(var("x")), Box::new(var("x")));
    assert_eq!(s().simplify(e), var("x"));
}

#[test]
fn doc_rule_or_zero_identity() {
    let e = SymExpr::Or(Box::new(var("x")), Box::new(bv(0, 64)));
    assert_eq!(s().simplify(e), var("x"));
}

#[test]
fn doc_rule_or_self_identity() {
    let e = SymExpr::Or(Box::new(var("x")), Box::new(var("x")));
    assert_eq!(s().simplify(e), var("x"));
}

#[test]
fn doc_rule_xor_self_zero() {
    let e = SymExpr::Xor(Box::new(var("x")), Box::new(var("x")));
    assert_eq!(s().simplify(e), bv(0, 64));
}

// ───────── evaluate (env-based) ─────────

#[test]
fn evaluate_const() {
    let env = HashMap::new();
    assert_eq!(bv(42, 32).evaluate(&env), Some(42));
}

#[test]
fn evaluate_var_present() {
    let mut env = HashMap::new();
    env.insert("x".to_string(), 7u64);
    assert_eq!(var("x").evaluate(&env), Some(7));
}

#[test]
fn evaluate_var_missing_returns_none() {
    let env = HashMap::new();
    assert_eq!(var("missing").evaluate(&env), None);
}

#[test]
fn evaluate_arith_wraps() {
    let env = HashMap::new();
    let e = SymExpr::Add(Box::new(bv(u64::MAX, 64)), Box::new(bv(1, 64)));
    assert_eq!(e.evaluate(&env), Some(0));
}

#[test]
fn evaluate_udiv_by_zero_is_none() {
    let env = HashMap::new();
    let e = SymExpr::UDiv(Box::new(bv(1, 32)), Box::new(bv(0, 32)));
    assert_eq!(e.evaluate(&env), None);
}

#[test]
fn evaluate_sdiv_by_zero_is_none() {
    let env = HashMap::new();
    let e = SymExpr::SDiv(Box::new(bv(1, 32)), Box::new(bv(0, 32)));
    assert_eq!(e.evaluate(&env), None);
}

#[test]
fn evaluate_load_and_store_return_none() {
    let env = HashMap::new();
    let l = SymExpr::Load {
        addr: Box::new(bv(0, 64)),
        size: 4,
    };
    assert_eq!(l.evaluate(&env), None);
}

#[test]
fn evaluate_signed_comparisons() {
    let env = HashMap::new();
    let e = SymExpr::SLt(Box::new(bv(0xFFFF_FFFF_FFFF_FFFF, 64)), Box::new(bv(1, 64)));
    // -1 < 1
    assert_eq!(e.evaluate(&env), Some(1));
}

#[test]
fn evaluate_ite_picks_branch() {
    let env = HashMap::new();
    let e = SymExpr::ite(SymExpr::ConstBool(true), bv(11, 32), bv(22, 32));
    assert_eq!(e.evaluate(&env), Some(11));
}

#[test]
fn evaluate_concat_correct_shift() {
    let env = HashMap::new();
    let e = SymExpr::Concat(Box::new(bv(0xAB, 8)), Box::new(bv(0xCD, 8)));
    assert_eq!(e.evaluate(&env), Some(0xABCD));
}

#[test]
fn evaluate_extract_byte_from_word() {
    let env = HashMap::new();
    let e = SymExpr::Extract {
        expr: Box::new(bv(0xDEAD_BEEF, 32)),
        hi: 15,
        lo: 8,
    };
    // bits 15..8 of 0xDEADBEEF = 0xBE
    assert_eq!(e.evaluate(&env), Some(0xBE));
}

#[test]
fn evaluate_sext_signed() {
    let env = HashMap::new();
    let e = SymExpr::SExt {
        expr: Box::new(bv(0xFF, 8)),
        target_width: 32,
    };
    assert_eq!(e.evaluate(&env), Some(0xFFFF_FFFF));
}

// ───────── eval_concrete (id-keyed env) ─────────

#[test]
fn eval_concrete_named_symbol() {
    let mut env: HashMap<SymId, u64> = HashMap::new();
    env.insert(3, 99);
    let e = SymExpr::Symbol(3, 64, "x");
    assert_eq!(eval_concrete(&e, &env), Some(99));
}

#[test]
fn eval_concrete_const_only() {
    let env: HashMap<SymId, u64> = HashMap::new();
    assert_eq!(eval_concrete(&bv(7, 32), &env), Some(7));
}

#[test]
fn eval_concrete_unknown_var_is_none() {
    let env: HashMap<SymId, u64> = HashMap::new();
    let e = SymExpr::Symbol(42, 64, "x");
    assert_eq!(eval_concrete(&e, &env), None);
}

#[test]
fn eval_concrete_memory_returns_none() {
    let env: HashMap<SymId, u64> = HashMap::new();
    let e = SymExpr::Load {
        addr: Box::new(bv(0, 64)),
        size: 4,
    };
    assert_eq!(eval_concrete(&e, &env), None);
}

// ───────── sym_* helpers ─────────

#[test]
fn sym_helpers_fold_constants() {
    assert_eq!(sym_add(bv(2, 32), bv(3, 32)), bv(5, 32));
    assert_eq!(sym_sub(bv(10, 32), bv(4, 32)), bv(6, 32));
    assert_eq!(sym_mul(bv(2, 32), bv(3, 32)), bv(6, 32));
    assert_eq!(sym_and(bv(0xF0, 8), bv(0x0F, 8)), bv(0, 8));
    assert_eq!(sym_or(bv(0xF0, 8), bv(0x0F, 8)), bv(0xFF, 8));
    assert_eq!(sym_xor(bv(0xFF, 8), bv(0x0F, 8)), bv(0xF0, 8));
    assert_eq!(sym_not(bv(0x0F, 8)), bv(0xF0, 8));
}

// ───────── expr_width ─────────

#[test]
fn expr_width_known_and_default() {
    assert_eq!(expr_width(&bv(0, 16)), 16);
    assert_eq!(expr_width(&var("x")), 64);
    assert_eq!(
        expr_width(&SymExpr::var("b", SymType::Bool)),
        1
    );
    assert_eq!(expr_width(&SymExpr::Add(Box::new(bv(0, 8)), Box::new(bv(0, 8)))), 64);
}

// ───────── SymMemory ─────────

#[test]
fn symmem_concrete_roundtrip() {
    let mut m = SymMemory::new();
    m.store_concrete(0x1000, bv(0xCAFE, 32));
    assert_eq!(m.load_concrete(0x1000), bv(0xCAFE, 32));
}

#[test]
fn symmem_unknown_returns_var() {
    let m = SymMemory::new();
    let v = m.load_concrete(0xDEAD);
    if let SymExpr::Var { name, ty } = v {
        assert!(name.contains("dead") || name.contains("DEAD") || name.contains("mem_"));
        assert_eq!(ty, SymType::BitVec(8));
    } else {
        panic!("expected Var");
    }
}

#[test]
fn symmem_symbolic_store_and_load() {
    let mut m = SymMemory::new();
    m.store_symbolic(5, bv(0xBEEF, 32));
    assert_eq!(m.load_symbolic(5), Some(&bv(0xBEEF, 32)));
    assert_eq!(m.load_symbolic(6), None);
}

// ───────── PathConstraint ─────────

#[test]
fn pathcond_empty_is_true() {
    let pc = PathConstraint::new();
    assert_eq!(pc.as_conjunction(), SymExpr::ConstBool(true));
}

#[test]
fn pathcond_add_and_trivially_false() {
    let mut pc = PathConstraint::new();
    pc.add(SymExpr::ConstBool(false));
    assert!(pc.is_trivially_false());
}

#[test]
fn pathcond_two_terms_conjoin_with_booland() {
    let mut pc = PathConstraint::new();
    pc.add(var("a"));
    pc.add(var("b"));
    let conj = pc.as_conjunction();
    assert!(matches!(conj, SymExpr::BoolAnd(_, _)));
}

// ───────── SymbolicState ─────────

#[test]
fn state_default_empty() {
    let st = SymbolicState::new();
    assert_eq!(st.pc, 0);
    assert_eq!(st.depth, 0);
    assert!(st.registers.is_empty());
    assert!(st.path_condition.is_empty());
}

#[test]
fn state_register_roundtrip_and_default() {
    let mut st = SymbolicState::new();
    st.write_register("rax", bv(7, 64));
    assert_eq!(st.read_register("rax"), bv(7, 64));
    // undefined → Var with that register name
    if let SymExpr::Var { name, ty } = st.read_register("undef") {
        assert_eq!(name, "undef");
        assert_eq!(ty, SymType::BitVec(64));
    } else {
        panic!("expected Var for unknown register");
    }
}

#[test]
fn state_fork_increments_depth_and_pushes_cond() {
    let st = SymbolicState::new();
    let f = st.fork(SymExpr::ConstBool(true));
    assert_eq!(f.depth, 1);
    assert_eq!(f.path_condition.len(), 1);
}

#[test]
fn state_fork_pair_negates_second() {
    let st = SymbolicState::new();
    let cond = SymExpr::eq(var("x"), bv(0, 64));
    let (t, f) = st.fork_pair(cond.clone());
    assert_eq!(t.depth, 1);
    assert_eq!(f.depth, 1);
    assert_eq!(t.path_condition[0], cond);
    assert!(matches!(f.path_condition[0], SymExpr::BoolNot(_)));
}

#[test]
fn state_assume_unsat_returns_err() {
    let mut st = SymbolicState::new();
    let r = st.assume(&SymExpr::ConstBool(false));
    assert!(matches!(r, Err(Unsat)));
    // State must not mutate on Err.
    assert!(st.path_condition.is_empty());
}

#[test]
fn state_assume_sat_pushes_simplified() {
    let mut st = SymbolicState::new();
    let r = st.assume(&SymExpr::ConstBool(true));
    assert!(r.is_ok());
    assert_eq!(st.path_condition.len(), 1);
}

#[test]
fn state_is_satisfiable_true_when_empty() {
    let st = SymbolicState::new();
    assert!(st.is_satisfiable());
}

#[test]
fn state_is_satisfiable_false_on_const_false() {
    let mut st = SymbolicState::new();
    st.add_path_condition(SymExpr::ConstBool(false));
    assert!(!st.is_satisfiable());
}

#[test]
fn state_all_constraints_includes_both() {
    let mut st = SymbolicState::new();
    st.add_path_condition(var("a"));
    st.add_constraint(var("b"));
    let all = st.all_constraints();
    assert_eq!(all.len(), 2);
}

#[test]
fn state_get_model_returns_zero_for_unknown_vars() {
    let mut st = SymbolicState::new();
    st.add_path_condition(SymExpr::eq(var("x"), bv(0, 64)));
    let m = st.get_model();
    assert_eq!(m.get("x"), Some(&0));
}

#[test]
fn state_get_model_seeds_concrete_register() {
    let mut st = SymbolicState::new();
    st.write_register("r", bv(42, 64));
    let m = st.get_model();
    assert_eq!(m.get("r"), Some(&42));
}

#[test]
fn state_merge_equal_registers_no_ite() {
    let mut a = SymbolicState::new();
    let mut b = SymbolicState::new();
    a.write_register("rax", bv(5, 64));
    b.write_register("rax", bv(5, 64));
    let merged = SymbolicState::merge(a, b, &SymExpr::ConstBool(true));
    assert_eq!(merged.read_register("rax"), bv(5, 64));
}

#[test]
fn state_merge_differing_registers_wraps_ite() {
    let mut a = SymbolicState::new();
    let mut b = SymbolicState::new();
    a.write_register("rax", bv(1, 64));
    b.write_register("rax", bv(2, 64));
    let merged = SymbolicState::merge(a, b, &SymExpr::ConstBool(true));
    assert!(matches!(merged.read_register("rax"), SymExpr::Ite { .. }));
}

#[test]
fn state_merge_uses_max_depth() {
    let mut a = SymbolicState::new();
    a.depth = 3;
    let mut b = SymbolicState::new();
    b.depth = 7;
    let merged = SymbolicState::merge(a, b, &SymExpr::ConstBool(true));
    assert_eq!(merged.depth, 7);
}

// ───────── SymbolicValue ─────────

#[test]
fn symbolicvalue_new() {
    let v = SymbolicValue::new(1, SymType::BitVec(32), bv(42, 32));
    assert_eq!(v.id, 1);
    assert_eq!(v.ty, SymType::BitVec(32));
    assert_eq!(v.expr, bv(42, 32));
}

// ───────── Serde roundtrip (Serialize/Deserialize) ─────────

#[test]
fn symexpr_serde_roundtrip() {
    let e = SymExpr::Add(Box::new(bv(1, 32)), Box::new(bv(2, 32)));
    let s = serde_json::to_string(&e).unwrap();
    let back: SymExpr = serde_json::from_str(&s).unwrap();
    assert_eq!(e, back);
}

#[test]
fn symtype_serde_roundtrip() {
    let t = SymType::Array {
        elem_ty: Box::new(SymType::BitVec(8)),
        len: Some(16),
    };
    let s = serde_json::to_string(&t).unwrap();
    let back: SymType = serde_json::from_str(&s).unwrap();
    assert_eq!(t, back);
}

// ───────── SpecSymExpr ─────────

fn cbv(val: u64, w: SymWidth) -> SpecSymExpr {
    SpecSymExpr::Const { val, width: w }
}

#[test]
fn specsymexpr_width_basic() {
    assert_eq!(cbv(0, SymWidth::W32).width(), Some(SymWidth::W32));
    let v = SpecSymExpr::Var {
        name: "x".into(),
        width: SymWidth::W16,
    };
    assert_eq!(v.width(), Some(SymWidth::W16));
}

#[test]
fn specsymexpr_extract_width_matches_size() {
    let e = SpecSymExpr::Extract {
        expr: Box::new(cbv(0, SymWidth::W32)),
        hi: 7,
        lo: 0,
    };
    assert_eq!(e.width(), Some(SymWidth::W8));
}

#[test]
fn specsymexpr_extract_non_power_of_two_is_none() {
    let e = SpecSymExpr::Extract {
        expr: Box::new(cbv(0, SymWidth::W32)),
        hi: 4,
        lo: 0,
    }; // 5 bits — not a SymWidth variant
    assert_eq!(e.width(), None);
}

#[test]
fn specsymexpr_is_concrete() {
    assert!(cbv(0, SymWidth::W8).is_concrete());
    assert!(!SpecSymExpr::Var {
        name: "x".into(),
        width: SymWidth::W8,
    }
    .is_concrete());
    let e = SpecSymExpr::Add(Box::new(cbv(1, SymWidth::W8)), Box::new(cbv(2, SymWidth::W8)));
    assert!(e.is_concrete());
}

#[test]
fn specsymexpr_eval_concrete_arith() {
    let e = SpecSymExpr::Add(Box::new(cbv(2, SymWidth::W32)), Box::new(cbv(3, SymWidth::W32)));
    assert_eq!(e.eval_concrete(), Some(5));
}

#[test]
fn specsymexpr_eval_div_by_zero_none() {
    let e = SpecSymExpr::Div(Box::new(cbv(10, SymWidth::W32)), Box::new(cbv(0, SymWidth::W32)));
    assert_eq!(e.eval_concrete(), None);
}

#[test]
fn specsymexpr_eval_var_none() {
    let e = SpecSymExpr::Var {
        name: "x".into(),
        width: SymWidth::W32,
    };
    assert_eq!(e.eval_concrete(), None);
}

#[test]
fn specsymexpr_substitute_replaces_only_matching_name() {
    let e = SpecSymExpr::Add(
        Box::new(SpecSymExpr::Var {
            name: "x".into(),
            width: SymWidth::W32,
        }),
        Box::new(SpecSymExpr::Var {
            name: "y".into(),
            width: SymWidth::W32,
        }),
    );
    let replaced = e.substitute("x", &cbv(42, SymWidth::W32));
    // After substitution, eval should still be None (y is still a var).
    assert_eq!(replaced.eval_concrete(), None);
    // But substituting both should let it fold.
    let both = replaced.substitute("y", &cbv(8, SymWidth::W32));
    assert_eq!(both.eval_concrete(), Some(50));
}

// ───────── SymConstraint ─────────

#[test]
fn symconstraint_assert_and_deny() {
    let e = cbv(1, SymWidth::W8);
    let a = SymConstraint::assert(e.clone());
    assert!(!a.is_negated);
    let d = SymConstraint::deny(e);
    assert!(d.is_negated);
}

// ───────── SymState ─────────

#[test]
fn symstate_var_set_get() {
    let mut st = SymState::new();
    st.set_var("x", cbv(7, SymWidth::W32));
    let v = st.get_var("x").unwrap();
    assert_eq!(v.eval_concrete(), Some(7));
    assert!(st.get_var("missing").is_none());
}

#[test]
fn symstate_mem_store_load() {
    let mut st = SymState::new();
    st.store_mem(0x100, cbv(0xAA, SymWidth::W8));
    assert!(st.load_mem(0x100).is_some());
    assert!(st.load_mem(0x200).is_none());
}

#[test]
fn symstate_clone_state_is_independent() {
    let mut st = SymState::new();
    st.set_var("x", cbv(1, SymWidth::W8));
    let c = st.clone_state();
    assert!(c.get_var("x").is_some());
}

// ───────── SmtFormula / ExprToSmtLib ─────────

#[test]
fn smtformula_new_is_empty() {
    let f = SmtFormula::new(SmtLogic::QfBv);
    assert_eq!(f.assertion_count(), 0);
    assert_eq!(f.declaration_count(), 0);
}

#[test]
fn smtformula_declare_and_assert() {
    let mut f = SmtFormula::new(SmtLogic::QfBv);
    f.declare("x", SmtSort::BitVec(32));
    f.assert("(= x (_ bv0 32))");
    assert_eq!(f.declaration_count(), 1);
    assert_eq!(f.assertion_count(), 1);
    let out = f.to_smtlib();
    assert!(out.contains("(set-logic QF_BV)"));
    assert!(out.contains("(declare-const x (_ BitVec 32))"));
    assert!(out.contains("(assert (= x (_ bv0 32)))"));
    assert!(out.contains("(check-sat)"));
}

#[test]
fn smtlogic_as_str_all_variants() {
    assert_eq!(SmtLogic::QfBv.as_str(), "QF_BV");
    assert_eq!(SmtLogic::QfAbv.as_str(), "QF_ABV");
    assert_eq!(SmtLogic::QfLia.as_str(), "QF_LIA");
    assert_eq!(SmtLogic::QfNia.as_str(), "QF_NIA");
    assert_eq!(SmtLogic::All.as_str(), "ALL");
}

#[test]
fn smtsort_to_smtlib() {
    assert_eq!(SmtSort::Bool.to_smtlib(), "Bool");
    assert_eq!(SmtSort::BitVec(8).to_smtlib(), "(_ BitVec 8)");
    let arr = SmtSort::Array(Box::new(SmtSort::BitVec(64)), Box::new(SmtSort::BitVec(8)));
    assert_eq!(arr.to_smtlib(), "(Array (_ BitVec 64) (_ BitVec 8))");
}

#[test]
fn exprtosmtlib_const_and_var() {
    let mut t = ExprToSmtLib::new();
    assert_eq!(t.translate(&bv(42, 32)), "(_ bv42 32)");
    assert_eq!(t.translate(&SymExpr::ConstBool(true)), "true");
    assert_eq!(t.translate(&SymExpr::ConstBool(false)), "false");
    let _ = t.translate(&var("x"));
    assert!(t.vars.iter().any(|(n, w)| n == "x" && *w == 64));
}

#[test]
fn exprtosmtlib_arith_translations() {
    let mut t = ExprToSmtLib::new();
    assert!(t.translate(&SymExpr::Add(Box::new(bv(1, 32)), Box::new(bv(2, 32)))).contains("bvadd"));
    assert!(t.translate(&SymExpr::Sub(Box::new(bv(1, 32)), Box::new(bv(2, 32)))).contains("bvsub"));
    assert!(t.translate(&SymExpr::Mul(Box::new(bv(1, 32)), Box::new(bv(2, 32)))).contains("bvmul"));
    assert!(t.translate(&SymExpr::UDiv(Box::new(bv(1, 32)), Box::new(bv(2, 32)))).contains("bvudiv"));
    assert!(t.translate(&SymExpr::SDiv(Box::new(bv(1, 32)), Box::new(bv(2, 32)))).contains("bvsdiv"));
    assert!(t.translate(&SymExpr::URem(Box::new(bv(1, 32)), Box::new(bv(2, 32)))).contains("bvurem"));
    assert!(t.translate(&SymExpr::SRem(Box::new(bv(1, 32)), Box::new(bv(2, 32)))).contains("bvsrem"));
}

#[test]
fn exprtosmtlib_logical_and_shift() {
    let mut t = ExprToSmtLib::new();
    assert!(t.translate(&SymExpr::And(Box::new(bv(1, 8)), Box::new(bv(2, 8)))).contains("bvand"));
    assert!(t.translate(&SymExpr::Or(Box::new(bv(1, 8)), Box::new(bv(2, 8)))).contains("bvor"));
    assert!(t.translate(&SymExpr::Xor(Box::new(bv(1, 8)), Box::new(bv(2, 8)))).contains("bvxor"));
    assert!(t.translate(&SymExpr::Not(Box::new(bv(0, 8)))).contains("bvnot"));
    assert!(t.translate(&SymExpr::Neg(Box::new(bv(0, 8)))).contains("bvneg"));
    assert!(t.translate(&SymExpr::Shl(Box::new(bv(0, 8)), Box::new(bv(1, 8)))).contains("bvshl"));
    assert!(t.translate(&SymExpr::LShr(Box::new(bv(0, 8)), Box::new(bv(1, 8)))).contains("bvlshr"));
    assert!(t.translate(&SymExpr::AShr(Box::new(bv(0, 8)), Box::new(bv(1, 8)))).contains("bvashr"));
}

#[test]
fn exprtosmtlib_concat_extract_zext_sext() {
    let mut t = ExprToSmtLib::new();
    assert!(t.translate(&SymExpr::Concat(Box::new(bv(0, 8)), Box::new(bv(0, 8)))).contains("concat"));
    assert!(t
        .translate(&SymExpr::Extract {
            expr: Box::new(bv(0, 32)),
            hi: 7,
            lo: 0,
        })
        .contains("extract"));
    assert!(t
        .translate(&SymExpr::ZExt {
            expr: Box::new(bv(0, 8)),
            target_width: 32,
        })
        .contains("zero_extend"));
    assert!(t
        .translate(&SymExpr::SExt {
            expr: Box::new(bv(0, 8)),
            target_width: 32,
        })
        .contains("sign_extend"));
}

#[test]
fn exprtosmtlib_cmps_and_ite() {
    let mut t = ExprToSmtLib::new();
    assert!(t.translate(&SymExpr::ULt(Box::new(bv(0, 8)), Box::new(bv(1, 8)))).contains("bvult"));
    assert!(t.translate(&SymExpr::SGt(Box::new(bv(0, 8)), Box::new(bv(1, 8)))).contains("bvsgt"));
    assert!(t.translate(&SymExpr::BoolAnd(Box::new(SymExpr::ConstBool(true)), Box::new(SymExpr::ConstBool(false)))).contains("(and"));
    assert!(t.translate(&SymExpr::BoolOr(Box::new(SymExpr::ConstBool(true)), Box::new(SymExpr::ConstBool(false)))).contains("(or"));
    assert!(t.translate(&SymExpr::BoolNot(Box::new(SymExpr::ConstBool(true)))).contains("(not"));
    assert!(t.translate(&SymExpr::ite(SymExpr::ConstBool(true), bv(1, 8), bv(2, 8))).contains("ite"));
}

#[test]
fn exprtosmtlib_var_deduplicated() {
    let mut t = ExprToSmtLib::new();
    let _ = t.translate(&var("x"));
    let _ = t.translate(&var("x"));
    let count = t.vars.iter().filter(|(n, _)| n == "x").count();
    assert_eq!(count, 1, "var x must only be recorded once");
}

#[test]
fn exprtosmtlib_build_formula_unique_decls() {
    let mut t = ExprToSmtLib::new();
    let constraints = vec![
        SymExpr::eq(var("x"), bv(0, 64)),
        SymExpr::eq(var("x"), bv(1, 64)),
    ];
    let f = t.build_formula(&constraints);
    assert_eq!(f.assertion_count(), 2);
    // x declared exactly once.
    assert_eq!(f.declaration_count(), 1);
    let out = f.to_smtlib();
    assert!(out.contains("(declare-const x"));
}

#[test]
fn sym_type_to_sort_mapping() {
    assert_eq!(sym_type_to_sort(&SymType::Bool), SmtSort::Bool);
    assert_eq!(sym_type_to_sort(&SymType::BitVec(16)), SmtSort::BitVec(16));
    assert_eq!(sym_type_to_sort(&SymType::Pointer), SmtSort::BitVec(64));
    let arr = sym_type_to_sort(&SymType::Array {
        elem_ty: Box::new(SymType::BitVec(8)),
        len: None,
    });
    match arr {
        SmtSort::Array(idx, elem) => {
            assert_eq!(*idx, SmtSort::BitVec(64));
            assert_eq!(*elem, SmtSort::BitVec(8));
        }
        _ => panic!("expected Array sort"),
    }
}

#[test]
fn smtformula_display_matches_to_smtlib() {
    let mut f = SmtFormula::new(SmtLogic::QfBv);
    f.declare("y", SmtSort::BitVec(8));
    let a = f.to_smtlib();
    let b = format!("{f}");
    assert_eq!(a, b);
}

// ───────── Send/Sync invariants ─────────

#[test]
fn types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SymExpr>();
    assert_send_sync::<SymType>();
    assert_send_sync::<SymbolicState>();
    assert_send_sync::<SymMemory>();
    assert_send_sync::<PathConstraint>();
    assert_send_sync::<SmtFormula>();
}
