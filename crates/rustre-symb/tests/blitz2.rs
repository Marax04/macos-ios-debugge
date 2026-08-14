//! Deep adversarial tests for rustre-symb core.
//!
//! Covers: SymExpr construction, simplifier algebra, eval_concrete & evaluate,
//! SymbolicState fork/merge/assume, SymMemory, PathConstraint, Send+Sync,
//! integer overflow paths, hash/eq consistency, seeded LCG fuzz.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use rustre_symb::{
    eval_concrete, sym_and, sym_mul, sym_not, sym_or, sym_sub, sym_xor, PathConstraint,
    SymExpr, SymExprSimplifier, SymMemory, SymType, SymbolicState, SymbolicValue, Unsat,
};

// ── seeded LCG ────────────────────────────────────────────────────────────────
fn make_lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn bv(v: u64, w: u32) -> SymExpr {
    SymExpr::bv(v, w)
}

// ── 1. literal construction and width ────────────────────────────────────────
#[test]
fn t01_bv_constructor_roundtrip() {
    for w in [1u32, 4, 8, 16, 32, 64] {
        let e = SymExpr::bv(0, w);
        assert_eq!(e.bit_width(), w);
        assert!(e.is_const());
        assert_eq!(e.as_const_u64(), Some(0));
    }
}

#[test]
fn t02_const_alias_same_as_bv() {
    let a = SymExpr::Const(0xAB, 16);
    let b = SymExpr::bv(0xAB, 16);
    assert_eq!(a, b);
}

#[test]
fn t03_constant_alt_signature() {
    let a = SymExpr::constant(8, 0xFF);
    assert_eq!(a, SymExpr::bv(0xFF, 8));
}

#[test]
fn t04_constbool_is_const() {
    assert!(SymExpr::ConstBool(true).is_const());
    assert_eq!(SymExpr::ConstBool(true).as_const_bool(), Some(true));
    assert_eq!(SymExpr::ConstBool(false).as_const_bool(), Some(false));
    assert_eq!(SymExpr::ConstBool(true).as_const_u64(), None);
}

#[test]
fn t05_var_bit_width_from_ty() {
    let v = SymExpr::var("x", SymType::BitVec(32));
    assert_eq!(v.bit_width(), 32);
    let p = SymExpr::var("p", SymType::Pointer);
    assert_eq!(p.bit_width(), 64);
    let b = SymExpr::var("b", SymType::Bool);
    assert_eq!(b.bit_width(), 1);
}

// ── 2. simplifier algebraic identities ───────────────────────────────────────
#[test]
fn t06_add_zero_identity_left_and_right() {
    let s = SymExprSimplifier::new();
    let x = SymExpr::var("x", SymType::BitVec(32));
    assert_eq!(s.simplify(SymExpr::Add(Box::new(x.clone()), Box::new(bv(0, 32)))), x);
    assert_eq!(s.simplify(SymExpr::Add(Box::new(bv(0, 32)), Box::new(x.clone()))), x);
}

#[test]
fn t07_xor_self_zero_and_const_fold() {
    let x = SymExpr::var("x", SymType::BitVec(8));
    let r = sym_xor(x.clone(), x);
    // simplifier collapses x^x to 0 with proper width
    match r {
        SymExpr::ConstBv { val: 0, .. } => {}
        other => panic!("expected 0, got {other:?}"),
    }
}

#[test]
fn t08_and_zero_yields_zero() {
    let x = SymExpr::var("x", SymType::BitVec(16));
    let r = sym_and(x, bv(0, 16));
    assert_eq!(r, bv(0, 16));
}

#[test]
fn t09_or_zero_identity() {
    let x = SymExpr::var("x", SymType::BitVec(32));
    let r = sym_or(x.clone(), bv(0, 32));
    assert_eq!(r, x);
}

#[test]
fn t10_mul_zero_is_zero_mul_one_is_x() {
    let x = SymExpr::var("x", SymType::BitVec(32));
    assert_eq!(sym_mul(x.clone(), bv(0, 32)), bv(0, 32));
    assert_eq!(sym_mul(x.clone(), bv(1, 32)), x);
}

#[test]
fn t11_sub_self_zero_and_sub_zero_identity() {
    let x = SymExpr::var("x", SymType::BitVec(64));
    // x - 0 = x
    assert_eq!(sym_sub(x.clone(), bv(0, 64)), x.clone());
    // x - x folds via constant folding only if both sides are constants; here
    // both sides are the same Var — verify simplifier handles "x - x = 0".
    let r = sym_sub(x.clone(), x);
    // Doc claims x - x = 0 is implemented.
    assert_eq!(r, bv(0, 64));
}

#[test]
fn t12_not_not_collapses() {
    let x = SymExpr::var("x", SymType::BitVec(8));
    let r = sym_not(sym_not(x.clone()));
    assert_eq!(r, x);
}

#[test]
fn t13_neg_neg_collapses() {
    let s = SymExprSimplifier::new();
    let x = SymExpr::var("x", SymType::BitVec(32));
    let inner = SymExpr::Neg(Box::new(x.clone()));
    let outer = SymExpr::Neg(Box::new(inner));
    assert_eq!(s.simplify(outer), x);
}

#[test]
fn t14_bool_not_doublenegation() {
    let s = SymExprSimplifier::new();
    let x = SymExpr::var("p", SymType::Bool);
    let r = s.simplify(SymExpr::BoolNot(Box::new(SymExpr::BoolNot(Box::new(x.clone())))));
    assert_eq!(r, x);
}

#[test]
fn t15_bool_and_false_short_circuit() {
    let s = SymExprSimplifier::new();
    let x = SymExpr::var("p", SymType::Bool);
    let r = s.simplify(SymExpr::BoolAnd(
        Box::new(SymExpr::ConstBool(false)),
        Box::new(x),
    ));
    assert_eq!(r, SymExpr::ConstBool(false));
}

#[test]
fn t16_bool_or_true_short_circuit() {
    let s = SymExprSimplifier::new();
    let x = SymExpr::var("p", SymType::Bool);
    let r = s.simplify(SymExpr::BoolOr(
        Box::new(SymExpr::ConstBool(true)),
        Box::new(x),
    ));
    assert_eq!(r, SymExpr::ConstBool(true));
}

#[test]
fn t17_ite_const_cond_folds_branches() {
    let s = SymExprSimplifier::new();
    let then_ = bv(7, 32);
    let else_ = bv(9, 32);
    let r_true = s.simplify(SymExpr::ite(
        SymExpr::ConstBool(true),
        then_.clone(),
        else_.clone(),
    ));
    assert_eq!(r_true, then_);
    let r_false = s.simplify(SymExpr::ite(SymExpr::ConstBool(false), then_, else_.clone()));
    assert_eq!(r_false, else_);
}

#[test]
fn t18_ite_same_branches_folds() {
    let s = SymExprSimplifier::new();
    let v = bv(42, 32);
    let r = s.simplify(SymExpr::ite(
        SymExpr::var("c", SymType::Bool),
        v.clone(),
        v.clone(),
    ));
    assert_eq!(r, v);
}

// ── 3. constant folding ─────────────────────────────────────────────────────
#[test]
fn t19_const_fold_add_with_width_mask() {
    let s = SymExprSimplifier::new();
    // 0xFF + 0x01 in 8-bit = 0
    let r = s.simplify(SymExpr::Add(Box::new(bv(0xFF, 8)), Box::new(bv(1, 8))));
    assert_eq!(r, bv(0, 8));
}

#[test]
fn t20_const_fold_sub_underflow_masked() {
    let s = SymExprSimplifier::new();
    let r = s.simplify(SymExpr::Sub(Box::new(bv(0, 8)), Box::new(bv(1, 8))));
    assert_eq!(r, bv(0xFF, 8));
}

#[test]
fn t21_const_fold_extract() {
    let s = SymExprSimplifier::new();
    let r = s.simplify(SymExpr::Extract {
        expr: Box::new(bv(0xABCD, 16)),
        hi: 7,
        lo: 0,
    });
    assert_eq!(r, bv(0xCD, 8));
}

#[test]
fn t22_const_fold_zext_sext() {
    let s = SymExprSimplifier::new();
    let r = s.simplify(SymExpr::ZExt {
        expr: Box::new(bv(0xFF, 8)),
        target_width: 32,
    });
    assert_eq!(r, bv(0xFF, 32));
    // Sign-extend 0xFF (8-bit, MSB set) to 32 bits = 0xFFFFFFFF.
    let r2 = s.simplify(SymExpr::SExt {
        expr: Box::new(bv(0xFF, 8)),
        target_width: 32,
    });
    assert_eq!(r2, bv(0xFFFF_FFFF, 32));
}

#[test]
fn t23_const_fold_concat() {
    let s = SymExprSimplifier::new();
    let r = s.simplify(SymExpr::Concat(Box::new(bv(0xAB, 8)), Box::new(bv(0xCD, 8))));
    assert_eq!(r, bv(0xABCD, 16));
}

#[test]
fn t24_const_fold_div_rem() {
    let s = SymExprSimplifier::new();
    let r = s.simplify(SymExpr::UDiv(Box::new(bv(10, 32)), Box::new(bv(3, 32))));
    assert_eq!(r, bv(3, 32));
    let r = s.simplify(SymExpr::URem(Box::new(bv(10, 32)), Box::new(bv(3, 32))));
    assert_eq!(r, bv(1, 32));
}

#[test]
fn t25_div_by_zero_left_as_symbolic() {
    let s = SymExprSimplifier::new();
    let r = s.simplify(SymExpr::UDiv(Box::new(bv(10, 32)), Box::new(bv(0, 32))));
    // Should NOT be folded — div-by-zero is preserved as symbolic node.
    match r {
        SymExpr::UDiv(..) => {}
        other => panic!("expected unfolded UDiv, got {other:?}"),
    }
}

// ── 4. comparison folding ────────────────────────────────────────────────────
#[test]
fn t26_eq_ne_const_fold() {
    let s = SymExprSimplifier::new();
    assert_eq!(
        s.simplify(SymExpr::Eq(Box::new(bv(5, 32)), Box::new(bv(5, 32)))),
        SymExpr::ConstBool(true)
    );
    assert_eq!(
        s.simplify(SymExpr::Ne(Box::new(bv(5, 32)), Box::new(bv(6, 32)))),
        SymExpr::ConstBool(true)
    );
}

#[test]
fn t27_unsigned_vs_signed_compare() {
    let s = SymExprSimplifier::new();
    // 0xFFFFFFFF unsigned > 1, but signed < 1.
    let big = bv(0xFFFF_FFFF, 32);
    let one = bv(1, 32);
    assert_eq!(
        s.simplify(SymExpr::UGt(Box::new(big.clone()), Box::new(one.clone()))),
        SymExpr::ConstBool(true)
    );
    assert_eq!(
        s.simplify(SymExpr::SLt(Box::new(big), Box::new(one))),
        SymExpr::ConstBool(true)
    );
}

// ── 5. eval_concrete and evaluate roundtrips ─────────────────────────────────
#[test]
fn t28_eval_concrete_basic_arith() {
    let env: HashMap<u64, u64> = [(0, 5), (1, 7)].into_iter().collect();
    let a = SymExpr::Symbol(0, 32, "x");
    let b = SymExpr::Symbol(1, 32, "y");
    let sum = SymExpr::Add(Box::new(a), Box::new(b));
    assert_eq!(eval_concrete(&sum, &env), Some(12));
}

#[test]
fn t29_eval_concrete_unknown_var_returns_none() {
    let env: HashMap<u64, u64> = HashMap::new();
    let a = SymExpr::Symbol(99, 32, "x");
    assert_eq!(eval_concrete(&a, &env), None);
}

#[test]
fn t30_evaluate_with_string_env() {
    let mut env = HashMap::new();
    env.insert("x".to_string(), 10u64);
    env.insert("y".to_string(), 3u64);
    let xy = SymExpr::Add(
        Box::new(SymExpr::var("x", SymType::BitVec(64))),
        Box::new(SymExpr::var("y", SymType::BitVec(64))),
    );
    assert_eq!(xy.evaluate(&env), Some(13));
}

#[test]
fn t31_evaluate_div_by_zero_returns_none() {
    let mut env = HashMap::new();
    env.insert("x".to_string(), 10u64);
    env.insert("y".to_string(), 0u64);
    let e = SymExpr::UDiv(
        Box::new(SymExpr::var("x", SymType::BitVec(32))),
        Box::new(SymExpr::var("y", SymType::BitVec(32))),
    );
    assert_eq!(e.evaluate(&env), None);
}

#[test]
fn t32_evaluate_extract_lo_gt_hi_returns_none() {
    // Boundary: extract with lo > hi must not panic; doc says return None.
    let mut env = HashMap::new();
    env.insert("x".to_string(), 0xABCDu64);
    let e = SymExpr::Extract {
        expr: Box::new(SymExpr::var("x", SymType::BitVec(16))),
        hi: 3,
        lo: 7,
    };
    assert_eq!(e.evaluate(&env), None);
}

#[test]
fn t33_evaluate_memory_ops_return_none() {
    let env = HashMap::new();
    let ld = SymExpr::Load {
        addr: Box::new(bv(0x1000, 64)),
        size: 4,
    };
    assert_eq!(ld.evaluate(&env), None);
}

// ── 6. seeded LCG fuzz: simplify never panics ────────────────────────────────
fn gen_expr(rng: &mut impl FnMut() -> u64, depth: u32) -> SymExpr {
    let r = rng();
    if depth == 0 || (r & 0xF) < 3 {
        // leaf
        match r % 3 {
            0 => bv(rng() & 0xFFFF, 32),
            1 => SymExpr::ConstBool(r & 1 == 0),
            _ => SymExpr::var(format!("v{}", r & 0xFF), SymType::BitVec(32)),
        }
    } else {
        let l = gen_expr(rng, depth - 1);
        let rr = gen_expr(rng, depth - 1);
        match r % 10 {
            0 => SymExpr::Add(Box::new(l), Box::new(rr)),
            1 => SymExpr::Sub(Box::new(l), Box::new(rr)),
            2 => SymExpr::Mul(Box::new(l), Box::new(rr)),
            3 => SymExpr::And(Box::new(l), Box::new(rr)),
            4 => SymExpr::Or(Box::new(l), Box::new(rr)),
            5 => SymExpr::Xor(Box::new(l), Box::new(rr)),
            6 => SymExpr::Eq(Box::new(l), Box::new(rr)),
            7 => SymExpr::ULt(Box::new(l), Box::new(rr)),
            8 => SymExpr::UDiv(Box::new(l), Box::new(rr)),
            _ => SymExpr::URem(Box::new(l), Box::new(rr)),
        }
    }
}

#[test]
fn t34_fuzz_simplify_50_inputs_no_panic() {
    let mut rng = make_lcg();
    let s = SymExprSimplifier::new();
    for _ in 0..50 {
        let e = gen_expr(&mut rng, 4);
        let _ = s.simplify(e);
    }
}

#[test]
fn t35_fuzz_bit_width_stable() {
    let mut rng = make_lcg();
    for _ in 0..50 {
        let e = gen_expr(&mut rng, 3);
        let w = e.bit_width();
        // sanity: width is bounded
        assert!(w > 0, "bit_width returned 0 for {e:?}");
    }
}

#[test]
fn t36_fuzz_evaluate_no_panic() {
    let mut rng = make_lcg();
    let env: HashMap<String, u64> = (0..20).map(|i| (format!("v{i}"), rng())).collect();
    for _ in 0..50 {
        let e = gen_expr(&mut rng, 3);
        let _ = e.evaluate(&env); // may be None, must not panic
    }
}

// ── 7. boundaries / overflow paths ──────────────────────────────────────────
#[test]
fn t37_shl_by_64_does_not_panic_eval() {
    let mut env = HashMap::new();
    env.insert("x".to_string(), 1u64);
    env.insert("s".to_string(), 64u64);
    let e = SymExpr::Shl(
        Box::new(SymExpr::var("x", SymType::BitVec(64))),
        Box::new(SymExpr::var("s", SymType::BitVec(64))),
    );
    // Guard documented: evaluate min(63) on shift; should not panic.
    let _ = e.evaluate(&env);
}

#[test]
fn t38_eval_concrete_shl_huge_shift() {
    let env: HashMap<u64, u64> = [(0, 1), (1, 1000)].into_iter().collect();
    let e = SymExpr::Shl(
        Box::new(SymExpr::Symbol(0, 64, "x")),
        Box::new(SymExpr::Symbol(1, 64, "s")),
    );
    // checked_shl returns 0 if shift >= bits; should not panic.
    assert_eq!(eval_concrete(&e, &env), Some(0));
}

#[test]
fn t39_concat_constant_high_part_lost_at_64() {
    let s = SymExprSimplifier::new();
    // 32-bit hi ++ 64-bit lo: shift by 64 must not panic.
    let r = s.simplify(SymExpr::Concat(
        Box::new(bv(0xABCD, 32)),
        Box::new(bv(0xDEAD_BEEF, 64)),
    ));
    // simplifier's concat fold preserves lo when lw>=64.
    if let SymExpr::ConstBv { val, width } = r {
        assert_eq!(val, 0xDEAD_BEEF);
        assert_eq!(width, 96);
    } else {
        panic!("expected ConstBv");
    }
}

#[test]
fn t40_bit_width_off_by_one_extract() {
    let v = SymExpr::var("x", SymType::BitVec(32));
    let e = SymExpr::Extract {
        expr: Box::new(v),
        hi: 0,
        lo: 0,
    };
    assert_eq!(e.bit_width(), 1);
}

// ── 8. Hash/Eq consistency ──────────────────────────────────────────────────
#[test]
fn t41_hash_eq_consistency_30_pairs() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    fn h(e: &SymExpr) -> u64 {
        let mut s = DefaultHasher::new();
        e.hash(&mut s);
        s.finish()
    }
    let mut rng = make_lcg();
    for _ in 0..30 {
        let e = gen_expr(&mut rng, 3);
        let e2 = e.clone();
        assert_eq!(e, e2);
        assert_eq!(h(&e), h(&e2));
    }
}

#[test]
fn t42_symtype_hash_eq() {
    use std::collections::HashSet;
    let mut set: HashSet<SymType> = HashSet::new();
    set.insert(SymType::Bool);
    set.insert(SymType::Bool);
    set.insert(SymType::BitVec(32));
    set.insert(SymType::BitVec(32));
    set.insert(SymType::Pointer);
    assert_eq!(set.len(), 3);
}

// ── 9. SymbolicState ────────────────────────────────────────────────────────
#[test]
fn t43_state_register_default_to_var() {
    let st = SymbolicState::new();
    let r = st.read_register("rax");
    match r {
        SymExpr::Var { name, .. } => assert_eq!(name, "rax"),
        other => panic!("expected var, got {other:?}"),
    }
}

#[test]
fn t44_state_write_then_read() {
    let mut st = SymbolicState::new();
    st.write_register("rax", bv(42, 64));
    assert_eq!(st.read_register("rax"), bv(42, 64));
}

#[test]
fn t45_state_fork_increments_depth() {
    let st = SymbolicState::new();
    let cond = SymExpr::ConstBool(true);
    let child = st.fork(cond.clone());
    assert_eq!(child.depth, 1);
    assert!(child.path_condition.contains(&cond));
}

#[test]
fn t46_state_fork_pair_negates_one_branch() {
    let st = SymbolicState::new();
    let cond = SymExpr::var("c", SymType::Bool);
    let (t, f) = st.fork_pair(cond.clone());
    assert_eq!(t.depth, 1);
    assert_eq!(f.depth, 1);
    assert!(t.path_condition.contains(&cond));
    // false branch wraps cond in BoolNot
    assert!(f
        .path_condition
        .iter()
        .any(|e| matches!(e, SymExpr::BoolNot(_))));
}

#[test]
fn t47_state_assume_unsat_rejects() {
    let mut st = SymbolicState::new();
    let r = st.assume(&SymExpr::ConstBool(false));
    assert!(matches!(r, Err(Unsat)));
    assert!(st.path_condition.is_empty(), "state must not be mutated");
}

#[test]
fn t48_state_assume_satisfiable_appends() {
    let mut st = SymbolicState::new();
    st.assume(&SymExpr::ConstBool(true)).unwrap();
    assert_eq!(st.path_condition.len(), 1);
}

#[test]
fn t49_state_is_path_infeasible_detects_false() {
    let mut st = SymbolicState::new();
    st.add_path_condition(SymExpr::ConstBool(false));
    assert!(st.is_path_infeasible());
    assert!(!st.is_satisfiable());
}

#[test]
fn t50_state_is_satisfiable_empty_is_true() {
    let st = SymbolicState::new();
    assert!(st.is_satisfiable());
}

#[test]
fn t51_state_all_constraints_union() {
    let mut st = SymbolicState::new();
    st.add_path_condition(SymExpr::var("p", SymType::Bool));
    st.add_constraint(SymExpr::var("q", SymType::Bool));
    assert_eq!(st.all_constraints().len(), 2);
}

#[test]
fn t52_state_get_model_seeds_zero() {
    let mut st = SymbolicState::new();
    st.add_path_condition(SymExpr::Eq(
        Box::new(SymExpr::var("a", SymType::BitVec(32))),
        Box::new(bv(0, 32)),
    ));
    let m = st.get_model();
    assert_eq!(m.get("a").copied(), Some(0));
}

#[test]
fn t53_state_merge_same_register_collapses() {
    let mut a = SymbolicState::new();
    let mut b = SymbolicState::new();
    a.write_register("rax", bv(7, 64));
    b.write_register("rax", bv(7, 64));
    let merged = SymbolicState::merge(a, b, &SymExpr::var("c", SymType::Bool));
    // identical values: no ITE wrap
    assert_eq!(merged.read_register("rax"), bv(7, 64));
}

#[test]
fn t54_state_merge_different_registers_introduces_ite() {
    let mut a = SymbolicState::new();
    let mut b = SymbolicState::new();
    a.write_register("rax", bv(1, 64));
    b.write_register("rax", bv(2, 64));
    let merged = SymbolicState::merge(a, b, &SymExpr::var("c", SymType::Bool));
    assert!(matches!(merged.read_register("rax"), SymExpr::Ite { .. }));
}

// ── 10. SymMemory ───────────────────────────────────────────────────────────
#[test]
fn t55_memory_store_load_concrete() {
    let mut m = SymMemory::new();
    m.store_concrete(0x1000, bv(0xAB, 8));
    assert_eq!(m.load_concrete(0x1000), bv(0xAB, 8));
}

#[test]
fn t56_memory_load_unknown_returns_var() {
    let m = SymMemory::new();
    let r = m.load_concrete(0x2000);
    match r {
        SymExpr::Var { name, .. } => assert!(name.contains("mem_")),
        other => panic!("expected var, got {other:?}"),
    }
}

#[test]
fn t57_memory_symbolic_store_load() {
    let mut m = SymMemory::new();
    m.store_symbolic(7, bv(99, 32));
    assert_eq!(m.load_symbolic(7), Some(&bv(99, 32)));
    assert_eq!(m.load_symbolic(8), None);
}

// ── 11. PathConstraint ──────────────────────────────────────────────────────
#[test]
fn t58_path_constraint_empty_conjunction_is_true() {
    let pc = PathConstraint::new();
    assert_eq!(pc.as_conjunction(), SymExpr::ConstBool(true));
    assert!(!pc.is_trivially_false());
}

#[test]
fn t59_path_constraint_false_term_detected() {
    let mut pc = PathConstraint::new();
    pc.add(SymExpr::ConstBool(true));
    pc.add(SymExpr::ConstBool(false));
    assert!(pc.is_trivially_false());
}

#[test]
fn t60_path_constraint_as_conjunction_n_terms() {
    let mut pc = PathConstraint::new();
    for i in 0..5 {
        pc.add(SymExpr::Eq(Box::new(bv(i, 32)), Box::new(bv(i, 32))));
    }
    // The conjunction is left-folded; check that it's a chain of BoolAnd.
    let c = pc.as_conjunction();
    match c {
        SymExpr::BoolAnd(..) => {}
        other => panic!("expected BoolAnd chain, got {other:?}"),
    }
}

// ── 12. SymbolicValue construction ──────────────────────────────────────────
#[test]
fn t61_symbolic_value_new_roundtrip() {
    let v = SymbolicValue::new(42, SymType::BitVec(32), bv(7, 32));
    assert_eq!(v.id, 42);
    assert_eq!(v.ty, SymType::BitVec(32));
    assert_eq!(v.expr, bv(7, 32));
}

// ── 13. Serde round-trip (serialize then deserialize) ───────────────────────
#[test]
fn t62_serde_symexpr_roundtrip_50_inputs() {
    let mut rng = make_lcg();
    for _ in 0..50 {
        let e = gen_expr(&mut rng, 3);
        let s = serde_json::to_string(&e).expect("serialize");
        let back: SymExpr = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(e, back);
    }
}

#[test]
fn t63_serde_state_roundtrip() {
    let mut st = SymbolicState::new();
    st.write_register("rax", bv(1, 64));
    st.add_path_condition(SymExpr::ConstBool(true));
    let s = serde_json::to_string(&st).expect("ser");
    let back: SymbolicState = serde_json::from_str(&s).expect("de");
    assert_eq!(back.registers.len(), 1);
    assert_eq!(back.path_condition.len(), 1);
}

// ── 14. Symbol naming convention preserved ──────────────────────────────────
#[test]
fn t64_symbol_naming_id_suffix() {
    let e = SymExpr::Symbol(7, 32, "alpha");
    match e {
        SymExpr::Var { name, .. } => assert!(name.ends_with("_7"), "name={name}"),
        _ => panic!(),
    }
}

// ── 15. Send + Sync threaded stress ─────────────────────────────────────────
#[test]
fn t65_threaded_simplifier_stress() {
    // SymExprSimplifier is Default and shareable across threads (stateless).
    let expr = Arc::new({
        let x = SymExpr::var("x", SymType::BitVec(32));
        SymExpr::Add(Box::new(x), Box::new(bv(0, 32)))
    });
    let mut handles = vec![];
    for _ in 0..4 {
        let e = expr.clone();
        handles.push(thread::spawn(move || {
            let s = SymExprSimplifier::new();
            for _ in 0..100 {
                let r = s.simplify((*e).clone());
                // x + 0 = x
                assert!(matches!(r, SymExpr::Var { .. }));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn t66_threaded_state_clone_stress() {
    let st = Arc::new({
        let mut s = SymbolicState::new();
        s.write_register("rax", bv(1, 64));
        s
    });
    let mut handles = vec![];
    for _ in 0..4 {
        let s = st.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let c = (*s).clone();
                assert_eq!(c.read_register("rax"), bv(1, 64));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── 16. Ops::Add / Sub via std ops ──────────────────────────────────────────
#[test]
fn t67_std_ops_add_constructs_add_node() {
    let a = bv(1, 32);
    let b = bv(2, 32);
    let s = a + b;
    match s {
        SymExpr::Add(..) => {}
        other => panic!("expected Add, got {other:?}"),
    }
}

#[test]
fn t68_std_ops_sub_constructs_sub_node() {
    let a = bv(5, 32);
    let b = bv(3, 32);
    let s = a - b;
    match s {
        SymExpr::Sub(..) => {}
        other => panic!("expected Sub, got {other:?}"),
    }
}

// ── 17. SymType::width ──────────────────────────────────────────────────────
#[test]
fn t69_symtype_width_table() {
    assert_eq!(SymType::Bool.width(), None);
    assert_eq!(SymType::BitVec(13).width(), Some(13));
    assert_eq!(SymType::Pointer.width(), Some(64));
    let arr = SymType::Array {
        elem_ty: Box::new(SymType::BitVec(8)),
        len: Some(16),
    };
    assert_eq!(arr.width(), None);
}

// ── 18. ugt / uge helpers ───────────────────────────────────────────────────
#[test]
fn t70_ugt_uge_helpers() {
    let r = SymExpr::ugt(bv(5, 32), bv(3, 32));
    assert!(matches!(r, SymExpr::UGt(..)));
    let r = SymExpr::uge(bv(5, 32), bv(5, 32));
    assert!(matches!(r, SymExpr::UGe(..)));
}

// ── 19. SymbolicError Debug + Display ───────────────────────────────────────
#[test]
fn t71_unsat_display_nonempty() {
    let u = Unsat;
    let s = format!("{u}");
    assert!(!s.is_empty());
}
