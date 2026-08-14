//! The one law a simplifier cannot break: it must not change what an
//! expression means.
//!
//! `SymExpr::evaluate` says in its own documentation that the semantics of this
//! crate are implemented *three* times — here, in `SymExprSimplifier`, and in
//! `formula_simplifier::ConstantFolding` — and that a past divergence between
//! them made a model "scored satisfiable or unsatisfiable on a wrong number".
//! Three independent interpreters is exactly the shape that drifts, so this
//! checks them against each other by enumeration instead of by inspection.

use std::collections::HashMap;

use rustre_symb::{SymExpr, SymType};

const W: u32 = 8;
const MASK: u64 = 0xFF;

fn bv(v: u64) -> SymExpr {
    SymExpr::ConstBv { val: v & MASK, width: W }
}

fn var(n: &str) -> SymExpr {
    SymExpr::var(n, SymType::BitVec(W))
}

/// Small expression shapes over two variables and a few constants.
fn expressions() -> Vec<SymExpr> {
    let atoms = vec![var("a"), var("b"), bv(0), bv(1), bv(0xFF), bv(0x80)];
    let mut out = atoms.clone();

    // Unary
    for a in &atoms {
        out.push(SymExpr::Not(Box::new(a.clone())));
        out.push(SymExpr::Neg(Box::new(a.clone())));
    }

    // Binary, over every ordered pair
    for l in &atoms {
        for r in &atoms {
            let (lb, rb) = (Box::new(l.clone()), Box::new(r.clone()));
            out.push(SymExpr::Add(lb.clone(), rb.clone()));
            out.push(SymExpr::Sub(lb.clone(), rb.clone()));
            out.push(SymExpr::Mul(lb.clone(), rb.clone()));
            out.push(SymExpr::And(lb.clone(), rb.clone()));
            out.push(SymExpr::Or(lb.clone(), rb.clone()));
            out.push(SymExpr::Xor(lb.clone(), rb.clone()));
        }
    }

    // One nesting level, to reach rules that only fire on compound trees.
    let shallow: Vec<SymExpr> = out.clone();
    for e in shallow.iter().take(40) {
        out.push(SymExpr::Add(Box::new(e.clone()), Box::new(var("a"))));
        out.push(SymExpr::Xor(Box::new(e.clone()), Box::new(bv(0xFF))));
        out.push(SymExpr::Not(Box::new(e.clone())));
    }

    out
}

/// Concrete environments to evaluate under.
fn envs() -> Vec<HashMap<String, u64>> {
    let vals = [0u64, 1, 2, 0x7F, 0x80, 0xFE, 0xFF];
    let mut out = Vec::new();
    for a in vals {
        for b in vals {
            let mut m = HashMap::new();
            m.insert("a".to_string(), a);
            m.insert("b".to_string(), b);
            out.push(m);
        }
    }
    out
}

/// `simplify` must preserve meaning under every concrete assignment.
#[test]
fn simplify_preserves_evaluation() {
    let envs = envs();
    for e in expressions() {
        let s = e.simplify();
        for env in &envs {
            let before = e.evaluate(env);
            let after = s.evaluate(env);
            assert_eq!(
                before, after,
                "simplify changed the meaning of {e:?}\n  into {s:?}\n  \
                 env a={:?} b={:?}: {before:?} became {after:?}",
                env.get("a"),
                env.get("b"),
            );
        }
    }
}

/// Simplification must not change the width of the value being computed.
#[test]
fn simplify_preserves_bit_width() {
    for e in expressions() {
        let before = e.bit_width();
        let after = e.simplify().bit_width();
        assert_eq!(
            before, after,
            "simplify changed bit_width of {e:?} from {before} to {after}"
        );
    }
}

/// Simplification must be idempotent: applying it twice adds nothing.
///
/// A non-idempotent simplifier means the fixpoint was never reached, so callers
/// get different trees depending on how many times they happened to call it.
#[test]
fn simplify_is_idempotent() {
    for e in expressions() {
        let once = e.simplify();
        let twice = once.simplify();
        assert_eq!(
            once, twice,
            "simplify is not at a fixpoint for {e:?}:\n  once = {once:?}\n  twice = {twice:?}"
        );
    }
}

/// Guards the three laws above against passing vacuously.
///
/// If `simplify` were a near no-op on these shapes, "simplification preserves
/// meaning" would be true for the uninteresting reason that nothing is ever
/// simplified. This asserts the generator actually reaches the rewrite rules,
/// so a future change that silently disables them fails *here* rather than
/// leaving three green tests that no longer test anything.
#[test]
fn the_generator_actually_exercises_the_rewriter() {
    let all = expressions();
    let changed = all.iter().filter(|e| &e.simplify() != *e).count();

    assert!(
        changed * 10 >= all.len(),
        "simplify rewrote only {changed} of {} expressions — the preservation \
         laws would be passing vacuously",
        all.len()
    );
}

// A substitution law would belong here too, but `substitute` is a method of
// `SpecSymExpr`, not `SymExpr` — a different type with its own interpreter.
// Checking it needs its own expression generator, so it is left for a later
// pass rather than asserted against the wrong type.
