//! Randomized property / oracle tests for the type lattice and unifier.
//!
//! Deterministic seeded PRNG (xorshift64*), no external dependencies. Each
//! property runs 500–2000 trials. Where a brute-force oracle is cheap it is
//! preferred over self-consistency, because an oracle catches bugs that
//! self-consistency cannot.

use crate::constraints::{ConstraintFact, TypeConstraintSolver, VarRef};
use crate::lattice::{TypeClass, TypeLevel};
use crate::type_inference_engine::{
    BaseType, GeneralizedType, Substitution, TypeEnv, TypeTerm, TypeVariable, Unification,
};
use crate::TypeFact;

// ── PRNG ─────────────────────────────────────────────────────────────────────

struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % (n as u64)) as usize
    }
}

// ── Generators ───────────────────────────────────────────────────────────────

const WIDTHS: [usize; 4] = [1, 2, 4, 8];

fn gen_fact(rng: &mut Rng, depth: usize) -> TypeFact {
    let arms = if depth == 0 { 7 } else { 9 };
    match rng.below(arms) {
        0 => TypeFact::Unknown,
        1 => TypeFact::Sized(WIDTHS[rng.below(4)]),
        2 => TypeFact::SignedInt(WIDTHS[rng.below(4)]),
        3 => TypeFact::UnsignedInt(WIDTHS[rng.below(4)]),
        4 => TypeFact::Float(if rng.below(2) == 0 { 4 } else { 8 }),
        5 => TypeFact::Bool,
        6 => TypeFact::Char,
        7 => TypeFact::Pointer(Box::new(gen_fact(rng, depth - 1))),
        _ => TypeFact::Array {
            element: Box::new(gen_fact(rng, depth - 1)),
            length: if rng.below(2) == 0 {
                Some(1 + rng.below(4))
            } else {
                None
            },
        },
    }
}

fn gen_level(rng: &mut Rng) -> TypeLevel {
    match rng.below(6) {
        0 => TypeLevel::Top,
        1 => TypeLevel::Width(WIDTHS[rng.below(4)]),
        2 => TypeLevel::Class(gen_class(rng)),
        3 => TypeLevel::Concrete(gen_fact(rng, 1)),
        4 => TypeLevel::LibrarySignature,
        _ => TypeLevel::Conflict,
    }
}

fn gen_class(rng: &mut Rng) -> TypeClass {
    match rng.below(6) {
        0 => TypeClass::Integer(WIDTHS[rng.below(4)]),
        1 => TypeClass::Float(if rng.below(2) == 0 { 4 } else { 8 }),
        2 => TypeClass::Pointer(8),
        3 => TypeClass::Boolean,
        4 => TypeClass::Character,
        _ => TypeClass::Aggregate(WIDTHS[rng.below(4)]),
    }
}

fn gen_term(rng: &mut Rng, depth: usize) -> TypeTerm {
    let arms = if depth == 0 { 2 } else { 4 };
    match rng.below(arms) {
        0 => TypeTerm::Var(TypeVariable::new(rng.below(4) as u32)),
        1 => TypeTerm::Base(match rng.below(4) {
            0 => BaseType::Int(32),
            1 => BaseType::UInt(64),
            2 => BaseType::Float(64),
            _ => BaseType::Bool,
        }),
        2 => TypeTerm::Ptr(Box::new(gen_term(rng, depth - 1))),
        _ => {
            let n = rng.below(3);
            TypeTerm::Func(
                (0..n).map(|_| gen_term(rng, depth - 1)).collect(),
                Box::new(gen_term(rng, depth - 1)),
            )
        }
    }
}

// ── Oracles ──────────────────────────────────────────────────────────────────

/// Ground-truth refinement order, written independently of `TypeFact::join`:
/// `refines(a, b)` == "a is at least as specific as b".
fn refines(a: &TypeFact, b: &TypeFact) -> bool {
    if a == b || *b == TypeFact::Unknown {
        return true;
    }
    match (a, b) {
        (_, TypeFact::Sized(n)) => a.byte_size() == Some(*n),
        (TypeFact::Pointer(x), TypeFact::Pointer(y)) => refines(x, y),
        _ => false,
    }
}

// ── Properties: TypeFact::join ───────────────────────────────────────────────

#[test]
fn prop_typefact_join_commutative_and_idempotent() {
    let mut rng = Rng::new(0xC0FF_EE01);
    for _ in 0..2000 {
        let a = gen_fact(&mut rng, 2);
        let b = gen_fact(&mut rng, 2);
        assert_eq!(a.join(&a), a, "join not idempotent on {a:?}");
        assert_eq!(a.join(&b), b.join(&a), "join not commutative: {a:?} {b:?}");
    }
}

#[test]
fn prop_typefact_join_is_a_true_lower_bound() {
    let mut rng = Rng::new(0xC0FF_EE02);
    for _ in 0..2000 {
        let a = gen_fact(&mut rng, 2);
        let b = gen_fact(&mut rng, 2);
        let j = a.join(&b);
        // `TypeFact::join` is a *meet* that widens on conflict (Unknown is Top).
        // So the result must be comparable to each input in the refinement
        // order: either it refines the input (a genuine meet) or the input
        // refines it (a widening). An incomparable result would be a fabricated
        // type unrelated to the evidence.
        for input in [&a, &b] {
            assert!(
                refines(&j, input) || refines(input, &j),
                "join({a:?},{b:?})={j:?} is incomparable to {input:?}"
            );
        }
    }
}

/// Associativity holds on *pairwise-compatible* triples. It does NOT hold in
/// general, because `TypeFact::Unknown` is overloaded as both the lattice Top
/// and the "contradictory evidence" result, so a conflict is indistinguishable
/// from "no information" and gets re-absorbed by a later join. See the module
/// docs of `TypeFact::join`; a general fix needs a distinct `Conflict` variant.
#[test]
fn prop_typefact_join_associative_on_compatible_triples() {
    let mut rng = Rng::new(0xC0FF_EE03);
    for _ in 0..2000 {
        let a = gen_fact(&mut rng, 2);
        let b = gen_fact(&mut rng, 2);
        let c = gen_fact(&mut rng, 2);
        // Compatible == the pairwise join is a genuine meet at every nesting
        // depth (it refines both inputs rather than widening on a conflict).
        let compatible = |x: &TypeFact, y: &TypeFact| {
            let j = x.join(y);
            refines(&j, x) && refines(&j, y)
        };
        if !(compatible(&a, &b) && compatible(&b, &c) && compatible(&a, &c)) {
            continue;
        }
        assert_eq!(
            a.join(&b).join(&c),
            a.join(&b.join(&c)),
            "join not associative: {a:?} {b:?} {c:?}"
        );
    }
}

/// Brute-force oracle: `TypeFact::join` is a meet, so it must equal the
/// *greatest lower bound* of `{a, b}` over a finite universe, computed only
/// from the independent `refines` relation.
#[test]
fn oracle_typefact_join_equals_brute_force_glb() {
    let universe: Vec<TypeFact> = {
        let mut u = vec![
            TypeFact::Unknown,
            TypeFact::Bool,
            TypeFact::Char,
            TypeFact::Float(4),
            TypeFact::Float(8),
        ];
        for w in WIDTHS {
            u.push(TypeFact::Sized(w));
            u.push(TypeFact::SignedInt(w));
            u.push(TypeFact::UnsignedInt(w));
        }
        let base = u.clone();
        u.extend(base.into_iter().map(|t| TypeFact::Pointer(Box::new(t))));
        u
    };
    for a in &universe {
        for b in &universe {
            // Lower bounds: elements that refine both a and b.
            let lowers: Vec<&TypeFact> = universe
                .iter()
                .filter(|l| refines(l, a) && refines(l, b))
                .collect();
            // Greatest lower bounds: lower bounds with nothing strictly above them.
            let greatest: Vec<&&TypeFact> = lowers
                .iter()
                .filter(|l| {
                    !lowers
                        .iter()
                        .any(|v| v != *l && refines(l, v) && !refines(v, l))
                })
                .collect();
            if greatest.len() == 1 {
                let expect = *greatest[0];
                let got = a.join(b);
                assert_eq!(&got, expect, "join({a:?},{b:?}) = {got:?}, GLB = {expect:?}");
            }
        }
    }
}

// ── Properties: TypeLevel lattice ────────────────────────────────────────────

#[test]
fn prop_typelevel_join_meet_commutative_idempotent() {
    let mut rng = Rng::new(0xC0FF_EE04);
    for _ in 0..2000 {
        let a = gen_level(&mut rng);
        let b = gen_level(&mut rng);
        assert_eq!(a.join(&a), a, "TypeLevel::join not idempotent: {a:?}");
        assert_eq!(a.meet(&a), a, "TypeLevel::meet not idempotent: {a:?}");
        assert_eq!(
            a.join(&b),
            b.join(&a),
            "TypeLevel::join not commutative: {a:?} {b:?}"
        );
        assert_eq!(
            a.meet(&b),
            b.meet(&a),
            "TypeLevel::meet not commutative: {a:?} {b:?}"
        );
    }
}

#[test]
fn prop_typelevel_join_never_conflicts_and_meet_is_lower() {
    let mut rng = Rng::new(0xC0FF_EE05);
    for _ in 0..2000 {
        let a = gen_level(&mut rng);
        let b = gen_level(&mut rng);
        let j = a.join(&b);
        if a != TypeLevel::Conflict && b != TypeLevel::Conflict {
            assert_ne!(j, TypeLevel::Conflict, "join produced Conflict: {a:?} {b:?}");
        }
        // join generalises: it is never more specific than both inputs.
        assert!(
            j.specificity() <= a.specificity().max(b.specificity()),
            "join({a:?},{b:?})={j:?} more specific than both"
        );
        let m = a.meet(&b);
        assert!(
            m.specificity() >= a.specificity().min(b.specificity()),
            "meet({a:?},{b:?})={m:?} less specific than both"
        );
    }
}

// ── Properties: unification ──────────────────────────────────────────────────

#[test]
fn prop_unify_produces_a_real_unifier() {
    let mut rng = Rng::new(0xC0FF_EE06);
    for _ in 0..2000 {
        let a = gen_term(&mut rng, 3);
        let b = gen_term(&mut rng, 3);
        if let Ok(s) = Unification::unify(&a, &b) {
            assert_eq!(
                a.apply(&s),
                b.apply(&s),
                "unify({a}, {b}) is not a unifier (subst len {})",
                s.len()
            );
        }
    }
}

#[test]
fn prop_unify_substitution_is_idempotent() {
    let mut rng = Rng::new(0xC0FF_EE07);
    for _ in 0..2000 {
        let a = gen_term(&mut rng, 3);
        let b = gen_term(&mut rng, 3);
        if let Ok(s) = Unification::unify(&a, &b) {
            let once = a.apply(&s);
            let twice = once.apply(&s);
            assert_eq!(once, twice, "substitution not idempotent on {a} vs {b}");
        }
    }
}

#[test]
fn prop_unify_is_symmetric_in_solvability() {
    let mut rng = Rng::new(0xC0FF_EE08);
    for _ in 0..1000 {
        let a = gen_term(&mut rng, 3);
        let b = gen_term(&mut rng, 3);
        assert_eq!(
            Unification::unify(&a, &b).is_ok(),
            Unification::unify(&b, &a).is_ok(),
            "solvability not symmetric: {a} vs {b}"
        );
    }
}

#[test]
fn prop_generalize_quantifier_order_is_deterministic_and_sorted() {
    let mut rng = Rng::new(0xC0FF_EE09);
    for _ in 0..1000 {
        let t = gen_term(&mut rng, 3);
        let env = TypeEnv::new();
        let g1 = GeneralizedType::generalize(&env, t.clone());
        let g2 = GeneralizedType::generalize(&env, t.clone());
        assert_eq!(g1.quantified, g2.quantified, "quantifier order unstable: {t}");
        assert!(
            g1.quantified.windows(2).all(|w| w[0] < w[1]),
            "quantifiers not sorted/deduped: {:?}",
            g1.quantified
        );
    }
}

#[test]
fn prop_deep_ptr_nesting_terminates() {
    // 100_000 levels of Ptr must not overflow the stack in unify/apply/free_vars.
    let mut a = TypeTerm::Var(TypeVariable::new(0));
    let mut b = TypeTerm::Base(BaseType::Int(32));
    for _ in 0..100_000 {
        a = TypeTerm::Ptr(Box::new(a));
        b = TypeTerm::Ptr(Box::new(b));
    }
    let s = Unification::unify(&a, &b).expect("deep ptr spines unify");
    assert_eq!(s.len(), 1);
    assert_eq!(a.free_vars().len(), 1);
    let applied = a.apply(&s);
    assert_eq!(applied.free_vars().len(), 0);
}

// ── Properties: constraint solving ───────────────────────────────────────────

fn gen_constraint(rng: &mut Rng, nvars: u32) -> ConstraintFact {
    let a = VarRef::new(0, rng.below(nvars as usize) as u32);
    let b = VarRef::new(0, rng.below(nvars as usize) as u32);
    match rng.below(5) {
        0 => ConstraintFact::SameType { a, b },
        1 => ConstraintFact::HasSize {
            var: a,
            size: WIDTHS[rng.below(4)] as u8,
        },
        2 => ConstraintFact::IsSigned { var: a },
        3 => ConstraintFact::IsUnsigned { var: a },
        _ => ConstraintFact::IsPointer {
            var: a,
            pointee_size: if rng.below(2) == 0 { Some(4) } else { None },
        },
    }
}

/// `solve()` must not depend on the order in which *independent* kinds of
/// constraint were inserted. Conflicting sign hints (`IsSigned` + `IsUnsigned`
/// on the same class) are genuinely last-writer-wins, so those permutations
/// are excluded from the comparison.
#[test]
fn prop_solve_is_permutation_independent() {
    let mut rng = Rng::new(0xC0FF_EE0A);
    for _ in 0..500 {
        let n = 3 + rng.below(6);
        let facts: Vec<ConstraintFact> = (0..n).map(|_| gen_constraint(&mut rng, 4)).collect();
        // Skip sets containing both a signed and an unsigned hint (order-sensitive
        // by design: later evidence overrides earlier).
        let has_signed = facts
            .iter()
            .any(|f| matches!(f, ConstraintFact::IsSigned { .. }));
        let has_unsigned = facts
            .iter()
            .any(|f| matches!(f, ConstraintFact::IsUnsigned { .. }));
        // Same for contradictory widths: `HasSize(4)` + `HasSize(8)` on the
        // same variable is irreconcilable evidence, resolved last-writer-wins.
        let mut sizes: Vec<u8> = facts
            .iter()
            .filter_map(|f| match f {
                ConstraintFact::HasSize { size, .. } => Some(*size),
                _ => None,
            })
            .collect();
        sizes.dedup();
        sizes.sort_unstable();
        sizes.dedup();
        if (has_signed && has_unsigned) || sizes.len() > 1 {
            continue;
        }
        let mut base = TypeConstraintSolver::new();
        base.add_facts(facts.clone());
        let sol = base.solve();

        // Compare against several random permutations.
        for _ in 0..4 {
            let mut permuted = facts.clone();
            for i in (1..permuted.len()).rev() {
                permuted.swap(i, rng.below(i + 1));
            }
            let mut s2 = TypeConstraintSolver::new();
            s2.add_facts(permuted.clone());
            let sol2 = s2.solve();
            assert_eq!(sol.len(), sol2.len(), "var count differs under permutation");
            for (var, ty) in sol.iter() {
                assert_eq!(
                    &sol2.type_of(var),
                    ty,
                    "solve() order-dependent for {var:?}\nbase: {facts:?}\nperm: {permuted:?}"
                );
            }
        }
    }
}

/// Unifying variables must be an equivalence: variables in the same
/// `SameType` component must all receive the same type.
#[test]
fn prop_solve_same_type_components_agree() {
    let mut rng = Rng::new(0xC0FF_EE0B);
    for _ in 0..500 {
        let n = 4 + rng.below(6);
        let facts: Vec<ConstraintFact> = (0..n).map(|_| gen_constraint(&mut rng, 5)).collect();
        let mut solver = TypeConstraintSolver::new();
        solver.add_facts(facts.clone());
        let sol = solver.solve();
        for f in &facts {
            if let ConstraintFact::SameType { a, b } = f {
                assert_eq!(
                    sol.type_of(*a),
                    sol.type_of(*b),
                    "SameType({a:?},{b:?}) not respected in {facts:?}"
                );
            }
        }
    }
}

#[test]
fn prop_substitution_compose_is_associative_on_terms() {
    let mut rng = Rng::new(0xC0FF_EE0C);
    for _ in 0..1000 {
        let mk = |rng: &mut Rng| {
            let mut s = Substitution::new();
            for _ in 0..(1 + rng.below(3)) {
                s.insert(
                    TypeVariable::new(rng.below(4) as u32),
                    gen_term(rng, 1),
                );
            }
            s
        };
        let (s1, s2, s3) = (mk(&mut rng), mk(&mut rng), mk(&mut rng));
        let t = gen_term(&mut rng, 2);
        let left = t.apply(&s3.compose(&s2).compose(&s1));
        let right = t.apply(&s3.compose(&s2.compose(&s1)));
        assert_eq!(left, right, "compose not associative on {t}");
    }
}
