//! `TypeConstraint::Deref` must not lose information (T39).
//!
//! # The suspicion, and why it was worth checking
//!
//! `rustre-analysis-type/src/lib.rs:437` has an empty match arm:
//!
//! ```text
//! TypeConstraint::Deref { .. } => {}
//! ```
//!
//! In a constraint solver, an empty arm normally means a constraint that was
//! accepted and then dropped — the caller gets a confident, wrong answer rather
//! than an `Unknown`, which is the failure mode this project keeps finding.
//! It was recorded as T39: "da verificare se intenzionale".
//!
//! # Refuted, by behaviour rather than by reading
//!
//! The arm is deliberate. Deref is handled by a dedicated pass that runs *after*
//! all `Equal` constraints are resolved, iterated to a fixed point; deriving
//! pointer types inline, mid-unification, made the result depend on the order
//! constraints were added. `solve_checked` even reports whether that fixpoint
//! converged instead of silently truncating.
//!
//! Reading the comment is not verification — the comment could describe an
//! intention the code no longer implements. These tests exercise the solver
//! through its public API and assert the information actually survives.
//!
//! The crate under test is `rustre-analysis-type`, which is not one of the four
//! this effort owns. The tests live here, in `typerecov`, which depends on it:
//! the behaviour gets pinned from the consumer's side without editing another
//! crate's sources.

use std::collections::HashMap;

use rustre_analysis_type::{TypeConstraint, TypeFact, TypeInferenceEngine, TypeVar};

fn solved(constraints: Vec<TypeConstraint>) -> HashMap<u32, TypeFact> {
    let mut engine = TypeInferenceEngine::new();
    for c in constraints {
        engine.add_constraint(c);
    }
    engine.solve().expect("il solver non deve fallire su questi vincoli")
}

#[test]
fn a_deref_makes_the_pointer_a_pointer_to_the_pointee_type() {
    // The whole point of the constraint. If the arm really discarded it, `p`
    // would come back Unknown (or merely Sized) and every dereferenced variable
    // in the decompiler would lose its pointer type.
    let facts = solved(vec![
        TypeConstraint::HasType(TypeVar(1), TypeFact::UnsignedInt(4)),
        TypeConstraint::Deref {
            ptr: TypeVar(0),
            pointee: TypeVar(1),
        },
    ]);

    let p = facts.get(&0).expect("il puntatore deve avere un fatto");
    assert!(
        matches!(p, TypeFact::Pointer(inner) if **inner == TypeFact::UnsignedInt(4)),
        "atteso Pointer(UnsignedInt(4)), ottenuto {p:?}: l'informazione di \
         dereferenziazione e' stata scartata"
    );
}

#[test]
fn a_deref_stated_before_its_pointee_type_still_resolves() {
    // The ordering case the dedicated pass exists for. Constraint order is
    // arbitrary in a real walk, so a solver that only worked when the pointee's
    // type arrived first would be correct by luck.
    let facts = solved(vec![
        TypeConstraint::Deref {
            ptr: TypeVar(0),
            pointee: TypeVar(1),
        },
        TypeConstraint::HasType(TypeVar(1), TypeFact::UnsignedInt(4)),
    ]);

    let p = facts.get(&0).expect("il puntatore deve avere un fatto");
    assert!(
        matches!(p, TypeFact::Pointer(inner) if **inner == TypeFact::UnsignedInt(4)),
        "l'ordine dei vincoli cambia il risultato: ottenuto {p:?}"
    );
}

#[test]
fn deref_is_order_independent() {
    // Stated as its own property, the way `unifier_properties.rs` does it: the
    // solved assignment must be a function of the constraint *set*, not of the
    // sequence. This is the property the empty arm exists to protect, so it is
    // the one that must hold.
    let a = TypeConstraint::HasType(TypeVar(1), TypeFact::UnsignedInt(4));
    let b = TypeConstraint::Deref {
        ptr: TypeVar(0),
        pointee: TypeVar(1),
    };
    let c = TypeConstraint::Equal(TypeVar(1), TypeVar(2));

    let forward = solved(vec![a.clone(), b.clone(), c.clone()]);
    let reverse = solved(vec![c.clone(), b.clone(), a.clone()]);
    let shuffled = solved(vec![b, a, c]);

    assert_eq!(forward, reverse, "ordine inverso da' un risultato diverso");
    assert_eq!(forward, shuffled, "ordine mescolato da' un risultato diverso");
}

#[test]
fn chained_derefs_produce_a_pointer_to_a_pointer() {
    // A single non-iterated pass would resolve the outer Deref against an inner
    // type that was still Unknown, silently flattening one level. Two levels is
    // the smallest case that can tell the difference.
    let facts = solved(vec![
        TypeConstraint::Deref {
            ptr: TypeVar(0),
            pointee: TypeVar(1),
        },
        TypeConstraint::Deref {
            ptr: TypeVar(1),
            pointee: TypeVar(2),
        },
        TypeConstraint::HasType(TypeVar(2), TypeFact::UnsignedInt(1)),
    ]);

    let outer = facts.get(&0).expect("il puntatore esterno deve avere un fatto");
    let TypeFact::Pointer(mid) = outer else {
        panic!("atteso un puntatore al livello esterno, ottenuto {outer:?}");
    };
    assert!(
        matches!(&**mid, TypeFact::Pointer(inner) if **inner == TypeFact::UnsignedInt(1)),
        "atteso Pointer(Pointer(UnsignedInt(1))), ottenuto {outer:?}: la catena \
         di dereferenziazioni e' stata appiattita di un livello"
    );
}

/// A Deref cycle (`p → q`, `q → p`) would deepen the pointer type forever. The
/// solver caps the fixpoint and reports non-convergence rather than hanging or
/// pretending. Pinned because "terminates" and "converged" are different
/// answers, and collapsing them is how a truncated result gets published as a
/// complete one.
#[test]
fn a_deref_cycle_is_reported_as_not_converged_rather_than_hanging() {
    let mut engine = TypeInferenceEngine::new();
    engine.add_constraint(TypeConstraint::Deref {
        ptr: TypeVar(0),
        pointee: TypeVar(1),
    });
    engine.add_constraint(TypeConstraint::Deref {
        ptr: TypeVar(1),
        pointee: TypeVar(0),
    });
    engine.add_constraint(TypeConstraint::HasType(TypeVar(0), TypeFact::Sized(8)));

    let (_facts, converged) = engine
        .solve_checked()
        .expect("un ciclo non deve essere un errore: e' un input legittimo");
    assert!(
        !converged,
        "un ciclo di Deref e' stato dichiarato convergente: allora o il cap non \
         e' stato raggiunto (aggiorna il test) o la non-convergenza e' silenziosa"
    );
}
