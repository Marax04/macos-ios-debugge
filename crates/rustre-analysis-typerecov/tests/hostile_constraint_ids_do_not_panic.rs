//! A hostile `TypeVar` id inside a constraint must be an error, not a panic (T24).
//!
//! # The half the previous fix missed
//!
//! Iteration 63 made `TypeUnifier::try_new` reject an adversarial `var_count`.
//! That covered the constructor and nothing else: constraints carry their own
//! `TypeVar` ids, they are built from the analysed binary, and `solve` fed them
//! straight into the union-find.
//!
//! Measured before this fix, a single constraint was enough:
//!
//! ```text
//! TypeVar(16777215) -> PANIC
//!   "would grow union-find by 16777212 nodes in one call (max 4096)"
//! ```
//!
//! Note the id: **below** the capacity cap. So it was not even an out-of-range
//! value — an id inside the legal range aborted the process, because the
//! anti-amplification guard was written as an `assert!`. Checking `var_count`
//! alone would never have found it, which is why the probe went through the
//! public entry point instead of the constructor.
//!
//! `solve` now validates every id in the constraint set before touching the
//! union-find, and pre-grows capacity in bounded steps so the per-call guard
//! stays an internal invariant rather than a reachable panic.

use rustre_analysis_typerecov::TypeVar;
use rustre_analysis_typerecov::type_constraint_generator::{
    ConstraintKind, Provenance, TypeConstraint,
};
use rustre_analysis_typerecov::type_unifier::{TypeUnifier, UnifyError, unify_types};

fn equal(lhs: u32, rhs: u32) -> TypeConstraint {
    TypeConstraint::certain(
        0,
        ConstraintKind::Equal {
            lhs: TypeVar::new(lhs),
            rhs: TypeVar::new(rhs),
        },
        Provenance::new(0, "test"),
    )
}

/// The exact value that used to abort: large, sparse, but legal.
#[test]
fn a_large_but_legal_id_solves_instead_of_aborting() {
    let id = TypeUnifier::MAX_VARIABLES - 1;
    let r = unify_types(&[equal(0, id)], 4);
    assert!(
        r.is_ok(),
        "un id dentro il tetto deve risolvere, ottenuto {r:?} — era questo il \
         caso che abortiva il processo"
    );
}

#[test]
fn an_id_past_the_cap_is_reported_as_an_error() {
    for id in [TypeUnifier::MAX_VARIABLES, u32::MAX] {
        match unify_types(&[equal(0, id)], 4) {
            Err(UnifyError::TooManyVariables { max, .. }) => {
                assert_eq!(max, TypeUnifier::MAX_VARIABLES);
            }
            other => panic!("atteso TooManyVariables per {id}, ottenuto {other:?}"),
        }
    }
}

/// Every constraint shape carries ids, so validating only `Equal` would leave
/// the others as a way in. One representative of each shape that names a
/// variable.
#[test]
fn every_constraint_shape_is_validated() {
    let huge = TypeVar::new(u32::MAX);
    let shapes = [
        ConstraintKind::Equal { lhs: TypeVar::new(0), rhs: huge },
        ConstraintKind::IsPointerTo { ptr: huge, pointee: TypeVar::new(0) },
        ConstraintKind::IsInteger { var: huge, min_width: 4, signed: None },
        ConstraintKind::IsFloat { var: huge, width: 8 },
    ];
    for (i, kind) in shapes.into_iter().enumerate() {
        let c = TypeConstraint::certain(0, kind, Provenance::new(0, "test"));
        let r = unify_types(&[c], 4);
        assert!(
            matches!(r, Err(UnifyError::TooManyVariables { .. })),
            "forma {i}: un id ostile non e' stato validato, ottenuto {r:?}"
        );
    }
}

/// Sparse but ordinary ids must keep working — a fix that rejected them would
/// have traded a panic for a broken feature.
#[test]
fn ordinary_sparse_ids_still_solve() {
    let cs = vec![equal(0, 1), equal(1, 5000), equal(5000, 100_000)];
    let r = unify_types(&cs, 4);
    assert!(r.is_ok(), "id sparsi ma legittimi devono risolvere: {r:?}");
}
