//! An adversarial variable count must be an error, not a process kill (T24).
//!
//! # What was measured
//!
//! T24 records "55 `unwrap/expect/panic` on 54 `pub fn`". Counted properly —
//! excluding `#[cfg(test)]` blocks by brace depth rather than cutting at the
//! first one — production code has **9**, not 55; the 55 counts test code, the
//! same over-count this project has hit before.
//!
//! But the count was the wrong thing to look at. The reachable one was an
//! `assert!` no regex for `unwrap|expect|panic` would have found:
//!
//! ```text
//! // Guard against OOM from an adversarially large var_count.
//! const MAX_NODES: u32 = 1 << 24;
//! assert!(n <= MAX_NODES, …);
//! ```
//!
//! The comment states the input is adversarial, and then guards it by panicking.
//! Measured before the fix: `TypeUnifier::new(16_777_217)` aborted the process.
//! `var_count` is derived from the analysed binary, so a crafted file could take
//! down any tool built on this crate — panicking *is* the denial of service the
//! guard was meant to prevent.
//!
//! `TypeUnifier::try_new` and the `unify_types` entry point now return
//! [`UnifyError::TooManyVariables`] instead. `new` still panics and says so, for
//! callers with a count they control.

use rustre_analysis_typerecov::type_unifier::{TypeUnifier, UnifyError, unify_types};

#[test]
fn the_cap_is_where_the_documentation_says() {
    assert_eq!(
        TypeUnifier::MAX_VARIABLES,
        1 << 24,
        "il tetto e' cambiato: aggiorna il doc e rimisura il costo di memoria"
    );
}

#[test]
fn a_count_at_the_cap_is_accepted() {
    // The boundary matters in both directions: a cap that rejects its own limit
    // would silently lose the largest legitimate input.
    assert!(
        TypeUnifier::try_new(TypeUnifier::MAX_VARIABLES).is_ok(),
        "il conteggio esattamente al tetto deve essere accettato"
    );
}

#[test]
fn a_count_past_the_cap_is_an_error_not_a_panic() {
    for n in [TypeUnifier::MAX_VARIABLES + 1, u32::MAX / 2, u32::MAX] {
        match TypeUnifier::try_new(n) {
            Err(UnifyError::TooManyVariables { requested, max }) => {
                assert_eq!(requested, n);
                assert_eq!(max, TypeUnifier::MAX_VARIABLES);
            }
            Err(other) => panic!("errore inatteso per {n}: {other}"),
            Ok(_) => panic!(
                "try_new({n}) accettato: il tetto non protegge piu' dall'OOM"
            ),
        }
    }
}

/// The public convenience entry point is the one a caller reaches with a count
/// taken from a binary, so it is the one that must not panic.
#[test]
fn the_public_entry_point_reports_the_error() {
    let err = unify_types(&[], u32::MAX)
        .expect_err("unify_types deve rifiutare un conteggio ostile");
    assert!(
        matches!(err, UnifyError::TooManyVariables { .. }),
        "atteso TooManyVariables, ottenuto {err}"
    );
}

/// A legitimate small problem must still solve — otherwise the guard would have
/// been "fixed" by breaking the feature.
#[test]
fn ordinary_counts_still_solve() {
    let r = unify_types(&[], 16).expect("un conteggio normale deve funzionare");
    let _ = r;
    assert!(TypeUnifier::try_new(0).is_ok(), "zero variabili e' legittimo");
}
