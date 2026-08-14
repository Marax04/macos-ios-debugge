//! There is one prototype source, not two (Level 7 / T7).
//!
//! # The avenue this closes
//!
//! Level 7's measured bottleneck is that matched names have no prototype: of 29
//! names our scan identifies in a corpus C binary, 4 have one and 25 do not.
//! `rename_propagator::builtin_signatures()` looked like a second, independent
//! source — it returns `FunctionSignature`s with C types, and the bridge never
//! consults it.
//!
//! Measured (iteration 61):
//!
//! | | count |
//! |---|---|
//! | prototypes known to the bridge | 227 |
//! | builtin signatures in the propagator | 88 |
//! | in both | **88** |
//! | only in the propagator | **0** |
//! | of the 25 missing names, covered by the propagator | **0** |
//!
//! The 88 are a strict subset. There is no untapped source, and wiring it in
//! would rescue nothing. A negative result, but a measured one: it closes a
//! plausible avenue instead of leaving it as a hunch to be re-explored.
//!
//! # A correction to T7's framing
//!
//! T7 calls these two modules "the name propagators", to be collapsed into one.
//! They are not the same concept. `name_propagator` walks the call graph
//! propagating names between caller and callee; `rename_propagator` carries
//! function signatures with C types and applies them. Both are live — 4 and 3
//! production references — and collapsing them would merge two different jobs,
//! which is the same mistake as treating every duplicated *name* as a duplicated
//! concept.

use std::collections::HashSet;

fn bridge_names() -> HashSet<String> {
    rustre_flirt_apply::typerecov_bridge::all_known_prototypes()
        .into_iter()
        .map(|s| s.name)
        .collect()
}

fn builtin_names() -> HashSet<String> {
    rustre_flirt_apply::rename_propagator::builtin_signatures()
        .into_iter()
        .map(|s| s.name)
        .collect()
}

#[test]
fn both_sources_are_non_empty() {
    // Vacuity guard: a subset claim is free if either side is empty.
    assert!(bridge_names().len() > 100, "il ponte conosce pochi prototipi");
    assert!(builtin_names().len() > 10, "poche firme builtin");
}

/// The propagator's signatures must stay a subset of what the bridge knows. If
/// they ever diverge, the bridge is missing prototypes that exist in the
/// workspace — and that is a gap worth closing, not a detail.
#[test]
fn the_propagator_adds_no_prototype_the_bridge_lacks() {
    let bridge = bridge_names();
    let builtin = builtin_names();

    let only: Vec<&String> = builtin.difference(&bridge).collect();
    assert!(
        only.is_empty(),
        "{} firme esistono solo nel propagatore e il ponte non le conosce: \
         collegarle recupererebbe prototipi gia' presenti nel workspace — {only:?}",
        only.len()
    );
}

/// The two sources must also agree on the *content* of the prototypes they
/// share, not just the names. Two records for one function that disagree on
/// arity would be the same defect class as the duplicated types measured earlier.
#[test]
fn shared_prototypes_agree_on_arity() {
    let bridge: std::collections::HashMap<String, usize> =
        rustre_flirt_apply::typerecov_bridge::all_known_prototypes()
            .into_iter()
            .map(|s| (s.name, s.params.len()))
            .collect();

    let mut checked = 0usize;
    for s in rustre_flirt_apply::rename_propagator::builtin_signatures() {
        if let Some(&n) = bridge.get(&s.name) {
            assert_eq!(
                s.params.len(),
                n,
                "{} ha {} parametri nel propagatore e {n} nel ponte",
                s.name,
                s.params.len()
            );
            checked += 1;
        }
    }
    assert!(checked > 10, "confrontate solo {checked} firme condivise");
}
