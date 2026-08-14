//! At most one detector may claim any symbol.
//!
//! When two detectors claim the same name, the answer is decided by the
//! position of each in `AutoDemangler`'s chain rather than by any property of
//! the symbol. That makes the ABI label — which consumers route on — an
//! artefact of ordering, and it makes reordering the chain a semantic change
//! disguised as a refactor.
//!
//! Measured 2026-07-29: **0 of 6468** corpus symbols are claimed by more than
//! one detector, and none of the deliberately ambiguous constructed shapes
//! either. So the order is currently *not* load-bearing — which is worth
//! stating, because nothing recorded it and four detectors were tightened
//! shortly before this was written (`detect_ghc` twice, `GoDemangler::detect`
//! twice). Any of those could have introduced an overlap and nothing would
//! have noticed: an overlap does not fail a test, it just quietly changes
//! which backend answers.
//!
//! This is the complement of `tests/detector_conventions.rs`, which checks that
//! a detector does not claim what belongs to *another* ABI. That is about
//! correctness of each detector alone; this is about their relationship.

use rustre_demangle::go_demangler::GoDemangler;
use rustre_demangle::lang_extra as le;

type Detector = (&'static str, fn(&str) -> bool);

/// The convention and name-shape detectors that can overlap.
///
/// The sigil-prefixed ABIs (Itanium, MSVC, Rust, Swift, D) are excluded: they
/// are separated by their prefixes, which `tests/c_identifier_claims.rs` and
/// `tests/detect_demangle_agreement.rs` already guard. What can genuinely
/// collide is the family that claims on *name shape* — `__` separators, a
/// trailing suffix word, a dot.
fn detectors() -> Vec<Detector> {
    vec![
    ("ghc", le::detect_ghc),
    ("ocaml", le::detect_ocaml),
    ("ada", le::detect_gnat_ada),
    ("gfortran", le::detect_gfortran),
    ("jni", le::detect_jni),
    ("c_decorated", le::detect_c_decorated),
    ("go", GoDemangler::detect),
    ]
}

fn claimants(sym: &str) -> Vec<&'static str> {
    detectors()
        .into_iter()
        .filter(|(_, f)| f(sym))
        .map(|(name, _)| name)
        .collect()
}

#[test]
fn no_corpus_symbol_is_claimed_by_two_detectors() {
    let corpus = include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty());

    let mut offenders: Vec<(&str, Vec<&'static str>)> = Vec::new();
    let mut checked = 0usize;
    for sym in corpus {
        checked += 1;
        let who = claimants(sym);
        if who.len() > 1 {
            offenders.push((sym, who));
        }
    }

    assert!(
        offenders.is_empty(),
        "{} symbols are claimed by more than one detector, so their ABI depends \
         on chain order; first 5: {:?}",
        offenders.len(),
        &offenders[..offenders.len().min(5)]
    );
    assert!(
        checked > 6000,
        "vacuity guard: only {checked} symbols examined — did the corpora move?"
    );
}

/// Shapes where an overlap is most plausible, with their rightful owner.
///
/// Neither corpus has an Ada, OCaml, Haskell, Fortran or JNI symbol, so the
/// corpus sweep proves nothing about the `__`-separated family — the one where
/// the conventions genuinely resemble each other. Naming the expected claimant
/// makes a *silent reassignment* fail as loudly as an overlap.
const AMBIGUOUS: &[(&str, &str)] = &[
    ("ada__text_io__put_line", "ada"),
    ("camlStdlib__Printf__printf_42", "ocaml"),
    ("base_GHCziBase_map_closure", "ghc"),
        // Ends in a GHC suffix but is a real Dune entry point: OCaml's.
    ("camlDune__exe__Main__entry", "ocaml"),
        // Ends in a GHC suffix, all lowercase with `__`: Ada's.
    ("ada__text__info", "ada"),
    ("pkg__sub__proc_info", "ada"),
        // Ends in a GHC suffix and carries `_MOD_`: gfortran's.
    ("__mod_MOD_proc_entry", "gfortran"),
    ("__physics_MOD_get_value", "gfortran"),
    ("Java_com_example_Foo_bar", "jni"),
    ("_MessageBoxA@16", "c_decorated"),
    ("main.main", "go"),
];

#[test]
fn ambiguous_shapes_have_exactly_one_claimant() {
    for (sym, expected) in AMBIGUOUS {
        let who = claimants(sym);
        assert_eq!(
            who,
            vec![*expected],
            "{sym} should be claimed by exactly `{expected}`"
        );
    }
}

/// The chain order must not be load-bearing.
///
/// Stated as an executable property rather than a comment: if at most one
/// detector claims each input, then evaluating them in any order yields the
/// same claimant. Checked by comparing the forward and reversed evaluation
/// orders — only equivalent while exclusivity holds, so it fails the moment an
/// overlap appears, whichever detector gains it.
///
/// **It must run over `AMBIGUOUS` as well as the corpus, and a mutation showed
/// why.** Removing `detect_ghc`'s OCaml/Ada deferral — the exact loosening this
/// guard exists for — left the corpus sweep and this test both green, because
/// neither corpus contains a single OCaml, Ada, Haskell or Fortran symbol. The
/// corpus half of this check is *vacuous for the family that can actually
/// collide*; only the constructed shapes exercise it.
#[test]
fn reversing_the_detector_order_changes_nothing() {
    let corpus = include_str!("data/real_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty());

    let mut checked = 0usize;
    for sym in corpus.chain(AMBIGUOUS.iter().map(|(s, _)| *s)) {
        let mut forward = detectors();
        let first_forward = forward.iter().find(|(_, f)| f(sym)).map(|(n, _)| *n);

        forward.reverse();
        let first_reversed = forward.iter().find(|(_, f)| f(sym)).map(|(n, _)| *n);

        assert_eq!(
            first_forward, first_reversed,
            "{sym} is answered by a different detector depending on chain order"
        );
        checked += 1;
    }
    assert!(checked > 5000, "vacuity guard: only {checked} symbols examined");
}
