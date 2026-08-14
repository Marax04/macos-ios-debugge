//! What `cpp_demangler`'s Itanium agreement figure actually measures.
//!
//! The crate CLAUDE.md records `cpp_demangler` matching the live path on 813/813
//! real Itanium symbols, and used to call it "the only healthy one". Measured
//! 2026-07-30: **both sides delegate to `cpp_demangle`**
//! (`cpp_demangler.rs`'s own comment says the hand-written `ItaniumParser` is kept
//! only as a fallback), so the figure establishes that their normalisation layers
//! agree — not that a parser in this crate is accurate.
//!
//! This file pins the distinction so the number cannot be re-read as validation:
//!
//! * the delegating surface agrees with the engine by construction;
//! * the **fallback** surface — the shapes `cpp_demangle` rejects — is the only
//!   place the local parser runs, and that is where a real measurement lives.
//!
//! Same class as two other findings this session: iter 76's cache test driven by a
//! stub demangler, and iter 77's gate 4 run over a hand-picked subset of targets.
//! **A green number that cannot fail for the reason it claims.**

fn engine(sym: &str) -> Option<String> {
    cpp_demangle::Symbol::new(sym)
        .ok()
        .and_then(|s| s.demangle(&cpp_demangle::DemangleOptions::default()).ok())
}

/// Grammar shapes chosen to straddle the engine's coverage: some it accepts, some
/// it rejects. Beyond the corpus on purpose — the real symbols exercise almost none
/// of these.
const SHAPES: &[&str] = &[
    // Accepted by the engine (delegating surface).
    "_ZN1AntEv",
    "_ZN1AcoEv",
    "_ZN1AixEi",
    "_ZN1AclEv",
    "_ZN1AptEv",
    "_ZN1AnwEm",
    "_ZN1AdlEPv",
    "_Z1fB5cxx11v",
    "_Z1fIJidEEvDpT_",
    "_ZNKR1A1fEv",
    "_ZNKO1A1fEv",
    "_ZGVZ1fvE1x",
    "_ZTH1x",
    "_Z1fDv4_i",
    "_ZZ1fvEUlvE_clEv",
    // Rejected by the engine (fallback surface).
    "_Z1fUt_",
    "_ZN1AoRIi",
    "_ZN1AcvIiEEv",
];

/// On everything the engine accepts, the crate's two Itanium entry points agree
/// with it — necessarily, since both call it.
#[test]
fn the_delegating_surface_agrees_with_the_engine() {
    let mut compared = 0;
    for sym in SHAPES {
        let Some(want) = engine(sym) else {
            continue; // fallback surface, covered by the next test
        };
        assert_eq!(
            rustre_demangle::demangle(sym).map(|r| r.demangled).as_deref(),
            Some(want.as_str()),
            "live path diverged from the engine it delegates to: {sym}"
        );
        assert_eq!(
            rustre_demangle::cpp_demangler::demangle_cpp(sym).ok().as_deref(),
            Some(want.as_str()),
            "cpp_demangler diverged from the engine it delegates to: {sym}"
        );
        compared += 1;
    }
    // Loose on purpose: which shapes the engine accepts depends on the
    // `cpp_demangle` version, so a tight count would break on an upgrade rather
    // than on a defect. 14 of 18 reach it today; the guard only needs to catch the
    // case where delegation stops happening at all.
    assert!(
        compared >= 12,
        "only {compared} of {} shapes reached the delegating surface — delegation          may have been removed",
        SHAPES.len()
    );
}

/// The fallback surface exists and is small — that is what makes the 813/813 figure
/// almost entirely a self-comparison.
#[test]
fn the_fallback_surface_is_where_the_local_parser_runs() {
    assert!(
        SHAPES.iter().any(|s| engine(s).is_none()),
        "no shape reaches the fallback — this test can no longer measure anything"
    );

    // Over the REAL corpus, the fallback surface is empty: every Itanium symbol is
    // handled by the engine. That is the quantitative form of the point — 813/813
    // never exercises the local parser at all.
    let corpus_fallback = include_str!("data/real_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|s| s.starts_with("_Z"))
        .filter(|s| engine(s).is_none())
        .count();
    assert_eq!(
        corpus_fallback, 0,
        "{corpus_fallback} corpus symbols now reach the fallback — the 813/813 \
         figure has stopped being a self-comparison and should be re-read"
    );
}

/// KNOWN GAP, pinned as current behaviour: the fallback fabricates on `_Z1fUt_`.
///
/// An unnamed type renders `f(?U, unsigned short, unsigned short)` — two
/// placeholders, a fabricated `unsigned short` read out of the `t` in `Ut_`, and
/// three parameters invented from one type. The live path declines it, so the two
/// public entry points disagree.
///
/// Not fixed: the obvious rule (decline on any `?`) is rejected with reasons in
/// `tests/cpp_demangler_invalid_utf8.rs`, because it would also discard the
/// correctly-recovered name in `_Z3fooñ`. Separating the two needs a
/// trailing-garbage rule the Itanium path does not have.
#[test]
fn the_fallback_fabrication_is_recorded() {
    let sym = "_Z1fUt_";
    assert!(engine(sym).is_none(), "premise: the engine must reject {sym}");
    assert!(
        rustre_demangle::demangle(sym).is_none(),
        "the live path declines {sym}"
    );
    let own = rustre_demangle::cpp_demangler::demangle_cpp(sym).ok();
    assert!(
        own.is_some_and(|d| d.contains('?')),
        "documents the fabrication; if this now declines, the trailing-garbage rule \
         has been defined and both notes should be updated"
    );
}
