//! Demangler *output* fed back in as input.
//!
//! `tests/data/pdb_proc_symbols.txt` is the `CodeView` `S_GPROC32`/`S_LPROC32`
//! records of the two corpus PDBs. An MSVC-targeting compiler writes the
//! already-decoded name into debug info, so those records hold
//! `alloc::raw_vec::RawVec::grow_one<u16,alloc::alloc::Global>` where
//! `S_PUB32` a few bytes away holds the mangled form. `extract_pdb` only ever
//! read the publics, so this shape had never reached the crate.
//!
//! It is a harder precision test than the import corpus added alongside it:
//! plain C names look nothing like manglings, whereas these carry `$`, `::`,
//! `<>` and underscore prefixes and are full of ABI-ish substrings.
//!
//! 223 of them classified `DeclineReason::Unknown`, a variant this crate holds
//! at zero so that an unrecognised shape gets understood and named rather than
//! parked. `AlreadyDemangled` names it.

use rustre_demangle::decline::{decline_reason, is_already_demangled, DeclineReason};

const PROCS: &str = include_str!("data/pdb_proc_symbols.txt");

fn symbols() -> Vec<&'static str> {
    PROCS.lines().map(str::trim).filter(|s| !s.is_empty()).collect()
}

/// Precision: a decoded name must not be decoded again. Whatever category it
/// lands in, no backend may claim it and rewrite it.
#[test]
fn no_already_demangled_name_is_claimed_by_an_abi() {
    let claimed: Vec<_> = symbols()
        .into_iter()
        .filter_map(|s| {
            rustre_demangle::demangle(s).filter(|r| r.demangled != s).map(|r| (s, r.demangled))
        })
        .collect();
    assert!(claimed.is_empty(), "decoder claimed already-decoded names: {claimed:?}");
}

/// The gap this closes: scope-separated names are a named category, not
/// `Unknown`.
#[test]
fn scope_separated_names_are_classified_not_parked() {
    let parked: Vec<_> = symbols()
        .into_iter()
        .filter(|s| s.contains("::"))
        .filter(|s| decline_reason(s) == DeclineReason::Unknown)
        // `1'::filt$0` is an MSVC debug fragment, not a decoded name; the
        // identifier-head guard keeps it out on purpose.
        .filter(|s| s.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
        .collect();
    assert!(parked.is_empty(), "scope-separated names still Unknown: {parked:?}");
}

/// Vacuity guard. The two tests above pass trivially on an empty or degraded
/// corpus, so assert the shapes that make them mean something — including the
/// generic and operator forms, which are what stress the classifier.
#[test]
fn the_corpus_carries_the_shapes_it_exists_for() {
    let syms = symbols();
    assert!(syms.len() > 250, "corpus shrank: {} symbols", syms.len());

    let scoped = syms.iter().filter(|s| s.contains("::")).count();
    assert!(scoped > 150, "only {scoped} scope-separated names");
    assert!(syms.iter().any(|s| s.contains('<') && s.contains("::")), "no generic names");
    assert!(syms.iter().any(|s| s.contains('$')), "no `$`-bearing names");
    assert!(
        syms.iter().any(|s| s.starts_with('_') && !s.contains("::")),
        "no underscore-prefixed C names"
    );
}

/// The discriminating case, and the one that separates a correct
/// implementation from one that merely made `Unknown` go away.
///
/// `AlreadyDemangled` reports a *correct* decline, so a rule that ran too early
/// or matched too loosely would silently reclassify real defects as fine. A
/// symbol carrying an ABI sigil must stay `UnsupportedAbi` even when it also
/// contains `::`.
#[test]
fn a_sigil_still_wins_over_the_scope_separator() {
    for s in [
        "_Znot::valid::itanium",
        "_RNvC::bogus::path",
        "?bad@@::not::msvc",
        "$sBroken::swift::name",
    ] {
        assert_ne!(
            decline_reason(s),
            DeclineReason::AlreadyDemangled,
            "{s}: a sigil-bearing symbol was absorbed into a correct-decline category"
        );
    }
}

/// The predicate is narrow by construction; malformed separator use is not a
/// decoded name.
#[test]
fn the_predicate_rejects_malformed_separator_use() {
    for s in ["::leading", "trailing::", "a::::b", "1'::filt$0", "'::x", "no_separator"] {
        assert!(!is_already_demangled(s), "{s} should not read as decoded output");
    }
    for s in [
        "std::vector<int>::push_back",
        "alloc::raw_vec::RawVec::grow_one<u16,alloc::alloc::Global>",
        "_CxxThrowException::inner",
    ] {
        assert!(is_already_demangled(s), "{s} should read as decoded output");
    }
}
