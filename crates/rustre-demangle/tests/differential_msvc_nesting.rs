//! Nested qualified names, checked against the MSVC oracle at every depth.
//!
//! `differential_msvc_pdb.rs` covers the 14 real PDB symbols and
//! `unused_msvc_full.rs` covers 20 curated feature shapes, but **nesting depth was
//! not a dimension either exercised**: the deepest real symbol is a handful of
//! scopes.
//!
//! That gap mattered after iter 84 added `MSVC_MAX_DEPTH = 64` to fix a stack
//! overflow. A depth limit is exactly the kind of change that can quietly reject
//! legitimate input, and "the corpus still decodes" is a weak control when the
//! corpus never goes deep.
//!
//! Measured on 2026-07-30 against `msvc-demangler`: **identical at every depth from
//! 1 to 20**, so the limit does not bite on real shapes. Twenty nested namespaces is
//! already far past anything a compiler emits.
//!
//! One caution recorded from building this: an earlier probe used `"bar@".repeat(n)`
//! and produced `?foo@bar@bar@…bar@@YAXXZ`, which has one separator too many before
//! the `@@` and is malformed. It declined, and I briefly read that as a parser gap.
//! **The oracle is what settles whether a constructed symbol is valid** — that is
//! the whole reason to use one here rather than assert my own expectations.

mod msvc_oracle;

use msvc_demangler::{demangle as oracle, DemangleFlags};
use msvc_oracle::normalise;

/// `?foo@n@n@…@@YAXXZ` — `depth` nested scopes named `n`.
fn nested(depth: usize) -> String {
    let scopes = "n@".repeat(depth);
    format!("?foo@{}@@YAXXZ", scopes.trim_end_matches('@'))
}

#[test]
fn nested_namespaces_match_the_oracle_at_every_depth() {
    let mut compared = 0;
    for depth in 1..=20 {
        let sym = nested(depth);
        let Ok(want) = oracle(&sym, DemangleFlags::COMPLETE) else {
            panic!("{sym} must be valid MSVC — the oracle rejected it, so the test \
                    input is wrong, not the crate");
        };
        let got = rustre_demangle::demangle(&sym).map(|r| r.demangled);
        assert_eq!(
            got.as_deref().map(normalise),
            Some(normalise(&want)),
            "depth {depth}: {sym}
  oracle: {want}
  ours:   {got:?}"
        );
        compared += 1;
    }
    assert!(compared == 20, "expected 20 depths, compared {compared}");
}

/// The depth limit added at iter 84 must reject only what a compiler cannot emit.
///
/// Paired with the test above: that one shows legitimate nesting is unaffected,
/// this one shows the guard is still doing its job. Both halves are needed — a
/// missing limit crashes the process, and a limit set too low silently loses
/// symbols.
#[test]
fn the_depth_limit_still_rejects_pathological_nesting() {
    // Far past `MSVC_MAX_DEPTH`. The requirement is that it returns rather than
    // exhausting the stack; declining is the expected answer.
    for depth in [512usize, 4096, 30000] {
        let sym = format!("?f@@YAX{}H@Z", "PEA".repeat(depth));
        let got = rustre_demangle::demangle(&sym);
        assert!(
            got.is_none(),
            "{depth} nested pointers should be declined, got {got:?}"
        );
    }

    // And the boundary: shallow pointer nesting, which compilers do emit, must
    // decode and match the oracle.
    for depth in 1..=6 {
        let sym = format!("?f@@YAX{}H@Z", "PEA".repeat(depth));
        let Ok(want) = oracle(&sym, DemangleFlags::COMPLETE) else {
            continue; // no ground truth for this shape
        };
        // Normalised: the reference writes `int *` where this crate writes `int*`,
        // a presentation difference the shared helper collapses. Comparing raw
        // strings here failed on exactly that, which is why the helper exists.
        let got = rustre_demangle::demangle(&sym).map(|r| r.demangled);
        assert_eq!(
            got.as_deref().map(normalise),
            Some(normalise(&want)),
            "{depth} levels of pointer must still decode
  oracle: {want}
  ours:   {got:?}"
        );
    }
}
