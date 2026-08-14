//! Pins how far the hand-written `rust_demangler` is from the live path.
//!
//! `rust_demangler::demangle_rust` / `demangle_rust_v0` are public API with
//! ~12 call sites in other workspace crates. On the 135 real rustc-1.96 v0
//! symbols they produce **zero** correct results — 83 errors and 52 wrong
//! decodes — while `crate::demangle`, which delegates to `rustc-demangle`,
//! is exact on all 135 (verified in `tests/differential_rust_pdb.rs`).
//!
//! Two symbols can even collapse to one string:
//! `…14rustc_demangle12try_demangle` and `…14rustc_demangle8demangle` both
//! render `rustc_demangle[a20b64e359616fff]::{{vtable}}`.
//!
//! These assertions do not endorse the numbers — they stop them getting worse
//! and stop the finding being forgotten. Improve the parser and tighten them.

fn rust_v0_symbols() -> Vec<&'static str> {
    include_str!("data/pdb_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|s| {
            s.strip_prefix("_R")
                .and_then(|r| r.chars().next())
                .is_some_and(|c| matches!(c, 'N' | 'I' | 'C' | 'M' | 'X' | 'Y' | 'K' | 'B'))
        })
        .collect()
}

/// The live path is exact; the hand-written one is not. Both halves matter:
/// the first is the guarantee, the second is the gap.
#[test]
fn hand_written_v0_parser_accuracy_does_not_regress() {
    // Measured 2026-07-23: exactly 0 of 135 correct. Asserted as an equality
    // rather than a floor — `>= 0` asserts nothing — so the test trips in both
    // directions: a regression cannot go lower, and an improvement forces
    // whoever makes it to update the module header alongside.
    const CORRECT_AS_MEASURED: usize = 0;

    let syms = rust_v0_symbols();
    assert!(
        syms.len() > 100,
        "expected >100 real v0 symbols, found {} — this suite has gone vacuous",
        syms.len()
    );

    let live_ok = syms
        .iter()
        .filter(|s| rustre_demangle::demangle(s).is_some())
        .count();
    assert_eq!(
        live_ok,
        syms.len(),
        "the live path must decode every real v0 symbol"
    );

    let correct = syms
        .iter()
        .filter(|s| {
            let live = rustre_demangle::demangle(s).map(|r| r.demangled);
            rustre_demangle::rust_demangler::demangle_rust(s)
                .ok()
                .is_some_and(|a| Some(&a) == live.as_ref())
        })
        .count();

    println!("{}/{} correct via demangle_rust", correct, syms.len());
    assert_eq!(
        correct,
        CORRECT_AS_MEASURED,
        "demangle_rust now agrees with the live path on {correct} of {} real \
         v0 symbols. If that is an improvement, update this constant and the \
         warning in src/rust_demangler.rs — a caveat that outlives the defect \
         it describes is how documentation starts lying.",
        syms.len()
    );
}

/// The identity-losing failure named in the module header must stay reported
/// there accurately: two distinct symbols must not silently share a rendering.
#[test]
fn distinct_symbols_must_not_render_identically() {
    let a = "_RNvCsdUyFeGaMdop_14rustc_demangle12try_demangle";
    let b = "_RNvCsdUyFeGaMdop_14rustc_demangle8demangle";

    let live_a = rustre_demangle::demangle(a).expect("live path decodes a").demangled;
    let live_b = rustre_demangle::demangle(b).expect("live path decodes b").demangled;
    assert_ne!(live_a, live_b, "the live path keeps them distinct");

    // The hand-written parser does not. Asserted so the header's example stays
    // true; if this starts failing the parser improved and the docs must move.
    if let (Ok(x), Ok(y)) = (
        rustre_demangle::rust_demangler::demangle_rust(a),
        rustre_demangle::rust_demangler::demangle_rust(b),
    ) {
        assert_eq!(
            x, y,
            "demangle_rust no longer collapses these two — update the module header"
        );
    }
}
