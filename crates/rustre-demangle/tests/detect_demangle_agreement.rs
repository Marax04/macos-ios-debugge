//! `Demangler::detect` must agree with `Demangler::demangle` on well-formed
//! and on structurally-truncated input.
//!
//! **`detect` is a cheap shape check, not a promise that decoding succeeds.**
//! `_RNvXXXX!!!` carries a valid Rust v0 sigil and path tag, so `detect`
//! accepts it, and the parser then rejects the body — that is by design, and
//! `d.demangle(s).unwrap()` is *not* safe on arbitrary input. Making it safe
//! would require `detect` to be a full parser.
//!
//! What this suite does assert is the narrower property that was actually
//! broken: `detect` must not claim symbols that are incomplete *at the sigil
//! itself* (`_RN`, `_D4`, `-[]`), nor may `demangle` return `Some("")`. Those
//! shapes produce a phantom `DeclineReason::UnsupportedAbi` and a decode with
//! no name in it — and `AutoDemangler` cannot surface either, because it skips
//! `detect` entirely and calls `demangle` directly.
//!
//! Measured over both real corpora, plus hand-picked degenerate inputs: real
//! binaries contain no truncated symbols, so the corpora alone are blind here.

use std::collections::BTreeMap;

use rustre_demangle::{Demangler, ItaniumDemangler, MsvcDemangler, RustDemangler, SwiftDemangler};

fn corpora() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

#[test]
fn detect_never_promises_more_than_demangle_delivers() {
    let backends: Vec<(&str, Box<dyn Demangler>)> = vec![
        ("ItaniumDemangler", Box::new(ItaniumDemangler)),
        ("MsvcDemangler", Box::new(MsvcDemangler)),
        ("RustDemangler", Box::new(RustDemangler)),
        ("SwiftDemangler", Box::new(SwiftDemangler)),
    ];
    let syms = corpora();
    let mut broken_promises: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut silent_decodes: BTreeMap<&str, usize> = BTreeMap::new();
    let mut claimed = 0usize;

    for (name, d) in &backends {
        for s in &syms {
            let detected = d.detect(s);
            let decoded = d.demangle(s).is_some();
            if detected {
                claimed += 1;
            }
            if detected && !decoded {
                broken_promises.entry(name).or_default().push(s);
            }
            if !detected && decoded {
                *silent_decodes.entry(name).or_default() += 1;
            }
        }
    }

    for (name, n) in &silent_decodes {
        println!("  {name}: {n} decoded without detect() claiming them");
    }
    for (name, v) in &broken_promises {
        println!("  {name}: {} claimed by detect() but declined", v.len());
        for s in v.iter().take(3) {
            println!("      {s}");
        }
    }

    // Without claims there is nothing to check.
    assert!(
        claimed > 500,
        "only {claimed} detect() hits across the corpora — suite gone vacuous"
    );

    let total: usize = broken_promises.values().map(Vec::len).sum();
    assert_eq!(
        total, 0,
        "{total} symbols are claimed by detect() but declined by demangle(); a \
         caller writing `if d.detect(s) {{ d.demangle(s).unwrap() }}` panics on them"
    );
}

/// The same invariant for the public types that expose `detect`/`demangle` as
/// inherent methods rather than through the `Demangler` trait.
///
/// These are reachable the same way — `rustre-mcp-tools` exposes each as its
/// own wire tool — so the same `detect`-then-`unwrap` shape applies.
#[test]
fn inherent_detect_methods_agree_with_their_demangle() {
    use rustre_demangle::{DDemangler, ObjCDemangler, RustV0Demangler};

    #[allow(
        clippy::type_complexity,
        reason = "a table of (name, detect, demangle) triples reads better inline than behind an alias"
    )]
    let pairs: &[(&str, fn(&str) -> bool, fn(&str) -> Option<String>)] = &[
        ("DDemangler", DDemangler::detect, DDemangler::demangle),
        (
            "RustV0Demangler",
            RustV0Demangler::detect,
            RustV0Demangler::demangle,
        ),
        (
            "ObjCDemangler",
            ObjCDemangler::detect,
            ObjCDemangler::demangle,
        ),
    ];

    let syms = corpora();
    let mut broken: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut claimed = 0usize;

    for (name, detect, demangle) in pairs {
        for s in &syms {
            if detect(s) {
                claimed += 1;
                if demangle(s).is_none() {
                    broken.entry(name).or_default().push(s);
                }
            }
        }
    }

    for (name, v) in &broken {
        println!("  {name}: {} claimed but declined", v.len());
        for s in v.iter().take(3) {
            println!("      {s}");
        }
    }

    // These detectors are narrow by design, so the corpora may legitimately
    // offer few matches; a low count is reported rather than asserted, since
    // demanding hits would be asserting the corpus, not the crate.
    println!("  {claimed} detect() hits across the three types");

    let total: usize = broken.values().map(Vec::len).sum();
    assert_eq!(
        total, 0,
        "{total} symbols are claimed by an inherent detect() but declined by \
         its demangle()"
    );
}

/// Degenerate inputs, which the corpora do not contain.
///
/// `inherent_detect_methods_agree_with_their_demangle` above iterates the real
/// corpora, so it never sees a malformed symbol — and two Obj-C bugs hid
/// behind exactly that gap: `-[]` was claimed by `detect` and declined by
/// `demangle` (a phantom defect, and a panic for
/// `if detect(s) { demangle(s).unwrap() }`), while a bare `_OBJC_` "decoded"
/// to the empty string, handing the caller a success with no name in it.
///
/// A corpus invariant is blind to shapes the corpus lacks; these are chosen by
/// hand for that reason.
#[test]
fn degenerate_inputs_keep_detect_and_demangle_in_step() {
    use rustre_demangle::{DDemangler, ObjCDemangler, RustV0Demangler};

    #[allow(
        clippy::type_complexity,
        reason = "a table of (name, detect, demangle) triples reads better inline"
    )]
    let pairs: &[(&str, fn(&str) -> bool, fn(&str) -> Option<String>)] = &[
        ("DDemangler", DDemangler::detect, DDemangler::demangle),
        (
            "RustV0Demangler",
            RustV0Demangler::detect,
            RustV0Demangler::demangle,
        ),
        (
            "ObjCDemangler",
            ObjCDemangler::detect,
            ObjCDemangler::demangle,
        ),
    ];

    let degenerate = [
        "", "_", "__", "-[", "-[]", "+[]", "-[ ]", "_OBJC_", "_OBJC_CLASS_$_", "_D", "_D4", "_R",
        "_RN", "$s", "_$s", "__T", "_T0",
    ];

    // Equality, not `if detect { assert … }` — same reason as the trait-backend
    // loop below. Measured, this conditional ran **1 of 51** times: only
    // `ObjCDemangler` claims anything here (`_OBJC_CLASS_$_`), so two of the
    // three pairs contributed no assertion at all, and a change to ObjC's
    // `detect` would have taken the whole half to zero without a sound.
    let mut compared = 0usize;
    for (name, detect, demangle) in pairs {
        for s in degenerate {
            let claimed = detect(s);
            let out = demangle(s);
            assert_eq!(
                claimed,
                out.is_some(),
                "{name}: detect and demangle disagree on {s:?}"
            );
            if let Some(text) = out {
                assert!(
                    !text.is_empty(),
                    "{name} decoded {s:?} to the empty string"
                );
            }
            compared += 1;
        }
    }
    assert!(
        compared > 45,
        "vacuity guard: only {compared} pair/input combinations compared"
    );

    // Positive control per pair, so the equality cannot be satisfied by
    // detectors that reject everything.
    for (name, detect, demangle, sym) in [
        ("DDemangler", pairs[0].1, pairs[0].2, "_D4main3fooFiZi"),
        ("RustV0Demangler", pairs[1].1, pairs[1].2, "_RNvC4main3foo"),
        ("ObjCDemangler", pairs[2].1, pairs[2].2, "-[NSString length]"),
    ] {
        assert!(detect(sym), "{name} must claim {sym}");
        assert!(demangle(sym).is_some(), "{name} must decode {sym}");
    }

    // The trait-based backends take the same inputs through the same contract.
    let backends: Vec<(&str, Box<dyn Demangler>)> = vec![
        ("ItaniumDemangler", Box::new(ItaniumDemangler)),
        ("MsvcDemangler", Box::new(MsvcDemangler)),
        ("RustDemangler", Box::new(RustDemangler)),
        ("SwiftDemangler", Box::new(SwiftDemangler)),
    ];
    // Stated as an equality, not `if detect { assert … }`.
    //
    // The conditional form was **vacuous**: measured 0 of 17 for every one of
    // these four backends, so not a single assertion ran. It would still have
    // fired had a detector been loosened — that much it did — but it gave no
    // standing evidence the property held, and it was structurally blind to the
    // opposite regression, a detector grown too strict. Both directions matter
    // here: this file exists because tightening `demangle` while leaving
    // `detect` turned a consistent error into a divergence that panicked 89
    // corpus symbols.
    let mut compared = 0usize;
    for (name, d) in &backends {
        for s in degenerate {
            let claimed = d.detect(s);
            let out = d.demangle(s);
            assert_eq!(
                claimed,
                out.is_some(),
                "{name}: detect and demangle disagree on {s:?}"
            );
            if let Some(r) = out {
                assert!(
                    !r.demangled.is_empty(),
                    "{name} decoded {s:?} to the empty string"
                );
            }
            compared += 1;
        }
    }
    assert!(
        compared > 60,
        "vacuity guard: only {compared} backend/input pairs compared"
    );

    // Positive control: a well-formed symbol per backend, so the equality above
    // cannot be satisfied by detectors that reject everything — which is exactly
    // the state the conditional version could not distinguish from success.
    for (name, d, sym) in [
        ("ItaniumDemangler", &backends[0].1, "_ZN3foo3barEi"),
        ("MsvcDemangler", &backends[1].1, "?foo@@YAHH@Z"),
        ("RustDemangler", &backends[2].1, "_RNvC4main3foo"),
        ("SwiftDemangler", &backends[3].1, "$s4main3fooyyF"),
    ] {
        assert!(d.detect(sym), "{name} must claim {sym}");
        assert!(d.demangle(sym).is_some(), "{name} must decode {sym}");
    }
}
