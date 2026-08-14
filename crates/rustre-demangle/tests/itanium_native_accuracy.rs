//! Pins how far `ItaniumNativeDemangler` is from the consolidated path.
//!
//! It is public API with ~10 call sites in other workspace crates, and its
//! header used to describe it only as a "full native parser" — no accuracy
//! caveat, unlike `itanium_full`, which honestly documents 6/28. Measured over
//! the 815 real Itanium symbols, it is substantively wrong on 68% and gets the
//! *parameter count* wrong on 37%, because it loses the `St` (`std::`)
//! substitution and `S<n>_` back-references.
//!
//! This suite does not assert that the parser is good — it asserts the
//! measurement, so the gap cannot widen unnoticed and cannot be quietly
//! forgotten. Improve the parser and these ceilings should be tightened.

fn itanium_symbols() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| l.starts_with("_Z") || l.starts_with("__Z"))
        .collect()
}

/// East/west `const` and spacing are presentation, not disagreement.
fn normalise(s: &str) -> String {
    let mut t = s.replace("const ", "").replace(" const", "");
    t.retain(|c| c != ' ');
    t
}

/// Parameter count of a rendered signature, 0 when there is no argument list.
fn arity(s: &str) -> usize {
    s.rfind('(').map_or(0, |i| {
        let inner = &s[i + 1..s.len().saturating_sub(1)];
        if inner.is_empty() {
            0
        } else {
            inner.matches(',').count() + 1
        }
    })
}

#[test]
fn native_parser_accuracy_does_not_regress() {
    // Ceilings, not targets: measured 529 and 293 on 2026-07-23. A change that
    // pushes past them has made a bad parser worse; a change that beats them
    // should tighten these numbers in the same commit.
    const MAX_SUBSTANTIVE: usize = 529;
    const MAX_WRONG_ARITY: usize = 293;

    let syms = itanium_symbols();
    let (mut compared, mut substantive, mut wrong_arity) = (0usize, 0usize, 0usize);

    for s in &syms {
        let (Some(live), Some(native)) = (
            rustre_demangle::demangle(s).map(|r| r.demangled),
            rustre_demangle::ItaniumNativeDemangler::demangle(s),
        ) else {
            continue;
        };
        compared += 1;
        if live != native && normalise(&live) != normalise(&native) {
            substantive += 1;
            if arity(&live) != arity(&native) {
                wrong_arity += 1;
            }
        }
    }

    println!("{compared} compared: {substantive} substantive, {wrong_arity} wrong arity");
    assert!(
        compared > 700,
        "only {compared} symbols reached both parsers — this suite has gone vacuous"
    );
    assert!(
        substantive <= MAX_SUBSTANTIVE,
        "native parser regressed: {substantive} substantive differences > {MAX_SUBSTANTIVE}"
    );
    assert!(
        wrong_arity <= MAX_WRONG_ARITY,
        "native parser regressed: {wrong_arity} wrong-arity results > {MAX_WRONG_ARITY}"
    );
}

/// The specific shapes named in the module docs must keep behaving as
/// documented, so the header cannot drift from reality.
#[test]
fn documented_failure_shapes_still_hold() {
    let sym = "_ZL16get_adjusted_ptrPKSt9type_infoS1_PPv";
    let live = rustre_demangle::demangle(sym).expect("live path must decode").demangled;
    assert_eq!(arity(&live), 3, "live path: {live}");

    if let Some(native) = rustre_demangle::ItaniumNativeDemangler::demangle(sym) {
        assert_ne!(
            arity(&native),
            arity(&live),
            "the documented arity failure is gone — update the module docs and \
             the ceilings in this file: {native}"
        );
    }
}
