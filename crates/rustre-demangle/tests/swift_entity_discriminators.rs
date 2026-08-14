//! Swift's `f<kind>` discriminators name different declarations.
//!
//! A member entity ends in `v` (variable) or `f` (function), and `f` is
//! followed by a letter saying *which* function: `fc` constructor, `fC`
//! allocating constructor, `fd` destructor, `fD` deallocating destructor.
//!
//! The `v` branch reads its accessor table — `vg` getter, `vs` setter, `vM`
//! modify, `vr` read, `vw` willset, `vW` didset, all rendered. The `f` branch
//! consumed the `f` and returned a plain method, dropping the letter in
//! silence, so eleven distinct manglings collapsed onto one rendering:
//!
//! ```text
//!   …3barSif   …3barSifc   …3barSifd   …3barSifD
//!     all  =>  main.Foo.bar() -> Swift.Int
//! ```
//!
//! Found by crossing axes that no test crossed: nominal kind × member name ×
//! type × entity × accessor, 432 symbols rendering only 48 distinct strings.
//! The per-axis Swift checks could not see it, exactly as three per-axis D
//! checks could not see `K`/`R` (iter 163).
//!
//! **No spelling is invented.** The fix rewinds so the existing `[unparsed …]`
//! echo fires — the marker was already there for constructs this crate cannot
//! verify, but was gated on no signature having been produced, and a method
//! rendering suppressed it. Naming these entities properly needs a Swift
//! oracle; distinguishing them does not.
//!
//! Only the four unambiguous discriminators are handled. A letter left out
//! costs nothing (the symbol keeps its method rendering); a letter wrongly
//! included would turn a real method into an echo, so the conservative
//! direction is fewer.

use std::collections::BTreeMap;

fn sym(parts: &[&str], tail: &str) -> String {
    let mut s = String::from("$s");
    for p in parts {
        s.push_str(&p.len().to_string());
        s.push_str(p);
    }
    s.push_str(tail);
    s
}

fn render(tail: &str) -> String {
    let s = sym(&["main", "Foo"], tail);
    rustre_demangle::demangle(&s).unwrap_or_else(|| panic!("{s} must decode")).demangled
}

/// **The defect.** Each discriminator must produce its own rendering.
#[test]
fn function_kind_discriminators_do_not_collapse() {
    let plain = render("C3barSif");
    let mut seen: BTreeMap<String, &str> = BTreeMap::new();
    seen.insert(plain.clone(), "f");

    for d in ["c", "C", "d", "D"] {
        let tail = format!("C3barSif{d}");
        let out = render(&tail);
        assert_ne!(out, plain, "f{d} renders as a plain method");
        if let Some(prev) = seen.insert(out.clone(), "dup") {
            assert_eq!(prev, "dup", "f{d} collides with an earlier discriminator: {out}");
        }
    }
    assert_eq!(seen.len(), 5, "five inputs must give five renderings");
}

/// The distinction is made by the honest echo, not by an invented name — so
/// each rendering carries the mangling it did not parse, verbatim.
#[test]
fn the_distinction_is_an_echo_not_an_invented_spelling() {
    for d in ["c", "C", "d", "D"] {
        let out = render(&format!("C3barSif{d}"));
        assert!(out.contains("[unparsed "), "f{d} must echo rather than name: {out}");
        assert!(out.contains(&format!("Sif{d}")), "f{d} echo must be verbatim: {out}");
        // No spelling was invented for the entity kind.
        for invented in ["constructor", "destructor", "init", "deinit", "allocating"] {
            assert!(!out.contains(invented), "f{d} invented {invented}: {out}");
        }
    }
}

/// The control: a plain function entity is untouched, and so is the whole `v`
/// accessor table. A fix that widened into either would show here.
#[test]
fn plain_methods_and_variable_accessors_are_unchanged() {
    assert_eq!(render("C3barSif"), "main.Foo.bar() -> Swift.Int");
    assert_eq!(render("C3barSiF"), "main.Foo.bar() -> Swift.Int");

    for (tail, want) in [
        ("C3barSiv", "main.Foo.bar : Swift.Int"),
        ("C3barSivg", "main.Foo.bar.getter : Swift.Int"),
        ("C3barSivs", "main.Foo.bar.setter : Swift.Int"),
        ("C3barSivM", "main.Foo.bar.modify : Swift.Int"),
        ("C3barSivr", "main.Foo.bar.read : Swift.Int"),
        ("C3barSivw", "main.Foo.bar.willset : Swift.Int"),
        ("C3barSivW", "main.Foo.bar.didset : Swift.Int"),
    ] {
        assert_eq!(render(tail), want, "{tail}");
    }
}

/// The cross-axis sweep that found it, kept as the guard.
///
/// Two collision families remain and both are excluded by name: the nominal
/// kind marker (`V`/`C`/`O`/`P`), which Swift's own simplified form does not
/// render either — see `tests/swift_soundness.rs` — and trailing junk after a
/// complete entity, which Swift is deliberately exempt from rejecting
/// (`tests/trailing_input.rs`: its parser reaches the end of only 9 of 16
/// realistic symbols, so strictness would decline 7 legitimate ones).
#[test]
fn the_member_grammar_has_no_other_collisions() {
    const KINDS: [&str; 4] = ["V", "C", "O", "P"];
    const TYPES: [&str; 6] = ["Si", "SS", "Sb", "Sd", "Sf", "Su"];
    const ACCESSORS: [&str; 7] = ["", "g", "s", "M", "r", "w", "W"];

    let mut by_output: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut decoded = 0;
    for k in KINDS {
        for t in TYPES {
            for a in ACCESSORS {
                let tail = format!("{k}3bar{t}v{a}");
                if let Some(r) = rustre_demangle::demangle(&sym(&["main", "Foo"], &tail)) {
                    decoded += 1;
                    by_output.entry(r.demangled).or_default().push(tail);
                }
            }
        }
    }
    assert!(decoded > 150, "vacuous: only {decoded} decoded");

    // Every remaining group must differ ONLY in the nominal kind marker.
    let unexpected: Vec<_> = by_output
        .iter()
        .filter(|(_, codes)| codes.len() > 1)
        .filter(|(_, codes)| {
            let normalise = |s: &str| s.chars().skip(1).collect::<String>();
            let first = normalise(&codes[0]);
            !codes.iter().all(|c| normalise(c) == first)
        })
        .map(|(out, codes)| format!("{codes:?} -> {out}"))
        .collect();
    assert!(unexpected.is_empty(), "new collision families: {unexpected:#?}");
}
