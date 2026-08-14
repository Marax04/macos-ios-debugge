//! Contract properties of `DemanglingResult` that nothing else asserts.
//!
//! Iters 137-145 examined all five *derived* fields (`namespace`, `class`,
//! `function`, `args`, `return_type`) and found six defects. This covers what
//! is left: `original`, and the ABI label's own invariant.
//!
//! **Measured 2026-07-30 over 3170 decodes: both hold. No defect.** The value
//! is the guard — `original` is the only field a caller can use to correlate a
//! result back to the symbol table it came from, so a backend that trimmed or
//! normalised on the way in would break that correlation silently, and nothing
//! checked it.

/// `original` is the input, byte for byte.
///
/// Includes inputs with surrounding whitespace, which the Obj-C backend does
/// trim internally before parsing — the field must still report what it was
/// given, not what the parser used.
#[test]
fn original_is_always_the_input() {
    let mut inputs: Vec<String> = include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    for s in [
        "  -[Foo bar]  ",
        "-[Foo bar]",
        "_D4main3fooFZv",
        "?f@@YAXHH@Z",
        "$s4main3fooySiF",
        "Java_com_foo_Bar_baz",
        "pkg__proc",
        "_ZN4core3fmt5write17h0123456789abcdefE",
        "main.main",
        "_D4main3fooFZv.cold",
    ] {
        inputs.push(s.to_owned());
    }

    let mut checked = 0;
    let mut offenders = Vec::new();
    for sym in &inputs {
        let Some(r) = rustre_demangle::demangle(sym) else {
            continue;
        };
        checked += 1;
        if r.original != *sym {
            offenders.push(format!("{sym:?} reported original {:?}", r.original));
        }
    }
    assert!(checked > 3000, "vacuous: only {checked} decodes");
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

/// A decoded symbol is never labelled `Unknown`.
///
/// `ManglingAbi::Unknown` means "no backend claimed this". A result that
/// carries it is a decode nobody owns, which makes the label useless for
/// routing — and routing is what consumers do with it.
///
/// Note the scope honestly: this passes over the corpora because they are
/// Itanium and Go. Several `lang_more` conventions (Nim, Zig, Clojure) DO
/// decode as `Unknown`, which is the open `ManglingAbi` variants question in
/// the crate's CLAUDE.md — a decision, not a defect. This pins the corpora.
#[test]
fn no_corpus_decode_is_labelled_unknown() {
    let mut checked = 0;
    let mut unknown = Vec::new();
    for line in include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
    {
        let sym = line.trim();
        if sym.is_empty() {
            continue;
        }
        let Some(r) = rustre_demangle::demangle(sym) else {
            continue;
        };
        checked += 1;
        if format!("{:?}", r.abi) == "Unknown" {
            unknown.push(sym.to_owned());
        }
    }
    assert!(checked > 3000, "vacuous: only {checked} decodes");
    assert!(
        unknown.is_empty(),
        "{} corpus symbols decoded without an ABI: {:?}",
        unknown.len(),
        &unknown[..unknown.len().min(10)]
    );
}
