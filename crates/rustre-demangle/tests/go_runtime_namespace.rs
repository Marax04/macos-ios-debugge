//! The `go:` namespace: a gap in the iter-141 sigil sweep, and an open question
//! it uncovered.
//!
//! Iter 141 swept 22 mangling sigils for "does any reach the output". It listed
//! `go.shape.` and **not `go:`**, so it could not see that `go:` symbols are
//! echoed with their namespace marker intact while the sibling `type:` family
//! is rewritten (`type:.eq.int` -> `type descriptor for .eq.int`). Closing that
//! gap in my own guard is the certain part of this file.
//!
//! **What it uncovered is NOT changed here**, and the reason is in the crate's
//! own source. Within one family the treatment splits on an accident:
//!
//! ```text
//! go:buildid                        declines, classified LinkerArtifact
//! go:x                              declines, classified LinkerArtifact
//! go:buildinfo.ref                  decodes as a Go FUNCTION
//! go:itab.*errors.errorString,error decodes as a Go FUNCTION
//! ```
//!
//! The only difference is a dot, which Go's deliberately permissive detector
//! accepts. That looks like an inconsistency to fix — and `GoSymbolKind`'s own
//! doc already records it as an open question: the `type:.eq.…` / `type:.hash.…`
//! families "today classify as `Function` and `Unknown`. Deciding which of
//! those are genuinely thunks needs Go [evidence]". Overriding a documented
//! open decision on a consistency argument is the mistake of iters 121 and 141,
//! where the corpus proved the asymmetry correct both times.
//!
//! So this file pins the behaviour and the evidence, and states what would
//! settle it: knowing whether a consumer wants an itab reported as a symbol it
//! can name, or as an artifact it should skip.

/// The `go:` marker survives into the rendering; `type:` is rewritten.
///
/// Pinned as a pair, because the asymmetry is the finding — neither half is
/// asserted as *correct*, only as *what happens*.
#[test]
fn the_two_runtime_namespaces_are_treated_differently() {
    let go = rustre_demangle::demangle("go:itab.*os.File,io.Writer")
        .expect("must decode")
        .demangled;
    assert!(go.starts_with("go:"), "the marker no longer survives: {go}");

    let ty = rustre_demangle::demangle("type:.eq.int")
        .expect("must decode")
        .demangled;
    assert!(!ty.starts_with("type:"), "the marker is no longer rewritten: {ty}");
    assert_eq!(ty, "type descriptor for .eq.int");
}

/// Within the `go:` family, a dot decides whether the symbol decodes at all.
///
/// The accident this file records. If a future change makes the family
/// consistent — either way — this test is where the decision gets written down.
#[test]
fn a_dot_decides_whether_a_go_symbol_decodes() {
    for sym in ["go:buildid", "go:buildinfo", "go:fipsinfo", "go:x"] {
        assert_eq!(rustre_demangle::demangle(sym), None, "{sym}");
        assert_eq!(
            format!("{:?}", rustre_demangle::decline::decline_reason(sym)),
            "LinkerArtifact",
            "{sym}"
        );
    }
    for sym in [
        "go:buildinfo.ref",
        "go:func.*",
        "go:itab.*errors.errorString,error",
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert_eq!(format!("{:?}", r.abi), "Go", "{sym}");
    }
}

/// Whatever the classification, the payload is never lost.
///
/// This is the part that holds under either resolution of the open question,
/// and it is the property that matters for a consumer: a symbol that decodes
/// must still identify itself.
#[test]
fn the_payload_survives_whatever_the_classification() {
    let mut checked = 0;
    for line in include_str!("data/real_symbols.txt").lines() {
        let sym = line.trim();
        if !sym.starts_with("go:") && !sym.starts_with("type:") {
            continue;
        }
        let Some(r) = rustre_demangle::demangle(sym) else {
            continue;
        };
        checked += 1;
        let payload = sym
            .strip_prefix("go:")
            .or_else(|| sym.strip_prefix("type:"))
            .unwrap_or(sym);
        assert!(
            r.demangled.contains(payload),
            "{sym} lost its payload: {}",
            r.demangled
        );
    }
    assert!(checked >= 20, "vacuous: only {checked} runtime symbols decoded");
}

/// The sigil sweep, with `go:` and `type:` now in the list.
///
/// Every OTHER namespace marker must still be absent from every rendering —
/// the iter-141 property, with the gap that let this one through closed.
#[test]
fn no_other_namespace_marker_reaches_the_output() {
    const MARKERS: &[&str] = &[
        "_ZN", "__Z", "_RN", "$s", "$S", "__T", "_Tt", "@@", "17h", "_ada_",
        "___elab", "_OBJC_", "Java_", "_MOD_", "__anon_", "??_",
    ];
    let mut checked = 0;
    let mut leaks = Vec::new();
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
        for m in MARKERS {
            if r.demangled.contains(m) {
                leaks.push(format!("{m}: {sym} => {}", r.demangled));
                break;
            }
        }
    }
    assert!(checked > 3000, "vacuous: only {checked} decodes");
    assert!(leaks.is_empty(), "{}", leaks.join("\n"));
}
