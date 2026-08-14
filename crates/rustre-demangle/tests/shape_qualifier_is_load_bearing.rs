//! `go.shape.` is noise in a type ARGUMENT and load-bearing in a type
//! DESCRIPTOR.
//!
//! The crate strips the synthetic shape package from type arguments
//! (`main.Foo[go.shape.int].m` -> `main.Foo[int].m`) and keeps it verbatim in
//! `type:` descriptor renderings. That asymmetry looks like an oversight — the
//! same marker, stripped on one path and echoed on another — and a crate-wide
//! sweep for "no mangling marker reaches the output" flags it on five real
//! corpus symbols.
//!
//! **It is not an oversight, and the corpus proves it.** Both forms exist as
//! SEPARATE symbols in the same binary:
//!
//! ```text
//! type:.eq.internal/sync.indirect[go.shape.interface {},go.shape.interface {}]
//! type:.eq.internal/sync.indirect[interface {},interface {}]
//! ```
//!
//! One is the descriptor for the shape-instantiated type, the other for the
//! concrete one. Stripping the qualifier merges two real functions — exactly
//! the collision class this session has spent a dozen iterations removing.
//!
//! I made that change, and `corpus_decodes_do_not_collide_unexpectedly` caught
//! it. This file records the evidence so the next sweep does not re-derive it:
//! the asymmetry is justified by the data, not by neglect.

/// Both descriptor forms are present in the corpus, and must stay distinct.
#[test]
fn shape_and_concrete_descriptors_are_separate_symbols() {
    let corpus: Vec<&str> = include_str!("data/real_symbols.txt")
        .lines()
        .map(str::trim)
        .collect();

    let mut pairs = 0;
    for shape in corpus.iter().filter(|s| s.starts_with("type:") && s.contains("go.shape.")) {
        let concrete = shape.replace("go.shape.", "");
        if !corpus.contains(&concrete.as_str()) {
            continue;
        }
        pairs += 1;
        let a = rustre_demangle::demangle(shape).map(|r| r.demangled);
        let b = rustre_demangle::demangle(&concrete).map(|r| r.demangled);
        assert!(a.is_some(), "{shape} must decode");
        assert_ne!(
            a, b,
            "the shape-instantiated and concrete descriptors of one type \
             collapsed onto a single rendering"
        );
    }
    assert!(
        pairs >= 2,
        "vacuous: only {pairs} shape/concrete descriptor pairs found in the corpus"
    );
}

/// A type ARGUMENT keeps its stripping — the two paths differ deliberately.
///
/// Pinned beside the above so the asymmetry reads as a decision. Stripping is
/// safe here because the corpus holds no method whose shape and concrete
/// instantiations both appear; the collision sweep would fail if one did.
#[test]
fn type_arguments_still_drop_the_shape_qualifier() {
    let out = rustre_demangle::demangle("main.Foo[go.shape.int].m")
        .expect("must decode")
        .demangled;
    assert_eq!(out, "main.Foo[int].m");
    assert!(!out.contains("go.shape."));
}

/// The descriptor payload is echoed whole, qualifier included.
#[test]
fn descriptor_payloads_are_verbatim() {
    for sym in [
        "type:.eq.internal/sync.entry[go.shape.interface {},go.shape.interface {}]",
        "type:.eq.sync/atomic.Pointer[go.shape.struct { internal/sync.isEntry bool }]",
    ] {
        let out = rustre_demangle::demangle(sym)
            .unwrap_or_else(|| panic!("{sym} must decode"))
            .demangled;
        let payload = sym.strip_prefix("type:").expect("prefix");
        assert!(
            out.contains(payload),
            "{sym} lost part of its payload: {out}"
        );
        assert!(out.contains("go.shape."), "the qualifier was stripped: {out}");
    }
}
