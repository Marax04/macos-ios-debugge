//! MSVC numeric back-references name a TOP-LEVEL parameter, not a nested type.
//!
//! `0`-`9` in a parameter list repeat a previously-seen parameter type. The
//! individual type parsers each registered whatever they built — including
//! nested types — so a parameter containing a class registered the class too,
//! and the back-reference resolved to it:
//!
//! ```text
//! ?f@@YAXPAVFoo@@0@Z    was  Foo*, Foo         want  Foo*, Foo*
//! ?f@@YAXABVFoo@@0@Z    was  const Foo&, Foo   want  const Foo&, const Foo&
//! ?f@@YAXPAPAVFoo@@0@Z  was  Foo**, Foo        want  Foo**, Foo**
//! ```
//!
//! Silently wrong, and invisible to any check defined over our own output: the
//! symbol decoded, the rendering was well-formed C++, and only the second
//! parameter was a different type from the one the mangling names. The
//! reference branch registered nothing at all, so `?f@@YAXABH0@Z` declined
//! outright and reported `UnsupportedAbi`.
//!
//! **The slot rule was measured, not assumed** — `msvc-demangler` is the only
//! thing that could settle it:
//!
//! * `?f@@YAXHVFoo@@0@Z` is `int, Foo, Foo` — a bare primitive occupies NO slot
//! * `?f@@YAXABHVFoo@@0@Z` is `int const&, Foo, int const&` — a *reference to*
//!   a primitive does
//! * `?f@@YAXH0@Z` is rejected by the oracle — a lone primitive leaves no slot
//!   to refer back to
//!
//! Found by the per-variant sweep (iters 123-125): MSVC's `??$` template
//! functions were the one sigil variant reporting `UnsupportedAbi`, and the
//! template turned out to be incidental — the back-reference in its signature
//! was the real cause.

fn oracle(sym: &str) -> Option<String> {
    msvc_demangler::demangle(sym, msvc_demangler::DemangleFlags::COMPLETE).ok()
}

fn ours(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

/// Collapse the presentation differences the crate already normalises
/// elsewhere: `undname` writes east-const and elaborates class tags.
fn normalise(s: &str) -> String {
    let mut t = s
        .replace("class ", "")
        .replace("struct ", "")
        .replace("enum ", "")
        .replace("union ", "");
    let consts = t.matches("const").count();
    t = t.replace("const", "");
    t.retain(|c| c != ' ');
    format!("{t}|const x{consts}")
}

/// Back-referenced parameters match the oracle, nested classes and all.
#[test]
fn back_referenced_parameters_agree_with_the_oracle() {
    const CASES: &[&str] = &[
        "?f@@YAXPAVFoo@@0@Z",
        "?f@@YAXABVFoo@@0@Z",
        "?f@@YAXVFoo@@0@Z",
        "?f@@YAXABH0@Z",
        "?f@@YAXPAH0@Z",
        "?f@@YAXPAPAVFoo@@0@Z",
        "?f@@YAXHVFoo@@0@Z",
        "?f@@YAXVFoo@@H0@Z",
        "?f@@YAXABHVFoo@@0@Z",
        "??$max@H@@YAHABH0@Z",
        "?f@@YAXAAH0@Z",
        "?f@@YAXABD0@Z",
    ];

    let mut checked = 0;
    let mut wrong = Vec::new();
    for sym in CASES {
        let want = oracle(sym).unwrap_or_else(|| panic!("{sym}: the oracle rejects it — the test vector is malformed"));
        checked += 1;
        match ours(sym) {
            Some(got) if normalise(&got) == normalise(&want) => {}
            Some(got) => wrong.push(format!("{sym}\n  oracle: {want}\n  ours:   {got}")),
            None => wrong.push(format!("{sym}\n  oracle: {want}\n  ours:   <declined>")),
        }
    }
    assert!(checked >= 12, "vacuous: only {checked} vectors");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The two parameters really are the same type.
///
/// Stated structurally rather than against an expected string: whatever the
/// rendering, a back-reference must reproduce its target exactly. This is what
/// `Foo*, Foo` violated while looking perfectly well-formed.
#[test]
fn a_back_reference_reproduces_its_target() {
    for sym in [
        "?f@@YAXPAVFoo@@0@Z",
        "?f@@YAXABVFoo@@0@Z",
        "?f@@YAXPAPAVFoo@@0@Z",
        "?f@@YAXABH0@Z",
    ] {
        let out = ours(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        let open = out.find('(').expect("a signature");
        let close = out.rfind(')').expect("a signature");
        let args: Vec<&str> = out[open + 1..close].split(", ").collect();
        assert_eq!(args.len(), 2, "{sym} => {out}");
        assert_eq!(args[0], args[1], "{sym}: the back-reference differs from its target ({out})");
    }
}

/// A bare primitive occupies no slot, so a back-reference skips past it.
///
/// Discriminating: `?f@@YAXVFoo@@0@Z` passes under either slot rule — there is
/// only one candidate. `?f@@YAXHVFoo@@0@Z` is what separates them, and it is
/// the case the oracle had to decide.
#[test]
fn a_bare_primitive_occupies_no_slot() {
    let out = ours("?f@@YAXHVFoo@@0@Z").expect("must decode");
    assert!(out.ends_with("(int, Foo, Foo)"), "{out}");
    let out = ours("?f@@YAXVFoo@@H0@Z").expect("must decode");
    assert!(out.ends_with("(Foo, int, Foo)"), "{out}");
    // But a reference to a primitive does take one.
    let out = ours("?f@@YAXABHVFoo@@0@Z").expect("must decode");
    assert!(out.ends_with("(const int&, Foo, const int&)"), "{out}");
}

/// Signatures without back-references are unchanged.
#[test]
fn ordinary_signatures_are_unaffected() {
    for (sym, want) in [
        ("?f@@YAXHH@Z", "void __cdecl f(int, int)"),
        ("?bar@Foo@@QAEXXZ", "public: void __thiscall Foo::bar(void)"),
        ("?f@@YAXABHABH@Z", "void __cdecl f(const int&, const int&)"),
        ("??0Foo@@QAE@XZ", "public: __thiscall Foo::Foo(void)"),
    ] {
        assert_eq!(ours(sym).as_deref(), Some(want), "{sym}");
    }
}
