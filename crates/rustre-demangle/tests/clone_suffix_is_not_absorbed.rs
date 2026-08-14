//! A backend that claims a clone-suffixed name must ACCOUNT for the suffix.
//!
//! Found by probing a COMBINATION — clone suffixes applied to ABIs that had
//! only ever been tested without one. The wrapper that renders `[clone .cold]`
//! runs *after* the strict backends, so any backend whose grammar tolerates a
//! dot swallowed the suffix into the name instead:
//!
//! ```text
//! Java_com_foo_Bar_baz.cold   =>  com.foo.Bar.baz.cold    function == "cold"
//! Java_com_foo_Bar_baz.part.0 =>  com.foo.Bar.baz.part.0  function == "0"
//! $s4main3fooyyFTA.cold       =>  main.foo() -> ()
//! ```
//!
//! The JNI method was **renamed to the clone tag**, and Swift lost both the tag
//! and the `[TA]` operator suffix — five distinct symbols on one rendering.
//!
//! **Itanium and Rust are exempt, and that is the point of the rule rather than
//! an exception to it.** Both are oracle-backed and handle suffixes their own
//! way: `cpp_demangle` writes `[clone .cold]`, `rustc-demangle` appends `.cold`
//! inline and DROPS `.llvm.<hash>` entirely. My first version tested only for
//! the `[clone ` spelling and broke iter 127 — whose finding was precisely that
//! the oracle decides. `compiler_suffix_variants.rs` caught it immediately.

fn ours(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

/// Clone-suffixed symbols stay distinct from their bases and from each other.
#[test]
fn clone_suffixes_do_not_collide() {
    let mut seen: std::collections::BTreeMap<String, &str> = std::collections::BTreeMap::new();
    let mut collisions = Vec::new();
    for sym in [
        "$s4main3fooyyF",
        "$s4main3fooyyFTA",
        "$s4main3fooyyF.cold",
        "$s4main3fooyyFTA.cold",
        "$s4main3fooyyFTo.cold",
        "$s4main3fooyyFTA.part.0",
        "Java_com_foo_Bar_baz",
        "Java_com_foo_Bar_baz.cold",
        "Java_com_foo_Bar_baz.part.0",
    ] {
        let out = ours(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        if let Some(prev) = seen.insert(out.clone(), sym) {
            collisions.push(format!("{prev} and {sym} both render {out}"));
        }
    }
    assert_eq!(seen.len(), 9, "{collisions:?}");
    assert!(collisions.is_empty(), "{}", collisions.join("\n"));
}

/// The entity name is the entity's, not the clone tag's.
///
/// The sharpest symptom: `function` reported `"cold"` and `"0"`.
#[test]
fn the_clone_tag_does_not_become_the_name() {
    for (sym, function) in [
        ("Java_com_foo_Bar_baz.cold", "baz"),
        ("Java_com_foo_Bar_baz.part.0", "baz"),
        ("camlFoo__bar.cold", "bar"),
        ("__mymod_MOD_solve.cold", "solve"),
        ("_OBJC_CLASS_$_Foo.cold", "Foo"),
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert_eq!(r.function, function, "{sym} => {:?}", r.demangled);
        assert!(
            r.demangled.contains("[clone "),
            "{sym}: the suffix was absorbed rather than reported: {:?}",
            r.demangled
        );
    }
}

/// Markers already in the rendering survive alongside the clone tag.
///
/// This is what composition broke: `[TA]` disappeared the moment a clone suffix
/// was present.
#[test]
fn other_markers_survive_beside_the_clone_tag() {
    for (sym, want) in [
        ("$s4main3fooyyFTA.cold", "main.foo() -> () [TA] [clone .cold]"),
        ("$s4main3fooyyFTo.cold", "main.foo() -> () [To] [clone .cold]"),
        ("$s4main3fooyyFTA.part.0", "main.foo() -> () [TA] [clone .part.0]"),
        ("_ada_pkg__proc.cold", "pkg.proc [ada entry] [clone .cold]"),
        ("_D4main3fooFZ3barFZv.cold", "void main.foo().bar() [clone .cold]"),
    ] {
        assert_eq!(ours(sym).as_deref(), Some(want), "{sym}");
    }
}

/// The oracle-backed ABIs keep their own suffix handling.
///
/// The exemption, pinned: `rustc-demangle` drops `.llvm.<hash>` and appends
/// `.cold` inline; `cpp_demangle` writes `[clone …]`. Forcing either into this
/// crate's wrapper is what my first attempt did, and it contradicted iter 127.
#[test]
fn oracle_backed_abis_are_unchanged() {
    let legacy = "_ZN4core3fmt5write17h0123456789abcdefE";
    assert_eq!(
        ours(&format!("{legacy}.llvm.1234567890")).as_deref(),
        Some("core::fmt::write"),
        "rustc-demangle drops the ThinLTO suffix"
    );
    assert_eq!(
        ours(&format!("{legacy}.cold")).as_deref(),
        Some("core::fmt::write.cold"),
        "rustc-demangle appends .cold inline"
    );
    assert_eq!(
        ours("_ZN2ns4funcEv.cold").as_deref(),
        Some("ns::func() [clone .cold]"),
        "cpp_demangle writes its own clone formatting"
    );
    // And neither gains a doubled marker.
    for sym in [
        format!("{legacy}.cold"),
        "_ZN2ns4funcEv.cold".to_owned(),
    ] {
        let out = ours(&sym).unwrap_or_else(|| panic!("{sym}"));
        assert!(out.matches("[clone ").count() <= 1, "{sym} => {out}");
    }
}

/// Unsuffixed symbols are untouched by the new rule.
#[test]
fn unsuffixed_symbols_are_unaffected() {
    for (sym, want) in [
        ("Java_com_foo_Bar_baz", "com.foo.Bar.baz"),
        ("$s4main3fooyyFTA", "main.foo() -> () [TA]"),
        ("camlFoo__bar", "Foo.bar"),
        ("_OBJC_CLASS_$_Foo", "class Foo"),
        ("?f@@YAXHH@Z", "void __cdecl f(int, int)"),
    ] {
        assert_eq!(ours(sym).as_deref(), Some(want), "{sym}");
    }
}
