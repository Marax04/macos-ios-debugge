//! The `class` field must name a class, and only when there is one.
//!
//! Continuing iters 137-138 through the ABIs the field probe had not reached.
//! Two more were folding the aggregate into `namespace` and reporting
//! `class: None`:
//!
//! ```text
//! _D4main3Foo3barMFZv   namespace "main.Foo", class None    (a D method)
//! Java_com_foo_Bar_baz  namespace "com.foo.Bar", class None (a JNI method)
//! ```
//!
//! **Both are fixed on evidence, not on the Rust/MSVC guess.** Those two assume
//! the last scope component is the class, which is wrong for a nested module —
//! `core::fmt::write` reports `fmt` as a class. Here:
//!
//! * D's mangling carries `M`, the MEMBER-function marker, precisely when the
//!   symbol belongs to an aggregate. `DDemangledSymbol` now records it, so the
//!   split happens only when the symbol says so. A free function in a nested
//!   module (`std.stdio.writeln`) correctly keeps `class: None` — the case the
//!   generic rule would have got wrong.
//! * JNI's encoding places the class between the package and the method by
//!   construction, so reading it there is not a guess either.
//!
//! OCaml is deliberately unchanged: `Stdlib.Printf` are *modules*, so folding
//! them into the namespace is right. The difference between the conventions is
//! justified by the conventions, not by taste.

fn fields(sym: &str) -> (Option<String>, Option<String>, String) {
    let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
    (r.namespace, r.class, r.function)
}

/// D reports a class exactly when the mangling carries `M`.
///
/// Discriminating: `_D4main3Foo3barMFZv` and `_D3std5stdio7writelnFAyaZv` have
/// the same *shape* — two scope components and a name — and differ only in the
/// member marker. Any rule based on component count alone gets one of them
/// wrong.
#[test]
fn d_reports_a_class_only_for_a_member_function() {
    for (sym, ns, class) in [
        // Member: the aggregate is the class.
        ("_D4main3Foo3barMFZv", Some("main"), Some("Foo")),
        ("_D4main3Foo3barMxFZv", Some("main"), Some("Foo")),
        // Free function, one module: no class.
        ("_D4main3fooFZv", Some("main"), None),
        // Free function, NESTED module: still no class. This is the case the
        // "last component is the class" rule would have called `stdio`.
        ("_D3std5stdio7writelnFAyaZv", Some("std.stdio"), None),
        // Data and compiler-generated symbols carry no member marker.
        ("_D4main1xi", Some("main"), None),
        ("_D4main12__ModuleInfoZ", Some("main"), None),
    ] {
        let (got_ns, got_class, _) = fields(sym);
        assert_eq!(got_ns.as_deref(), ns, "{sym} namespace");
        assert_eq!(got_class.as_deref(), class, "{sym} class");
    }
}

/// JNI splits package, class and method — all three, always.
#[test]
fn jni_reports_package_class_and_method() {
    for (sym, ns, class, function) in [
        ("Java_com_foo_Bar_baz", Some("com.foo"), Some("Bar"), "baz"),
        ("Java_a_b_c_d_e", Some("a.b.c"), Some("d"), "e"),
        ("Java_Bar_baz", None, Some("Bar"), "baz"),
        (
            "Java_com_foo_Bar_my_1method",
            Some("com.foo"),
            Some("Bar"),
            "my_method",
        ),
        (
            "Java_pkg_Cls_meth__Ljava_lang_String_2",
            Some("pkg"),
            Some("Cls"),
            "meth",
        ),
    ] {
        let (got_ns, got_class, got_fn) = fields(sym);
        assert_eq!(got_ns.as_deref(), ns, "{sym} namespace");
        assert_eq!(got_class.as_deref(), class, "{sym} class");
        assert_eq!(got_fn, function, "{sym} function");
    }
}

/// OCaml is unchanged — its path components are modules, not classes.
#[test]
fn ocaml_modules_stay_in_the_namespace() {
    let (ns, class, function) = fields("camlStdlib__Printf__printf_42");
    assert_eq!(ns.as_deref(), Some("Stdlib.Printf"));
    assert_eq!(class, None);
    assert_eq!(function, "printf");
}

/// Rejoining the fields must still reproduce the rendered path.
///
/// The guard against moving a component between fields and losing it on the
/// way: whatever the split, `namespace` + `class` + `function` must account for
/// the whole dotted name.
#[test]
fn the_fields_still_account_for_the_whole_name() {
    for sym in [
        "_D4main3Foo3barMFZv",
        "_D4main3fooFZv",
        "_D3std5stdio7writelnFAyaZv",
        "Java_com_foo_Bar_baz",
        "Java_a_b_c_d_e",
        "camlStdlib__Printf__printf_42",
        "ada__text_io__put_line",
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym}"));
        let mut joined = String::new();
        if let Some(ns) = &r.namespace {
            joined.push_str(ns);
            joined.push('.');
        }
        if let Some(c) = &r.class {
            joined.push_str(c);
            joined.push('.');
        }
        joined.push_str(&r.function);
        assert!(
            r.demangled.contains(&joined),
            "{sym}: fields rejoin to {joined:?}, which is not in {:?}",
            r.demangled
        );
    }
}
