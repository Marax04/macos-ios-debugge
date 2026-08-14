//! Swift's structured decomposition must name the right things.
//!
//! `DemanglingResult` carries both a rendered string and a decomposition
//! (`namespace`, `class`, `function`). Consumers use the fields — the
//! decompiler names variables from them — so a wrong decomposition is a real
//! defect even when the string is perfect.
//!
//! `split_swift_components` used to split the *whole* rendering on `.`. Swift
//! renderings also carry a type annotation, a signature and an accessor
//! marker, none of which are path components:
//!
//! ```text
//! "Foundation.Data.count.getter : Swift.Int"
//!    was  namespace=Foundation  class="getter : Swift"  function="Int"
//!    now  namespace=Foundation  class=Data             function=count
//! ```
//!
//! `class` was an accessor kind glued to half a type name, `function` was the
//! *return type*, and `Data` — the actual enclosing type — was lost entirely.
//!
//! **Why nothing caught it.** `tests/structured_consistency.rs` requires every
//! field to appear inside the rendered string, and each of those wrong values
//! does: `getter : Swift` and `Int` are both substrings of the rendering. That
//! invariant is necessary but not sufficient — exactly the blind spot recorded
//! for the Go backend, where the strings were right and the structured fields
//! lied. It also runs only over the corpora, and neither contains a Swift
//! symbol at all.
//!
//! The correct answers here need no oracle: they are read off the crate's own
//! rendering, which the differential and completeness suites already cover.

fn parts(sym: &str) -> (Option<String>, Option<String>, String, String) {
    let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
    (r.namespace, r.class, r.function, r.demangled)
}

/// Accessors: the type annotation and the accessor marker must stay out of the
/// path fields.
///
/// This is the discriminating shape. A plain method like `$s3foo3bar` decodes
/// to `foo.bar` and is split correctly by *any* implementation, including the
/// broken one — it has no annotation, no signature and no accessor suffix.
#[test]
fn accessor_symbols_decompose_to_type_and_property() {
    for (sym, ns, class, function) in [
        (
            "$s10Foundation4DataV5countSivg",
            "Foundation",
            "Data",
            "count",
        ),
        ("$s4main3FooC3barSivg", "main", "Foo", "bar"),
        // Setter: same shape, different accessor keyword.
        ("$s4main3FooC3barSivs", "main", "Foo", "bar"),
    ] {
        let (got_ns, got_class, got_fn, rendered) = parts(sym);
        assert_eq!(got_ns.as_deref(), Some(ns), "namespace of {sym}");
        assert_eq!(got_class.as_deref(), Some(class), "class of {sym}");
        assert_eq!(got_fn, function, "function of {sym}");

        // The specific failure modes, stated so they cannot come back in a
        // different disguise.
        assert!(
            !got_fn.contains("Swift"),
            "the return type leaked into `function` for {sym}: {got_fn}"
        );
        for kind in ["getter", "setter", "modify", "read"] {
            assert!(
                got_class.as_deref() != Some(kind) && !got_fn.contains(kind),
                "the accessor kind leaked into a path field for {sym}"
            );
        }
        // And the rendering itself is unchanged by any of this.
        assert!(rendered.starts_with(&format!("{ns}.{class}.{function}")));
    }
}

/// A signature must not leak into `function`.
///
/// `main.foo() -> ()` reported `function = "foo() -> ()"`, so a consumer using
/// the field as an identifier got something that is not one.
#[test]
fn a_signature_does_not_leak_into_the_function_name() {
    for (sym, ns, function) in [
        ("$s4main3fooyyF", "main", "foo"),
        ("$s4main3fooySiF", "main", "foo"),
    ] {
        let (got_ns, _, got_fn, _) = parts(sym);
        assert_eq!(got_ns.as_deref(), Some(ns), "namespace of {sym}");
        assert_eq!(got_fn, function, "function of {sym}");
        assert!(
            !got_fn.contains('(') && !got_fn.contains("->"),
            "signature leaked into `function` for {sym}: {got_fn}"
        );
    }
}

/// Control: the simple shapes the broken implementation also got right must
/// stay right.
///
/// Without these, a fix that mangled ordinary paths would still satisfy every
/// assertion above.
#[test]
fn plain_paths_are_unchanged() {
    for (sym, ns, class, function) in [
        ("$s3foo3bar", Some("foo"), None, "bar"),
        ("$sSS", Some("Swift"), None, "String"),
        ("$s4main3FooV3bazyySi_SStF", Some("main"), Some("Foo"), "baz"),
        ("$s3foo", None, None, "foo"),
    ] {
        let (got_ns, got_class, got_fn, _) = parts(sym);
        assert_eq!(got_ns.as_deref(), ns, "namespace of {sym}");
        assert_eq!(got_class.as_deref(), class, "class of {sym}");
        assert_eq!(got_fn, function, "function of {sym}");
    }
}

/// Every field must still appear in the rendered string.
///
/// The invariant `tests/structured_consistency.rs` enforces over the corpora,
/// applied to Swift — which neither corpus contains, so it was never checked
/// for this ABI at all. Kept alongside the assertions above precisely because
/// it is the weaker property: it holds for the broken decomposition too.
#[test]
fn every_field_still_appears_in_the_rendering() {
    let mut checked = 0;
    for sym in [
        "$s4main3fooyyF",
        "$s10Foundation4DataV5countSivg",
        "$s4main3FooC3barSivg",
        "$s3foo3bar",
        "$sSS",
        "$s4main3FooV3bazyySi_SStF",
    ] {
        let (ns, class, function, rendered) = parts(sym);
        for (label, value) in [("namespace", ns), ("class", class)] {
            if let Some(v) = value {
                assert!(
                    rendered.contains(&v),
                    "{label} {v:?} of {sym} is absent from {rendered:?}"
                );
            }
        }
        assert!(
            rendered.contains(&function),
            "function {function:?} of {sym} is absent from {rendered:?}"
        );
        checked += 1;
    }
    assert!(checked > 5, "vacuous: only {checked} symbols checked");
}
