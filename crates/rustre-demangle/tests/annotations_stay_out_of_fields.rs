//! A synthesized annotation belongs in the rendering, never in a field.
//!
//! This crate adds markers the mangling does not literally contain, to keep
//! distinct symbols distinct: `{closure-2 #2.3}` (Go), `[TA]` (Swift operator
//! suffix), `[clone .cold]` (GCC/LLVM), `main.foo().bar()` (a D function
//! nested in another function's scope), `[ada entry]` / `[elaborate body]`
//! (GNAT). Most already kept their marker out of the structured fields; two —
//! **both added during this session** — did not:
//!
//! ```text
//! pkg.proc [ada entry]       function  = "proc [ada entry]"   (iter 136)
//! void main.foo(int).bar()   namespace = "main.foo(int)"      (iter 130)
//! ```
//!
//! The fields are lookup keys — the decompiler names variables from them — so a
//! namespace of `main.foo(int)` matches nothing, and a function named
//! `proc [ada entry]` is not a name at all.
//!
//! The rule was already right for the clone suffix and the Swift suffix, which
//! is what made the two outliers visible: same shape of rendering, different
//! treatment.
//!
//! **The trade-off is deliberate.** `main.foo()` and `main.foo(int)` now report
//! the same namespace, as do two Go closures of one function. The rendering
//! keeps the distinction; the fields are keys, and overloads have always shared
//! them (`f(int)` and `f(char)` agree on all three in every ABI).

fn fields(sym: &str) -> (Option<String>, Option<String>, String, String) {
    let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
    (r.namespace, r.class, r.function, r.demangled)
}

/// No field may carry a marker character.
///
/// Stated over the OUTPUT against a character class rather than a list of
/// symbols, so an annotation added later is covered without editing this test.
#[test]
fn no_field_carries_an_annotation() {
    const ANNOTATED: &[&str] = &[
        "main.f.func2.3",
        "main.f.func1.2.3",
        "$s4main3fooyyFTA",
        "$s4main3fooyyFTATm",
        "_D4main3fooFZ3barFZv",
        "_D4main3fooFiZ3barFZv",
        "_D4main3Foo3barMxFZv",
        "_ada_pkg__proc",
        "_ada_hello",
        "pkg___elabb",
        "pkg___elabs",
        "_D4main3fooFZv.cold",
        "_D4main3fooFZv.llvm.1234567890",
        "_OBJC_PROTOCOL_$_NSCopying",
        "_OBJC_$_INSTANCE_METHODS_Foo",
        // Added iter 142: the Swift `[unparsed …]` echo. It leaked into
        // `function` on its first version — the defect this file exists for,
        // reintroduced by the very next rendering feature.
        "$s4main3fooySaySiGF",
        "$s4main3FooV3bazyySi_SStF",
        "$sSS7countedSiSo7NSArrayCF",
    ];
    let markers = ['[', ']', '{', '}', '(', ')', '#'];
    let mut checked = 0;
    let mut offenders = Vec::new();
    for sym in ANNOTATED {
        let (ns, class, function, rendering) = fields(sym);
        checked += 1;
        for (label, v) in [
            ("namespace", ns),
            ("class", class),
            ("function", Some(function)),
        ] {
            let Some(v) = v else { continue };
            if v.contains(markers) {
                offenders.push(format!("{sym}: {label} = {v:?} (rendering {rendering:?})"));
            }
        }
    }
    assert!(checked >= 15, "vacuous: only {checked}");
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

/// The annotation must still be in the RENDERING — the fix removes it from the
/// fields, it does not delete it.
///
/// Without this the previous test could be satisfied by dropping the marker
/// everywhere, which would undo four separate collision fixes from this
/// session.
#[test]
fn the_rendering_keeps_every_annotation() {
    for (sym, marker) in [
        ("main.f.func2.3", "{closure-2 #2.3}"),
        ("$s4main3fooyyFTA", "[TA]"),
        ("_D4main3fooFiZ3barFZv", "main.foo(int).bar()"),
        ("_ada_pkg__proc", "[ada entry]"),
        ("pkg___elabb", "[elaborate body]"),
        ("_D4main3fooFZv.cold", "[clone .cold]"),
    ] {
        let (_, _, _, rendering) = fields(sym);
        assert!(
            rendering.contains(marker),
            "{sym} lost its annotation {marker:?}: {rendering}"
        );
    }
}

/// The names themselves survive the scrubbing.
#[test]
fn the_scrubbed_fields_keep_the_real_names() {
    for (sym, ns, function) in [
        ("_D4main3fooFZ3barFZv", Some("main.foo"), "bar"),
        ("_D4main3fooFiZ3barFZv", Some("main.foo"), "bar"),
        ("_ada_pkg__proc", Some("pkg"), "proc"),
        ("pkg___elabb", None, "pkg"),
        ("main.f.func2.3", Some("main"), "f"),
        ("$s4main3fooyyFTA", Some("main"), "foo"),
    ] {
        let (got_ns, _, got_fn, _) = fields(sym);
        assert_eq!(got_ns.as_deref(), ns, "{sym} namespace");
        assert_eq!(got_fn, function, "{sym} function");
    }
}

/// Every field is still a substring of the rendering.
///
/// Scrubbing must remove characters, never invent a name that was not there.
#[test]
fn scrubbing_invents_nothing() {
    for sym in [
        "_D4main3fooFZ3barFZv",
        "_ada_pkg__proc",
        "pkg___elabb",
        "main.f.func2.3",
        "$s4main3fooyyFTA",
        "_D4main3Foo3barMxFZv",
    ] {
        let (ns, class, function, rendering) = fields(sym);
        for (label, v) in [
            ("namespace", ns),
            ("class", class),
            ("function", Some(function)),
        ] {
            let Some(v) = v else { continue };
            assert!(
                rendering.contains(&v),
                "{sym}: {label} {v:?} is not part of {rendering:?}"
            );
        }
    }
}
