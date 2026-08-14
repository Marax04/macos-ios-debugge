//! Swift's `y` is an empty-LIST marker, not a parameter type.
//!
//! The collector pushes an empty tuple for each `y`, and the signature builder
//! dropped it only when it was the sole entry:
//!
//! ```text
//! if params.len() == 1 && params[0] == TupleType(vec![]) { params.clear() }
//! ```
//!
//! A second marker therefore became an invented parameter:
//!
//! ```text
//! $s4main3fooyySiF  =>  main.foo((), ()) -> Swift.Int   // arity 2, both ()
//! $s4main1aySiSSF   =>  main.a((), Swift.Int) -> …      // arity 2 for one arg
//! ```
//!
//! Phantom parameters are the class this repo singles out as the worst kind:
//! well-formed, plausible, and invisible to every check but arity itself. Swift
//! has no oracle, so nothing could contradict the rendering — which is exactly
//! why an ARITY property, defined over the input, is the instrument that works.
//!
//! **This is independent of the open signature-ORDER question**
//! (`tests/swift_signature_order.rs`, which stays ignored and untouched): a list
//! marker is not a parameter under either reading of `result-type params-type`,
//! so nothing asserted here presumes an answer to it. The assertions below fix
//! only the *count* and the *absence of `()` entries*, never which side of the
//! arrow a named type lands on.

/// Parameters of a rendered signature, or `None` if no signature is claimed.
fn params(sym: &str) -> Option<Vec<String>> {
    let out = rustre_demangle::demangle(sym)?.demangled;
    let open = out.find('(')?;
    let close = out[open..].find(')')? + open;
    let inner = &out[open + 1..close];
    Some(if inner.is_empty() {
        Vec::new()
    } else {
        inner.split(", ").map(str::to_owned).collect()
    })
}

/// An empty-list marker never appears as a parameter entry.
///
/// Stated over the OUTPUT against the `()` entry rather than over a list of
/// known-bad symbols, so any future path that lets a marker through fails here.
#[test]
fn no_empty_tuple_survives_as_a_parameter() {
    let symbols = [
        "$s4main3fooyyF",
        "$s4main3barSiyF",
        "$s4main3fooyySiF",
        "$s4main1aySiSSF",
        "$s4main3fooySiF",
        "$s4main3fooySSF",
        "$s4main3fooySiSiF",
    ];
    let mut checked = 0;
    let mut offenders = Vec::new();
    for sym in symbols {
        let Some(ps) = params(sym) else { continue };
        checked += 1;
        if ps.iter().any(|p| p == "()") {
            offenders.push(format!("{sym} => params {ps:?}"));
        }
    }
    assert!(checked >= 6, "vacuous: only {checked} signatures rendered");
    assert!(
        offenders.is_empty(),
        "the empty-list marker was rendered as a parameter:\n{}",
        offenders.join("\n")
    );
}

/// Arity counts named types, not markers.
///
/// Discriminating: `$s4main3fooyyF` and `$s4main3barSiyF` pass whether or not
/// the rule handles more than one marker — they carry at most one, and were
/// already right. `$s4main3fooyySiF` and `$s4main1aySiSSF` are what separate a
/// correct rule from a plausible one.
#[test]
fn arity_counts_types_not_markers() {
    for (sym, want) in [
        ("$s4main3fooyyF", 0),
        ("$s4main3barSiyF", 1),
        ("$s4main3fooyySiF", 0),
        ("$s4main1aySiSSF", 1),
        ("$s4main3fooySiSiF", 1),
    ] {
        assert_eq!(
            params(sym).map(|p| p.len()),
            Some(want),
            "{sym} has the wrong parameter count"
        );
    }
}

/// The named types are still all present — the fix removes markers, not
/// information.
///
/// The completeness direction: dropping a marker must not drop a type with it.
#[test]
fn named_types_survive_the_marker_removal() {
    for (sym, needles) in [
        ("$s4main3fooyySiF", &["Swift.Int"][..]),
        ("$s4main1aySiSSF", &["Swift.Int", "Swift.String"][..]),
        ("$s4main3barSiyF", &["Swift.Int"][..]),
    ] {
        let out = rustre_demangle::demangle(sym)
            .unwrap_or_else(|| panic!("{sym} must decode"))
            .demangled;
        for n in needles {
            assert!(out.contains(n), "{sym} lost {n}: {out}");
        }
    }
}

/// The signature ORDER is deliberately not asserted here, but it must not have
/// MOVED: these two renderings are what they were before the marker fix, so a
/// future change to the order question is a deliberate act rather than a side
/// effect of this one.
#[test]
fn the_open_order_question_is_unchanged_by_this_fix() {
    let bar = rustre_demangle::demangle("$s4main3barSiyF")
        .expect("must decode")
        .demangled;
    let foo = rustre_demangle::demangle("$s4main3fooyyF")
        .expect("must decode")
        .demangled;
    assert_eq!(bar, "main.bar(Swift.Int) -> ()");
    assert_eq!(foo, "main.foo() -> ()");
}
