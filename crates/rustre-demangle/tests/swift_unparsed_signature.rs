//! Swift dropped an unparseable signature, collapsing distinct functions.
//!
//! The parser renders the path, then fails on the signature and returns the
//! path alone. Five different signatures became one name:
//!
//! ```text
//! $s4main3fooySaySiGF    (Array<Int>)     main.foo
//! $s4main3fooySDySSSiGF  (Dictionary)     main.foo
//! $s4main3fooySqySiGF    (Optional)       main.foo
//! $s4main3fooySpySiGF    (Pointer)        main.foo
//! $s4main3fooySi_SitF    (a tuple)        main.foo
//! ```
//!
//! **`swift_completeness.rs` is structurally unable to see this.** Its
//! invariant is defined over `<len><chars>` identifiers, and a standard-library
//! substitution (`Si`, `SS`, `Say…G`) carries no length prefix — the same blind
//! spot that let Go drop a numeric closure index past `go_completeness.rs`
//! (iter 120). Finding the blind spot in an existing completeness check is what
//! produced both.
//!
//! Rendering those types properly needs the Swift grammar and an oracle to
//! validate it, neither of which is available here. **Echoing the unread
//! mangling needs neither**, and restores the distinction — the same remedy as
//! the operator suffixes at iter 131.
//!
//! The echo is anchored to the LAST rendered path component, not to a leading
//! run of identifiers: a Swift path may carry type markers between its names
//! (`$s4main3añC3baryyF` is `main.añ.bar`), so a leading-run scan returns a tail
//! overlapping text the rendering already contains.

fn ours(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

/// Distinct signatures render distinctly.
#[test]
fn unparseable_signatures_do_not_collide() {
    let mut seen: std::collections::BTreeMap<String, &str> = std::collections::BTreeMap::new();
    let mut collisions = Vec::new();
    for code in ["Si", "SS", "Sb", "Sd", "Sf", "Su", "Si_Sit", "SaySiG", "SDySSSiG", "SqySiG", "SpySiG"] {
        let sym = format!("$s4main3fooy{code}F");
        let out = ours(&sym).unwrap_or_else(|| panic!("{sym} must decode"));
        if let Some(prev) = seen.insert(out.clone(), code) {
            collisions.push(format!("{prev} and {code} both render {out}"));
        }
    }
    assert_eq!(seen.len(), 11, "{collisions:?}");
    assert!(collisions.is_empty(), "{}", collisions.join("\n"));
}

/// The echo carries the mangling verbatim, and the path is untouched.
#[test]
fn the_echo_is_verbatim_and_the_path_is_intact() {
    for (sym, path, tail) in [
        ("$s4main3fooySaySiGF", "main.foo", "ySaySiGF"),
        ("$s4main3fooySi_SitF", "main.foo", "ySi_SitF"),
        ("$sSS7countedSiSo7NSArrayCF", "Swift.String.counted", "SiSo7NSArrayCF"),
    ] {
        let out = ours(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert_eq!(out, format!("{path} [unparsed {tail}]"), "{sym}");
        assert!(sym.contains(tail), "the echo is not verbatim: {tail}");
    }
}

/// A symbol whose signature DOES parse gains no marker.
///
/// This is what keeps the echo from being noise: it fires only where the
/// signature was lost, which is exactly where the collision was.
#[test]
fn a_parsed_signature_gains_no_marker() {
    for sym in [
        "$s4main3fooyyF",
        "$s4main3fooySiF",
        "$s4main3barSiyF",
        "$s4main1aySiSSF",
        "_TtC4main3Foo",
        "_TF4main3fooFT_T_",
    ] {
        let out = ours(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(!out.contains("[unparsed"), "{sym} gained a marker: {out}");
    }
}

/// The marker never reaches a structured field.
///
/// It did, on the first version — the iter-140 defect reintroduced by the very
/// next rendering feature, which is why that iteration's note says a new
/// annotation must be run past the field probe.
#[test]
fn the_marker_stays_out_of_the_fields() {
    for sym in [
        "$s4main3fooySaySiGF",
        "$s4main3FooV3bazyySi_SStF",
        "$sSS7countedSiSo7NSArrayCF",
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym}"));
        for (label, v) in [
            ("namespace", r.namespace.clone()),
            ("class", r.class.clone()),
            ("function", Some(r.function.clone())),
        ] {
            let Some(v) = v else { continue };
            assert!(
                !v.contains("unparsed") && !v.contains('['),
                "{sym}: {label} = {v:?} carries the annotation"
            );
        }
    }
}

/// A multibyte identifier must not make the echo panic.
///
/// A byte-counted length can land inside a character, and slicing there aborts
/// the process. The first version did exactly that, caught by
/// `multibyte_length_prefixes.rs`.
#[test]
fn multibyte_identifiers_do_not_panic() {
    for sym in [
        "$s4main2añ3baryyF",
        "$s4main3añC3baryyF",
        "$s3añ3fooyyF",
        "$s4main3añyyF",
        "$s4main3FooC3añyyF",
    ] {
        // Returning at all is the requirement.
        let _ = rustre_demangle::demangle(sym);
    }
}
