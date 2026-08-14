//! A length prefix that cuts a multi-byte character names nothing.
//!
//! D, Swift and Itanium all encode identifiers as `<byte-length><bytes>`. The
//! length is in **bytes**, so a malformed symbol can declare a length that ends
//! *between* the bytes of a multi-byte character, leaving a slice that is not
//! valid UTF-8. There are three ways an implementation can respond, and only
//! one of them is honest:
//!
//! * decline — the slice is not a name (correct);
//! * substitute a placeholder — visible fabrication;
//! * substitute U+FFFD via `from_utf8_lossy` — **invisible** fabrication, which
//!   is the worst of the three because a replacement character reads as data
//!   rather than as an error.
//!
//! Swift took the third route: `$s1ñ` decoded to `Some("\u{fffd}")` — a symbol
//! whose entire rendered content was a replacement character — and
//! `$s2añ3fooyyF` to `Some("a\u{fffd}")`, silently dropping `foo` as well.
//! D already declined the same shapes, which is what made the divergence
//! visible: two length-prefixed backends, same malformed input, opposite
//! answers.
//!
//! Neither corpus contains a non-ASCII symbol, and `tests/unicode_identifiers.rs`
//! covers only Rust's punycode encoding, so nothing exercised this. `ñ` is two
//! bytes (C3 B1) and `中` three (E4 B8 AD), which is all the arithmetic needed
//! to build the cases below.

/// Malformed where the cut is in a **later** component — past the point a
/// first-prefix-only `detect` prefilter can see.
///
/// These are what discriminate the parser fix from the prefilter. With
/// `from_utf8_lossy` restored they render `foo.a` followed by a replacement
/// character; the `CUT` list below is rejected by `detect` before the parser is
/// ever reached, so it would pass either way. A mutation test that only used
/// `CUT` proved nothing about the line it was meant to cover.
const CUT_LATER: &[&str] = &["$s3foo2añ", "$s3foo1ñ", "$s4main2añ3baryyF"];

/// Malformed: the declared byte length ends inside a character.
const CUT: &[(&str, &str)] = &[
    ("_D2añ3fooFZv", "D: 2 bytes over `a` + first half of ñ"),
    ("_D1ñ3fooFZv", "D: 1 byte over the first third of ñ"),
    ("_D2中3fooFZv", "D: 2 of the 3 bytes of 中"),
    ("$s2añ3fooyyF", "Swift: 2 bytes over `a` + first half of ñ"),
    ("$s1ñ", "Swift: 1 byte over the first half of ñ"),
];

/// Well-formed: the same characters, measured correctly.
const WHOLE: &[(&str, &str)] = &[
    ("_D3añ3fooFZv", "void añ.foo()"),
    ("$s3añ3fooyyF", "añ.foo() -> ()"),
];

#[test]
fn a_cut_multibyte_name_declines() {
    let mut checked = 0;
    for (sym, why) in CUT {
        let got = rustre_demangle::demangle(sym);
        assert!(
            got.is_none(),
            "{sym} ({why}) must decline, but decoded to {:?}",
            got.map(|r| r.demangled)
        );
        checked += 1;
    }
    assert!(checked > 4, "vacuous: only {checked} inputs checked");
}

/// The specific failure mode, stated so a future `from_utf8_lossy` cannot
/// reintroduce it while still declining these particular inputs.
///
/// U+FFFD must never appear in a rendered symbol: no ABI here encodes it, so
/// its presence can only mean a byte slice was coerced rather than read.
#[test]
fn no_decode_ever_contains_a_replacement_character() {
    let mut checked = 0;
    for sym in CUT
        .iter()
        .map(|(s, _)| *s)
        .chain(WHOLE.iter().map(|(s, _)| *s))
        .chain(CUT_LATER.iter().copied())
    {
        if let Some(r) = rustre_demangle::demangle(sym) {
            assert!(
                !r.demangled.contains('\u{fffd}'),
                "{sym} decoded to a lossy substitution: {:?}",
                r.demangled
            );
        }
        checked += 1;
    }
    assert!(checked > 9, "vacuous: only {checked} inputs checked");
}

/// **Known residual defect, recorded with the reason it resists fixing.**
///
/// Removing the lossy substitution stopped the fabrication but did not make
/// these symbols honest: the malformed component is *dropped silently*.
/// `$s4main2añ3baryyF` returns `Some("main")` — losing both the cut component
/// and the `bar` after it — and reports success while doing so.
///
/// Two attempts (iters 66 and 67) tried to fix it by widening
/// `backends::dropped_swift_local_name` from local entities to **any**
/// length-prefixed identifier absent from the rendering. Both reverted, and the
/// second found the real obstacle:
///
/// > `$sSS7countedSiSo7NSArrayCF` renders `Swift.String.counted`. `NSArray` is a
/// > length-prefixed identifier in **signature** position, and the renderer drops
/// > signatures — the loss the measured Swift trailing-input exemption exists to
/// > permit. So a bare identifier is ambiguous: absent from path position it is
/// > lost identity; absent from type position it is lost detail. An input-only
/// > rule cannot tell them apart.
///
/// Iter 66 had blamed the non-ASCII character instead, on a control that was
/// itself invalid Swift. That diagnosis was wrong, and the controls below now
/// establish it as fact rather than leaving it to be re-litigated.
///
/// A real fix needs parser state — the position an identifier occupies — not a
/// wider string scan.
#[test]
fn a_cut_later_component_is_dropped_silently() {
    // The truncation REMAINS — a real fix still needs parser state, as the note
    // above says — but it is no longer SILENT, which is what this test is named
    // for. Iter 142 made the Swift path echo the mangling that follows
    // everything the rendering names, so the dropped components are visible
    // instead of vanishing, and two symbols truncated at different points no
    // longer render alike.
    assert_eq!(
        rustre_demangle::demangle("$s4main2añ3baryyF").map(|r| r.demangled),
        Some("main [unparsed 2añ3baryyF]".to_owned()),
        "the truncation is documented, but must not be silent"
    );

    // Non-ASCII identifiers are NOT the problem: they decode in every valid
    // position. Pinned so the wrong diagnosis cannot be reached again.
    for (sym, want) in [
        ("$s3añ3fooyyF", "añ.foo() -> ()"),
        ("$s4main3añyyF", "main.añ() -> ()"),
        // These two render a PATH with no signature, so the unread signature
        // mangling is echoed (iter 142). The point of this loop — that a
        // non-ASCII identifier decodes in every valid position — is unchanged:
        // `añ` still appears, in the same place, in both.
        ("$s4main3añC3baryyF", "main.añ.bar [unparsed yyF]"),
        ("$s4main3FooC3añyyF", "main.Foo.añ [unparsed yyF]"),
    ] {
        assert_eq!(
            rustre_demangle::demangle(sym).map(|r| r.demangled).as_deref(),
            Some(want),
            "{sym} is valid Swift and must decode"
        );
    }

    // The symbol that blocks the widening. If a future change makes the rule
    // position-aware, this must still decode — it is the constraint, not a
    // casualty.
    assert_eq!(
        rustre_demangle::demangle("$sSS7countedSiSo7NSArrayCF")
            .map(|r| r.demangled)
            .as_deref(),
        // The constraint is that this still DECODES with its path intact.
        // Iter 142 additionally echoes the unread signature, so the permitted
        // detail loss is visible rather than silent — which is what every note
        // in this file argues for.
        Some("Swift.String.counted [unparsed SiSo7NSArrayCF]"),
        "NSArray sits in signature position; dropping it is permitted detail loss"
    );
}

/// Control: measured correctly, the very same characters decode.
///
/// Without this, declining every non-ASCII identifier would satisfy both tests
/// above while destroying legitimate decodes.
#[test]
fn a_correctly_measured_multibyte_name_decodes() {
    for (sym, want) in WHOLE {
        let got = rustre_demangle::demangle(sym)
            .unwrap_or_else(|| panic!("{sym} is well-formed and must decode"))
            .demangled;
        assert_eq!(got, *want, "{sym}");
        assert!(got.contains('ñ'), "the character must survive intact: {got}");
    }
}

/// `detect` and `demangle` must give the same answer on a cut name.
///
/// Tightening the parser alone turns a consistent error into a divergence, and
/// `if d.detect(s) { d.demangle(s).unwrap() }` then panics — the mistake that
/// once broke 89 corpus symbols here. The Swift prefilter has to reject a
/// length that does not land on a character boundary for exactly this reason.
///
/// **Written first as `if detect(sym) { assert demangle.is_some() }`, which was
/// vacuous: measured 0 of 5.** Both detectors reject every cut name — which is
/// the correct behaviour this file establishes — so the body never ran. A
/// conditional assertion cannot verify the condition gating it, and it is blind
/// to the opposite regression, a detector grown too strict.
///
/// Stated as an equality it holds non-vacuously, and the positive control forces
/// both sides true so the pairing is exercised in each direction.
#[test]
fn detect_and_demangle_agree_on_cut_names() {
    use rustre_demangle::{DDemangler, Demangler, SwiftDemangler};

    let swift = SwiftDemangler;
    let mut checked = 0;
    for (sym, why) in CUT {
        let (claimed, decoded) = if sym.starts_with("$s") {
            (swift.detect(sym), swift.demangle(sym).is_some())
        } else {
            (DDemangler::detect(sym), DDemangler::demangle(sym).is_some())
        };
        assert_eq!(claimed, decoded, "detect and demangle disagree on {sym} ({why})");
        assert!(!claimed, "{sym} ({why}) is not a symbol and must not be claimed");
        checked += 1;
    }
    assert!(checked > 4, "vacuity guard: only {checked} cut names compared");

    // Positive control: measured correctly, the same characters are claimed and
    // decoded by both backends. Without this the assertions above are satisfied
    // by detectors that reject everything.
    for (sym, _) in WHOLE {
        let (claimed, decoded) = if sym.starts_with("$s") {
            (swift.detect(sym), swift.demangle(sym).is_some())
        } else {
            (DDemangler::detect(sym), DDemangler::demangle(sym).is_some())
        };
        assert!(claimed, "{sym} is well-formed and must be claimed");
        assert!(decoded, "{sym} is well-formed and must decode");
    }
}

/// An enormous length prefix must not overflow the arithmetic that uses it.
///
/// `backends::dropped_swift_local_name` scans the symbol for `<len><name>` and
/// computed `i + len` plainly. `len` comes from the input, so a prefix at
/// `usize::MAX` makes the sum wrap:
///
/// ```text
/// $s4main5outeryyF18446744073709551615aL_yyF
///   -> panicked: attempt to add with overflow
/// ```
///
/// Reachable on attacker-controlled input, and **invisible to all four release
/// gates**, because overflow checks are compiled out of a release build. Found by
/// `tests/debug_assertions_hold.sh` (added iter 81) plus a targeted probe: the
/// symbol has to decode far enough for the helper to run, so the overflowing
/// prefix must sit *after* a well-formed prefix.
///
/// Fixed with `checked_add`. The test drives the boundary from both sides — a
/// prefix that fits and one that does not — so a fix that simply stopped scanning
/// would fail the first half.
#[test]
fn an_enormous_length_prefix_does_not_overflow() {
    // Prefixes at and around `usize::MAX`, and one longer than it can hold.
    for prefix in [
        "18446744073709551615", // usize::MAX exactly
        "18446744073709551614",
        "18446744073709551610",
        "99999999999999999999", // does not parse into usize at all
        "9999999999999999999",  // parses, and i + len does NOT overflow
    ] {
        let sym = format!("$s4main5outeryyF{prefix}aL_yyF");
        // The assertion is that this returns rather than panicking; the value is
        // not the point. A release build cannot observe the panic, so this test
        // earns its keep only under `debug_assertions_hold.sh`.
        let _ = rustre_demangle::demangle(&sym);
    }

    // Boundary from the other side: ordinary prefixes must still be scanned, or
    // the guard could pass by refusing to look at lengths at all. The local name
    // `inside` is dropped, so this must decline.
    assert!(
        rustre_demangle::demangle("$s4main5outeryyF6insideL_yyF").is_none(),
        "a normal length prefix must still be read and the dropped name caught"
    );
    // And a well-formed symbol with no local entity must still decode.
    assert_eq!(
        rustre_demangle::demangle("$s4main5outeryyF")
            .map(|r| r.demangled)
            .as_deref(),
        Some("main.outer() -> ()")
    );
}
