//! A Swift symbol the parser could not make sense of must decline, not decode.
//!
//! `swift_demangler` renders `?module` (and `?(…)`) when an `unwrap_or_else`
//! fallback fires — its way of saying "I could not read this". Those renderings
//! were reaching callers as **successful decodes**: `$s` alone, `$s10ab` (a
//! length prefix longer than the text that follows) and `$s{}` all returned
//! `Some("?module")`, and `decline_reason` classified them `Decoded`. A
//! fabrication was being counted as a success, both in the classification
//! metric — the metric this crate treats as authoritative — and in any corpus
//! decode total.
//!
//! The rule applied here is not new. This crate already refuses `Java_` on its
//! own, and the loose `_R`/`_T`/`_D` prefix rules were removed precisely
//! because they claimed plain C names: a bare sigil is not a symbol. Swift was
//! simply out of step with a lesson already paid for.
//!
//! Note the direction of the change: it *removes* output rather than replacing
//! it with a better guess. That lowers the decode count, which a raw count
//! reads as a loss and this crate's own history reads as a fidelity gain — the
//! same trade as the five earlier steps recorded in the crate's CLAUDE.md.

use rustre_demangle::decline::{DeclineReason, decline_reason};

/// Inputs carrying the Swift sigil but no readable symbol after it.
const DEGENERATE: &[(&str, &str)] = &[
    ("$s", "bare sigil, nothing follows"),
    ("$s10ab", "length prefix 10, only 2 characters available"),
    ("$s99ab", "length prefix 99, only 2 characters available"),
    ("$s99abcdef", "length prefix 99, 6 characters available"),
    ("$s{}", "not an identifier at all"),
    ("$sñ", "non-ASCII where a length prefix is required"),
    ("$s0foo", "zero-length identifier"),
];

#[test]
fn degenerate_swift_inputs_decline_instead_of_fabricating() {
    let mut checked = 0;
    for (sym, why) in DEGENERATE {
        let got = rustre_demangle::demangle(sym);
        assert!(
            got.is_none(),
            "{sym} ({why}) must decline, but decoded to {:?}",
            got.map(|r| r.demangled)
        );
        assert_ne!(
            decline_reason(sym),
            DeclineReason::Decoded,
            "{sym} must not be counted as a decode"
        );
        checked += 1;
    }
    assert!(checked > 5, "vacuous: only {checked} inputs checked");
}

/// `detect` and `demangle` must give the same answer.
///
/// Tightening `demangle` alone turns a consistent error into a divergence, and
/// the idiom `if d.detect(s) { d.demangle(s).unwrap() }` then panics. That
/// exact mistake once broke 89 corpus symbols in this crate.
///
/// **This test was written as `if d.detect(sym) { assert!(demangle.is_some()) }`,
/// and once `detect` was tightened to reject these very inputs its body stopped
/// running: measured 0 of 7.** It would still have fired had `detect` been
/// loosened — that much it did — but it executed no assertion under correct
/// code, so it gave no standing evidence the property held, and it was blind to
/// the opposite regression: a `detect` grown *too* strict, rejecting valid
/// symbols, satisfies a conditional assertion perfectly.
///
/// Stated as an equality instead, it holds non-vacuously: both sides must be
/// `false` here, and the positive control below forces both to be `true`, so
/// the pairing is exercised in each direction.
#[test]
fn detect_and_demangle_give_the_same_answer() {
    use rustre_demangle::{Demangler, SwiftDemangler};

    let d = SwiftDemangler;
    let mut checked = 0;
    for (sym, why) in DEGENERATE {
        assert_eq!(
            d.detect(sym),
            d.demangle(sym).is_some(),
            "detect and demangle disagree on {sym} ({why})"
        );
        assert!(
            !d.detect(sym),
            "{sym} ({why}) is not a symbol and must not be claimed"
        );
        checked += 1;
    }
    assert!(checked > 5, "vacuity guard: only {checked} inputs compared");

    // Positive control: a well-formed symbol, where both must answer `true`.
    // Without it the assertions above are satisfied by a `detect` that rejects
    // everything — which is exactly how the previous version went quiet.
    for sym in ["$s4main3fooyyF", "$s10Foundation4DataV5countSivg", "$sSS"] {
        assert!(d.detect(sym), "{sym} must be claimed");
        assert!(d.demangle(sym).is_some(), "{sym} must decode");
    }
}

/// Control: a well-formed Swift symbol still decodes, and the neighbouring
/// shapes that differ only in being *valid* are unaffected.
///
/// Without this, a fix that simply declined everything Swift would pass every
/// assertion above.
#[test]
fn well_formed_swift_symbols_still_decode() {
    for (sym, want) in [
        ("$s3foo", "foo"),
        ("$s4main3fooyyF", "main.foo() -> ()"),
        (
            "$s10Foundation4DataV5countSivg",
            "Foundation.Data.count.getter : Swift.Int",
        ),
        ("$sSS", "Swift.String"),
    ] {
        let got = rustre_demangle::demangle(sym)
            .unwrap_or_else(|| panic!("{sym} must still decode"))
            .demangled;
        assert_eq!(got, want, "{sym}");
    }

    // The Mach-O spelling of a valid symbol must survive the tightening too.
    assert!(rustre_demangle::demangle("_$s4main3fooyyF").is_some());
}

/// ASCII punctuation cannot occur inside a Swift identifier.
///
/// The parser took the length prefix at face value, so any bytes at all became
/// a name: `$s5Av.*2dY)j…` decoded to `Av.*2`, a fragment of random text
/// reported as a Swift identifier. Found by sweeping random printable ASCII —
/// 120 of 20000 such strings still decoded after the Go charset fix, and these
/// were among them.
///
/// **The rule is deliberately narrow, and the reason is worth keeping.** A
/// stricter "alphanumeric plus `_`" rule is what a 38-identifier sample of
/// known-good symbols suggests, and it agrees with the claim that Swift
/// punycodes everything else — but it rejects `$s3añ3fooyyF`, which
/// `tests/multibyte_length_prefixes.rs` pins as decoding. Both beliefs rest on
/// hand-built symbols; Swift has neither an oracle nor a corpus in this crate,
/// so there is no way to settle which is right. Only the certain half is
/// enforced.
#[test]
fn punctuation_cannot_appear_in_a_swift_identifier() {
    for sym in [
        "$s5Av.*2x",
        "$s5a(b)cx",
        "$s5a\"bcx",
        "$s4a,bcx",
        "$s4a;bcx",
        "$s4a=bcx",
    ] {
        assert!(
            rustre_demangle::demangle(sym).is_none(),
            "{sym} holds punctuation in its identifier and must decline"
        );
    }

    // Controls: plain and underscored identifiers still decode, and so does the
    // non-ASCII case this rule deliberately does not touch.
    for sym in ["$s5abcdex", "$s5ab_cdx", "$s3añ3fooyyF", "$s4main3fooyyF"] {
        assert!(
            rustre_demangle::demangle(sym).is_some(),
            "{sym} must still decode"
        );
    }
}
