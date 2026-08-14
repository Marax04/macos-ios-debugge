//! Which ABIs reject trailing input, and why the answer differs per ABI.
//!
//! `tests/trailing_input.rs` established the rule for D: a symbol with bytes
//! left over is not the symbol it appears to be, and absorbing them collapses
//! two distinct linker symbols into one rendering. The obvious next move is to
//! apply that rule everywhere. This file exists because that would be **wrong**,
//! and the reasons are measured rather than argued.
//!
//! * **Itanium** rejects trailing input. It is the reference case.
//! * **D** now rejects it too (this session's fix).
//! * **MSVC rejects it, on both its function and its data forms.** The oracle
//!   absorbs trailing input *everywhere* — on `?foo@@YAHXZGARBAGE` as much as on
//!   `??_7Foo@@6B@GARBAGE` — so "agree with the oracle" was never this crate's
//!   position here: it already declined the first while accepting the second.
//!   That split was an accident of which parser checked for leftovers, not a
//!   decision, and it left 6 of the 14 real MSVC symbols collapsing distinct
//!   linker symbols into one rendering. Made uniform; see
//!   `tests/trailing_input.rs::msvc_rejects_trailing_input` for the measurement
//!   that it costs no coverage.
//! * **Swift is exempt for a different reason**: its parser reaches the end of
//!   only 9 of 16 realistic symbols, so requiring full consumption would
//!   decline 7 legitimate ones. See `tests/trailing_input.rs`.
//! * **Go and the convention detectors are not length-prefixed grammars.**
//!   `main.mainGARBAGE` is not `main.main` with junk attached, it is a
//!   different name, and it must decode to a different string. "Rejecting
//!   trailing input" is not even meaningful there.
//!
//! Without this file, the inconsistency looks like an oversight and invites a
//! later change that breaks agreement with the MSVC oracle.

fn dm(s: &str) -> Option<String> {
    rustre_demangle::demangle(s).map(|r| r.demangled)
}

fn oracle(s: &str) -> Option<String> {
    msvc_demangler::demangle(s, msvc_demangler::DemangleFlags::llvm()).ok()
}

/// Itanium is strict, and that is what made D's and Swift's laxity visible.
#[test]
fn itanium_rejects_trailing_input() {
    assert_eq!(
        dm("_ZN3foo3barEi").as_deref(),
        Some("foo::bar(int)")
    );
    for junk in ["GARBAGE", "!!!", "99"] {
        assert!(
            dm(&format!("_ZN3foo3barEi{junk}")).is_none(),
            "Itanium must reject trailing {junk}"
        );
    }
}

/// MSVC agrees with the oracle on clean symbols and is stricter on junk — the
/// same position as the ordinary-symbol test below, now applied to the special
/// data forms too.
///
/// This test previously asserted the opposite, that absorbing trailing input on
/// the special forms was correct *because* the oracle absorbs it. The reason
/// that could not stand is in the very next test: the crate already declined
/// trailing input on ordinary MSVC symbols, where the oracle also absorbs, and
/// pinned that as intended. One ABI cannot be governed by "match the oracle" in
/// one parser and "two symbols must not collapse" in another; the difference
/// was which parser happened to check for leftovers.
#[test]
fn msvc_is_stricter_than_the_oracle_on_special_form_junk() {
    let mut checked = 0;
    for base in ["??_7Foo@@6B@", "??_R0?AVFoo@@@8"] {
        // Clean: must still agree with the oracle exactly.
        assert_eq!(dm(base), oracle(base), "clean symbols must still agree: {base}");
        checked += 1;

        for junk in ["GARBAGE", "!!!"] {
            let sym = format!("{base}{junk}");
            assert!(dm(&sym).is_none(), "we decline trailing input here: {sym}");
            assert!(
                oracle(&sym).is_some(),
                "…while the oracle absorbs it — the point of this test"
            );
            checked += 1;
        }
    }
    assert!(checked > 5, "vacuous: only {checked} compared");
}

/// Where the crate is *stricter* than the MSVC oracle, that is recorded too.
///
/// On ordinary function symbols we decline trailing input and the oracle does
/// not. By the argument that motivated the D fix — two distinct symbols must
/// not collapse into one rendering — the stricter answer is the better one, so
/// this is pinned as intended behaviour rather than filed as a divergence to
/// repair. It is stated explicitly because "we disagree with the oracle" is
/// otherwise indistinguishable from a bug.
#[test]
fn the_crate_is_stricter_than_the_oracle_on_ordinary_msvc_symbols() {
    for base in ["?foo@@YAHXZ", "??0Foo@@QAE@XZ"] {
        assert!(dm(base).is_some(), "{base} must decode");
        assert_eq!(dm(base), oracle(base), "clean symbols must still agree");

        let polluted = format!("{base}GARBAGE");
        assert!(
            dm(&polluted).is_none(),
            "we decline trailing input here: {polluted}"
        );
        assert!(
            oracle(&polluted).is_some(),
            "…while the oracle absorbs it — the point of this test"
        );
    }
}

/// For schemes that are not length-prefixed, junk makes a *different name*.
///
/// The correct behaviour is a different decoding, not a refusal. Asserting this
/// keeps the D rule from being generalised into places where it has no meaning.
#[test]
fn unterminated_schemes_decode_junk_as_part_of_the_name() {
    for base in [
        "main.main",
        "Java_com_example_Foo_bar",
        "camlStdlib__Printf__printf_42",
        "__physics_MOD_get_value",
    ] {
        let clean = dm(base).unwrap_or_else(|| panic!("{base} must decode"));
        let polluted = dm(&format!("{base}GARBAGE"));
        assert_ne!(
            polluted.as_deref(),
            Some(clean.as_str()),
            "{base}: appending text must change the decoding, not be swallowed"
        );
    }
}
