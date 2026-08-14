//! `cpp_demangler::demangle_itanium` must not return `Ok` for a name it could
//! not read.
//!
//! The entry point tries the `cpp_demangle` oracle first and falls back to the
//! crate's hand-written `ItaniumParser`. That parser slices source names by the
//! mangled length prefix and, when the slice is not valid UTF-8, substitutes
//! the literal `<invalid>`. The substitution was reaching callers inside an
//! `Ok`: `_Z2añ` returned `Ok("<invalid>(?±)")` — a fabrication reported as a
//! success, in a public entry point with roughly a dozen call sites across the
//! workspace.
//!
//! Reaching it requires a **non-ASCII identifier**, because the input is
//! already valid UTF-8 as a `&str`; only a length prefix that ends *between*
//! the bytes of a multi-byte character can produce an unreadable slice. `ñ` is
//! two bytes (C3 B1), so `_Z2añ` declares a two-byte name over `a` plus the
//! first half of `ñ`. Neither corpus contains such a symbol, and the ASCII
//! cases that dominate every existing Itanium test cannot exercise this.
//!
//! `crate::demangle` already declined every one of these, so this also removes
//! a divergence between the crate's two public Itanium entry points — the
//! recurring defect shape here, where two copies of one job disagree.

use rustre_demangle::cpp_demangler::demangle_itanium;

/// Length prefixes that cut through the bytes of `ñ`.
const SPLIT_MULTIBYTE: &[&str] = &["_Z2añ", "_Z2añE", "_Z1ñ"];

#[test]
fn a_name_that_is_not_valid_utf8_is_an_error_not_a_decode() {
    let mut checked = 0;
    for sym in SPLIT_MULTIBYTE {
        let got = demangle_itanium(sym);
        assert!(
            got.is_err(),
            "{sym} must not decode, but returned {got:?}"
        );
        checked += 1;
    }
    assert!(checked > 2, "vacuous: only {checked} inputs checked");
}

/// Both public Itanium entry points must agree on these.
///
/// `crate::demangle` declined them all along; only the alternate path
/// fabricated. Comparing the two is what makes this a regression guard rather
/// than a restatement of the fix.
#[test]
fn both_itanium_entry_points_agree_on_unreadable_names() {
    for sym in SPLIT_MULTIBYTE {
        assert!(
            rustre_demangle::demangle(sym).is_none(),
            "live path unexpectedly decoded {sym}"
        );
        assert!(
            demangle_itanium(sym).is_err(),
            "alternate path still decodes {sym}"
        );
    }
}

/// Control: a multi-byte identifier whose length prefix is *correct* must still
/// decode.
///
/// `añb` is four bytes (`a`, two for `ñ`, `b`), so `_Z4añbc` is well-formed and
/// means `añb(char)`. This is the case a careless fix would break — declining
/// every non-ASCII name would satisfy the assertions above while destroying
/// legitimate decodes, which is exactly the trade this crate has been burned by
/// before.
#[test]
fn a_correctly_measured_multibyte_name_still_decodes() {
    assert_eq!(
        demangle_itanium("_Z4añbc").expect("well-formed multi-byte name must decode"),
        "añb(char)"
    );

    // Plain ASCII is untouched.
    assert_eq!(demangle_itanium("_Z3fooi").expect("ascii must decode"), "foo(int)");
}

/// **Known remaining case, deliberately not covered by the fix.**
///
/// `_Z3fooñ` still renders `foo(?Ã, ?±)`: the name decodes, but the trailing
/// raw bytes become fabricated parameter types spelled `?<byte>`. Declining on
/// any `?` would be the obvious generalisation and is wrong — `?` occurs in
/// legitimate Itanium output, `operator?:` being the plain example — so the
/// narrow, certain rule was taken instead of a broad, unvalidated one.
///
/// Recorded as a passing test of *current* behaviour rather than an ignored
/// test of desired behaviour, because unlike the `<invalid>` case the correct
/// rendering here is not settled: the input is malformed, and whether the right
/// answer is a decline or a partial decode needs a rule about trailing garbage
/// that nothing in the crate currently defines.
///
/// **Iter 88 found a second, DIFFERENT case that this reasoning does not cover,
/// and tried the broad rule anyway.** `_Z1fUt_` is an unnamed type — a recognised
/// grammar construct, not trailing garbage. `cpp_demangle` rejects it, so it lands
/// in the fallback, which renders `f(?U, unsigned short, unsigned short)`: two
/// placeholders, a fabricated `unsigned short` read out of the `t` in `Ut_`, and
/// **three parameters invented from one type**. The live path declines it.
///
/// Declining on any `?` other than `?:` fixes that and breaks this test, because
/// it conflates the two cases:
///
/// * `_Z1fUt_` — a construct inside a well-formed grammar is mis-parsed. The
///   recovered output is worthless, so declining loses nothing.
/// * `_Z3fooñ` — the name `foo` IS recovered; only bytes past the end are junk.
///   Declining throws away a correct name.
///
/// Separating them needs exactly the trailing-garbage rule this note says is
/// undefined: "did the parser consume the whole symbol?". The crate has that
/// concept for other ABIs (`tests/trailing_input.rs`) but not here. Until it does,
/// the narrow `<invalid>`-only rule stands, and the `Ut_` fabrication is a known
/// gap rather than a fixed one.
#[test]
fn trailing_raw_bytes_still_render_as_placeholder_parameters() {
    let got = demangle_itanium("_Z3fooñ").expect("currently decodes");
    assert!(got.starts_with("foo("), "name still decodes: {got}");
    assert!(
        got.contains('?'),
        "documents that placeholder parameters remain: {got}"
    );
    // The live path, by contrast, declines it outright.
    assert!(rustre_demangle::demangle("_Z3fooñ").is_none());
}
