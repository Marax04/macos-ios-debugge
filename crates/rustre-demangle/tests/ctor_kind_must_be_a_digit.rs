//! A constructor/destructor kind is a digit, and a non-digit must not wrap.
//!
//! Itanium spells constructors `C1`/`C2`/`C3` and destructors `D0`/`D1`/`D2`, so
//! `cpp_demangler` rendered the index with `kind - b'0'`. On a non-digit that
//! subtraction underflows:
//!
//! * with overflow checks on, it **panics** — `attempt to subtract with overflow`;
//! * in a release build it **wraps and fabricates an index**, which is worse:
//!   `_ZN1AC!Ev` rendered `A::ctor241` and `_ZN1AD!Ev` rendered `A::~dtor241`,
//!   from `b'!' - b'0'`.
//!
//! `cpp_demangler` is the crate's *healthy* alternative implementation — 813/813
//! against the live path on real Itanium symbols, 12 call sites — so this was
//! fabrication in the one module the CLAUDE.md holds up as correct. It only
//! appears on malformed input, which is why the corpora never showed it.
//!
//! Found by running the suite as a release build with `-C debug-assertions=on`
//! (`tests/debug_assertions_hold.sh`). The four ordinary gates cannot see this
//! class: they build release, where both the panic and the overflow check are
//! compiled out.

use rustre_demangle::cpp_demangler::demangle_cpp;

/// Malformed kinds must be rejected, not turned into a number.
#[test]
fn a_non_digit_ctor_kind_is_rejected() {
    let mut checked = 0;
    // A spread of non-digits: below `'0'` (which is what underflows), above `'9'`,
    // and a space.
    for bad in ['!', ' ', '#', '(', '-', '.', '/', 'x', 'Z', '~'] {
        for tag in ['C', 'D'] {
            let sym = format!("_ZN1A{tag}{bad}Ev");
            let got = demangle_cpp(&sym).ok();
            assert!(
                got.is_none(),
                "{sym}: {tag}{bad:?} is not a valid kind and must be rejected, got {got:?}"
            );
            checked += 1;
        }
    }
    assert!(checked == 20, "expected 20 malformed kinds, checked {checked}");
}

/// No rendering may carry a wrapped index.
///
/// The specific numbers the bug produced, asserted directly: a fix that rejected
/// *all* constructors would satisfy the test above, and this pins the shape of
/// what went wrong.
#[test]
fn no_rendering_contains_a_wrapped_index() {
    for sym in ["_ZN1AC!Ev", "_ZN1AD!Ev", "_ZN1AC Ev", "_ZN1AD Ev"] {
        if let Ok(d) = demangle_cpp(sym) {
            assert!(
                !d.contains("241") && !d.contains("240"),
                "{sym} rendered a wrapped index: {d}"
            );
        }
    }
}

/// Controls: valid kinds still decode, in both the sugared and numeric forms.
///
/// Without these the fix could be "reject every C/D name", which would break the
/// 813/813 agreement this module is documented for.
#[test]
fn valid_ctor_and_dtor_kinds_still_decode() {
    assert_eq!(demangle_cpp("_ZN1AC1Ev").ok().as_deref(), Some("A::A()"));
    assert_eq!(demangle_cpp("_ZN1AD1Ev").ok().as_deref(), Some("A::~A()"));

    // A digit that is not a defined kind still renders numerically — loose, but
    // it is a digit, so it is not the defect this file is about.
    assert_eq!(demangle_cpp("_ZN1AC9Ev").ok().as_deref(), Some("A::ctor9"));

    // And the live path, which is what consumers reach, is unaffected.
    assert_eq!(
        rustre_demangle::demangle("_ZN3FooC1Ev").map(|r| r.demangled).as_deref(),
        Some("Foo::Foo()")
    );
    assert_eq!(
        rustre_demangle::demangle("_ZN3FooD1Ev").map(|r| r.demangled).as_deref(),
        Some("Foo::~Foo()")
    );
}
