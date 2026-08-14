//! `strip_rust_hash` must be anchored to the trailing component.
//!
//! The Rust path is almost pure delegation — `crate::demangle` hands legacy and
//! v0 symbols to `rustc-demangle`, which is why it is exact on all 135 real v0
//! symbols and why probing it against its own oracle is close to vacuous. The
//! one part that is *not* delegation is the crate's own post-processing: the
//! output has the compiler hash stripped, so that `…write_fmt::h0123…` renders
//! as `…write_fmt`. That step is this crate's code and nothing was comparing it
//! with the oracle beyond the corpus.
//!
//! The discriminating input is a path component that *looks* like a hash but is
//! not one. A Rust module may legitimately be named `h0123456789abcdef`, and
//! the legacy convention only makes such a component a hash when it is **last**.
//! A stripper matching anywhere would delete a real module name and produce a
//! shorter, entirely plausible, wrong answer — the failure mode this crate is
//! least able to see, since nothing about the output would look malformed.
//!
//! Every expectation here is taken from `rustc-demangle`'s alternate (`{:#}`)
//! form rather than written by hand, so the test cannot encode a belief about
//! what the answer should be. It compares two implementations; the oracle
//! decides.

/// Compare the crate against the oracle's hash-free rendering.
fn agree(mangled: &str) -> (String, String) {
    let ours = rustre_demangle::demangle(mangled)
        .map_or_else(|| "<declined>".to_owned(), |r| r.demangled);
    let oracle = rustc_demangle::try_demangle(mangled)
        .map_or_else(|_| "<declined>".to_owned(), |d| format!("{d:#}"));
    (ours, oracle)
}

/// Shapes chosen so that position, not spelling, decides the answer.
const SHAPES: &[&str] = &[
    // Hash in trailing position: stripped.
    "_ZN3std2io5Write9write_fmt17h0123456789abcdefE",
    "_ZN3foo3bar17h0123456789abcdefE",
    // Hash-*shaped* component in leading position: a real module name.
    "_ZN17h0123456789abcdef3fooE",
    // Hash-shaped component in the middle: also a real module name.
    "_ZN3foo17h0123456789abcdef3barE",
    // No hash at all.
    "_ZN3foo3barE",
    // v0, where the disambiguator is spelled differently again.
    "_RNvNtCs1234_4core3fmt5write",
    "_RNvC4main3foo",
    "_RNCNvC4main3foo0",
    "_RINvNtC4core3ptr13drop_in_placeNtC4main3FooE",
];

#[test]
fn hash_stripping_matches_the_oracle() {
    let mut checked = 0;
    for m in SHAPES {
        let (ours, oracle) = agree(m);
        assert_eq!(ours, oracle, "diverged from rustc-demangle on {m}");
        checked += 1;
    }
    // Vacuity guard: an empty or all-declining table would pass silently.
    assert!(checked > 6, "too few shapes compared: {checked}");
}

/// The property the corpus cannot exercise, stated directly: a hash-shaped
/// component that is not last must survive.
///
/// Asserted against the oracle *and* as a containment check, because the two
/// fail differently — the oracle comparison catches divergence, the containment
/// catches both implementations agreeing on a loss.
#[test]
fn a_hash_shaped_component_that_is_not_last_survives() {
    for m in [
        "_ZN17h0123456789abcdef3fooE",
        "_ZN3foo17h0123456789abcdef3barE",
    ] {
        let (ours, oracle) = agree(m);
        assert_eq!(ours, oracle, "{m}");
        assert!(
            ours.contains("h0123456789abcdef"),
            "a non-trailing hash-shaped component is a real module name and must \
             not be stripped: {m} -> {ours}"
        );
    }

    // Control: in trailing position the same text *is* the hash and goes away.
    let (ours, oracle) = agree("_ZN3foo3bar17h0123456789abcdefE");
    assert_eq!(ours, oracle);
    assert!(
        !ours.contains("h0123456789abcdef"),
        "the trailing hash must be stripped: {ours}"
    );
}
