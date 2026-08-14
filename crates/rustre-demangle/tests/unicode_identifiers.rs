//! Non-ASCII identifiers must survive demangling.
//!
//! Rust v0 encodes them in punycode (RFC 2603: `u` before the length), so a
//! Georgian or Tibetan identifier round-trips through pure ASCII in the symbol
//! and must come back out intact. Both corpora are entirely ASCII, so no
//! corpus invariant exercises this.
//!
//! The live path is correct here **because it delegates to `rustc-demangle`**.
//! That is worth pinning: the crate also carries a hand-written v0 parser
//! (`rust_demangler.rs`) which is correct on 0 of 135 real v0 symbols, and a
//! future change routing the live path through it would silently lose Unicode
//! along with everything else. Each case is checked against the oracle rather
//! than against a hard-coded string, so the test cannot drift from the
//! reference.

fn oracle(s: &str) -> Option<String> {
    rustc_demangle::try_demangle(s)
        .ok()
        .map(|d| format!("{d:#}"))
}

/// Punycode-encoded identifiers decode to the original script.
#[test]
fn punycode_identifiers_match_the_oracle() {
    let cases = [
        // Georgian, from rustc-demangle's own utf8_idents fixture.
        "_RNqCs4fqI2P2rA04_11utf8_identsu30____7hkackfecea1cbdathfdh9hlq6y",
        // Tibetan numerals in a module path.
        "_RNvNtCs1234_7mycrateu6_bcdefg3foo",
        // Short punycode payload.
        "_RNvC1cu4_abcd",
    ];

    for s in cases {
        let want = oracle(s).unwrap_or_else(|| {
            panic!("{s} should decode via rustc-demangle — fixture is wrong")
        });
        let got = rustre_demangle::demangle(s)
            .unwrap_or_else(|| panic!("{s} must decode; oracle gives {want}"))
            .demangled;
        assert_eq!(got, want, "{s}");
    }
}

/// At least one case must carry genuinely non-ASCII output, or the suite would
/// pass while only exercising the ASCII path.
#[test]
fn the_fixtures_actually_contain_non_ascii() {
    let s = "_RNqCs4fqI2P2rA04_11utf8_identsu30____7hkackfecea1cbdathfdh9hlq6y";
    let out = rustre_demangle::demangle(s).expect("must decode").demangled;
    assert!(
        !out.is_ascii(),
        "expected non-ASCII output, got {out}"
    );
}
