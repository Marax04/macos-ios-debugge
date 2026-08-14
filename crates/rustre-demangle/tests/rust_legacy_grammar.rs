//! Legacy Rust (`_ZN…17h<hash>E`): the escape table and, more importantly, the
//! ROUTING.
//!
//! `differential_rust_grammar.rs` covers v0. Legacy is a different ABI and had
//! no grammar-derived coverage — but most of it is delegation: the live path
//! hands legacy symbols to `rustc_demangle` and formats with `{:#}` to drop the
//! hash. Comparing that against `rustc_demangle` is close to a tautology, the
//! trap this crate already records for `cpp_demangler`'s "813/813".
//!
//! What is **not** delegated, and is the reason this file exists:
//!
//! * **Routing.** A legacy Rust symbol is also a well-formed Itanium mangling,
//!   so both backends can decode it and the choice is entirely this crate's.
//!   `_ZN3foo17hello_there_worldE` is C++ (a component that merely begins with
//!   `17h`), while `_ZN3foo17h0123456789abcdefE` is Rust. Nothing but this
//!   crate decides that.
//! * **Hash stripping**, which is a presentation choice made here.
//!
//! The escape comparison is kept anyway, as a guard rather than a measurement:
//! if the delegation is ever replaced by a hand-written parser, these 17
//! entries are what will catch it.
//!
//! **Prefixes are COMPUTED, never hand-counted.** Miscounting a length prefix
//! has produced more false findings in this crate than any other mistake — it
//! cost two entries in the first run of this very probe. A generator cannot
//! miscount.
//!
//! Measured 2026-07-30: 17/17 escapes and the trait-impl path agree, routing is
//! correct in both directions. No defect.

/// Build a legacy Rust symbol from path components, computing every prefix.
fn legacy(parts: &[&str]) -> String {
    let mut s = String::from("_ZN");
    for p in parts {
        s.push_str(&p.len().to_string());
        s.push_str(p);
    }
    s.push_str("17h0123456789abcdef");
    s.push('E');
    s
}

fn ours(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

fn oracle(sym: &str) -> Option<String> {
    rustc_demangle::try_demangle(sym)
        .ok()
        .map(|d| format!("{d:#}"))
}

/// Every documented `$…$` escape decodes as `rustc-demangle` decodes it.
#[test]
fn every_escape_agrees_with_the_oracle() {
    const ESCAPES: &[(&str, char)] = &[
        ("$SP$", '@'),
        ("$BP$", '*'),
        ("$RF$", '&'),
        ("$LT$", '<'),
        ("$GT$", '>'),
        ("$LP$", '('),
        ("$RP$", ')'),
        ("$C$", ','),
        ("$u20$", ' '),
        ("$u27$", '\''),
        ("$u5b$", '['),
        ("$u5d$", ']'),
        ("$u7b$", '{'),
        ("$u7d$", '}'),
        ("$u3b$", ';'),
        ("$u2b$", '+'),
        ("$u21$", '!'),
    ];

    let mut checked = 0;
    let mut wrong = Vec::new();
    for (esc, ch) in ESCAPES {
        let sym = legacy(&["test", &format!("a{esc}b")]);
        let (got, want) = (ours(&sym), oracle(&sym));
        assert!(want.is_some(), "the oracle rejects {sym} — the generator is wrong");
        checked += 1;
        if got != want {
            wrong.push(format!("{esc} ({ch}): ours {got:?}, oracle {want:?}"));
        }
        // And the decoded character must actually appear.
        if let Some(g) = &got {
            assert!(g.contains(*ch), "{esc} did not produce {ch}: {g}");
        }
    }
    assert_eq!(checked, 17, "the escape list changed — update the vectors");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A trait-impl path exercises `..` (the path separator, not an escape)
/// together with the bracket and space escapes.
#[test]
fn a_trait_impl_path_agrees_with_the_oracle() {
    let sym = legacy(&[
        "_$LT$core..option..Option$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$",
        "fmt",
    ]);
    assert_eq!(
        ours(&sym).as_deref(),
        Some("<core::option::Option<T> as core::fmt::Debug>::fmt")
    );
    assert_eq!(ours(&sym), oracle(&sym));
}

/// The routing, which is this crate's own decision and not the oracle's.
///
/// Discriminating: `_ZN3foo3barE` is plainly C++ and `_ZN…$LT$…17h…E` is plainly
/// Rust; neither separates a correct rule from a loose one. The pair that does
/// is `17hello_there_world` versus `17h0123456789abcdef` — same shape, same
/// leading `17h`, and only the hex-digit test tells them apart.
#[test]
fn legacy_rust_routes_to_rust_and_c_plus_plus_does_not() {
    for (sym, want_abi) in [
        (legacy(&["core", "ptr", "drop_in_place"]), "Rust"),
        (legacy(&["test", "a$LT$b"]), "Rust"),
        ("_ZN3foo3barE".to_owned(), "Itanium"),
        ("_ZN3foo17hello_there_worldE".to_owned(), "Itanium"),
    ] {
        let r = rustre_demangle::demangle(&sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert_eq!(format!("{:?}", r.abi), want_abi, "{sym} routed to the wrong ABI");
    }
}

/// The hash is stripped, and stripping it does not merge distinct paths.
///
/// The crate's standard for dropping a disambiguator, from
/// `delegated_postprocessing.rs`: strip only after verifying it costs nothing.
#[test]
fn the_hash_is_stripped_without_merging_distinct_paths() {
    let a = legacy(&["mycrate", "foo"]);
    let b = legacy(&["mycrate", "bar"]);
    assert_eq!(ours(&a).as_deref(), Some("mycrate::foo"));
    assert!(
        !ours(&a).unwrap().contains("17h"),
        "the hash must not reach the output"
    );
    assert_ne!(ours(&a), ours(&b));
}
