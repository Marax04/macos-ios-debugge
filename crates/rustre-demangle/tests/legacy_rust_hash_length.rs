//! Legacy Rust's trailing hash is not always 16 hex digits.
//!
//! `is_rust_legacy` demanded exactly `17h` + 16, which is what current rustc
//! emits and what every symbol in every corpus happens to carry — 135 of the
//! 137 real Rust symbols are v0, and both legacy ones use 16. So the corpora
//! could not see the rule was too tight.
//!
//! `rustc-demangle`, the oracle for this ABI, accepts a hash of any length.
//! Below 16 or above, the symbol was labelled `Itanium` *and* rendered with the
//! hash still attached — two wrong fields at once, and a leak of exactly the
//! token this crate strips everywhere else.
//!
//! Every symbol here is built by a generator that computes its own length
//! prefixes, and every expectation is the oracle's answer rather than one
//! written down by hand. Nine defects in this file's history came from
//! hand-counted prefixes.

use rustre_demangle::sigil::is_rust_legacy;
use rustre_demangle::ManglingAbi;

/// `_ZN` + length-prefixed components + `<n>h<hash>` + `E`.
fn legacy(path: &[&str], hash: &str) -> String {
    let mut s = String::from("_ZN");
    for p in path {
        s.push_str(&p.len().to_string());
        s.push_str(p);
    }
    s.push_str(&(hash.len() + 1).to_string());
    s.push('h');
    s.push_str(hash);
    s.push('E');
    s
}

fn oracle(s: &str) -> Option<String> {
    rustc_demangle::try_demangle(s).ok().map(|d| format!("{d:#}"))
}

/// The defect: ABI and rendering must both track the oracle at every hash
/// length, not just at 16.
#[test]
fn any_hash_length_decodes_as_rust_and_matches_the_oracle() {
    for n in [1usize, 2, 4, 8, 15, 16, 17, 20, 32, 40] {
        let hash = "a".repeat(n);
        let sym = legacy(&["core", "fmt", "write"], &hash);

        // The oracle arbitrates construction: if it rejects, the test is wrong.
        let want = oracle(&sym).unwrap_or_else(|| panic!("generator produced invalid {sym}"));
        let got = rustre_demangle::demangle(&sym)
            .unwrap_or_else(|| panic!("declined {sym} (hash length {n})"));

        assert_eq!(got.abi, ManglingAbi::Rust, "{sym} (hash length {n})");
        assert_eq!(got.demangled, want, "{sym} (hash length {n})");
        assert!(!got.demangled.contains(&hash), "hash leaked into output: {}", got.demangled);
    }
}

/// Discriminating in the other direction. Loosening a sigil test is the change
/// that historically invents defects, so the counter-cases this module already
/// documents must all still fail — a bare "ends in hex digits" would pass the
/// test above and break every one of these.
#[test]
fn loosening_did_not_let_cpp_in() {
    for s in [
        // Not hex: the discriminator that does the real work.
        "_ZN3foo17hello_there_worldE",
        "__ZN3foo17hello_there_worldE",
        // Ordinary Itanium.
        "_ZN3foo3barEv",
        "_ZNSt10bad_typeidD1Ev",
        "_ZN10__cxxabiv119__terminate_handlerE",
        "__ZN10__cxxabiv119__terminate_handlerE",
    ] {
        assert!(!is_rust_legacy(s), "{s} is C++, not legacy Rust");
    }
}

/// The length prefix is load-bearing: `h` followed by hex is not enough, the
/// component must be the size the mangling says it is. Without this the rule
/// would be a bare suffix test, and every case here would be claimed.
#[test]
fn the_length_prefix_must_agree_with_the_hash() {
    let good = legacy(&["core", "fmt", "write"], "0123456789abcdef");
    assert!(is_rust_legacy(&good));

    // Same hash, wrong prefix — 16 and 18 instead of the required 17.
    for wrong in ["16", "18", "9", "170"] {
        let bad = good.replace("17h0123456789abcdef", &format!("{wrong}h0123456789abcdef"));
        assert_ne!(bad, good, "replacement did not apply");
        assert!(!is_rust_legacy(&bad), "{bad} has a mismatched length prefix");
    }
    // No prefix at all.
    assert!(!is_rust_legacy("_ZN4core3fmt5writeh0123456789abcdefE"));
}

/// The whole corpus must be unmoved: every real Rust symbol still decodes as
/// Rust, and no real Itanium symbol was captured. This is the measurement that
/// justified the loosening rather than an assumption that it was safe.
#[test]
fn no_real_corpus_symbol_changed_hands() {
    let real = include_str!("data/real_symbols.txt");
    let pdb = include_str!("data/pdb_symbols.txt");
    let mut itanium = 0;
    let mut rust = 0;
    for s in real.lines().chain(pdb.lines()).map(str::trim).filter(|s| !s.is_empty()) {
        let Some(r) = rustre_demangle::demangle(s) else { continue };
        match r.abi {
            ManglingAbi::Itanium => {
                itanium += 1;
                assert!(!is_rust_legacy(s), "{s} was reclassified as Rust");
            }
            ManglingAbi::Rust => rust += 1,
            _ => {}
        }
    }
    assert!(itanium > 700, "vacuous: only {itanium} Itanium symbols checked");
    assert!(rust > 100, "vacuous: only {rust} Rust symbols checked");
}
