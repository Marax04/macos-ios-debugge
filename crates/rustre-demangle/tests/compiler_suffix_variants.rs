//! A compiler suffix must not change which ABI a symbol belongs to.
//!
//! LLVM and GCC append suffixes to optimised symbols: `.llvm.<hash>` from
//! `ThinLTO`, `.cold`, `.part.N`, `.constprop.N`. On an optimised Rust binary
//! these are everywhere.
//!
//! `sigil::is_rust_legacy` required the symbol to END with `E`, so every
//! suffixed legacy symbol failed the test and fell through to the Itanium
//! backend. Two things went wrong at once, and the second is visible in the
//! output:
//!
//! ```text
//! _ZN4core3fmt5write17h…E.cold
//!   was   core::fmt::write::h0123456789abcdef [clone .cold]   (abi Itanium)
//!   want  core::fmt::write.cold                               (abi Rust)
//! ```
//!
//! The ABI label was wrong — the iter-125 defect again, one variant over — and
//! **the hash leaked into the rendering**, the disambiguator this crate strips
//! everywhere else. Rust v0 was unaffected: its sigil never had the
//! end-anchored test, so `_R…​.cold` stayed Rust throughout. That asymmetry
//! between two manglings of one ABI is what the per-variant sweep exists to
//! find.
//!
//! `rustc-demangle` is the oracle for every assertion here, including the
//! detail that `.llvm.<hash>` is *dropped* while `.cold` is *kept*.

fn ours(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

fn abi_of(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| format!("{:?}", r.abi))
}

fn oracle(sym: &str) -> Option<String> {
    rustc_demangle::try_demangle(sym)
        .ok()
        .map(|d| format!("{d:#}"))
}

/// Build a legacy Rust symbol with computed length prefixes.
fn legacy(parts: &[&str]) -> String {
    let body = parts.iter().fold(String::new(), |mut acc, p| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{}{p}", p.len());
        acc
    });
    format!("_ZN{body}17h0123456789abcdefE")
}

const SUFFIXES: &[&str] = &[
    "",
    ".llvm.1234567890",
    ".cold",
    ".part.0",
    ".constprop.0",
    ".cold.1",
    ".llvm.9876543210123456789",
];

/// Every suffixed legacy Rust symbol agrees with the oracle.
#[test]
fn suffixed_legacy_rust_agrees_with_the_oracle() {
    let base = legacy(&["core", "fmt", "write"]);
    let mut checked = 0;
    let mut wrong = Vec::new();
    for sfx in SUFFIXES {
        let sym = format!("{base}{sfx}");
        let want = oracle(&sym).unwrap_or_else(|| panic!("{sym}: the oracle rejects it"));
        checked += 1;
        match ours(&sym) {
            Some(got) if got == want => {}
            other => wrong.push(format!("{sym}\n  oracle: {want}\n  ours:   {other:?}")),
        }
    }
    assert_eq!(checked, 7);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The suffix changes neither the ABI label nor the hash-stripping.
///
/// Discriminating: the unsuffixed symbol passed before this fix — it is the
/// case everything already tested. `.cold` is what separates a sigil that
/// tolerates a compiler suffix from one anchored to the closing `E`.
#[test]
fn a_suffix_changes_neither_abi_nor_hash_stripping() {
    let base = legacy(&["core", "fmt", "write"]);
    for sfx in SUFFIXES {
        let sym = format!("{base}{sfx}");
        assert_eq!(abi_of(&sym).as_deref(), Some("Rust"), "{sym}");
        let out = ours(&sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(
            !out.contains("17h") && !out.contains("h0123456789abcdef"),
            "the hash leaked through the suffix path: {out}"
        );
        assert!(
            !out.contains("[clone"),
            "the Itanium clone rendering leaked into a Rust symbol: {out}"
        );
    }
}

/// Rust v0 carries the same suffixes and was never affected — pinned so the two
/// manglings cannot drift apart again.
#[test]
fn v0_and_legacy_treat_suffixes_alike() {
    for sfx in SUFFIXES {
        let v0 = format!("_RNvNtC4core3fmt5write{sfx}");
        let leg = format!("{}{sfx}", legacy(&["core", "fmt", "write"]));
        assert_eq!(abi_of(&v0).as_deref(), Some("Rust"), "{v0}");
        assert_eq!(
            ours(&v0),
            ours(&leg),
            "the two Rust manglings of one path render differently under {sfx:?}"
        );
    }
}

/// Admitting a suffix must not admit C++.
///
/// The `17h<16 hex>` test still does the discriminating; these all keep a
/// trailing suffix and none is Rust — including the one whose last component
/// merely begins with `17h`.
#[test]
fn suffixed_c_plus_plus_stays_itanium() {
    for sym in [
        "_ZN2ns4funcEv.cold",
        "_ZN3foo3barE.cold",
        "_ZN3foo3barE.llvm.123",
        "_ZNSt6vectorIiE9push_backERKi.part.0",
        "_ZN3foo17hello_there_worldE.cold",
    ] {
        assert_eq!(abi_of(sym).as_deref(), Some("Itanium"), "{sym}");
    }
}
