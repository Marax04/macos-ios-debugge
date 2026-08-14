//! `Demangler2` must not be weaker than `demangle` on the ABIs it claims.
//!
//! This is a live path, not a curiosity: `batch_demangle` and
//! `batch_demangle_parallel` are exported and driven by two wire tools in
//! `rustre-mcp-tools`, and `classify.rs` routes through `Demangler2` internally.
//! Every divergence is a real consumer getting a worse answer than
//! `demangle` gives.
//!
//! Measured over the two real corpora, the divergence was **2199 symbols**.
//! Of those, 36 were fixable here and are fixed:
//!
//! * **34 linker indirection wrappers.** `.refptr._ZN…` and `__imp__ZN…` wrap a
//!   real mangled symbol; the live path unwraps, decodes and re-prefixes, while
//!   this dispatcher tested `starts_with("_Z")` and echoed them back under
//!   `Unknown`.
//! * **2 legacy Rust.** `_ZN…17h<hex>E` is Itanium-shaped, so the Itanium arm
//!   claimed it and got **both** fields wrong — `CppItanium` instead of `Rust`,
//!   and the disambiguator hash left in the output. Exactly the pair iter 155
//!   fixed on the live path, still here because this dispatcher never consulted
//!   `sigil`, the module that exists so every claiming site shares one rule.
//!
//! The remaining **2163 are all Go**, and closing them is not a bug fix: the
//! `MangleLanguage` enum has no `Go` variant, so it needs a public-API decision
//! rather than wiring. That is why this file asserts parity *per ABI* instead of
//! globally — a global assertion would be permanently red and tell nobody which
//! part is a defect.

use rustre_demangle::{Demangler2, ManglingAbi};

const CORPORA: [&str; 2] = [
    include_str!("data/real_symbols.txt"),
    include_str!("data/pdb_symbols.txt"),
];

/// What `Demangler2` produced, or `None` when it echoed the input back.
fn dispatcher(sym: &str) -> Option<String> {
    let r = Demangler2::demangle(sym);
    (r.demangled != sym).then_some(r.demangled)
}

fn symbols() -> impl Iterator<Item = &'static str> {
    CORPORA.iter().flat_map(|b| b.lines()).map(str::trim).filter(|s| !s.is_empty())
}

/// Parity on every ABI except Go.
#[test]
fn the_dispatcher_matches_the_live_path_outside_go() {
    let mut checked = 0;
    let mut diverged = Vec::new();

    for sym in symbols() {
        let Some(live) = rustre_demangle::demangle(sym) else { continue };
        if live.abi == ManglingAbi::Go {
            continue;
        }
        checked += 1;
        let got = dispatcher(sym);
        if got.as_deref() != Some(live.demangled.as_str()) {
            diverged.push(format!("{sym}\n  live: {}\n  d2:   {got:?}", live.demangled));
        }
    }

    assert!(checked > 800, "vacuous: only {checked} non-Go symbols");
    assert!(
        diverged.is_empty(),
        "{} of {checked} diverge:\n{:#?}",
        diverged.len(),
        &diverged[..diverged.len().min(8)]
    );
}

/// The two shapes that were wrong, spelled out so a regression names the cause.
#[test]
fn the_two_repaired_shapes_stay_repaired() {
    // Legacy Rust: hash stripped, language Rust — not CppItanium.
    let r = Demangler2::demangle("_ZN19sample3_struct_loop4main17h051ebe1ecfcb2bb2E");
    assert_eq!(r.demangled, "sample3_struct_loop::main");
    assert!(!r.demangled.contains("h051ebe"), "hash leaked: {}", r.demangled);
    assert_eq!(format!("{:?}", r.language), "Rust");

    // Linker wrappers: decoded, and the prefix survives so `.refptr.f` never
    // reads as `f`.
    for (sym, want) in [
        (".refptr._ZN10__cxxabiv119__terminate_handlerE", ".refptr.__cxxabiv1::__terminate_handler"),
        ("__imp__ZNSt10bad_typeidD1Ev", "__imp_std::bad_typeid::~bad_typeid()"),
    ] {
        assert_eq!(Demangler2::demangle(sym).demangled, want, "{sym}");
    }
}

/// The legacy-Rust arm must sit BEFORE the Itanium one, and must not swallow
/// ordinary C++. This is the direction that historically invents defects.
#[test]
fn plain_itanium_is_not_claimed_as_rust() {
    for sym in [
        "_ZN3foo3barEv",
        "_ZNSt10bad_typeidD1Ev",
        "_ZN10__cxxabiv119__terminate_handlerE",
        // Not a hash: the discriminating case from `sigil.rs`.
        "_ZN3foo17hello_there_worldE",
    ] {
        let r = Demangler2::demangle(sym);
        assert_ne!(format!("{:?}", r.language), "Rust", "{sym} claimed as Rust");
    }
}

/// Go is the whole remaining divergence, and it is an API decision rather than
/// a defect. Pinned so the claim stays true — if `MangleLanguage` ever gains a
/// `Go` variant and the arm is wired, this fails and the exclusion above can go.
#[test]
fn go_is_the_only_remaining_divergence() {
    let mut go_diverging = 0;
    for sym in symbols() {
        let Some(live) = rustre_demangle::demangle(sym) else { continue };
        if live.abi != ManglingAbi::Go {
            continue;
        }
        if dispatcher(sym).as_deref() != Some(live.demangled.as_str()) {
            go_diverging += 1;
        }
    }
    assert!(
        go_diverging > 2000,
        "Go divergence shrank to {go_diverging}; if Demangler2 gained a Go arm, \
         update this file and the module note"
    );
}
