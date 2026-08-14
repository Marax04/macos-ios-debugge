//! `demangler_dispatcher::auto_demangle` must not be weaker than `demangle`.
//!
//! A live path with consumers in three other crates: a wire tool in
//! `rustre-mcp-tools`, a measurement harness in `rustre-flirt-apply`, and
//! production code in `rustre-symbols-pdb`. Every divergence is a real consumer
//! getting a worse answer, and the fixes below reach them without touching
//! their crates.
//!
//! Measured over both real corpora, the divergence was **255 symbols** in three
//! classes, all of them defects this crate has a documented name for:
//!
//! * **136 Rust v0 kept the crate disambiguator** —
//!   `core[d2e35dc664ad455]::panicking::assert_failed`. The cause was
//!   `sym.to_string()` where the live path uses `{:#}`; the plain `Display` of
//!   `rustc-demangle` retains it. One character, and the same defect class as
//!   the legacy-Rust hash leak in `dispatch.rs`: a disambiguator reaching the
//!   output because a second dispatcher formatted the oracle's result its own
//!   way.
//! * **119 linker indirection wrappers** (`.refptr._ZN…`, `__imp__ZN…`) echoed
//!   back undecoded, because scheme detection looks at the leading bytes.
//! * **85 ordinary Itanium symbols routed to Rust.** `detect_scheme` used
//!   `starts_with("_ZN") && (contains("17h") || ends_with('E'))`, and the
//!   `ends_with('E')` half claims every `_ZN…E` symbol. They went to
//!   `rustc-demangle`, which rejects them, so they came back undecoded.
//!   Recurring defects #0 and #1 in one line — a classifier looser than its
//!   backend, at a site that never consulted `sigil`.
//!
//! Now **0**.

use rustre_demangle::demangler_dispatcher::auto_demangle;

const CORPORA: [&str; 2] = [
    include_str!("data/real_symbols.txt"),
    include_str!("data/pdb_symbols.txt"),
];

fn symbols() -> impl Iterator<Item = &'static str> {
    CORPORA.iter().flat_map(|b| b.lines()).map(str::trim).filter(|s| !s.is_empty())
}

/// Full parity on every symbol the live path decodes.
#[test]
fn the_dispatcher_matches_the_live_path() {
    let mut checked = 0;
    let mut diverged = Vec::new();

    for sym in symbols() {
        let Some(live) = rustre_demangle::demangle(sym) else { continue };
        checked += 1;
        let got = auto_demangle(sym);
        if got != live.demangled {
            diverged.push(format!("{sym}\n  live: {}\n  disp: {got}", live.demangled));
        }
    }

    assert!(checked > 3000, "vacuous: only {checked} symbols");
    assert!(
        diverged.is_empty(),
        "{} of {checked} diverge:\n{:#?}",
        diverged.len(),
        &diverged[..diverged.len().min(8)]
    );
}

/// The crate disambiguator must not survive into the output.
///
/// Spelled out because `{}` versus `{:#}` is invisible at a glance, and the
/// difference is a whole class of wrong output.
#[test]
fn rust_v0_drops_the_crate_disambiguator() {
    let got = auto_demangle("_RINvNtCs189ThkfrTWj_4core9panicking13assert_failedjjEB4_");
    assert_eq!(got, "core::panicking::assert_failed::<usize, usize>");
    assert!(!got.contains('['), "disambiguator leaked: {got}");
}

/// Linker wrappers decode, and the prefix survives — `.refptr.f` must never
/// read as `f`.
#[test]
fn linker_wrappers_decode_and_keep_their_prefix() {
    for (sym, want) in [
        (".refptr._ZN10__cxxabiv119__terminate_handlerE", ".refptr.__cxxabiv1::__terminate_handler"),
        ("__imp__ZNSt10bad_typeidD1Ev", "__imp_std::bad_typeid::~bad_typeid()"),
    ] {
        assert_eq!(auto_demangle(sym), want, "{sym}");
    }
}

/// **The discriminating case.** Ordinary Itanium must not be routed to Rust.
///
/// This is the direction that historically invents defects, and the old rule
/// failed it on every `_ZN…E` symbol — which is most of them.
#[test]
fn ordinary_itanium_is_not_routed_to_rust() {
    use rustre_demangle::demangler_dispatcher::detect_scheme;

    for sym in [
        "_ZN10__cxxabiv111__terminateEPFvvE",
        "_ZN3foo3barEv",
        "_ZNSt10bad_typeidD1Ev",
        "_ZN10__cxxabiv119__terminate_handlerE",
        // Not a hash, though it contains `17h` — the discriminating case from
        // `sigil.rs`, which the old `contains("17h")` half also got wrong.
        "_ZN3foo17hello_there_worldE",
    ] {
        assert_eq!(
            format!("{:?}", detect_scheme(sym)),
            "ItaniumCpp",
            "{sym} misrouted"
        );
        assert_ne!(auto_demangle(sym), sym, "{sym} must decode");
    }

    // The converse: real legacy Rust still routes to Rust and loses its hash.
    let rust = "_ZN19sample3_struct_loop4main17h051ebe1ecfcb2bb2E";
    assert_eq!(format!("{:?}", detect_scheme(rust)), "RustLegacy");
    assert_eq!(auto_demangle(rust), "sample3_struct_loop::main");
}
