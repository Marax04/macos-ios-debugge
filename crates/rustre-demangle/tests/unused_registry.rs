//! Does the unwired `demangler_registry` agree with the live path?
//!
//! `demangler_registry` is public API that nothing in the crate calls, and it
//! is not a small helper: it defines its own `ItaniumDemangler`,
//! `MsvcDemangler`, `SwiftDemangler`, `RustDemangler`, `DDemangler`,
//! `AutoDemangler` and `DemanglerCache` — names that also exist in the live
//! path and in other modules. Every one of those core types has two or three
//! definitions in this crate.
//!
//! A caller reaching for `demangler_registry::AutoDemangler` reasonably
//! expects the crate's answers. This measures whether they get them, over the
//! real corpora, the same way `tests/unused_msvc_full.rs` does for
//! `msvc_full`.

use std::collections::BTreeMap;

use rustre_demangle::demangler_registry::AutoDemangler as RegistryAuto;

fn corpora() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// Report how the registry's dispatcher compares with `demangle()`.
///
/// This is deliberately a measurement, not a preference: the registry may be
/// intended as an independent implementation. What it must not do is silently
/// decode *less* while carrying the same type names, since that is what turns
/// an alternative into a trap.
#[test]
fn registry_dispatcher_is_not_silently_weaker() {
    // This list held `_RTC_Initialize` and `_RTC_Terminate` — MSVC CRT C
    // functions the registry's `RustDemangler` claimed through a loose `_R`
    // prefix rule that had already been fixed in the live path. It is empty
    // now: the registry was migrated to `crate::sigil`, so the copy no longer
    // lags behind.
    //
    // Deciding whether this module should exist is a separate question from
    // whether it should carry a known bug; the second was fixable without
    // prejudging the first.
    const STALE_FALSE_POSITIVES: &[&str] = &[];

    let syms = corpora();
    let registry = RegistryAuto::standard();

    let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
    let mut registry_only: Vec<&str> = Vec::new();
    let mut live_only: Vec<&str> = Vec::new();

    for s in &syms {
        let live = rustre_demangle::demangle(s).is_some();
        let reg = registry.demangle(s).is_some();
        match (live, reg) {
            (true, true) => *tally.entry("both").or_default() += 1,
            (true, false) => {
                *tally.entry("live only").or_default() += 1;
                live_only.push(s);
            }
            (false, true) => {
                *tally.entry("registry only").or_default() += 1;
                registry_only.push(s);
            }
            (false, false) => *tally.entry("neither").or_default() += 1,
        }
    }

    for (k, n) in &tally {
        println!("  {n:>5}  {k}");
    }
    println!("  registry-only examples: {:?}", &registry_only[..registry_only.len().min(3)]);
    println!("  live-only examples:     {:?}", &live_only[..live_only.len().min(3)]);

    // The corpora must actually exercise this, or the comparison says nothing.
    assert!(
        tally.get("both").copied().unwrap_or(0) > 500,
        "too few symbols decoded by both paths to draw a conclusion"
    );

    let unexpected: Vec<&&str> = registry_only
        .iter()
        .filter(|s| !STALE_FALSE_POSITIVES.contains(s))
        .collect();
    assert!(
        unexpected.is_empty(),
        "{} symbols decode only through the unwired registry, beyond its known \
         stale false positives; first 10: {:#?}",
        unexpected.len(),
        &unexpected[..unexpected.len().min(10)]
    );
    assert_eq!(
        registry_only.len(),
        STALE_FALSE_POSITIVES.len(),
        "the registry's stale `_R` false positives changed; re-measure before \
         editing this list"
    );
}

/// DOCUMENTED GAP: the registry should agree with the live dispatcher.
///
/// It decodes 2209 fewer corpus symbols (no Go, no linker wrappers) while
/// exposing the same type names — `AutoDemangler`, `ItaniumDemangler`,
/// `DemanglerCache` and the rest all exist two or three times in this crate —
/// and it reproduces a `_R` false positive already fixed in the live path.
///
/// Asserted as the correct behaviour and ignored, per the convention of
/// `fidelity_demangle.rs::fidelity_known_gaps`. Resolving it means deciding
/// what this module is for: an independent implementation worth maintaining, a
/// façade over the live path, or dead weight to remove. That is a public-API
/// decision, not a drive-by fix.
#[test]
#[ignore = "documents the registry/live divergence; the assertion is the correct behaviour"]
fn registry_should_match_the_live_dispatcher() {
    let syms = corpora();
    let registry = RegistryAuto::standard();
    let divergent: Vec<&&str> = syms
        .iter()
        .filter(|s| rustre_demangle::demangle(s).is_some() != registry.demangle(s).is_some())
        .collect();
    assert!(
        divergent.is_empty(),
        "{} symbols are decoded by one dispatcher and not the other; first 10: {:#?}",
        divergent.len(),
        &divergent[..divergent.len().min(10)]
    );
}
