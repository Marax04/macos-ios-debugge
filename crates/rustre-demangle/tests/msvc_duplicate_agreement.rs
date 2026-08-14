//! The duplicate `msvc_demangler::MsvcDemangler` must stay oracle-correct.
//!
//! This crate carries more than one MSVC demangler: the live path
//! (`crate::demangle` → `backends` → `msvc_extras`) and the public
//! `msvc_demangler::MsvcDemangler`, used by this crate's own `differential.rs`,
//! `hardening.rs` and `alloc_profile.rs`. The crate's notes record that such
//! copies drift apart the moment nothing compares them — and drift in *both*
//! directions, one copy fixed while the other keeps the bug.
//!
//! When MSVC RTTI and deleting destructors were fixed on the live path, the
//! obvious worry was that this second copy still produced the old scraped
//! output. It does not: measured against `msvc-demangler`, it agrees with the
//! oracle on all 14 real PDB MSVC symbols, exactly as the live path now does.
//! That was worth checking rather than assuming — and worth pinning, so a
//! future edit to either copy that reintroduces a divergence fails here instead
//! of hiding until someone greps a format string.

mod msvc_oracle;
use msvc_oracle::{normalise, reference};

fn real_msvc_symbols() -> Vec<&'static str> {
    include_str!("data/pdb_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|s| s.starts_with('?'))
        .collect()
}

#[test]
fn duplicate_msvc_demangler_agrees_with_the_oracle() {
    let syms = real_msvc_symbols();
    let mut compared = 0usize;
    let mut mismatches = Vec::new();

    for sym in &syms {
        let Some(reference) = reference(sym) else {
            continue;
        };
        compared += 1;
        let dup = rustre_demangle::msvc_demangler::MsvcDemangler::demangle_to_string(sym);
        if normalise(&dup) != normalise(&reference) {
            mismatches.push(format!(
                "  {sym}\n    reference: {reference}\n    duplicate: {dup}"
            ));
        }
    }

    // Vacuity guard: the oracle must accept the bulk of the corpus, so a broken
    // `reference` cannot make this pass by comparing nothing.
    println!("duplicate MSVC vs oracle: {compared} compared");
    assert!(
        compared >= 10,
        "only {compared} real MSVC symbols compared — the guard has gone vacuous"
    );
    assert!(
        mismatches.is_empty(),
        "the duplicate msvc_demangler::MsvcDemangler diverged from the oracle on \
         {} real symbols — the two MSVC copies have drifted:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
