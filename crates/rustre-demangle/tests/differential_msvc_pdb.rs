//! Differential testing of the REAL MSVC symbols against `msvc-demangler`.
//!
//! `differential_msvc.rs` compares against the oracle, but over a hand-written
//! corpus of synthetic symbols (`?foo@@YAHH@Z`, `??_7Foo@@6B@`). The real MSVC
//! symbols the toolchain actually emitted live in `pdb_symbols.txt` — pulled
//! from `sample3_rust.pdb`/`sample8_rust.pdb`, the only real MSVC source in the
//! repo — and were only ever checked for *decoding* (`pdb_corpus.rs` asserts
//! they return `Some`), never for *output correctness* against the oracle.
//!
//! Adding that check found real defects, which is the whole reason the crate's
//! notes insist on the real corpus over the obvious case. Of the 14 real MSVC
//! symbols, 7 decoded but disagreed with `msvc-demangler`, in two shapes the
//! synthetic corpus never exercised — both since fixed:
//!
//!   * **Deleting destructors** (`??_E…`, `??_G…`) emitted only the special
//!     name and dropped the trailing member-function signature. A `??_E…`
//!     symbol is a member function whose name is the special label, so the
//!     rest (`UEAAPEAXI@Z`) now parses through the shared function tail —
//!     ``public: virtual void * __cdecl type_info::`vector deleting
//!     destructor'(unsigned int)``.
//!
//!   * **RTTI descriptors** (`??_R0`–`??_R4`) were character-scraped into
//!     ``RTTI Type Descriptor for 'AVtype_info'`` and fabricated fields. They
//!     now decode by grammar: the type key for `??_R0`, four signed MSVC
//!     numbers for the base-class descriptor
//!     (``type_info::`RTTI Base Class Descriptor at (0,-1,0,64)'``), a cv byte
//!     for the complete object locator.
//!
//! All 14 now match, so the whole real corpus is a live differential guard with
//! no exclusions — the state the synthetic suite claimed but did not hold.

mod msvc_oracle;
use msvc_oracle::{normalise, reference};

fn real_msvc_symbols() -> Vec<&'static str> {
    include_str!("data/pdb_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|s| s.starts_with('?'))
        .collect()
}

/// Every real MSVC symbol must match `msvc-demangler`, with no exclusions.
#[test]
fn real_msvc_symbols_match_the_reference() {
    let syms = real_msvc_symbols();
    assert!(
        !syms.is_empty(),
        "no MSVC symbols in the PDB corpus — file truncated?"
    );

    let mut mismatches = Vec::new();
    let mut compared = 0usize;
    let mut skipped = 0usize;

    for sym in &syms {
        let Some(reference) = reference(sym) else {
            skipped += 1;
            continue;
        };
        compared += 1;
        match rustre_demangle::demangle(sym) {
            Some(ours) if normalise(&ours.demangled) == normalise(&reference) => {}
            Some(ours) => mismatches.push(format!(
                "  {sym}\n    reference: {reference}\n    ours:      {}",
                ours.demangled
            )),
            None => mismatches.push(format!(
                "  {sym}\n    reference: {reference}\n    ours:      <None>"
            )),
        }
    }

    // Vacuity guard: the oracle must actually accept most of the corpus, or a
    // future edit that broke `reference` would make this pass comparing nothing.
    println!("real MSVC differential: {compared} compared, {skipped} skipped (reference rejects)");
    assert!(
        compared >= 10,
        "only {compared} real MSVC symbols compared — the oracle stopped \
         accepting them and the guard has gone vacuous"
    );
    assert!(
        mismatches.is_empty(),
        "{} of {compared} real MSVC symbols differ from msvc-demangler:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
