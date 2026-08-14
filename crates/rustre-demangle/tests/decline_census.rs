//! The corpus classifies completely, with nothing in a defect bucket.
//!
//! This is the standing proof for the "3089 other" question: every symbol that
//! does not decode is accounted for as a linker section, undecorated C, or a
//! toolchain artifact — none is an unhandled ABI or an unclassified shape.
//!
//! Measured over BOTH corpora — `real_symbols.txt` (6074, Itanium + Go) and
//! `pdb_symbols.txt` (394, the only source of real Rust v0 and MSVC symbols).
//! The PDB corpus is included deliberately: it is the one place an unhandled
//! `?` (MSVC) or `_R` (Rust v0) sigil would surface, so a census that omitted
//! it could read zero defects while a whole ABI went unhandled. Combined
//! partition, 6468 symbols (re-measured 2026-07-29):
//!
//! | reason           | count | meaning                                        |
//! |------------------|-------|------------------------------------------------|
//! | `Decoded`        |  3161 | a real demangling                              |
//! | `LinkerSection`  |  2215 | `.text`, `.pdata$…` — a section, not a symbol  |
//! | `UndecoratedC`   |   783 | a plain C name, already its own demangling     |
//! | `LinkerArtifact` |   309 | `__CTOR_LIST__`, import thunks, `$f64.<hex>`    |
//! | `Unknown`        |     0 | no category fits — locked at 0                  |
//! | `UnsupportedAbi` |     0 | a sigil no backend decoded — the defect bucket |
//!
//! The two zeros are the point. `UnsupportedAbi` is the only reason that means
//! a defect in this crate, and `Unknown` means a symbol shape nobody has named;
//! both are held at zero so a regression that reintroduced either — a new ABI
//! sigil going unhandled, or a symbol class falling through classification —
//! fails here rather than hiding inside the decode count.

use rustre_demangle::decline::{decline_reason, DeclineReason};
use std::collections::BTreeMap;

fn corpus() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// Nothing may land in `Unknown` or `UnsupportedAbi`, and the classification
/// must cover every symbol exactly once.
#[test]
fn classification_is_complete_with_no_defects() {
    let syms = corpus();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut unknown: Vec<&str> = Vec::new();
    let mut unsupported: Vec<&str> = Vec::new();

    for s in &syms {
        let r = decline_reason(s);
        *counts.entry(format!("{r:?}")).or_default() += 1;
        match r {
            DeclineReason::Unknown => unknown.push(s),
            DeclineReason::UnsupportedAbi => unsupported.push(s),
            _ => {}
        }
    }

    for (k, v) in &counts {
        println!("{v:6}  {k}");
    }

    // The partition must be total: `decline_reason` returns one of six variants
    // for every input, so the counts must sum to the corpus. A gap would mean a
    // variant went uncounted — the census silently narrowing.
    let total: usize = counts.values().sum();
    assert_eq!(
        total,
        syms.len(),
        "census does not cover the corpus: {total} of {}",
        syms.len()
    );

    // Vacuity guards: each real bucket must be populated, so this cannot pass by
    // the corpus collapsing. The floors are well under the measured values.
    assert!(
        counts.get("Decoded").copied().unwrap_or(0) > 2000,
        "Decoded bucket collapsed — corpus truncated or decoding broke"
    );
    assert!(
        counts.get("LinkerSection").copied().unwrap_or(0) > 1000,
        "LinkerSection bucket collapsed"
    );
    assert!(
        counts.get("UndecoratedC").copied().unwrap_or(0) > 300,
        "UndecoratedC bucket collapsed"
    );
    // `LinkerArtifact` had no guard while the other three did — and it is the
    // bucket this crate has most recently *added* to (MSVC constant pools,
    // ARM mapping symbols), so an over-broad rule collapsing it back into
    // `Decoded` would have passed the census unnoticed.
    assert!(
        counts.get("LinkerArtifact").copied().unwrap_or(0) > 200,
        "LinkerArtifact bucket collapsed"
    );

    assert!(
        unknown.is_empty(),
        "{} symbols classify as Unknown — an unnamed shape has appeared; \
         first 10: {:#?}",
        unknown.len(),
        &unknown[..unknown.len().min(10)]
    );
    assert!(
        unsupported.is_empty(),
        "{} symbols classify as UnsupportedAbi — a mangling sigil went \
         unhandled; first 10: {:#?}",
        unsupported.len(),
        &unsupported[..unsupported.len().min(10)]
    );
}
