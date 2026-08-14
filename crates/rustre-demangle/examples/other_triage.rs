//! Triage of the real-symbol corpus by decline reason.
//!
//! `tests/real_corpus.rs` buckets by leading sigil, which leaves ~3000 entries
//! in an opaque "other" bucket. This example reports the same corpus through
//! [`rustre_demangle::decline_reason`], so the undecoded remainder is split
//! into correct declines (section names, undecorated C, toolchain artifacts)
//! and the only category that represents a defect — a recognised mangling
//! sigil that no backend decoded.
//!
//! Run: `cargo run --release -p rustre-demangle --example other_triage`

use std::collections::BTreeMap;

use rustre_demangle::{DeclineReason, decline_reason};

fn main() {
    let raw = include_str!("../tests/data/real_symbols.txt");
    let syms: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    let mut buckets: BTreeMap<&'static str, Vec<&str>> = BTreeMap::new();
    for s in &syms {
        buckets.entry(label(decline_reason(s))).or_default().push(s);
    }

    println!("corpus: {} symbols\n", syms.len());
    let mut rows: Vec<_> = buckets.iter().collect();
    rows.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
    for (name, items) in rows {
        println!("{:>6}  {name}", items.len());
        // Samples matter only for the categories still under investigation;
        // printing six of 2000 section names is noise.
        if *name != label(DeclineReason::Decoded) {
            for sample in items.iter().take(6) {
                println!("           {sample}");
            }
        }
    }

    let defect_label = label(DeclineReason::UnsupportedAbi);
    match buckets.get(defect_label) {
        None => println!("\ndefects (mangled but unhandled): 0"),
        Some(defects) => {
            println!("\ndefects (mangled but unhandled): {}", defects.len());
            println!("these are the only entries worth fixing:");
            for s in defects {
                println!("  {s}");
            }
        }
    }
}

const fn label(r: DeclineReason) -> &'static str {
    match r {
        DeclineReason::Decoded => "decoded",
        DeclineReason::LinkerSection => "linker section (not a symbol)",
        DeclineReason::LinkerArtifact => "toolchain artifact",
        DeclineReason::UndecoratedC => "undecorated C (nothing to demangle)",
        DeclineReason::UnsupportedAbi => "UNSUPPORTED ABI (defect)",
        DeclineReason::DotNetMetadata => ".NET metadata name (nothing to demangle)",
        DeclineReason::AlreadyDemangled => "already demangled (debug-info name)",
        DeclineReason::Unknown => "unknown shape",
    }
}
