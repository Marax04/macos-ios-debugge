//! Real-symbol corpus for the ABIs `real_corpus.rs` cannot reach.
//!
//! The 12 corpus executables are mingw-built, so `nm` yields only Itanium and
//! Go names — the Rust and MSVC backends, which are among the largest parts of
//! this crate, had NO real-world coverage at all, only synthetic tests. The
//! two Rust binaries ship a PDB, and `sample3_rust.exe` itself is stripped
//! (`nm` reports "no symbols"), which is why this went unnoticed.
//!
//! `tests/data/pdb_symbols.txt` holds the `S_PUB32` public symbols of
//! `sample3_rust.pdb` and `sample8_rust.pdb` — rustc-emitted Rust v0 names
//! (`_RNv…`) and MSVC CRT names (`??3@YAXPEAX@Z`), the real thing rather than
//! grammar-generated. Regenerate with `tests/data/regenerate.sh`, which also
//! asserts that both ABIs are still present.

use std::collections::BTreeMap;

use rustre_demangle::{DeclineReason, decline_reason};

fn symbols() -> Vec<String> {
    include_str!("data/pdb_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// No symbol may panic the demangler. Completing the loop is the proof.
#[test]
fn no_panic_on_pdb_symbols() {
    let syms = symbols();
    assert!(syms.len() > 300, "PDB corpus went missing or was truncated");
    let decoded = syms
        .iter()
        .filter(|s| rustre_demangle::demangle(s).is_some())
        .count();
    println!("pdb corpus: {decoded}/{} symbols demangled", syms.len());
}

/// Every Rust v0 symbol rustc emitted must decode. Unlike a percentage floor
/// this is exact: `_RNv…` is a strict, well-specified grammar, so a failure is
/// a gap in the backend, never an ambiguous input.
#[test]
fn every_rust_v0_symbol_decodes() {
    let syms = symbols();
    let v0: Vec<&String> = syms.iter().filter(|s| is_rust_v0(s)).collect();
    assert!(
        v0.len() > 100,
        "expected the PDBs to carry >100 Rust v0 symbols, found {}",
        v0.len()
    );

    let failures: Vec<&&String> = v0
        .iter()
        .filter(|s| rustre_demangle::demangle(s).is_none())
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} Rust v0 symbols failed to decode; first 10: {:#?}",
        failures.len(),
        v0.len(),
        &failures[..failures.len().min(10)]
    );
}

/// Every MSVC symbol in the PDB corpus must decode.
///
/// This briefly carried an allowlist for two function-local statics
/// (`?_OptionsStorage@?1??__local_stdio_printf_options@@9@4_KA`); local-scope
/// support landed in `parse_msvc_qualified_name`, so the allowlist is gone.
#[test]
fn every_msvc_symbol_decodes() {
    let syms = symbols();
    let msvc: Vec<&String> = syms.iter().filter(|s| s.starts_with('?')).collect();
    assert!(!msvc.is_empty(), "expected MSVC symbols in the PDB corpus");

    let failures: Vec<&String> = msvc
        .iter()
        .filter(|s| rustre_demangle::demangle(s).is_none())
        .copied()
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} MSVC symbols failed to decode; first 10: {:#?}",
        failures.len(),
        msvc.len(),
        &failures[..failures.len().min(10)]
    );
}

/// `_R` is Rust v0's sigil, but MSVC's CRT also ships `_RTC_Initialize`,
/// `_RTC_InitBase` and the C++ RTTI helper `_R4type_info`. Claiming those as
/// Rust would be a false positive on a name that is plain C.
#[test]
fn msvc_runtime_names_are_not_mistaken_for_rust() {
    for s in ["_RTC_Initialize", "_RTC_InitBase", "_RTC_Shutdown"] {
        if let Some(r) = rustre_demangle::demangle(s) {
            assert_ne!(
                r.abi,
                rustre_demangle::ManglingAbi::Rust,
                "{s} is an MSVC CRT symbol, not Rust: {}",
                r.demangled
            );
        }
    }
}

/// Same classification discipline as the main corpus: nothing may sit in
/// `Unknown`, and no symbol carrying a recognised sigil may go unhandled.
#[test]
fn pdb_corpus_is_fully_classified() {
    let syms = symbols();
    let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
    let mut defects: Vec<&String> = Vec::new();
    let mut unclassified: Vec<&String> = Vec::new();

    for s in &syms {
        let reason = decline_reason(s);
        *tally
            .entry(match reason {
                DeclineReason::Decoded => "decoded",
                DeclineReason::LinkerSection => "linker section",
                DeclineReason::LinkerArtifact => "toolchain artifact",
                DeclineReason::UndecoratedC => "undecorated C",
                DeclineReason::UnsupportedAbi => "UNSUPPORTED ABI (defect)",
                DeclineReason::DotNetMetadata => ".NET metadata name (nothing to demangle)",
                DeclineReason::AlreadyDemangled => "already demangled (debug-info name)",
                DeclineReason::Unknown => "unknown shape",
            })
            .or_default() += 1;
        if reason.is_defect() {
            defects.push(s);
        }
        if reason == DeclineReason::Unknown {
            unclassified.push(s);
        }
    }
    for (label, n) in &tally {
        println!("  {n:>4}  {label}");
    }

    assert!(
        defects.is_empty(),
        "{} mangled symbols went unhandled; first 10: {:#?}",
        defects.len(),
        &defects[..defects.len().min(10)]
    );
    assert!(
        unclassified.is_empty(),
        "{} symbols fall into no known category; first 10: {:#?}",
        unclassified.len(),
        &unclassified[..unclassified.len().min(10)]
    );
}

/// Rust v0 proper: `_R` followed by the grammar's leading item tag, which
/// excludes MSVC CRT names like `_RTC_Initialize`.
fn is_rust_v0(s: &str) -> bool {
    s.strip_prefix("_R")
        .and_then(|r| r.chars().next())
        .is_some_and(|c| matches!(c, 'N' | 'I' | 'C' | 'M' | 'X' | 'Y' | 'K' | 'B'))
}
