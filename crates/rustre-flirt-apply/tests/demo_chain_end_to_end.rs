//! The demo chain must keep working, and keep being believable (T18).
//!
//! `examples/flirt_demo.rs` runs archive → patterns → `.sig` → scan and prints
//! the before/after. This pins the properties that make its output worth
//! reading, so the demo cannot quietly become a program that prints numbers.
//!
//! Measured (iteration 72) on `libmingw32.a` against a mingw-built corpus binary:
//!
//! | stage | value |
//! |---|---|
//! | patterns harvested | 43 (34 carrying wildcards) |
//! | `.sig` written | 3 078 bytes |
//! | signatures read back | **43 of 43** |
//! | functions identified on the target | **24** |
//! | identifications on the control binary | **0** |
//!
//! The control column is the point. A chain that produces names is easy; one
//! whose names are absent from a binary that cannot contain those functions is
//! the claim worth making. Both numbers move together when something breaks:
//! iteration 47 measured 5 false positives here, from patterns the container was
//! truncating at their first wildcard.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

const ARCHIVE: &str = r"C:\msys64\mingw64\lib\libmingw32.a";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("il crate deve stare in <root>/crates/<name>")
}

fn corpus(name: &str) -> PathBuf {
    repo_root().join("tests/decompiler_corpus/bin").join(name)
}

fn patterns() -> Option<Vec<rustre_flirt::FlirtPattern>> {
    let data = std::fs::read(ARCHIVE).ok()?;
    let opts = rustre_flirt_gen::coff_archive::ArchiveHarvestOptions::default();
    let (p, _) = rustre_flirt_gen::coff_archive::harvest_archive_bytes(&data, &opts).ok()?;
    (!p.is_empty()).then_some(p)
}

fn scanner_over(pats: &[rustre_flirt::FlirtPattern]) -> rustre_flirt_apply::FlirtScanner {
    let sig = rustre_flirt_gen::SigWriter::default().build(pats, "demo");
    rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig)
        .expect("il .sig appena scritto deve essere rileggibile")
}

fn names_in(scanner: &rustre_flirt_apply::FlirtScanner, path: &Path) -> HashSet<String> {
    std::fs::read(path).map_or_else(
        |_| HashSet::new(),
        |b| {
            scanner
                .scan_fast(&b, 0)
                .into_iter()
                .map(|m| m.function_name)
                .filter(|n| !n.is_empty())
                .collect()
        },
    )
}

#[test]
fn the_chain_writes_and_reads_back_every_pattern() {
    let Some(pats) = patterns() else {
        eprintln!("SKIP: {ARCHIVE} assente");
        return;
    };
    let sig = rustre_flirt_gen::SigWriter::default().build(&pats, "demo");

    let dir = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    let tmp = Path::new(&dir).join("rustre_demo_chain.sig");
    std::fs::write(&tmp, &sig).expect("scrittura");
    let back = rustre_flirt_apply::load_sig_file(&tmp).expect("rilettura");
    let _ = std::fs::remove_file(&tmp);

    assert_eq!(
        back.len(),
        pats.len(),
        "rilette {} firme su {} scritte: il container perde contenuto",
        back.len(),
        pats.len()
    );
}

#[test]
fn the_demo_identifies_functions_on_the_target() {
    let Some(pats) = patterns() else { return };
    if !corpus("sample1_c.exe").exists() {
        eprintln!("SKIP: corpus assente");
        return;
    }
    let found = names_in(&scanner_over(&pats), &corpus("sample1_c.exe"));
    assert!(
        found.len() >= 10,
        "solo {} funzioni identificate: la demo non mostrerebbe nulla",
        found.len()
    );
}

/// The claim the demo actually makes. Zero here is what separates "it produces
/// names" from "the names mean something".
#[test]
fn the_demo_finds_nothing_on_the_control_binary() {
    let Some(pats) = patterns() else { return };
    if !corpus("sample4_go.exe").exists() {
        eprintln!("SKIP: corpus assente");
        return;
    }
    let found = names_in(&scanner_over(&pats), &corpus("sample4_go.exe"));
    assert!(
        found.is_empty(),
        "{} identificazioni su un binario Go che non collega libmingw32: sono \
         falsi positivi per costruzione — {found:?}",
        found.len()
    );
}

/// Most of this archive's patterns carry wildcards, so if the container ever
/// went back to truncating them the demo would still print names while silently
/// losing what makes them specific.
#[test]
fn most_patterns_carry_wildcards_and_still_survive() {
    let Some(pats) = patterns() else { return };
    let with_wc = pats
        .iter()
        .filter(|p| {
            p.initial_bytes
                .iter()
                .any(|b| matches!(b, rustre_flirt::PatternByte::Wildcard))
        })
        .count();
    assert!(
        with_wc * 2 > pats.len(),
        "solo {with_wc} pattern su {} con wildcard: corpus inatteso",
        pats.len()
    );

    let sig = rustre_flirt_gen::SigWriter::default().build(&pats, "demo");
    let dir = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    let tmp = Path::new(&dir).join("rustre_demo_wc.sig");
    std::fs::write(&tmp, &sig).expect("scrittura");
    let back = rustre_flirt_apply::load_sig_file(&tmp).expect("rilettura");
    let _ = std::fs::remove_file(&tmp);

    let back_wc = back.iter().filter(|s| s.mask.contains(&0)).count();
    assert!(
        back_wc > 0,
        "nessun wildcard sopravvive alla scrittura: il container li sta \
         scartando di nuovo"
    );
}
