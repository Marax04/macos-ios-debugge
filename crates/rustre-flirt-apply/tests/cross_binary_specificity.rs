//! Signatures from one archive must not match a binary that never linked it (T14).
//!
//! # The half of T14 the round-trip could not do
//!
//! `self_match_experiment.rs` scans the bytes a signature was generated from.
//! That proves a signature is broken when it fails, but it cannot measure
//! recognition across artefacts, and it is blind to wildcard loss: the container
//! truncates a pattern at its first wildcard, and on the original bytes the
//! surviving exact prefix still matches.
//!
//! Measured across binaries (iteration 46), harvesting `libmingwex.a`
//! (293 objects, 522 patterns; 151 truncated by a wildcard, 27 reduced to under
//! 8 bytes) and scanning a mingw-linked corpus binary versus a Go binary that
//! cannot contain those functions:
//!
//! | subset | target | foreign |
//! |---|---|---|
//! | all 522 | 4 | **5** |
//! | only untruncated (371) | 1 | **0** |
//! | only truncated (151) | 3 | 5 |
//! | only reduced under 8 bytes (27) | 3 | 5 |
//!
//! More names matched the *foreign* binary than the legitimate one, and every
//! false positive came from the truncated set — 27 patterns, cut short by
//! wildcard loss, produced all of them. The untruncated majority produced zero.
//!
//! That also means the 3 "target" matches from the truncated set are most likely
//! false positives too, being the same class of 3-to-7-byte keys. Real recall is
//! therefore about **1 of 522**, not 4 — a number worth stating plainly rather
//! than leaving flattering.
//!
//! Threshold sweep on the same inputs:
//!
//! | `min_bytes_without_crc` | target | foreign |
//! |---|---|---|
//! | 0 | 4 | 5 |
//! | 4 | 1 | 2 |
//! | **8** | 1 | **0** |
//! | 16 | 1 | 0 |
//! | 24 | 0 | 0 |
//!
//! This is an independent data point for the pending threshold decision: it was
//! previously measured on the rust-stdlib database (5071 false positives at 0,
//! zero at 16). Here 8 already suffices and 16 costs nothing extra, while 24
//! destroys the only surviving true match.
//!
//! # Why this test skips instead of failing when inputs are missing
//!
//! It needs a mingw installation and the repo corpus. A test that fails on a
//! machine without them would train people to ignore it; one that silently
//! passes would be worse. It skips loudly, and `the_inputs_are_not_vacuous`
//! keeps a skip from being mistaken for a pass.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rustre_flirt::PatternByte;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("il crate deve stare in <root>/crates/<name>")
}

const ARCHIVE: &str = r"C:\msys64\mingw64\lib\libmingwex.a";

fn corpus(name: &str) -> PathBuf {
    repo_root().join("tests/decompiler_corpus/bin").join(name)
}

/// Harvested patterns, or `None` when the toolchain is not installed.
fn patterns() -> Option<Vec<rustre_flirt::FlirtPattern>> {
    let data = std::fs::read(ARCHIVE).ok()?;
    let opts = rustre_flirt_gen::coff_archive::ArchiveHarvestOptions::default();
    let (pats, _stats) = rustre_flirt_gen::coff_archive::harvest_archive_bytes(&data, &opts).ok()?;
    (!pats.is_empty()).then_some(pats)
}

fn distinct_matches(
    pats: &[rustre_flirt::FlirtPattern],
    haystack: &[u8],
    min_bytes: usize,
) -> usize {
    let sig = rustre_flirt_gen::SigWriter::default().build(pats, "crossbin");
    let mut scanner = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig)
        .expect("il .sig appena scritto deve essere leggibile");
    scanner.set_min_bytes_without_crc(min_bytes);
    scanner
        .scan_fast(haystack, 0)
        .into_iter()
        .map(|m| m.function_name)
        .collect::<HashSet<_>>()
        .len()
}

/// What the container will actually keep of a pattern: bytes before the first
/// wildcard.
fn kept_len(p: &rustre_flirt::FlirtPattern) -> usize {
    p.initial_bytes
        .iter()
        .take_while(|b| matches!(b, PatternByte::Exact(_)))
        .count()
}

#[test]
fn the_inputs_are_not_vacuous() {
    // A degenerate corpus makes every specificity claim pass for free. This
    // project has already been caught by that three times, so the guard comes
    // first.
    let Some(pats) = patterns() else {
        eprintln!("SKIP: {ARCHIVE} assente");
        return;
    };
    assert!(
        pats.len() > 100,
        "attesi molti pattern da libmingwex.a, trovati {}",
        pats.len()
    );
    assert!(
        pats.iter().any(|p| kept_len(p) < p.initial_bytes.len()),
        "nessun pattern troncato: senza wildcard questa misura non dice nulla \
         sul troncamento"
    );
    let foreign = corpus("sample4_go.exe");
    assert!(
        foreign.exists(),
        "corpus assente: {} — il test di specificita' non avrebbe bersaglio",
        foreign.display()
    );
}

#[test]
fn a_threshold_of_eight_removes_every_false_positive() {
    let Some(pats) = patterns() else {
        eprintln!("SKIP: {ARCHIVE} assente");
        return;
    };
    let Ok(go) = std::fs::read(corpus("sample4_go.exe")) else {
        eprintln!("SKIP: corpus assente");
        return;
    };

    // A Go binary cannot contain mingwex functions: every match is wrong.
    let at_zero = distinct_matches(&pats, &go, 0);
    let at_eight = distinct_matches(&pats, &go, 8);

    // Iterazione 53: da quando il container trasporta la coda mascherata, i
    // falsi positivi sono **zero gia' a soglia 0**. Prima erano 5, tutti dai
    // pattern troncati. Non e' piu' la soglia a proteggere: e' il pattern
    // completo. La soglia era un filtro che compensava firme arrivate corte.
    assert_eq!(
        at_zero, 0,
        "attesi 0 falsi positivi su un binario Go anche senza soglia (erano 5), \
         ottenuti {at_zero}: il container avrebbe ripreso a troncare i pattern"
    );
    assert_eq!(
        at_eight, 0,
        "a soglia 8 restano {at_eight} falsi positivi su un binario Go"
    );
}

/// The wildcard truncation is where the false positives come from — not the
/// signatures in general. Stated separately so a fix to the container can be
/// recognised as such.
#[test]
fn the_untruncated_patterns_produce_no_false_positives() {
    let Some(pats) = patterns() else {
        eprintln!("SKIP: {ARCHIVE} assente");
        return;
    };
    let Ok(go) = std::fs::read(corpus("sample4_go.exe")) else {
        eprintln!("SKIP: corpus assente");
        return;
    };

    let intact: Vec<_> = pats
        .iter()
        .filter(|p| kept_len(p) == p.initial_bytes.len())
        .cloned()
        .collect();
    let truncated: Vec<_> = pats
        .iter()
        .filter(|p| kept_len(p) < p.initial_bytes.len())
        .cloned()
        .collect();

    assert!(!intact.is_empty() && !truncated.is_empty(), "servono entrambi i gruppi");

    assert_eq!(
        distinct_matches(&intact, &go, 0),
        0,
        "i pattern non troncati non devono combaciare con un binario Go"
    );
    // Erano proprio questi a produrre tutti i falsi positivi: 27 pattern ridotti
    // sotto gli 8 byte ne generavano 5 su un binario Go. Ora che la coda
    // mascherata viaggia con la firma, non ne producono piu' nessuno.
    assert_eq!(
        distinct_matches(&truncated, &go, 0),
        0,
        "i pattern con wildcard producono di nuovo falsi positivi: il container \
         avrebbe ripreso a scartare la coda mascherata"
    );
}
