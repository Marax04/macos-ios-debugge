//! A rust-stdlib database must not rename functions in a C, C++, Go or C# binary.
//!
//! # Why this oracle is the strong one
//!
//! The PDB measurement needs a binary with symbols; the corpus ships two, both
//! Rust, both linking the same stdlib — one sample, not two.
//!
//! This needs no symbols. A binary built from C contains no Rust standard
//! library, so **every match is a false positive by construction**. Nothing to
//! trust, nothing to normalise, no UNKNOWN bucket.
//!
//! Measured across six non-Rust corpus binaries, distinct addresses renamed:
//!
//! | threshold | 0 | 8 | 12 | 16 | 20 | 24 | 32 |
//! |---|---|---|---|---|---|---|---|
//! | false positives | **5071** | 2 | 1 | **0** | 0 | 0 | 0 |
//!
//! Go alone accounted for 1 580 and C# for 2 928. Beside the PDB curve — where
//! threshold 16 keeps 15 of the 18 verified-correct names — this is what makes
//! 16 a defensible default rather than a guess.
//!
//! This measures **specificity only**. A database matching nothing at all would
//! score perfectly here, so it must be read next to the precision numbers, never
//! instead of them.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("il crate deve stare in <root>/crates/<name>")
}

/// Build the `.sig` from the repo's own database, or skip when absent.
fn database() -> Option<Vec<u8>> {
    let raw = std::fs::read(repo_root().join("assets/rust-stdlib.sig")).ok()?;
    rustre_flirt_gen::rflirt_bin::to_sig_bytes(&raw, "rust-stdlib", 75).ok()
}

fn renamed_addresses(sig: &[u8], bin: &[u8], min_bytes: usize) -> usize {
    let Ok(pe) = rustre_pe_tools::PeFile::parse(bin) else {
        return 0;
    };
    let mut scanner = rustre_flirt_apply::FlirtScanner::from_sig_bytes(sig).expect("scanner");
    scanner.set_min_bytes_without_crc(min_bytes);

    let mut matches = Vec::new();
    for s in &pe.sections {
        if s.characteristics & 0x2000_0000 == 0 || s.data.is_empty() {
            continue;
        }
        let va = pe.image_base + u64::from(s.virtual_address);
        matches.extend(scanner.scan_fast(&s.data, va));
    }
    let (renames, _) = rustre_flirt_apply::resolve_renames(&matches, 0);
    renames
        .iter()
        .map(|r| r.address)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

const FOREIGN: &[&str] = &[
    "sample1_c.exe",
    "sample2_cpp.exe",
    "sample4_go.exe",
    "sample5_cs.exe",
    "sample6_c.exe",
    "sample7_cpp.exe",
];

fn foreign_binaries() -> Vec<(String, Vec<u8>)> {
    let dir = repo_root().join("tests/decompiler_corpus/bin");
    FOREIGN
        .iter()
        .filter_map(|n| std::fs::read(dir.join(n)).ok().map(|b| ((*n).to_string(), b)))
        .collect()
}

#[test]
fn threshold_16_renames_nothing_in_a_non_rust_binary() {
    let Some(sig) = database() else {
        eprintln!("assets/rust-stdlib.sig assente — test saltato");
        return;
    };
    let bins = foreign_binaries();
    if bins.is_empty() {
        eprintln!("binari del corpus assenti — test saltato");
        return;
    }

    for (name, bin) in &bins {
        let n = renamed_addresses(&sig, bin, 16);
        assert_eq!(
            n, 0,
            "{name}: {n} rinomine da firme rust-stdlib in un binario che non contiene Rust"
        );
    }
}

/// The database no longer renames anything on a binary it cannot belong to —
/// **without any threshold at all**.
///
/// This test used to assert the opposite, as a floor: "expect thousands of false
/// positives without a threshold", measured at **5071** across six foreign
/// binaries. Its own message said to update the baseline if the matcher
/// improved. It did (iteration 53): the `.sig` leaf now carries a masked tail,
/// so a wildcarded pattern reaches the scanner whole instead of truncated to its
/// first few concrete bytes, and a 3-byte key no longer matches everything.
///
/// Measured now: **0**, at threshold 0, on the same six binaries.
///
/// This retires the threshold as the thing that provides specificity. The
/// threshold was a filter compensating for patterns that arrived too short; with
/// the patterns intact there is nothing left to filter.
#[test]
fn the_database_does_not_rename_anything_on_foreign_binaries() {
    let Some(sig) = database() else { return };
    let bins = foreign_binaries();
    if bins.is_empty() {
        return;
    }

    let total: usize = bins.iter().map(|(_, b)| renamed_addresses(&sig, b, 0)).sum();
    eprintln!("falsi positivi a soglia 0 su {} binari: {total}", bins.len());
    assert_eq!(
        total, 0,
        "attesi 0 falsi positivi senza soglia (erano 5071 prima della coda          mascherata), ottenuti {total}: il container avrebbe ripreso a troncare          i pattern al primo wildcard"
    );
}

#[test]
fn raising_the_threshold_monotonically_reduces_false_positives() {
    // A filter can only remove. If a higher threshold ever produced *more*
    // wrong renames, it would be doing something other than filtering.
    let Some(sig) = database() else { return };
    let bins = foreign_binaries();
    if bins.is_empty() {
        return;
    }

    let mut previous = usize::MAX;
    for n in [0usize, 8, 12, 16, 24] {
        let total: usize = bins.iter().map(|(_, b)| renamed_addresses(&sig, b, n)).sum();
        assert!(
            total <= previous,
            "soglia {n}: {total} falsi positivi, ma con la soglia precedente erano {previous}"
        );
        previous = total;
    }
    assert_eq!(previous, 0, "a soglia 24 non deve restare alcun falso positivo");
}
