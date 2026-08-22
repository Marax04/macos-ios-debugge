//! No-regression gate for scanner throughput (D9).
//!
//! # Measured baseline, 2026-07-29
//!
//! Database: `assets/rust-stdlib.sig` converted to `IDASGN`, 67 168 signatures,
//! 7.6 MB.
//!
//! | metric | measured |
//! |---|---|
//! | index build | **103 ms** (≈650 signatures/ms) |
//! | scan, `sample3_rust.exe` (79.5 KB) | 148.8 MB/s |
//! | scan, `sample4_go.exe` (534.5 KB) | 235.4 MB/s |
//! | scan, `sample7_cpp.exe` (173.5 KB) | 213.5 MB/s |
//!
//! # Why the thresholds are loose
//!
//! This repo is built concurrently by several agents; a run can land on a
//! machine with every core busy. A gate tuned near the measured value would
//! fail for reasons unrelated to the code, and a test that cries wolf gets
//! disabled — at which point it protects nothing.
//!
//! So the bounds sit roughly an order of magnitude away from the measurement.
//! They catch a **complexity** change — an accidental O(n·m) scan, an index
//! rebuilt per call — not a slow afternoon.
//!
//! Run `cargo run --release -p rustre-flirt-apply --example scan_benchmark` for
//! the actual numbers; this only asserts they have not collapsed.

use std::path::{Path, PathBuf};

use rustre_flirt_apply::usize_to_f64;
use std::time::{Duration, Instant};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("il crate deve stare in <root>/crates/<name>")
}

/// The real database, converted. `None` in a checkout without the asset.
fn database() -> Option<Vec<u8>> {
    let raw = std::fs::read(repo_root().join("assets/rust-stdlib.sig")).ok()?;
    rustre_flirt_gen::rflirt_bin::to_sig_bytes(&raw, "rust-stdlib", 75).ok()
}

fn corpus_binary(name: &str) -> Option<Vec<u8>> {
    std::fs::read(repo_root().join("tests/decompiler_corpus/bin").join(name)).ok()
}

#[test]
fn building_the_index_from_67k_signatures_stays_under_a_few_seconds() {
    let Some(sig) = database() else {
        eprintln!("assets/rust-stdlib.sig assente — test saltato");
        return;
    };

    let t = Instant::now();
    let scanner = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig).expect("scanner");
    let elapsed = t.elapsed();

    let n = scanner.signature_count();
    eprintln!("build: {n} firme in {elapsed:?}");

    // Guard against a vacuous pass: a database that failed to load would build
    // instantly and sail through the timing assertion below.
    assert!(n > 1000, "solo {n} firme caricate: il test non misura nulla");

    // Measured at 103 ms. 30x that catches an index rebuilt per signature.
    assert!(
        elapsed < Duration::from_secs(3),
        "la costruzione dell'indice ha richiesto {elapsed:?} (misurato: ~103 ms)"
    );
}

#[test]
fn scanning_throughput_has_not_collapsed() {
    let Some(sig) = database() else { return };
    let Some(bin) = corpus_binary("sample4_go.exe") else {
        eprintln!("binario del corpus assente — test saltato");
        return;
    };
    let Ok(pe) = rustre_pe_tools::PeFile::parse(&bin) else { return };

    let scanner = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig).expect("scanner");

    let mut byte_total = 0usize;
    let t = Instant::now();
    for s in &pe.sections {
        if s.characteristics & 0x2000_0000 == 0 || s.data.is_empty() {
            continue;
        }
        byte_total += s.data.len();
        let va = pe.image_base + u64::from(s.virtual_address);
        let _ = scanner.scan_fast(&s.data, va);
    }
    let elapsed = t.elapsed();

    assert!(byte_total > 100_000, "solo {byte_total} byte scansionati: test vacuo");

    let mbs = (usize_to_f64(byte_total) / (1024.0 * 1024.0)) / elapsed.as_secs_f64().max(1e-9);
    eprintln!("scan: {byte_total} byte in {elapsed:?} = {mbs:.1} MB/s");

    // Measured at 235 MB/s. 10 MB/s is ~23x slower: reachable only by a
    // complexity change, not by a busy machine.
    assert!(
        mbs > 10.0,
        "throughput sceso a {mbs:.1} MB/s (misurato: ~235 MB/s)"
    );
}

#[test]
fn scan_cost_grows_with_input_not_with_the_square_of_it() {
    // The property that actually matters: scanning a bigger section must not
    // cost disproportionately more. An accidental restart of the match loop per
    // signature would show up here long before the absolute bounds above trip.
    let Some(sig) = database() else { return };
    let scanner = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig).expect("scanner");

    let small = vec![0x90u8; 64 * 1024];
    let large = vec![0x90u8; 640 * 1024];

    let t = Instant::now();
    let _ = scanner.scan_fast(&small, 0x1000);
    let t_small = t.elapsed().max(Duration::from_micros(100));

    let t = Instant::now();
    let _ = scanner.scan_fast(&large, 0x1000);
    let t_large = t.elapsed().max(Duration::from_micros(100));

    let ratio = t_large.as_secs_f64() / t_small.as_secs_f64();
    eprintln!("10x input -> {ratio:.1}x tempo ({t_small:?} -> {t_large:?})");
    assert!(
        ratio < 60.0,
        "10x l'input è costato {ratio:.1}x il tempo: atteso ~10x, oltre 60x \
         indica una regressione di complessità"
    );
}

#[test]
fn the_scanner_is_reusable_without_rebuilding_the_index() {
    // Scanning twice with the same scanner must cost about the same as once
    // each: if the second call were rebuilding the index, this ratio explodes.
    let Some(sig) = database() else { return };
    let scanner = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig).expect("scanner");
    let data = vec![0x55u8; 256 * 1024];

    let t = Instant::now();
    let _ = scanner.scan_fast(&data, 0x1000);
    let first = t.elapsed().max(Duration::from_micros(100));

    let t = Instant::now();
    for _ in 0..5 {
        let _ = scanner.scan_fast(&data, 0x1000);
    }
    let five = t.elapsed();

    let ratio = five.as_secs_f64() / first.as_secs_f64();
    eprintln!("5 scansioni / 1 scansione = {ratio:.1}x");
    assert!(
        ratio < 30.0,
        "5 scansioni sono costate {ratio:.1}x una sola: l'indice viene \
         probabilmente ricostruito a ogni chiamata"
    );
}
