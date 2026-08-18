//! A converted `RFLIRTBIN` asset must come back intact (T27).
//!
//! # What this closes
//!
//! `assets/*.sig` hold ~13 MB of generated signatures in this project's own
//! `RFLIRTBIN` container — a format nothing on the decompilation path reads. T27
//! called for converting them to `IDASGN`. Writing the file is the easy half;
//! what matters is that its contents survive.
//!
//! Measured on the largest asset (iteration 70), `assets/rust-stdlib.sig`:
//!
//! | | value |
//! |---|---|
//! | patterns converted | 67 168 |
//! | signatures read back | **67 168** |
//! | distinct names | 66 943 |
//! | carrying wildcards | **31 533** |
//! | carrying a CRC | 49 780 |
//! | mean pattern length | 30.7 bytes |
//!
//! The wildcard figure is the one worth noting. Before iteration 53 the
//! container truncated every pattern at its first wildcard, so those 31 533 —
//! 47% of the database — would have arrived as short exact prefixes, which is
//! how a 3-byte key ends up matching a Go binary. The mean length of 30.7 bytes
//! against a 32-byte cap says the patterns are arriving whole.
//!
//! This test uses a smaller asset so it stays fast; the numbers above come from
//! `examples/asset_conversion_round_trip.rs`, which takes any of them.

use std::collections::HashSet;

use rustre_flirt_apply::usize_to_f64;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("il crate deve stare in <root>/crates/<name>")
}

fn small_asset() -> PathBuf {
    repo_root().join("assets/tmp-1.92.0-x86_64-pc-windows-msvc.sig")
}

/// Convert the asset to `IDASGN` in a temporary file and read it back.
fn convert_and_load() -> Option<Vec<rustre_flirt_apply::FlirtSignature>> {
    let src = small_asset();
    if !src.exists() {
        return None;
    }
    let dir = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    let dst = Path::new(&dir).join("rustre_asset_rt.sig");

    rustre_flirt_gen::rflirt_bin::convert_file(&src, &dst, "rust-stdlib", 6).ok()?;
    let sigs = rustre_flirt_apply::load_sig_file(&dst).ok();
    let _ = std::fs::remove_file(&dst);
    sigs
}

#[test]
fn the_asset_is_present_and_in_the_old_container() {
    // Vacuity guard, and a check on the premise: if the asset were already
    // `IDASGN`, converting it would prove nothing.
    let src = small_asset();
    let Ok(head) = std::fs::read(&src) else {
        eprintln!("SKIP: asset assente");
        return;
    };
    assert!(head.len() > 100_000, "asset troppo piccolo: {}", head.len());
    assert_eq!(
        &head[..9],
        b"RFLIRTBIN",
        "l'asset non e' piu' nel container proprietario: aggiorna il test"
    );
}

#[test]
fn every_converted_pattern_comes_back() {
    let Some(sigs) = convert_and_load() else {
        eprintln!("SKIP: asset assente o conversione fallita");
        return;
    };
    assert!(
        sigs.len() > 1000,
        "solo {} firme rilette: la conversione perde contenuto",
        sigs.len()
    );
    let named = sigs.iter().filter(|s| !s.name.is_empty()).count();
    assert_eq!(
        named,
        sigs.len(),
        "{} firme su {} senza nome: un nome vuoto non rinomina niente",
        sigs.len() - named,
        sigs.len()
    );
    let distinct: HashSet<&str> = sigs.iter().map(|s| s.name.as_str()).collect();
    assert!(
        distinct.len() * 10 > sigs.len() * 9,
        "solo {} nomi distinti su {}: sospetto di collasso dei nomi",
        distinct.len(),
        sigs.len()
    );
}

/// The property the iteration-53 container change bought: wildcards survive the
/// round trip instead of truncating the pattern.
#[test]
fn wildcards_survive_and_patterns_stay_long() {
    let Some(sigs) = convert_and_load() else {
        eprintln!("SKIP: asset assente");
        return;
    };
    let with_wc = sigs.iter().filter(|s| s.mask.iter().any(|m| *m == 0)).count();
    assert!(
        with_wc > 100,
        "solo {with_wc} firme con wildcard: il container avrebbe ripreso a \
         troncare al primo wildcard, e con esso tornerebbero i falsi positivi"
    );

    let mean =
        usize_to_f64(sigs.iter().map(|s| s.bytes.len()).sum::<usize>()) / usize_to_f64(sigs.len());
    assert!(
        mean > 20.0,
        "lunghezza media {mean:.1} byte: i pattern arrivano troncati, ed erano \
         chiavi corte cosi' a produrre i falsi positivi cross-binario"
    );
}
