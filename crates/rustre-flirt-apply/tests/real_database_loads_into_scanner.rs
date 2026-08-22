//! The repo's real signature database must load into a working scanner.
//!
//! Everything before this test used synthetic one- or two-pattern files. This
//! one takes `assets/rust-stdlib.sig` — 10.8 MB of generated signatures that no
//! part of the decompilation path could read — converts it to `IDASGN`, and
//! builds a scanner from it.
//!
//! The number to compare against is **22**: the total signatures in the two
//! `.sigpack` files the decompiler actually uses.
//!
//! Skipped, loudly, when the asset is absent from a checkout.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("il crate deve stare in <root>/crates/<name>")
}

fn load_asset() -> Option<Vec<u8>> {
    let p = repo_root().join("assets/rust-stdlib.sig");
    let Ok(b) = std::fs::read(&p) else {
        eprintln!("assets/rust-stdlib.sig assente in questo checkout — test saltato");
        return None;
    };
    Some(b)
}

#[test]
fn the_real_database_converts_and_builds_a_scanner() {
    let Some(raw) = load_asset() else { return };

    assert!(
        raw.starts_with(b"RFLIRTBIN\0"),
        "l'asset non è nel formato atteso"
    );

    let sig = rustre_flirt_gen::rflirt_bin::to_sig_bytes(&raw, "rust-stdlib", 75)
        .expect("il database reale deve convertirsi");

    let scanner = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig)
        .expect("il .sig convertito deve produrre uno scanner");

    let n = scanner.signature_count();
    eprintln!("firme caricate dal database reale: {n}");

    // The number that matters: 22 is the decompiler's entire FLIRT capability
    // today, across both hand-written `.sigpack` files.
    //
    // This assertion used to read `assert_eq!(n, 1)` — a tripwire, because the
    // trie decoder returned exactly one node no matter how many patterns the
    // file held. Fixed in iteration 16: the writer omitted the extra-names
    // terminator, so the decoder read the next node's prefix-length byte as an
    // extra-name length and desynchronised after the first leaf.
    assert!(
        n > 1000,
        "atteso un database molto piu' grande dei 22 sigpack, ottenute {n} firme"
    );

    // Nothing may be lost in the crossing: every converted pattern must survive
    // as a signature. `>` alone would hide losing 90% of them.
    let pats = rustre_flirt_gen::rflirt_bin::parse(&raw).expect("parse");
    assert_eq!(
        n,
        pats.len(),
        "convertiti {} pattern ma lo scanner ne espone {n}",
        pats.len()
    );
}

#[test]
fn every_loaded_signature_carries_a_name() {
    let Some(raw) = load_asset() else { return };
    let pats = rustre_flirt_gen::rflirt_bin::parse(&raw).expect("parse del database reale");

    // A nameless signature cannot rename anything: it would inflate the count
    // while contributing nothing, which is exactly the kind of number that
    // makes a metric look better than the tool.
    let unnamed = pats.iter().filter(|p| p.names.is_empty()).count();
    assert_eq!(unnamed, 0, "{unnamed} pattern senza alcun nome");
}

#[test]
fn conversion_preserves_the_pattern_count() {
    let Some(raw) = load_asset() else { return };
    let pats = rustre_flirt_gen::rflirt_bin::parse(&raw).expect("parse");
    let sig = rustre_flirt_gen::rflirt_bin::to_sig_bytes(&raw, "rust-stdlib", 75).expect("convert");

    let h = rustre_flirt::sig_header::SigFileHeader::decode(&sig).expect("header");
    assert_eq!(
        h.n_functions as usize,
        pats.len(),
        "il .sig deve dichiarare tutti i pattern convertiti"
    );
}
