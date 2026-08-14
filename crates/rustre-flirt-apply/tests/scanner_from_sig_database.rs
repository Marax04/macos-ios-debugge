//! A scanner must be buildable from a `.sig` database, not only from `.sigpack`.
//!
//! # The bottleneck this removes
//!
//! The decompiler's FLIRT capability was **22 hand-written signatures** — 8 in
//! `msvcrt-x64.sigpack`, 14 in `rust-stdlib-x64.sigpack` — because
//! `FlirtScanner` could only be built from `SignaturePack`, which only parses
//! the `SIGPACK 1` text format. The loader could read a binary `.sig`, but no
//! path led from a loaded `.sig` to a scanner.
//!
//! Every downstream improvement was therefore inert: better prototypes, a
//! working Level 7 bridge and a correct matcher cannot help when the
//! *identification* step has 22 candidates. This test pins the new path open.

use std::io::Write;

// NOTE: `FlirtPattern` exists in BOTH `rustre-flirt` and `rustre-flirt-apply`
// as two unrelated types. `SignaturePack` holds the apply-crate one, so that is
// what a pack must be built from. Recorded as its own defect (see TODO T29);
// this test uses the correct type rather than papering over it.
use rustre_flirt_apply::{FlirtPattern, FlirtScanner, SignaturePack};

/// A `.sig` holding one function whose first bytes are `55 48 89 E5`.
///
/// Built with `rustre_flirt_gen::SigWriter` (the one in `lib.rs`, used by
/// `write_sig_file`). NOT with `rustre_flirt_gen::sig_writer::SigWriter`: the
/// two are different types with **incompatible trie encodings**, and only this
/// one produces a body the loader can read. See TODO T30.
fn sig_with(name: &str, bytes: &[u8]) -> Vec<u8> {
    use rustre_flirt::{FlirtName, PatternByte};
    let mut pat = rustre_flirt::FlirtPattern::new(
        bytes.iter().map(|b| PatternByte::Exact(*b)).collect(),
    );
    pat.names.push(FlirtName {
        name: name.to_string(),
        offset: 0,
        is_public: true,
        is_local: false,
    });
    pat.pattern_length = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    rustre_flirt_gen::SigWriter::default().build(&[pat], "testlib")
}

/// A `.sigpack` holding one differently-named function.
fn pack_with(name: &str, bytes: &[u8]) -> SignaturePack {
    let pat = FlirtPattern {
        bytes: bytes.iter().map(|b| Some(*b)).collect(),
        name: name.to_string(),
        lib_name: "curated".into(),
        version: String::new(),
        crc_offset: 0,
        crc_len: 0,
        crc: 0,
        public_names: Vec::new(),
        local_names: Vec::new(),
        references: Vec::new(),
    };
    SignaturePack { name: "curated".into(), patterns: vec![pat] }
}

#[test]
fn a_scanner_can_be_built_from_sig_bytes() {
    let raw = sig_with("from_database", &[0x55, 0x48, 0x89, 0xE5]);
    let scanner = FlirtScanner::from_sig_bytes(&raw)
        .expect("un .sig valido deve produrre uno scanner");
    assert!(
        scanner.signature_count() > 0,
        "lo scanner costruito da .sig non contiene firme"
    );
}

#[test]
fn a_scanner_can_be_built_from_a_sig_file_on_disk() {
    let raw = sig_with("from_disk", &[0x55, 0x48, 0x89, 0xE5]);
    let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
    tmp.write_all(&raw).expect("write");
    tmp.flush().expect("flush");

    let scanner = FlirtScanner::from_sig_file(tmp.path())
        .expect("un .sig su disco deve produrre uno scanner");
    assert!(scanner.signature_count() > 0);
}

/// The point of the whole exercise: curated packs and a generated database must
/// combine, so adopting a `.sig` never means losing the hand-checked entries.
#[test]
fn packs_and_sig_databases_combine_into_one_scanner() {
    let raw = sig_with("from_database", &[0x55, 0x48, 0x89, 0xE5]);
    let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
    tmp.write_all(&raw).expect("write");
    tmp.flush().expect("flush");

    let pack = pack_with("from_pack", &[0x48, 0x83, 0xEC, 0x28]);

    let only_pack = FlirtScanner::from_packs(std::slice::from_ref(&pack));
    let combined = FlirtScanner::from_packs_and_sig_files(
        std::slice::from_ref(&pack),
        &[tmp.path().to_path_buf()],
    )
    .expect("pack + .sig devono combinarsi");

    assert!(
        combined.signature_count() > only_pack.signature_count(),
        "combinando pack e database il conteggio deve crescere: {} vs {}",
        combined.signature_count(),
        only_pack.signature_count()
    );
}

#[test]
fn an_empty_pack_list_with_no_sig_files_yields_an_empty_scanner() {
    let s = FlirtScanner::from_packs_and_sig_files(&[], &[]).expect("nessun input è valido");
    assert_eq!(s.signature_count(), 0);
}

/// A `.sig` is untrusted third-party input: garbage must be an error, never a
/// silently empty scanner that would look like "no matches found".
#[test]
fn a_corrupt_sig_is_an_error_not_a_silently_empty_scanner() {
    assert!(FlirtScanner::from_sig_bytes(&[0xFF; 200]).is_err());
    assert!(FlirtScanner::from_sig_bytes(b"IDASGN").is_err(), "header troncato");
    assert!(FlirtScanner::from_sig_bytes(&[]).is_err());
}

#[test]
fn a_missing_sig_path_is_an_error() {
    let missing = std::path::Path::new("this-file-does-not-exist.sig");
    assert!(FlirtScanner::from_sig_file(missing).is_err());
}

/// Both `.sig` writers must now round-trip through the loader.
///
/// Until iteration 14 `sig_writer::SigWriter` encoded the trie body in a format
/// `sig_file_loader` could not read, so a file it produced yielded **zero**
/// signatures — a silently empty scanner, downstream indistinguishable from
/// "this binary contains no known functions". It now delegates to the one
/// encoding the loader understands.
#[test]
fn both_writers_produce_a_readable_trie() {
    let mut w = rustre_flirt_gen::sig_writer::SigWriter::new("testlib", 75);
    w.add_from_hex("5548 89E5", 0, 0, 8, "orphan");
    let raw = w.build();

    let h = rustre_flirt::sig_header::SigFileHeader::decode(&raw)
        .expect("header canonico");
    assert_eq!(h.n_functions, 1);

    let loaded = rustre_flirt_apply::sig_file_loader::SigFileLoader::new()
        .load_from_bytes(&raw, None)
        .expect("il file deve caricarsi");
    let sigs = loaded.to_signatures();
    assert_eq!(sigs.len(), 1, "il trie del secondo writer deve essere leggibile");
    assert_eq!(sigs[0].name, "orphan");
}

/// And the two writers must agree with each other, not merely both be readable.
#[test]
fn the_two_writers_agree_on_the_same_input() {
    use rustre_flirt::{FlirtName, PatternByte};

    let bytes = [0x55u8, 0x48, 0x89, 0xE5];
    let name = "same_fn";

    let mut a = rustre_flirt_gen::sig_writer::SigWriter::new("testlib", 75);
    a.add_from_hex("5548 89E5", 0, 0, 8, name);
    let from_a = a.build();

    let mut pat = rustre_flirt::FlirtPattern::new(
        bytes.iter().map(|b| PatternByte::Exact(*b)).collect(),
    );
    pat.names.push(FlirtName {
        name: name.to_string(),
        offset: 0,
        is_public: true,
        is_local: false,
    });
    pat.pattern_length = 8;
    let from_b = rustre_flirt_gen::SigWriter {
        arch: 75,
        ..rustre_flirt_gen::SigWriter::default()
    }
    .build(&[pat], "testlib");

    let loader = rustre_flirt_apply::sig_file_loader::SigFileLoader::new();
    let na: Vec<String> = loader
        .load_from_bytes(&from_a, None)
        .expect("writer A")
        .to_signatures()
        .into_iter()
        .map(|s| s.name)
        .collect();
    let nb: Vec<String> = loader
        .load_from_bytes(&from_b, None)
        .expect("writer B")
        .to_signatures()
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(na, nb, "i due writer devono produrre le stesse firme");
    assert_eq!(na, vec![name.to_string()]);
}
