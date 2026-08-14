//! `ida_sig_compat` must read the header this workspace writes (T36).
//!
//! # What was measured
//!
//! T36 recorded that `ida_sig_compat` implements "a third IDASGN layout, name at
//! 22..86". Measured (iteration 69): handed a header produced by
//! `rustre_flirt::sig_header` — 61 bytes, the format this workspace both writes
//! and claims to read — `IdaSigHeader::parse` returned **`Truncated`**. It
//! demanded 88 bytes for a fixed 64-byte name field that the published layout
//! does not have.
//!
//! So the module named after IDA compatibility was the one component that could
//! not read an IDA-format header. It now delegates to the canonical codec.
//!
//! This is the **fifth** site found on the wrong header layout: T27 corrected
//! two, iteration 43 found `parse_sig_header`, iteration 45 found
//! `load_sig_file`, and this is the last. Each time the local copy was
//! internally consistent, which is why none of them failed their own tests.

use rustre_flirt::sig_header::SigFileHeader;
use rustre_flirt_apply::ida_sig_compat::IdaSigHeader;

fn canonical(name: &str) -> SigFileHeader {
    let mut h = SigFileHeader::default();
    h.version = 10;
    h.arch = 6;
    h.file_types = 0x0000_0002;
    h.n_functions = 1234;
    h.lib_name = name.to_string();
    h
}

#[test]
fn it_reads_a_header_written_by_the_canonical_codec() {
    let h = canonical("libz mingw64 build");
    let bytes = h.encode();

    let (parsed, consumed) =
        IdaSigHeader::parse(&bytes).expect("deve leggere un header canonico");

    assert_eq!(parsed.library_name, h.lib_name, "nome della libreria perso");
    assert_eq!(parsed.version, h.version);
    assert_eq!(
        parsed.arch,
        rustre_flirt_apply::ida_sig_compat::IdaArch::from_byte(h.arch),
        "architettura decodificata diversamente"
    );
    assert_eq!(parsed.n_modules, h.n_functions, "conteggio funzioni perso");
    assert_eq!(
        consumed,
        h.len_bytes(),
        "l'offset restituito deve essere la lunghezza reale dell'header: se \
         diverge, il trie che segue viene letto disallineato"
    );
}

/// The header is variable length, and that is precisely what the old fixed
/// 64-byte field got wrong. Names of several lengths, including the empty one
/// and one longer than the old field, must all round-trip.
#[test]
fn names_of_every_length_survive() {
    for name in ["", "a", "libz", "libz mingw64 build", &"x".repeat(200)] {
        let h = canonical(name);
        let bytes = h.encode();
        let (parsed, consumed) = IdaSigHeader::parse(&bytes)
            .unwrap_or_else(|e| panic!("nome di {} byte: {e:?}", name.len()));
        assert_eq!(parsed.library_name, name, "nome di {} byte", name.len());
        assert_eq!(consumed, h.len_bytes(), "nome di {} byte", name.len());
        assert_eq!(
            parsed.n_modules, h.n_functions,
            "un nome di {} byte ha spostato la lettura dei campi che lo precedono",
            name.len()
        );
    }
}

#[test]
fn a_bad_magic_is_rejected() {
    let mut bytes = canonical("lib").encode();
    bytes[0] = b'X';
    assert!(
        IdaSigHeader::parse(&bytes).is_err(),
        "un magic errato deve essere rifiutato"
    );
}

#[test]
fn a_truncated_header_is_rejected_without_panicking() {
    let bytes = canonical("libz mingw64 build").encode();
    for cut in 0..bytes.len() {
        // Any prefix must be an error, never a panic: `.sig` files come from
        // outside.
        let _ = IdaSigHeader::parse(&bytes[..cut]);
    }
}
