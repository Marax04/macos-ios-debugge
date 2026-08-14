//! Every `SigHeader` decoder must read the canonical bytes the same way (T37).
//!
//! # The family, measured
//!
//! `SigHeader` is declared **five times** across the four crates, all modelling
//! the same IDASGN file header, and no two agree on their fields — they do not
//! even agree on what to call them:
//!
//! | declaration | name field | count field | arch field |
//! |---|---|---|---|
//! | `rustre-flirt/lib.rs` | `library_name` | — | `arch` |
//! | `rustre-flirt-gen/pat_sig_format.rs` | `lib_name` | — | `arch` |
//! | `rustre-flirt-gen/sig_writer.rs` | `library_name` | `num_functions` | `arch` |
//! | `rustre-flirt-apply/sig_file_loader.rs` | `lib_name` | `n_funcs` | `arch` |
//! | `rustre-flirt-apply/sig_parser.rs` | `name` | `n_pats` | `cpu` |
//!
//! T27 introduced `rustre_flirt::sig_header::SigFileHeader` as the canonical
//! codec, after the layout defect recorded in this project's notes: offset 34 is
//! `library_name_len: u8`, not the start of a `u32`, which made the name field
//! variable-length and every fixed-offset reader wrong. Eleven green tests had
//! confirmed the wrong layout, because they asserted against constants derived
//! from it rather than decoding.
//!
//! Unifying five types is a refactor. Verifying they **agree** is a
//! measurement, and it is the part that decides whether the duplication is
//! currently doing damage. That is what this file does, using the same method
//! that found a real bug in the COFF pair one iteration earlier: encode once
//! with the canonical codec, decode with everyone, compare.
//!
//! # Scope
//!
//! Only the decoders reachable through a public entry point are exercised.
//! `sig_writer`'s `SigHeader` is an encoder and appears here through the bytes
//! it produces, not as a decode target.

use rustre_flirt::sig_header::{self, SigFileHeader};

/// A canonical v10 header with a name whose length is deliberately not a round
/// number — a fixed-offset reader that assumes a padded name field will land in
/// the wrong place, which is exactly the defect T27 fixed.
fn canonical_header() -> SigFileHeader {
    let mut h = SigFileHeader::default();
    h.version = 10;
    h.arch = 6;
    h.file_types = 0x0000_0002;
    h.os_types = 0x0001;
    h.app_types = 0x0003;
    h.feature_flags = 0;
    h.n_functions = 4321;
    h.pattern_size = sig_header::DEFAULT_PATTERN_SIZE;
    h.lib_name = "libz mingw64 build".to_string();
    h
}

#[test]
fn the_canonical_codec_round_trips() {
    // The premise everything else rests on. If the canonical codec is not
    // self-consistent, agreement of the others with it means nothing.
    let h = canonical_header();
    let bytes = h.encode();
    let back = SigFileHeader::decode(&bytes).expect("il codec canonico deve rileggersi");

    assert_eq!(back.lib_name, h.lib_name);
    assert_eq!(back.n_functions, h.n_functions);
    assert_eq!(back.arch, h.arch);
    assert_eq!(back.version, h.version);
    assert_eq!(back.pattern_size, h.pattern_size);
}

#[test]
fn the_name_length_lives_at_offset_34_as_a_single_byte() {
    // The layout fact that the five declarations disagreed about, asserted by
    // decoding rather than by restating the constant — the mistake that let
    // eleven tests certify the wrong layout.
    let h = canonical_header();
    let bytes = h.encode();

    assert_eq!(
        usize::from(bytes[sig_header::OFF_NAME_LEN]),
        h.lib_name.len(),
        "offset 34 deve contenere la lunghezza del nome come singolo byte"
    );
    assert_eq!(
        &bytes[sig_header::OFF_NAME..sig_header::OFF_NAME + h.lib_name.len()],
        h.lib_name.as_bytes(),
        "il nome deve iniziare a offset 43"
    );
    assert_eq!(
        bytes.len(),
        h.len_bytes(),
        "len_bytes deve descrivere l'header effettivamente codificato"
    );
}

#[test]
fn the_apply_side_loader_agrees_with_the_canonical_codec() {
    let h = canonical_header();
    let bytes = h.encode();

    let loaded = rustre_flirt_apply::sig_file_loader::SigHeader::parse(&bytes)
        .expect("sig_file_loader deve accettare un header canonico");

    assert_eq!(
        loaded.lib_name, h.lib_name,
        "sig_file_loader legge un nome diverso dal codec canonico"
    );
    assert_eq!(
        u32::from(loaded.arch),
        u32::from(h.arch),
        "sig_file_loader legge un'architettura diversa"
    );
}

#[test]
fn the_flirt_side_parser_agrees_with_the_canonical_codec() {
    let h = canonical_header();
    let bytes = h.encode();

    let (parsed, consumed) =
        rustre_flirt::parse_sig_header(&bytes).expect("rustre-flirt deve accettare un header canonico");

    assert_eq!(
        parsed.library_name, h.lib_name,
        "rustre-flirt::parse_sig_header legge un nome diverso dal codec canonico"
    );
    assert_eq!(
        consumed,
        h.len_bytes(),
        "il parser consuma un numero di byte diverso dalla lunghezza codificata: \
         tutto cio' che segue l'header verrebbe letto disallineato"
    );
}

/// A name length that is not a multiple of anything, plus an empty name and a
/// maximal one. Fixed-offset readers survive the middle case and fail at the
/// edges, so the edges are the test.
#[test]
fn decoders_agree_across_name_lengths() {
    for name in ["", "a", "ab", "libz mingw64 build", &"x".repeat(200)] {
        let mut h = canonical_header();
        h.lib_name = name.to_string();
        let bytes = h.encode();

        let back = SigFileHeader::decode(&bytes)
            .unwrap_or_else(|e| panic!("codec canonico su nome len {}: {e:?}", name.len()));
        assert_eq!(back.lib_name, name);
        assert_eq!(
            back.n_functions, h.n_functions,
            "n_functions corrotto da un nome di lunghezza {}: il campo dopo il \
             nome e' stato letto all'offset sbagliato",
            name.len()
        );

        let (parsed, consumed) = rustre_flirt::parse_sig_header(&bytes)
            .unwrap_or_else(|e| panic!("rustre-flirt su nome len {}: {e:?}", name.len()));
        assert_eq!(parsed.library_name, name, "nome len {}", name.len());
        assert_eq!(consumed, h.len_bytes(), "nome len {}", name.len());
    }
}
