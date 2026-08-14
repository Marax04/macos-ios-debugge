//! End-to-end: a `.sig` written by `rustre-flirt-gen` must be readable by
//! `rustre-flirt-apply`'s loader.
//!
//! The header round-trip test covers the header alone. This one covers the
//! thing that actually matters for T27: a **complete file** — header plus
//! pattern trie — crossing the crate boundary from generator to consumer.
//!
//! Until iteration 10 there were four independent `.sig` header writers and
//! three readers, split across two mutually incompatible layouts, so this
//! crossing was impossible. Everything now goes through the single codec in
//! `rustre_flirt::sig_header`.

use rustre_flirt::sig_header::SigFileHeader;
use rustre_flirt_apply::sig_file_loader::SigFileLoader;
use rustre_flirt_gen::sig_writer::SigWriter;

fn build_sig(lib: &str, arch: u8, funcs: &[(&str, &str, u16, u8, u16)]) -> Vec<u8> {
    let mut w = SigWriter::new(lib, arch);
    for (hex, name, crc16, crc_len, func_len) in funcs {
        w.add_from_hex(hex, *crc16, *crc_len, *func_len, name);
    }
    w.build()
}

#[test]
fn a_generated_sig_header_is_readable_by_the_loader() {
    let bytes = build_sig(
        "testlib",
        75,
        &[("5548..E5C3", "func_a", 0xABCD, 4, 10)],
    );

    // The canonical codec reads it...
    let canonical = SigFileHeader::decode(&bytes).expect("codec canonico");
    assert_eq!(canonical.lib_name, "testlib");
    assert_eq!(canonical.arch, 75);
    assert_eq!(canonical.n_functions, 1);

    // ...and so does the consumer crate's loader, which is the crossing that
    // was broken: generator and loader used to disagree on the layout, so a
    // file written here could not be read there at all.
    let loader = SigFileLoader::new();
    let loaded = loader
        .load_from_bytes(&bytes, None)
        .expect("il loader di flirt-apply deve leggere un .sig scritto da flirt-gen");
    assert_eq!(loaded.header.lib_name, "testlib");
    assert_eq!(loaded.header.arch, 75);
}

#[test]
fn the_library_name_survives_the_crossing_at_several_lengths() {
    // A fixed-size header hid this: the name only round-tripped for one length.
    for name in ["a", "msvcrt", "a-considerably-longer-library-name"] {
        let bytes = build_sig(name, 0, &[("90", "nop_fn", 1, 1, 1)]);
        let loaded = SigFileLoader::new()
            .load_from_bytes(&bytes, None)
            .unwrap_or_else(|e| panic!("nome {name:?}: {e:?}"));
        assert_eq!(loaded.header.lib_name, name);
        assert_eq!(
            loaded.header.header_len(),
            43 + name.len(),
            "il trie deve iniziare subito dopo il nome"
        );
    }
}

#[test]
fn function_count_crosses_intact() {
    let funcs: Vec<(&str, &str, u16, u8, u16)> = vec![
        ("5548", "f1", 0x1111, 2, 5),
        ("564889", "f2", 0x2222, 3, 8),
        ("4883EC", "f3", 0x3333, 3, 9),
    ];
    let bytes = build_sig("multi", 75, &funcs);
    let loaded = SigFileLoader::new().load_from_bytes(&bytes, None).unwrap();
    assert_eq!(
        loaded.header.n_funcs,
        u32::try_from(funcs.len()).unwrap(),
        "n_functions letto a offset 37 dopo il fix, non a 34"
    );
}

/// A generated file must not be mistaken for a valid one after corruption.
/// `.sig` files are untrusted input: they arrive from third parties.
#[test]
fn corrupting_the_declared_name_length_is_rejected_not_absorbed() {
    let mut bytes = build_sig("lib", 0, &[("90", "f", 1, 1, 1)]);
    bytes[34] = 250; // dichiara un nome molto piu' lungo del file
    assert!(
        SigFileLoader::new().load_from_bytes(&bytes, None).is_err(),
        "una lunghezza nome fuori dal buffer deve essere rifiutata"
    );
}

#[test]
fn truncating_a_generated_file_never_panics() {
    let bytes = build_sig("lib", 0, &[("5548", "f", 1, 2, 4)]);
    for cut in 0..bytes.len() {
        let _ = SigFileLoader::new().load_from_bytes(&bytes[..cut], None);
    }
}
