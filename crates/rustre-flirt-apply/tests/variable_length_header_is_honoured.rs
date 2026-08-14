//! Every `.sig` reader must honour the variable-length header.
//!
//! The IDA header is `43 + library_name_len` bytes. Seven sites in this stack
//! assumed a fixed 104, and each one failed differently:
//!
//! * writers padded the name into a 40..104 window nobody else reads;
//! * parsers read `n_functions` as a `u32` at offset 34, which is the one-byte
//!   `library_name_len`;
//! * `inspect_sig_header` read exactly 104 bytes from disk and treated a
//!   shorter read as "old format", silently returning a **nameless** header for
//!   any file whose library name was short enough to fit under 104 bytes — i.e.
//!   for essentially every valid file.
//!
//! That last one is the reason this test exists as its own file: it was not
//! caught by the header round-trip tests, because it is not a layout bug. It is
//! a bug about *how much of the file you read before decoding*, and only a test
//! that goes through the filesystem can see it.

use std::io::Write;

use rustre_flirt::sig_header::SigFileHeader;

fn write_sig(name: &str) -> tempfile::NamedTempFile {
    let bytes = SigFileHeader {
        version: 9,
        arch: 75,
        pattern_size: 32,
        n_functions: 0,
        lib_name: name.to_string(),
        ..SigFileHeader::default()
    }
    .encode();
    let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
    tmp.write_all(&bytes).expect("write");
    tmp.write_all(&[0x00]).expect("sentinel"); // end-of-trie
    tmp.flush().expect("flush");
    tmp
}

#[test]
fn short_library_names_are_not_silently_dropped() {
    // Every one of these produces a file **shorter than 104 bytes**, which is
    // exactly the case the fixed-size read mishandled.
    for name in ["a", "libc", "msvcrt", "inspector_lib"] {
        let tmp = write_sig(name);
        let hdr = rustre_flirt_apply::inspect_sig_header(tmp.path())
            .unwrap_or_else(|e| panic!("nome {name:?}: {e:?}"));
        assert_eq!(hdr.lib_name, name, "il nome della libreria è stato perso");
        assert_eq!(hdr.version, 9);
        assert_eq!(hdr.arch, 75);
        assert_eq!(hdr.pattern_size, 32);
    }
}

#[test]
fn names_longer_than_the_old_fixed_window_still_work() {
    // The old layout capped the name at 63 bytes (a 64-byte padded window).
    // The format's real ceiling is 255, since the length is one byte.
    for len in [64usize, 100, 200, 255] {
        let name = "x".repeat(len);
        let tmp = write_sig(&name);
        let hdr = rustre_flirt_apply::inspect_sig_header(tmp.path())
            .unwrap_or_else(|e| panic!("lunghezza {len}: {e:?}"));
        assert_eq!(hdr.lib_name.len(), len, "nome troncato a {}", hdr.lib_name.len());
    }
}

#[test]
fn an_empty_library_name_is_valid_and_stays_empty() {
    let tmp = write_sig("");
    let hdr = rustre_flirt_apply::inspect_sig_header(tmp.path()).expect("nome vuoto è valido");
    assert_eq!(hdr.lib_name, "");
    assert_eq!(hdr.version, 9);
}

/// A file that is genuinely too short must be an error, not a stub with
/// plausible-looking defaults — `.sig` files are untrusted input, and a header
/// invented from nothing is worse than a refusal.
#[test]
fn a_genuinely_truncated_file_is_rejected() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(b"IDASGN\x09\x4b").unwrap(); // solo 8 byte
    tmp.flush().unwrap();
    assert!(
        rustre_flirt_apply::inspect_sig_header(tmp.path()).is_err(),
        "un header troncato deve essere rifiutato, non completato con default"
    );
}

#[test]
fn a_bad_magic_is_rejected_regardless_of_length() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&vec![0xFFu8; 300]).unwrap();
    tmp.flush().unwrap();
    assert!(rustre_flirt_apply::inspect_sig_header(tmp.path()).is_err());
}
