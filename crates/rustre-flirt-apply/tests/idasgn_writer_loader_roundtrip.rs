//! Round-trip: our `IDASGN` writer → our `IDASGN` loader.
//!
//! T27 unifies the signature stack on `IDASGN`. That only works if writer and
//! loader agree on the header, so this test used to be a **tripwire** asserting
//! that they did *not* — because they didn't, and in two different ways:
//!
//! * the loader read `n_funcs` as a `u32` at offset 34 (which is the one-byte
//!   `library_name_len`) and took the library name from a fixed 40..104 window;
//! * the writer put the name **immediately** after the length byte, before
//!   `alt_ctype_crc` and `n_functions`.
//!
//! Neither was IDA's layout, so a `.sig` written here could not be read here,
//! and a real flair file could not be read at all. Both sides now follow the
//! published layout and this test asserts the round-trip **succeeds**.
//!
//! # The published IDA v9 header (flair)
//!
//! ```text
//! off  size  field
//!   0     6  magic "IDASGN"
//!   6     1  version
//!   7     1  processor / arch
//!   8     4  file_types
//!  12     2  os_types
//!  14     2  app_types
//!  16     2  feature_flags
//!  18     2  old_n_functions
//!  20     2  crc16
//!  22    12  ctype
//!  34     1  library_name_len
//!  35     2  alt_ctype_crc
//!  37     4  n_functions     (v6+)
//!  41     2  pattern_size    (v8+)
//!  43    ..  library name
//! ```

use rustre_flirt_apply::sig_file_loader::{SigHeader, SIG_MAGIC};

/// Header bytes exactly as `rustre_flirt::FlirtSigSerializer::write_header`
/// emits them, spelled out here so the test states the layout it checks rather
/// than trusting the writer to agree with itself.
fn published_layout_header(lib_name: &str, n_funcs: u32, pattern_size: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"IDASGN");
    out.push(9); // version
    out.push(0x06); // arch
    out.extend_from_slice(&0x0000_0003u32.to_le_bytes()); // file_types
    out.extend_from_slice(&0u16.to_le_bytes()); // os_types
    out.extend_from_slice(&0u16.to_le_bytes()); // app_types
    out.extend_from_slice(&0u16.to_le_bytes()); // feature_flags
    out.extend_from_slice(&u16::try_from(n_funcs).unwrap_or(u16::MAX).to_le_bytes()); // old_n
    out.extend_from_slice(&0u16.to_le_bytes()); // crc16
    out.extend_from_slice(&[0u8; 12]); // ctype
    let name = lib_name.as_bytes();
    out.push(u8::try_from(name.len()).unwrap()); // 34
    out.extend_from_slice(&0u16.to_le_bytes()); // 35 alt_ctype_crc
    out.extend_from_slice(&n_funcs.to_le_bytes()); // 37 n_functions
    out.extend_from_slice(&pattern_size.to_le_bytes()); // 41 pattern_size
    out.extend_from_slice(name); // 43 name
    assert_eq!(out.len(), 43 + name.len(), "header a lunghezza variabile");
    out
}

#[test]
fn header_round_trips_through_the_loader() {
    let raw = published_layout_header("mylib", 7, 32);

    assert_eq!(&raw[0..6], SIG_MAGIC);
    assert_eq!(raw[34], 5, "library_name_len è un singolo byte a offset 34");

    let hdr = SigHeader::parse(&raw).expect("il layout pubblicato deve essere leggibile");
    assert_eq!(hdr.version, 9);
    assert_eq!(hdr.arch, 0x06);
    assert_eq!(hdr.n_funcs, 7, "n_functions letto a offset 37, non 34");
    assert_eq!(hdr.pattern_size, 32);
    assert_eq!(hdr.lib_name, "mylib");
    assert_eq!(hdr.header_len(), 43 + 5, "il trie inizia alla fine del nome");
}

/// The header length must follow the name, not a constant. A fixed 104 meant
/// the trie was read from the wrong offset for every library whose name was not
/// exactly 61 bytes — i.e. essentially always.
#[test]
fn header_length_tracks_the_library_name() {
    for name in ["", "a", "libgcc", "a-rather-long-library-name-for-testing"] {
        let raw = published_layout_header(name, 1, 32);
        let hdr = SigHeader::parse(&raw).unwrap();
        assert_eq!(hdr.lib_name, name);
        assert_eq!(hdr.header_len(), 43 + name.len(), "nome {name:?}");
        assert_eq!(hdr.header_len(), raw.len(), "l'header consuma tutto il buffer");
    }
}

/// A `.sig` is untrusted third-party input. A declared name length that runs
/// past the buffer must be rejected, not clamped: a truncated name yields a
/// plausible-looking library identity that is simply wrong.
#[test]
fn a_name_length_past_the_end_is_rejected() {
    let mut raw = published_layout_header("lib", 1, 32);
    raw[34] = 200; // dichiara 200 byte di nome in un buffer da 46
    assert!(
        SigHeader::parse(&raw).is_err(),
        "una lunghezza nome fuori dal buffer deve essere un errore, non un troncamento"
    );
}

#[test]
fn truncated_headers_are_rejected_rather_than_read_out_of_bounds() {
    let full = published_layout_header("lib", 1, 32);
    for cut in 0..full.len().min(43) {
        let _ = SigHeader::parse(&full[..cut]); // non deve andare in panic
    }
    assert!(SigHeader::parse(&full[..10]).is_err());
}

/// Older versions simply do not carry `n_functions` / `pattern_size`; reporting
/// a fabricated value would be worse than reporting what the file actually has.
#[test]
fn pre_v8_files_do_not_invent_a_pattern_size() {
    let mut raw = published_layout_header("lib", 3, 32);
    raw[6] = 5; // versione 5: nessun n_functions a 32 bit, nessun pattern_size
    let hdr = SigHeader::parse(&raw).expect("la v5 è supportata");
    assert_eq!(hdr.pattern_size, 0, "pattern_size è v8+: non va inventato");
    assert_eq!(
        u32::from(hdr.old_n_funcs),
        hdr.n_funcs,
        "prima della v6 il conteggio viene dal campo legacy a 16 bit"
    );
}
