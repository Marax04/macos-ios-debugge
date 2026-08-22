//! The `.sig` / `RFLIRTBIN` parsers must survive hostile input.
//!
//! # Why this matters here specifically
//!
//! A signature database is **third-party input**. It arrives from a colleague, a
//! vendor, a downloaded pack — exactly like the binary being analysed. A parser
//! that panics on a malformed one takes the whole decompiler down; one that
//! reads out of bounds is worse.
//!
//! These crates parse three such formats, all added or reworked in the last few
//! days: the `IDASGN` header codec, the `.sig` trie loader, and the `RFLIRTBIN`
//! container. Each carries attacker-controlled length fields — `library_name_len`,
//! `prefix_len`, `mask_len`, `name_len`, a pattern `count` — and every one of
//! them is an opportunity to over-read.
//!
//! # Method
//!
//! A deterministic mutation sweep, not random: same seed, same corpus, same
//! result on every run, so a failure is reproducible from the test name alone.
//! Three families, because they break different things:
//!
//! * **truncation** — every prefix of a valid file (missing-length handling);
//! * **single-byte corruption** — walks each offset, hitting length fields
//!   individually (over-read handling);
//! * **length-field saturation** — sets bytes to `0xFF`, the shape that turns a
//!   declared length into a huge allocation or a wild slice.
//!
//! The bar is deliberately low and absolute: **never panic**. Returning an error
//! is success; parsing something odd but bounded is success. Only a crash — or a
//! hang — is failure.

use rustre_flirt::sig_header::SigFileHeader;
use rustre_flirt_apply::sig_file_loader::SigFileLoader;

/// A small, valid `.sig` built through the real writer.
fn valid_sig() -> Vec<u8> {
    use rustre_flirt::{FlirtName, FlirtPattern, PatternByte};
    let mut pats = Vec::new();
    for (i, name) in ["alpha", "beta_function", "gamma"].iter().enumerate() {
        let mut p = FlirtPattern::new(
            (0..12u8).map(|b| PatternByte::Exact(b.wrapping_add(i as u8 * 7))).collect(),
        );
        p.crc16 = 0x1234;
        p.crc_length = 8;
        p.pattern_length = 40;
        p.names.push(FlirtName {
            name: (*name).to_string(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        pats.push(p);
    }
    rustre_flirt_gen::SigWriter::default().build(&pats, "hostile-test")
}

/// A small, valid `RFLIRTBIN` container.
fn valid_rflirt() -> Vec<u8> {
    let mut f = b"RFLIRTBIN\0".to_vec();
    f.extend_from_slice(&2u32.to_le_bytes());
    for name in ["one", "two_longer_name"] {
        let prefix: Vec<u8> = (0..10u8).collect();
        f.extend_from_slice(&(prefix.len() as u16).to_le_bytes());
        f.extend_from_slice(&prefix);
        f.extend_from_slice(&(prefix.len() as u16).to_le_bytes());
        f.extend_from_slice(&vec![0xffu8; prefix.len()]);
        f.extend_from_slice(&0xABCDu16.to_le_bytes());
        f.push(8);
        f.extend_from_slice(&40u16.to_le_bytes());
        f.push(1);
        f.push(0x01);
        f.extend_from_slice(&0u16.to_le_bytes());
        f.extend_from_slice(&(name.len() as u16).to_le_bytes());
        f.extend_from_slice(name.as_bytes());
    }
    f
}

/// Run every parser over `data`. Any panic fails the test by propagating.
fn parse_all(data: &[u8]) {
    let _ = SigFileHeader::decode(data);
    let _ = SigFileLoader::new().load_from_bytes(data, None);
    let _ = rustre_flirt_gen::rflirt_bin::parse(data);
    let _ = rustre_flirt_apply::FlirtScanner::from_sig_bytes(data);
}

/// Guards the sweep itself.
///
/// If the corpus were degenerate — an empty buffer, a wrong magic — every
/// mutation test would pass without exercising a single parser, and a green
/// result would mean nothing. This asserts the base files really are valid and
/// really do parse, so the sweeps around them have something to break.
#[test]
fn the_corpus_the_sweep_mutates_is_actually_valid() {
    let sig = valid_sig();
    let h = SigFileHeader::decode(&sig).expect("il .sig base deve essere valido");
    assert_eq!(h.n_functions, 3, "il corpus deve contenere 3 pattern");
    let loaded = SigFileLoader::new()
        .load_from_bytes(&sig, None)
        .expect("il .sig base deve caricarsi");
    assert_eq!(loaded.to_signatures().len(), 3, "3 firme leggibili");

    let rf = valid_rflirt();
    let pats = rustre_flirt_gen::rflirt_bin::parse(&rf).expect("RFLIRTBIN base valido");
    assert_eq!(pats.len(), 2);
    assert_eq!(pats[0].primary_name(), Some("one"));
}

#[test]
fn truncation_at_every_offset_never_panics() {
    for base in [valid_sig(), valid_rflirt()] {
        for cut in 0..=base.len() {
            parse_all(&base[..cut]);
        }
    }
}

#[test]
fn single_byte_corruption_at_every_offset_never_panics() {
    // Walking every offset guarantees each length field is hit on its own,
    // rather than hoping a random sweep lands on one.
    for base in [valid_sig(), valid_rflirt()] {
        for i in 0..base.len() {
            for replacement in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
                let mut m = base.clone();
                m[i] = replacement;
                parse_all(&m);
            }
        }
    }
}

#[test]
fn saturated_length_fields_never_panic_or_allocate_wildly() {
    // 0xFF..FF in a length field is the classic shape: a declared size far
    // beyond the buffer. It must be rejected, not attempted.
    for base in [valid_sig(), valid_rflirt()] {
        for width in [2usize, 4] {
            for i in 0..base.len().saturating_sub(width) {
                let mut m = base.clone();
                for b in &mut m[i..i + width] {
                    *b = 0xff;
                }
                parse_all(&m);
            }
        }
    }
}

#[test]
fn a_declared_count_of_four_billion_is_rejected_without_allocating() {
    // The specific denial-of-service shape: a tiny file claiming u32::MAX
    // patterns. Rejecting it must not depend on trying to allocate first.
    let mut buf = b"RFLIRTBIN\0".to_vec();
    buf.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(rustre_flirt_gen::rflirt_bin::parse(&buf).is_err());

    let mut hdr = valid_sig();
    hdr[34] = 0xff; // library_name_len oltre la fine
    assert!(SigFileHeader::decode(&hdr).is_err());
}

#[test]
fn random_bytes_are_rejected_not_interpreted() {
    // Deterministic pseudo-random: an xorshift with a fixed seed, so a failure
    // is reproducible without storing a corpus.
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for size in [0usize, 1, 8, 43, 64, 200, 1024] {
        for _ in 0..40 {
            let buf: Vec<u8> = (0..size).map(|_| (next() & 0xff) as u8).collect();
            parse_all(&buf);
        }
    }
}

#[test]
fn a_valid_file_with_a_hostile_prefix_length_is_bounded() {
    // `prefix_len` and `mask_len` must agree; a mismatch is an error, not a
    // read past the buffer.
    let mut buf = valid_rflirt();
    buf[14] = 0xff; // primo prefix_len (dopo magic 10 + count 4)
    buf[15] = 0xff;
    assert!(rustre_flirt_gen::rflirt_bin::parse(&buf).is_err());
}

// ─── ida_sig_compat: un terzo layout, e nessun consumatore ───────────────────

/// `ida_sig_compat::IdaSigHeader` implements **yet another** `IDASGN` layout —
/// library name as a 64-byte NUL-padded field at 22..86, `alt_crc16` at 86 —
/// which matches neither the canonical codec (name at 43, variable length) nor
/// the layout `sig_file_loader` used before it was corrected.
///
/// Measured: nothing outside the module calls it. It is dead code implementing a
/// third incompatible reading of the same format. Recorded rather than deleted
/// (removal is a separate decision), but covered here because it is public API:
/// a consumer of this crate can reach it, so it must not panic on hostile input.
#[test]
fn the_ida_compat_parser_never_panics_on_hostile_input() {
    // A structurally valid header for *its* layout.
    let mut base = vec![0u8; 92];
    base[..6].copy_from_slice(b"IDASGN");
    base[6] = 9;
    base[7] = 0x06;
    base[22..30].copy_from_slice(b"testlib ");

    // Sanity: the corpus must actually parse, or every mutation below proves
    // nothing.
    assert!(
        rustre_flirt_apply::ida_sig_compat::IdaSigHeader::parse(&base).is_ok(),
        "il corpus base deve essere valido per il layout di ida_sig_compat"
    );

    for cut in 0..=base.len() {
        let _ = rustre_flirt_apply::ida_sig_compat::IdaSigHeader::parse(&base[..cut]);
    }
    for i in 0..base.len() {
        for repl in [0x00u8, 0x05, 0x09, 0x0a, 0xff] {
            let mut m = base.clone();
            m[i] = repl;
            let _ = rustre_flirt_apply::ida_sig_compat::IdaSigHeader::parse(&m);
        }
    }
}

#[test]
fn the_ida_compat_hex_pattern_parser_never_panics() {
    for s in [
        "",
        "5",
        "55",
        "..",
        "5548..EC",
        "ZZ",
        "55 48",
        &"AB".repeat(10_000),
        "  ",
        "..........",
    ] {
        let _ = rustre_flirt_apply::ida_sig_compat::parse_hex_pattern(s);
    }
}
