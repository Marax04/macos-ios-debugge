//! The crate's two COFF decoders must decode the same bytes the same way (T37).
//!
//! # Why this pair, out of 50
//!
//! Iteration 41 classified the 52 duplicated public types: 50 diverge on their
//! fields, but most of those are harmless name collisions across crates. This
//! pair is different, and it is why it was picked as the next target:
//! `CoffSection` and `CoffSymbol` are each declared **twice inside
//! `rustre-flirt-gen`** — `library_scanner.rs` and `pattern_extractor.rs` — so
//! there are two decoders of one file format in one crate. That cannot be
//! coincidence, and unlike the cross-crate collisions it has published ground
//! truth: the PE/COFF section header layout.
//!
//! # What was measured
//!
//! On the shared fields the two agree on offsets (8/12/16/20/36), so a
//! well-formed object decodes identically. They disagree on **name decoding**:
//!
//! | decoder | rule |
//! |---|---|
//! | `library_scanner` | truncate at the first NUL |
//! | `pattern_extractor` | `trim_end_matches('\0')` — strip *trailing* NULs |
//!
//! A COFF section name is an 8-byte field, NUL-**padded**. The two rules
//! coincide only when the padding is all zeroes, which is what a linker emits —
//! so this never shows up on real objects and never would have been found by
//! spot-checking one. On a name with a NUL followed by any non-zero byte,
//! `trim_end_matches` strips nothing and yields a `String` with an embedded NUL
//! and trailing garbage, while the other yields the real name.
//!
//! That input is not hypothetical for this crate: `flirt-gen` ingests
//! third-party `.lib` archives, and the hostile-input suites in this project
//! exist because those bytes are not trusted. A section name is not cosmetic
//! either — `is_code`/`is_executable` filtering and name-based section lookup
//! decide which bytes become signature patterns.
//!
//! The fix applied is the one the format specifies: truncate at the first NUL,
//! in both. These tests pin the agreement so the decoders cannot drift apart
//! again while they remain two.

use rustre_flirt_gen::library_scanner;
use rustre_flirt_gen::pattern_extractor::ObjParser;

const MACHINE_X64: u16 = 0x8664;

/// Build a minimal single-section COFF object whose section name is `name8`.
fn coff_object_with_section_name(name8: [u8; 8]) -> Vec<u8> {
    let mut o = Vec::new();
    // ── COFF file header (20 bytes) ──
    o.extend_from_slice(&MACHINE_X64.to_le_bytes()); // machine
    o.extend_from_slice(&1u16.to_le_bytes()); // number_of_sections
    o.extend_from_slice(&0u32.to_le_bytes()); // time_date_stamp
    o.extend_from_slice(&0u32.to_le_bytes()); // pointer_to_symbol_table
    o.extend_from_slice(&0u32.to_le_bytes()); // number_of_symbols
    o.extend_from_slice(&0u16.to_le_bytes()); // size_of_optional_header
    o.extend_from_slice(&0u16.to_le_bytes()); // characteristics

    // ── section header (40 bytes) ──
    o.extend_from_slice(&name8); // 0: name
    o.extend_from_slice(&0x10u32.to_le_bytes()); // 8: virtual_size
    o.extend_from_slice(&0x20u32.to_le_bytes()); // 12: virtual_address
    o.extend_from_slice(&0x10u32.to_le_bytes()); // 16: size_of_raw_data
    o.extend_from_slice(&60u32.to_le_bytes()); // 20: pointer_to_raw_data
    o.extend_from_slice(&0u32.to_le_bytes()); // 24: pointer_to_relocations
    o.extend_from_slice(&0u32.to_le_bytes()); // 28: pointer_to_linenumbers
    o.extend_from_slice(&0u16.to_le_bytes()); // 32: number_of_relocations
    o.extend_from_slice(&0u16.to_le_bytes()); // 34: number_of_linenumbers
    o.extend_from_slice(&0x6000_0020u32.to_le_bytes()); // 36: characteristics (CODE|EXECUTE)

    // ── section payload ──
    o.extend_from_slice(&[0x90u8; 16]);
    o
}

fn names_from_both(obj: &[u8]) -> (String, String) {
    let (_hdr, sections, _syms) =
        library_scanner::parse_coff_object(obj).expect("library_scanner deve accettare l'oggetto");
    let parser = ObjParser::parse(obj).expect("pattern_extractor deve accettare l'oggetto");

    let a = sections.first().expect("una sezione").name.clone();
    let b = parser.sections.first().expect("una sezione").name.clone();
    (a, b)
}

#[test]
fn a_normally_padded_name_decodes_identically() {
    // The case that always worked, kept as the control: if this ever fails, the
    // divergence is not the one documented here.
    let (a, b) = names_from_both(&coff_object_with_section_name(*b".text\0\0\0"));
    assert_eq!(a, ".text");
    assert_eq!(a, b, "i due decoder divergono gia' sul caso ben formato");
}

#[test]
fn a_full_eight_byte_name_decodes_identically() {
    // No NUL at all: the field is exactly full. Neither rule has anything to
    // strip, so agreement here says nothing about the padding rules — included
    // so the boundary is covered rather than assumed.
    let (a, b) = names_from_both(&coff_object_with_section_name(*b".xdata12"));
    assert_eq!(a, ".xdata12");
    assert_eq!(a, b);
}

#[test]
fn a_name_with_an_embedded_nul_decodes_identically() {
    // The divergence. `trim_end_matches('\0')` strips nothing here, because the
    // last byte is not NUL — so the buggy rule yields ".text\0AB".
    let (a, b) = names_from_both(&coff_object_with_section_name(*b".text\0AB"));
    assert_eq!(
        a, ".text",
        "il nome COFF e' NUL-padded: va troncato al primo NUL"
    );
    assert_eq!(
        a, b,
        "i due decoder dello stesso formato, nello stesso crate, danno nomi \
         diversi per gli stessi byte"
    );
}

#[test]
fn a_decoded_name_never_contains_a_nul() {
    // Stated as a property rather than a case: whatever the padding looks like,
    // a decoded name is a name. A `String` carrying an interior NUL breaks
    // comparison, lookup and anything that later hands it to a C API.
    for pattern in [
        *b".text\0AB",
        *b"\0\0\0\0\0\0\0\0",
        *b".d\0\0\0\0\0x",
        *b".rdata\0\x01",
    ] {
        let (a, b) = names_from_both(&coff_object_with_section_name(pattern));
        assert!(!a.contains('\0'), "library_scanner: NUL interno in {a:?}");
        assert!(!b.contains('\0'), "pattern_extractor: NUL interno in {b:?}");
        assert_eq!(a, b, "decoder in disaccordo su {pattern:?}");
    }
}

#[test]
fn the_shared_numeric_fields_agree() {
    // The offsets were already consistent; pinned so that unifying the two
    // structs later cannot silently shift one of them. `pattern_extractor`'s
    // type is the superset and uses the published PE/COFF field names, which is
    // why it is the one to keep when these finally become one type.
    let obj = coff_object_with_section_name(*b".text\0\0\0");
    let (_hdr, sections, _syms) = library_scanner::parse_coff_object(&obj).expect("parse");
    let parser = ObjParser::parse(&obj).expect("parse");

    let s = sections.first().expect("una sezione");
    let p = parser.sections.first().expect("una sezione");

    assert_eq!(s.virtual_size, p.virtual_size);
    assert_eq!(s.virtual_addr, p.virtual_address);
    assert_eq!(s.raw_size, p.size_of_raw_data);
    assert_eq!(s.raw_offset, p.pointer_to_raw_data);
    assert_eq!(s.characteristics, p.characteristics);
    assert!(p.is_code() && p.is_executable(), "caratteristiche CODE|EXECUTE");
}
