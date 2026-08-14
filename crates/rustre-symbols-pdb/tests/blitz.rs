//! Exhaustive blitz test suite for `rustre-symbols-pdb`.
//!
//! Targets the public API surface re-exposed via `lib.rs`, plus the
//! standalone parser modules (`pdb_omap`, `section_contributions`,
//! `stream_reader`, `tpi_types`, `global_symbols`).

use rustre_symbols_pdb::{
    PdbAge, PdbError, PdbGuid, PdbModule, PdbPublicSymbol, PdbPublicSymbolScanner, PdbReader,
    PdbStreamInfo, PdbStreamReader, PdbSymbol, PdbType, SymbolKind, TypeKind, stream_indices,
};
use rustre_symbols_pdb::pdb_omap::{OmapEntry, OmapError, OmapKind, PdbOmap, OmapStatistics};
use rustre_symbols_pdb::section_contributions::{
    SectionContrib, find_module_for_address, find_module_sorted, parse_section_contribs,
    sort_contribs,
};
use rustre_symbols_pdb::stream_reader::{StreamReader, StringTable, RecordHeader};
use rustre_symbols_pdb::tpi_types::{
    LeafKind, TpiHeader, TpiRecord, TpiTypeData, TypeDb, TypeIndex,
};
use rustre_symbols_pdb::global_symbols::{
    GlobalSymKind, GlobalSymbol, SymFlags, parse_global_symbols,
};

// ─────────────────────────────────────────────────────────────────────────────
// PdbGuid
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn guid_format_total_length() {
    let g = PdbGuid { data: [0u8; 16] };
    assert_eq!(g.to_string_fmt().len(), 38);
}

#[test]
fn guid_format_all_ff() {
    let g = PdbGuid { data: [0xFF; 16] };
    let s = g.to_string_fmt();
    assert!(s.starts_with('{') && s.ends_with('}'));
    // 32 hex chars + 4 dashes + 2 braces = 38
    assert_eq!(s.len(), 38);
    assert!(s.chars().filter(|c| *c == '-').count() == 4);
}

#[test]
fn guid_equality() {
    let a = PdbGuid { data: [1u8; 16] };
    let b = PdbGuid { data: [1u8; 16] };
    let c = PdbGuid { data: [2u8; 16] };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ─────────────────────────────────────────────────────────────────────────────
// PdbAge
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn age_zero_and_max() {
    assert_eq!(PdbAge(0).0, 0);
    assert_eq!(PdbAge(u32::MAX).0, u32::MAX);
}

// ─────────────────────────────────────────────────────────────────────────────
// PdbReader::from_bytes — bad inputs
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn from_bytes_empty_is_bad_magic() {
    assert!(matches!(
        PdbReader::from_bytes(&[]),
        Err(PdbError::BadMagic)
    ));
}

#[test]
fn from_bytes_short_is_bad_magic() {
    assert!(matches!(
        PdbReader::from_bytes(&[0u8; 8]),
        Err(PdbError::BadMagic)
    ));
}

#[test]
fn from_bytes_garbage_512_is_bad_magic() {
    assert!(matches!(
        PdbReader::from_bytes(&vec![0u8; 512]),
        Err(PdbError::BadMagic)
    ));
}

#[test]
fn from_bytes_magic_only_56_bytes_no_streams() {
    // 32 byte magic + minimal header but zero block_size triggers CorruptData.
    let mut v = vec![0u8; 56];
    v[0..32].copy_from_slice(b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00");
    // block_size left at zero
    match PdbReader::from_bytes(&v) {
        Err(PdbError::CorruptData | PdbError::StreamTooShort | PdbError::BadMagic) => {}
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(_) => panic!("expected error from zero block_size"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PdbStreamReader (parse_pdb_info / parse_stream_names)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stream_reader_parse_info_none_on_garbage() {
    assert!(PdbStreamReader::parse_pdb_info(&[0u8; 64]).is_none());
}

#[test]
fn stream_reader_parse_names_empty_on_garbage() {
    assert!(PdbStreamReader::parse_stream_names(&[0u8; 64]).is_empty());
}

#[test]
fn stream_reader_parse_names_empty_on_empty() {
    assert!(PdbStreamReader::parse_stream_names(&[]).is_empty());
}

#[test]
fn pdb_stream_info_construct() {
    let info = PdbStreamInfo {
        version: 1,
        signature: 2,
        age: 3,
        guid: [9u8; 16],
    };
    assert_eq!(info.version, 1);
    assert_eq!(info.guid[0], 9);
}

#[test]
fn stream_indices_well_known() {
    assert_eq!(stream_indices::OLD_DIRECTORY, 0);
    assert_eq!(stream_indices::PDB_INFO, 1);
    assert_eq!(stream_indices::TPI, 2);
    assert_eq!(stream_indices::DBI, 3);
    assert_eq!(stream_indices::IPI, 4);
}

// ─────────────────────────────────────────────────────────────────────────────
// PdbPublicSymbolScanner
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pub_scanner_empty_on_garbage() {
    let syms = PdbPublicSymbolScanner::scan_public_symbols(&[0u8; 128]);
    assert!(syms.is_empty());
}

#[test]
fn pub_scanner_empty_on_empty() {
    assert!(PdbPublicSymbolScanner::scan_public_symbols(&[]).is_empty());
}

#[test]
fn pdb_public_symbol_eq() {
    let a = PdbPublicSymbol { name: "x".into(), offset: 1, section: 2 };
    let b = a.clone();
    assert_eq!(a, b);
}

// ─────────────────────────────────────────────────────────────────────────────
// Core public types
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn symbol_kind_distinct() {
    assert_ne!(SymbolKind::Function, SymbolKind::Data);
    assert_ne!(SymbolKind::Function, SymbolKind::Label);
    assert_ne!(SymbolKind::Function, SymbolKind::Thunk);
    assert_ne!(SymbolKind::Data, SymbolKind::Label);
}

#[test]
fn pdb_symbol_clone_eq() {
    let s = PdbSymbol {
        name: "foo".into(),
        address: 0xDEAD_BEEF_CAFEu64,
        size: 16,
        kind: SymbolKind::Function,
    };
    assert_eq!(s, s.clone());
}

#[test]
fn pdb_type_struct_fields() {
    let t = PdbType {
        name: "S".into(),
        kind: TypeKind::Struct { fields: vec!["a".into(), "b".into()] },
        size: 8,
    };
    if let TypeKind::Struct { fields } = &t.kind {
        assert_eq!(fields.len(), 2);
    } else {
        panic!();
    }
}

#[test]
fn pdb_module_eq() {
    let m = PdbModule { name: "n".into(), object_file: "o".into(), stream_index: 5 };
    assert_eq!(m, m.clone());
}

// ─────────────────────────────────────────────────────────────────────────────
// pdb_omap
// ─────────────────────────────────────────────────────────────────────────────

fn make_omap_bytes(entries: &[(u32, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * 8);
    for (a, b) in entries {
        out.extend_from_slice(&a.to_le_bytes());
        out.extend_from_slice(&b.to_le_bytes());
    }
    out
}

#[test]
fn omap_from_bytes_empty() {
    let m = PdbOmap::from_bytes(OmapKind::ToRemapped, &[]).unwrap();
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
}

#[test]
fn omap_from_bytes_bad_alignment() {
    let res = PdbOmap::from_bytes(OmapKind::ToRemapped, &[0u8; 7]);
    assert_eq!(res.unwrap_err(), OmapError::BadAlignment);
}

#[test]
fn omap_translate_basic() {
    let raw = make_omap_bytes(&[(0x1000, 0x2000), (0x2000, 0x3000)]);
    let m = PdbOmap::from_bytes(OmapKind::ToRemapped, &raw).unwrap();
    assert_eq!(m.translate_rva(0x1000).unwrap(), 0x2000);
    assert_eq!(m.translate_rva(0x1050).unwrap(), 0x2050);
    assert_eq!(m.translate_rva(0x2000).unwrap(), 0x3000);
}

#[test]
fn omap_translate_below_range() {
    let raw = make_omap_bytes(&[(0x1000, 0x2000)]);
    let m = PdbOmap::from_bytes(OmapKind::ToRemapped, &raw).unwrap();
    assert_eq!(m.translate_rva(0x100).unwrap_err(), OmapError::RvaBelowRange(0x100));
}

#[test]
fn omap_translate_unmapped() {
    let raw = make_omap_bytes(&[(0x1000, 0)]);
    let m = PdbOmap::from_bytes(OmapKind::ToRemapped, &raw).unwrap();
    assert_eq!(m.translate_rva(0x1000).unwrap_err(), OmapError::Unmapped(0x1000));
}

#[test]
fn omap_translate_empty_table_err() {
    let m = PdbOmap::from_bytes(OmapKind::ToRemapped, &[]).unwrap();
    assert_eq!(m.translate_rva(0).unwrap_err(), OmapError::EmptyTable);
}

#[test]
fn omap_try_translate_returns_none() {
    let m = PdbOmap::from_bytes(OmapKind::ToRemapped, &[]).unwrap();
    assert!(m.try_translate(0x100).is_none());
}

#[test]
fn omap_translate_many_drops_failures() {
    let raw = make_omap_bytes(&[(0x1000, 0x2000)]);
    let m = PdbOmap::from_bytes(OmapKind::ToRemapped, &raw).unwrap();
    let v = m.translate_many(&[0x500, 0x1000, 0x1100]);
    assert_eq!(v, vec![(0x1000, 0x2000), (0x1100, 0x2100)]);
}

#[test]
fn omap_covering_entry_none_below() {
    let raw = make_omap_bytes(&[(0x1000, 0x2000)]);
    let m = PdbOmap::from_bytes(OmapKind::ToRemapped, &raw).unwrap();
    assert!(m.covering_entry(0x100).is_none());
    let e = m.covering_entry(0x1500).unwrap();
    assert_eq!(e.rva, 0x1000);
}

#[test]
fn omap_to_bytes_round_trip() {
    let raw = make_omap_bytes(&[(0x1000, 0x2000), (0x3000, 0)]);
    let m = PdbOmap::from_bytes(OmapKind::FromRemapped, &raw).unwrap();
    assert_eq!(m.to_bytes(), raw);
}

#[test]
fn omap_max_source_dest() {
    let raw = make_omap_bytes(&[(0x1000, 0x2000), (0x4000, 0x5000), (0x5000, 0)]);
    let m = PdbOmap::from_bytes(OmapKind::ToRemapped, &raw).unwrap();
    assert_eq!(m.max_source_rva(), Some(0x5000));
    assert_eq!(m.max_dest_rva(), Some(0x5000));
}

#[test]
fn omap_unmapped_count() {
    let raw = make_omap_bytes(&[(0x1000, 0), (0x2000, 0x3000), (0x4000, 0)]);
    let m = PdbOmap::from_bytes(OmapKind::ToRemapped, &raw).unwrap();
    assert_eq!(m.unmapped_count(), 2);
}

#[test]
fn omap_unsorted_input_gets_sorted() {
    let raw = make_omap_bytes(&[(0x3000, 0x4000), (0x1000, 0x2000)]);
    let m = PdbOmap::from_bytes(OmapKind::ToRemapped, &raw).unwrap();
    assert_eq!(m.entries()[0].rva, 0x1000);
    assert_eq!(m.entries()[1].rva, 0x3000);
}

#[test]
fn omap_entry_is_unmapped() {
    assert!(OmapEntry::new(0x1000, 0).is_unmapped());
    assert!(!OmapEntry::new(0x1000, 1).is_unmapped());
}

#[test]
fn omap_kind_stream_name() {
    assert_eq!(OmapKind::ToRemapped.stream_name(), "OMAPTO");
    assert_eq!(OmapKind::FromRemapped.stream_name(), "OMAPFROM");
}

#[test]
fn omap_kind_display() {
    assert_eq!(format!("{}", OmapKind::ToRemapped), "OMAPTO");
}

#[test]
fn omap_error_display() {
    assert_eq!(format!("{}", OmapError::BadAlignment), "OMAP stream length is not a multiple of 8");
    assert_eq!(format!("{}", OmapError::EmptyTable), "OMAP table is empty");
    let s = format!("{}", OmapError::RvaBelowRange(0xABCD));
    assert!(s.contains("0x0000ABCD"));
}

#[test]
fn omap_compose() {
    let a = PdbOmap::from_bytes(OmapKind::ToRemapped, &make_omap_bytes(&[(0x1000, 0x2000)])).unwrap();
    let b = PdbOmap::from_bytes(OmapKind::FromRemapped, &make_omap_bytes(&[(0x2000, 0x9000)])).unwrap();
    let c = a.compose(&b);
    assert_eq!(c.translate_rva(0x1000).unwrap(), 0x9000);
}

#[test]
fn omap_standalone_translate_fn() {
    let raw = make_omap_bytes(&[(0x1000, 0x2000)]);
    let r = rustre_symbols_pdb::pdb_omap::translate_rva(&raw, 0x1050).unwrap();
    assert_eq!(r, 0x2050);
}

#[test]
fn omap_standalone_translate_bad_align() {
    assert_eq!(
        rustre_symbols_pdb::pdb_omap::translate_rva(&[0u8; 7], 0).unwrap_err(),
        OmapError::BadAlignment
    );
}

#[test]
fn omap_standalone_translate_empty() {
    assert_eq!(
        rustre_symbols_pdb::pdb_omap::translate_rva(&[], 0).unwrap_err(),
        OmapError::EmptyTable
    );
}

#[test]
fn omap_statistics_compute() {
    let raw = make_omap_bytes(&[(0x1000, 0x2000), (0x3000, 0)]);
    let m = PdbOmap::from_bytes(OmapKind::ToRemapped, &raw).unwrap();
    let _s = OmapStatistics::compute(&m);
}

#[test]
fn omap_from_entries_sorts() {
    let m = PdbOmap::from_entries(
        OmapKind::ToRemapped,
        vec![OmapEntry::new(0x3000, 0x4000), OmapEntry::new(0x1000, 0x2000)],
    );
    assert_eq!(m.entries()[0].rva, 0x1000);
}

// ─────────────────────────────────────────────────────────────────────────────
// section_contributions
// ─────────────────────────────────────────────────────────────────────────────

fn sc_v1(seg: u16, off: u32, size: u32, module: u16, chars: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&seg.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&off.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v.extend_from_slice(&chars.to_le_bytes());
    v.extend_from_slice(&module.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v
}

#[test]
fn sc_empty_input() {
    assert!(parse_section_contribs(&[]).unwrap().is_empty());
}

#[test]
fn sc_parse_v1_two() {
    let mut d = sc_v1(1, 0x1000, 0x100, 5, 0x20);
    d.extend(sc_v1(2, 0x2000, 0x200, 6, 0x40));
    let contribs = parse_section_contribs(&d).unwrap();
    assert_eq!(contribs.len(), 2);
    assert_eq!(contribs[0].module_idx, 5);
    assert_eq!(contribs[1].segment, 2);
}

#[test]
fn sc_find_module() {
    let d = sc_v1(1, 0x1000, 0x100, 7, 0x20);
    let cs = parse_section_contribs(&d).unwrap();
    assert_eq!(find_module_for_address(&cs, 1, 0x1000), Some(7));
    assert_eq!(find_module_for_address(&cs, 1, 0x10FF), Some(7));
    assert_eq!(find_module_for_address(&cs, 1, 0x1100), None);
    assert_eq!(find_module_for_address(&cs, 2, 0x1000), None);
}

#[test]
fn sc_find_module_sorted() {
    let mut d = sc_v1(1, 0x2000, 0x100, 2, 0);
    d.extend(sc_v1(1, 0x1000, 0x100, 1, 0));
    let mut cs = parse_section_contribs(&d).unwrap();
    sort_contribs(&mut cs);
    assert_eq!(find_module_sorted(&cs, 1, 0x1050), Some(1));
    assert_eq!(find_module_sorted(&cs, 1, 0x2050), Some(2));
    assert_eq!(find_module_sorted(&cs, 1, 0x500), None);
    assert_eq!(find_module_sorted(&cs, 1, 0x1100), None); // hole between
}

#[test]
fn sc_contains_edges() {
    let c = SectionContrib { module_idx: 0, segment: 1, offset: 0x100, size: 4, characteristics: 0 };
    assert!(c.contains(1, 0x100));
    assert!(c.contains(1, 0x103));
    assert!(!c.contains(1, 0x104));
    assert!(!c.contains(2, 0x100));
}

#[test]
fn sc_contains_size_zero_never_matches() {
    let c = SectionContrib { module_idx: 0, segment: 1, offset: 0x100, size: 0, characteristics: 0 };
    assert!(!c.contains(1, 0x100));
}

#[test]
fn sc_is_code_via_execute_bit() {
    let c = SectionContrib { module_idx: 0, segment: 1, offset: 0, size: 4, characteristics: 0x2000_0000 };
    assert!(c.is_code());
}

#[test]
fn sc_is_data() {
    let c = SectionContrib { module_idx: 0, segment: 1, offset: 0, size: 4, characteristics: 0x40 };
    assert!(c.is_data());
    assert!(!c.is_code());
}

#[test]
fn sc_is_read_only_read_set_write_unset() {
    let c = SectionContrib { module_idx: 0, segment: 1, offset: 0, size: 4, characteristics: 0x4000_0000 };
    assert!(c.is_read_only());
    let rw = SectionContrib { characteristics: 0xC000_0000, ..c };
    assert!(!rw.is_read_only());
}

#[test]
fn sc_contains_offset_size_overflow_does_not_panic() {
    // offset + size overflows u32; release builds wrap, debug builds panic.
    // The function is `const fn` using raw + — this can panic on overflow in debug.
    let c = SectionContrib {
        module_idx: 0,
        segment: 1,
        offset: u32::MAX - 5,
        size: 100,
        characteristics: 0,
    };
    // We just exercise it — a panic here is a real bug to report.
    let res = std::panic::catch_unwind(|| c.contains(1, u32::MAX - 4));
    assert!(res.is_ok(), "SectionContrib::contains panicked on overflow");
}

// ─────────────────────────────────────────────────────────────────────────────
// stream_reader
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sr_new_pos_zero() {
    let r = StreamReader::new(&[1, 2, 3]);
    assert_eq!(r.pos(), 0);
    assert_eq!(r.len(), 3);
    assert!(!r.is_empty());
    assert_eq!(r.remaining(), 3);
}

#[test]
fn sr_read_u8_seq() {
    let mut r = StreamReader::new(&[0xAA, 0xBB]);
    assert_eq!(r.read_u8().unwrap(), 0xAA);
    assert_eq!(r.read_u8().unwrap(), 0xBB);
    assert!(r.read_u8().is_err());
}

#[test]
fn sr_read_le_widths() {
    let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut r = StreamReader::new(&data);
    assert_eq!(r.read_u16().unwrap(), 0x0201);
    let mut r = StreamReader::new(&data);
    assert_eq!(r.read_u32().unwrap(), 0x0403_0201);
    let mut r = StreamReader::new(&data);
    assert_eq!(r.read_u64().unwrap(), 0x0807_0605_0403_0201);
}

#[test]
fn sr_read_signed() {
    let mut r = StreamReader::new(&[0xFF, 0xFF]);
    assert_eq!(r.read_i16().unwrap(), -1);
    let mut r = StreamReader::new(&[0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(r.read_i32().unwrap(), -1);
    let mut r = StreamReader::new(&[0xFF; 8]);
    assert_eq!(r.read_i64().unwrap(), -1);
}

#[test]
fn sr_seek_clamps_to_len() {
    let mut r = StreamReader::new(&[1, 2, 3]);
    r.seek(999);
    assert_eq!(r.pos(), 3);
    assert!(r.is_empty());
}

#[test]
fn sr_align_one_is_noop() {
    let mut r = StreamReader::new(&[0u8; 10]);
    r.seek(3);
    r.align(1);
    assert_eq!(r.pos(), 3);
}

#[test]
fn sr_align_four() {
    let mut r = StreamReader::new(&[0u8; 10]);
    r.seek(1);
    r.align(4);
    assert_eq!(r.pos(), 4);
}

#[test]
fn sr_read_cstring() {
    let data = b"hello\x00world\x00";
    let mut r = StreamReader::new(data);
    assert_eq!(r.read_cstring().unwrap(), "hello");
    assert_eq!(r.pos(), 6);
}

#[test]
fn sr_read_cstring_no_nul() {
    let data = b"oops";
    let mut r = StreamReader::new(data);
    assert_eq!(r.read_cstring().unwrap(), "oops");
    assert_eq!(r.pos(), 4);
}

#[test]
fn sr_read_length_prefixed_string() {
    let data = b"\x05hello\x00";
    let mut r = StreamReader::new(data);
    assert_eq!(r.read_length_prefixed_string().unwrap(), "hello");
}

#[test]
fn sr_peek_does_not_advance() {
    let r = StreamReader::new(&[1, 2, 3, 4]);
    let _ = r.peek_bytes(2).unwrap();
    assert_eq!(r.pos(), 0);
}

#[test]
fn sr_read_bytes_too_far_errors() {
    let mut r = StreamReader::new(&[1, 2]);
    assert!(r.read_bytes(5).is_err());
}

#[test]
fn sr_remaining_data_after_partial() {
    let mut r = StreamReader::new(&[1, 2, 3]);
    r.read_u8().unwrap();
    assert_eq!(r.remaining_data(), &[2, 3]);
}

#[test]
fn sr_numeric_leaf_small() {
    let mut r = StreamReader::new(&[0x10, 0x00]); // 0x0010 < 0x8000
    assert_eq!(r.read_numeric_leaf().unwrap(), 0x10);
}

#[test]
fn sr_numeric_leaf_ushort() {
    let mut r = StreamReader::new(&[0x02, 0x80, 0x34, 0x12]);
    assert_eq!(r.read_numeric_leaf().unwrap(), 0x1234);
}

#[test]
fn sr_numeric_leaf_long_negative() {
    let mut r = StreamReader::new(&[0x03, 0x80, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(r.read_numeric_leaf().unwrap(), -1);
}

#[test]
fn sr_skip_past_end_errors() {
    let mut r = StreamReader::new(&[0u8; 4]);
    assert!(r.skip(10).is_err());
}

#[test]
fn sr_skip_overflow_does_not_panic() {
    // skip uses raw + which can overflow.
    let mut r = StreamReader::new(&[0u8; 4]);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| r.skip(usize::MAX)));
    assert!(res.is_ok(), "StreamReader::skip panicked on overflow");
}

#[test]
fn sr_read_bytes_overflow_does_not_panic() {
    let mut r = StreamReader::new(&[0u8; 4]);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| r.read_bytes(usize::MAX)));
    assert!(res.is_ok(), "StreamReader::read_bytes panicked on overflow");
}

// ─────────────────────────────────────────────────────────────────────────────
// StringTable
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn string_table_default_empty() {
    let t = StringTable::new();
    assert!(t.get(0).is_none() || t.get(0) == Some(""));
}

#[test]
fn string_table_from_stream_basic() {
    // 8-byte header is stripped; heap starts at offset 8 in input.
    let mut data: Vec<u8> = vec![0u8; 8];
    data.extend_from_slice(b"\x00hello\x00world\x00");
    let t = StringTable::from_stream(&data);
    assert_eq!(t.get(1), Some("hello"));
    assert_eq!(t.get(7), Some("world"));
}

// ─────────────────────────────────────────────────────────────────────────────
// RecordHeader
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn record_header_read_basic() {
    // length = 8, kind = 0x1234
    let data = [0x08, 0x00, 0x34, 0x12, 0, 0, 0, 0, 0, 0];
    let mut r = StreamReader::new(&data);
    let h = RecordHeader::read(&mut r).unwrap();
    assert_eq!(h.length, 8);
    assert_eq!(h.kind, 0x1234);
}

// ─────────────────────────────────────────────────────────────────────────────
// tpi_types
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn type_index_primitive() {
    assert!(TypeIndex::new(0x10).is_primitive());
    assert!(!TypeIndex::new(0x1000).is_primitive());
}

#[test]
fn type_index_primitive_names() {
    assert_eq!(TypeIndex::new(0x0003).primitive_name(), Some("T_VOID"));
    assert_eq!(TypeIndex::new(0x0022).primitive_name(), Some("T_INT4"));
    assert_eq!(TypeIndex::new(0x9999).primitive_name(), None);
}

#[test]
fn type_index_display_primitive() {
    let s = format!("{}", TypeIndex::new(0x0003));
    assert!(s.contains("T_VOID"));
}

#[test]
fn type_index_display_user() {
    let s = format!("{}", TypeIndex::new(0x1000));
    assert!(s.contains("0x1000"));
}

#[test]
fn type_index_as_u32() {
    assert_eq!(TypeIndex::new(42).as_u32(), 42);
}

#[test]
fn leaf_kind_from_u16_known() {
    assert_eq!(LeafKind::from_u16(0x1002), LeafKind::Pointer);
    assert_eq!(LeafKind::from_u16(0x1505), LeafKind::Structure2);
    assert_eq!(LeafKind::from_u16(0xDEAD), LeafKind::Unknown);
}

#[test]
fn leaf_kind_is_aggregate() {
    assert!(LeafKind::Structure.is_aggregate());
    assert!(LeafKind::Class2.is_aggregate());
    assert!(!LeafKind::Pointer.is_aggregate());
}

#[test]
fn leaf_kind_is_numeric() {
    assert!(LeafKind::Long.is_numeric());
    assert!(LeafKind::UOctword.is_numeric());
    assert!(!LeafKind::Pointer.is_numeric());
}

#[test]
fn leaf_kind_display_prefix() {
    let s = format!("{}", LeafKind::Pointer);
    assert!(s.starts_with("LF_"));
}

#[test]
fn tpi_header_too_short_none() {
    assert!(TpiHeader::from_bytes(&[0u8; 10]).is_none());
}

#[test]
fn tpi_header_parses_56_bytes() {
    let mut d = vec![0u8; 56];
    d[0..4].copy_from_slice(&20_040_203u32.to_le_bytes());
    d[8..12].copy_from_slice(&0x1000u32.to_le_bytes());
    d[12..16].copy_from_slice(&0x2000u32.to_le_bytes());
    let h = TpiHeader::from_bytes(&d).unwrap();
    assert_eq!(h.version, TpiHeader::EXPECTED_VERSION);
    assert_eq!(h.type_count(), 0x1000);
}

#[test]
fn tpi_header_type_count_saturates() {
    let mut d = vec![0u8; 56];
    d[8..12].copy_from_slice(&100u32.to_le_bytes());
    d[12..16].copy_from_slice(&50u32.to_le_bytes()); // end < begin
    let h = TpiHeader::from_bytes(&d).unwrap();
    assert_eq!(h.type_count(), 0);
}

#[test]
fn tpi_record_parse_too_short() {
    assert!(TpiRecord::parse(&[0u8; 2], 0, TypeIndex::new(0x1000)).is_none());
}

#[test]
fn type_db_new_empty() {
    let db = TypeDb::new();
    assert_eq!(db.count(), 0);
    assert!(db.get(TypeIndex::new(0x1000)).is_none());
    assert!(db.get_by_name("foo").is_none());
    assert_eq!(db.iter_structs().count(), 0);
    assert_eq!(db.iter_enums().count(), 0);
    assert_eq!(db.iter_pointers().count(), 0);
}

#[test]
fn type_db_load_from_empty_bytes() {
    let mut db = TypeDb::new();
    db.load_from_bytes(&[], 0x1000);
    assert_eq!(db.count(), 0);
}

#[test]
fn type_db_insert_and_get() {
    let mut db = TypeDb::new();
    let rec = TpiRecord::new(
        TypeIndex::new(0x1000),
        LeafKind::Pointer,
        TpiTypeData::Empty,
    );
    db.insert(rec);
    assert_eq!(db.count(), 1);
    assert!(db.get(TypeIndex::new(0x1000)).is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// global_symbols
// ─────────────────────────────────────────────────────────────────────────────

fn frame_rec(rec_type: u16, payload: &[u8]) -> Vec<u8> {
    let length = u16::try_from(2 + payload.len()).unwrap();
    let mut v = Vec::new();
    v.extend_from_slice(&length.to_le_bytes());
    v.extend_from_slice(&rec_type.to_le_bytes());
    v.extend_from_slice(payload);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

#[test]
fn gs_parse_empty() {
    assert!(parse_global_symbols(&[]).unwrap().is_empty());
}

#[test]
fn gs_parse_pub32_function() {
    const S_PUB32: u16 = 0x110E;
    let mut p = Vec::new();
    p.extend_from_slice(&2u32.to_le_bytes()); // flags = function
    p.extend_from_slice(&0x1000u32.to_le_bytes());
    p.extend_from_slice(&1u16.to_le_bytes());
    p.extend_from_slice(b"foo\x00");
    let stream = frame_rec(S_PUB32, &p);
    let syms = parse_global_symbols(&stream).unwrap();
    assert_eq!(syms.len(), 1);
    assert!(syms[0].is_function());
}

#[test]
fn gs_parse_label32() {
    const S_LABEL32: u16 = 0x1105;
    let mut p = Vec::new();
    p.extend_from_slice(&0x3000u32.to_le_bytes());
    p.extend_from_slice(&1u16.to_le_bytes());
    p.push(0);
    p.extend_from_slice(b"L\x00");
    let stream = frame_rec(S_LABEL32, &p);
    let syms = parse_global_symbols(&stream).unwrap();
    assert!(matches!(syms[0].kind, GlobalSymKind::Label { .. }));
}

#[test]
fn gs_global_symbol_is_function_label_false() {
    let s = GlobalSymbol {
        name: "x".into(),
        demangled: None,
        address: None,
        kind: GlobalSymKind::Label { offset: 0, segment: 1 },
    };
    assert!(!s.is_function());
    assert!(s.type_index().is_none());
}

#[test]
fn gs_global_symbol_type_index_constant() {
    let s = GlobalSymbol {
        name: "K".into(),
        demangled: None,
        address: None,
        kind: GlobalSymKind::Constant { type_index: 7, value: 42 },
    };
    assert_eq!(s.type_index(), Some(7));
}

#[test]
fn gs_sym_flags_functions() {
    assert!(SymFlags(SymFlags::FUNCTION).is_function());
    assert!(SymFlags(SymFlags::CODE).is_code());
    assert!(!SymFlags(0).is_function());
}

#[test]
fn gs_sym_flags_combination() {
    let f = SymFlags(SymFlags::CODE | SymFlags::FUNCTION);
    assert!(f.is_code() && f.is_function());
}

// ─────────────────────────────────────────────────────────────────────────────
// Send/Sync invariants for public types
// ─────────────────────────────────────────────────────────────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn public_types_are_send_sync() {
    assert_send_sync::<PdbSymbol>();
    assert_send_sync::<PdbType>();
    assert_send_sync::<PdbModule>();
    assert_send_sync::<PdbGuid>();
    assert_send_sync::<PdbAge>();
    assert_send_sync::<PdbError>();
    assert_send_sync::<PdbOmap>();
    assert_send_sync::<OmapError>();
    assert_send_sync::<SectionContrib>();
    assert_send_sync::<TypeIndex>();
    assert_send_sync::<LeafKind>();
}
