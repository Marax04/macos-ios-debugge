//! Integration blitz tests for `rustre-symbols-codeview`.
//!
//! Focused on adversarial / boundary cases for the public API surface in
//! `lib.rs`. Existing in-module unit tests cover happy paths; this file
//! probes edge cases that may reveal bugs.

use rustre_symbols_codeview::*;
use rustre_symbols::{SymbolProvider, TypeInfo};

// =========================================================================
// CvSignature
// =========================================================================

#[test]
fn sig_empty_returns_none() {
    assert!(CvSignature::from_bytes(&[]).is_none());
}

#[test]
fn sig_exactly_three_bytes_none() {
    assert!(CvSignature::from_bytes(b"NB1").is_none());
}

#[test]
fn sig_cv8_marker() {
    let bytes = [4u8, 0, 0, 0];
    assert_eq!(CvSignature::from_bytes(&bytes), Some(CvSignature::Cv8));
}

#[test]
fn sig_as_str_all_variants_nonempty() {
    for s in [
        CvSignature::Cv41,
        CvSignature::Cv50,
        CvSignature::Cv70,
        CvSignature::Pdb70,
        CvSignature::Cv8,
    ] {
        assert!(!s.as_str().is_empty());
    }
}

// =========================================================================
// CvSymKind / CvTypeKind
// =========================================================================

#[test]
fn cv_sym_kind_unknown_for_zero() {
    assert_eq!(CvSymKind::from_u16(0), CvSymKind::Unknown);
}

#[test]
fn cv_sym_kind_thunk_is_function() {
    assert!(CvSymKind::Thunk32.is_function());
}

#[test]
fn cv_sym_kind_label_is_data_and_named() {
    assert!(CvSymKind::Label32.is_data());
    assert!(CvSymKind::Label32.is_named_address());
}

#[test]
fn cv_sym_kind_inline_unknown_paths() {
    assert_eq!(CvSymKind::from_u16(0x114D), CvSymKind::InlineSite);
    assert_eq!(CvSymKind::from_u16(0x114E), CvSymKind::InlineSiteEnd);
    assert_eq!(CvSymKind::from_u16(0x113E), CvSymKind::Local);
}

#[test]
fn cv_type_kind_all_known() {
    let mappings: &[(u16, CvTypeKind)] = &[
        (0x1001, CvTypeKind::Modifier),
        (0x1002, CvTypeKind::Pointer),
        (0x1003, CvTypeKind::Array),
        (0x1004, CvTypeKind::Class),
        (0x1005, CvTypeKind::Structure),
        (0x1006, CvTypeKind::Union),
        (0x1007, CvTypeKind::Enum),
        (0x1008, CvTypeKind::Procedure),
        (0x1009, CvTypeKind::MFunction),
        (0x1201, CvTypeKind::Arglist),
        (0x1203, CvTypeKind::FieldList),
        (0x1205, CvTypeKind::Bitfield),
        (0x150D, CvTypeKind::Member),
        (0x1502, CvTypeKind::Enumerate),
    ];
    for (raw, kind) in mappings {
        assert_eq!(CvTypeKind::from_u16(*raw), *kind);
    }
}

// =========================================================================
// parse_cv_symbols boundary
// =========================================================================

#[test]
fn parse_cv_symbols_three_bytes_returns_empty() {
    // Less than 4 bytes — loop condition fails, returns Ok([]).
    let syms = parse_cv_symbols(&[0xff, 0xff, 0xff]).unwrap();
    assert!(syms.is_empty());
}

#[test]
fn parse_cv_symbols_len_zero_breaks_silently() {
    // len=0 < 2 -> break (silent). Not RecordTooShort.
    let data = [0u8, 0, 0x10, 0x11];
    let syms = parse_cv_symbols(&data).unwrap();
    assert!(syms.is_empty());
}

#[test]
fn parse_cv_symbols_len_exactly_buffer_ok() {
    // a single S_END record (len=2, kind=0x0006) fits exactly.
    let data = [2u8, 0, 0x06, 0x00];
    let syms = parse_cv_symbols(&data).unwrap();
    assert!(syms.is_empty()); // S_END not emitted
}

#[test]
fn parse_cv_symbols_len_one_too_big_errors() {
    // record claims to extend 1 byte past buffer
    let data = [3u8, 0, 0x06, 0x00];
    let result = parse_cv_symbols(&data);
    assert!(matches!(result, Err(CodeViewError::RecordTooShort)));
}

#[test]
fn parse_cv_symbols_gproc_truncated_payload_silently_skipped() {
    // S_GPROC32 with payload < 35 bytes => parse_one_symbol returns silently.
    let mut payload = vec![0u8; 10]; // far less than 35
    // record kind GProc32
    let kind: u16 = 0x1110;
    let len = u16::try_from(2 + payload.len()).unwrap_or(u16::MAX);
    let mut rec = Vec::new();
    rec.extend_from_slice(&len.to_le_bytes());
    rec.extend_from_slice(&kind.to_le_bytes());
    rec.append(&mut payload);
    let syms = parse_cv_symbols(&rec).unwrap();
    assert!(syms.is_empty());
}

#[test]
fn parse_cv_symbols_max_u16_length_errors() {
    let data = [0xffu8, 0xff, 0x10, 0x11];
    let r = parse_cv_symbols(&data);
    assert!(matches!(r, Err(CodeViewError::RecordTooShort)));
}

// =========================================================================
// build_test_* round trips
// =========================================================================

#[test]
fn roundtrip_pub32() {
    let bytes = build_test_pub32("PublicSym", 0xDEAD_BEEF);
    let syms = parse_cv_symbols(&bytes).unwrap();
    assert_eq!(syms.len(), 1);
    assert_eq!(syms[0].kind, CvSymKind::Pub32);
    assert_eq!(syms[0].name, "PublicSym");
    assert_eq!(syms[0].offset, 0xDEAD_BEEF);
    assert_eq!(syms[0].segment, 1);
}

#[test]
fn roundtrip_gdata32() {
    let bytes = build_test_gdata32("var", 0x1000, 0x74);
    let syms = parse_cv_symbols(&bytes).unwrap();
    assert_eq!(syms[0].type_index, 0x74);
    assert_eq!(syms[0].name, "var");
}

#[test]
fn roundtrip_lproc32_long_name() {
    let n = "x".repeat(200);
    let bytes = build_test_lproc32(&n, 0x42);
    let syms = parse_cv_symbols(&bytes).unwrap();
    assert_eq!(syms[0].name, n);
}

#[test]
fn empty_name_parses() {
    let bytes = build_test_gproc32("", 0, 0, 0);
    let syms = parse_cv_symbols(&bytes).unwrap();
    assert_eq!(syms.len(), 1);
    assert_eq!(syms[0].name, "");
}

// =========================================================================
// parse_cv_symbol single-record
// =========================================================================

#[test]
fn parse_cv_symbol_offset_oob() {
    let data = [0u8; 2];
    let r = parse_cv_symbol(&data, 10);
    assert!(r.is_err());
}

#[test]
fn parse_cv_symbol_len_too_small() {
    let data = [1u8, 0, 0, 0]; // len=1
    let r = parse_cv_symbol(&data, 0);
    assert!(r.is_err());
}

#[test]
fn parse_cv_symbol_returns_consumed() {
    let bytes = build_test_gproc32("f", 0x100, 1, 0);
    let total = bytes.len();
    let (sym, consumed) = parse_cv_symbol(&bytes, 0).unwrap();
    assert_eq!(consumed, total);
    assert_eq!(sym.name, "f");
}

// =========================================================================
// CvTypeTable / primitives
// =========================================================================

#[test]
fn primitive_void_zero() {
    // T_VOID is 0x0003; 0x0000 is T_NOTYPE, which has no type at all.
    assert!(matches!(primitive_type(0x03), TypeInfo::Void));
    assert!(matches!(primitive_type(0x00), TypeInfo::Unknown));
}

#[test]
fn primitive_int_widths() {
    let cases = [
        (0x10, 8, true),
        (0x20, 8, false),
        (0x12, 32, true),
        (0x22, 32, false),
        (0x13, 64, true),
        (0x23, 64, false),
    ];
    for (idx, width, signed) in cases {
        match primitive_type(idx) {
            TypeInfo::Int { width: w, signed: s } => {
                assert_eq!(w, width);
                assert_eq!(s, signed);
            }
            other => panic!("expected Int for {idx:#x}, got {other:?}"),
        }
    }
}

#[test]
fn primitive_unknown_high_index() {
    // 0xFF (base) with mode=0: not in the match table -> Unknown.
    assert!(matches!(primitive_type(0xFF), TypeInfo::Unknown));
}

#[test]
fn type_table_lookup_missing() {
    let t = CvTypeTable::new();
    assert!(t.lookup(0x9999).is_none());
}

#[test]
fn type_table_to_type_info_unknown() {
    let t = CvTypeTable::new();
    // Non-primitive (>=0x1000) with no record -> Unknown.
    assert!(matches!(t.to_type_info(0x4000), TypeInfo::Unknown));
}

// =========================================================================
// CvStringTable adversarial
// =========================================================================

#[test]
fn string_table_no_nul_returns_remaining() {
    let t = CvStringTable::from_bytes(b"abc");
    // No NUL terminator — returns whole remaining.
    assert_eq!(t.get(0), "abc");
}

#[test]
fn string_table_offset_equal_len_empty() {
    let t = CvStringTable::from_bytes(b"abc\0");
    assert_eq!(t.get(4), "");
}

#[test]
fn string_table_invalid_utf8_returns_empty() {
    // Lossy fallback returns empty on invalid utf8 (str::from_utf8 path).
    let t = CvStringTable::from_bytes(&[0xff, 0xfe, 0]);
    assert_eq!(t.get(0), "");
}

// =========================================================================
// CV8 line parsing
// =========================================================================

#[test]
fn cv8_lines_empty_short_buffer() {
    assert!(parse_cv8_lines(&[]).unwrap().is_empty());
    assert!(parse_cv8_lines(&[0u8; 11]).unwrap().is_empty());
}

#[test]
fn cv8_lines_one_block_one_entry() {
    // header: code_off(4)+seg(2)+flags(2)+code_len(4) = 12
    // then file_index(4)+num_lines(4)+block_size(4)+entries(num_lines*8)
    let mut data = Vec::new();
    data.extend_from_slice(&0x1000u32.to_le_bytes()); // code_offset
    data.extend_from_slice(&1u16.to_le_bytes()); // segment
    data.extend_from_slice(&0u16.to_le_bytes()); // flags
    data.extend_from_slice(&64u32.to_le_bytes()); // code_len
    data.extend_from_slice(&0u32.to_le_bytes()); // file_index
    data.extend_from_slice(&1u32.to_le_bytes()); // num_lines=1
    data.extend_from_slice(&(12u32 + 8).to_le_bytes()); // block_size
    data.extend_from_slice(&4u32.to_le_bytes()); // line_offset
    // Flags word: lineStart:24 | deltaLineEnd:7 | isStatement:1 (bit 31).
    data.extend_from_slice(&0x8000_002Au32.to_le_bytes()); // line 42, isStatement

    let blocks = parse_cv8_lines(&data).unwrap();
    assert_eq!(blocks.len(), 1);
    let b = &blocks[0];
    assert_eq!(b.code_offset, 0x1000);
    assert_eq!(b.segment, 1);
    assert_eq!(b.code_len, 64);
    assert_eq!(b.lines.len(), 1);
    assert_eq!(b.lines[0].offset, 4);
    assert_eq!(b.lines[0].line_start, 42);
    assert!(b.lines[0].is_statement);
}

#[test]
fn cv8_lines_truncated_entries_errors() {
    let mut data = Vec::new();
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes()); // file_index
    data.extend_from_slice(&5u32.to_le_bytes()); // num_lines=5 — but no bytes follow
    data.extend_from_slice(&0u32.to_le_bytes()); // block_size
    let r = parse_cv8_lines(&data);
    assert!(matches!(r, Err(CodeViewError::RecordTooShort)));
}

// =========================================================================
// CvDebugSection
// =========================================================================

#[test]
fn debug_section_empty_short() {
    let s = CvDebugSection::parse(&[]).unwrap();
    assert!(s.symbols.is_empty());
}

#[test]
fn debug_section_wrong_version() {
    let mut data = vec![];
    data.extend_from_slice(&5u32.to_le_bytes()); // not 4
    let r = CvDebugSection::parse(&data);
    assert!(matches!(r, Err(CodeViewError::UnsupportedVersion(5))));
}

#[test]
fn debug_section_with_symbols_subsection() {
    let mut data = vec![];
    data.extend_from_slice(&4u32.to_le_bytes()); // version
    // Symbols subsection
    let payload = build_test_gproc32("x", 0x100, 1, 0);
    data.extend_from_slice(&0xF1u32.to_le_bytes()); // kind
    data.extend_from_slice(&u32::try_from(payload.len()).unwrap_or(u32::MAX).to_le_bytes()); // len
    data.extend_from_slice(&payload);
    // align
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let s = CvDebugSection::parse(&data).unwrap();
    assert_eq!(s.symbols.len(), 1);
}

#[test]
fn debug_section_subsection_overruns() {
    let mut data = vec![];
    data.extend_from_slice(&4u32.to_le_bytes());
    data.extend_from_slice(&0xF1u32.to_le_bytes());
    data.extend_from_slice(&999u32.to_le_bytes()); // claim 999 bytes
    // only 0 bytes of payload
    let r = CvDebugSection::parse(&data);
    assert!(matches!(r, Err(CodeViewError::RecordTooShort)));
}

// =========================================================================
// CodeViewProvider
// =========================================================================

#[test]
fn provider_with_type_table() {
    let p = CodeViewProvider::from_bytes(&[], 0).unwrap();
    let t = CvTypeTable::new();
    let p2 = p.with_type_table(t);
    assert_eq!(p2.type_table().len(), 0);
}

#[test]
fn provider_from_debug_section_roundtrip() {
    let mut data = vec![];
    data.extend_from_slice(&4u32.to_le_bytes());
    let payload = build_test_gproc32("entry", 0x10, 1, 0);
    data.extend_from_slice(&0xF1u32.to_le_bytes());
    data.extend_from_slice(&u32::try_from(payload.len()).unwrap_or(u32::MAX).to_le_bytes());
    data.extend_from_slice(&payload);
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let p = CodeViewProvider::from_debug_section(&data, 0x1000).unwrap();
    assert!(p.lookup_name("entry").is_some());
    assert_eq!(p.lookup_name("entry").unwrap().address, 0x1000 + 0x10);
}

// =========================================================================
// PdbSuperBlock
// =========================================================================

#[test]
fn pdb_superblock_too_short() {
    assert!(PdbSuperBlock::parse(&[0u8; 51]).is_none());
}

#[test]
fn pdb_superblock_parse_valid_magic() {
    let mut data = Vec::new();
    data.extend_from_slice(MSF_MAGIC);
    data.extend_from_slice(&4096u32.to_le_bytes()); // page_size
    data.extend_from_slice(&2u32.to_le_bytes()); // free_page_map
    data.extend_from_slice(&100u32.to_le_bytes()); // num_pages
    data.extend_from_slice(&8192u32.to_le_bytes()); // num_dir_bytes
    data.extend_from_slice(&0u32.to_le_bytes()); // unknown @48
    data.extend_from_slice(&5u32.to_le_bytes()); // block_map_addr @52
    assert_eq!(data.len(), 56);
    let sb = PdbSuperBlock::parse(&data).unwrap();
    assert!(sb.magic_ok);
    assert_eq!(sb.page_size, 4096);
    // BlockMapAddr lives at offset 52, not at the reserved field at 48.
    assert_eq!(sb.block_map_addr, 5);
    assert!(sb.is_valid());
}

#[test]
fn pdb_superblock_invalid_page_size() {
    let mut data = vec![0u8; 60];
    // No magic, page size 0
    let sb = PdbSuperBlock::parse(&data).unwrap();
    assert!(!sb.is_valid());
    // Non-power-of-two page size
    data[32..36].copy_from_slice(&3u32.to_le_bytes());
    let sb2 = PdbSuperBlock::parse(&data).unwrap();
    assert!(!sb2.is_valid());
}

// =========================================================================
// GUID formatting
// =========================================================================

#[test]
fn guid_to_string_format() {
    let g = [
        0x01, 0x02, 0x03, 0x04, // d1 LE => 0x04030201
        0x05, 0x06, // d2 LE => 0x0605
        0x07, 0x08, // d3 LE => 0x0807
        0x09, 0x0A, // d4a BE => 0x090A
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    ];
    let s = guid_to_string(&g);
    assert_eq!(s, "{04030201-0605-0807-090A-0B0C0D0E0F10}");
}

// =========================================================================
// PdbPathFromPe
// =========================================================================

#[test]
fn pdb_path_from_pe_empty() {
    assert!(PdbPathFromPe::extract(&[]).is_none());
}

#[test]
fn pdb_path_from_pe_not_mz() {
    let data = vec![0u8; 1024];
    assert!(PdbPathFromPe::extract(&data).is_none());
}

#[test]
fn pdb_path_from_pe_mz_no_pe_header() {
    let mut data = vec![0u8; 1024];
    data[0] = b'M';
    data[1] = b'Z';
    // e_lfanew points to garbage
    data[0x3C] = 0x80;
    assert!(PdbPathFromPe::extract(&data).is_none());
}

// =========================================================================
// CodeViewMagic
// =========================================================================

#[test]
fn codeview_magic_detect_rsds() {
    assert_eq!(CodeViewMagic::detect(b"RSDS"), Some(CodeViewMagic::Cv70));
}

#[test]
fn codeview_magic_detect_unknown() {
    assert!(CodeViewMagic::detect(b"XXXX").is_none());
    assert!(CodeViewMagic::detect(b"ab").is_none());
}

#[test]
fn codeview_magic_nb09_cv41() {
    assert_eq!(CodeViewMagic::detect(b"NB09"), Some(CodeViewMagic::Cv41));
}

#[test]
fn codeview_magic_nb11_decoded_as_cv50_variant() {
    // The `CodeViewMagic` enum variant is named Cv50 but its tag is NB11.
    // This documents the existing mapping for regression purposes.
    assert_eq!(CodeViewMagic::detect(b"NB11"), Some(CodeViewMagic::Cv50));
}

#[test]
fn codeview_magic_labels_nonempty() {
    for m in [CodeViewMagic::Cv41, CodeViewMagic::Cv50, CodeViewMagic::Cv70] {
        assert!(!m.label().is_empty());
        assert_eq!(m.to_string(), m.label());
    }
}

// =========================================================================
// CvSymbolKind (extended)
// =========================================================================

#[test]
fn cv_symbol_kind_categorization() {
    assert!(CvSymbolKind::SGproc32.is_function());
    assert!(CvSymbolKind::SThunk32.is_function());
    assert!(CvSymbolKind::SGdata32.is_data());
    assert!(CvSymbolKind::SLabel32.is_data());
    assert!(!CvSymbolKind::SEnd.is_function());
}

#[test]
fn cv_symbol_kind_from_unknown() {
    assert_eq!(CvSymbolKind::from_u16(0xDEAD), CvSymbolKind::Unknown);
}

// =========================================================================
// Structured payload parsers
// =========================================================================

#[test]
fn cv_proc32_parse_short_none() {
    assert!(CvProc32::parse(&[0u8; 34]).is_none());
}

#[test]
fn cv_proc32_parse_round() {
    let mut data = vec![0u8; 35];
    data[28..32].copy_from_slice(&0xCAFEu32.to_le_bytes());
    data[32..34].copy_from_slice(&7u16.to_le_bytes());
    data[24..28].copy_from_slice(&0x1111u32.to_le_bytes()); // type_index
    data.extend_from_slice(b"fn\0");
    let p = CvProc32::parse(&data).unwrap();
    assert_eq!(p.offset, 0xCAFE);
    assert_eq!(p.segment, 7);
    assert_eq!(p.type_index, 0x1111);
    assert_eq!(p.name, "fn");
}

#[test]
fn cv_data32_parse_short_none() {
    assert!(CvData32::parse(&[0u8; 9]).is_none());
}

#[test]
fn cv_public32_is_function_flag() {
    let mut data = vec![0u8; 10];
    data[0..4].copy_from_slice(&0x02u32.to_le_bytes());
    let p = CvPublic32::parse(&data).unwrap();
    assert!(p.is_function());
    data[0..4].copy_from_slice(&0u32.to_le_bytes());
    let p2 = CvPublic32::parse(&data).unwrap();
    assert!(!p2.is_function());
}

#[test]
fn cv_regrel32_parse() {
    let mut data = vec![0u8; 10];
    data[0..4].copy_from_slice(&0x40u32.to_le_bytes());
    data[4..8].copy_from_slice(&0x74u32.to_le_bytes());
    data[8..10].copy_from_slice(&17u16.to_le_bytes());
    data.extend_from_slice(b"var\0");
    let r = CvRegrel32::parse(&data).unwrap();
    assert_eq!(r.offset, 0x40);
    assert_eq!(r.type_index, 0x74);
    assert_eq!(r.register, 17);
    assert_eq!(r.name, "var");
}

#[test]
fn cv_regrel32_short_none() {
    assert!(CvRegrel32::parse(&[0u8; 9]).is_none());
}

#[test]
fn cv_objname_parse() {
    let mut d = vec![0u8; 4];
    d.extend_from_slice(b"foo.obj\0");
    let o = CvObjname::parse(&d).unwrap();
    assert_eq!(o.name, "foo.obj");
}

#[test]
fn cv_frameproc_flags() {
    // FRAMEPROCSYM is a 26-byte payload with flags:u32 at offset 22.
    let mut d = vec![0u8; 26];
    // fHasAlloca (bit 0) | fAsyncEH (bit 9)
    d[22..26].copy_from_slice(&0x201u32.to_le_bytes());
    let f = CvFrameproc::parse(&d).unwrap();
    assert!(f.has_alloca());
    assert!(f.has_async_eh());
    // 0x100 is fSecurityChecks, not fHasAlloca.
    let mut d2 = vec![0u8; 26];
    d2[22..26].copy_from_slice(&0x100u32.to_le_bytes());
    let f2 = CvFrameproc::parse(&d2).unwrap();
    assert!(f2.has_security_checks());
    assert!(!f2.has_alloca());
}

#[test]
fn cv_frameproc_short_none() {
    assert!(CvFrameproc::parse(&[0u8; 25]).is_none());
    // A correctly sized 26-byte payload must parse.
    assert!(CvFrameproc::parse(&[0u8; 26]).is_some());
}

#[test]
fn cv_constant_immediate() {
    let mut d = vec![0u8; 4];
    // numeric leaf immediate u16
    d.extend_from_slice(&123u16.to_le_bytes());
    d.extend_from_slice(b"K\0");
    let c = CvConstant::parse(&d).unwrap();
    assert_eq!(c.value, 123);
    assert_eq!(c.name, "K");
}

#[test]
fn cv_constant_lf_ulong() {
    let mut d = vec![0u8; 4]; // type_index
    d.extend_from_slice(&0x8004u16.to_le_bytes()); // LF_ULONG tag
    d.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    d.extend_from_slice(b"BIG\0");
    let c = CvConstant::parse(&d).unwrap();
    assert_eq!(c.value, 0xDEAD_BEEF);
    assert_eq!(c.name, "BIG");
}

#[test]
fn cv_udt_parse() {
    let mut d = vec![0u8; 4];
    d.extend_from_slice(b"MyTypedef\0");
    let u = CvUdt::parse(&d).unwrap();
    assert_eq!(u.name, "MyTypedef");
}

#[test]
fn cv_udt_short_none() {
    assert!(CvUdt::parse(&[0u8; 3]).is_none());
}

// =========================================================================
// CvSymbolStream iterator
// =========================================================================

#[test]
fn symbol_stream_iterates() {
    let mut data = build_test_gproc32("a", 0x10, 1, 0);
    data.extend(build_test_gproc32("b", 0x20, 1, 0));
    let s: Vec<_> = CvSymbolStream::new(&data).collect();
    assert_eq!(s.len(), 2);
    for (kind, _payload, consumed) in &s {
        assert!(matches!(kind, CvSymbolKind::SGproc32));
        assert!(*consumed > 0);
    }
}

#[test]
fn symbol_stream_stops_on_truncation() {
    let mut data = build_test_gproc32("a", 0x10, 1, 0);
    // Append a bogus header claiming huge length.
    data.extend_from_slice(&0xFFFFu16.to_le_bytes());
    data.extend_from_slice(&0x1110u16.to_le_bytes());
    let s: Vec<_> = CvSymbolStream::new(&data).collect();
    assert_eq!(s.len(), 1); // truncated record dropped
}

#[test]
fn symbol_stream_empty() {
    let s: Vec<_> = CvSymbolStream::new(&[]).collect();
    assert!(s.is_empty());
}

// =========================================================================
// parse_debug_s
// =========================================================================

#[test]
fn parse_debug_s_empty() {
    assert!(parse_debug_s(&[]).unwrap().is_empty());
}

#[test]
fn parse_debug_s_wrong_version() {
    let data = 7u32.to_le_bytes();
    assert!(parse_debug_s(&data).is_err());
}

#[test]
fn parse_debug_s_subsection_overrun() {
    let mut data = vec![];
    data.extend_from_slice(&4u32.to_le_bytes());
    data.extend_from_slice(&0xF1u32.to_le_bytes());
    data.extend_from_slice(&100u32.to_le_bytes());
    // no payload
    assert!(parse_debug_s(&data).is_err());
}

// =========================================================================
// parse_type_record
// =========================================================================

#[test]
fn parse_type_record_too_short() {
    assert!(parse_type_record(&[0u8; 3]).is_none());
}

#[test]
fn parse_type_record_unknown_leaf() {
    // len=2 (valid), leaf=0xFFFF (unknown).
    let data = [2u8, 0, 0xFF, 0xFF];
    assert!(parse_type_record(&data).is_none());
}

#[test]
fn parse_type_record_pointer_64bit() {
    // LF_POINTER body: [target:u32][attributes:u32]
    let mut body = Vec::new();
    body.extend_from_slice(&0x74u32.to_le_bytes()); // target
    // attributes: ptrtype bits 0..5, value 0x0C = CV_PTR_64 (near 64-bit pointer)
    body.extend_from_slice(&0x0Cu32.to_le_bytes());
    let leaf: u16 = 0x1002;
    let len = u16::try_from(2 + body.len()).unwrap_or(u16::MAX);
    let mut rec = Vec::new();
    rec.extend_from_slice(&len.to_le_bytes());
    rec.extend_from_slice(&leaf.to_le_bytes());
    rec.extend_from_slice(&body);
    let r = parse_type_record(&rec).unwrap();
    assert_eq!(r.kind, CvTypeKind::Pointer);
    assert_eq!(r.underlying_type, 0x74);
    assert_eq!(r.size, 8);
}

// =========================================================================
// SymbolProvider trait methods coverage
// =========================================================================

#[test]
fn provider_lookup_nearest_above_returns_none_in_empty() {
    let p = CodeViewProvider::from_bytes(&[], 0).unwrap();
    assert!(p.lookup_nearest(0x1000).is_none());
}

#[test]
fn provider_lookup_nearest_picks_lower() {
    let mut data = build_test_gproc32("a", 0x100, 1, 0);
    data.extend(build_test_gproc32("b", 0x200, 1, 0));
    data.extend(build_test_gproc32("c", 0x500, 1, 0));
    let p = CodeViewProvider::from_bytes(&data, 0).unwrap();
    let n = p.lookup_nearest(0x250).unwrap();
    assert_eq!(n.name, "b");
}

// =========================================================================
// Misc display/debug
// =========================================================================

#[test]
fn pdb_location_display() {
    let loc = PdbLocation {
        guid: "{0-0-0-0-0}".to_string(),
        age: 1,
        path: "x.pdb".to_string(),
    };
    let s = format!("{loc}");
    assert!(s.contains("x.pdb"));
}

#[test]
fn cv8_subsection_kind_unknown() {
    match Cv8SubsectionKind::from_u32(0x1234) {
        Cv8SubsectionKind::Unknown(v) => assert_eq!(v, 0x1234),
        _ => panic!("expected Unknown"),
    }
}
