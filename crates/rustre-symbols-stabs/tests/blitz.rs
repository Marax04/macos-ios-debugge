//! Exhaustive external test suite for `rustre-symbols-stabs`.
//!
//! Targets the top-level public API (and selected sub-module APIs) with
//! boundary, malformed-input, round-trip, and dead-code coverage.

use rustre_symbols::{SymKind, SymbolProvider, TypeInfo};
use rustre_symbols_stabs::*;

// --- helpers ---------------------------------------------------------------

fn rec_le(strx: u32, t: u8, other: u8, desc: u16, value: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0..4].copy_from_slice(&strx.to_le_bytes());
    b[4] = t;
    b[5] = other;
    b[6..8].copy_from_slice(&desc.to_le_bytes());
    b[8..12].copy_from_slice(&value.to_le_bytes());
    b
}

fn rec_be(strx: u32, t: u8, other: u8, desc: u16, value: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0..4].copy_from_slice(&strx.to_be_bytes());
    b[4] = t;
    b[5] = other;
    b[6..8].copy_from_slice(&desc.to_be_bytes());
    b[8..12].copy_from_slice(&value.to_be_bytes());
    b
}

fn stabstr(strs: &[&str]) -> Vec<u8> {
    let mut v = vec![0u8]; // conventional leading null
    for s in strs {
        v.extend_from_slice(s.as_bytes());
        v.push(0);
    }
    v
}

// --- StabType exhaustive ---------------------------------------------------

#[test]
fn stab_type_round_trip_all_known() {
    let known: &[u8] = &[
        0x00, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x30, 0x32, 0x34, 0x38, 0x3C, 0x40,
        0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x50, 0x54, 0x60, 0x62, 0x64, 0x80, 0x82, 0x84,
        0xA0, 0xA2, 0xA4, 0xC0, 0xC2, 0xC4, 0xE0, 0xE2, 0xE4, 0xE8, 0xEA, 0xF0, 0xF2, 0xF4,
        0xF6, 0xF8,
    ];
    for &v in known {
        let t = StabType::from_u8(v);
        assert_ne!(t, StabType::Unknown, "byte {v:#x}");
        assert_eq!(t as u8, v, "round-trip byte {v:#x}");
        assert!(StabType::name_for(v).is_some());
        assert_eq!(t.name(), StabType::name_for(v).unwrap());
    }
}

#[test]
fn stab_type_unknown_for_arbitrary_bytes() {
    for v in [0x01u8, 0x10, 0x55, 0xAA, 0xCF, 0xFF, 0xFE, 0x21] {
        if v == 0xFE { continue; } // not in either set for primary StabType
        let t = StabType::from_u8(v);
        if t != StabType::Unknown {
            // known—skip
            continue;
        }
        assert!(StabType::name_for(v).is_none(), "0x{v:x} unexpectedly named");
    }
}

#[test]
fn stab_type_categories_partition() {
    // every known type returns a non-empty category
    let cats = ["symbol", "file", "line", "scope", "other"];
    for v in 0u8..=255 {
        let t = StabType::from_u8(v);
        assert!(cats.contains(&t.category()));
    }
}

#[test]
fn stab_type_display_matches_name() {
    assert_eq!(StabType::NFun.to_string(), "N_FUN");
    assert_eq!(StabType::Unknown.to_string(), "Unknown");
}

// --- StabsType (second enum) -----------------------------------------------

#[test]
fn stabs_type_from_u8_basic() {
    assert_eq!(StabsType::from_u8(0x24), StabsType::FUN);
    assert_eq!(StabsType::from_u8(0x64), StabsType::SO);
    assert_eq!(StabsType::from_u8(0xfe), StabsType::LENG);
    assert_eq!(StabsType::from_u8(0x01), StabsType::Unknown);
}

#[test]
fn stabs_type_display_uses_debug() {
    let s = StabsType::FUN.to_string();
    assert!(s.contains("FUN"));
}

// --- StabRecord parsing ----------------------------------------------------

#[test]
fn parse_all_le_basic() {
    let s = stabstr(&["main.c"]);
    let r = rec_le(1, 0x64, 0, 0, 0);
    let v = StabRecord::parse_all(&r, &s);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].string, "main.c");
}

#[test]
fn parse_all_be_basic() {
    let s = stabstr(&["foo.c"]);
    let r = rec_be(1, 0x64, 0, 0, 0);
    let v = StabRecord::parse_all_be(&r, &s);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].string, "foo.c");
}

#[test]
fn parse_all_truncated_chunk_ignored() {
    let bad = vec![0u8; 25]; // 25 is not multiple of 12 → 2 full records, 1 byte dropped
    let v = StabRecord::parse_all(&bad, &[]);
    assert_eq!(v.len(), 2);
}

#[test]
fn parse_all_empty_inputs() {
    assert!(StabRecord::parse_all(&[], &[]).is_empty());
    assert!(StabRecord::parse_all_be(&[], &[]).is_empty());
}

#[test]
fn parse_all_strx_at_exact_end_yields_empty_string() {
    let s = stabstr(&["abc"]); // length = 5 ("\0abc\0")
    let r = rec_le(s.len() as u32, 0x20, 0, 0, 0);
    let v = StabRecord::parse_all(&r, &s);
    assert_eq!(v[0].string, "");
}

#[test]
fn parse_all_non_utf8_lossy() {
    let s = b"\0\xFF\xFE\xFD\0";
    let r = rec_le(1, 0x20, 0, 0, 0);
    let v = StabRecord::parse_all(&r, s);
    // From_utf8_lossy: must not panic, must yield U+FFFD replacements
    assert!(!v[0].string.is_empty());
}

#[test]
fn stab_record_symbol_name_and_descriptor() {
    let r = StabRecord {
        strx: 0,
        stab_type: StabType::NFun,
        other: 0,
        desc: 0,
        value: 0,
        string: "name:F(0,1)".to_string(),
    };
    assert_eq!(r.symbol_name(), "name");
    assert_eq!(r.type_descriptor(), "F(0,1)");
    assert!(r.has_string());
}

#[test]
fn stab_record_no_colon() {
    let r = StabRecord {
        strx: 0,
        stab_type: StabType::NSo,
        other: 0,
        desc: 0,
        value: 0,
        string: "main.c".to_string(),
    };
    assert_eq!(r.symbol_name(), "main.c");
    assert_eq!(r.type_descriptor(), "");
}

#[test]
fn stab_record_empty_string_has_string_false() {
    let r = StabRecord {
        strx: 0,
        stab_type: StabType::NUndf,
        other: 0,
        desc: 0,
        value: 0,
        string: String::new(),
    };
    assert!(!r.has_string());
}

// --- StabTypeCode ----------------------------------------------------------

#[test]
fn stab_type_code_known_chars() {
    use StabTypeCode::*;
    for (c, expected) in [
        ('f', Function),
        ('F', GlobalFunction),
        ('g', GlobalVar),
        ('s', StaticVar),
        ('r', RegisterVar),
        ('p', Parameter),
        ('t', Typedef),
        ('T', Tag),
        ('v', VarArray),
    ] {
        assert_eq!(StabTypeCode::from_char(c), expected);
    }
}

#[test]
fn stab_type_code_other() {
    match StabTypeCode::from_char('Z') {
        StabTypeCode::Other('Z') => (),
        _ => panic!(),
    }
}

#[test]
fn stab_type_code_display_other_form() {
    assert_eq!(StabTypeCode::Other('Q').to_string(), "Other(Q)");
}

// --- StabsTypeParser -------------------------------------------------------

#[test]
fn type_parser_primitives_all() {
    let p = StabsTypeParser::new();
    assert!(matches!(p.lookup("(0,1)"), Some(TypeInfo::Int { width: 32, signed: true })));
    assert!(matches!(p.lookup("(0,2)"), Some(TypeInfo::Int { width: 8, signed: true })));
    assert!(matches!(p.lookup("(0,4)"), Some(TypeInfo::Int { width: 64, signed: true })));
    assert!(matches!(p.lookup("(0,7)"), Some(TypeInfo::Int { width: 32, signed: false })));
    assert!(matches!(p.lookup("(0,9)"), Some(TypeInfo::Float { width: 32 })));
    assert!(matches!(p.lookup("(0,11)"), Some(TypeInfo::Float { width: 80 })));
    assert!(matches!(p.lookup("(0,14)"), Some(TypeInfo::Void)));
}

#[test]
fn type_parser_register_and_lookup_unknown() {
    let mut p = StabsTypeParser::new();
    assert!(p.lookup("(99,99)").is_none());
    p.register("(99,99)".into(), TypeInfo::Bool);
    assert!(matches!(p.lookup("(99,99)"), Some(TypeInfo::Bool)));
}

#[test]
fn type_parser_len_is_empty_consistency() {
    let p = StabsTypeParser::new();
    assert!(!p.is_empty());
    assert_eq!(p.len() > 0, !p.is_empty());
}

#[test]
fn type_parser_pointer_chain() {
    let p = StabsTypeParser::new();
    let t = p.parse_descriptor("*(0,1)").unwrap();
    match t {
        TypeInfo::Pointer { target, size } => {
            assert_eq!(size, 8);
            assert!(matches!(*target, TypeInfo::Int { width: 32, signed: true }));
        }
        _ => panic!("expected pointer"),
    }
}

#[test]
fn type_parser_array_count_zero_when_hi_lt_lo() {
    let p = StabsTypeParser::new();
    let t = p.parse_descriptor("ar(0,1);5;3;(0,1)").unwrap();
    if let TypeInfo::Array { count, .. } = t {
        assert_eq!(count, 0);
    } else {
        panic!("expected array");
    }
}

#[test]
fn type_parser_array_normal_count() {
    let p = StabsTypeParser::new();
    let t = p.parse_descriptor("ar(0,1);0;9;(0,1)").unwrap();
    if let TypeInfo::Array { count, .. } = t { assert_eq!(count, 10); } else { panic!(); }
}

#[test]
fn type_parser_enum_variants() {
    let p = StabsTypeParser::new();
    let t = p.parse_descriptor("eA:0,B:1,C:2;").unwrap();
    if let TypeInfo::Enum { variants, .. } = t {
        assert_eq!(variants.len(), 3);
        assert_eq!(variants[2].0, "C");
        assert_eq!(variants[2].1, 2);
    } else { panic!(); }
}

#[test]
fn type_parser_struct_offset_in_bytes() {
    let p = StabsTypeParser::new();
    // field x at bit offset 0, y at bit offset 32 → byte offsets 0, 4
    let t = p.parse_descriptor("s8x:(0,1),0,32;y:(0,1),32,32;").unwrap();
    if let TypeInfo::Struct { fields, .. } = t {
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].offset, 0);
        assert_eq!(fields[1].offset, 4);
    } else { panic!(); }
}

#[test]
fn type_parser_unknown_typeref_named() {
    let p = StabsTypeParser::new();
    let t = p.parse_descriptor("(7,3)").unwrap();
    assert!(matches!(t, TypeInfo::Named(_)));
}

#[test]
fn type_parser_empty_descriptor_unknown() {
    let p = StabsTypeParser::new();
    assert!(matches!(p.parse_descriptor("").unwrap(), TypeInfo::Unknown));
}

#[test]
fn type_parser_whitespace_descriptor_unknown() {
    let p = StabsTypeParser::new();
    assert!(matches!(p.parse_descriptor("   ").unwrap(), TypeInfo::Unknown));
}

// --- LineNumberTable -------------------------------------------------------

#[test]
fn line_table_empty_lookup() {
    let t = LineNumberTable::new();
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert!(t.lookup(0).is_none());
    assert!(t.entries().is_empty());
}

#[test]
fn line_table_sort_and_lookup_at_or_before() {
    let mut t = LineNumberTable::new();
    for (a, l) in [(0x2000u64, 20), (0x1000, 10), (0x3000, 30)] {
        t.add(LineEntry { address: a, line: l, file: "f.c".into() });
    }
    t.sort();
    assert_eq!(t.lookup(0x1500).unwrap().line, 10);
    assert_eq!(t.lookup(0x3000).unwrap().line, 30);
    assert_eq!(t.lookup(0xFFFFFFFF).unwrap().line, 30);
    assert!(t.lookup(0x0FFF).is_none());
}

#[test]
fn line_entry_display_format() {
    let e = LineEntry { address: 0x1234, line: 99, file: "a.c".into() };
    let s = e.to_string();
    assert!(s.contains("a.c"));
    assert!(s.contains("99"));
    assert!(s.contains("0x1234"));
}

// --- StabsParser high-level ------------------------------------------------

#[test]
fn stabs_parser_locals_and_params() {
    let s = stabstr(&["src.c", "fn:F", "loc:1", "p1:p"]);
    // Offsets in `s`: leading \0 then strings. src.c=1, fn:F=7, loc:1=12, p1:p=18
    let mut raw = Vec::new();
    raw.extend_from_slice(&rec_le(1, 0x64, 0, 0, 0)); // N_SO src.c
    raw.extend_from_slice(&rec_le(7, 0x24, 0, 0, 0x100)); // N_FUN fn:F
    raw.extend_from_slice(&rec_le(12, 0x80, 0, 0, 0xFFFFFFE0)); // N_LSYM loc (offset -32)
    raw.extend_from_slice(&rec_le(18, 0xA0, 0, 0, 8)); // N_PSYM p1
    let records = StabRecord::parse_all(&raw, &s);
    let mut p = StabsParser::new();
    p.process(&records, 0).unwrap();
    let fns = p.functions();
    assert_eq!(fns.len(), 1);
    assert_eq!(fns[0].locals.len(), 1);
    assert_eq!(fns[0].locals[0].name, "loc");
    assert_eq!(fns[0].locals[0].fp_offset, -32);
    assert_eq!(fns[0].parameters.len(), 1);
    assert_eq!(fns[0].parameters[0].offset, 8);
}

#[test]
fn stabs_parser_nstsym_attaches_file_and_adds_image_base() {
    let s = stabstr(&["src.c", "sv:S"]);
    // src.c=1, sv:S=7
    let mut raw = Vec::new();
    raw.extend_from_slice(&rec_le(1, 0x64, 0, 0, 0));
    raw.extend_from_slice(&rec_le(7, 0x26, 0, 0, 0x10)); // N_STSYM
    let recs = StabRecord::parse_all(&raw, &s);
    let mut p = StabsParser::new();
    p.process(&recs, 0x400000).unwrap();
    assert_eq!(p.globals().len(), 1);
    assert_eq!(p.globals()[0].address, 0x400010);
    assert_eq!(p.globals()[0].source_file.as_deref(), Some("src.c"));
}

#[test]
fn stabs_parser_sline_uses_fn_base() {
    let s = stabstr(&["x.c", "fn:F"]);
    let mut raw = Vec::new();
    raw.extend_from_slice(&rec_le(1, 0x64, 0, 0, 0));
    raw.extend_from_slice(&rec_le(5, 0x24, 0, 0, 0x100));
    raw.extend_from_slice(&rec_le(0, 0x44, 0, 12, 0x10)); // N_SLINE off 0x10, line 12
    let recs = StabRecord::parse_all(&raw, &s);
    let mut p = StabsParser::new();
    p.process(&recs, 0x1000).unwrap();
    // fn address = 0x1000 + 0x100 = 0x1100; sline addr = 0x1100 + 0x10 = 0x1110
    let entry = p.line_table().lookup(0x1110).unwrap();
    assert_eq!(entry.line, 12);
}

#[test]
fn stabs_parser_type_parser_accessor() {
    let p = StabsParser::new();
    assert!(p.type_parser().lookup("(0,1)").is_some());
}

#[test]
fn stabs_parser_type_parser_mut_accessor() {
    let mut p = StabsParser::new();
    p.type_parser_mut().register("(9,9)".into(), TypeInfo::Bool);
    assert!(matches!(p.type_parser().lookup("(9,9)"), Some(TypeInfo::Bool)));
}

#[test]
fn stabs_parser_all_symbols_funcs_then_globals() {
    let s = stabstr(&["fn:F", "g:G"]);
    // fn:F=1, g:G=6
    let mut raw = Vec::new();
    raw.extend_from_slice(&rec_le(1, 0x24, 0, 0, 0x100));
    raw.extend_from_slice(&rec_le(6, 0x20, 0, 0, 0x200));
    let recs = StabRecord::parse_all(&raw, &s);
    let mut p = StabsParser::new();
    p.process(&recs, 0).unwrap();
    let all = p.all_symbols();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].kind, SymKind::Function);
    assert_eq!(all[1].kind, SymKind::Data);
}

// --- StabsProvider ---------------------------------------------------------

#[test]
fn provider_lookup_nearest_with_no_match_below() {
    let s = stabstr(&["fn:F"]);
    let raw = rec_le(1, 0x24, 0, 0, 0x1000);
    let recs = StabRecord::parse_all(&raw, &s);
    let p = StabsProvider::from_records(&recs, 0);
    assert!(p.lookup_nearest(0x500).is_none());
    let near = p.lookup_nearest(0x1000).unwrap();
    assert_eq!(near.name, "fn");
}

#[test]
fn provider_from_bytes_round_trips_through_parse_all() {
    let s = stabstr(&["a.c", "fn:F"]);
    let mut raw = Vec::new();
    raw.extend_from_slice(&rec_le(1, 0x64, 0, 0, 0));
    raw.extend_from_slice(&rec_le(5, 0x24, 0, 0, 0x100));
    let p_bytes = StabsProvider::from_bytes(&raw, &s, 0);
    let recs = StabRecord::parse_all(&raw, &s);
    let p_rec = StabsProvider::from_records(&recs, 0);
    assert_eq!(p_bytes.symbol_count(), p_rec.symbol_count());
}

#[test]
fn provider_symbols_sorted_is_sorted() {
    let s = stabstr(&["z:F", "a:F", "m:F"]);
    // z:F=1, a:F=5, m:F=9
    let mut raw = Vec::new();
    raw.extend_from_slice(&rec_le(1, 0x24, 0, 0, 0x3000));
    raw.extend_from_slice(&rec_le(5, 0x24, 0, 0, 0x1000));
    raw.extend_from_slice(&rec_le(9, 0x24, 0, 0, 0x2000));
    let recs = StabRecord::parse_all(&raw, &s);
    let p = StabsProvider::from_records(&recs, 0);
    let sorted = p.symbols_sorted();
    let addrs: Vec<u64> = sorted.iter().map(|s| s.address).collect();
    assert_eq!(addrs, vec![0x1000, 0x2000, 0x3000]);
}

#[test]
fn provider_symbols_with_prefix_empty_prefix_returns_all() {
    let s = stabstr(&["a:F", "b:F"]);
    // a:F=1, b:F=5
    let mut raw = Vec::new();
    raw.extend_from_slice(&rec_le(1, 0x24, 0, 0, 0));
    raw.extend_from_slice(&rec_le(5, 0x24, 0, 0, 0x10));
    let recs = StabRecord::parse_all(&raw, &s);
    let p = StabsProvider::from_records(&recs, 0);
    assert_eq!(p.symbols_with_prefix("").len(), 2);
    assert_eq!(p.symbols_with_prefix("zzz").len(), 0);
}

#[test]
fn provider_parse_from_elf_non_elf_returns_empty() {
    let v = StabsLowParser::parse_from_elf(b"this is not an elf").ok();
    assert!(v.is_none() || v.unwrap().is_empty());
}

// --- StabsLowParser --------------------------------------------------------

#[test]
fn lowparser_parse_basic() {
    let s = stabstr(&["foo"]);
    let r = rec_le(1, 0x20, 1, 2, 3);
    let e = StabsLowParser::parse(&r, &s).unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].n_type, 0x20);
    assert_eq!(e[0].n_other, 1);
    assert_eq!(e[0].n_desc, 2);
    assert_eq!(e[0].n_value, 3);
    assert_eq!(e[0].string_value, "foo");
    assert_eq!(e[0].stabs_type(), StabsType::GSYM);
}

#[test]
fn lowparser_parse_neg_desc() {
    // n_desc is i16 here; 0xFFFF should decode to -1
    let r = rec_le(0, 0x44, 0, 0xFFFF, 0);
    let e = StabsLowParser::parse(&r, &[]).unwrap();
    assert_eq!(e[0].n_desc, -1);
}

#[test]
fn stabs_entry_symbol_name_and_descriptor() {
    let e = StabsEntry {
        n_strx: 0,
        n_type: 0x24,
        n_other: 0,
        n_desc: 0,
        n_value: 0,
        string_value: "name:F(0,1)".into(),
    };
    assert_eq!(e.symbol_name(), "name");
    assert_eq!(e.type_descriptor(), "F(0,1)");
}

#[test]
fn stabs_entry_display_contains_fields() {
    let e = StabsEntry {
        n_strx: 0,
        n_type: 0x24,
        n_other: 7,
        n_desc: 11,
        n_value: 0xCAFE,
        string_value: "x:F".into(),
    };
    let s = e.to_string();
    assert!(s.contains("FUN"));
    assert!(s.contains("0xcafe"));
    assert!(s.contains("x:F"));
    assert!(s.contains("7"));
}

// --- StabsSymbolExtractor --------------------------------------------------

#[test]
fn extractor_extract_functions_tracks_current_file() {
    let entries = vec![
        StabsEntry { n_strx: 0, n_type: 0x64, n_other: 0, n_desc: 0, n_value: 0, string_value: "f.c".into() },
        StabsEntry { n_strx: 0, n_type: 0x24, n_other: 0, n_desc: 0, n_value: 0x100, string_value: "fn:F".into() },
    ];
    let fns = StabsSymbolExtractor::extract_functions(&entries);
    assert_eq!(fns.len(), 1);
    assert_eq!(fns[0].name, "fn");
    assert_eq!(fns[0].addr, 0x100);
    assert_eq!(fns[0].source_file.as_deref(), Some("f.c"));
}

#[test]
fn extractor_skips_empty_name_fun() {
    let entries = vec![
        StabsEntry { n_strx: 0, n_type: 0x24, n_other: 0, n_desc: 0, n_value: 0x100, string_value: String::new() },
    ];
    assert!(StabsSymbolExtractor::extract_functions(&entries).is_empty());
}

#[test]
fn extractor_extract_source_files() {
    let entries = vec![
        StabsEntry { n_strx: 0, n_type: 0x64, n_other: 0, n_desc: 0, n_value: 0, string_value: "a.c".into() },
        StabsEntry { n_strx: 0, n_type: 0x64, n_other: 0, n_desc: 0, n_value: 0, string_value: "b.c".into() },
        StabsEntry { n_strx: 0, n_type: 0x24, n_other: 0, n_desc: 0, n_value: 0, string_value: "x:F".into() },
    ];
    let files = StabsSymbolExtractor::extract_source_files(&entries);
    assert_eq!(files, vec!["a.c".to_string(), "b.c".to_string()]);
}

#[test]
fn extractor_extract_line_info_tracks_fn() {
    let entries = vec![
        StabsEntry { n_strx: 0, n_type: 0x24, n_other: 0, n_desc: 0, n_value: 0x100, string_value: "fn:F".into() },
        StabsEntry { n_strx: 0, n_type: 0x44, n_other: 0, n_desc: 7, n_value: 0x10, string_value: String::new() },
    ];
    let lines = StabsSymbolExtractor::extract_line_info(&entries);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].line_no, 7);
    assert_eq!(lines[0].addr, 0x10);
    assert_eq!(lines[0].function.as_deref(), Some("fn"));
}

#[test]
fn extractor_negative_n_desc_casts_to_large_u16() {
    // n_desc = -1 → cast_unsigned → 0xFFFF
    let entries = vec![StabsEntry {
        n_strx: 0, n_type: 0x44, n_other: 0, n_desc: -1, n_value: 0, string_value: String::new(),
    }];
    let lines = StabsSymbolExtractor::extract_line_info(&entries);
    assert_eq!(lines[0].line_no, 0xFFFF);
}

// --- StabsStringTable ------------------------------------------------------

#[test]
fn string_table_starts_with_null_byte() {
    let t = StabsStringTable::new();
    assert_eq!(t.as_bytes(), &[0u8]);
    assert!(t.is_empty());
    assert_eq!(t.len(), 1);
}

#[test]
fn string_table_intern_returns_stable_offset() {
    let mut t = StabsStringTable::new();
    let o1 = t.intern("hello");
    let o2 = t.intern("hello");
    let o3 = t.intern("world");
    assert_eq!(o1, o2);
    assert_ne!(o1, o3);
    assert_eq!(t.get(o1), "hello");
    assert_eq!(t.get(o3), "world");
}

#[test]
fn string_table_first_intern_at_offset_1() {
    let mut t = StabsStringTable::new();
    let o = t.intern("a");
    assert_eq!(o, 1);
}

#[test]
fn string_table_get_oob_returns_empty() {
    let t = StabsStringTable::new();
    assert_eq!(t.get(9999), "");
    assert_eq!(t.get(u32::MAX), "");
}

#[test]
fn string_table_intern_empty_str() {
    let mut t = StabsStringTable::new();
    let o = t.intern("");
    assert_eq!(t.get(o), "");
}

// --- StabsTypeDescParser ---------------------------------------------------

#[test]
fn type_desc_parser_int() {
    let info = StabsTypeDescParser::parse_type_desc("i");
    assert_eq!(info.kind, "int");
    assert_eq!(info.size, Some(4));
}

#[test]
fn type_desc_parser_char_bool_long() {
    assert_eq!(StabsTypeDescParser::parse_type_desc("c").kind, "char");
    assert_eq!(StabsTypeDescParser::parse_type_desc("b").kind, "bool");
    assert_eq!(StabsTypeDescParser::parse_type_desc("l").kind, "long");
}

#[test]
fn type_desc_parser_pointer() {
    let info = StabsTypeDescParser::parse_type_desc("*(0,1)");
    assert_eq!(info.kind, "pointer");
}

#[test]
fn type_desc_parser_array_kind() {
    let info = StabsTypeDescParser::parse_type_desc("ar(0,1);0;9;(0,2)");
    assert_eq!(info.kind, "array");
    assert_eq!(info.size, Some(10));
}

#[test]
fn type_desc_parser_struct_size() {
    let info = StabsTypeDescParser::parse_type_desc("s16x:(0,1),0,32;");
    assert_eq!(info.kind, "struct");
    assert_eq!(info.size, Some(16));
}

#[test]
fn type_desc_parser_union_size() {
    let info = StabsTypeDescParser::parse_type_desc("u4x:(0,1),0,32;");
    assert_eq!(info.kind, "union");
    assert_eq!(info.size, Some(4));
}

#[test]
fn type_desc_parser_subrange() {
    let info = StabsTypeDescParser::parse_type_desc("r(0,1);0;255;");
    assert_eq!(info.kind, "subrange");
    assert_eq!(info.size, Some(1));
}

#[test]
fn type_desc_parser_subrange_16bit() {
    let info = StabsTypeDescParser::parse_type_desc("r(0,1);0;1000;");
    assert_eq!(info.size, Some(2));
}

#[test]
fn type_desc_parser_enum() {
    assert_eq!(StabsTypeDescParser::parse_type_desc("eA:0,B:1;").kind, "enum");
}

#[test]
fn type_desc_parser_unknown_falls_through() {
    let info = StabsTypeDescParser::parse_type_desc("?xyz");
    assert_eq!(info.kind, "unknown");
}

#[test]
fn type_desc_parser_ref_for_typeref() {
    let info = StabsTypeDescParser::parse_type_desc("(7,3)");
    assert_eq!(info.kind, "ref");
}

#[test]
fn type_desc_info_display() {
    let info = StabsTypeDescParser::parse_type_desc("i");
    let s = info.to_string();
    assert!(s.contains("int"));
    assert!(s.contains("4"));
}

// --- StabsSymbolParser (tuple-form) ----------------------------------------

#[test]
fn symbol_parser_empty() {
    assert!(StabsSymbolParser::parse(&[]).is_empty());
}

#[test]
fn symbol_parser_sline_uses_current_fn_addr() {
    let entries: Vec<(u32, u8, u16, u32, &str)> = vec![
        (0, 0x64, 0, 0, "f.c"),
        (0, 0x24, 1, 0x1000, "fn:F"),
        (0, 0x44, 5, 0x20, ""),
    ];
    let syms = StabsSymbolParser::parse(&entries);
    let sline = syms.iter().find(|s| s.kind == StabsKind::SourceLine).unwrap();
    assert_eq!(sline.value, 0x1020);
    assert_eq!(sline.line, Some(5));
}

#[test]
fn symbol_parser_unknown_type_with_name_becomes_other() {
    let entries: Vec<(u32, u8, u16, u32, &str)> = vec![(0, 0x01, 0, 0, "weird")];
    let syms = StabsSymbolParser::parse(&entries);
    assert_eq!(syms.len(), 1);
    assert_eq!(syms[0].kind, StabsKind::Other);
}

#[test]
fn symbol_parser_unknown_type_no_name_skipped() {
    let entries: Vec<(u32, u8, u16, u32, &str)> = vec![(0, 0x01, 0, 0, "")];
    assert!(StabsSymbolParser::parse(&entries).is_empty());
}

// --- StabsToSourceMap ------------------------------------------------------

#[test]
fn source_map_empty() {
    let m = StabsToSourceMap::default();
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
    assert!(m.lookup(0x100).is_none());
    assert!(m.entries().is_empty());
}

#[test]
fn source_map_lookup_at_or_before_largest() {
    let entries: Vec<(u32, u8, u16, u32, &str)> = vec![
        (0, 0x64, 0, 0, "f.c"),
        (0, 0x24, 0, 0x1000, "fn:F"),
        (0, 0x44, 10, 0, ""),
        (0, 0x44, 20, 0x20, ""),
    ];
    let m = StabsToSourceMap::from_stab_entries(&entries);
    let (f, l) = m.lookup(0x1019).unwrap();
    assert_eq!(f, "f.c");
    assert_eq!(l, 10);
    let (f, l) = m.lookup(0x1020).unwrap();
    assert_eq!(f, "f.c");
    assert_eq!(l, 20);
    assert!(m.lookup(0x0).is_none());
}

#[test]
fn source_map_skips_entries_without_file_or_line() {
    let syms = vec![StabsSymbol {
        kind: StabsKind::SourceLine,
        name: String::new(),
        value: 0x100,
        source_file: None,
        line: Some(1),
    }];
    let m = StabsToSourceMap::from_symbols(&syms);
    assert!(m.is_empty());
}

// --- convert_to_symbol_table ----------------------------------------------

#[test]
fn convert_symbol_table_mapping() {
    let entries = vec![
        StabsEntry { n_strx: 0, n_type: 0x24, n_other: 0, n_desc: 0, n_value: 0x100, string_value: "fn:F".into() },
        StabsEntry { n_strx: 0, n_type: 0x20, n_other: 0, n_desc: 0, n_value: 0x200, string_value: "g:G".into() },
        StabsEntry { n_strx: 0, n_type: 0xA4, n_other: 0, n_desc: 0, n_value: 0x300, string_value: "entry:E".into() }, // ENTRY → Label
        StabsEntry { n_strx: 0, n_type: 0x64, n_other: 0, n_desc: 0, n_value: 0, string_value: "f.c".into() }, // SO → skip
    ];
    let syms = convert_to_symbol_table(&entries);
    assert_eq!(syms.len(), 3);
    assert_eq!(syms[0].kind, SymbolKind::Function);
    assert_eq!(syms[1].kind, SymbolKind::Variable);
    assert_eq!(syms[2].kind, SymbolKind::Label);
    // All have source = Stabs
    for s in &syms {
        assert_eq!(s.source, SymbolSource::Stabs);
    }
}

#[test]
fn convert_symbol_table_skips_empty_names() {
    let entries = vec![
        StabsEntry { n_strx: 0, n_type: 0x24, n_other: 0, n_desc: 0, n_value: 0, string_value: String::new() },
        StabsEntry { n_strx: 0, n_type: 0x24, n_other: 0, n_desc: 0, n_value: 0, string_value: ":F".into() },
    ];
    assert!(convert_to_symbol_table(&entries).is_empty());
}

#[test]
fn unified_symbol_display_format() {
    let u = UnifiedSymbol {
        name: "f".into(),
        addr: 0x100,
        kind: SymbolKind::Function,
        source: SymbolSource::Stabs,
    };
    let s = u.to_string();
    assert!(s.contains("Stabs"));
    assert!(s.contains("Function"));
    assert!(s.contains("0x100"));
    assert!(s.contains('f'));
}

// --- StabsError display ----------------------------------------------------

#[test]
fn errors_display_carry_payload() {
    assert!(StabsError::InvalidRecord(42).to_string().contains("42"));
    assert!(StabsError::StringTable("x".into()).to_string().contains("x"));
    assert!(StabsError::Parse("y".into()).to_string().contains("y"));
    assert!(StabsError::TypeParse("z".into()).to_string().contains("z"));
}

// --- Send / Sync invariants ------------------------------------------------

#[test]
fn provider_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<StabsProvider>();
    assert_send_sync::<StabsTypeParser>();
    assert_send_sync::<StabsParser>();
    assert_send_sync::<LineNumberTable>();
    assert_send_sync::<StabsStringTable>();
    assert_send_sync::<StabsToSourceMap>();
}

// --- Round-trip stabstr table → parse_all ----------------------------------

#[test]
fn round_trip_string_table_then_parse() {
    let mut t = StabsStringTable::new();
    let o_file = t.intern("file.c");
    let o_fn = t.intern("foo:F(0,1)");
    let mut raw = Vec::new();
    raw.extend_from_slice(&rec_le(o_file, 0x64, 0, 0, 0));
    raw.extend_from_slice(&rec_le(o_fn, 0x24, 0, 0, 0x1000));
    let recs = StabRecord::parse_all(&raw, t.as_bytes());
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].string, "file.c");
    assert_eq!(recs[1].string, "foo:F(0,1)");
}

// --- Serde round-trip on simple records ------------------------------------

#[test]
fn serde_round_trip_stabs_entry() {
    let e = StabsEntry {
        n_strx: 1,
        n_type: 0x24,
        n_other: 2,
        n_desc: -7,
        n_value: 0xCAFE,
        string_value: "x:F".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: StabsEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.n_value, 0xCAFE);
    assert_eq!(back.n_desc, -7);
    assert_eq!(back.string_value, "x:F");
}

#[test]
fn serde_round_trip_unified_symbol() {
    let u = UnifiedSymbol {
        name: "f".into(),
        addr: 0x100,
        kind: SymbolKind::Function,
        source: SymbolSource::Stabs,
    };
    let json = serde_json::to_string(&u).unwrap();
    let back: UnifiedSymbol = serde_json::from_str(&json).unwrap();
    assert_eq!(back.name, "f");
    assert_eq!(back.addr, 0x100);
    assert_eq!(back.kind, SymbolKind::Function);
}
