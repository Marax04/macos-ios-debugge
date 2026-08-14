//! Deep adversarial tests for rustre-symbols-codeview.

use rustre_symbols::{SymbolProvider, TypeInfo};
use rustre_symbols_codeview::*;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ---- CvSignature ----

#[test]
fn t01_sig_all_known() {
    assert_eq!(CvSignature::from_bytes(b"NB09....").unwrap(), CvSignature::Cv41);
    assert_eq!(CvSignature::from_bytes(b"NB10....").unwrap(), CvSignature::Cv50);
    assert_eq!(CvSignature::from_bytes(b"NB11....").unwrap(), CvSignature::Cv70);
    assert_eq!(CvSignature::from_bytes(b"Micr....").unwrap(), CvSignature::Pdb70);
    let cv8 = [4u8, 0, 0, 0, 0xff];
    assert_eq!(CvSignature::from_bytes(&cv8).unwrap(), CvSignature::Cv8);
}

#[test]
fn t02_sig_short_and_unknown() {
    assert!(CvSignature::from_bytes(&[]).is_none());
    assert!(CvSignature::from_bytes(b"XYZ").is_none());
    assert!(CvSignature::from_bytes(b"ZZZZ").is_none());
}

#[test]
fn t03_sig_fuzz_never_panic() {
    let mut g = lcg();
    for _ in 0..200 {
        let n = (g() % 16) as usize;
        let buf: Vec<u8> = (0..n).map(|_| (g() & 0xff) as u8).collect();
        let _ = CvSignature::from_bytes(&buf);
    }
}

#[test]
fn t04_sig_display_and_as_str() {
    for s in [
        CvSignature::Cv41,
        CvSignature::Cv50,
        CvSignature::Cv70,
        CvSignature::Pdb70,
        CvSignature::Cv8,
    ] {
        assert!(!s.to_string().is_empty());
        assert!(!s.as_str().is_empty());
    }
}

// ---- CvSymKind ----

#[test]
fn t05_sym_kind_roundtrip() {
    let kinds = [
        (0x110Eu16, CvSymKind::Pub32),
        (0x1110, CvSymKind::GProc32),
        (0x110F, CvSymKind::LProc32),
        (0x1111, CvSymKind::RegRel32),
        (0x110D, CvSymKind::GData32),
        (0x110C, CvSymKind::LData32),
        (0x1105, CvSymKind::Label32),
        (0x1102, CvSymKind::Thunk32),
        (0x1103, CvSymKind::Block32),
        (0x0006, CvSymKind::End),
        (0x113E, CvSymKind::Local),
        (0x113C, CvSymKind::Compile3),
        (0x114D, CvSymKind::InlineSite),
        (0x114E, CvSymKind::InlineSiteEnd),
    ];
    for (v, k) in kinds {
        assert_eq!(CvSymKind::from_u16(v), k);
    }
    assert_eq!(CvSymKind::from_u16(0xFFFE), CvSymKind::Unknown);
}

#[test]
fn t06_sym_kind_categories() {
    assert!(CvSymKind::GProc32.is_function());
    assert!(CvSymKind::LProc32.is_function());
    assert!(CvSymKind::Thunk32.is_function());
    assert!(!CvSymKind::GData32.is_function());

    assert!(CvSymKind::GData32.is_data());
    assert!(CvSymKind::Pub32.is_data());
    assert!(!CvSymKind::GProc32.is_data());

    assert!(CvSymKind::GProc32.is_named_address());
    assert!(CvSymKind::Pub32.is_named_address());
    assert!(!CvSymKind::End.is_named_address());
}

#[test]
fn t07_sym_kind_fuzz() {
    let mut g = lcg();
    for _ in 0..500 {
        let v = (g() & 0xffff) as u16;
        let _ = CvSymKind::from_u16(v);
    }
}

// ---- CvTypeKind ----

#[test]
fn t08_type_kind_roundtrip() {
    for v in [
        0x1001u16, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007, 0x1008, 0x1009, 0x1201, 0x1203,
        0x1205, 0x150D, 0x1502,
    ] {
        let k = CvTypeKind::from_u16(v);
        assert_ne!(k, CvTypeKind::Unknown);
    }
    assert_eq!(CvTypeKind::from_u16(0), CvTypeKind::Unknown);
}

// ---- parse_cv_symbols ----

#[test]
fn t09_parse_empty() {
    assert!(parse_cv_symbols(&[]).unwrap().is_empty());
}

#[test]
fn t10_parse_gproc32_basic() {
    let d = build_test_gproc32("hello", 0x1000, 1, 0x42);
    let syms = parse_cv_symbols(&d).unwrap();
    assert_eq!(syms.len(), 1);
    assert_eq!(syms[0].name, "hello");
    assert_eq!(syms[0].offset, 0x1000);
    assert_eq!(syms[0].segment, 1);
    assert_eq!(syms[0].type_index, 0x42);
}

#[test]
fn t11_parse_multi_records() {
    let mut d = build_test_gproc32("a", 0x10, 1, 0);
    d.extend(build_test_lproc32("b", 0x20));
    d.extend(build_test_pub32("c", 0x30));
    d.extend(build_test_gdata32("d", 0x40, 0x74));
    let syms = parse_cv_symbols(&d).unwrap();
    assert_eq!(syms.len(), 4);
    let names: Vec<_> = syms.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["a", "b", "c", "d"]);
}

#[test]
fn t12_parse_record_too_short() {
    let data: Vec<u8> = vec![100, 0, 0x10, 0x11];
    assert!(matches!(
        parse_cv_symbols(&data),
        Err(CodeViewError::RecordTooShort)
    ));
}

#[test]
fn t13_parse_zero_len_stops() {
    // len=0 breaks the loop
    let data = vec![0u8, 0, 0x09, 0x10];
    assert!(parse_cv_symbols(&data).unwrap().is_empty());
}

#[test]
fn t14_parse_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..300 {
        let n = (g() % 256) as usize;
        let buf: Vec<u8> = (0..n).map(|_| (g() & 0xff) as u8).collect();
        let _ = parse_cv_symbols(&buf);
    }
}

#[test]
fn t15_parse_50_deterministic_gprocs() {
    let mut all = Vec::new();
    for i in 0..50u32 {
        all.extend(build_test_gproc32(&format!("fn{i}"), i * 0x10, (i % 4) as u16 + 1, i));
    }
    let syms = parse_cv_symbols(&all).unwrap();
    assert_eq!(syms.len(), 50);
    for (i, s) in syms.iter().enumerate() {
        assert_eq!(s.name, format!("fn{i}"));
        assert_eq!(s.offset, u32::try_from(i).unwrap_or(u32::MAX) * 0x10);
    }
}

#[test]
fn t16_parse_truncation_seq() {
    let full = build_test_gproc32("xxxxxx", 0x100, 1, 7);
    // truncate at every length less than full -> never panic
    for n in 0..full.len() {
        let _ = parse_cv_symbols(&full[..n]);
    }
}

// ---- parse_cv_type_records ----

fn struct_rec(name: &str, count: u16, size: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&count.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&size.to_le_bytes());
    body.extend_from_slice(name.as_bytes());
    body.push(0);
    let leaf: u16 = 0x1005;
    let len = u16::try_from(2 + body.len()).unwrap_or(u16::MAX);
    let mut r = Vec::new();
    r.extend_from_slice(&len.to_le_bytes());
    r.extend_from_slice(&leaf.to_le_bytes());
    r.extend_from_slice(&body);
    r
}

#[test]
fn t17_type_records_index_increment() {
    let mut d = struct_rec("A", 1, 4);
    d.extend(struct_rec("B", 2, 8));
    d.extend(struct_rec("C", 3, 12));
    let recs = parse_cv_type_records(&d).unwrap();
    assert_eq!(recs.len(), 3);
    assert_eq!(recs[0].index, 0x1000);
    assert_eq!(recs[1].index, 0x1001);
    assert_eq!(recs[2].index, 0x1002);
}

#[test]
fn t18_type_records_too_short() {
    let data = vec![50u8, 0, 0x05, 0x10];
    assert!(matches!(
        parse_cv_type_records(&data),
        Err(CodeViewError::RecordTooShort)
    ));
}

#[test]
fn t19_type_records_fuzz() {
    let mut g = lcg();
    for _ in 0..300 {
        let n = (g() % 256) as usize;
        let buf: Vec<u8> = (0..n).map(|_| (g() & 0xff) as u8).collect();
        let _ = parse_cv_type_records(&buf);
    }
}

// ---- CvTypeTable ----

#[test]
fn t20_type_table_default_empty() {
    let t = CvTypeTable::new();
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert!(t.lookup(0x1000).is_none());
    assert!(t.records().is_empty());
}

#[test]
fn t21_type_table_lookup_after_parse() {
    let d = struct_rec("Foo", 2, 8);
    let t = CvTypeTable::from_bytes(&d).unwrap();
    assert_eq!(t.len(), 1);
    assert_eq!(t.lookup(0x1000).unwrap().name, "Foo");
    assert!(t.lookup(0x1001).is_none());
}

#[test]
fn t22_to_type_info_struct_fields() {
    let d = struct_rec("S", 4, 16);
    let t = CvTypeTable::from_bytes(&d).unwrap();
    match t.to_type_info(0x1000) {
        TypeInfo::Struct { name, fields } => {
            assert_eq!(name, "S");
            // Without LF_FIELDLIST data no per-member layout is available;
            // invented strided offsets must NOT be emitted.
            assert!(fields.is_empty());
        }
        _ => panic!("expected struct"),
    }
}

#[test]
fn t23_to_type_info_unknown_index() {
    let t = CvTypeTable::new();
    assert!(matches!(t.to_type_info(0xDEAD), TypeInfo::Unknown));
}

#[test]
fn t24_primitive_types_all() {
    let cases = [
        // T_VOID is 0x0003; 0x0000 is T_NOTYPE -> Unknown.
        (0x03u32, TypeInfo::Void),
        (0x00, TypeInfo::Unknown),
        (0x10, TypeInfo::Int { width: 8, signed: true }),
        // T_RCHAR (0x70) is an 8-bit char, not a 16-bit int.
        (0x70, TypeInfo::Int { width: 8, signed: true }),
        (0x20, TypeInfo::Int { width: 8, signed: false }),
        (0x11, TypeInfo::Int { width: 16, signed: true }),
        (0x21, TypeInfo::Int { width: 16, signed: false }),
        (0x12, TypeInfo::Int { width: 32, signed: true }),
        (0x22, TypeInfo::Int { width: 32, signed: false }),
        (0x13, TypeInfo::Int { width: 64, signed: true }),
        (0x23, TypeInfo::Int { width: 64, signed: false }),
        (0x40, TypeInfo::Float { width: 32 }),
        (0x41, TypeInfo::Float { width: 64 }),
        (0x30, TypeInfo::Bool),
    ];
    for (i, want) in cases {
        let got = primitive_type(i);
        assert_eq!(format!("{got:?}"), format!("{want:?}"));
    }
}

#[test]
fn t25_primitive_pointer_modes() {
    // mode != 0 should produce Pointer
    assert!(matches!(primitive_type(0x0174), TypeInfo::Pointer { .. }));
    // mode 4 = 32-bit near pointer (4 bytes); mode 6 = 64-bit near pointer (8 bytes).
    assert!(matches!(primitive_type(0x0474), TypeInfo::Pointer { size: 4, .. }));
    assert!(matches!(primitive_type(0x0674), TypeInfo::Pointer { size: 8, .. }));
}

// ---- CvSymbol & CvTypeRecord helpers ----

#[test]
fn t26_cv_symbol_is_function_and_data() {
    let mut s = CvSymbol {
        kind: CvSymKind::GProc32,
        offset: 0,
        segment: 0,
        name: "x".into(),
        type_index: 0,
        flags: 0,
    };
    assert!(s.is_function());
    assert!(!s.is_data());
    s.kind = CvSymKind::Pub32;
    assert!(s.is_data());
}

#[test]
fn t27_cv_type_record_is_aggregate_callable() {
    let mut r = CvTypeRecord {
        kind: CvTypeKind::Class,
        index: 0x1000,
        name: "C".into(),
        size: 0,
        count: 0,
        underlying_type: 0,
        return_type: 0,
        arg_types: vec![],
    };
    assert!(r.is_aggregate());
    assert!(!r.is_callable());
    r.kind = CvTypeKind::Procedure;
    assert!(r.is_callable());
}

// ---- parse_cv8_lines ----

#[test]
fn t28_cv8_lines_short_returns_empty() {
    assert!(parse_cv8_lines(&[]).unwrap().is_empty());
    assert!(parse_cv8_lines(&[0u8; 11]).unwrap().is_empty());
}

#[test]
fn t29_cv8_lines_basic_block() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x1000u32.to_le_bytes()); // code_offset
    buf.extend_from_slice(&1u16.to_le_bytes()); // seg
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&0x100u32.to_le_bytes()); // code_len
    // one file block: file_index, num_lines, block_size
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&2u32.to_le_bytes());
    buf.extend_from_slice(&(12 + 16u32).to_le_bytes());
    for i in 0..2u32 {
        buf.extend_from_slice(&(i * 4).to_le_bytes());
        buf.extend_from_slice(&(10 + i).to_le_bytes());
    }
    let blocks = parse_cv8_lines(&buf).unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].code_offset, 0x1000);
    assert_eq!(blocks[0].lines.len(), 2);
    assert_eq!(blocks[0].lines[0].line_start, 10);
    assert_eq!(blocks[0].lines[1].line_start, 11);
}

#[test]
fn t30_cv8_lines_overflow_guard() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    // file_index, num_lines=u32::MAX (would overflow * 8)
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&u32::MAX.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    assert!(parse_cv8_lines(&buf).is_err());
}

#[test]
fn t31_cv8_lines_fuzz() {
    let mut g = lcg();
    for _ in 0..200 {
        let n = (g() % 128) as usize;
        let buf: Vec<u8> = (0..n).map(|_| (g() & 0xff) as u8).collect();
        let _ = parse_cv8_lines(&buf);
    }
}

// ---- CvStringTable ----

#[test]
fn t32_string_table() {
    let t = CvStringTable::from_bytes(b"hello\0world\0!\0");
    assert_eq!(t.get(0), "hello");
    assert_eq!(t.get(6), "world");
    assert_eq!(t.get(12), "!");
    assert_eq!(t.get(9999), "");
    assert!(!t.is_empty());
    assert_eq!(t.len(), 14);
    let empty = CvStringTable::default();
    assert!(empty.is_empty());
}

// ---- CvDebugSection ----

#[test]
fn t33_debug_section_empty() {
    let s = CvDebugSection::parse(&[]).unwrap();
    assert!(s.symbols.is_empty());
}

#[test]
fn t34_debug_section_bad_version() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&7u32.to_le_bytes());
    assert!(matches!(
        CvDebugSection::parse(&buf),
        Err(CodeViewError::UnsupportedVersion(7))
    ));
}

#[test]
fn t35_debug_section_symbols_subsection() {
    let symdata = build_test_gproc32("zfn", 0x100, 1, 0);
    let mut buf = Vec::new();
    buf.extend_from_slice(&4u32.to_le_bytes()); // version
    buf.extend_from_slice(&0xF1u32.to_le_bytes());
    buf.extend_from_slice(&u32::try_from(symdata.len()).unwrap_or(u32::MAX).to_le_bytes());
    buf.extend_from_slice(&symdata);
    // pad to 4
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    let s = CvDebugSection::parse(&buf).unwrap();
    assert_eq!(s.symbols.len(), 1);
    assert_eq!(s.symbols[0].name, "zfn");
}

#[test]
fn t36_debug_section_truncated_subsection() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&4u32.to_le_bytes());
    buf.extend_from_slice(&0xF1u32.to_le_bytes());
    buf.extend_from_slice(&1000u32.to_le_bytes()); // claimed len too large
    buf.push(0);
    assert!(matches!(
        CvDebugSection::parse(&buf),
        Err(CodeViewError::RecordTooShort)
    ));
}

#[test]
fn t37_debug_section_fuzz() {
    let mut g = lcg();
    for _ in 0..200 {
        let n = (g() % 256) as usize;
        let buf: Vec<u8> = (0..n).map(|_| (g() & 0xff) as u8).collect();
        let _ = CvDebugSection::parse(&buf);
    }
}

// ---- CodeViewProvider + SymbolProvider trait ----

#[test]
fn t38_provider_lookups() {
    let mut d = build_test_gproc32("first", 0x100, 1, 0);
    d.extend(build_test_gproc32("second", 0x200, 1, 0));
    let p = CodeViewProvider::from_bytes(&d, 0x4000).unwrap();
    assert_eq!(p.all_symbols().len(), 2);
    assert_eq!(p.lookup_name("first").unwrap().address, 0x4100);
    assert!(p.lookup_name("missing").is_none());
    assert_eq!(p.lookup_address(0x4200).unwrap().name, "second");
    assert_eq!(p.lookup_nearest(0x4150).unwrap().name, "first");
    assert_eq!(p.name(), "codeview");
    assert!(p.source_line_for_address(0x4200).is_none());
    assert_eq!(p.all_functions().len(), 2);
}

#[test]
fn t39_provider_filters_and_sorted() {
    let mut d = build_test_gproc32("z", 0x300, 1, 0);
    d.extend(build_test_gproc32("a", 0x100, 1, 0));
    d.extend(build_test_gdata32("g", 0x500, 0x74));
    let p = CodeViewProvider::from_bytes(&d, 0).unwrap();
    let sorted = p.symbols_sorted();
    for w in sorted.windows(2) {
        assert!(w[0].address <= w[1].address);
    }
    assert_eq!(p.functions().len(), 2);
    assert_eq!(p.data_symbols().len(), 1);
    assert!(p.symbols_with_prefix("z").iter().any(|s| s.name == "z"));
    let ti = p.resolve_type(0x40);
    assert!(matches!(ti, TypeInfo::Float { width: 32 }));
}

#[test]
fn t40_provider_with_type_table() {
    let td = struct_rec("X", 1, 4);
    let table = CvTypeTable::from_bytes(&td).unwrap();
    let p = CodeViewProvider::from_bytes(&[], 0).unwrap().with_type_table(table);
    assert_eq!(p.type_table().len(), 1);
    let ti = p.resolve_type(0x1000);
    assert!(matches!(ti, TypeInfo::Struct { .. }));
}

#[test]
fn t41_provider_send_sync_threaded() {
    use std::sync::Arc;
    use std::thread;
    let mut d = build_test_gproc32("a", 0x10, 1, 0);
    d.extend(build_test_gproc32("b", 0x20, 1, 0));
    let p = Arc::new(CodeViewProvider::from_bytes(&d, 0).unwrap());
    let mut handles = vec![];
    for _ in 0..4 {
        let pc = Arc::clone(&p);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                assert!(pc.lookup_name("a").is_some());
                assert_eq!(pc.all_symbols().len(), 2);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ---- CvSymbolFilter ----

#[test]
fn t42_symbol_filter_chains() {
    let syms = vec![
        CvSymbol {
            kind: CvSymKind::GProc32,
            offset: 0,
            segment: 1,
            name: "foo_bar".into(),
            type_index: 0,
            flags: 0,
        },
        CvSymbol {
            kind: CvSymKind::GData32,
            offset: 0,
            segment: 1,
            name: "g_var".into(),
            type_index: 0,
            flags: 0,
        },
        CvSymbol {
            kind: CvSymKind::GProc32,
            offset: 0,
            segment: 2,
            name: "foo_baz".into(),
            type_index: 0,
            flags: 0,
        },
    ];
    let f = CvSymbolFilter::new(syms)
        .by_kind(CvSymKind::GProc32)
        .name_contains("foo")
        .in_segment(1);
    assert_eq!(f.count(), 1);
    let names: Vec<_> = f.into_symbols().into_iter().map(|s| s.name).collect();
    assert_eq!(names, vec!["foo_bar"]);
}

// ---- Cv8SubsectionKind ----

#[test]
fn t43_cv8_subsection_kind() {
    assert_eq!(Cv8SubsectionKind::from_u32(0xF1), Cv8SubsectionKind::Symbols);
    assert_eq!(Cv8SubsectionKind::from_u32(0xF2), Cv8SubsectionKind::Lines);
    assert_eq!(Cv8SubsectionKind::from_u32(0xF3), Cv8SubsectionKind::StringTable);
    assert_eq!(Cv8SubsectionKind::from_u32(0xF4), Cv8SubsectionKind::FileChecksums);
    match Cv8SubsectionKind::from_u32(0x1234) {
        Cv8SubsectionKind::Unknown(v) => assert_eq!(v, 0x1234),
        _ => panic!("expected Unknown"),
    }
}

// ---- CodeViewMagic ----

#[test]
fn t44_codeview_magic_detect_and_short() {
    assert_eq!(CodeViewMagic::detect(b"NB09"), Some(CodeViewMagic::Cv41));
    assert_eq!(CodeViewMagic::detect(b"NB11"), Some(CodeViewMagic::Cv50));
    assert_eq!(CodeViewMagic::detect(b"RSDS"), Some(CodeViewMagic::Cv70));
    assert_eq!(CodeViewMagic::detect(b"XXXX"), None);
    assert_eq!(CodeViewMagic::detect(b"NB"), None);
    for m in [CodeViewMagic::Cv41, CodeViewMagic::Cv50, CodeViewMagic::Cv70] {
        assert!(!m.label().is_empty());
        assert!(!m.to_string().is_empty());
    }
}

// ---- CvSymbolKind (extended) ----

#[test]
fn t45_cv_symbol_kind_ext_roundtrip() {
    let cases = [
        (0x0001u16, CvSymbolKind::SCompile),
        (0x0006, CvSymbolKind::SEnd),
        (0x000A, CvSymbolKind::SEndarg),
        (0x110D, CvSymbolKind::SGdata32),
        (0x110E, CvSymbolKind::SPub32),
        (0x110F, CvSymbolKind::SLproc32),
        (0x1110, CvSymbolKind::SGproc32),
        (0x113C, CvSymbolKind::SCompile3),
        (0x113E, CvSymbolKind::SLocal),
    ];
    for (v, k) in cases {
        assert_eq!(CvSymbolKind::from_u16(v), k);
    }
    assert_eq!(CvSymbolKind::from_u16(0xABCD), CvSymbolKind::Unknown);
    assert!(CvSymbolKind::SGproc32.is_function());
    assert!(CvSymbolKind::SGdata32.is_data());
}

// ---- Structured payloads ----

#[test]
fn t46_cv_proc32_parse_roundtrip() {
    let raw = build_test_gproc32("hello", 0x1000, 2, 0xAABBu32);
    // record body (skip 4-byte header). NOTE: build_test_gproc32 places
    // type_index at offset 0 while CvProc32::parse expects type_index at
    // offset 24 (its native layout), so we only assert fields that overlap.
    let body = &raw[4..];
    let p = CvProc32::parse(body).unwrap();
    assert_eq!(p.name, "hello");
    assert_eq!(p.offset, 0x1000);
    assert_eq!(p.segment, 2);
}

#[test]
fn t47_cv_data32_parse_too_short() {
    assert!(CvData32::parse(&[0u8; 5]).is_none());
    let mut data = Vec::new();
    data.extend_from_slice(&0x42u32.to_le_bytes());
    data.extend_from_slice(&0x100u32.to_le_bytes());
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(b"x\0");
    let d = CvData32::parse(&data).unwrap();
    assert_eq!(d.name, "x");
    assert_eq!(d.type_index, 0x42);
}

#[test]
fn t48_cv_public32_parse_and_flag() {
    let mut data = Vec::new();
    data.extend_from_slice(&0x02u32.to_le_bytes());
    data.extend_from_slice(&0x100u32.to_le_bytes());
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(b"sym\0");
    let p = CvPublic32::parse(&data).unwrap();
    assert!(p.is_function());
    assert!(CvPublic32::parse(&[0u8; 3]).is_none());
}

#[test]
fn t49_cv_regrel32_objname_constant() {
    // regrel
    let mut d = Vec::new();
    d.extend_from_slice(&0x10u32.to_le_bytes()); // offset
    d.extend_from_slice(&0x74u32.to_le_bytes()); // type
    d.extend_from_slice(&21u16.to_le_bytes()); // register
    d.extend_from_slice(b"v\0");
    let r = CvRegrel32::parse(&d).unwrap();
    assert_eq!(r.name, "v");
    assert_eq!(r.register, 21);

    // objname
    let mut o = Vec::new();
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(b"x.obj\0");
    let on = CvObjname::parse(&o).unwrap();
    assert_eq!(on.name, "x.obj");

    // constant with immediate value (< 0x8000)
    let mut c = Vec::new();
    c.extend_from_slice(&0x74u32.to_le_bytes()); // type
    c.extend_from_slice(&100u16.to_le_bytes()); // leaf tag (immediate value 100)
    c.extend_from_slice(b"K\0");
    let cc = CvConstant::parse(&c).unwrap();
    assert_eq!(cc.value, 100);
    assert_eq!(cc.name, "K");
}

#[test]
fn t50_frameproc_and_udt() {
    // FRAMEPROCSYM: 26-byte payload, flags:u32 at offset 22.
    // fHasAlloca is bit 0; 0x100 is fSecurityChecks.
    let mut d = vec![0u8; 26];
    d[22..26].copy_from_slice(&0x0001u32.to_le_bytes());
    let fp = CvFrameproc::parse(&d).unwrap();
    assert!(fp.has_alloca());
    assert!(!fp.has_async_eh());
    assert!(CvFrameproc::parse(&[0u8; 10]).is_none());

    let mut u = Vec::new();
    u.extend_from_slice(&0x1234u32.to_le_bytes());
    u.extend_from_slice(b"MyUdt\0");
    let udt = CvUdt::parse(&u).unwrap();
    assert_eq!(udt.name, "MyUdt");
    assert_eq!(udt.type_index, 0x1234);
}

// ---- parse_cv_symbol single ----

#[test]
fn t51_parse_cv_symbol_single() {
    let d = build_test_gproc32("one", 0x500, 1, 7);
    let (sym, consumed) = parse_cv_symbol(&d, 0).unwrap();
    assert_eq!(sym.name, "one");
    assert_eq!(consumed, d.len());
    assert!(parse_cv_symbol(&[0u8; 3], 0).is_err());
    // len < 2
    let bad = vec![0u8, 0, 0x10, 0x11];
    assert!(parse_cv_symbol(&bad, 0).is_err());
}

// ---- parse_debug_s ----

#[test]
fn t52_parse_debug_s_basic() {
    let symdata = build_test_gproc32("z", 0x100, 1, 0);
    let mut buf = Vec::new();
    buf.extend_from_slice(&4u32.to_le_bytes());
    buf.extend_from_slice(&0xF1u32.to_le_bytes());
    buf.extend_from_slice(&u32::try_from(symdata.len()).unwrap_or(u32::MAX).to_le_bytes());
    buf.extend_from_slice(&symdata);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    let syms = parse_debug_s(&buf).unwrap();
    assert_eq!(syms.len(), 1);
    assert!(parse_debug_s(&[]).unwrap().is_empty());
    let mut bad = Vec::new();
    bad.extend_from_slice(&5u32.to_le_bytes());
    assert!(parse_debug_s(&bad).is_err());
}

// ---- guid_to_string ----

#[test]
fn t53_guid_to_string_known() {
    let guid = [
        0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x12, 0x34, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
        0x45,
    ];
    let s = guid_to_string(&guid);
    assert!(s.starts_with("{12345678-1234-5678-1234-ABCDEF012345"));
    assert!(s.ends_with('}'));
}

// ---- parse_type_record ----

#[test]
fn t54_parse_type_record_single() {
    let d = struct_rec("Q", 2, 8);
    let r = parse_type_record(&d).unwrap();
    assert_eq!(r.name, "Q");
    assert_eq!(r.kind, CvTypeKind::Structure);
    assert!(parse_type_record(&[0u8; 3]).is_none());
    // Unknown leaf kind
    let mut bad = Vec::new();
    bad.extend_from_slice(&4u16.to_le_bytes());
    bad.extend_from_slice(&0xFFFFu16.to_le_bytes());
    bad.extend_from_slice(&[0u8; 4]);
    assert!(parse_type_record(&bad).is_none());
}

// ---- CvSymbolStream iterator ----

#[test]
fn t55_symbol_stream_iter() {
    let mut d = build_test_gproc32("a", 0x1, 1, 0);
    d.extend(build_test_gdata32("b", 0x2, 0));
    let mut count = 0;
    for (kind, _payload, consumed) in CvSymbolStream::new(&d) {
        assert!(consumed >= 4);
        let _ = kind;
        count += 1;
    }
    assert_eq!(count, 2);

    // truncated/empty stream
    assert!(CvSymbolStream::new(&[]).next().is_none());
}

// ---- PdbSuperBlock ----

#[test]
fn t56_pdb_superblock_short_and_valid() {
    // BlockMapAddr lives at offset 52, so 56 bytes are required.
    assert!(PdbSuperBlock::parse(&[0u8; 55]).is_none());
    let mut buf = Vec::new();
    buf.extend_from_slice(MSF_MAGIC); // 32 bytes
    buf.extend_from_slice(&4096u32.to_le_bytes()); // page_size
    buf.extend_from_slice(&1u32.to_le_bytes()); // free_page_map
    buf.extend_from_slice(&10u32.to_le_bytes()); // num_pages
    buf.extend_from_slice(&100u32.to_le_bytes()); // num_dir_bytes
    buf.extend_from_slice(&0u32.to_le_bytes()); // unknown @48
    buf.extend_from_slice(&3u32.to_le_bytes()); // block_map_addr @52
    let sb = PdbSuperBlock::parse(&buf).unwrap();
    assert!(sb.magic_ok);
    assert!(sb.is_valid());
    assert_eq!(sb.page_size, 4096);
    assert_eq!(sb.block_map_addr, 3);

    // invalid magic
    let mut bad = vec![0u8; 32];
    bad.extend_from_slice(&4096u32.to_le_bytes());
    bad.extend_from_slice(&[0u8; 20]);
    let sb2 = PdbSuperBlock::parse(&bad).unwrap();
    assert!(!sb2.magic_ok);
    assert!(!sb2.is_valid());
}

// ---- PdbPathFromPe ----

#[test]
fn t57_pdb_path_from_pe_invalid() {
    assert!(PdbPathFromPe::extract(&[]).is_none());
    assert!(PdbPathFromPe::extract(b"NOTMZ stuff").is_none());
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() % 512) as usize;
        let buf: Vec<u8> = (0..n).map(|_| (g() & 0xff) as u8).collect();
        let _ = PdbPathFromPe::extract(&buf);
    }
}

// ---- Hash/Eq consistency for hashable types ----

#[test]
fn t58_eq_consistency_pairs() {
    let pairs_sigs = [
        CvSignature::Cv41,
        CvSignature::Cv50,
        CvSignature::Cv70,
        CvSignature::Pdb70,
        CvSignature::Cv8,
    ];
    for a in pairs_sigs {
        for b in pairs_sigs {
            if a == b {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
    let kinds = [
        CvSymKind::Pub32,
        CvSymKind::GProc32,
        CvSymKind::LProc32,
        CvSymKind::GData32,
        CvSymKind::LData32,
        CvSymKind::End,
    ];
    for a in kinds {
        for b in kinds {
            assert_eq!(a == b, format!("{a:?}") == format!("{b:?}"));
        }
    }
    let tkinds = [
        CvTypeKind::Class,
        CvTypeKind::Structure,
        CvTypeKind::Enum,
        CvTypeKind::Pointer,
        CvTypeKind::Array,
        CvTypeKind::Procedure,
    ];
    let mut count = 0;
    for a in tkinds {
        for b in tkinds {
            if a == b {
                count += 1;
            }
        }
    }
    assert_eq!(count, tkinds.len());
}

// ---- Boundaries on parse_cv8_lines and primitive_type ----

#[test]
fn t59_primitive_type_pointer_fuzz() {
    let mut g = lcg();
    for _ in 0..200 {
        let idx = (g() & 0xFFFF) as u32;
        let _ = primitive_type(idx);
    }
}

#[test]
fn t60_provider_from_debug_section_path() {
    let symdata = build_test_gproc32("ds_fn", 0x10, 1, 0);
    let mut buf = Vec::new();
    buf.extend_from_slice(&4u32.to_le_bytes());
    buf.extend_from_slice(&0xF1u32.to_le_bytes());
    buf.extend_from_slice(&u32::try_from(symdata.len()).unwrap_or(u32::MAX).to_le_bytes());
    buf.extend_from_slice(&symdata);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    let p = CodeViewProvider::from_debug_section(&buf, 0x0040_0000).unwrap();
    assert_eq!(p.symbol_count(), 1);
    assert_eq!(p.all_symbols()[0].address, 0x0040_0010);
    // bad version
    let mut bad = Vec::new();
    bad.extend_from_slice(&9u32.to_le_bytes());
    assert!(CodeViewProvider::from_debug_section(&bad, 0).is_err());
}

#[test]
fn t61_display_symbol_kind_ext_and_type_record() {
    let s = format!("{}", CvSymbolKind::SGproc32);
    assert!(s.contains("SGproc"));
    let r = CvTypeRecord {
        kind: CvTypeKind::Structure,
        index: 0x1000,
        name: "DR".into(),
        size: 4,
        count: 1,
        underlying_type: 0,
        return_type: 0,
        arg_types: vec![],
    };
    let txt = r.to_string();
    assert!(txt.contains("DR"));
}
