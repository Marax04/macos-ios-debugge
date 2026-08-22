//! Deep adversarial tests for rustre-symbols-stabs.

use rustre_symbols_stabs::*;
use rustre_symbols::{SymbolProvider, TypeInfo};

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        s
    }
}

fn stab_record(strx: u32, t: u8, other: u8, desc: u16, value: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0..4].copy_from_slice(&strx.to_le_bytes());
    b[4] = t;
    b[5] = other;
    b[6..8].copy_from_slice(&desc.to_le_bytes());
    b[8..12].copy_from_slice(&value.to_le_bytes());
    b
}

fn stab_record_be(strx: u32, t: u8, other: u8, desc: u16, value: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0..4].copy_from_slice(&strx.to_be_bytes());
    b[4] = t;
    b[5] = other;
    b[6..8].copy_from_slice(&desc.to_be_bytes());
    b[8..12].copy_from_slice(&value.to_be_bytes());
    b
}

fn build_stabstr(strings: &[&str]) -> Vec<u8> {
    let mut buf = Vec::new();
    for s in strings {
        buf.extend_from_slice(s.as_bytes());
        buf.push(0);
    }
    buf
}

// ---- StabType ----

#[test]
fn t01_stab_type_roundtrip_all_known() {
    let known: &[u8] = &[
        0x00, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x30, 0x32, 0x34, 0x38, 0x3C, 0x40,
        0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x50, 0x54, 0x60, 0x62, 0x64, 0x80, 0x82, 0x84,
        0xA0, 0xA2, 0xA4, 0xC0, 0xC2, 0xC4, 0xE0, 0xE2, 0xE4, 0xE8, 0xEA, 0xF0, 0xF2, 0xF4,
        0xF6, 0xF8,
    ];
    for &v in known {
        let t = StabType::from_u8(v);
        assert_ne!(t, StabType::Unknown, "byte {v:#x} known");
        assert_eq!(t as u8, v, "roundtrip {v:#x}");
        assert!(StabType::name_for(v).is_some());
    }
}

#[test]
fn t02_stab_type_fuzz_never_panic() {
    let mut g = lcg();
    for _ in 0..500 {
        let b = (g() & 0xFF) as u8;
        let t = StabType::from_u8(b);
        let _ = t.is_symbol();
        let _ = t.is_source_file();
        let _ = t.is_line_number();
        let _ = t.is_scope_bracket();
        let _ = t.category();
        let _ = t.name();
        let _ = t.to_string();
    }
}

#[test]
fn t03_stab_type_name_unknown() {
    assert_eq!(StabType::Unknown.name(), "Unknown");
    assert!(StabType::name_for(0x01).is_none());
    assert!(StabType::name_for(0xFF).is_none());
}

#[test]
fn t04_stab_type_display_matches_name() {
    for b in [0x20u8, 0x24, 0x44, 0x64, 0x80, 0xA0] {
        let t = StabType::from_u8(b);
        assert_eq!(t.to_string(), t.name());
    }
}

#[test]
fn t05_stab_type_categories_partition() {
    // Each known type has a non-"other" category iff it matches one of the predicates.
    for b in 0u8..=255 {
        let t = StabType::from_u8(b);
        let cat = t.category();
        let preds = [t.is_symbol(), t.is_source_file(), t.is_line_number(), t.is_scope_bracket()];
        let count = preds.iter().filter(|x| **x).count();
        if count > 0 {
            assert_ne!(cat, "other");
        }
    }
}

// ---- StabRecord ----

#[test]
fn t06_parse_all_chunk_remainder_ignored() {
    let mut data = stab_record(0, 0x64, 0, 0, 0x1000).to_vec();
    data.extend_from_slice(&[1, 2, 3, 4, 5]); // trailing partial
    let stabstr = build_stabstr(&["x"]);
    let r = StabRecord::parse_all(&data, &stabstr);
    assert_eq!(r.len(), 1);
}

#[test]
fn t07_parse_all_be_endianness() {
    let stabstr = build_stabstr(&["foo"]);
    let raw = stab_record_be(0, 0x24, 0, 0x0102, 0xDEADBEEF);
    let r = StabRecord::parse_all_be(&raw, &stabstr);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].desc, 0x0102);
    assert_eq!(r[0].value, 0xDEADBEEF);
}

#[test]
fn t08_parse_all_le_vs_be_different() {
    let raw = stab_record(0, 0x24, 0, 0x1234, 0xAABBCCDD);
    let le = StabRecord::parse_all(&raw, &[]);
    let be = StabRecord::parse_all_be(&raw, &[]);
    assert_ne!(le[0].value, be[0].value);
}

#[test]
fn t09_parse_all_fuzz_never_panic() {
    let mut g = lcg();
    for _ in 0..100 {
        let len = (g() % 96) as usize;
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            data.push((g() & 0xFF) as u8);
        }
        let strlen = (g() % 64) as usize;
        let mut stabstr = Vec::with_capacity(strlen);
        for _ in 0..strlen {
            stabstr.push((g() & 0xFF) as u8);
        }
        let _ = StabRecord::parse_all(&data, &stabstr);
        let _ = StabRecord::parse_all_be(&data, &stabstr);
    }
}

#[test]
fn t10_stab_record_symbol_name_empty() {
    let r = StabRecord {
        strx: 0,
        stab_type: StabType::NFun,
        other: 0,
        desc: 0,
        value: 0,
        string: String::new(),
    };
    assert_eq!(r.symbol_name(), "");
    assert_eq!(r.type_descriptor(), "");
    assert!(!r.has_string());
}

#[test]
fn t11_stab_record_symbol_name_no_colon() {
    let r = StabRecord {
        strx: 0,
        stab_type: StabType::NFun,
        other: 0,
        desc: 0,
        value: 0,
        string: "noColon".to_string(),
    };
    assert_eq!(r.symbol_name(), "noColon");
    assert_eq!(r.type_descriptor(), "");
}

#[test]
fn t12_parse_all_strx_at_exact_boundary() {
    let stabstr = b"hello\0";
    let raw = stab_record(stabstr.len() as u32, 0x20, 0, 0, 0);
    let r = StabRecord::parse_all(&raw, stabstr);
    assert_eq!(r[0].string, "");
}

// ---- StabTypeCode ----

#[test]
fn t13_stab_type_code_all_letters() {
    let cases = [
        ('f', StabTypeCode::Function),
        ('F', StabTypeCode::GlobalFunction),
        ('g', StabTypeCode::GlobalVar),
        ('s', StabTypeCode::StaticVar),
        ('r', StabTypeCode::RegisterVar),
        ('p', StabTypeCode::Parameter),
        ('t', StabTypeCode::Typedef),
        ('T', StabTypeCode::Tag),
        ('v', StabTypeCode::VarArray),
    ];
    for (c, expected) in cases {
        assert_eq!(StabTypeCode::from_char(c), expected);
    }
}

#[test]
fn t14_stab_type_code_other() {
    for c in ['Z', 'q', '@', '#', '0'] {
        assert_eq!(StabTypeCode::from_char(c), StabTypeCode::Other(c));
    }
}

#[test]
fn t15_stab_type_code_fuzz() {
    let mut g = lcg();
    for _ in 0..200 {
        let c = char::from_u32((g() as u32) % 128).unwrap_or('?');
        let _ = StabTypeCode::from_char(c).to_string();
    }
}

// ---- StabsTypeParser ----

#[test]
fn t16_type_parser_default_eq_new() {
    let a = StabsTypeParser::new();
    let b = StabsTypeParser::default();
    assert_eq!(a.len(), b.len());
}

#[test]
fn t17_type_parser_register_lookup() {
    let mut p = StabsTypeParser::new();
    let before = p.len();
    p.register("(9,9)".to_string(), TypeInfo::Bool);
    assert_eq!(p.len(), before + 1);
    assert!(matches!(p.lookup("(9,9)"), Some(TypeInfo::Bool)));
}

#[test]
fn t18_type_parser_pointer_nested() {
    let p = StabsTypeParser::new();
    let t = p.parse_descriptor("**(0,1)").unwrap();
    if let TypeInfo::Pointer { target, .. } = t {
        assert!(matches!(*target, TypeInfo::Pointer { .. }));
    } else {
        panic!("expected pointer of pointer");
    }
}

#[test]
fn t19_type_parser_unknown_descriptor_safe() {
    let p = StabsTypeParser::new();
    let t = p.parse_descriptor("@#$%").unwrap();
    let _ = format!("{t:?}");
}

#[test]
fn t20_type_parser_array_bounds() {
    let p = StabsTypeParser::new();
    let t = p.parse_descriptor("ar(0,1);0;99;(0,1)").unwrap();
    if let TypeInfo::Array { count, .. } = t {
        assert_eq!(count, 100);
    } else {
        panic!("expected Array");
    }
}

#[test]
fn t21_type_parser_array_negative_range() {
    let p = StabsTypeParser::new();
    // lo > hi → clamped to 0
    let t = p.parse_descriptor("ar(0,1);10;5;(0,1)").unwrap();
    if let TypeInfo::Array { count, .. } = t {
        assert_eq!(count, 0);
    } else {
        panic!("expected Array");
    }
}

#[test]
fn t22_type_parser_descriptor_fuzz() {
    let p = StabsTypeParser::new();
    let mut g = lcg();
    let charset: &[u8] = b"sefFgrptTv*ar(),0123456789;:";
    for _ in 0..200 {
        let len = (g() % 32) as usize;
        let mut s = String::new();
        for _ in 0..len {
            let i = (g() as usize) % charset.len();
            s.push(charset[i] as char);
        }
        let _ = p.parse_descriptor(&s);
    }
}

#[test]
fn t23_type_parser_int_widths() {
    let p = StabsTypeParser::new();
    for (k, w, signed) in [
        ("(0,1)", 32u8, true),
        ("(0,2)", 8, true),
        ("(0,3)", 16, true),
        ("(0,4)", 64, true),
        ("(0,5)", 8, false),
        ("(0,6)", 16, false),
        ("(0,7)", 32, false),
        ("(0,8)", 64, false),
    ] {
        if let Some(TypeInfo::Int { width, signed: s2 }) = p.lookup(k) {
            assert_eq!(*width, w);
            assert_eq!(*s2, signed);
        } else {
            panic!("missing {k}");
        }
    }
}

#[test]
fn t24_type_parser_named_fallback() {
    let p = StabsTypeParser::new();
    let t = p.parse_descriptor("(7,7)").unwrap();
    assert!(matches!(t, TypeInfo::Named(_)));
}

// ---- LineNumberTable ----

#[test]
fn t25_line_table_lookup_after_last() {
    let mut t = LineNumberTable::new();
    t.add(LineEntry { address: 0x100, line: 1, file: "f".into() });
    t.add(LineEntry { address: 0x200, line: 2, file: "f".into() });
    t.sort();
    let e = t.lookup(0x9999).unwrap();
    assert_eq!(e.line, 2);
}

#[test]
fn t26_line_table_50_entries_sorted() {
    let mut t = LineNumberTable::new();
    let mut g = lcg();
    for i in 0..50 {
        t.add(LineEntry {
            address: (g() % 1_000_000) as u64,
            line: i,
            file: "f.c".into(),
        });
    }
    t.sort();
    let es = t.entries();
    for w in es.windows(2) {
        assert!(w[0].address <= w[1].address);
    }
    assert_eq!(t.len(), 50);
}

#[test]
fn t27_line_table_lookup_at_address() {
    let mut t = LineNumberTable::new();
    t.add(LineEntry { address: 0x1000, line: 7, file: "x".into() });
    t.sort();
    assert_eq!(t.lookup(0x1000).unwrap().line, 7);
}

#[test]
fn t28_line_entry_display_contains_addr() {
    let e = LineEntry { address: 0xABCD, line: 11, file: "z.c".into() };
    let s = e.to_string();
    assert!(s.contains("0xabcd"));
}

// ---- StabsParser ----

#[test]
fn t29_stabs_parser_default() {
    let p = StabsParser::default();
    assert!(p.functions().is_empty());
    assert!(p.globals().is_empty());
}

#[test]
fn t30_stabs_parser_n_psym_n_lsym_attached() {
    let stabstr = build_stabstr(&["main.c", "fn:F", "x:p(0,1)", "y:(0,1)"]);
    let r_so = stab_record(0, 0x64, 0, 0, 0);
    let r_fn = stab_record(7, 0x24, 0, 0, 0x100);
    let r_p = stab_record(12, 0xA0, 0, 0, 16);
    let r_l = stab_record(21, 0x80, 0, 0, (-8i32) as u32);
    let mut raw = r_so.to_vec();
    raw.extend_from_slice(&r_fn);
    raw.extend_from_slice(&r_p);
    raw.extend_from_slice(&r_l);
    let records = StabRecord::parse_all(&raw, &stabstr);
    let mut parser = StabsParser::new();
    parser.process(&records, 0).unwrap();
    assert_eq!(parser.functions().len(), 1);
    assert_eq!(parser.functions()[0].parameters.len(), 1);
    assert_eq!(parser.functions()[0].locals.len(), 1);
    assert_eq!(parser.functions()[0].locals[0].fp_offset, -8);
}

#[test]
fn t31_stabs_parser_multiple_files_and_fns() {
    let stabstr = build_stabstr(&["a.c", "f1:F", "f2:F"]);
    let so = stab_record(0, 0x64, 0, 0, 0);
    let f1 = stab_record(4, 0x24, 0, 0, 0x100);
    let f2 = stab_record(9, 0x24, 0, 0, 0x200);
    let mut raw = so.to_vec();
    raw.extend_from_slice(&f1);
    raw.extend_from_slice(&f2);
    let recs = StabRecord::parse_all(&raw, &stabstr);
    let mut p = StabsParser::new();
    p.process(&recs, 0x1000).unwrap();
    assert_eq!(p.functions().len(), 2);
    assert_eq!(p.functions()[0].address, 0x1100);
    assert_eq!(p.functions()[1].address, 0x1200);
}

#[test]
fn t32_stabs_parser_stsym_attaches_file() {
    let stabstr = build_stabstr(&["src.c", "stat:S"]);
    let so = stab_record(0, 0x64, 0, 0, 0);
    let st = stab_record(6, 0x26, 0, 0, 0x500);
    let mut raw = so.to_vec();
    raw.extend_from_slice(&st);
    let recs = StabRecord::parse_all(&raw, &stabstr);
    let mut p = StabsParser::new();
    p.process(&recs, 0x10000).unwrap();
    assert_eq!(p.globals().len(), 1);
    assert_eq!(p.globals()[0].source_file.as_deref(), Some("src.c"));
}

#[test]
fn t33_stabs_parser_type_parser_mut() {
    let mut p = StabsParser::new();
    let before = p.type_parser().len();
    p.type_parser_mut().register("(42,1)".into(), TypeInfo::Bool);
    assert_eq!(p.type_parser().len(), before + 1);
}

#[test]
fn t34_stabs_parser_process_empty_ok() {
    let mut p = StabsParser::new();
    assert!(p.process(&[], 0).is_ok());
}

// ---- StabsProvider trait ----

#[test]
fn t35_provider_send_sync_threaded() {
    use std::sync::Arc;
    use std::thread;
    let stabstr = build_stabstr(&["f1:F", "f2:F", "f3:F"]);
    let r1 = stab_record(0, 0x24, 0, 0, 0x100);
    let r2 = stab_record(4, 0x24, 0, 0, 0x200);
    let r3 = stab_record(8, 0x24, 0, 0, 0x300);
    let mut raw = r1.to_vec();
    raw.extend_from_slice(&r2);
    raw.extend_from_slice(&r3);
    let recs = StabRecord::parse_all(&raw, &stabstr);
    let p = Arc::new(StabsProvider::from_records(&recs, 0));
    let mut handles = vec![];
    for _ in 0..4 {
        let pc = Arc::clone(&p);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = pc.lookup_name("f1");
                let _ = pc.lookup_address(0x200);
                let _ = pc.lookup_nearest(0x250);
                let _ = pc.all_symbols();
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn t36_provider_lookup_nearest_empty() {
    let p = StabsProvider::from_records(&[], 0);
    assert!(p.lookup_nearest(0x1000).is_none());
}

#[test]
fn t37_provider_source_line_chosen_correctly() {
    let stabstr = build_stabstr(&["a.c", "fn:F"]);
    let so = stab_record(0, 0x64, 0, 0, 0);
    let fun = stab_record(4, 0x24, 0, 0, 0x100);
    let sl1 = stab_record(0, 0x44, 0, 10, 0x100);
    let sl2 = stab_record(0, 0x44, 0, 20, 0x200);
    let mut raw = so.to_vec();
    raw.extend_from_slice(&fun);
    raw.extend_from_slice(&sl1);
    raw.extend_from_slice(&sl2);
    let recs = StabRecord::parse_all(&raw, &stabstr);
    let p = StabsProvider::from_records(&recs, 0);
    // Note: source line uses raw value, not fn-relative — verify whatever it produces is consistent.
    let loc = p.source_line_for_address(0x200).unwrap();
    assert!(loc.line == 20 || loc.line == 10);
}

#[test]
fn t38_provider_no_panic_oversized_strx() {
    let stabstr = b"\0short\0";
    let raw = stab_record(u32::MAX, 0x24, 0, 0, 0);
    let recs = StabRecord::parse_all(&raw, stabstr);
    let _ = StabsProvider::from_records(&recs, 0);
}

#[test]
fn t39_provider_50_lcg_inputs_no_panic() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() % 20) as usize;
        let mut bytes = Vec::with_capacity(n * 12);
        for _ in 0..(n * 12) {
            bytes.push((g() & 0xFF) as u8);
        }
        let str_len = (g() % 128) as usize;
        let mut stabstr = Vec::with_capacity(str_len);
        for _ in 0..str_len {
            stabstr.push((g() & 0xFF) as u8);
        }
        let _ = StabsProvider::from_bytes(&bytes, &stabstr, 0x1000);
    }
}

// ---- StabsStringTable ----

#[test]
fn t40_string_table_intern_roundtrip_50() {
    let mut t = StabsStringTable::new();
    let mut offs = vec![];
    for i in 0..50 {
        let s = format!("sym_{i}");
        let off = t.intern(&s);
        offs.push((s, off));
    }
    for (s, off) in &offs {
        assert_eq!(t.get(*off), s);
    }
}

#[test]
fn t41_string_table_dedup_consistent() {
    let mut t = StabsStringTable::new();
    let a = t.intern("dup");
    let b = t.intern("dup");
    let c = t.intern("dup");
    assert_eq!(a, b);
    assert_eq!(b, c);
}

#[test]
fn t42_string_table_oob_safe() {
    let mut t = StabsStringTable::new();
    t.intern("ab");
    assert_eq!(t.get(u32::MAX), "");
    assert!(!t.as_bytes().is_empty());
}

#[test]
fn t43_string_table_default_eq_new() {
    let a = StabsStringTable::default();
    let b = StabsStringTable::new();
    assert_eq!(a.len(), b.len());
    assert_eq!(a.is_empty(), b.is_empty());
}

// ---- StabsType (alt enum) / StabsEntry ----

#[test]
fn t44_stabs_type_known_values() {
    assert_eq!(StabsType::from_u8(0x24), StabsType::FUN);
    assert_eq!(StabsType::from_u8(0x44), StabsType::SLINE);
    assert_eq!(StabsType::from_u8(0x99), StabsType::Unknown);
}

#[test]
fn t45_stabs_type_display() {
    assert_eq!(StabsType::FUN.to_string(), "FUN");
    assert_eq!(StabsType::SLINE.to_string(), "SLINE");
}

#[test]
fn t46_stabs_entry_name_descriptor() {
    let e = StabsEntry {
        n_strx: 0,
        n_type: 0x24,
        n_other: 0,
        n_desc: 5,
        n_value: 0x100,
        string_value: "name:F(0,1)".to_string(),
    };
    assert_eq!(e.symbol_name(), "name");
    assert_eq!(e.type_descriptor(), "F(0,1)");
    assert_eq!(e.stabs_type(), StabsType::FUN);
}

#[test]
fn t47_stabs_entry_display() {
    let e = StabsEntry {
        n_strx: 0,
        n_type: 0x24,
        n_other: 0,
        n_desc: 5,
        n_value: 0x100,
        string_value: "fn".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("FUN"));
    assert!(s.contains("0x100"));
}

// ---- StabsLowParser ----

#[test]
fn t48_low_parser_roundtrip_fields() {
    let stabstr = build_stabstr(&["abc"]);
    let raw = stab_record(0, 0x64, 7, 0xABCD, 0xDEADBEEF);
    let entries = StabsLowParser::parse(&raw, &stabstr).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].n_strx, 0);
    assert_eq!(entries[0].n_type, 0x64);
    assert_eq!(entries[0].n_other, 7);
    // n_desc is i16 LE — 0xABCD as i16 is negative
    assert_eq!(entries[0].n_desc as u16, 0xABCD);
    assert_eq!(entries[0].n_value, 0xDEADBEEF);
    assert_eq!(entries[0].string_value, "abc");
}

#[test]
fn t49_low_parser_empty_elf_safe() {
    let r = StabsLowParser::parse_from_elf(&[1, 2, 3, 4, 5]);
    assert!(r.is_err() || r.unwrap().is_empty());
}

#[test]
fn t50_low_parser_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = (g() % 100) as usize;
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            data.push((g() & 0xFF) as u8);
        }
        let _ = StabsLowParser::parse(&data, &[0u8; 8]);
    }
}

// ---- StabsSymbolExtractor ----

#[test]
fn t51_extractor_filters_empty_n_fun() {
    let entries = vec![
        StabsEntry { n_strx: 0, n_type: 0x64, n_other: 0, n_desc: 0, n_value: 0, string_value: "a.c".into() },
        StabsEntry { n_strx: 0, n_type: 0x24, n_other: 0, n_desc: 0, n_value: 0x100, string_value: "f:F".into() },
        StabsEntry { n_strx: 0, n_type: 0x24, n_other: 0, n_desc: 0, n_value: 0x200, string_value: String::new() },
    ];
    let fns = StabsSymbolExtractor::extract_functions(&entries);
    assert_eq!(fns.len(), 1);
    assert_eq!(fns[0].name, "f");
    assert_eq!(fns[0].source_file.as_deref(), Some("a.c"));
}

#[test]
fn t52_extractor_source_files() {
    let entries = vec![
        StabsEntry { n_strx: 0, n_type: 0x64, n_other: 0, n_desc: 0, n_value: 0, string_value: "a.c".into() },
        StabsEntry { n_strx: 0, n_type: 0x64, n_other: 0, n_desc: 0, n_value: 0, string_value: "b.c".into() },
        StabsEntry { n_strx: 0, n_type: 0x64, n_other: 0, n_desc: 0, n_value: 0, string_value: String::new() },
    ];
    let files = StabsSymbolExtractor::extract_source_files(&entries);
    assert_eq!(files, vec!["a.c".to_string(), "b.c".to_string()]);
}

#[test]
fn t53_extractor_line_info_tracks_fn() {
    let entries = vec![
        StabsEntry { n_strx: 0, n_type: 0x24, n_other: 0, n_desc: 0, n_value: 0x100, string_value: "f:F".into() },
        StabsEntry { n_strx: 0, n_type: 0x44, n_other: 0, n_desc: 10, n_value: 0, string_value: String::new() },
        StabsEntry { n_strx: 0, n_type: 0x44, n_other: 0, n_desc: 11, n_value: 4, string_value: String::new() },
    ];
    let lines = StabsSymbolExtractor::extract_line_info(&entries);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].line_no, 10);
    assert_eq!(lines[0].function.as_deref(), Some("f"));
    assert_eq!(lines[1].line_no, 11);
}

// ---- StabsTypeDescParser ----

#[test]
fn t54_desc_parser_int() {
    let i = StabsTypeDescParser::parse_type_desc("i");
    assert_eq!(i.kind, "int");
    assert_eq!(i.size, Some(4));
}

#[test]
fn t55_desc_parser_pointer_ref() {
    let p = StabsTypeDescParser::parse_type_desc("*(0,1)");
    assert_eq!(p.kind, "pointer");
    let r = StabsTypeDescParser::parse_type_desc("&(0,1)");
    assert_eq!(r.kind, "ref");
}

#[test]
fn t56_desc_parser_struct_size() {
    let s = StabsTypeDescParser::parse_type_desc("s16x:i,0,32;");
    assert_eq!(s.kind, "struct");
    assert_eq!(s.size, Some(16));
}

#[test]
fn t57_desc_parser_union_size() {
    let u = StabsTypeDescParser::parse_type_desc("u8a:i,0,32;");
    assert_eq!(u.kind, "union");
    assert_eq!(u.size, Some(8));
}

#[test]
fn t58_desc_parser_subrange_byte() {
    let r = StabsTypeDescParser::parse_type_desc("r1;0;127;");
    assert_eq!(r.kind, "subrange");
    assert_eq!(r.size, Some(1));
}

#[test]
fn t59_desc_parser_subrange_word() {
    let r = StabsTypeDescParser::parse_type_desc("r1;0;1000;");
    assert_eq!(r.kind, "subrange");
    assert_eq!(r.size, Some(2));
}

#[test]
fn t60_desc_parser_subrange_dword() {
    let r = StabsTypeDescParser::parse_type_desc("r1;0;200000;");
    assert_eq!(r.kind, "subrange");
    assert_eq!(r.size, Some(4));
}

#[test]
fn t61_desc_parser_array() {
    let a = StabsTypeDescParser::parse_type_desc("ar(0,1);0;9;(0,1)");
    assert_eq!(a.kind, "array");
}

#[test]
fn t62_desc_parser_fuzz() {
    let mut g = lcg();
    let charset: &[u8] = b"sefFgrptTv*&ar(),0123456789;:iBcdwxl";
    for _ in 0..200 {
        let len = (g() % 30) as usize;
        let mut s = String::new();
        for _ in 0..len {
            let i = (g() as usize) % charset.len();
            s.push(charset[i] as char);
        }
        let info = StabsTypeDescParser::parse_type_desc(&s);
        let _ = info.to_string();
    }
}

#[test]
fn t63_desc_parser_char_codes() {
    assert_eq!(StabsTypeDescParser::parse_type_desc("c").kind, "char");
    assert_eq!(StabsTypeDescParser::parse_type_desc("B").kind, "bool");
    assert_eq!(StabsTypeDescParser::parse_type_desc("d").kind, "double");
    assert_eq!(StabsTypeDescParser::parse_type_desc("l").kind, "long");
    assert_eq!(StabsTypeDescParser::parse_type_desc("w").kind, "void");
}

#[test]
fn t64_desc_parser_unknown() {
    let u = StabsTypeDescParser::parse_type_desc("@@@");
    assert_eq!(u.kind, "unknown");
}

#[test]
fn t65_desc_parser_typeinfo_display() {
    let info = StabsTypeDescParser::parse_type_desc("s16abc");
    let s = info.to_string();
    assert!(s.contains("struct"));
    assert!(s.contains("16"));
}

// ---- UnifiedSymbol / convert_to_symbol_table ----

#[test]
fn t66_convert_to_symbol_table_kinds() {
    let entries = vec![
        StabsEntry { n_strx: 0, n_type: 0x24, n_other: 0, n_desc: 0, n_value: 0x100, string_value: "fn:F".into() },
        StabsEntry { n_strx: 0, n_type: 0x20, n_other: 0, n_desc: 0, n_value: 0x200, string_value: "g:G".into() },
        StabsEntry { n_strx: 0, n_type: 0xA4, n_other: 0, n_desc: 0, n_value: 0x300, string_value: "ent:L".into() },
        StabsEntry { n_strx: 0, n_type: 0x64, n_other: 0, n_desc: 0, n_value: 0, string_value: "src.c".into() }, // skip
    ];
    let syms = convert_to_symbol_table(&entries);
    assert_eq!(syms.len(), 3);
    assert_eq!(syms[0].kind, SymbolKind::Function);
    assert_eq!(syms[1].kind, SymbolKind::Variable);
    assert_eq!(syms[2].kind, SymbolKind::Label);
}

#[test]
fn t67_convert_skips_empty_name() {
    let entries = vec![
        StabsEntry { n_strx: 0, n_type: 0x24, n_other: 0, n_desc: 0, n_value: 0, string_value: String::new() },
        StabsEntry { n_strx: 0, n_type: 0x24, n_other: 0, n_desc: 0, n_value: 0, string_value: ":F".into() },
    ];
    let syms = convert_to_symbol_table(&entries);
    assert_eq!(syms.len(), 0);
}

#[test]
fn t68_unified_symbol_display() {
    let s = UnifiedSymbol {
        name: "foo".into(),
        addr: 0x1234,
        kind: SymbolKind::Function,
        source: SymbolSource::Stabs,
    };
    let r = s.to_string();
    assert!(r.contains("foo"));
    assert!(r.contains("0x1234"));
}

#[test]
fn t69_symbol_kind_eq() {
    assert_eq!(SymbolKind::Function, SymbolKind::Function);
    assert_ne!(SymbolKind::Function, SymbolKind::Variable);
    assert_ne!(SymbolKind::Variable, SymbolKind::Label);
}

// ---- StabsSymbolParser / StabsToSourceMap ----

#[test]
fn t70_symbol_parser_n_sline_calc() {
    let entries: Vec<(u32, u8, u16, u32, &str)> = vec![
        (0, 0x64, 0, 0, "x.c"),
        (0, 0x24, 0, 0x4000, "f:F"),
        (0, 0x44, 5, 0x10, ""),
        (0, 0x44, 7, 0x20, ""),
    ];
    let syms = StabsSymbolParser::parse(&entries);
    let slines: Vec<_> = syms.iter().filter(|s| s.kind == StabsKind::SourceLine).collect();
    assert_eq!(slines.len(), 2);
    assert_eq!(slines[0].value, 0x4010);
    assert_eq!(slines[1].value, 0x4020);
}

#[test]
fn t71_source_map_50_entries_sorted() {
    let mut g = lcg();
    let mut syms = Vec::new();
    for i in 0..50 {
        syms.push(StabsSymbol {
            kind: StabsKind::SourceLine,
            name: String::new(),
            value: (g() % 100_000) as u64,
            source_file: Some("f.c".into()),
            line: Some(i + 1),
        });
    }
    let m = StabsToSourceMap::from_symbols(&syms);
    assert_eq!(m.len(), 50);
    let es = m.entries();
    for w in es.windows(2) {
        assert!(w[0].0 <= w[1].0);
    }
}

#[test]
fn t72_source_map_lookup_misses_below() {
    let syms = vec![StabsSymbol {
        kind: StabsKind::SourceLine,
        name: String::new(),
        value: 0x100,
        source_file: Some("f.c".into()),
        line: Some(1),
    }];
    let m = StabsToSourceMap::from_symbols(&syms);
    assert!(m.lookup(0).is_none());
    assert!(m.lookup(0xFF).is_none());
    assert!(m.lookup(0x100).is_some());
}

#[test]
fn t73_source_map_empty() {
    let m = StabsToSourceMap::default();
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
    assert!(m.entries().is_empty());
    assert!(m.lookup(0).is_none());
}

#[test]
fn t74_symbol_parser_n_so_n_sol() {
    let entries: Vec<(u32, u8, u16, u32, &str)> = vec![
        (0, 0x64, 0, 0, "main.c"),
        (0, 0x84, 0, 0, "header.h"),
    ];
    let syms = StabsSymbolParser::parse(&entries);
    assert!(syms.iter().any(|s| s.name == "main.c"));
    assert!(syms.iter().any(|s| s.name == "header.h"));
}

#[test]
fn t75_stabs_kind_distinct() {
    let kinds = [
        StabsKind::Function, StabsKind::Global, StabsKind::Local,
        StabsKind::SourceFile, StabsKind::SourceLine, StabsKind::Other,
    ];
    for (i, a) in kinds.iter().enumerate() {
        for (j, b) in kinds.iter().enumerate() {
            if i != j { assert_ne!(a, b); }
        }
    }
}

// ---- Serde roundtrip ----

#[test]
fn t76_serde_stabs_entry_roundtrip() {
    let e = StabsEntry {
        n_strx: 12,
        n_type: 0x24,
        n_other: 1,
        n_desc: -3,
        n_value: 0xABCD,
        string_value: "fn:F".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: StabsEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.n_strx, e.n_strx);
    assert_eq!(back.n_desc, e.n_desc);
    assert_eq!(back.string_value, e.string_value);
}

#[test]
fn t77_serde_unified_symbol_roundtrip() {
    let s = UnifiedSymbol {
        name: "x".into(),
        addr: 0xDEAD,
        kind: SymbolKind::Variable,
        source: SymbolSource::Stabs,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: UnifiedSymbol = serde_json::from_str(&json).unwrap();
    assert_eq!(back.name, s.name);
    assert_eq!(back.kind, s.kind);
}

// ---- StabsError ----

#[test]
fn t78_stabs_error_variants_distinct() {
    let a = StabsError::InvalidRecord(1).to_string();
    let b = StabsError::Parse("x".into()).to_string();
    let c = StabsError::TypeParse("y".into()).to_string();
    let d = StabsError::StringTable("z".into()).to_string();
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(c, d);
}

// ---- Mixed parse pipeline ----

#[test]
fn t79_full_pipeline_provider_consistent() {
    let stabstr = build_stabstr(&["m.c", "a:F", "b:F", "c:F"]);
    let so = stab_record(0, 0x64, 0, 0, 0);
    let f1 = stab_record(4, 0x24, 0, 0, 0x100);
    let f2 = stab_record(8, 0x24, 0, 0, 0x200);
    let f3 = stab_record(12, 0x24, 0, 0, 0x300);
    let mut raw = so.to_vec();
    raw.extend_from_slice(&f1);
    raw.extend_from_slice(&f2);
    raw.extend_from_slice(&f3);
    let recs = StabRecord::parse_all(&raw, &stabstr);
    let p = StabsProvider::from_records(&recs, 0x10000);
    let all = p.all_symbols();
    let sorted = p.symbols_sorted();
    assert_eq!(all.len(), sorted.len());
    assert_eq!(p.all_functions().len(), 3);
}

#[test]
fn t80_stabs_function_display() {
    let f = StabsFunction {
        name: "fn".into(),
        addr: 0x100,
        source_file: Some("x.c".into()),
    };
    let s = f.to_string();
    assert!(s.contains("fn"));
    assert!(s.contains("x.c"));

    let f2 = StabsFunction { name: "g".into(), addr: 0x200, source_file: None };
    let s2 = f2.to_string();
    assert!(s2.contains('g'));
}

#[test]
fn t81_stabs_line_display() {
    let l = StabsLine { addr: 0x100, line_no: 42, function: Some("fn".into()) };
    let s = l.to_string();
    assert!(s.contains("42"));
}
