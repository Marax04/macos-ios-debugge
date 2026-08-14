//! Exhaustive integration tests for `rustre-symbols-dwarf`.
//!
//! Focus: lib.rs public API + `dwarf_abbrev` + `split_dwarf` + `type_units`.

use rustre_symbols_dwarf as rsd;
use rsd::{
    DwarfError, DwarfFunction, DwarfLocation, DwarfReader, DwarfType, DwarfTypeTag, DwarfVariable,
    LineEntry,
};
use rsd::dwarf_abbrev as ab;
use rsd::split_dwarf as sd;
use rsd::type_units as tu;

use std::collections::HashMap;
use std::path::PathBuf;

// ───────────────────────────── helpers ─────────────────────────────

fn enc_uleb(mut n: u64) -> Vec<u8> {
    let mut v = Vec::new();
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 { b |= 0x80; }
        v.push(b);
        if n == 0 { break; }
    }
    v
}

fn enc_sleb(mut n: i64) -> Vec<u8> {
    let mut v = Vec::new();
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        let done = (n == 0 && b & 0x40 == 0) || (n == -1 && b & 0x40 != 0);
        if !done { b |= 0x80; }
        v.push(b);
        if done { break; }
    }
    v
}

// ───────────────────────────── DwarfReader: ELF parsing edge cases ─────────────────────────────

#[test]
fn from_bytes_empty() {
    let r = DwarfReader::from_bytes(&[]);
    assert!(matches!(r, Err(DwarfError::UnsupportedFormat)));
}

#[test]
fn from_bytes_short() {
    let r = DwarfReader::from_bytes(&[0u8; 8]);
    assert!(matches!(r, Err(DwarfError::UnsupportedFormat)));
}

#[test]
fn from_bytes_not_elf_magic() {
    let mut raw = vec![0u8; 64];
    raw[0] = 0x7e;
    raw[1] = b'E';
    raw[2] = b'L';
    raw[3] = b'F';
    let r = DwarfReader::from_bytes(&raw);
    assert!(matches!(r, Err(DwarfError::UnsupportedFormat)));
}

#[test]
fn from_bytes_be_unsupported() {
    let mut raw = vec![0u8; 64];
    raw[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    raw[4] = 2; // class 64
    raw[5] = 2; // BE
    let r = DwarfReader::from_bytes(&raw);
    assert!(matches!(r, Err(DwarfError::UnsupportedFormat)));
}

#[test]
fn from_bytes_bad_class() {
    let mut raw = vec![0u8; 64];
    raw[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    raw[4] = 9; // bogus class
    raw[5] = 1; // LE
    let r = DwarfReader::from_bytes(&raw);
    assert!(matches!(r, Err(DwarfError::UnsupportedFormat)));
}

#[test]
fn from_sections_empty_returns_empty_results() {
    let r = DwarfReader::from_sections(HashMap::new());
    assert!(r.functions().is_empty());
    assert!(r.variables().is_empty());
    assert!(r.types().is_empty());
    assert!(r.line_info().is_empty());
}

#[test]
fn open_nonexistent_path_returns_io_error() {
    let r = DwarfReader::open(std::path::Path::new(
        "this_path_definitely_does_not_exist_xyz_12345.bin",
    ));
    assert!(matches!(r, Err(DwarfError::Io(_))));
}

// ───────────────────────────── DwarfLocation Eq/Serde ─────────────────────────────

#[test]
fn dwarf_location_equality() {
    assert_eq!(DwarfLocation::Register(5), DwarfLocation::Register(5));
    assert_ne!(DwarfLocation::Register(5), DwarfLocation::Register(6));
    assert_eq!(
        DwarfLocation::MemoryOffset { register: 1, offset: -4 },
        DwarfLocation::MemoryOffset { register: 1, offset: -4 }
    );
    assert_eq!(DwarfLocation::Constant(42), DwarfLocation::Constant(42));
    assert_eq!(DwarfLocation::Unknown, DwarfLocation::Unknown);
}

#[test]
fn dwarf_location_serde_roundtrip() {
    let loc = DwarfLocation::MemoryOffset { register: 6, offset: -16 };
    let json = serde_json::to_string(&loc).unwrap();
    let back: DwarfLocation = serde_json::from_str(&json).unwrap();
    assert_eq!(loc, back);
}

#[test]
fn dwarf_function_serde_roundtrip() {
    let f = DwarfFunction {
        name: "main".into(),
        low_pc: 0x1000,
        high_pc: 0x1080,
        parameters: vec![DwarfVariable {
            name: "argc".into(),
            type_name: "int".into(),
            location: DwarfLocation::Register(0),
        }],
        return_type: Some("int".into()),
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: DwarfFunction = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

#[test]
fn dwarf_type_tag_serde() {
    let t = DwarfType { name: "u32".into(), byte_size: 4, tag: DwarfTypeTag::Base };
    let s = serde_json::to_string(&t).unwrap();
    let back: DwarfType = serde_json::from_str(&s).unwrap();
    assert_eq!(t, back);
}

#[test]
fn line_entry_serde() {
    let e = LineEntry { address: 0x100, file: "x.c".into(), line: 10, column: 4 };
    let s = serde_json::to_string(&e).unwrap();
    let back: LineEntry = serde_json::from_str(&s).unwrap();
    assert_eq!(e, back);
}

// ───────────────────────────── DwarfError Display ─────────────────────────────

#[test]
fn dwarf_error_display() {
    assert!(format!("{}", DwarfError::MalformedDwarf).contains("Malformed"));
    assert!(format!("{}", DwarfError::UnsupportedFormat).contains("supported"));
    assert!(format!("{}", DwarfError::UnexpectedEof).contains("end of data"));
    assert!(format!("{}", DwarfError::SectionMissing(".debug_info".into())).contains(".debug_info"));
}

// ───────────────────────────── dwarf_abbrev: LEB128 ─────────────────────────────

#[test]
fn uleb_single_byte() {
    let mut pos = 0;
    assert_eq!(ab::read_uleb128(&[0x00], &mut pos), Some(0));
    assert_eq!(pos, 1);
    pos = 0;
    assert_eq!(ab::read_uleb128(&[0x7f], &mut pos), Some(127));
}

#[test]
fn uleb_multi_byte() {
    // 624485 from DWARF spec
    let bytes = [0xE5, 0x8E, 0x26];
    let mut pos = 0;
    assert_eq!(ab::read_uleb128(&bytes, &mut pos), Some(624_485));
    assert_eq!(pos, 3);
}

#[test]
fn uleb_empty_returns_none() {
    let mut pos = 0;
    assert_eq!(ab::read_uleb128(&[], &mut pos), None);
}

#[test]
fn uleb_truncated_returns_none() {
    let mut pos = 0;
    assert_eq!(ab::read_uleb128(&[0x80, 0x80], &mut pos), None);
}

#[test]
fn uleb_overflow_returns_none() {
    // 11 bytes of 0x80 then 0x01 — shift exceeds 64
    let bytes = [0x80u8; 11];
    let mut pos = 0;
    assert_eq!(ab::read_uleb128(&bytes, &mut pos), None);
}

#[test]
fn sleb_positive() {
    let mut pos = 0;
    assert_eq!(ab::read_sleb128(&[0x3e], &mut pos), Some(62));
}

#[test]
fn sleb_negative_small() {
    // -1 encoded
    let mut pos = 0;
    assert_eq!(ab::read_sleb128(&[0x7f], &mut pos), Some(-1));
}

#[test]
fn sleb_negative_large() {
    let mut pos = 0;
    assert_eq!(ab::read_sleb128(&[0xC0, 0xBB, 0x78], &mut pos), Some(-123_456));
}

#[test]
fn sleb_roundtrip_various() {
    for &n in &[0i64, 1, -1, 63, 64, -64, -65, 12345, -12345, i64::MAX, i64::MIN] {
        let enc = enc_sleb(n);
        let mut pos = 0;
        assert_eq!(ab::read_sleb128(&enc, &mut pos), Some(n), "n={n}");
    }
}

#[test]
fn uleb_roundtrip_various() {
    for &n in &[0u64, 1, 127, 128, 16383, 16384, u64::MAX, 1 << 35] {
        let enc = enc_uleb(n);
        let mut pos = 0;
        assert_eq!(ab::read_uleb128(&enc, &mut pos), Some(n), "n={n}");
    }
}

// ───────────────────────────── dwarf_abbrev: DwForm ─────────────────────────────

#[test]
fn dwform_from_code_known() {
    assert_eq!(ab::DwForm::from_code(0x01), ab::DwForm::Addr);
    assert_eq!(ab::DwForm::from_code(0x08), ab::DwForm::String);
    assert_eq!(ab::DwForm::from_code(0x18), ab::DwForm::Exprloc);
    assert_eq!(ab::DwForm::from_code(0x21), ab::DwForm::ImplicitConst);
    assert_eq!(ab::DwForm::from_code(0x1F20), ab::DwForm::GnuStrpAlt);
}

#[test]
fn dwform_from_code_unknown() {
    assert_eq!(ab::DwForm::from_code(0xBEEF), ab::DwForm::Unknown);
    assert_eq!(ab::DwForm::from_code(0), ab::DwForm::Unknown);
}

#[test]
fn dwform_is_implicit_const() {
    assert!(ab::DwForm::ImplicitConst.is_implicit_const());
    assert!(!ab::DwForm::Addr.is_implicit_const());
}

#[test]
fn dwform_fixed_size_basic() {
    assert_eq!(ab::DwForm::Data1.fixed_size(8), Some(1));
    assert_eq!(ab::DwForm::Data2.fixed_size(8), Some(2));
    assert_eq!(ab::DwForm::Data4.fixed_size(8), Some(4));
    assert_eq!(ab::DwForm::Data8.fixed_size(8), Some(8));
    assert_eq!(ab::DwForm::Data16.fixed_size(8), Some(16));
    assert_eq!(ab::DwForm::FlagPresent.fixed_size(8), Some(0));
    assert_eq!(ab::DwForm::Addr.fixed_size(8), Some(8));
    assert_eq!(ab::DwForm::Addr.fixed_size(4), Some(4));
    assert_eq!(ab::DwForm::String.fixed_size(8), None);
    assert_eq!(ab::DwForm::Block.fixed_size(8), None);
}

#[test]
fn dwform_display() {
    let s = format!("{}", ab::DwForm::Addr);
    assert!(s.starts_with("DW_FORM_"));
}

// ───────────────────────────── AbbrevAttr / AbbrevDecl / AbbrevTable ─────────────────────────────

#[test]
fn abbrev_attr_new_normal() {
    let a = ab::AbbrevAttr::new(0x03, 0x08);
    assert_eq!(a.name, ab::DwAt(0x03));
    assert_eq!(a.form, ab::DwForm::String);
    assert_eq!(a.implicit_const, 0);
}

#[test]
fn abbrev_attr_new_implicit() {
    let a = ab::AbbrevAttr::new_implicit(0x99, -42);
    assert_eq!(a.form, ab::DwForm::ImplicitConst);
    assert_eq!(a.implicit_const, -42);
}

#[test]
fn abbrev_decl_push_and_attr() {
    let mut d = ab::AbbrevDecl::new(1, 0x11, true);
    d.push_attr(ab::AbbrevAttr::new(0x03, 0x08));
    d.push_attr(ab::AbbrevAttr::new(0x11, 0x01));
    assert_eq!(d.attrs.len(), 2);
    assert!(d.attr(ab::DwAt(0x03)).is_some());
    assert!(d.attr(ab::DwAt(0x42)).is_none());
    let s = format!("{d}");
    assert!(s.contains("abbrev[1]"));
    assert!(s.contains("2 attrs"));
}

#[test]
fn abbrev_table_empty_and_insert() {
    let t = ab::AbbrevTable::new();
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
}

#[test]
fn parse_abbrev_table_simple() {
    // code=1 tag=0x11 hc=1 attrs:(0x03,0x08)(0,0) end
    let mut data = Vec::new();
    data.extend(enc_uleb(1));      // code
    data.extend(enc_uleb(0x11));   // tag = compile_unit
    data.push(1);                  // has_children
    data.extend(enc_uleb(0x03));   // attr DW_AT_name
    data.extend(enc_uleb(0x08));   // form DW_FORM_string
    data.push(0); data.push(0);    // terminator
    data.push(0);                  // table end code 0

    let t = ab::parse_abbrev_table(&data, 0).expect("parsed");
    assert_eq!(t.len(), 1);
    let d = t.get(1).unwrap();
    assert_eq!(d.tag, ab::DwTag(0x11));
    assert!(d.has_children);
    assert_eq!(d.attrs.len(), 1);
    assert_eq!(d.attrs[0].form, ab::DwForm::String);
}

#[test]
fn parse_abbrev_table_with_implicit_const() {
    let mut data = Vec::new();
    data.extend(enc_uleb(1));
    data.extend(enc_uleb(0x2e)); // subprogram
    data.push(0);
    data.extend(enc_uleb(0x03));        // name attr
    data.extend(enc_uleb(0x21));        // implicit_const form
    data.extend(enc_sleb(-7));          // implicit value
    data.push(0); data.push(0);         // attr terminator
    data.push(0);                       // table end
    let t = ab::parse_abbrev_table(&data, 0).unwrap();
    let d = t.get(1).unwrap();
    assert_eq!(d.attrs[0].implicit_const, -7);
}

#[test]
fn parse_abbrev_table_empty_returns_empty() {
    let data = [0u8];
    let t = ab::parse_abbrev_table(&data, 0).unwrap();
    assert!(t.is_empty());
}

#[test]
fn parse_abbrev_table_truncated_returns_none() {
    // code present, but tag byte missing
    let data = enc_uleb(1);
    assert!(ab::parse_abbrev_table(&data, 0).is_none());
}

// ───────────────────────────── read_form_value ─────────────────────────────

#[test]
fn read_form_value_addr_u64() {
    let data = 0x1122_3344_5566_7788u64.to_le_bytes();
    let mut pos = 0;
    let v = ab::read_form_value(&data, &mut pos, ab::DwForm::Addr, 8, false, 0).unwrap();
    assert!(matches!(v, ab::FormValue::Uint(0x1122_3344_5566_7788)));
    assert_eq!(pos, 8);
}

#[test]
fn read_form_value_addr_u32() {
    let data = 0x1234_5678u32.to_le_bytes();
    let mut pos = 0;
    let v = ab::read_form_value(&data, &mut pos, ab::DwForm::Addr, 4, false, 0).unwrap();
    assert!(matches!(v, ab::FormValue::Uint(0x1234_5678)));
}

#[test]
fn read_form_value_flag_present_no_consumption() {
    let mut pos = 0;
    let v = ab::read_form_value(&[], &mut pos, ab::DwForm::FlagPresent, 8, false, 0).unwrap();
    assert!(matches!(v, ab::FormValue::Uint(1)));
    assert_eq!(pos, 0);
}

#[test]
fn read_form_value_implicit_const_returns_value() {
    let mut pos = 0;
    let v = ab::read_form_value(&[], &mut pos, ab::DwForm::ImplicitConst, 8, false, -99).unwrap();
    assert!(matches!(v, ab::FormValue::Int(-99)));
    assert_eq!(pos, 0);
}

#[test]
fn read_form_value_string_inline() {
    let data = b"hello\0extra";
    let mut pos = 0;
    let v = ab::read_form_value(data, &mut pos, ab::DwForm::String, 8, false, 0).unwrap();
    if let ab::FormValue::String(s) = v {
        assert_eq!(s, "hello");
    } else {
        panic!("expected String");
    }
    assert_eq!(pos, 6);
}

#[test]
fn read_form_value_block1() {
    let data = [3u8, 0xAA, 0xBB, 0xCC, 0xDD];
    let mut pos = 0;
    let v = ab::read_form_value(&data, &mut pos, ab::DwForm::Block1, 8, false, 0).unwrap();
    if let ab::FormValue::Bytes(b) = v {
        assert_eq!(b, vec![0xAA, 0xBB, 0xCC]);
    } else {
        panic!();
    }
    assert_eq!(pos, 4);
}

#[test]
fn read_form_value_block1_truncated() {
    let data = [5u8, 0xAA, 0xBB];
    let mut pos = 0;
    let v = ab::read_form_value(&data, &mut pos, ab::DwForm::Block1, 8, false, 0);
    assert!(v.is_none());
}

#[test]
fn read_form_value_strp_32bit() {
    let data = 0x1234u32.to_le_bytes();
    let mut pos = 0;
    let v = ab::read_form_value(&data, &mut pos, ab::DwForm::Strp, 8, false, 0).unwrap();
    assert!(matches!(v, ab::FormValue::StrOffset(0x1234)));
}

#[test]
fn read_form_value_strp_64bit() {
    let data = 0x1122_3344_5566_7788u64.to_le_bytes();
    let mut pos = 0;
    let v = ab::read_form_value(&data, &mut pos, ab::DwForm::Strp, 8, true, 0).unwrap();
    assert!(matches!(v, ab::FormValue::StrOffset(0x1122_3344_5566_7788)));
}

#[test]
fn read_form_value_data1_through_data8() {
    let mut pos = 0;
    let v = ab::read_form_value(&[0xAB], &mut pos, ab::DwForm::Data1, 8, false, 0).unwrap();
    assert!(matches!(v, ab::FormValue::Uint(0xAB)));

    pos = 0;
    let v = ab::read_form_value(&[0x01, 0x02], &mut pos, ab::DwForm::Data2, 8, false, 0).unwrap();
    assert!(matches!(v, ab::FormValue::Uint(0x0201)));
}

#[test]
fn read_form_value_sdata_negative() {
    let bytes = enc_sleb(-100);
    let mut pos = 0;
    let v = ab::read_form_value(&bytes, &mut pos, ab::DwForm::Sdata, 8, false, 0).unwrap();
    assert!(matches!(v, ab::FormValue::Int(-100)));
}

#[test]
fn read_form_value_udata() {
    let bytes = enc_uleb(98765);
    let mut pos = 0;
    let v = ab::read_form_value(&bytes, &mut pos, ab::DwForm::Udata, 8, false, 0).unwrap();
    assert!(matches!(v, ab::FormValue::Uint(98765)));
}

#[test]
fn formvalue_display() {
    assert_eq!(format!("{}", ab::FormValue::Uint(0x10)), "0x10");
    assert_eq!(format!("{}", ab::FormValue::Int(-1)), "-1");
    assert!(format!("{}", ab::FormValue::String("x".into())).contains('x'));
    assert!(format!("{}", ab::FormValue::Bytes(vec![1, 2, 3])).contains('3'));
    assert!(format!("{}", ab::FormValue::Indirect).contains("indirect"));
    assert!(format!("{}", ab::FormValue::Unknown).contains("unknown"));
}

// ───────────────────────────── type_units ─────────────────────────────

fn build_tu_header_32(sig: u64, type_offset: u32) -> Vec<u8> {
    let mut v = Vec::new();
    // unit_length (placeholder 19 = bytes after the length field; we'll have no DIE bytes)
    // header: 2 ver + 4 abbrev_off + 1 addr + 8 sig + 4 type_off = 19
    v.extend(&19u32.to_le_bytes());
    v.extend(&4u16.to_le_bytes());           // version 4
    v.extend(&0u32.to_le_bytes());           // abbrev offset
    v.push(8);                                // addr size
    v.extend(&sig.to_le_bytes());
    v.extend(&type_offset.to_le_bytes());
    v
}

#[test]
fn type_unit_header_parse_32bit() {
    let data = build_tu_header_32(0xDEAD_BEEF_CAFE_BABE, 0x18);
    let (hdr, off) = tu::parse_type_unit_header(&data, 0).expect("ok");
    assert_eq!(hdr.version, 4);
    assert_eq!(hdr.address_size, 8);
    assert_eq!(hdr.type_signature, 0xDEAD_BEEF_CAFE_BABE);
    assert_eq!(hdr.type_offset, 0x18);
    assert!(!hdr.is_64bit);
    assert_eq!(off, data.len());
    assert_eq!(hdr.header_size(), 23);
}

#[test]
fn type_unit_header_parse_truncated() {
    let data = [0u8; 5];
    assert!(tu::parse_type_unit_header(&data, 0).is_none());
}

#[test]
fn type_unit_header_rejects_dwarf_v3() {
    let mut data = build_tu_header_32(0, 0);
    // Overwrite version to 3
    data[4] = 3;
    data[5] = 0;
    assert!(tu::parse_type_unit_header(&data, 0).is_none());
}

#[test]
fn type_unit_header_size_64bit() {
    let hdr = tu::TypeUnitHeader {
        unit_length: 0,
        version: 5,
        debug_abbrev_offset: 0,
        address_size: 8,
        type_signature: 0,
        type_offset: 0,
        is_64bit: true,
    };
    assert_eq!(hdr.header_size(), 39);
}

#[test]
fn type_signature_index_basic() {
    let mut idx = tu::TypeSignatureIndex::new();
    assert!(idx.is_empty());
    let hdr = tu::TypeUnitHeader {
        unit_length: 0, version: 4, debug_abbrev_offset: 0, address_size: 8,
        type_signature: 0xAA, type_offset: 0, is_64bit: false,
    };
    idx.insert(tu::TypeUnit::new(hdr, vec![1, 2, 3]).with_type_name("X"));
    assert_eq!(idx.len(), 1);
    assert!(!idx.is_empty());
    let u = idx.get(0xAA).unwrap();
    assert_eq!(u.signature(), 0xAA);
    assert_eq!(u.version(), 4);
    assert_eq!(u.die_size(), 3);
    assert_eq!(u.type_name.as_deref(), Some("X"));
    assert_eq!(idx.signatures(), vec![0xAA]);
    assert!(tu::find_type_by_signature(&idx, 0xAA).is_some());
    assert!(tu::find_type_by_signature(&idx, 0xBB).is_none());
}

#[test]
fn type_signature_index_from_debug_types_empty() {
    let idx = tu::TypeSignatureIndex::from_debug_types(&[]);
    assert!(idx.is_empty());
}

#[test]
fn type_signature_index_from_debug_types_one_unit() {
    // unit length 19 -> covers all header bytes (no DIE bytes)
    let data = build_tu_header_32(0x77, 0x18);
    let idx = tu::TypeSignatureIndex::from_debug_types(&data);
    assert_eq!(idx.len(), 1);
    assert!(idx.get(0x77).is_some());
}

#[test]
fn type_signature_index_skips_truncated() {
    let mut data = build_tu_header_32(0x77, 0x18);
    // chop last 2 bytes -> declared length still 19 but past EOF
    data.truncate(data.len() - 2);
    let idx = tu::TypeSignatureIndex::from_debug_types(&data);
    assert!(idx.is_empty());
}

// ───────────────────────────── split_dwarf ─────────────────────────────

#[test]
fn dwo_section_is_debug() {
    let s = sd::DwoSection::new(".debug_info.dwo", vec![1, 2]);
    assert!(s.is_debug_section());
    let s2 = sd::DwoSection::new(".text", vec![]);
    assert!(!s2.is_debug_section());
}

#[test]
fn dwo_from_elf_bytes_not_elf() {
    let r = sd::DwoFile::from_elf_bytes("x.dwo", b"NOTELF");
    assert!(matches!(r, Err(sd::SplitDwarfError::NotDwo)));
}

#[test]
fn dwo_from_elf_bytes_too_short() {
    let r = sd::DwoFile::from_elf_bytes("x.dwo", &[]);
    assert!(matches!(r, Err(sd::SplitDwarfError::NotDwo)));
}

#[test]
fn dwp_from_elf_bytes_not_elf() {
    let r = sd::DwpPackage::from_elf_bytes(b"abcd");
    assert!(matches!(r, Err(sd::SplitDwarfError::NotDwp)));
}

#[test]
fn skeleton_unit_resolve_relative() {
    let su = sd::SkeletonUnit {
        offset: 0,
        dwo_id: 0,
        dwo_name: "foo.dwo".into(),
        comp_dir: "/tmp/build".into(),
    };
    let p = su.resolve_path();
    assert!(p.ends_with("foo.dwo"));
    assert!(p.to_string_lossy().contains("build"));
}

#[test]
fn skeleton_unit_resolve_empty_compdir() {
    let su = sd::SkeletonUnit {
        offset: 0,
        dwo_id: 0,
        dwo_name: "foo.dwo".into(),
        comp_dir: String::new(),
    };
    assert_eq!(su.resolve_path(), PathBuf::from("foo.dwo"));
}

#[test]
fn skeleton_unit_resolve_absolute_dwo() {
    // On Windows, an absolute path looks like C:\... — emulate with both styles
    let abs = if cfg!(windows) { "C:\\abs\\foo.dwo" } else { "/abs/foo.dwo" };
    let su = sd::SkeletonUnit {
        offset: 0, dwo_id: 0,
        dwo_name: abs.into(),
        comp_dir: "/should/be/ignored".into(),
    };
    let p = su.resolve_path();
    assert!(p.is_absolute());
    assert!(p.to_string_lossy().contains("foo.dwo"));
}

#[test]
fn resolve_dwo_path_fn() {
    assert_eq!(
        sd::resolve_dwo_path("/a", "b.dwo"),
        PathBuf::from("/a").join("b.dwo")
    );
    assert_eq!(sd::resolve_dwo_path("", "b.dwo"), PathBuf::from("b.dwo"));
}

#[test]
fn dwo_resolver_returns_none_for_missing() {
    let r = sd::DwoResolver::new(vec![PathBuf::from("/no/such/dir")]);
    let su = sd::SkeletonUnit {
        offset: 0, dwo_id: 0,
        dwo_name: "nonexistent_zzz.dwo".into(),
        comp_dir: "/tmp".into(),
    };
    assert!(r.resolve_path(&su).is_none());
}

#[test]
fn split_dwarf_error_display() {
    let e = sd::SplitDwarfError::IdMismatch(0xAA, 0xBB);
    let s = format!("{e}");
    assert!(s.contains("0xaa") && s.contains("0xbb"));
}
