//! Deep adversarial tests for `rustre-symbols-dwarf` (blitz2).
//!
//! Focus: LEB128 fuzz, DwForm/DwTag/DwAt invariants, `AbbrevTable` round-trips,
//! TypeUnitHeader/TypeSignatureIndex, `LineRowFlags` bit-field, `LineMatrix` lookup,
//! `LocationExpr`, RegisterFile/SimpleMemory, `DwoFile` / `DwpPackage` / `DwoResolver`,
//! `DwarfReader` edge cases, threaded stress on Send+Sync types.

use rustre_symbols_dwarf as rsd;
use rsd::dwarf_abbrev as ab;
use rsd::line_program as lp;
use rsd::location_expr as le;
use rsd::split_dwarf as sd;
use rsd::type_units as tu;
use rsd::{
    DwarfError, DwarfFunction, DwarfLocation, DwarfReader, DwarfType, DwarfTypeTag,
    DwarfVariable, LineEntry,
};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

// ── Seeded LCG ────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    const fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self.0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            let w = self.next();
            for b in w.to_le_bytes() {
                v.push(b);
                if v.len() == n {
                    break;
                }
            }
        }
        v
    }
}

// ── LEB128 encoders ───────────────────────────────────────────────────────────

fn enc_uleb(mut n: u64) -> Vec<u8> {
    let mut v = Vec::new();
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        v.push(b);
        if n == 0 {
            break;
        }
    }
    v
}
fn enc_sleb(mut n: i64) -> Vec<u8> {
    let mut v = Vec::new();
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        let done = (n == 0 && b & 0x40 == 0) || (n == -1 && b & 0x40 != 0);
        if !done {
            b |= 0x80;
        }
        v.push(b);
        if done {
            break;
        }
    }
    v
}

// ── 1. LEB128 deterministic round-trip ────────────────────────────────────────

#[test]
fn uleb_roundtrip_50_deterministic() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = lcg.next();
        let enc = enc_uleb(n);
        let mut pos = 0;
        let dec = ab::read_uleb128(&enc, &mut pos).expect("decode");
        assert_eq!(dec, n);
        assert_eq!(pos, enc.len());
    }
}

#[test]
fn sleb_roundtrip_50_deterministic() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = lcg.next().cast_signed();
        let enc = enc_sleb(n);
        let mut pos = 0;
        let dec = ab::read_sleb128(&enc, &mut pos).expect("decode");
        assert_eq!(dec, n, "for n={n}");
        assert_eq!(pos, enc.len());
    }
}

#[test]
fn uleb_boundaries() {
    for &n in &[0u64, 1, 127, 128, 16383, 16384, u64::from(u32::MAX), u64::MAX] {
        let enc = enc_uleb(n);
        let mut pos = 0;
        assert_eq!(ab::read_uleb128(&enc, &mut pos), Some(n));
    }
}

#[test]
fn sleb_boundaries() {
    for &n in &[0i64, 1, -1, 63, -64, 64, -65, i64::from(i32::MAX), i64::from(i32::MIN), i64::MAX, i64::MIN] {
        let enc = enc_sleb(n);
        let mut pos = 0;
        assert_eq!(ab::read_sleb128(&enc, &mut pos), Some(n), "n={n}");
    }
}

// ── 2. LEB128 truncation / overflow fuzz ──────────────────────────────────────

#[test]
fn uleb_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..200 {
        let len = (lcg.next() % 16) as usize;
        let buf = lcg.bytes(len);
        let mut pos = 0;
        let _ = ab::read_uleb128(&buf, &mut pos); // must not panic
    }
}

#[test]
fn sleb_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..200 {
        let len = (lcg.next() % 16) as usize;
        let buf = lcg.bytes(len);
        let mut pos = 0;
        let _ = ab::read_sleb128(&buf, &mut pos);
    }
}

#[test]
fn uleb_truncated_continuation() {
    // continuation bit set but no more bytes
    let mut pos = 0;
    assert_eq!(ab::read_uleb128(&[0x80u8], &mut pos), None);
}

#[test]
fn uleb_overflow_too_many_bytes() {
    let bytes = [0xFFu8; 12];
    let mut pos = 0;
    assert_eq!(ab::read_uleb128(&bytes, &mut pos), None);
}

#[test]
fn uleb_zero_empty_slice() {
    let mut pos = 0;
    assert_eq!(ab::read_uleb128(&[], &mut pos), None);
    assert_eq!(pos, 0);
}

// ── 3. DwForm exhaustive code map ─────────────────────────────────────────────

#[test]
fn dw_form_known_codes_roundtrip() {
    for &(code, expect_known) in &[
        (0x01u64, true),  // Addr
        (0x08, true),     // String
        (0x21, true),     // ImplicitConst
        (0x1F20, true),   // GnuStrpAlt
        (0x9999, false),
        (0xFFFF, true),   // Unknown sentinel matches its own discriminant
    ] {
        let f = ab::DwForm::from_code(code);
        if expect_known {
            // Known codes (except deliberate Unknown=0xFFFF) should not be Unknown.
            if code != 0xFFFF {
                assert_ne!(f, ab::DwForm::Unknown, "code {code:#x}");
            }
        } else {
            assert_eq!(f, ab::DwForm::Unknown);
        }
    }
}

#[test]
fn dw_form_fixed_size_invariants() {
    for addr_size in [4u8, 8u8] {
        assert_eq!(ab::DwForm::Addr.fixed_size(addr_size), Some(addr_size as usize));
        assert_eq!(ab::DwForm::Data1.fixed_size(addr_size), Some(1));
        assert_eq!(ab::DwForm::Data2.fixed_size(addr_size), Some(2));
        assert_eq!(ab::DwForm::Data4.fixed_size(addr_size), Some(4));
        assert_eq!(ab::DwForm::Data8.fixed_size(addr_size), Some(8));
        assert_eq!(ab::DwForm::Data16.fixed_size(addr_size), Some(16));
        assert_eq!(ab::DwForm::FlagPresent.fixed_size(addr_size), Some(0));
        // Variable-length forms have no fixed size.
        assert_eq!(ab::DwForm::Udata.fixed_size(addr_size), None);
        assert_eq!(ab::DwForm::String.fixed_size(addr_size), None);
        assert_eq!(ab::DwForm::Block.fixed_size(addr_size), None);
    }
}

#[test]
fn dw_form_implicit_const_flag() {
    assert!(ab::DwForm::ImplicitConst.is_implicit_const());
    assert!(!ab::DwForm::Data4.is_implicit_const());
    assert!(!ab::DwForm::String.is_implicit_const());
}

#[test]
fn dw_form_display_contains_name() {
    let s = format!("{}", ab::DwForm::Addr);
    assert!(s.starts_with("DW_FORM_"));
    assert!(s.contains("Addr"));
}

#[test]
fn dw_form_hash_eq_consistency() {
    use std::collections::HashSet;
    let mut set: HashSet<ab::DwForm> = HashSet::new();
    set.insert(ab::DwForm::Addr);
    set.insert(ab::DwForm::Addr); // dup
    set.insert(ab::DwForm::Data4);
    assert_eq!(set.len(), 2);
}

// ── 4. DwTag/DwAt invariants ──────────────────────────────────────────────────

#[test]
fn dw_tag_constants_distinct() {
    use std::collections::HashSet;
    let tags = [
        ab::DwTag::COMPILE_UNIT,
        ab::DwTag::SUBPROGRAM,
        ab::DwTag::VARIABLE,
        ab::DwTag::FORMAL_PARAM,
        ab::DwTag::BASE_TYPE,
        ab::DwTag::POINTER_TYPE,
        ab::DwTag::TYPEDEF,
        ab::DwTag::STRUCTURE_TYPE,
        ab::DwTag::UNION_TYPE,
        ab::DwTag::ARRAY_TYPE,
        ab::DwTag::MEMBER,
        ab::DwTag::LEXICAL_BLOCK,
        ab::DwTag::INLINED_SUBP,
    ];
    let unique: HashSet<_> = tags.iter().collect();
    assert_eq!(unique.len(), tags.len());
}

#[test]
fn dw_at_constants_distinct_and_displayable() {
    assert_eq!(ab::DwAt::NAME, ab::DwAt(0x03));
    assert_ne!(ab::DwAt::NAME, ab::DwAt::TYPE);
    let s = format!("{}", ab::DwAt::NAME);
    assert!(s.contains("0x3") || s.contains("0x03"));
}

// ── 5. AbbrevAttr / AbbrevDecl ────────────────────────────────────────────────

#[test]
fn abbrev_attr_implicit_keeps_value() {
    for &v in &[-1000i64, -1, 0, 1, 1_000_000] {
        let a = ab::AbbrevAttr::new_implicit(0x0B, v);
        assert_eq!(a.form, ab::DwForm::ImplicitConst);
        assert_eq!(a.implicit_const, v);
    }
}

#[test]
fn abbrev_decl_lookup_consistency() {
    let mut d = ab::AbbrevDecl::new(7, 0x2E, true);
    d.push_attr(ab::AbbrevAttr::new(0x03, 0x08));
    d.push_attr(ab::AbbrevAttr::new(0x11, 0x01));
    d.push_attr(ab::AbbrevAttr::new(0x12, 0x07));
    assert!(d.attr(ab::DwAt(0x03)).is_some());
    assert!(d.attr(ab::DwAt(0x11)).is_some());
    assert!(d.attr(ab::DwAt(0xAA)).is_none());
    assert_eq!(d.attrs.len(), 3);
    assert!(format!("{d}").contains("3 attrs"));
}

// ── 6. parse_abbrev_table state machine ───────────────────────────────────────

#[test]
fn parse_abbrev_table_minimal() {
    let data = [
        0x01, 0x11, 0x01,
        0x03, 0x08,
        0x00, 0x00,
        0x00,
    ];
    let t = ab::parse_abbrev_table(&data, 0).expect("table");
    assert_eq!(t.len(), 1);
    let d = t.get(1).unwrap();
    assert_eq!(d.tag, ab::DwTag::COMPILE_UNIT);
    assert!(d.has_children);
}

#[test]
fn parse_abbrev_table_truncated_returns_none() {
    // Start of an entry but no terminator
    let data = [0x01u8, 0x11, 0x01, 0x03, 0x08, 0x00 /* missing second 0 */];
    assert!(ab::parse_abbrev_table(&data, 0).is_none());
}

#[test]
fn parse_abbrev_table_implicit_const_decoded() {
    // code=1 tag=0x11 has_children=0 attr=(name=0x0B, form=ImplicitConst=0x21, value=-42), term(0,0), table-end(0)
    let mut data = vec![0x01u8, 0x11, 0x00, 0x0B, 0x21];
    data.extend(enc_sleb(-42));
    data.extend([0x00, 0x00, 0x00]);
    let t = ab::parse_abbrev_table(&data, 0).expect("table");
    let d = t.get(1).unwrap();
    assert_eq!(d.attrs[0].implicit_const, -42);
    assert_eq!(d.attrs[0].form, ab::DwForm::ImplicitConst);
}

#[test]
fn parse_abbrev_table_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let len = (lcg.next() % 64) as usize;
        let buf = lcg.bytes(len);
        let _ = ab::parse_abbrev_table(&buf, 0);
    }
}

#[test]
fn parse_all_abbrev_tables_handles_garbage() {
    let mut lcg = Lcg::new();
    for _ in 0..20 {
        let len = (lcg.next() % 128) as usize;
        let buf = lcg.bytes(len);
        let _ = ab::parse_all_abbrev_tables(&buf);
    }
}

// ── 7. read_form_value boundaries ─────────────────────────────────────────────

#[test]
fn read_form_value_addr_sizes() {
    // 4-byte addr
    let data: [u8; 4] = [0xEF, 0xBE, 0xAD, 0xDE];
    let mut pos = 0;
    assert_eq!(
        ab::read_form_value(&data, &mut pos, ab::DwForm::Addr, 4, false, 0),
        Some(ab::FormValue::Uint(0xDEAD_BEEF))
    );
    // 8-byte addr
    let mut pos = 0;
    let d8 = [0x78, 0x56, 0x34, 0x12, 0x9A, 0x78, 0x56, 0x34];
    assert_eq!(
        ab::read_form_value(&d8, &mut pos, ab::DwForm::Addr, 8, false, 0),
        Some(ab::FormValue::Uint(0x3456_789A_1234_5678))
    );
}

#[test]
fn read_form_value_truncated_returns_none() {
    let data: [u8; 2] = [0xAA, 0xBB];
    let mut pos = 0;
    assert_eq!(
        ab::read_form_value(&data, &mut pos, ab::DwForm::Data4, 4, false, 0),
        None
    );
}

#[test]
fn read_form_value_indirect_recursion() {
    // Indirect form: read ULEB code, then read that form. Here: indirect → Data1 → 0xAB.
    let mut data = enc_uleb(ab::DwForm::Data1 as u64);
    data.push(0xAB);
    let mut pos = 0;
    let v = ab::read_form_value(&data, &mut pos, ab::DwForm::Indirect, 4, false, 0).unwrap();
    assert_eq!(v, ab::FormValue::Uint(0xAB));
}

#[test]
fn read_form_value_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    let forms = [
        ab::DwForm::Addr, ab::DwForm::Data1, ab::DwForm::Data2, ab::DwForm::Data4,
        ab::DwForm::Data8, ab::DwForm::Udata, ab::DwForm::Sdata, ab::DwForm::Block1,
        ab::DwForm::Block, ab::DwForm::Exprloc, ab::DwForm::String, ab::DwForm::Indirect,
    ];
    for _ in 0..200 {
        let len = (lcg.next() % 64) as usize;
        let buf = lcg.bytes(len);
        let form = forms[(lcg.next() as usize) % forms.len()];
        let mut pos = 0;
        let _ = ab::read_form_value(&buf, &mut pos, form, 8, false, 0);
    }
}

// ── 8. TypeUnitHeader / TypeSignatureIndex ────────────────────────────────────

fn build_type_unit_v4_le(sig: u64, type_off: u32, body: &[u8]) -> Vec<u8> {
    // unit_length: covers everything after the length field.
    // header bytes after length: ver(2)+abbrev_off(4)+addr_sz(1)+sig(8)+type_off(4) = 19
    let unit_len = (19 + body.len()) as u32;
    let mut v = Vec::new();
    v.extend_from_slice(&unit_len.to_le_bytes());
    v.extend_from_slice(&4u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes()); // abbrev offset
    v.push(8); // addr_size
    v.extend_from_slice(&sig.to_le_bytes());
    v.extend_from_slice(&type_off.to_le_bytes());
    v.extend_from_slice(body);
    v
}

#[test]
fn type_unit_header_parses_v4() {
    let blob = build_type_unit_v4_le(0xCAFE_BABE_DEAD_BEEF, 0x10, &[]);
    let (hdr, after) = tu::parse_type_unit_header(&blob, 0).expect("parse");
    assert_eq!(hdr.version, 4);
    assert_eq!(hdr.type_signature, 0xCAFE_BABE_DEAD_BEEF);
    assert_eq!(hdr.address_size, 8);
    assert_eq!(hdr.type_offset, 0x10);
    assert!(!hdr.is_64bit);
    assert_eq!(after, 23);
    assert_eq!(hdr.header_size(), 23);
}

#[test]
fn type_unit_header_rejects_v3() {
    // Modify version byte to 3.
    let mut blob = build_type_unit_v4_le(1, 1, &[]);
    blob[4] = 3;
    blob[5] = 0;
    assert!(tu::parse_type_unit_header(&blob, 0).is_none());
}

#[test]
fn type_unit_header_truncated() {
    let blob = build_type_unit_v4_le(1, 1, &[]);
    for end in 0..blob.len() {
        let _ = tu::parse_type_unit_header(&blob[..end], 0);
    }
}

#[test]
fn type_signature_index_insert_lookup_30() {
    let mut idx = tu::TypeSignatureIndex::new();
    let mut lcg = Lcg::new();
    let mut sigs = Vec::new();
    for _ in 0..30 {
        let sig = lcg.next();
        sigs.push(sig);
        let hdr = tu::TypeUnitHeader {
            unit_length: 19,
            version: 4,
            debug_abbrev_offset: 0,
            address_size: 8,
            type_signature: sig,
            type_offset: 0,
            is_64bit: false,
        };
        idx.insert(tu::TypeUnit::new(hdr, Vec::new()));
    }
    // Hash/Eq-style consistency: every inserted signature must lookup.
    for &s in &sigs {
        assert!(idx.get(s).is_some());
        assert!(tu::find_type_by_signature(&idx, s).is_some());
    }
    assert_eq!(idx.signatures().len(), idx.len());
    // signatures are sorted
    let mut sorted = sigs.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(idx.signatures(), sorted);
}

#[test]
fn type_signature_index_from_debug_types_roundtrip() {
    let body = b"\x00\x00\x00\x00\x00\x00\x00\x00"; // 8 NUL bytes as fake DIE
    let blob = build_type_unit_v4_le(0xABCD_1234_5678_9ABC, 0, body);
    let idx = tu::TypeSignatureIndex::from_debug_types(&blob);
    assert_eq!(idx.len(), 1);
    let u = idx.get(0xABCD_1234_5678_9ABC).unwrap();
    assert_eq!(u.version(), 4);
    assert_eq!(u.die_size(), body.len());
}

#[test]
fn type_signature_index_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let len = (lcg.next() % 256) as usize;
        let buf = lcg.bytes(len);
        let _ = tu::TypeSignatureIndex::from_debug_types(&buf);
    }
}

#[test]
fn type_unit_with_name_chain() {
    let hdr = tu::TypeUnitHeader {
        unit_length: 19,
        version: 4,
        debug_abbrev_offset: 0,
        address_size: 8,
        type_signature: 42,
        type_offset: 0,
        is_64bit: false,
    };
    let u = tu::TypeUnit::new(hdr, vec![1, 2, 3]).with_type_name("Foo");
    assert_eq!(u.type_name.as_deref(), Some("Foo"));
    assert_eq!(u.signature(), 42);
    assert_eq!(u.die_size(), 3);
}

// ── 9. LineRowFlags bit-field ─────────────────────────────────────────────────

#[test]
fn line_row_flags_independent_bits() {
    let mut f = lp::LineRowFlags::default();
    assert!(!f.is_stmt() && !f.basic_block() && !f.end_sequence());
    f.set_is_stmt(true);
    assert!(f.is_stmt());
    assert!(!f.basic_block());
    f.set_basic_block(true);
    f.set_end_sequence(true);
    f.set_prologue_end(true);
    f.set_epilogue_begin(true);
    assert!(f.is_stmt() && f.basic_block() && f.end_sequence() && f.prologue_end() && f.epilogue_begin());
    f.set_is_stmt(false);
    assert!(!f.is_stmt());
    assert!(f.basic_block());
}

#[test]
fn line_row_flags_toggle_50_random() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = lcg.next();
        let mut f = lp::LineRowFlags::default();
        f.set_is_stmt(n & 1 != 0);
        f.set_basic_block(n & 2 != 0);
        f.set_end_sequence(n & 4 != 0);
        f.set_prologue_end(n & 8 != 0);
        f.set_epilogue_begin(n & 16 != 0);
        assert_eq!(f.is_stmt(), n & 1 != 0);
        assert_eq!(f.basic_block(), n & 2 != 0);
        assert_eq!(f.end_sequence(), n & 4 != 0);
        assert_eq!(f.prologue_end(), n & 8 != 0);
        assert_eq!(f.epilogue_begin(), n & 16 != 0);
    }
}

// ── 10. LineMatrix lookup ─────────────────────────────────────────────────────

fn mk_row(addr: u64, file: u32, line: u32, is_stmt: bool) -> lp::LineRow {
    let mut flags = lp::LineRowFlags::default();
    flags.set_is_stmt(is_stmt);
    lp::LineRow {
        address: addr,
        op_index: 0,
        file,
        line,
        column: 0,
        flags,
        isa: 0,
        discriminator: 0,
    }
}

#[test]
fn line_matrix_lookup_partition() {
    let mut m = lp::LineMatrix::default();
    m.rows = vec![mk_row(10, 1, 1, true), mk_row(20, 1, 2, true), mk_row(30, 1, 3, false)];
    assert!(m.lookup(5).is_none());
    assert_eq!(m.lookup(10).unwrap().line, 1);
    assert_eq!(m.lookup(15).unwrap().line, 1);
    assert_eq!(m.lookup(20).unwrap().line, 2);
    assert_eq!(m.lookup(999).unwrap().line, 3);
}

#[test]
fn line_matrix_filters() {
    let mut m = lp::LineMatrix::default();
    m.rows = vec![mk_row(10, 1, 1, true), mk_row(20, 2, 2, false), mk_row(30, 1, 3, true)];
    assert_eq!(m.rows_for_file(1).len(), 2);
    assert_eq!(m.rows_for_file(2).len(), 1);
    assert_eq!(m.rows_for_file(9).len(), 0);
    assert_eq!(m.statement_rows().len(), 2);
    assert_eq!(m.row_for_address(20).map(|r| r.line), Some(2));
    assert!(m.row_for_address(99).is_none());
    assert_eq!(m.len(), 3);
    assert!(!m.is_empty());
}

#[test]
fn line_header_file_path_resolution() {
    let hdr = lp::LineHeader {
        version: 4,
        min_insn_len: 1,
        max_ops_per_insn: 1,
        default_is_stmt: true,
        line_base: -5,
        line_range: 14,
        opcode_base: 13,
        standard_opcode_lengths: vec![],
        include_directories: vec!["/src".into(), "/inc".into()],
        file_names: vec![
            lp::LineFile { name: String::new(), dir_index: 0, mtime: 0, size: 0 },
            lp::LineFile { name: "a.c".into(), dir_index: 0, mtime: 0, size: 0 },
            lp::LineFile { name: "b.c".into(), dir_index: 1, mtime: 0, size: 0 },
            lp::LineFile { name: "c.h".into(), dir_index: 2, mtime: 0, size: 0 },
        ],
    };
    assert_eq!(hdr.file_path(1), "a.c");
    assert_eq!(hdr.file_path(2), "/src/b.c");
    assert_eq!(hdr.file_path(3), "/inc/c.h");
    assert!(hdr.file_path(999).contains("<file:999>"));
}

#[test]
fn line_program_empty_data() {
    let mut p = lp::LineProgram::new(&[]);
    let m = p.execute_all().unwrap();
    assert!(m.is_empty());
}

#[test]
fn line_program_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let len = (lcg.next() % 64) as usize;
        let buf = lcg.bytes(len);
        let mut p = lp::LineProgram::new(&buf);
        // Either Ok or specific LineError; never panic.
        let _ = p.execute_all();
    }
}

// ── 11. Serde round-trip on public types (30 pairs total across types) ────────

#[test]
fn dwarf_location_serde_all_variants() {
    let cases = vec![
        DwarfLocation::Register(0),
        DwarfLocation::Register(31),
        DwarfLocation::Register(u32::MAX),
        DwarfLocation::MemoryOffset { register: 6, offset: 0 },
        DwarfLocation::MemoryOffset { register: 6, offset: i64::MIN },
        DwarfLocation::MemoryOffset { register: 0, offset: i64::MAX },
        DwarfLocation::Constant(0),
        DwarfLocation::Constant(u64::MAX),
        DwarfLocation::Unknown,
    ];
    for c in cases {
        let s = serde_json::to_string(&c).unwrap();
        let back: DwarfLocation = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }
}

#[test]
fn dwarf_type_tag_all_variants() {
    for t in [
        DwarfTypeTag::Base,
        DwarfTypeTag::Pointer,
        DwarfTypeTag::Typedef,
        DwarfTypeTag::Struct,
        DwarfTypeTag::Union,
        DwarfTypeTag::Array,
        DwarfTypeTag::Other,
    ] {
        let s = serde_json::to_string(&t).unwrap();
        let back: DwarfTypeTag = serde_json::from_str(&s).unwrap();
        assert_eq!(t, back);
    }
}

// ── 12. DwarfError Display + variants ─────────────────────────────────────────

#[test]
fn dwarf_error_all_messages() {
    let errs = [
        DwarfError::UnsupportedFormat,
        DwarfError::MalformedDwarf,
        DwarfError::UnexpectedEof,
        DwarfError::SectionMissing(".debug_xyz".into()),
    ];
    for e in errs {
        let s = format!("{e}");
        assert!(!s.is_empty());
    }
}

// ── 13. DwarfReader edge cases (ELF parsing) ──────────────────────────────────

#[test]
fn dwarf_reader_from_bytes_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let len = (lcg.next() % 256) as usize;
        let mut buf = lcg.bytes(len);
        // Sometimes inject ELF magic to push deeper into parser.
        if buf.len() >= 6 && lcg.next() & 1 == 0 {
            buf[0] = 0x7f;
            buf[1] = b'E';
            buf[2] = b'L';
            buf[3] = b'F';
            buf[4] = 2;
            buf[5] = 1;
        }
        let _ = DwarfReader::from_bytes(&buf);
    }
}

#[test]
fn dwarf_reader_from_sections_with_unrelated_section_yields_empty() {
    let mut map = HashMap::new();
    map.insert(".text".to_string(), vec![0u8; 16]);
    let r = DwarfReader::from_sections(map);
    assert!(r.functions().is_empty());
    assert!(r.types().is_empty());
    assert!(r.variables().is_empty());
    assert!(r.line_info().is_empty());
}

// ── 14. LocationExpr / LocationResult ─────────────────────────────────────────

#[test]
fn location_expr_basic() {
    let e = le::LocationExpr::from_slice(&[0x50, 0x9c, 0x91]);
    assert_eq!(e.len(), 3);
    assert!(!e.is_empty());
    let ops = e.opcodes();
    assert!(ops.contains(&0x50));
    assert!(ops.contains(&0x9c));
}

#[test]
fn location_expr_empty() {
    let e = le::LocationExpr::new(Vec::new());
    assert!(e.is_empty());
    assert_eq!(e.len(), 0);
    assert!(e.opcodes().is_empty());
}

#[test]
fn dw_op_name_known_and_unknown() {
    assert!(le::dw_op_name(0xA8).is_some()); // DW_OP_convert
    assert!(le::dw_op_name(0xFF).is_none());
}

#[test]
fn register_file_get_set_oob() {
    let mut rf = le::RegisterFile::new(8);
    rf.set(0, 0xAA);
    rf.set(7, 0xBB);
    rf.set(99, 0xCC); // out of range: silently ignored
    assert_eq!(rf.get(0), 0xAA);
    assert_eq!(rf.get(7), 0xBB);
    assert_eq!(rf.get(99), 0);
    assert_eq!(rf.get(3), 0);
}

#[test]
fn simple_memory_write_read_cross_page() {
    let mut m = le::SimpleMemory::new();
    let addr = 4096 - 4; // straddle page boundary
    m.write(addr, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    assert_eq!(m.read_u64(addr), Some(0x8877_6655_4433_2211));
}

#[test]
fn simple_memory_unmapped_returns_none() {
    let m = le::SimpleMemory::new();
    assert_eq!(m.read_u64(0xDEAD_0000), None);
}

#[test]
fn location_result_serde_variants() {
    let cases = vec![
        le::LocationResult::Register(5),
        le::LocationResult::RegisterOffset { register: 6, offset: -16 },
        le::LocationResult::Address(0x1000),
        le::LocationResult::Value(42),
        le::LocationResult::TlsAddress(0xfeed),
        le::LocationResult::CfaOffset(-8),
        le::LocationResult::ImplicitPointer { die_offset: 0x100, byte_offset: 4 },
        le::LocationResult::Unknown,
    ];
    for c in cases {
        let s = serde_json::to_string(&c).unwrap();
        let back: le::LocationResult = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }
}

// ── 15. split_dwarf: DwoFile / SkeletonUnit / DwoResolver ─────────────────────

#[test]
fn dwo_file_rejects_non_elf() {
    let r = sd::DwoFile::from_elf_bytes(PathBuf::from("x"), &[0, 0, 0, 0, 0]);
    assert!(matches!(r, Err(sd::SplitDwarfError::NotDwo)));
}

#[test]
fn dwo_file_rejects_empty() {
    let r = sd::DwoFile::from_elf_bytes(PathBuf::from("x"), &[]);
    assert!(matches!(r, Err(sd::SplitDwarfError::NotDwo)));
}

#[test]
fn dwo_file_fuzz_no_panic() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let len = (lcg.next() % 256) as usize;
        let mut buf = lcg.bytes(len);
        if buf.len() >= 4 {
            buf[0] = 0x7f;
            buf[1] = b'E';
            buf[2] = b'L';
            buf[3] = b'F';
        }
        let _ = sd::DwoFile::from_elf_bytes(PathBuf::from("x"), &buf);
    }
}

#[test]
fn dwp_package_rejects_non_elf() {
    let r = sd::DwpPackage::from_elf_bytes(&[1, 2, 3]);
    assert!(matches!(r, Err(sd::SplitDwarfError::NotDwp)));
}

#[test]
fn dwo_section_is_debug_section() {
    let s1 = sd::DwoSection::new(".debug_info.dwo", vec![]);
    assert!(s1.is_debug_section());
    let s2 = sd::DwoSection::new(".text", vec![]);
    assert!(!s2.is_debug_section());
}

#[test]
fn skeleton_unit_resolve_path_relative_and_absolute() {
    let sk = sd::SkeletonUnit {
        offset: 0,
        dwo_id: 0,
        dwo_name: "foo.dwo".into(),
        comp_dir: "/build".into(),
    };
    let p = sk.resolve_path();
    assert!(p.ends_with("foo.dwo"));
    // Path joined with comp_dir
    assert!(p.to_string_lossy().contains("build"));

    // Absolute path: comp_dir ignored.
    #[cfg(unix)]
    {
        let sk2 = sd::SkeletonUnit {
            offset: 0,
            dwo_id: 0,
            dwo_name: "/abs/x.dwo".into(),
            comp_dir: "/build".into(),
        };
        assert_eq!(sk2.resolve_path(), PathBuf::from("/abs/x.dwo"));
    }
}

#[test]
fn resolve_dwo_path_helper() {
    let p = sd::resolve_dwo_path("/build", "x.dwo");
    assert!(p.ends_with("x.dwo"));
    let p2 = sd::resolve_dwo_path("", "y.dwo");
    assert_eq!(p2, PathBuf::from("y.dwo"));
}

#[test]
fn dwo_resolver_missing_returns_none() {
    let r = sd::DwoResolver::new(vec![PathBuf::from("/nonexistent_xyz_12345")]);
    let sk = sd::SkeletonUnit {
        offset: 0,
        dwo_id: 0,
        dwo_name: "missing_qwerty.dwo".into(),
        comp_dir: "/nope_zzz".into(),
    };
    assert!(r.resolve_path(&sk).is_none());
}

#[test]
fn split_dwarf_error_display() {
    let errs = [
        sd::SplitDwarfError::NotDwo,
        sd::SplitDwarfError::NotDwp,
        sd::SplitDwarfError::IdMismatch(1, 2),
        sd::SplitDwarfError::SectionMissing("x".into()),
        sd::SplitDwarfError::Malformed("y".into()),
        sd::SplitDwarfError::Io("z".into()),
        sd::SplitDwarfError::Truncated(7),
    ];
    for e in errs {
        assert!(!format!("{e}").is_empty());
    }
}

// ── 16. Send+Sync threaded stress (4 threads × 100 ops) ───────────────────────

#[test]
fn dwarf_reader_send_sync_4_threads_100_ops() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DwarfReader>();

    let r = Arc::new(DwarfReader::from_sections(HashMap::new()));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let r = Arc::clone(&r);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                assert!(r.functions().is_empty());
                assert!(r.types().is_empty());
                assert!(r.variables().is_empty());
                assert!(r.line_info().is_empty());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn dwarf_function_send_sync() {
    fn s<T: Send + Sync>() {}
    s::<DwarfFunction>();
    s::<DwarfVariable>();
    s::<DwarfType>();
    s::<DwarfTypeTag>();
    s::<DwarfLocation>();
    s::<LineEntry>();
    s::<DwarfError>();
}

// ── 17. Hash/Eq consistency across types (30 pairs) ───────────────────────────

#[test]
fn dwarf_location_eq_30_pairs() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let n = lcg.next() as u32;
        let a = DwarfLocation::Register(n);
        let b = DwarfLocation::Register(n);
        assert_eq!(a, b);
        let c = DwarfLocation::Register(n.wrapping_add(1));
        assert_ne!(a, c);
    }
}

#[test]
fn dw_form_eq_30_pairs() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let code = lcg.next() & 0xFF;
        let a = ab::DwForm::from_code(code);
        let b = ab::DwForm::from_code(code);
        assert_eq!(a, b);
    }
}
