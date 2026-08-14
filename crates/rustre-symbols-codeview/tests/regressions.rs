//! Regression tests for the correctness / DoS fixes applied to this crate.
//!
//! Every test here fails against the pre-fix code and passes after.

use rustre_symbols_codeview::codeview_parser::{RawSymIter, RawTypeIter, find_debug_directory};
use rustre_symbols_codeview::codeview_symbol_parser::{CodeViewSymbolParser, Compile3Symbol, ParsedSymbol};
use rustre_symbols_codeview::codeview_type_parser::{CodeViewTypeParser, CvTypeLeaf};
use rustre_symbols_codeview::cv_function_info::{CvFunctionDb, SymbolStreamBuilder, symkind};
use rustre_symbols_codeview::cv_stream_parser::CvSectionHeaders;
use rustre_symbols_codeview::cv_symbol_records::{SymRecord, decode_symbol_record, sk};
use rustre_symbols_codeview::cv_symbols::{SProc32, SymKind};
use rustre_symbols_codeview::cv_type_records::{
    FieldListEntry, LfPointer, PrimitiveKind, TypeRecord, decode_type_record, lf,
};
use rustre_symbols::{SymbolProvider, TypeInfo};
use rustre_symbols_codeview::cv_types::TypeIndex;
use rustre_symbols_codeview::{
    CvFrameproc, CvTypeKind, CvTypeRecord, CvTypeTable, PdbSuperBlock, primitive_type,
};

// ---------------------------------------------------------------------------
// DoS: iterators must make progress on error
// ---------------------------------------------------------------------------

#[test]
fn raw_sym_iter_terminates_on_malformed_record() {
    // len < 2 previously returned Err forever without advancing `pos`, so any
    // `collect()` grew a Vec until the process was OOM-killed.
    let out: Vec<_> = RawSymIter::new(&[0u8, 0, 0, 0]).collect();
    assert_eq!(out.len(), 1);
    assert!(out[0].is_err());
}

#[test]
fn raw_sym_iter_terminates_on_truncated_record() {
    // Declares a 0x20-byte record in an 8-byte buffer.
    let data = [0x20u8, 0x00, 0x10, 0x11, 0, 0, 0, 0];
    let out: Vec<_> = RawSymIter::new(&data).collect();
    assert_eq!(out.len(), 1);
    assert!(out[0].is_err());
}

#[test]
fn raw_type_iter_terminates_on_malformed_record() {
    let out: Vec<_> = RawTypeIter::new(&[0u8, 0, 0, 0], 0x1000).collect();
    assert_eq!(out.len(), 1);
    assert!(out[0].is_err());
}

// ---------------------------------------------------------------------------
// DoS: allocations capped against the real buffer
// ---------------------------------------------------------------------------

#[test]
fn arglist_capacity_capped_by_buffer() {
    // A 4-byte LF_ARGLIST declaring 0xFFFF_FFFF args previously requested a
    // ~16 GiB reservation before any bounds check.
    let rec = decode_type_record(lf::ARGLIST, &[0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
    match rec {
        TypeRecord::ArgList(a) => {
            assert!(a.arg_types.is_empty());
            // The reservation itself is the bug: assert it was capped against
            // the buffer rather than sized from the file-declared count.
            assert!(
                a.arg_types.capacity() <= 1,
                "reserved {} slots from a 4-byte record",
                a.arg_types.capacity()
            );
        }
        other => panic!("expected ArgList, got {other:?}"),
    }
}

#[test]
fn type_table_recursion_is_depth_capped() {
    // An LF_POINTER at 0x1000 whose referent is 0x1000 used to recurse until
    // the stack was exhausted — a STATUS_STACK_OVERFLOW that cannot be caught.
    let t = CvTypeTable::from_records(vec![CvTypeRecord {
        kind: CvTypeKind::Pointer,
        index: 0x1000,
        name: String::new(),
        size: 8,
        count: 0,
        underlying_type: 0x1000, // points at itself
        return_type: 0,
        arg_types: vec![],
    }]);
    // Must terminate. The innermost target bottoms out at Unknown.
    let ti = t.to_type_info(0x1000);
    assert!(matches!(ti, TypeInfo::Pointer { .. }));
}

// ---------------------------------------------------------------------------
// Field lists: modern (non-_ST) leaf codes
// ---------------------------------------------------------------------------

#[test]
fn fieldlist_decodes_modern_lf_member() {
    // LF_MEMBER = 0x150D. The decoder previously matched 0x1405 (LF_MEMBER_ST),
    // so every data member of every struct/class was silently dropped.
    let mut body = Vec::new();
    body.extend_from_slice(&0x150Du16.to_le_bytes()); // leaf
    body.extend_from_slice(&3u16.to_le_bytes()); // attr = public
    body.extend_from_slice(&0x74u32.to_le_bytes()); // type = T_INT4
    body.extend_from_slice(&0u16.to_le_bytes()); // offset numeric leaf = 0
    body.extend_from_slice(b"x\0");

    let rec = decode_type_record(lf::FIELDLIST, &body).unwrap();
    match rec {
        TypeRecord::FieldList(entries) => {
            assert_eq!(entries.len(), 1, "got {entries:?}");
            match &entries[0] {
                FieldListEntry::Member(m) => {
                    assert_eq!(m.name, "x");
                    assert_eq!(m.field_type, 0x74);
                    assert_eq!(m.offset, 0);
                }
                other => panic!("expected Member, got {other:?}"),
            }
        }
        other => panic!("expected FieldList, got {other:?}"),
    }
}

#[test]
fn fieldlist_leaf_constants_are_modern() {
    assert_eq!(lf::MEMBER, 0x150D);
    assert_eq!(lf::STMEMBER, 0x150E);
    assert_eq!(lf::METHOD, 0x150F);
    assert_eq!(lf::NESTTYPE, 0x1510);
    assert_eq!(lf::ONEMETHOD, 0x1511);
}

#[test]
fn type_parser_fieldlist_survives_leading_bclass() {
    // `class Derived : public Base { int x; }` starts with LF_BCLASS (0x1400).
    // The parser previously hit `_ => break` and returned no members at all.
    let mut body = Vec::new();
    body.extend_from_slice(&0x1400u16.to_le_bytes()); // LF_BCLASS
    body.extend_from_slice(&3u16.to_le_bytes()); // attr
    body.extend_from_slice(&0x1001u32.to_le_bytes()); // base type
    body.extend_from_slice(&0u16.to_le_bytes()); // offset numeric leaf
    body.extend_from_slice(&[0xF2, 0xF1]); // LF_PAD to 4-byte alignment
    body.extend_from_slice(&0x150Du16.to_le_bytes()); // LF_MEMBER
    body.extend_from_slice(&3u16.to_le_bytes());
    body.extend_from_slice(&0x74u32.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(b"x\0");

    // Wrap as a full LF_FIELDLIST record: len:u16, leaf:u16, body.
    let mut rec = Vec::new();
    let len = u16::try_from(2 + body.len()).unwrap();
    rec.extend_from_slice(&len.to_le_bytes());
    rec.extend_from_slice(&0x1203u16.to_le_bytes());
    rec.extend_from_slice(&body);

    let mut p = CodeViewTypeParser::new();
    assert_eq!(p.parse_stream(&rec), 1);
    match &p.records()[0].leaf {
        CvTypeLeaf::FieldList { members, .. } => {
            assert_eq!(members.len(), 1, "member after LF_BCLASS was dropped");
            assert_eq!(members[0].name, "x");
        }
        other => panic!("expected FieldList, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Symbol stream framing
// ---------------------------------------------------------------------------

#[test]
fn parse_symbol_stream_reads_every_record() {
    // The old code added a phantom 2-byte realignment after each record, so it
    // desynchronized immediately and only ever saw the first proc.
    let mut b = SymbolStreamBuilder::new();
    for name in ["alpha", "beta", "gamma"] {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // parent
        body.extend_from_slice(&0u32.to_le_bytes()); // end
        body.extend_from_slice(&0u32.to_le_bytes()); // next
        body.extend_from_slice(&0x40u32.to_le_bytes()); // len
        body.extend_from_slice(&0u32.to_le_bytes()); // dbg_start
        body.extend_from_slice(&0u32.to_le_bytes()); // dbg_end
        body.extend_from_slice(&0x1000u32.to_le_bytes()); // type index
        body.extend_from_slice(&0x100u32.to_le_bytes()); // offset
        body.extend_from_slice(&1u16.to_le_bytes()); // segment
        body.push(0); // flags
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        b.add(symkind::S_GPROC32, body);
    }
    let stream = b.build();
    // Every record must be 4-aligned, padding folded into the length field.
    assert_eq!(stream.len() % 4, 0);

    let mut db = CvFunctionDb::new();
    db.parse_symbol_stream(&stream).unwrap();
    assert_eq!(db.functions.len(), 3, "records after the first were lost");
}

#[test]
fn symbol_kind_constants_match_the_spec() {
    assert_eq!(SymKind::from_u16(0x110F), Some(SymKind::Lproc32));
    assert_eq!(SymKind::from_u16(0x1110), Some(SymKind::Gproc32));
    assert_eq!(SymKind::from_u16(0x1111), Some(SymKind::Regrel32));
    assert_eq!(SymKind::from_u16(0x110E), Some(SymKind::Pub32));
    assert_eq!(symkind::S_LPROC32, 0x110F);
    assert_eq!(symkind::S_REGREL32, 0x1111);
}

#[test]
fn parser_decodes_lproc32_and_pub32() {
    // S_LPROC32 (0x110F) previously fell through to Raw while every
    // S_REGREL32 was misdecoded as a 35-byte procedure.
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0x40u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0x1000u32.to_le_bytes());
    body.extend_from_slice(&0x200u32.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.push(0);
    body.extend_from_slice(b"local_fn\0");

    let len = u16::try_from(2 + body.len()).unwrap();
    let mut rec = Vec::new();
    rec.extend_from_slice(&len.to_le_bytes());
    rec.extend_from_slice(&0x110Fu16.to_le_bytes()); // S_LPROC32
    rec.extend_from_slice(&body);

    let mut p = CodeViewSymbolParser::new();
    p.parse_stream(&rec).unwrap();
    match &p.records()[0].symbol {
        ParsedSymbol::Proc(pr) => assert_eq!(pr.name, "local_fn"),
        other => panic!("S_LPROC32 not decoded as a proc: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Record layouts
// ---------------------------------------------------------------------------

#[test]
fn frameproc_reads_flags_from_offset_22() {
    // 26-byte payload: the old parser required 28 and read flags from 24..28.
    let mut d = vec![0u8; 26];
    d[16..20].copy_from_slice(&0xAAAAu32.to_le_bytes()); // offExHdlr @16
    d[20..22].copy_from_slice(&3u16.to_le_bytes()); // sectExHdlr @20
    d[22..26].copy_from_slice(&0x0001u32.to_le_bytes()); // fHasAlloca
    let f = CvFrameproc::parse(&d).expect("26-byte payload must parse");
    assert_eq!(f.eh_offset, 0xAAAA);
    assert_eq!(f.eh_section, 3);
    assert!(f.has_alloca());
    assert!(!f.has_security_checks());
}

#[test]
fn compile3_version_string_starts_at_22() {
    let mut d = Vec::new();
    d.extend_from_slice(&0u32.to_le_bytes()); // flags
    d.extend_from_slice(&0xD0u16.to_le_bytes()); // machine
    for v in [1u16, 2, 3, 4, 19, 29, 30139, 0] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    d.extend_from_slice(b"Microsoft (R) Optimizing Compiler\0");
    let c = Compile3Symbol::parse(&d).unwrap();
    assert_eq!(c.fe_major, 1);
    assert_eq!(c.fe_qfe, 4);
    assert_eq!(c.be_major, 19);
    assert_eq!(c.be_build, 30139);
    assert_eq!(c.version_string, "Microsoft (R) Optimizing Compiler");
}

#[test]
fn callsiteinfo_reads_typind_from_offset_8() {
    let mut d = Vec::new();
    d.extend_from_slice(&0x100u32.to_le_bytes()); // off
    d.extend_from_slice(&1u16.to_le_bytes()); // sect
    d.extend_from_slice(&0u16.to_le_bytes()); // reserved
    d.extend_from_slice(&0x1234u32.to_le_bytes()); // typind @8
    match decode_symbol_record(sk::CALLSITEINFO, &d).unwrap() {
        SymRecord::CallSiteInfo(c) => assert_eq!(c.type_index, 0x1234),
        other => panic!("expected CallSiteInfo, got {other:?}"),
    }
}

#[test]
fn section_contributions_use_a_28_byte_stride() {
    // Two 28-byte records; the old 16-byte stride emitted 3 bogus entries and
    // read module_index out of the padding after ISect.
    let mut data = Vec::new();
    for (sect, imod) in [(1u16, 5u16), (2u16, 9u16)] {
        data.extend_from_slice(&sect.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // padding
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // off
        data.extend_from_slice(&0x200u32.to_le_bytes()); // size
        data.extend_from_slice(&0u32.to_le_bytes()); // characteristics
        data.extend_from_slice(&imod.to_le_bytes()); // IMod @16
        data.extend_from_slice(&0u16.to_le_bytes()); // padding2
        data.extend_from_slice(&0u32.to_le_bytes()); // DataCrc
        data.extend_from_slice(&0u32.to_le_bytes()); // RelocCrc
    }
    assert_eq!(data.len(), 56);
    let h = CvSectionHeaders::parse(&data);
    assert_eq!(h.contributions.len(), 2);
    assert_eq!(h.contributions[0].module_index, 5);
    assert_eq!(h.contributions[1].section, 2);
    assert_eq!(h.contributions[1].module_index, 9);
}

#[test]
fn superblock_block_map_addr_is_at_offset_52() {
    let mut d = vec![0u8; 56];
    d[48..52].copy_from_slice(&0xDEADu32.to_le_bytes()); // reserved
    d[52..56].copy_from_slice(&7u32.to_le_bytes()); // real BlockMapAddr
    let sb = PdbSuperBlock::parse(&d).unwrap();
    assert_eq!(sb.block_map_addr, 7);
    assert_eq!(sb.unknown, 0xDEAD);
    // 52..55-byte inputs can never carry a correct value.
    assert!(PdbSuperBlock::parse(&[0u8; 52]).is_none());
}

// ---------------------------------------------------------------------------
// Primitive type tables
// ---------------------------------------------------------------------------

#[test]
fn primitive_t_int4_is_32_bit() {
    // T_INT4 (0x74) is the most common primitive in any PDB. The lib table used
    // to report 0x74 as 8-bit and left T_VOID unresolved.
    assert_eq!(
        format!("{:?}", primitive_type(0x74)),
        format!("{:?}", TypeInfo::Int { width: 32, signed: true })
    );
    assert!(matches!(primitive_type(0x03), TypeInfo::Void));
    assert!(matches!(primitive_type(0x00), TypeInfo::Unknown));
    // T_RCHAR is 8-bit, not 16.
    assert_eq!(
        format!("{:?}", primitive_type(0x70)),
        format!("{:?}", TypeInfo::Int { width: 8, signed: true })
    );
}

#[test]
fn primitive_kind_widths_match_cvinfo() {
    let cases = [
        (0x68u32, PrimitiveKind::Int8, 1u32),
        (0x69, PrimitiveKind::Uint8, 1),
        (0x72, PrimitiveKind::Int16, 2),
        (0x73, PrimitiveKind::Uint16, 2),
        (0x74, PrimitiveKind::Int32, 4),
        (0x75, PrimitiveKind::Uint32, 4),
        (0x76, PrimitiveKind::Int64, 8),
        (0x77, PrimitiveKind::Uint64, 8),
        (0x78, PrimitiveKind::Int128, 16),
        (0x79, PrimitiveKind::Uint128, 16),
        (0x70, PrimitiveKind::Char8, 1),
        (0x71, PrimitiveKind::WChar, 2),
        (0x7A, PrimitiveKind::Char16, 2),
        (0x7B, PrimitiveKind::Char32, 4),
    ];
    for (ti, want, size) in cases {
        let got = PrimitiveKind::from_type_idx(ti);
        assert_eq!(got, want, "wrong kind for {ti:#x}");
        assert_eq!(got.byte_size(), Some(size), "wrong size for {ti:#x}");
    }
    // Indices >= 0x1000 are LF_ records, never primitives.
    assert!(matches!(
        PrimitiveKind::from_type_idx(0x1074),
        PrimitiveKind::Unknown(0x1074)
    ));
}

#[test]
fn pointer_byte_size_maps_ptrtype_correctly() {
    // CV_PTR_NEAR32 = 10 → 4 bytes; CV_PTR_64 = 12 → 8 bytes. These two were
    // exactly inverted, so every x64 pointer field looked 32-bit.
    assert_eq!(LfPointer { referent_type: 0x74, attr: 10 }.byte_size(), 4);
    assert_eq!(LfPointer { referent_type: 0x74, attr: 12 }.byte_size(), 8);
    assert_eq!(LfPointer { referent_type: 0x74, attr: 11 }.byte_size(), 6);
    assert_eq!(LfPointer { referent_type: 0x74, attr: 0 }.byte_size(), 2);
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

#[test]
fn sproc32_end_addr_does_not_overflow() {
    // offset + len overflows u32; the addition must be widened first.
    let p = SProc32 {
        parent: 0,
        end: 0,
        next: 0,
        len: 0x2000,
        debug_start: 0,
        debug_end: 0,
        type_index: TypeIndex(0),
        offset: 0xFFFF_F000,
        segment: 1,
        flags: 0,
        name: "f".into(),
        is_global: true,
    };
    assert_eq!(p.end_addr(), 0x1_0000_1000);
}

#[test]
fn debug_directory_uses_optional_header_magic() {
    // An ARM64 image (machine 0xAA64) has a PE32+ optional header. Selecting the
    // data directory by machine type read it 16 bytes early and never found the
    // debug entry.
    let mut pe = vec![0u8; 0x400];
    pe[..2].copy_from_slice(b"MZ");
    let sig_off = 0x80usize;
    pe[60..64].copy_from_slice(&u32::try_from(sig_off).unwrap().to_le_bytes());
    pe[sig_off..sig_off + 4].copy_from_slice(b"PE\0\0");
    pe[sig_off + 4..sig_off + 6].copy_from_slice(&0xAA64u16.to_le_bytes()); // ARM64
    pe[sig_off + 6..sig_off + 8].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    pe[sig_off + 20..sig_off + 22].copy_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader
    pe[sig_off + 24..sig_off + 26].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+

    // Debug data directory (index 6) at the PE32+ offset.
    let dd = sig_off + 24 + 112 + 6 * 8;
    pe[dd..dd + 4].copy_from_slice(&0x2000u32.to_le_bytes()); // rva
    pe[dd + 4..dd + 8].copy_from_slice(&28u32.to_le_bytes()); // size

    // One section header mapping RVA 0x2000 → file offset 0x200.
    let sec = sig_off + 24 + 240;
    pe[sec + 12..sec + 16].copy_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress
    pe[sec + 16..sec + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // SizeOfRawData
    pe[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData

    let (off, size) = find_debug_directory(&pe).expect("PE32+ debug directory not found");
    assert_eq!(off, 0x200);
    assert_eq!(size, 28);
}

#[test]
fn type_parser_honors_type_index_begin() {
    // A minimal LF_POINTER record: len:u16, leaf:u16, referent:u32, attr:u32.
    let mut rec = Vec::new();
    rec.extend_from_slice(&10u16.to_le_bytes());
    rec.extend_from_slice(&0x1002u16.to_le_bytes()); // LF_POINTER
    rec.extend_from_slice(&0x74u32.to_le_bytes());
    rec.extend_from_slice(&12u32.to_le_bytes());

    let mut p = CodeViewTypeParser::with_start_index(0x1004);
    assert_eq!(p.parse_stream(&rec), 1);
    assert_eq!(p.records()[0].type_index, 0x1004, "TypeIndexBegin was ignored");

    // Below 0x1000 is the reserved primitive range; clamp up.
    let mut q = CodeViewTypeParser::with_start_index(0);
    assert_eq!(q.parse_stream(&rec), 1);
    assert_eq!(q.records()[0].type_index, 0x1000);
}

// ---------------------------------------------------------------------------
// SRegrel32::is_stack_relative — CV_AMD64 register numbering
// ---------------------------------------------------------------------------

#[test]
fn regrel32_stack_relative_uses_rsp_rbp_not_rsi_rdi() {
    use rustre_symbols_codeview::cv_symbol_records::CvReg;
    use rustre_symbols_codeview::cv_symbols::SRegrel32;

    let mk = |reg: u16| SRegrel32 {
        offset: -8,
        type_index: TypeIndex(0),
        register: reg,
        name: "local".into(),
    };

    // CV_AMD64 numbers 328..=335 as RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP —
    // NOT the classic x86 order (see LLVM CodeViewRegisters.def). So RBP = 334
    // and RSP = 335.
    //
    // This assertion used to say 332/333, and the comment above it described
    // "fixing" code that matched 334|335. That original code was RIGHT: the
    // change was made against this crate's own mistaken table and this test
    // then cemented it. A defect that ships with its own regression test is
    // the hardest kind to see, which is why the numbers here are now tied to
    // the format rather than to the enum.
    assert_eq!(CvReg::Rbp as u16, 334);
    assert_eq!(CvReg::Rsp as u16, 335);
    assert_eq!(CvReg::Rsi as u16, 332);
    assert_eq!(CvReg::Rdi as u16, 333);

    assert!(mk(CvReg::Rsp as u16).is_stack_relative());
    assert!(mk(CvReg::Rbp as u16).is_stack_relative());
    assert!(!mk(CvReg::Rsi as u16).is_stack_relative());
    assert!(!mk(CvReg::Rdi as u16).is_stack_relative());
}

#[test]
fn regrel32_stack_relative_for_x86_machine() {
    use rustre_symbols_codeview::cv_symbols::SRegrel32;

    let mk = |reg: u16| SRegrel32 {
        offset: -4,
        type_index: TypeIndex(0),
        register: reg,
        name: "local".into(),
    };
    // CV_CFL_80386 = 0x03: EBP = 22, ESP = 21.
    assert!(mk(22).is_stack_relative_for(0x03));
    assert!(mk(21).is_stack_relative_for(0x03));
    assert!(!mk(23).is_stack_relative_for(0x03)); // ESI
    // CV_CFL_X64 = 0xD0 falls through to the x64 encoding.
    assert!(mk(334).is_stack_relative_for(0xD0), "334 is RBP under CV_CFL_X64");
    assert!(!mk(22).is_stack_relative_for(0xD0));
}

// ---------------------------------------------------------------------------
// CodeViewProvider: segment-aware VA resolution
// ---------------------------------------------------------------------------

fn pub32_record(name: &str, offset: u32, segment: u16) -> (u16, Vec<u8>) {
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes()); // flags
    body.extend_from_slice(&offset.to_le_bytes());
    body.extend_from_slice(&segment.to_le_bytes());
    body.extend_from_slice(name.as_bytes());
    body.push(0);
    (0x110E, body) // S_PUB32
}

#[test]
fn provider_resolves_va_through_section_table() {
    let mut b = SymbolStreamBuilder::new();
    for (name, off, seg) in [("text_fn", 0x40u32, 1u16), ("data_var", 0x40, 2)] {
        let (kind, body) = pub32_record(name, off, seg);
        b.add(kind, body);
    }
    let stream = b.build();

    let image_base = 0x1_4000_0000u64;
    // .text at RVA 0x1000, .data at RVA 0x5000.
    let section_rvas = [0x1000u64, 0x5000];

    let p = rustre_symbols_codeview::CodeViewProvider::from_bytes_with_sections(
        &stream,
        image_base,
        &section_rvas,
    )
    .unwrap();

    let syms = p.all_symbols();
    let addrs: Vec<u64> = syms.iter().map(|s| s.address).collect();
    // The old code ignored the segment: both landed on image_base + 0x40.
    assert!(
        addrs.contains(&(image_base + 0x1000 + 0x40)),
        "text symbol misplaced: {addrs:x?}"
    );
    assert!(
        addrs.contains(&(image_base + 0x5000 + 0x40)),
        "data symbol misplaced: {addrs:x?}"
    );
    assert_ne!(addrs[0], addrs[1], "distinct segments collapsed to one VA");
}

#[test]
fn provider_skips_segment_zero_and_out_of_range() {
    let mut b = SymbolStreamBuilder::new();
    for (name, off, seg) in [
        ("absolute", 0x10u32, 0u16), // segment 0: absolute / internal linkage
        ("bogus_seg", 0x10, 99),     // past the end of the section table
        ("real", 0x10, 1),
    ] {
        let (kind, body) = pub32_record(name, off, seg);
        b.add(kind, body);
    }
    let stream = b.build();

    let p = rustre_symbols_codeview::CodeViewProvider::from_bytes_with_sections(
        &stream,
        0x1000,
        &[0x1000u64],
    )
    .unwrap();
    let syms = p.all_symbols();
    assert_eq!(syms.len(), 1, "bogus segments were not filtered");
    assert_eq!(syms[0].name, "real");
    assert_eq!(syms[0].address, 0x1000 + 0x1000 + 0x10);
}

#[test]
fn provider_va_resolution_does_not_overflow() {
    // Crafted offsets near u64::MAX must be dropped, not panic in a debug build.
    assert_eq!(
        rustre_symbols_codeview::resolve_cv_va(u64::MAX, &[0x1000], 1, 0x10),
        None
    );
    assert_eq!(rustre_symbols_codeview::resolve_cv_va(0, &[0x1000], 0, 0x10), None);
    assert_eq!(
        rustre_symbols_codeview::resolve_cv_va(0x1000, &[0x2000], 1, 0x30),
        Some(0x3030)
    );
}

// ---------------------------------------------------------------------------
// read_cstring: lossy, not a shared placeholder
// ---------------------------------------------------------------------------

#[test]
fn non_utf8_names_stay_distinct() {
    use rustre_symbols_codeview::codeview_types::TypeReader;

    let a = [0xE0u8, 0x41, 0x00];
    let b = [0xE0u8, 0x42, 0x00];
    let na = TypeReader::new(&a).read_cstring().unwrap();
    let nb = TypeReader::new(&b).read_cstring().unwrap();
    // The old code returned the literal "<invalid utf8>" for both, so two
    // unrelated UDTs compared equal and forward refs cross-resolved.
    assert_ne!(na, nb, "distinct non-UTF-8 names collapsed to one string");
    assert_ne!(na, "<invalid utf8>");
    assert!(na.contains('A'));
    assert!(nb.contains('B'));
}

// ---------------------------------------------------------------------------
// parse_stream reports why it stopped
// ---------------------------------------------------------------------------

#[test]
fn parse_stream_reports_truncation() {
    use rustre_symbols_codeview::codeview_type_parser::TypeStreamStop;

    // One well-formed LF_POINTER record.
    let mut good = Vec::new();
    let body = [0x03u8, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00];
    good.extend_from_slice(&((2 + body.len()) as u16).to_le_bytes());
    good.extend_from_slice(&0x1002u16.to_le_bytes());
    good.extend_from_slice(&body);

    let mut p = CodeViewTypeParser::new();
    assert_eq!(p.parse_stream(&good), 1);
    assert_eq!(p.stop_reason(), Some(TypeStreamStop::Complete));

    // Same record followed by a header claiming far more data than remains.
    let mut bad = good.clone();
    bad.extend_from_slice(&0x0100u16.to_le_bytes()); // len = 256
    bad.extend_from_slice(&0x1002u16.to_le_bytes());

    let mut q = CodeViewTypeParser::new();
    // Still tolerant: the good record survives.
    assert_eq!(q.parse_stream(&bad), 1);
    // But the caller can now tell the stream went bad, which the bare count
    // could not express.
    assert!(matches!(
        q.stop_reason(),
        Some(TypeStreamStop::Truncated { .. })
    ));
}
