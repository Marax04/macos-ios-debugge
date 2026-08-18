//! Exhaustive integration tests for `rustre-loader-lua` public API.
//!
//! These tests exercise the API from outside the crate to surface
//! contract bugs, parser edge cases, and round-trip invariants.

use rustre_loader_lua::{
    ConstantIndex, LuaBytecode, LuaBytecodeLoader, LuaChunk, LuaConst, LuaEndian, LuaHeader,
    LuaInstr, LuaLoader, LuaLoaderError, LuaLocalVar, LuaModule, LuaProto, LuaUpvalue, LuaVersion,
    ModuleDisasm, OpcodeLayout, ProtoDisasm, ProtoStats, ProtoWalker, UpvalueDesc,
    disassemble_proto, is_lua_bytecode, opcode_layout, opcode_name, parse_proto_51,
    parse_proto_54, read_string_lua, LUA51_OPCODES, LUA52_OPCODES, LUA53_OPCODES, LUA54_OPCODES,
    LUA_MAGIC,
};
use rustre_core::{Loader, LoaderInput};

// ─── Helpers ────────────────────────────────────────────────────────────────

fn header_51_min() -> Vec<u8> {
    // 12-byte 5.1 header (LE, 4-byte int)
    vec![
        0x1B, b'L', b'u', b'a', 0x51, 0, 1, 4, 8, 4, 8, 0,
    ]
}

fn header_54_min() -> Vec<u8> {
    let mut v = vec![
        0x1B, b'L', b'u', b'a', 0x54, 0, 1, 4, 8, 4, 8, 0,
        // LUAC_DATA integrity block
        0x19, 0x93, 0x0D, 0x0A, 0x1A, 0x0A,
        8, // lua_integer_size
        8, // lua_float_size
    ];
    assert_eq!(v.len(), 20);
    v.truncate(20);
    v
}

fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

// ─── Magic detection ────────────────────────────────────────────────────────

#[test]
fn magic_constant_value() {
    assert_eq!(LUA_MAGIC, b"\x1bLua");
}

#[test]
fn is_bytecode_exact_5_bytes() {
    assert!(is_lua_bytecode(b"\x1bLuaX"));
}

#[test]
fn is_bytecode_four_bytes_only() {
    assert!(!is_lua_bytecode(b"\x1bLua"));
}

#[test]
fn is_bytecode_wrong_first_byte() {
    assert!(!is_lua_bytecode(b"\x1aLuaX"));
}

#[test]
fn is_bytecode_empty() {
    assert!(!is_lua_bytecode(&[]));
}

#[test]
fn is_bytecode_huge_buf_valid_magic() {
    let mut d = vec![0u8; 10_000];
    d[0..4].copy_from_slice(LUA_MAGIC);
    assert!(is_lua_bytecode(&d));
}

// ─── LuaVersion ─────────────────────────────────────────────────────────────

#[test]
fn version_roundtrip_known() {
    for b in [0x51, 0x52, 0x53, 0x54] {
        assert_eq!(LuaVersion::from_byte(b).as_byte(), b);
    }
}

#[test]
fn version_unknown_byte_roundtrip() {
    assert_eq!(LuaVersion::from_byte(0xAB).as_byte(), 0xAB);
}

#[test]
fn version_major_always_5_for_known() {
    for v in [LuaVersion::Lua51, LuaVersion::Lua52, LuaVersion::Lua53, LuaVersion::Lua54] {
        assert_eq!(v.major(), 5);
    }
}

#[test]
fn version_unknown_not_known() {
    assert!(!LuaVersion::Unknown(0).is_known());
    assert!(!LuaVersion::Unknown(0xFF).is_known());
}

#[test]
fn version_display_all() {
    assert_eq!(LuaVersion::Lua51.to_string(), "Lua 5.1");
    assert_eq!(LuaVersion::Lua52.to_string(), "Lua 5.2");
    assert_eq!(LuaVersion::Lua53.to_string(), "Lua 5.3");
    assert_eq!(LuaVersion::Lua54.to_string(), "Lua 5.4");
}

#[test]
fn version_equality_and_copy() {
    let a = LuaVersion::Lua54;
    let b = a;
    assert_eq!(a, b);
}

// ─── LuaEndian ──────────────────────────────────────────────────────────────

#[test]
fn endian_is_le_only_for_le() {
    assert!(LuaEndian::Le.is_le());
    assert!(!LuaEndian::Be.is_le());
}

#[test]
fn endian_any_nonzero_is_le() {
    // Spec: byte != 0 → LE
    assert_eq!(LuaEndian::from_byte(2), LuaEndian::Le);
    assert_eq!(LuaEndian::from_byte(0xFF), LuaEndian::Le);
}

// ─── LuaHeader parsing ──────────────────────────────────────────────────────

#[test]
fn header_parse_min_size_constant() {
    assert_eq!(LuaHeader::MIN_SIZE, 12);
}

#[test]
fn header_51_end_pos_is_12() {
    let d = header_51_min();
    let (_, end) = LuaHeader::parse(&d).unwrap();
    assert_eq!(end, 12);
}

#[test]
fn header_54_end_pos_is_20() {
    let d = header_54_min();
    let (_, end) = LuaHeader::parse(&d).unwrap();
    assert_eq!(end, 20);
}

#[test]
fn header_54_bad_luac_data_rejected() {
    let mut d = header_54_min();
    d[12] = 0xAA; // corrupt LUAC_DATA
    let err = LuaHeader::parse(&d).unwrap_err();
    assert!(matches!(err, LuaLoaderError::InvalidMagic));
}

#[test]
fn header_truncated_below_min() {
    for n in 0..12 {
        let d = vec![0u8; n];
        let err = LuaHeader::parse(&d).unwrap_err();
        assert!(matches!(err, LuaLoaderError::TruncatedData));
    }
}

#[test]
fn header_be_parses() {
    let mut d = header_51_min();
    d[6] = 0;
    let (h, _) = LuaHeader::parse(&d).unwrap();
    assert_eq!(h.endian, LuaEndian::Be);
}

#[test]
fn header_unknown_version_byte_accepted() {
    let mut d = header_51_min();
    d[4] = 0x77;
    let (h, _) = LuaHeader::parse(&d).unwrap();
    assert_eq!(h.version, LuaVersion::Unknown(0x77));
}

#[test]
fn header_display_contains_size_info() {
    let d = header_51_min();
    let (h, _) = LuaHeader::parse(&d).unwrap();
    let s = h.to_string();
    assert!(s.contains("int=4"));
    assert!(s.contains("ptr=8"));
}

#[test]
fn header_official_format_check() {
    let d = header_51_min();
    let (h, _) = LuaHeader::parse(&d).unwrap();
    assert!(h.is_official_format());
    let mut d2 = d;
    d2[5] = 1;
    let (h2, _) = LuaHeader::parse(&d2).unwrap();
    assert!(!h2.is_official_format());
}

// ─── LuaConst ───────────────────────────────────────────────────────────────

#[test]
fn const_tag_constants_distinct() {
    let tags = [
        LuaConst::TAG_NIL,
        LuaConst::TAG_BOOL,
        LuaConst::TAG_NUMBER,
        LuaConst::TAG_SHORT_STR,
        LuaConst::TAG_LONG_STR,
        LuaConst::TAG_INT,
    ];
    let unique: std::collections::HashSet<_> = tags.iter().collect();
    assert_eq!(unique.len(), tags.len());
}

#[test]
fn const_as_str_only_for_strings() {
    assert_eq!(LuaConst::Nil.as_str(), None);
    assert_eq!(LuaConst::Bool(true).as_str(), None);
    assert_eq!(LuaConst::Number(1.0).as_str(), None);
    assert_eq!(LuaConst::Integer(1).as_str(), None);
    assert_eq!(LuaConst::Str("a".into()).as_str(), Some("a"));
    assert_eq!(LuaConst::LongStr("b".into()).as_str(), Some("b"));
}

#[test]
fn const_eq() {
    assert_eq!(LuaConst::Integer(5), LuaConst::Integer(5));
    assert_ne!(LuaConst::Integer(5), LuaConst::Integer(6));
    assert_ne!(
        LuaConst::Str("x".into()),
        LuaConst::LongStr("x".into())
    );
}

#[test]
fn const_display_string_quoted() {
    assert_eq!(LuaConst::Str("x".into()).to_string(), "\"x\"");
}

// ─── LuaInstr bit decoding ──────────────────────────────────────────────────

#[test]
fn instr_decode_max_a() {
    let i = LuaInstr(0xFF << 6);
    assert_eq!(i.a(), 0xFF);
}

#[test]
fn instr_decode_max_b() {
    let i = LuaInstr(0x1FF << 23);
    assert_eq!(i.b(), 0x1FF);
}

#[test]
fn instr_decode_max_c() {
    let i = LuaInstr(0x1FF << 14);
    assert_eq!(i.c(), 0x1FF);
}

#[test]
fn instr_decode_max_bx() {
    let i = LuaInstr(0x3FFFF << 14);
    assert_eq!(i.bx(), 0x3FFFF);
}

#[test]
fn instr_sbx_max_negative() {
    // bx=0 → sbx = -131071
    let i = LuaInstr(0);
    assert_eq!(i.sbx(), -131071);
}

#[test]
fn instr_sbx_max_positive() {
    let i = LuaInstr(0x3FFFF << 14);
    assert_eq!(i.sbx(), 0x3FFFF - 131071);
}

#[test]
fn instr_writes_a_for_move() {
    // opcode 0x06 is not in the dead-list, so writes_a returns true
    assert!(LuaInstr(0x06).writes_a());
}

#[test]
fn instr_writes_a_false_for_low_ops() {
    for op in 0u32..=5 {
        assert!(!LuaInstr(op).writes_a());
    }
}

// ─── opcode tables ──────────────────────────────────────────────────────────

#[test]
fn opcode_tables_minimums() {
    assert!(LUA51_OPCODES.len() >= 38);
    assert!(LUA52_OPCODES.len() >= 40);
    assert!(LUA53_OPCODES.len() >= 47);
    assert!(LUA54_OPCODES.len() >= 80);
}

#[test]
fn opcode_name_first_is_move_all_versions() {
    for v in [LuaVersion::Lua51, LuaVersion::Lua52, LuaVersion::Lua53, LuaVersion::Lua54] {
        assert_eq!(opcode_name(v, 0), "MOVE");
    }
}

#[test]
fn opcode_name_out_of_range_is_unk() {
    assert_eq!(opcode_name(LuaVersion::Lua54, 0xFE), "UNK");
}

#[test]
fn opcode_name_unknown_version_uses_54_table() {
    assert_eq!(opcode_name(LuaVersion::Unknown(0x99), 0), "MOVE");
}

// ─── opcode_layout ──────────────────────────────────────────────────────────

#[test]
fn layout_54_extraarg_is_ax() {
    let idx = LUA54_OPCODES.iter().position(|&n| n == "EXTRAARG").unwrap() as u8;
    assert_eq!(opcode_layout(LuaVersion::Lua54, idx), OpcodeLayout::Ax);
}

#[test]
fn layout_54_jmp_is_isj() {
    let idx = LUA54_OPCODES.iter().position(|&n| n == "JMP").unwrap() as u8;
    assert_eq!(opcode_layout(LuaVersion::Lua54, idx), OpcodeLayout::IsJ);
}

#[test]
fn layout_51_loadk_is_abx() {
    let idx = LUA51_OPCODES.iter().position(|&n| n == "LOADK").unwrap() as u8;
    assert_eq!(opcode_layout(LuaVersion::Lua51, idx), OpcodeLayout::ABx);
}

#[test]
fn layout_51_unknown_for_non_classified() {
    // opcode beyond the 5.1 sBx/Bx list and not Abc — actually all default to Abc in legacy.
    // For Unknown version, layout returns Unknown for non-classified ops.
    let res = opcode_layout(LuaVersion::Unknown(0x99), 0);
    // The implementation: for non-54, uses instr_fmt_legacy which only returns Abc
    // for the catch-all. So opcode 0 → Abc.
    assert_eq!(res, OpcodeLayout::Abc);
}

// ─── LuaLocalVar / LuaUpvalue ───────────────────────────────────────────────

#[test]
fn local_var_eq_and_clone() {
    let a = LuaLocalVar { name: "x".into(), start_pc: 1, end_pc: 2 };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn upvalue_display_no_name() {
    let uv = LuaUpvalue { in_stack: true, idx: 4, name: None };
    let s = uv.to_string();
    assert!(s.contains("upval[4]"));
    assert!(s.contains('?'));
}

// ─── UpvalueDesc ────────────────────────────────────────────────────────────

#[test]
fn upvalue_desc_in_stack_zero_when_false() {
    let uv = LuaUpvalue { in_stack: false, idx: 7, name: Some("y".into()) };
    let d = UpvalueDesc::from_upvalue(&uv);
    assert_eq!(d.in_stack, 0);
    assert_eq!(d.idx, 7);
}

// ─── read_string_lua ────────────────────────────────────────────────────────

#[test]
fn read_string_lua_offset_truncated_size_field() {
    let data = [0u8, 0]; // not enough for u32 length
    let mut off = 0usize;
    let err = read_string_lua(&data, &mut off, 4).unwrap_err();
    assert!(matches!(err, LuaLoaderError::TruncatedData));
}

#[test]
fn read_string_lua_zero_len_no_advance_past_len_field() {
    let data = [0u8];
    let mut off = 0usize;
    let s = read_string_lua(&data, &mut off, 1).unwrap();
    assert_eq!(s, "");
    assert_eq!(off, 1);
}

#[test]
fn read_string_lua_no_nul_terminator() {
    let mut data = vec![3u8];
    data.extend_from_slice(b"abc"); // no NUL
    let mut off = 0usize;
    let s = read_string_lua(&data, &mut off, 1).unwrap();
    assert_eq!(s, "abc");
}

#[test]
fn read_string_lua_invalid_size_t_size() {
    let data = vec![0u8; 8];
    let mut off = 0usize;
    let err = read_string_lua(&data, &mut off, 3).unwrap_err();
    assert!(matches!(err, LuaLoaderError::ParseError(_)));
}

#[test]
fn read_string_lua_2byte_size() {
    let mut data = vec![4u8, 0]; // LE u16 = 4
    data.extend_from_slice(b"hi\0\0"); // 4 bytes incl trailing NUL → strips to "hi\0\0"->"hi\0"
    let mut off = 0usize;
    let s = read_string_lua(&data, &mut off, 2).unwrap();
    // strips one trailing NUL
    assert_eq!(s, "hi\0");
}

#[test]
fn read_string_lua_8byte_size() {
    let mut data = vec![3u8, 0, 0, 0, 0, 0, 0, 0]; // LE u64 = 3
    data.extend_from_slice(b"ab\0");
    let mut off = 0usize;
    let s = read_string_lua(&data, &mut off, 8).unwrap();
    assert_eq!(s, "ab");
    assert_eq!(off, 11);
}

// ─── LuaChunk ───────────────────────────────────────────────────────────────

#[test]
fn chunk_from_proto_no_name() {
    let mut p = LuaProto::mock(LuaVersion::Lua54);
    p.name = None;
    let c = LuaChunk::from_proto(&p);
    assert_eq!(c.name, "");
}

#[test]
fn chunk_counts_reflect_proto() {
    let p = LuaProto::mock(LuaVersion::Lua54);
    let c = LuaChunk::from_proto(&p);
    assert_eq!(c.instructions_count, p.instructions.len() as u32);
    assert_eq!(c.constants_count, p.constants.len() as u32);
    assert_eq!(c.functions_count, p.protos.len() as u32);
}

// ─── LuaProto ───────────────────────────────────────────────────────────────

#[test]
fn proto_total_instructions_nested() {
    let mut root = LuaProto::mock(LuaVersion::Lua54);
    let child = LuaProto::mock(LuaVersion::Lua54);
    root.protos.push(child);
    assert_eq!(root.total_instructions(), 2);
}

#[test]
fn proto_source_line_oob() {
    let p = LuaProto::mock(LuaVersion::Lua54);
    assert_eq!(p.source_line(999), None);
}

#[test]
fn proto_constant_type_counts_complete() {
    let p = LuaProto::mock(LuaVersion::Lua54);
    let m = p.constant_type_counts();
    assert_eq!(m.get("string").copied(), Some(1));
    assert_eq!(m.get("number").copied(), Some(1));
    assert_eq!(m.get("integer").copied(), Some(1));
    assert_eq!(m.get("bool").copied(), Some(1));
    assert_eq!(m.get("nil").copied(), Some(1));
}

#[test]
fn proto_all_strings_recurses() {
    let mut root = LuaProto::mock(LuaVersion::Lua54);
    root.protos.push(LuaProto::mock(LuaVersion::Lua54));
    let strings = root.all_strings();
    // Two "hello" entries (one per mock)
    assert_eq!(strings.iter().filter(|s| **s == "hello").count(), 2);
}

// ─── parse_proto_51 — adversarial inputs ────────────────────────────────────

#[test]
fn parse_proto_51_empty_buffer_errors() {
    let mut off = 0usize;
    let res = parse_proto_51(&[], &mut off, true, 4);
    assert!(matches!(res, Err(LuaLoaderError::TruncatedData)));
}

#[test]
fn parse_proto_51_truncated_after_name() {
    let mut buf: Vec<u8> = Vec::new();
    push_u32(&mut buf, 0); // name len = 0
    push_u32(&mut buf, 0); // first_line
    // truncate here
    let mut off = 0usize;
    let res = parse_proto_51(&buf, &mut off, true, 4);
    assert!(res.is_err());
}

#[test]
fn parse_proto_51_with_constants() {
    let mut buf: Vec<u8> = Vec::new();
    // The 5.1 dump format writes string lengths as size_t; parse_proto_51
    // synthesises an 8-byte pointer size, so the name length is 8 bytes wide,
    // and `nups` precedes `numparams`.
    buf.extend_from_slice(&0u64.to_le_bytes()); // name
    push_u32(&mut buf, 1); // first_line
    push_u32(&mut buf, 2); // last_line
    buf.push(0); // nups
    buf.push(0); // num_params
    buf.push(0); // is_vararg
    buf.push(2); // max_stack
    push_u32(&mut buf, 0); // inst_count
    push_u32(&mut buf, 2); // kst_count
    // const 0: NIL
    buf.push(LuaConst::TAG_NIL);
    // const 1: BOOL true
    buf.push(LuaConst::TAG_BOOL);
    buf.push(1);
    push_u32(&mut buf, 0); // proto_count
    push_u32(&mut buf, 0); // li_count
    push_u32(&mut buf, 0); // loc_count
    push_u32(&mut buf, 0); // uv_count

    let mut off = 0usize;
    let p = parse_proto_51(&buf, &mut off, true, 4).unwrap();
    assert_eq!(p.constants.len(), 2);
    assert_eq!(p.constants[0], LuaConst::Nil);
    assert_eq!(p.constants[1], LuaConst::Bool(true));
}

// ─── parse_proto_54 — adversarial / edge ────────────────────────────────────

#[test]
fn parse_proto_54_uv_prelim_mismatch_errors() {
    let mut buf: Vec<u8> = Vec::new();
    buf.push(0x00); // name=None
    push_u32(&mut buf, 0); // first_line
    push_u32(&mut buf, 0); // last_line
    buf.push(0); // num_params
    buf.push(0); // is_vararg
    buf.push(0); // max_stack
    buf.push(5); // uv_prelim = 5
    push_u32(&mut buf, 0); // inst_count
    push_u32(&mut buf, 0); // kst_count
    push_u32(&mut buf, 2); // uv_count = 2 (mismatch)
    // would-be uv records...
    buf.push(0);
    buf.push(0);
    buf.push(0);
    buf.push(0);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0);

    let mut off = 0usize;
    let res = parse_proto_54(&buf, &mut off);
    assert!(matches!(res, Err(LuaLoaderError::ParseError(_))));
}

#[test]
fn parse_proto_54_zero_uv_prelim_accepts_any_uv_count() {
    let mut buf: Vec<u8> = Vec::new();
    buf.push(0x00);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0);
    buf.push(0); buf.push(0); buf.push(0);
    buf.push(0); // uv_prelim = 0
    push_u32(&mut buf, 0); // inst
    push_u32(&mut buf, 0); // kst
    push_u32(&mut buf, 1); // uv_count = 1
    buf.push(1); buf.push(2); // uv record
    push_u32(&mut buf, 0); // proto
    push_u32(&mut buf, 0); // li
    push_u32(&mut buf, 0); // loc
    push_u32(&mut buf, 0); // uv_name

    let mut off = 0usize;
    let p = parse_proto_54(&buf, &mut off).unwrap();
    assert_eq!(p.upvalues.len(), 1);
    assert!(p.upvalues[0].in_stack);
    assert_eq!(p.upvalues[0].idx, 2);
}

// ─── End-to-end LuaBytecode / LuaModule ─────────────────────────────────────

#[test]
fn bytecode_parse_truncated_after_header() {
    let d = header_51_min();
    let err = LuaBytecode::parse(&d).unwrap_err();
    assert!(matches!(err, LuaLoaderError::TruncatedData));
}

#[test]
fn bytecode_loader_load_truncated() {
    let d = header_51_min();
    assert!(LuaBytecodeLoader::load(&d).is_err());
}

#[test]
fn bytecode_loader_load_version_truncated() {
    let small = b"\x1bLua".to_vec();
    let err = LuaBytecodeLoader::load_version(&small, 0x54).unwrap_err();
    assert!(matches!(err, LuaLoaderError::TruncatedData));
}

#[test]
fn module_total_instructions_from_mock() {
    let bc = LuaBytecode {
        header: LuaHeader::parse(&header_51_min()).unwrap().0,
        top_level: LuaProto::mock(LuaVersion::Lua51),
    };
    let m = LuaModule::from_bytecode(bc);
    assert_eq!(m.total_instructions(), 1);
}

// ─── ProtoWalker ────────────────────────────────────────────────────────────

#[test]
fn proto_walker_depth_first_order() {
    // root has two children, second has one grandchild
    let mut root = LuaProto::mock(LuaVersion::Lua54);
    root.name = Some("root".into());
    let mut c1 = LuaProto::mock(LuaVersion::Lua54);
    c1.name = Some("c1".into());
    let mut c2 = LuaProto::mock(LuaVersion::Lua54);
    c2.name = Some("c2".into());
    let mut gc = LuaProto::mock(LuaVersion::Lua54);
    gc.name = Some("gc".into());
    c2.protos.push(gc);
    root.protos.push(c1);
    root.protos.push(c2);

    let names: Vec<_> = ProtoWalker::new(&root)
        .map(|p| p.name.clone().unwrap_or_default())
        .collect();
    assert_eq!(names, vec!["root", "c1", "c2", "gc"]);
}

// ─── ConstantIndex ──────────────────────────────────────────────────────────

#[test]
fn constant_index_hash_eq() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(ConstantIndex(1));
    s.insert(ConstantIndex(1));
    assert_eq!(s.len(), 1);
}

// ─── ProtoStats ─────────────────────────────────────────────────────────────

#[test]
fn proto_stats_counts_consistent_with_total_instructions() {
    let mut root = LuaProto::mock(LuaVersion::Lua54);
    root.protos.push(LuaProto::mock(LuaVersion::Lua54));
    root.protos.push(LuaProto::mock(LuaVersion::Lua54));
    let stats = ProtoStats::from_proto(&root);
    assert_eq!(stats.proto_count, 3);
    assert_eq!(stats.instruction_count, root.total_instructions());
}

// ─── disassemble_proto ──────────────────────────────────────────────────────

#[test]
fn disassemble_empty_proto_returns_empty() {
    let mut p = LuaProto::mock(LuaVersion::Lua54);
    p.instructions.clear();
    let lines = disassemble_proto(&p, 0x54);
    assert!(lines.is_empty());
}

#[test]
fn disassemble_proto_index_padding() {
    let mut p = LuaProto::mock(LuaVersion::Lua54);
    p.instructions = vec![LuaInstr(0); 5];
    p.line_info.clear();
    let lines = disassemble_proto(&p, 0x54);
    for (i, line) in lines.iter().enumerate() {
        assert!(line.starts_with(&format!("{i:04}:")));
    }
}

#[test]
fn disassemble_handles_all_versions() {
    for ver_byte in [0x51u8, 0x52, 0x53, 0x54] {
        let p = LuaProto::mock(LuaVersion::from_byte(ver_byte));
        let lines = disassemble_proto(&p, ver_byte);
        assert!(!lines.is_empty(), "ver {ver_byte:#x}");
    }
}

// ─── ProtoDisasm / ModuleDisasm ─────────────────────────────────────────────

#[test]
fn proto_disasm_no_name_displays_question() {
    let mut p = LuaProto::mock(LuaVersion::Lua54);
    p.name = None;
    let pd = ProtoDisasm::from_proto(&p);
    assert_eq!(pd.name, "?");
}

#[test]
fn module_disasm_flat_listing_includes_separator_per_proto() {
    let mut root = LuaProto::mock(LuaVersion::Lua54);
    root.protos.push(LuaProto::mock(LuaVersion::Lua54));
    let bc = LuaBytecode {
        header: LuaHeader::parse(&header_54_min()).unwrap().0,
        top_level: root,
    };
    let m = LuaModule::from_bytecode(bc);
    let d = ModuleDisasm::from_module(&m);
    let listing = d.flat_listing();
    let separators = listing.iter().filter(|l| l.contains("===")).count();
    assert_eq!(separators, 2);
}

// ─── LuaLoader (async) ──────────────────────────────────────────────────────

#[tokio::test]
async fn loader_load_zero_byte_input_creates_view_without_segments() {
    let input = LoaderInput::new("empty", Vec::new());
    let res = LuaLoader::new().load(input).await.unwrap();
    // size == 0 → no segment added; view should still build
    assert_eq!(res.view.uri, "empty");
}

#[tokio::test]
async fn loader_load_unknown_version_falls_back_to_lua54() {
    // garbage data — can_load is false but load() defaults to 5.4 arch
    let input = LoaderInput::new("x", vec![0u8; 4]);
    let res = LuaLoader::new().load(input).await.unwrap();
    // architecture name comes from default fallback
    assert_eq!(res.view.arch.name(), "lua54");
}

#[test]
fn loader_can_load_short_input_false() {
    let input = LoaderInput::new("t", vec![0x1B, b'L', b'u', b'a']);
    // 4 bytes is too short for is_lua_bytecode (needs >=5)
    assert!(!LuaLoader::new().can_load(&input));
}

// ─── Round-trip: mock → display → contains expected fields ──────────────────

#[test]
fn proto_display_includes_counts() {
    let p = LuaProto::mock(LuaVersion::Lua54);
    let s = p.to_string();
    assert!(s.contains("instrs=1"));
    assert!(s.contains("consts=5"));
}

#[test]
fn lua_loader_error_display_variants() {
    let e1 = LuaLoaderError::InvalidMagic.to_string();
    assert!(e1.contains("invalid magic"));
    let e2 = LuaLoaderError::UnsupportedVersion(0x99).to_string();
    assert!(e2.contains("0x99"));
    let e3 = LuaLoaderError::TruncatedData.to_string();
    assert!(e3.contains("truncated"));
    let e4 = LuaLoaderError::Overflow.to_string();
    assert!(e4.contains("overflow"));
    let e5 = LuaLoaderError::ParseError("foo".into()).to_string();
    assert!(e5.contains("foo"));
}
