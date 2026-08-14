//! Blitz test suite for rustre-arch-lua: surfaces bugs in public API.

use rustre_arch_lua::*;
use rustre_core::arch::Architecture;
use rustre_core::address::Address;

// ---------- LuaVersion ----------

#[test]
fn version_default_is_lua54() {
    assert_eq!(LuaVersion::default(), LuaVersion::Lua54);
}

#[test]
fn version_names() {
    assert_eq!(LuaVersion::Lua51.name(), "lua51");
    assert_eq!(LuaVersion::Lua52.name(), "lua52");
    assert_eq!(LuaVersion::Lua53.name(), "lua53");
    assert_eq!(LuaVersion::Lua54.name(), "lua54");
}

#[test]
fn version_strings() {
    assert_eq!(LuaVersion::Lua51.version_string(), "Lua 5.1");
    assert_eq!(LuaVersion::Lua54.version_string(), "Lua 5.4");
}

#[test]
fn version_is_legacy() {
    assert!(LuaVersion::Lua51.is_legacy());
    assert!(LuaVersion::Lua52.is_legacy());
    assert!(LuaVersion::Lua53.is_legacy());
    assert!(!LuaVersion::Lua54.is_legacy());
}

#[test]
fn version_display_matches_version_string() {
    assert_eq!(format!("{}", LuaVersion::Lua53), "Lua 5.3");
}

// ---------- field extractors (Lua 5.4 builders/round-trips) ----------

#[test]
fn make_iabc_round_trip() {
    // op=32 ADD, A=5, B=6, C=7, k=1
    let w = make_iabc(32, 5, 6, 7, 1);
    assert_eq!(w & 0x7f, 32);
    assert_eq!((w >> 7) & 0xff, 5);
    assert_eq!((w >> 15) & 1, 1);
    assert_eq!((w >> 16) & 0xff, 6);
    assert_eq!((w >> 24) & 0xff, 7);
}

#[test]
fn make_iabx_round_trip() {
    let w = make_iabx(3, 10, 12345);
    assert_eq!(w & 0x7f, 3);
    assert_eq!((w >> 7) & 0xff, 10);
    assert_eq!(get_bx54(w), 12345);
}

#[test]
fn make_iasbx_zero() {
    let w = make_iasbx(1, 4, 0);
    assert_eq!(w & 0x7f, 1);
    // sbx=0 means bx = MAXARG_SBX
    assert_eq!(get_bx54(w), MAXARG_SBX as u32);
}

#[test]
fn make_iasbx_max() {
    let w = make_iasbx(1, 0, MAXARG_SBX);
    assert_eq!(get_bx54(w), (MAXARG_SBX * 2) as u32);
}

#[test]
fn make_iasbx_min() {
    let w = make_iasbx(1, 0, -MAXARG_SBX);
    assert_eq!(get_bx54(w), 0);
}

#[test]
fn make_iasbx_out_of_range_panics() {
    // The function documents that sbx outside [-MAXARG_SBX, MAXARG_SBX] panics.
    // Verify the bounds check actually fires (else silent overflow would be a bug).
    let r = std::panic::catch_unwind(|| make_iasbx(1, 0, MAXARG_SBX + 1));
    assert!(r.is_err(), "expected panic on out-of-range sbx");
}

#[test]
fn make_iax_round_trip() {
    let w = make_iax(80, 0x1_2345);
    assert_eq!(w & 0x7f, 80);
    assert_eq!(get_ax54(w), 0x1_2345);
}

#[test]
fn make_isj_round_trip_zero() {
    let w = make_isj(54, 0);
    assert_eq!(w & 0x7f, 54);
}

#[test]
fn make_isj_positive_offset() {
    let w = make_isj(54, 100);
    // get_sj54 is pub(crate), so we infer via disassembly.
    let arch = LuaArch::new();
    let i = arch.disassemble(Address::new(0), &w.to_le_bytes()).unwrap();
    assert!(i.operands.contains("100") || i.operands.contains("+100"));
}

#[test]
fn make_legacy_iabc_layout() {
    // Layout per get_a/b/c_old
    let w = make_legacy_iabc(12, 5, 6, 7);
    assert_eq!(w & 0x3f, 12);
    assert_eq!((w >> 6) & 0xff, 5);
    assert_eq!((w >> 14) & 0x1ff, 7); // C
    assert_eq!((w >> 23) & 0x1ff, 6); // B
}

#[test]
fn make_legacy_iabx_layout() {
    let w = make_legacy_iabx(1, 5, 200000);
    assert_eq!(w & 0x3f, 1);
    assert_eq!((w >> 6) & 0xff, 5);
    assert_eq!(w >> 14, 200000);
}

#[test]
fn make_legacy_iasbx_round_trip() {
    let w = make_legacy_iasbx(22, 0, 50);
    assert_eq!(w & 0x3f, 22);
    // Decode via Lua 5.1
    let arch = LuaArch::with_version(LuaVersion::Lua51);
    let i = arch.disassemble(Address::new(0), &w.to_le_bytes()).unwrap();
    assert_eq!(i.mnemonic, "jmp");
}

// ---------- opcode_name ----------

#[test]
fn opcode_name_lua54_move() {
    assert_eq!(opcode_name(LuaVersion::Lua54, 0), Some("MOVE"));
}

#[test]
fn opcode_name_out_of_range() {
    assert_eq!(opcode_name(LuaVersion::Lua51, 200), None);
    assert_eq!(opcode_name(LuaVersion::Lua54, 200), None);
}

#[test]
fn opcode_name_lua51_return() {
    assert_eq!(opcode_name(LuaVersion::Lua51, 30), Some("RETURN"));
}

// ---------- find_opcodes ----------

#[test]
fn find_opcodes_jmp_lua54() {
    let v = find_opcodes(LuaVersion::Lua54, "JMP");
    assert!(v.iter().any(|(i, _)| *i == 54));
}

#[test]
fn find_opcodes_case_insensitive() {
    let v = find_opcodes(LuaVersion::Lua54, "move");
    assert!(v.iter().any(|(_, name)| *name == "MOVE"));
}

#[test]
fn find_opcodes_empty_needle_returns_all() {
    let v = find_opcodes(LuaVersion::Lua54, "");
    assert_eq!(v.len(), 81);
}

#[test]
fn find_opcodes_nomatch() {
    let v = find_opcodes(LuaVersion::Lua54, "ZZZNOPE");
    assert!(v.is_empty());
}

// ---------- is_branch / is_call / is_return ----------

#[test]
fn is_branch_lua54_jmp() {
    assert!(is_branch_opcode(LuaVersion::Lua54, 54)); // JMP
    assert!(is_branch_opcode(LuaVersion::Lua54, 55)); // EQ
    assert!(!is_branch_opcode(LuaVersion::Lua54, 0));  // MOVE
}

#[test]
fn is_call_lua54() {
    assert!(is_call_opcode(LuaVersion::Lua54, 66)); // CALL
    assert!(is_call_opcode(LuaVersion::Lua54, 67)); // TAILCALL
    assert!(!is_call_opcode(LuaVersion::Lua54, 68));
}

#[test]
fn is_return_lua54() {
    assert!(is_return_opcode(LuaVersion::Lua54, 68));
    assert!(is_return_opcode(LuaVersion::Lua54, 69));
    assert!(is_return_opcode(LuaVersion::Lua54, 70));
    assert!(!is_return_opcode(LuaVersion::Lua54, 67));
}

#[test]
fn is_return_lua51() {
    assert!(is_return_opcode(LuaVersion::Lua51, 30));
    assert!(!is_return_opcode(LuaVersion::Lua51, 29));
}

// ---------- parse_chunk_header ----------

#[test]
fn header_too_short() {
    assert_eq!(
        parse_chunk_header(&[0x1b, b'L', b'u']),
        Err(ChunkHeaderError::TooShort)
    );
}

#[test]
fn header_too_short_empty() {
    assert_eq!(parse_chunk_header(&[]), Err(ChunkHeaderError::TooShort));
}

#[test]
fn header_bad_magic() {
    let data = [0x00, b'X', b'X', b'X', 0x54, 0, 0, 0];
    assert_eq!(parse_chunk_header(&data), Err(ChunkHeaderError::BadMagic));
}

#[test]
fn header_unsupported_version() {
    let data = [0x1b, b'L', b'u', b'a', 0x99, 1, 4, 4];
    assert_eq!(
        parse_chunk_header(&data),
        Err(ChunkHeaderError::UnsupportedVersion(0x99))
    );
}

#[test]
fn header_parses_lua54() {
    let data = [0x1b, b'L', b'u', b'a', 0x54, 1, 4, 8, 4];
    let h = parse_chunk_header(&data).unwrap();
    assert_eq!(h.version, LuaVersion::Lua54);
    assert_eq!(h.endian, 1);
    assert_eq!(h.int_size, 4);
    assert_eq!(h.size_t_size, 8);
    assert_eq!(h.instr_size, 4);
}

#[test]
fn header_default_instr_size_when_missing() {
    let data = [0x1b, b'L', b'u', b'a', 0x51, 1, 4, 8];
    let h = parse_chunk_header(&data).unwrap();
    assert_eq!(h.instr_size, 4);
    assert_eq!(h.version, LuaVersion::Lua51);
}

#[test]
fn header_error_display() {
    let s = format!("{}", ChunkHeaderError::TooShort);
    assert!(s.contains("too short"));
    let s = format!("{}", ChunkHeaderError::BadMagic);
    assert!(s.contains("bad magic") || s.contains("Lua"));
    let s = format!("{}", ChunkHeaderError::UnsupportedVersion(0xAB));
    assert!(s.contains("0xab"));
}

// ---------- LuaArch / Architecture ----------

#[test]
fn arch_name_per_version() {
    assert_eq!(LuaArch::with_version(LuaVersion::Lua51).name(), "lua51");
    assert_eq!(LuaArch::new().name(), "lua54");
}

#[test]
fn arch_disassemble_short_input_errors() {
    let a = LuaArch::new();
    assert!(a.disassemble(Address::new(0), &[0u8, 0, 0]).is_err());
}

#[test]
fn arch_disassemble_unknown_opcode_lua51() {
    // op=63 is out of range for lua51 (max=37)
    let w: u32 = 63;
    let a = LuaArch::with_version(LuaVersion::Lua51);
    assert!(a.disassemble(Address::new(0), &w.to_le_bytes()).is_err());
}

#[test]
fn arch_metadata_lua54() {
    let m = LuaArch::new().metadata();
    assert_eq!(m.opcode_bits, 7);
    assert_eq!(m.opcode_count, 81);
    assert_eq!(m.instr_width, 4);
    assert_eq!(m.version, "5.4");
}

#[test]
fn arch_metadata_lua51() {
    let m = LuaArch::with_version(LuaVersion::Lua51).metadata();
    assert_eq!(m.opcode_bits, 6);
    assert_eq!(m.opcode_count, 38);
}

#[test]
fn arch_pointer_alignment() {
    let a = LuaArch::new();
    assert_eq!(a.pointer_size(), 8);
    assert_eq!(a.instruction_alignment(), 4);
    assert_eq!(a.max_instruction_length(), 4);
}

#[test]
fn arch_registers_count() {
    let regs = LuaArch::new().registers();
    assert_eq!(regs.len(), 16);
}

#[test]
fn arch_calling_conv_present() {
    let cc = LuaArch::new().calling_conventions();
    assert_eq!(cc.len(), 1);
}

// ---------- decode dedicated functions ----------

#[test]
fn decode_lua51_unknown_opcode_errs() {
    let w: u32 = 50; // > 37
    assert!(decode_lua51(w, Address::new(0)).is_err());
}

#[test]
fn decode_lua52_unknown_opcode_errs() {
    let w: u32 = 60;
    assert!(decode_lua52(w, Address::new(0)).is_err());
}

#[test]
fn decode_lua53_unknown_opcode_errs() {
    let w: u32 = 60;
    assert!(decode_lua53(w, Address::new(0)).is_err());
}

#[test]
fn decode_by_version_routes_correctly() {
    let w = make_iabc(0, 0, 1, 0, 0); // MOVE
    let (m, _, _) = decode_by_version(LuaVersion::Lua54, w, Address::new(0)).unwrap();
    assert_eq!(m, "move");
}

#[test]
fn decode_lua51_move() {
    let w = make_legacy_iabc(0, 1, 2, 0);
    let (m, ops, _) = decode_lua51(w, Address::new(0)).unwrap();
    assert_eq!(m, "move");
    assert!(ops.contains("R1"));
}

// ---------- is_legacy_jump_op ----------

#[test]
fn is_legacy_jump_op_lua51_jmp() {
    assert!(is_legacy_jump_op(LuaVersion::Lua51, 22)); // JMP
}

#[test]
fn is_legacy_jump_op_lua54_returns_false() {
    // 5.4 isn't legacy; per docs should be false regardless.
    assert!(!is_legacy_jump_op(LuaVersion::Lua54, 54));
}

// ---------- disassemble_chunk ----------

#[test]
fn disassemble_chunk_empty() {
    let a = LuaArch::new();
    let r = disassemble_chunk(&a, Address::new(0), &[]);
    assert!(r.is_empty());
}

#[test]
fn disassemble_chunk_partial_word_dropped() {
    let a = LuaArch::new();
    // 5 bytes -> one decode of bytes[0..4], remainder dropped.
    let r = disassemble_chunk(&a, Address::new(0), &[0, 0, 0, 0, 0xff]);
    assert_eq!(r.len(), 1);
}

#[test]
fn disassemble_chunk_addresses_advance_by_4() {
    let a = LuaArch::new();
    let mut bytes = Vec::new();
    for _ in 0..3 {
        bytes.extend_from_slice(&make_iabc(0, 0, 1, 0, 0).to_le_bytes());
    }
    let r = disassemble_chunk(&a, Address::new(0x1000), &bytes);
    let ok: Vec<_> = r.into_iter().filter_map(std::result::Result::ok).collect();
    assert_eq!(ok.len(), 3);
    assert_eq!(ok[0].address.as_u64(), 0x1000);
    assert_eq!(ok[1].address.as_u64(), 0x1004);
    assert_eq!(ok[2].address.as_u64(), 0x1008);
}

#[test]
fn disassemble_chunk_lossy_skips_errors() {
    let a = LuaArch::with_version(LuaVersion::Lua51);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&make_legacy_iabc(0, 0, 1, 0).to_le_bytes()); // ok MOVE
    bytes.extend_from_slice(&63u32.to_le_bytes()); // bad opcode
    let r = disassemble_chunk_lossy(&a, Address::new(0), &bytes);
    assert_eq!(r.len(), 1);
}

// ---------- format_instruction / listing ----------

#[test]
fn format_instruction_contains_addr() {
    let a = LuaArch::new();
    let bytes = make_iabc(0, 1, 2, 0, 0).to_le_bytes();
    let i = a.disassemble(Address::new(0x42), &bytes).unwrap();
    let s = format_instruction(&i);
    assert!(s.contains("0x00000042"));
    assert!(s.contains("move"));
}

#[test]
fn format_listing_joins_newlines() {
    let a = LuaArch::new();
    let bytes = make_iabc(0, 0, 1, 0, 0).to_le_bytes();
    let i = a.disassemble(Address::new(0), &bytes).unwrap();
    let s = format_listing(&[i.clone(), i]);
    assert_eq!(s.matches('\n').count(), 1);
}

// ---------- LuaChunkStats ----------

#[test]
fn stats_empty() {
    let s = LuaChunkStats::from_instructions(LuaVersion::Lua54, &[]);
    assert_eq!(s.total, 0);
    assert_eq!(s.branch_ratio(), 0.0);
}

#[test]
fn stats_basic_counts() {
    let a = LuaArch::new();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&make_iabc(32, 0, 1, 2, 0).to_le_bytes()); // ADD
    bytes.extend_from_slice(&make_iabc(66, 0, 1, 1, 0).to_le_bytes()); // CALL
    bytes.extend_from_slice(&make_iabc(68, 0, 1, 1, 0).to_le_bytes()); // RETURN
    let v = disassemble_chunk_lossy(&a, Address::new(0), &bytes);
    let s = LuaChunkStats::from_instructions(LuaVersion::Lua54, &v);
    assert_eq!(s.total, 3);
    assert_eq!(s.arithmetic, 1);
    assert_eq!(s.calls, 1);
    assert_eq!(s.returns, 1);
}

#[test]
fn stats_display() {
    let s = LuaChunkStats::default();
    let f = format!("{s}");
    assert!(f.contains("total=0"));
}

// ---------- split_basic_blocks ----------

#[test]
fn split_blocks_empty() {
    let a = LuaArch::new();
    let v = split_basic_blocks(&a, &[]);
    assert!(v.is_empty());
}

#[test]
fn split_blocks_single() {
    let a = LuaArch::new();
    let bytes = make_iabc(0, 0, 1, 0, 0).to_le_bytes();
    let i = a.disassemble(Address::new(0), &bytes).unwrap();
    let v = split_basic_blocks(&a, &[i]);
    assert_eq!(v.len(), 1);
}

// ---------- LuaConst ----------

#[test]
fn const_type_names() {
    assert_eq!(LuaConst::Nil.type_name(), "nil");
    assert_eq!(LuaConst::Bool(true).type_name(), "boolean");
    assert_eq!(LuaConst::Int(0).type_name(), "integer");
    assert_eq!(LuaConst::Float(0.0).type_name(), "float");
    assert_eq!(LuaConst::String(String::new()).type_name(), "string");
}

#[test]
fn const_accessors() {
    assert!(LuaConst::Nil.is_nil());
    assert_eq!(LuaConst::Bool(true).as_bool(), Some(true));
    assert_eq!(LuaConst::Int(7).as_int(), Some(7));
    assert_eq!(LuaConst::Float(1.5).as_float(), Some(1.5));
    assert_eq!(LuaConst::String("hi".into()).as_str(), Some("hi"));
    assert_eq!(LuaConst::Nil.as_int(), None);
    assert_eq!(LuaConst::Int(1).as_bool(), None);
}

#[test]
fn const_display_string_uses_debug_quotes() {
    let s = format!("{}", LuaConst::String("hi".into()));
    assert_eq!(s, "\"hi\"");
}

#[test]
fn const_display_nil() {
    assert_eq!(format!("{}", LuaConst::Nil), "nil");
}

// ---------- extract_constants_from_proto ----------

#[test]
fn extract_constants_empty() {
    let v = extract_constants_from_proto(&[], LuaVersion::Lua54);
    assert!(v.is_empty());
}

#[test]
fn extract_constants_loadk_lua54() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&make_iabx(3, 0, 5).to_le_bytes()); // LOADK Bx=5
    bytes.extend_from_slice(&make_iabx(3, 0, 3).to_le_bytes()); // LOADK Bx=3
    bytes.extend_from_slice(&make_iabx(3, 0, 5).to_le_bytes()); // dup
    let v = extract_constants_from_proto(&bytes, LuaVersion::Lua54);
    assert_eq!(v.len(), 2); // unique
}

#[test]
fn extract_constants_loadk_lua51() {
    let bytes = make_legacy_iabx(1, 0, 7).to_le_bytes(); // LOADK Bx=7
    let v = extract_constants_from_proto(&bytes, LuaVersion::Lua51);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0], LuaConst::Int(7));
}

// ---------- parse_const_pool_51 ----------

#[test]
fn const_pool_51_empty() {
    let data = 0i32.to_le_bytes();
    let v = parse_const_pool_51(&data).unwrap();
    assert!(v.is_empty());
}

#[test]
fn const_pool_51_nil_bool() {
    let mut data = Vec::new();
    data.extend_from_slice(&2i32.to_le_bytes());
    data.push(0); // nil
    data.push(1); // bool
    data.push(1); // true
    let v = parse_const_pool_51(&data).unwrap();
    assert_eq!(v, vec![LuaConst::Nil, LuaConst::Bool(true)]);
}

#[test]
fn const_pool_51_float() {
    let mut data = Vec::new();
    data.extend_from_slice(&1i32.to_le_bytes());
    data.push(3);
    data.extend_from_slice(&3.5f64.to_le_bytes());
    let v = parse_const_pool_51(&data).unwrap();
    assert_eq!(v, vec![LuaConst::Float(3.5)]);
}

#[test]
fn const_pool_51_string() {
    let mut data = Vec::new();
    data.extend_from_slice(&1i32.to_le_bytes());
    data.push(4);
    data.extend_from_slice(&3i32.to_le_bytes()); // length includes NUL
    data.extend_from_slice(b"hi\0");
    let v = parse_const_pool_51(&data).unwrap();
    assert_eq!(v, vec![LuaConst::String("hi".into())]);
}

#[test]
fn const_pool_51_truncated_returns_none() {
    let data = [1i32.to_le_bytes()[0], 0, 0, 0]; // count=1 then nothing
    assert!(parse_const_pool_51(&data).is_none());
}

#[test]
fn const_pool_51_unknown_type_returns_none() {
    let mut data = Vec::new();
    data.extend_from_slice(&1i32.to_le_bytes());
    data.push(99); // unknown type
    assert!(parse_const_pool_51(&data).is_none());
}

// ---------- parse_const_pool_53 ----------

#[test]
fn const_pool_53_integer() {
    let mut data = Vec::new();
    data.extend_from_slice(&1i32.to_le_bytes());
    data.push(0x13);
    data.extend_from_slice(&42i64.to_le_bytes());
    let v = parse_const_pool_53(&data).unwrap();
    assert_eq!(v, vec![LuaConst::Int(42)]);
}

#[test]
fn const_pool_53_bool_variants() {
    let mut data = Vec::new();
    data.extend_from_slice(&2i32.to_le_bytes());
    data.push(0x01);
    data.push(0x11);
    let v = parse_const_pool_53(&data).unwrap();
    assert_eq!(v, vec![LuaConst::Bool(false), LuaConst::Bool(true)]);
}

#[test]
fn const_pool_53_short_string() {
    let mut data = Vec::new();
    data.extend_from_slice(&1i32.to_le_bytes());
    data.push(0x04);
    data.push(3); // length byte (includes NUL)
    data.extend_from_slice(b"hi\0");
    let v = parse_const_pool_53(&data).unwrap();
    assert_eq!(v, vec![LuaConst::String("hi".into())]);
}

#[test]
fn const_pool_53_nil() {
    let mut data = Vec::new();
    data.extend_from_slice(&1i32.to_le_bytes());
    data.push(0x00);
    let v = parse_const_pool_53(&data).unwrap();
    assert_eq!(v, vec![LuaConst::Nil]);
}

#[test]
fn const_pool_53_unknown_type_none() {
    let mut data = Vec::new();
    data.extend_from_slice(&1i32.to_le_bytes());
    data.push(0x77);
    assert!(parse_const_pool_53(&data).is_none());
}

// ---------- debug-info generators ----------

#[test]
fn generate_local_var_names_min_is_one() {
    let v = generate_local_var_names(0);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0], "local_0");
}

#[test]
fn generate_local_var_names_capped_64() {
    let v = generate_local_var_names(10_000);
    assert_eq!(v.len(), 64);
}

#[test]
fn generate_upvalue_names_zero() {
    assert!(generate_upvalue_names(0).is_empty());
}

#[test]
fn generate_upvalue_names_three() {
    let v = generate_upvalue_names(3);
    assert_eq!(v, vec!["upval_0", "upval_1", "upval_2"]);
}

#[test]
fn generate_param_names_no_self() {
    let v = generate_param_names(2, false);
    assert_eq!(v, vec!["arg1", "arg2"]);
}

#[test]
fn generate_param_names_with_self() {
    let v = generate_param_names(2, true);
    assert_eq!(v, vec!["self", "arg1"]);
}

#[test]
fn generate_param_names_zero() {
    let v = generate_param_names(0, false);
    assert!(v.is_empty());
}

#[test]
fn generate_param_names_self_only() {
    let v = generate_param_names(1, true);
    assert_eq!(v, vec!["self"]);
}

// ---------- LuaProtoInfo ----------

#[test]
fn proto_info_new_is_empty() {
    let p = LuaProtoInfo::new(LuaVersion::Lua54, vec![]);
    assert!(p.is_empty());
    assert_eq!(p.version, LuaVersion::Lua54);
}

// ---------- classify_opcode / OpcodeCategory ----------

#[test]
fn classify_known_opcodes() {
    // Existence: just call it on common mnemonics and ensure non-panicking.
    let _ = classify_opcode("ADD");
    let _ = classify_opcode("MOVE");
    let _ = classify_opcode("LOADK");
    let _ = classify_opcode("UNKNOWN_XYZ");
}

// ---------- detect_version ----------

#[test]
fn detect_version_from_header_lua54() {
    let data = [0x1b, b'L', b'u', b'a', 0x54, 1, 4, 8];
    assert_eq!(detect_version(&data), Some(LuaVersion::Lua54));
}

#[test]
fn detect_version_too_short() {
    assert_eq!(detect_version(&[]), None);
    assert_eq!(detect_version(&[1, 2, 3]), None);
}

#[test]
fn detect_version_heuristic_lua54_by_high_opcode() {
    // opcode 50 (LEN) in low 7 bits.
    let w: u32 = 50;
    assert_eq!(detect_version(&w.to_le_bytes()), Some(LuaVersion::Lua54));
}

// ---------- RegValue / RegisterSnapshot ----------

#[test]
fn register_snapshot_set_get() {
    let mut s = RegisterSnapshot::new(4);
    s.set(2, RegValue::Unknown);
    assert!(matches!(s.get(2), Some(RegValue::Unknown)));
    assert!(s.get(0).is_none());
}

#[test]
fn register_snapshot_resizes() {
    let mut s = RegisterSnapshot::new(2);
    s.set(10, RegValue::Const(LuaConst::Int(1)));
    assert!(s.get(10).is_some());
}

#[test]
fn register_snapshot_invalidate_from() {
    let mut s = RegisterSnapshot::new(4);
    s.set(0, RegValue::Unknown);
    s.set(2, RegValue::Unknown);
    s.invalidate_from(1);
    assert!(s.get(0).is_some());
    assert!(s.get(2).is_none());
}

#[test]
fn register_snapshot_propagate_move_lua54() {
    let a = LuaArch::new();
    let bytes = make_iabc(0, 5, 3, 0, 0).to_le_bytes(); // MOVE R5 <- R3
    let i = a.disassemble(Address::new(0), &bytes).unwrap();
    let mut s = RegisterSnapshot::new(8);
    s.propagate(&[i], &[], LuaVersion::Lua54);
    assert!(matches!(s.get(5), Some(RegValue::Alias(3))));
}

#[test]
fn register_snapshot_propagate_loadk_lua54() {
    let a = LuaArch::new();
    let bytes = make_iabx(3, 1, 0).to_le_bytes(); // LOADK R1 K[0]
    let i = a.disassemble(Address::new(0), &bytes).unwrap();
    let pool = vec![LuaConst::Int(99)];
    let mut s = RegisterSnapshot::new(4);
    s.propagate(&[i], &pool, LuaVersion::Lua54);
    assert!(matches!(s.get(1), Some(RegValue::Const(LuaConst::Int(99)))));
}

#[test]
fn regvalue_display() {
    assert_eq!(format!("{}", RegValue::Alias(3)), "R3");
    assert_eq!(format!("{}", RegValue::Upvalue(2)), "upval(2)");
    assert_eq!(format!("{}", RegValue::Unknown), "?");
}

// ---------- LuaArch get_branches ----------

#[test]
fn get_branches_for_return_is_empty() {
    let a = LuaArch::new();
    let bytes = make_iabc(68, 0, 1, 1, 0).to_le_bytes(); // RETURN
    let i = a.disassemble(Address::new(0), &bytes).unwrap();
    let b = a.get_branches(&i);
    assert!(b.is_empty());
}

// ---------- Eq / Hash invariants ----------

#[test]
fn version_eq_hash_consistent() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(LuaVersion::Lua51);
    s.insert(LuaVersion::Lua51);
    assert_eq!(s.len(), 1);
    s.insert(LuaVersion::Lua54);
    assert_eq!(s.len(), 2);
}

#[test]
fn header_eq_self() {
    let h = LuaChunkHeader {
        version: LuaVersion::Lua54,
        endian: 1,
        int_size: 4,
        size_t_size: 8,
        instr_size: 4,
    };
    assert_eq!(h.clone(), h);
}

// ---------- Send/Sync invariants ----------

#[test]
fn lua_arch_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LuaArch>();
    assert_send_sync::<LuaVersion>();
    assert_send_sync::<LuaChunkHeader>();
    assert_send_sync::<LuaConst>();
}
