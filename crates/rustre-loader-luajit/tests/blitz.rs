//! Blitz test suite for rustre-loader-luajit.
//!
//! Targets the public API exposed in `lib.rs`: magic detection, LEB128
//! encoders/decoders, header parsing, instruction decoding, prototype parsing,
//! KGC/KN constants, debug info, builder & encoder round-trips.

use rustre_loader_luajit::*;

// ───────────────────────── magic / detection ─────────────────────────

#[test]
fn magic_constant_is_esc_lj() {
    assert_eq!(LJ_MAGIC, [0x1B, b'L', b'J']);
}

#[test]
fn is_luajit_accepts_valid_magic() {
    assert!(is_luajit(&[0x1B, b'L', b'J', 2]));
    assert!(is_luajit(&[0x1B, b'L', b'J']));
}

#[test]
fn is_luajit_rejects_short_and_wrong() {
    assert!(!is_luajit(&[]));
    assert!(!is_luajit(&[0x1B, b'L']));
    assert!(!is_luajit(&[0x1B, b'X', b'J']));
    assert!(!is_luajit(&[0, 0, 0]));
}

// ───────────────────────── LEB128 ─────────────────────────

#[test]
fn uleb128_single_byte_values() {
    for v in [0u64, 1, 0x7F] {
        assert_eq!(read_uleb128(&[v as u8], 0), Some((v, 1)));
    }
}

#[test]
fn uleb128_multi_byte_round_trip() {
    // 624485 = 0xE5 0x8E 0x26 (classic LEB example)
    let bytes = [0xE5, 0x8E, 0x26];
    assert_eq!(read_uleb128(&bytes, 0), Some((624485u64, 3)));
}

#[test]
fn uleb128_empty_returns_none() {
    assert!(read_uleb128(&[], 0).is_none());
}

#[test]
fn uleb128_truncated_unterminated_returns_none() {
    // continuation bit set but no follow-up
    assert!(read_uleb128(&[0x80], 0).is_none());
    assert!(read_uleb128(&[0x80, 0x80], 0).is_none());
}

#[test]
fn uleb128_offset_starting_past_end_returns_none() {
    assert!(read_uleb128(&[1, 2, 3], 3).is_none());
    assert!(read_uleb128(&[1, 2, 3], 99).is_none());
}

#[test]
fn uleb128_overflow_returns_none() {
    // 11 bytes of 0xFF then a 0x01 — overflows past 64 bits.
    let bytes = [0xFF; 11].into_iter().chain(std::iter::once(0x01)).collect::<Vec<u8>>();
    assert!(read_uleb128(&bytes, 0).is_none());
}

#[test]
fn sleb128_positive_small() {
    assert_eq!(read_sleb128(&[0x00], 0), Some((0i64, 1)));
    assert_eq!(read_sleb128(&[0x3F], 0), Some((0x3F, 1)));
}

#[test]
fn sleb128_negative_one() {
    // -1 encoded as 0x7F (sign bit set in last byte)
    assert_eq!(read_sleb128(&[0x7F], 0), Some((-1i64, 1)));
}

#[test]
fn sleb128_empty_returns_none() {
    assert!(read_sleb128(&[], 0).is_none());
}

#[test]
fn sleb128_truncated_returns_none() {
    assert!(read_sleb128(&[0x80], 0).is_none());
}

// ───────────────────────── LjVersion ─────────────────────────

#[test]
fn version_from_byte_known() {
    assert_eq!(LjVersion::from_byte(1), LjVersion::Lj20);
    assert_eq!(LjVersion::from_byte(2), LjVersion::Lj21);
    assert!(LjVersion::Lj20.is_known());
    assert!(LjVersion::Lj21.is_known());
}

#[test]
fn version_from_byte_unknown() {
    let v = LjVersion::from_byte(0xFE);
    assert!(matches!(v, LjVersion::Unknown(0xFE)));
    assert!(!v.is_known());
    assert_eq!(v.as_byte(), 0xFE);
}

#[test]
fn version_as_byte_roundtrip() {
    for b in [0u8, 1, 2, 3, 99, 255] {
        assert_eq!(LjVersion::from_byte(b).as_byte(), b);
    }
}

#[test]
fn version_display_strings() {
    assert_eq!(LjVersion::Lj20.to_string(), "LuaJIT 2.0");
    assert_eq!(LjVersion::Lj21.to_string(), "LuaJIT 2.1");
    assert!(LjVersion::Unknown(0x9A).to_string().contains("9a"));
}

// ───────────────────────── Header parsing ─────────────────────────

#[test]
fn header_parse_too_short() {
    assert!(matches!(LjHeader::parse(&[]), Err(LjLoaderError::TruncatedData)));
    assert!(matches!(LjHeader::parse(&[0x1B, b'L', b'J']), Err(LjLoaderError::TruncatedData)));
}

#[test]
fn header_parse_bad_magic() {
    let data = [b'M', b'Z', 0x00, 0x00, 0x00];
    assert!(matches!(LjHeader::parse(&data), Err(LjLoaderError::InvalidMagic)));
}

#[test]
fn header_parse_stripped_ok() {
    let data = [0x1B, b'L', b'J', 2, LjFlags::STRIP.bits()];
    let (h, pos) = LjHeader::parse(&data).unwrap();
    assert_eq!(h.version, LjVersion::Lj21);
    assert!(h.flags.contains(LjFlags::STRIP));
    assert!(h.debug_name.is_none());
    assert_eq!(pos, 5);
}

#[test]
fn header_parse_unstripped_with_debug_name() {
    // magic + ver + flags(0) + len(4) + "main"
    let data = [0x1B, b'L', b'J', 1, 0x00, 4, b'm', b'a', b'i', b'n'];
    let (h, pos) = LjHeader::parse(&data).unwrap();
    assert_eq!(h.version, LjVersion::Lj20);
    assert_eq!(h.debug_name.as_deref(), Some("main"));
    assert_eq!(pos, data.len());
}

#[test]
fn header_parse_unstripped_empty_name_is_none() {
    let data = [0x1B, b'L', b'J', 2, 0x00, 0];
    let (h, _) = LjHeader::parse(&data).unwrap();
    assert!(h.debug_name.is_none());
}

#[test]
fn header_parse_truncated_debug_name() {
    // claims 10-byte name but only 2 available
    let data = [0x1B, b'L', b'J', 2, 0x00, 10, b'a', b'b'];
    assert!(matches!(LjHeader::parse(&data), Err(LjLoaderError::TruncatedData)));
}

#[test]
fn header_display_contains_flags() {
    let data = [0x1B, b'L', b'J', 2, LjFlags::STRIP.bits()];
    let (h, _) = LjHeader::parse(&data).unwrap();
    let s = h.to_string();
    assert!(s.contains("LuaJIT 2.1"));
    assert!(s.contains("stripped=true"));
}

// ───────────────────────── LjInstr ─────────────────────────

#[test]
fn instr_field_decode() {
    // opcode=0x42, A=0x11, C=0x22, B=0x33  → word = 0x33 22 11 42
    let i = LjInstr(0x3322_1142);
    assert_eq!(i.opcode(), 0x42);
    assert_eq!(i.a(), 0x11);
    assert_eq!(i.c(), 0x22);
    assert_eq!(i.b(), 0x33);
    assert_eq!(i.d(), 0x3322);
}

#[test]
fn instr_jump_offset_bias() {
    // D = 0x8000 → offset 0
    let i = LjInstr(0x8000_0058); // JMP, D=0x8000
    assert_eq!(i.opcode(), 0x58);
    assert_eq!(i.jump_offset(), 0);
    let i2 = LjInstr(0x8001_0058);
    assert_eq!(i2.jump_offset(), 1);
    let i3 = LjInstr(0x7FFF_0058);
    assert_eq!(i3.jump_offset(), -1);
}

#[test]
fn instr_mnemonic_known_and_unknown() {
    assert_eq!(LjInstr(0x0000_0000).mnemonic(), "ISLT");
    assert_eq!(LjInstr(0x0000_0042).mnemonic(), "CALL");
    assert_eq!(LjInstr(0x0000_0058).mnemonic(), "JMP");
    // out-of-table opcode
    assert_eq!(LjInstr(0x0000_00FF).mnemonic(), "UNK");
}

#[test]
fn instr_classification_buckets() {
    assert!(LjInstr(0x0000_0042).is_call()); // CALL
    assert!(LjInstr(0x0000_0044).is_call()); // CALLT
    assert!(LjInstr(0x0000_004A).is_return());
    assert!(LjInstr(0x0000_0058).is_branch());
    assert!(LjInstr(0x0000_0058).is_loop() || LjInstr(0x0000_0058).is_branch());
    assert!(LjInstr(0x0000_0000).is_compare());
    assert!(LjInstr(0x0000_0027).is_load_const());
    assert!(LjInstr(0x0000_0034).is_table_op());
    assert!(LjInstr(0x0000_002D).is_upvalue_op());
    assert!(LjInstr(0x0000_0059).is_function_header());
    assert!(LjInstr(0x0000_0020).is_arith()); // ADDVV
}

#[test]
fn instr_classification_negative() {
    let i = LjInstr(0x0000_0012); // MOV
    assert!(!i.is_call());
    assert!(!i.is_return());
    assert!(!i.is_branch());
    assert!(!i.is_compare());
    assert!(!i.is_arith());
    assert!(!i.is_table_op());
}

#[test]
fn instr_opcode_table_length_is_full() {
    // 0x60 (FUNCCW) is the last; table must include it.
    assert!(LJ_OPCODES.len() > 0x60);
    assert_eq!(LJ_OPCODES[0x60], "FUNCCW");
    assert_eq!(LJ_OPCODES[0x58], "JMP");
}

#[test]
fn instr_display_includes_mnemonic_and_fields() {
    let i = LjInstr(0x3322_1142);
    let s = i.to_string();
    assert!(s.contains("CALL"));
    assert!(s.contains("A=17"));
}

// ───────────────────────── VarName / LocalVar ─────────────────────────

#[test]
fn varname_is_live_at_range() {
    let v = VarName {
        name: "x".into(),
        start_pc: 5,
        end_pc: 10,
    };
    assert!(!v.is_live_at(4));
    assert!(v.is_live_at(5));
    assert!(v.is_live_at(9));
    assert!(!v.is_live_at(10));
}

#[test]
fn debuginfo_locals_at_filters() {
    let di = DebugInfo {
        source_name: None,
        first_line: 0,
        num_lines: 0,
        line_info: vec![],
        local_vars: vec![
            LjLocalVar { name: "a".into(), start_pc: 0, end_pc: 5 },
            LjLocalVar { name: "b".into(), start_pc: 3, end_pc: 8 },
        ],
        upvalue_names: vec![],
    };
    assert!(di.is_empty());
    let live = di.locals_at(4);
    assert_eq!(live.len(), 2);
    let live = di.locals_at(5);
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].name, "b");
}

#[test]
fn debuginfo_source_line_for_pc_oob() {
    let di = DebugInfo {
        source_name: None, first_line: 0, num_lines: 0,
        line_info: vec![1, 2, 3], local_vars: vec![], upvalue_names: vec![],
    };
    assert_eq!(di.source_line_for_pc(0), Some(1));
    assert_eq!(di.source_line_for_pc(2), Some(3));
    assert_eq!(di.source_line_for_pc(3), None);
}

// ───────────────────────── KGC / KNumConst / LjConst ─────────────────────────

#[test]
fn kgc_kind_name_matrix() {
    assert_eq!(KGC::Tab.kind_name(), "tab");
    assert_eq!(KGC::I64(1).kind_name(), "i64");
    assert_eq!(KGC::U64(1).kind_name(), "u64");
    assert_eq!(KGC::Complex(0.0, 0.0).kind_name(), "complex");
    assert_eq!(KGC::String("x".into()).kind_name(), "string");
    assert_eq!(KGC::Unknown(99).kind_name(), "unknown");
}

#[test]
fn kgc_as_str_and_predicates() {
    let s = KGC::String("hi".into());
    assert_eq!(s.as_str(), Some("hi"));
    assert!(s.is_string());
    assert!(!s.is_child());
    assert!(KGC::Tab.as_str().is_none());
}

#[test]
fn kgc_display_variants() {
    assert_eq!(KGC::Tab.to_string(), "<table>");
    assert!(KGC::I64(-7).to_string().contains("-7"));
    assert!(KGC::U64(99).to_string().contains("99"));
    assert!(KGC::String("abc".into()).to_string().contains("abc"));
    assert!(KGC::Unknown(42).to_string().contains("42"));
}

#[test]
fn knumconst_display() {
    assert_eq!(KNumConst::Int(-3).to_string(), "-3");
    assert!(KNumConst::Float(1.5).to_string().contains("1.5"));
}

#[test]
fn ljconst_display_all_variants() {
    assert_eq!(LjConst::Nil.to_string(), "nil");
    assert_eq!(LjConst::Bool(true).to_string(), "true");
    assert_eq!(LjConst::Int(5).to_string(), "5");
    assert!(LjConst::Num(2.5).to_string().contains("2.5"));
    assert_eq!(LjConst::Str("z".into()).to_string(), "\"z\"");
    assert_eq!(LjConst::Upval(2).to_string(), "upval[2]");
    assert_eq!(LjConst::Proto(7).to_string(), "proto[7]");
}

// ───────────────────────── UpvalInfo ─────────────────────────

#[test]
fn upvalinfo_local_immutable_decoding() {
    // bit 15 set → local; bit 8 set → immutable; low byte = idx
    let u = UpvalInfo::from_raw(0x8103);
    assert_eq!(u.index, 0x03);
    assert!(u.is_local);
    assert!(u.is_immutable);
    assert_eq!(u.raw, 0x8103);
}

#[test]
fn upvalinfo_nonlocal_mutable() {
    let u = UpvalInfo::from_raw(0x0005);
    assert!(!u.is_local);
    assert!(!u.is_immutable);
    assert_eq!(u.index, 5);
}

#[test]
fn upvalinfo_display_contains_fields() {
    let s = UpvalInfo::from_raw(0x8001).to_string();
    assert!(s.contains("local=true"));
    assert!(s.contains("idx=1"));
}

// ───────────────────────── Flags ─────────────────────────

#[test]
fn ljflags_bit_values() {
    assert_eq!(LjFlags::BE.bits(), 0x01);
    assert_eq!(LjFlags::STRIP.bits(), 0x02);
    assert_eq!(LjFlags::FFI.bits(), 0x04);
    assert_eq!(LjFlags::FR2.bits(), 0x08);
}

#[test]
fn ljprotoflags_bit_values() {
    assert_eq!(LjProtoFlags::CHILD.bits(), 0x01);
    assert_eq!(LjProtoFlags::VARARG.bits(), 0x02);
    assert_eq!(LjProtoFlags::FFI.bits(), 0x04);
}

// ───────────────────────── LjProto.mock ─────────────────────────

#[test]
fn mock_proto_basics() {
    let p = LjProto::mock();
    assert_eq!(p.instructions.len(), 1);
    assert!(p.is_vararg);
    assert_eq!(p.upvalue_name(0), Some("_ENV"));
    assert_eq!(p.string_constants(), vec!["hello"]);
    assert_eq!(p.kgc_strings(), vec!["hello"]);
}

#[test]
fn mock_proto_counters() {
    let p = LjProto::mock();
    // sole instruction is 0x4B = RET0
    assert_eq!(p.return_count(), 1);
    assert_eq!(p.call_count(), 0);
    assert_eq!(p.branch_count(), 0);
    assert!(!p.has_loops());
}

#[test]
fn locals_at_pc_empty_when_none() {
    let p = LjProto::mock();
    assert!(p.locals_at_pc(0).is_empty());
}

// ───────────────────────── ProtoBuilder ─────────────────────────

#[test]
fn protobuilder_basic_build() {
    let p = ProtoBuilder::new()
        .params(2)
        .frame(4)
        .vararg()
        .source("x.lua")
        .add_instr(LjInstr(0x0000_004B)) // RET0
        .add_kgc_str("hello")
        .add_kn_int(42)
        .add_upvalue(0, true, Some("env".into()))
        .build();
    assert_eq!(p.num_params, 2);
    assert_eq!(p.frame_size, 4);
    assert!(p.is_vararg);
    assert_eq!(p.instruction_count, 1);
    assert_eq!(p.upvalue_names, vec!["env"]);
    assert_eq!(p.kgc_strings(), vec!["hello"]);
    assert_eq!(p.constants.len(), 2);
    assert_eq!(p.source_name.as_deref(), Some("x.lua"));
    assert_eq!(p.line_info.len(), 1);
}

#[test]
fn protobuilder_default_empty() {
    let p = ProtoBuilder::new().build();
    assert_eq!(p.instruction_count, 0);
    assert!(p.line_info.is_empty());
    assert!(!p.is_vararg);
    assert!(p.upvalues.is_empty());
}

// ───────────────────────── string_at_pc semantics ─────────────────────────

#[test]
fn string_at_pc_returns_none_for_non_string_op() {
    let p = ProtoBuilder::new().add_instr(LjInstr(0x0000_0012)).build(); // MOV
    assert!(p.string_at_pc(0).is_none());
}

#[test]
fn string_at_pc_out_of_bounds() {
    let p = ProtoBuilder::new().build();
    assert!(p.string_at_pc(0).is_none());
    assert!(p.string_at_pc(99).is_none());
}

// ───────────────────────── BytecodeEncoder + round-trip parse ─────────────────────────

fn build_minimal_proto() -> LjProto {
    ProtoBuilder::new()
        .params(1)
        .frame(2)
        .add_instr(LjInstr(0x0000_004B)) // RET0
        .add_kgc_str("greet")
        .add_kn_int(7)
        .add_upvalue(0, true, None)
        .build()
}

#[test]
fn encoder_produces_valid_header() {
    let p = build_minimal_proto();
    let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj21, &p);
    assert!(is_luajit(&bytes));
    assert_eq!(bytes[3], 2);
    // STRIP flag byte at offset 4 (single-byte ULEB)
    assert_eq!(bytes[4], LjFlags::STRIP.bits());
}

#[test]
fn encoder_round_trip_load_recovers_proto() {
    let original = build_minimal_proto();
    let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj21, &original);
    let module = LuaJitLoader::load(&bytes).expect("load ok");
    assert_eq!(module.version(), LjVersion::Lj21);
    assert!(module.is_stripped());
    let rp = &module.root_proto;
    assert_eq!(rp.num_params, original.num_params);
    assert_eq!(rp.frame_size, original.frame_size);
    assert_eq!(rp.instructions.len(), 1);
    assert_eq!(rp.instructions[0].opcode(), 0x4B);
    assert_eq!(rp.kgc_strings(), vec!["greet"]);
    assert_eq!(rp.kn.len(), 1);
    match &rp.kn[0] {
        KNumConst::Int(v) => assert_eq!(*v, 7),
        other => panic!("expected Int, got {other:?}"),
    }
}

#[test]
fn encoder_round_trip_via_parse_all() {
    let original = build_minimal_proto();
    let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj20, &original);
    let bc = LjBytecode::parse(&bytes).unwrap();
    assert_eq!(bc.header.version, LjVersion::Lj20);
    assert_eq!(bc.protos.len(), 1);
    assert_eq!(bc.total_instructions(), 1);
    assert_eq!(bc.all_strings(), vec!["greet"]);
    assert_eq!(bc.protos_referencing_string("greet"), vec![0]);
    assert!(bc.protos_referencing_string("nope").is_empty());
}

// ───────────────────────── LuaJitLoader edge cases ─────────────────────────

#[test]
fn loader_can_load_matches_is_luajit() {
    assert!(LuaJitLoader::can_load(&[0x1B, b'L', b'J', 2]));
    assert!(!LuaJitLoader::can_load(b"MZ"));
}

#[test]
fn loader_load_rejects_bad_magic() {
    let err = LuaJitLoader::load(&[0, 0, 0, 0]).unwrap_err();
    assert!(matches!(err, LjLoaderError::InvalidMagic));
}

#[test]
fn loader_load_errors_when_no_protos() {
    // Valid header, then immediate 0 sentinel — no protos.
    let data = [0x1B, b'L', b'J', 2, LjFlags::STRIP.bits(), 0];
    let err = LuaJitLoader::load(&data).unwrap_err();
    assert!(matches!(err, LjLoaderError::ParseError(_)));
}

#[test]
fn parse_proto_advances_offset() {
    let p = build_minimal_proto();
    let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj21, &p);
    // Skip header: 3 magic + 1 ver + 1 flags = 5
    let mut off = 5usize;
    let proto = parse_proto(&bytes, &mut off, 0).expect("parses");
    assert_eq!(proto.num_params, 1);
    assert!(off > 5);
}

#[test]
fn parse_proto_errors_on_sentinel_zero() {
    // proto_size = 0 triggers TruncatedData wrapping
    let bytes = [0u8];
    let mut off = 0usize;
    let err = parse_proto(&bytes, &mut off, 0).unwrap_err();
    assert!(matches!(err, LjLoaderError::TruncatedData));
}

#[test]
fn read_uleb128_mut_advances_and_returns_value() {
    let bytes = [0x05u8, 0xAA];
    let mut off = 0usize;
    let v = read_uleb128_mut(&bytes, &mut off).unwrap();
    assert_eq!(v, 5);
    assert_eq!(off, 1);
}

#[test]
fn read_uleb128_mut_truncation_error() {
    let mut off = 0usize;
    let err = read_uleb128_mut(&[0x80u8], &mut off).unwrap_err();
    assert!(matches!(err, LjLoaderError::TruncatedData));
}

// ───────────────────────── ProtoStats ─────────────────────────

#[test]
fn protostats_zero_for_empty() {
    let p = ProtoBuilder::new().build();
    let s = ProtoStats::compute(&p);
    assert_eq!(s.total, 0);
    assert_eq!(s.calls, 0);
    assert_eq!(s.returns, 0);
    assert!(s.opcode_freq.is_empty());
}

#[test]
fn protostats_classifies_mixed_instrs() {
    let p = ProtoBuilder::new()
        .add_instr(LjInstr(0x0000_0042)) // CALL
        .add_instr(LjInstr(0x0000_004A)) // RET
        .add_instr(LjInstr(0x0000_0058)) // JMP (branch & loop range)
        .add_instr(LjInstr(0x0000_0000)) // ISLT (compare)
        .add_instr(LjInstr(0x0000_0020)) // ADDVV (arith)
        .add_instr(LjInstr(0x0000_0027)) // KSTR (load_const)
        .add_instr(LjInstr(0x0000_0034)) // TNEW (table)
        .add_instr(LjInstr(0x0000_002D)) // UGET (upvalue)
        .build();
    let s = ProtoStats::compute(&p);
    assert_eq!(s.total, 8);
    assert_eq!(s.calls, 1);
    assert_eq!(s.returns, 1);
    assert_eq!(s.branches, 1);
    assert_eq!(s.compares, 1);
    assert_eq!(s.arith, 1);
    assert_eq!(s.loads, 1);
    assert_eq!(s.table_ops, 1);
    assert_eq!(s.upvalue_ops, 1);
    // opcode_freq sorted by opcode and has 8 unique entries.
    assert_eq!(s.opcode_freq.len(), 8);
    for w in s.opcode_freq.windows(2) {
        assert!(w[0].0 < w[1].0);
    }
}

// ───────────────────────── LjDisassembler ─────────────────────────

#[test]
fn disassembler_proto_lines_match_instructions() {
    let p = ProtoBuilder::new()
        .add_instr(LjInstr(0x0000_004B))
        .add_instr(LjInstr(0x0000_0042))
        .build();
    let lines = LjDisassembler::disassemble_proto(&p);
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("0000"));
    assert!(lines[1].starts_with("0001"));
}

#[test]
fn disassembler_all_module_includes_header_comment() {
    let p = build_minimal_proto();
    let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj21, &p);
    let m = LuaJitLoader::load(&bytes).unwrap();
    let out = LjDisassembler::disassemble_all(&m);
    assert!(out.contains("LuaJIT bytecode"));
    assert!(out.contains("LuaJIT 2.1"));
}

#[test]
fn disassembler_bytecode_lists_all_protos() {
    let p = build_minimal_proto();
    let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj21, &p);
    let bc = LjBytecode::parse(&bytes).unwrap();
    let out = LjDisassembler::disassemble_bytecode(&bc);
    assert!(out.contains("protos=1"));
    assert!(out.contains("proto #0"));
}

// ───────────────────────── LjModule helpers ─────────────────────────

#[test]
fn module_helpers_reflect_flags() {
    let p = build_minimal_proto();
    let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj21, &p);
    let m = LuaJitLoader::load(&bytes).unwrap();
    assert!(m.is_stripped());
    assert!(!m.is_big_endian());
    assert!(!m.uses_ffi());
    assert!(!m.uses_fr2());
    assert_eq!(m.version(), LjVersion::Lj21);
    assert_eq!(m.total_instructions(), 1);
    assert_eq!(m.string_constants(), vec!["greet".to_string()]);
    assert_eq!(m.all_protos().len(), 1);
}

#[test]
fn module_display_smoke() {
    let p = build_minimal_proto();
    let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj21, &p);
    let m = LuaJitLoader::load(&bytes).unwrap();
    let s = m.to_string();
    assert!(s.contains("LjModule"));
}

// ───────────────────────── Send/Sync ─────────────────────────

#[test]
fn types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LjModule>();
    assert_send_sync::<LjBytecode>();
    assert_send_sync::<LjProto>();
    assert_send_sync::<LjInstr>();
    assert_send_sync::<LjLoaderError>();
    assert_send_sync::<LuaJitLoader>();
    assert_send_sync::<LjLoader>();
}

// ───────────────────────── Loader trait (async) ─────────────────────────

#[tokio::test]
async fn lj_loader_can_load_and_load_returns_view() {
    use rustre_core::{Loader, LoaderInput};
    let p = build_minimal_proto();
    let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj21, &p);
    let loader = LjLoader::new();
    let input = LoaderInput::new("test://".to_string(), bytes.clone());
    assert!(loader.can_load(&input));
    let res = loader.load(input).await.expect("load ok");
    let _ = res; // smoke
    let nested = loader.find_nested(&LoaderInput::new("test://".to_string(), bytes)).await.unwrap();
    assert!(nested.is_empty());
    assert_eq!(loader.name(), "luajit");
}

// ───────────────────────── Architecture trait ─────────────────────────

#[test]
fn arch_basic_metadata() {
    use rustre_core::arch::Architecture;
    let a = LuaJitArch;
    assert_eq!(a.name(), "luajit");
    assert_eq!(a.pointer_size(), 8);
    assert_eq!(a.registers().len(), 16);
    assert_eq!(a.calling_conventions().len(), 1);
}

#[test]
fn arch_disassemble_short_bytes_fallback_nop() {
    use rustre_core::{address::Address, arch::Architecture};
    let a = LuaJitArch;
    // Name kept for continuity; the "fallback nop" it described was the defect.
    // Two bytes are not a LuaJIT instruction (they are exactly four), so the
    // tail of a buffer used to be reported as a one-byte `nop` that a caller
    // could not tell from a real one. It is now a Truncated error.
    let err = a
        .disassemble(Address::new(0), &[0u8, 0u8])
        .expect_err("two bytes are not an instruction");
    let text = err.to_string();
    assert!(
        text.contains('4') && text.contains('2'),
        "the error should state what was expected and what was available: {text}"
    );
}

#[test]
fn arch_disassemble_decodes_opcode() {
    use rustre_core::{address::Address, arch::Architecture};
    let a = LuaJitArch;
    // RET0 = 0x4B
    let bytes = 0x0000_004Bu32.to_le_bytes();
    let ins = a.disassemble(Address::new(0), &bytes).unwrap();
    assert_eq!(ins.mnemonic, "RET0");
    assert!(ins.operands.contains("A="));
}

// ───────────────────────── KNumConst negative-int round trip ─────────────────────────

#[test]
fn encoder_kn_negative_int_round_trip() {
    // Encoder writes `((v as u64) << 1) | 1`. For a negative i32, the cast
    // sign-extends to u64; shifting and reading back as `(kval >> 1) as i32`
    // should recover the original value.
    let p = ProtoBuilder::new()
        .add_instr(LjInstr(0x0000_004B))
        .add_kn_int(-5)
        .build();
    let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj21, &p);
    let m = LuaJitLoader::load(&bytes).unwrap();
    assert_eq!(m.root_proto.kn.len(), 1);
    match &m.root_proto.kn[0] {
        KNumConst::Int(v) => assert_eq!(*v, -5, "negative KN int corrupted in encode/decode"),
        other => panic!("expected Int, got {other:?}"),
    }
}

// ───────────────────────── LjLoaderError Display ─────────────────────────

#[test]
fn error_display_strings() {
    assert_eq!(LjLoaderError::InvalidMagic.to_string(), "invalid magic");
    assert_eq!(LjLoaderError::TruncatedData.to_string(), "truncated data");
    assert!(LjLoaderError::UnsupportedVersion(9).to_string().contains('9'));
    assert!(LjLoaderError::ParseError("oops".into()).to_string().contains("oops"));
    assert_eq!(LjLoaderError::Leb128Overflow.to_string(), "LEB128 overflow");
}
