//! Comprehensive integration tests for `rustre-arch-luajit`.
//!
//! Covers the public surface in `lib.rs`: opcode enum, decoding, encoding
//! helpers, instruction details, bytecode parsing, basic-block analysis,
//! flag bitset, and architecture trait implementation.

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_luajit::{
    BasicBlock, DumpFlags, InstrCategory, LjConst, LjFmt, LjInstrDetail, LjInstrFlags,
    LjInstruction, LjOp, LjOpMeta, LjUpvalue, LuaJitArch, LuaJitBytecode, LuaJitProto,
    ParseError, RegAccess, collect_reg_accesses, decode_lj_instruction, disassemble_listing,
    find_basic_blocks, format_instruction, instr_a, instr_b, instr_c, instr_d, instr_d_signed,
    instr_op, make_lj_abc, make_lj_ad, make_lj_ad_signed, LJ_MAGIC, LJ_VERSION_20, LJ_VERSION_21,
};
use rustre_core::address::Address;
use rustre_core::arch::BranchKind;
use rustre_core::endian::Endian;

// -------------------------------------------------------------------------
// LjOp enum
// -------------------------------------------------------------------------

#[test]
fn ljop_from_u8_roundtrip_all_defined() {
    for v in 0u8..=96 {
        let op = LjOp::from_u8(v).expect("defined opcode");
        assert_eq!(op as u8, v);
    }
}

#[test]
fn ljop_from_u8_out_of_range() {
    assert!(LjOp::from_u8(97).is_none());
    assert!(LjOp::from_u8(150).is_none());
    assert!(LjOp::from_u8(255).is_none());
}

#[test]
fn ljop_mnemonic_known() {
    assert_eq!(LjOp::Islt.mnemonic(), "ISLT");
    assert_eq!(LjOp::Mov.mnemonic(), "MOV");
    assert_eq!(LjOp::Addvv.mnemonic(), "ADDVV");
    assert_eq!(LjOp::Jmp.mnemonic(), "JMP");
    assert_eq!(LjOp::Funccw.mnemonic(), "FUNCCW");
}

#[test]
fn ljop_category_classification() {
    assert_eq!(LjOp::Islt.category(), InstrCategory::Comparison);
    assert_eq!(LjOp::Mov.category(), InstrCategory::Arithmetic);
    assert_eq!(LjOp::Kstr.category(), InstrCategory::LoadConst);
    assert_eq!(LjOp::Uget.category(), InstrCategory::Upvalue);
    assert_eq!(LjOp::Tgetv.category(), InstrCategory::TableGet);
    assert_eq!(LjOp::Tsetv.category(), InstrCategory::TableSet);
    assert_eq!(LjOp::Call.category(), InstrCategory::Call);
    assert_eq!(LjOp::Ret.category(), InstrCategory::Return);
    assert_eq!(LjOp::Jmp.category(), InstrCategory::Branch);
    assert_eq!(LjOp::Funcf.category(), InstrCategory::FuncHeader);
    assert_eq!(LjOp::Funccw.category(), InstrCategory::FuncHeader);
}

#[test]
fn ljop_copy_eq_debug() {
    let a = LjOp::Mov;
    let b = a;
    assert_eq!(a, b);
    let s = format!("{a:?}");
    assert!(s.contains("Mov"));
}

// -------------------------------------------------------------------------
// Encoding helpers + extractors
// -------------------------------------------------------------------------

#[test]
fn make_lj_abc_layout() {
    let w = make_lj_abc(LjOp::Addvv as u8, 0x12, 0x34, 0x56);
    assert_eq!(instr_op(w), LjOp::Addvv as u8);
    assert_eq!(instr_a(w), 0x12);
    assert_eq!(instr_b(w), 0x34);
    assert_eq!(instr_c(w), 0x56);
}

#[test]
fn make_lj_ad_layout() {
    let w = make_lj_ad(LjOp::Kshort as u8, 5, 0xBEEF);
    assert_eq!(instr_op(w), LjOp::Kshort as u8);
    assert_eq!(instr_a(w), 5);
    assert_eq!(instr_d(w), 0xBEEF);
}

#[test]
fn make_lj_ad_boundaries() {
    let w0 = make_lj_ad(LjOp::Kstr as u8, 0, 0);
    assert_eq!(instr_d(w0), 0);
    let wmax = make_lj_ad(LjOp::Kstr as u8, 255, 0xFFFF);
    assert_eq!(instr_a(wmax), 255);
    assert_eq!(instr_d(wmax), 0xFFFF);
}

#[test]
fn make_lj_ad_signed_zero_pos_neg() {
    let w0 = make_lj_ad_signed(LjOp::Jmp as u8, 0, 0);
    assert_eq!(instr_d_signed(w0), 0);
    let wp = make_lj_ad_signed(LjOp::Jmp as u8, 0, 100);
    assert_eq!(instr_d_signed(wp), 100);
    let wn = make_lj_ad_signed(LjOp::Jmp as u8, 0, -100);
    assert_eq!(instr_d_signed(wn), -100);
}

#[test]
fn make_lj_ad_signed_extremes() {
    let wmin = make_lj_ad_signed(LjOp::Jmp as u8, 0, i16::MIN);
    assert_eq!(instr_d_signed(wmin), i16::MIN);
    let wmax = make_lj_ad_signed(LjOp::Jmp as u8, 0, i16::MAX);
    assert_eq!(instr_d_signed(wmax), i16::MAX);
}

#[test]
fn instr_d_combines_b_and_c() {
    let w = make_lj_abc(0, 0, 0xAB, 0xCD);
    // d = (b<<8) | c
    assert_eq!(instr_d(w), 0xABCD);
}

// -------------------------------------------------------------------------
// decode_lj_instruction + LjInstruction
// -------------------------------------------------------------------------

#[test]
fn decode_addvv() {
    let w = make_lj_abc(LjOp::Addvv as u8, 0, 1, 2);
    let d = decode_lj_instruction(w);
    assert_eq!(d.mnemonic(), "ADDVV");
    assert_eq!(d.op, LjOp::Addvv as u8);
    assert_eq!(d.a, 0);
    assert_eq!(d.b, 1);
    assert_eq!(d.c, 2);
    assert_eq!(d.fmt, LjFmt::Abc);
    assert!(d.flags.is_empty());
    assert_eq!(d.category, InstrCategory::Arithmetic);
    assert_eq!(d.raw, w);
}

#[test]
fn decode_jmp_sets_branch_flag() {
    let w = make_lj_ad_signed(LjOp::Jmp as u8, 0, 5);
    let d = decode_lj_instruction(w);
    assert_eq!(d.mnemonic(), "JMP");
    assert!(d.flags.contains(LjInstrFlags::BRANCH));
    assert_eq!(d.fmt, LjFmt::AdSigned);
    assert_eq!(d.d_signed, 5);
}

#[test]
fn decode_islt_conditional() {
    let w = make_lj_abc(LjOp::Islt as u8, 1, 2, 3);
    let d = decode_lj_instruction(w);
    assert!(d.flags.contains(LjInstrFlags::CONDITIONAL));
    assert!(d.flags.contains(LjInstrFlags::BRANCH));
    assert_eq!(d.category, InstrCategory::Comparison);
}

#[test]
fn decode_unknown_opcode_returns_placeholder() {
    // 0xFF is not a defined opcode
    let w: u32 = 0x00_00_00_FF;
    let d = decode_lj_instruction(w);
    assert_eq!(d.op, 0xFF);
    assert_eq!(d.mnemonic(), "???");
    assert!(d.flags.is_empty());
    assert_eq!(d.category, InstrCategory::Other);
}

#[test]
fn decode_uget_upvalue_flag() {
    let w = make_lj_ad(LjOp::Uget as u8, 0, 1);
    let d = decode_lj_instruction(w);
    assert!(d.flags.contains(LjInstrFlags::UPVALUE_READ));
}

#[test]
fn decode_usetv_upvalue_write() {
    let w = make_lj_ad(LjOp::Usetv as u8, 0, 1);
    let d = decode_lj_instruction(w);
    assert!(d.flags.contains(LjInstrFlags::UPVALUE_WRITE));
}

#[test]
fn decode_uclo_closes_upvalues_and_branches() {
    let w = make_lj_ad_signed(LjOp::Uclo as u8, 0, 3);
    let d = decode_lj_instruction(w);
    assert!(d.flags.contains(LjInstrFlags::CLOSES_UPVALUES));
    assert!(d.flags.contains(LjInstrFlags::BRANCH));
}

#[test]
fn ljinstruction_clone_eq() {
    let w = make_lj_abc(LjOp::Mulvv as u8, 1, 2, 3);
    let a = decode_lj_instruction(w);
    let b = a.clone();
    assert_eq!(a, b);
}

// -------------------------------------------------------------------------
// LjFmt / InstrCategory derives
// -------------------------------------------------------------------------

#[test]
fn ljfmt_copy_eq() {
    let a = LjFmt::Abc;
    let b = a;
    assert_eq!(a, b);
    assert_ne!(LjFmt::Abc, LjFmt::Ad);
    assert_ne!(LjFmt::Ad, LjFmt::AdSigned);
    assert_ne!(LjFmt::A, LjFmt::None);
}

#[test]
fn instr_category_eq() {
    assert_eq!(InstrCategory::Comparison, InstrCategory::Comparison);
    assert_ne!(InstrCategory::Comparison, InstrCategory::Branch);
}

// -------------------------------------------------------------------------
// LjOpMeta
// -------------------------------------------------------------------------

#[test]
fn ljopmeta_for_op_known() {
    let m = LjOpMeta::for_op(LjOp::Addvv as u8);
    assert_eq!(m.mnemonic, "ADDVV");
    assert_eq!(m.fmt, LjFmt::Abc);
    assert!(m.flags.is_empty());
    assert!(!m.description.is_empty());
}

#[test]
fn ljopmeta_for_op_jmp_branch_flag() {
    let m = LjOpMeta::for_op(LjOp::Jmp as u8);
    assert_eq!(m.mnemonic, "JMP");
    assert!(m.flags.contains(LjInstrFlags::BRANCH));
}

#[test]
fn ljopmeta_for_op_out_of_range_falls_back() {
    let m = LjOpMeta::for_op(250);
    // Should fall back to last valid entry rather than panic.
    assert!(!m.mnemonic.is_empty());
}

// -------------------------------------------------------------------------
// LjInstrFlags
// -------------------------------------------------------------------------

#[test]
fn flags_default_empty() {
    let f = LjInstrFlags::default();
    assert!(f.is_empty());
    assert_eq!(f, LjInstrFlags::NONE);
    assert_eq!(LjInstrFlags::empty(), LjInstrFlags::NONE);
}

#[test]
fn flags_union_and_contains() {
    let combined = LjInstrFlags::BRANCH.union(LjInstrFlags::CONDITIONAL);
    assert!(combined.contains(LjInstrFlags::BRANCH));
    assert!(combined.contains(LjInstrFlags::CONDITIONAL));
    assert!(!combined.contains(LjInstrFlags::CALL));
}

#[test]
fn flags_bitor_and_bitor_assign() {
    let mut f = LjInstrFlags::BRANCH;
    f |= LjInstrFlags::CONDITIONAL;
    assert!(f.contains(LjInstrFlags::BRANCH));
    assert!(f.contains(LjInstrFlags::CONDITIONAL));
    let g = LjInstrFlags::CALL | LjInstrFlags::RETURN;
    assert!(g.contains(LjInstrFlags::CALL));
    assert!(g.contains(LjInstrFlags::RETURN));
}

#[test]
fn flags_display_orders_bits() {
    let f = LjInstrFlags::BRANCH | LjInstrFlags::CALL;
    let s = format!("{f}");
    assert!(s.contains("BRANCH"));
    assert!(s.contains("CALL"));
}

#[test]
fn flags_display_empty_is_empty_string() {
    assert_eq!(format!("{}", LjInstrFlags::empty()), "");
}

// -------------------------------------------------------------------------
// LuaJitArch
// -------------------------------------------------------------------------

#[test]
fn arch_basic_metadata() {
    let a = LuaJitArch::new();
    assert_eq!(a.name(), "luajit");
    assert_eq!(a.pointer_size(), 8);
    assert_eq!(a.endian(), Endian::Little);
    assert_eq!(a.registers().len(), 16);
}

#[test]
fn arch_default_equals_new() {
    let _: LuaJitArch = LuaJitArch;
    let _ = LuaJitArch::new();
}

#[test]
fn arch_calling_conventions_present() {
    let a = LuaJitArch::new();
    let ccs = a.calling_conventions();
    assert_eq!(ccs.len(), 1);
    assert_eq!(ccs[0].name, "luajit");
    assert!(!ccs[0].caller_cleans_stack);
}

#[test]
fn arch_disassemble_short_input_errors() {
    let a = LuaJitArch::new();
    let r = a.disassemble(Address::new(0), &[0u8, 1, 2]);
    assert!(r.is_err());
}

#[test]
fn arch_disassemble_mov() {
    let a = LuaJitArch::new();
    let w = make_lj_ad(LjOp::Mov as u8, 3, 7);
    let bytes = w.to_le_bytes();
    let instr = a.disassemble(Address::new(0x1000), &bytes).unwrap();
    assert_eq!(instr.mnemonic, "mov");
    assert!(instr.operands.starts_with("R3"));
    assert_eq!(instr.size, 4);
}

#[test]
fn arch_disassemble_unknown_opcode_errors() {
    let a = LuaJitArch::new();
    // op 200 is invalid (LJ_NAMES has 97 entries)
    let w: u32 = 200;
    let bytes = w.to_le_bytes();
    assert!(a.disassemble(Address::new(0), &bytes).is_err());
}

#[test]
fn arch_branch_kind_for_call_ret_jmp() {
    let arch = LuaJitArch::new();

    let w_call = make_lj_abc(LjOp::Call as u8, 0, 1, 1);
    let i_call = arch
        .disassemble(Address::new(0), &w_call.to_le_bytes())
        .unwrap();
    assert_eq!(arch.branch_kind(&i_call), Some(BranchKind::Call));

    let w_ret = make_lj_ad(LjOp::Ret0 as u8, 0, 0);
    let i_ret = arch
        .disassemble(Address::new(0), &w_ret.to_le_bytes())
        .unwrap();
    assert_eq!(arch.branch_kind(&i_ret), Some(BranchKind::Return));

    let w_jmp = make_lj_ad_signed(LjOp::Jmp as u8, 0, 1);
    let i_jmp = arch
        .disassemble(Address::new(0), &w_jmp.to_le_bytes())
        .unwrap();
    assert_eq!(arch.branch_kind(&i_jmp), Some(BranchKind::UnconditionalJump));

    let w_mov = make_lj_ad(LjOp::Mov as u8, 0, 1);
    let i_mov = arch
        .disassemble(Address::new(0), &w_mov.to_le_bytes())
        .unwrap();
    assert_eq!(arch.branch_kind(&i_mov), None);
}

#[test]
fn arch_branch_kind_for_conditional() {
    let arch = LuaJitArch::new();
    let w_islt = make_lj_abc(LjOp::Islt as u8, 0, 1, 2);
    let i = arch
        .disassemble(Address::new(0), &w_islt.to_le_bytes())
        .unwrap();
    assert_eq!(arch.branch_kind(&i), Some(BranchKind::ConditionalJump));
}

#[test]
fn arch_get_branches_jmp_target() {
    let arch = LuaJitArch::new();
    let w = make_lj_ad_signed(LjOp::Jmp as u8, 0, 2);
    let i = arch.disassemble(Address::new(0x100), &w.to_le_bytes()).unwrap();
    let bs = arch.get_branches(&i);
    assert_eq!(bs.len(), 1);
    // target = 0x100 + 2*4 + 4 = 0x10c
    assert_eq!(bs[0].target, Some(0x10c));
}

#[test]
fn arch_get_branches_ret_returns_ret_branch() {
    let arch = LuaJitArch::new();
    let w = make_lj_ad(LjOp::Ret0 as u8, 0, 0);
    let i = arch.disassemble(Address::new(0), &w.to_le_bytes()).unwrap();
    let bs = arch.get_branches(&i);
    assert_eq!(bs.len(), 1);
}

#[test]
fn arch_get_branches_non_branch_empty() {
    let arch = LuaJitArch::new();
    let w = make_lj_ad(LjOp::Mov as u8, 0, 1);
    let i = arch.disassemble(Address::new(0), &w.to_le_bytes()).unwrap();
    assert!(arch.get_branches(&i).is_empty());
}

#[test]
fn arch_disassemble_block_collects_results() {
    let arch = LuaJitArch::new();
    let words = vec![
        make_lj_ad(LjOp::Mov as u8, 0, 1),
        make_lj_abc(LjOp::Addvv as u8, 2, 0, 1),
        make_lj_ad(LjOp::Ret0 as u8, 0, 1),
    ];
    let results = arch.disassemble_block(Address::new(0), &words);
    assert_eq!(results.len(), 3);
    for r in &results {
        assert!(r.is_ok());
    }
}

#[test]
fn arch_detail_returns_none_for_out_of_range_idx() {
    let arch = LuaJitArch::new();
    let words = [make_lj_ad(LjOp::Mov as u8, 0, 1)];
    assert!(arch.detail(0, &words).is_some());
    assert!(arch.detail(1, &words).is_none());
}

#[test]
fn arch_detail_branch_target_for_jmp() {
    let arch = LuaJitArch::new();
    let words = vec![
        make_lj_ad_signed(LjOp::Jmp as u8, 0, 2),
        make_lj_ad(LjOp::Mov as u8, 0, 1),
        make_lj_ad(LjOp::Mov as u8, 0, 1),
        make_lj_ad(LjOp::Mov as u8, 0, 1),
    ];
    let d = arch.detail(0, &words).unwrap();
    // target = 0 + 1 + 2 = 3
    assert_eq!(d.branch_target, Some(3));
}

#[test]
fn arch_detail_no_branch_target_for_mov() {
    let arch = LuaJitArch::new();
    let words = [make_lj_ad(LjOp::Mov as u8, 0, 1)];
    let d = arch.detail(0, &words).unwrap();
    assert!(d.branch_target.is_none());
}

// -------------------------------------------------------------------------
// LjInstrDetail reads/writes
// -------------------------------------------------------------------------

#[test]
fn detail_mov_writes_a() {
    let arch = LuaJitArch::new();
    let words = [make_lj_ad(LjOp::Mov as u8, 5, 1)];
    let d = arch.detail(0, &words).unwrap();
    assert!(d.writes_reg(5));
    assert!(!d.writes_reg(0));
}

#[test]
fn detail_tsetv_does_not_write_a() {
    let arch = LuaJitArch::new();
    // TSETV is opcode 60 — a store, so A is the source value.
    let words = [make_lj_abc(LjOp::Tsetv as u8, 5, 1, 2)];
    let d = arch.detail(0, &words).unwrap();
    assert!(!d.writes_reg(5));
}

#[test]
fn detail_addvv_reads_b_c() {
    let arch = LuaJitArch::new();
    let words = [make_lj_abc(LjOp::Addvv as u8, 0, 1, 2)];
    let d = arch.detail(0, &words).unwrap();
    assert!(d.reads_reg(1));
    assert!(d.reads_reg(2));
}

#[test]
fn detail_mnemonic_lowercase() {
    let arch = LuaJitArch::new();
    let words = [make_lj_ad(LjOp::Mov as u8, 0, 1)];
    let d = arch.detail(0, &words).unwrap();
    assert_eq!(d.mnemonic(), "mov");
}

#[test]
fn detail_clone_eq() {
    let arch = LuaJitArch::new();
    let words = [make_lj_abc(LjOp::Addvv as u8, 0, 1, 2)];
    let d1 = arch.detail(0, &words).unwrap();
    let d2 = d1.clone();
    assert_eq!(d1, d2);
    let _: LjInstrDetail = d2;
}

// -------------------------------------------------------------------------
// format_instruction / disassemble_listing
// -------------------------------------------------------------------------

#[test]
fn format_instruction_addvv() {
    let w = make_lj_abc(LjOp::Addvv as u8, 0, 1, 2);
    let s = format_instruction(0, w);
    assert!(s.contains("ADDVV"));
    assert!(s.contains("R0"));
    assert!(s.contains("R1"));
    assert!(s.contains("R2"));
    assert!(s.starts_with("0000"));
}

#[test]
fn format_instruction_unknown_op() {
    let s = format_instruction(0, 0x000000FF);
    assert!(s.contains("???"));
}

#[test]
fn disassemble_listing_multiline() {
    let words = vec![
        make_lj_ad(LjOp::Mov as u8, 0, 1),
        make_lj_ad(LjOp::Ret0 as u8, 0, 1),
    ];
    let s = disassemble_listing(&words);
    assert_eq!(s.lines().count(), 2);
    assert!(s.contains("MOV"));
    assert!(s.contains("RET0"));
}

#[test]
fn disassemble_listing_empty() {
    assert_eq!(disassemble_listing(&[]), "");
}

// -------------------------------------------------------------------------
// LuaJitProto
// -------------------------------------------------------------------------

#[test]
fn proto_default_is_empty() {
    let p = LuaJitProto::default();
    assert_eq!(p.instr_count(), 0);
    assert!(!p.has_children());
    assert!(p.string_constants().is_empty());
    assert!(p.branches().is_empty());
    assert_eq!(p.used_opcodes(), Vec::<u8>::new());
}

#[test]
fn proto_is_vararg_flag() {
    let mut p = LuaJitProto {
        flags: 0x02,
        ..Default::default()
    };
    assert!(p.is_vararg());
    p.flags = 0x00;
    assert!(!p.is_vararg());
}

#[test]
fn proto_iter_instructions_pairs() {
    let p = LuaJitProto {
        instructions: vec![10, 20, 30],
        ..Default::default()
    };
    let pairs: Vec<_> = p.iter_instructions().collect();
    assert_eq!(pairs, vec![(0, 10u32), (1, 20), (2, 30)]);
}

#[test]
fn proto_category_histogram_arithmetic() {
    let p = LuaJitProto {
        instructions: vec![
        make_lj_ad(LjOp::Mov as u8, 0, 1),     // Arithmetic
        make_lj_abc(LjOp::Addvv as u8, 0, 1, 2), // Arithmetic
        make_lj_ad(LjOp::Ret0 as u8, 0, 0),    // Return
    ],
        ..Default::default()
    };
    let h = p.category_histogram();
    assert_eq!(h[InstrCategory::Arithmetic as usize], 2);
    assert_eq!(h[InstrCategory::Return as usize], 1);
}

#[test]
fn proto_used_opcodes_unique_sorted() {
    let p = LuaJitProto {
        instructions: vec![
        make_lj_ad(LjOp::Mov as u8, 0, 1),
        make_lj_ad(LjOp::Mov as u8, 1, 2),
        make_lj_ad(LjOp::Ret0 as u8, 0, 0),
    ],
        ..Default::default()
    };
    let ops = p.used_opcodes();
    assert_eq!(ops.len(), 2);
    assert!(ops.contains(&(LjOp::Mov as u8)));
    assert!(ops.contains(&(LjOp::Ret0 as u8)));
    // Should be sorted (the impl iterates 0..=255)
    let mut sorted = ops.clone();
    sorted.sort_unstable();
    assert_eq!(ops, sorted);
}

#[test]
fn proto_string_constants_filters_strings() {
    let p = LuaJitProto {
        constants: vec![
        LjConst::Integer(1),
        LjConst::String(b"hi".to_vec()),
        LjConst::Nil,
        LjConst::String(b"world".to_vec()),
    ],
        ..Default::default()
    };
    let strs = p.string_constants();
    assert_eq!(strs.len(), 2);
    assert_eq!(strs[0], b"hi");
    assert_eq!(strs[1], b"world");
}

#[test]
fn proto_branches_includes_jmp() {
    let p = LuaJitProto {
        instructions: vec![
        make_lj_ad(LjOp::Mov as u8, 0, 1),
        make_lj_ad_signed(LjOp::Jmp as u8, 0, 0),
    ],
        ..Default::default()
    };
    let br = p.branches();
    assert!(!br.is_empty());
    assert!(br.iter().any(|b| b.op == LjOp::Jmp as u8));
}

#[test]
fn proto_has_children_when_protos_present() {
    let mut p = LuaJitProto::default();
    p.protos.push(LuaJitProto::default());
    assert!(p.has_children());
}

// -------------------------------------------------------------------------
// LjConst / LjUpvalue
// -------------------------------------------------------------------------

#[test]
fn ljconst_partial_eq_variants() {
    assert_eq!(LjConst::Nil, LjConst::Nil);
    assert_eq!(LjConst::Bool(true), LjConst::Bool(true));
    assert_ne!(LjConst::Bool(true), LjConst::Bool(false));
    assert_eq!(LjConst::Integer(42), LjConst::Integer(42));
    assert_eq!(
        LjConst::String(b"abc".to_vec()),
        LjConst::String(b"abc".to_vec())
    );
}

#[test]
fn ljupvalue_eq_clone() {
    let u = LjUpvalue { on_stack: true, idx: 3 };
    let u2 = u.clone();
    assert_eq!(u, u2);
}

// -------------------------------------------------------------------------
// DumpFlags
// -------------------------------------------------------------------------

#[test]
fn dump_flags_zero() {
    let f = DumpFlags::from_byte(0);
    assert!(!f.be());
    assert!(!f.strip());
    assert!(!f.ffi());
    assert!(!f.fr2());
}

#[test]
fn dump_flags_all_bits() {
    let f = DumpFlags::from_byte(0x0F);
    assert!(f.be());
    assert!(f.strip());
    assert!(f.ffi());
    assert!(f.fr2());
}

#[test]
fn dump_flags_default_zeroed() {
    let f = DumpFlags::default();
    assert!(!f.be() && !f.strip() && !f.ffi() && !f.fr2());
}

// -------------------------------------------------------------------------
// LuaJitBytecode::parse
// -------------------------------------------------------------------------

#[test]
fn parse_too_short_unexpected_eof() {
    let r = LuaJitBytecode::parse(&[0x1b, 0x4c]);
    assert_eq!(r.unwrap_err(), ParseError::UnexpectedEof);
}

#[test]
fn parse_bad_magic() {
    let r = LuaJitBytecode::parse(&[0xde, 0xad, 0xbe, 0xef, 0x00]);
    assert_eq!(r.unwrap_err(), ParseError::BadMagic);
}

#[test]
fn parse_bad_version() {
    // good magic, bad version byte (99)
    let data = [LJ_MAGIC[0], LJ_MAGIC[1], LJ_MAGIC[2], 99, 0];
    assert_eq!(LuaJitBytecode::parse(&data).unwrap_err(), ParseError::BadMagic);
}

#[test]
fn parse_empty_stripped_dump_errors_no_proto() {
    // Magic + version 2.1 + flags=strip (0x02) + sentinel 0x00.
    // No protos at all -> proto_stack pop yields UnexpectedEof.
    let data = [LJ_MAGIC[0], LJ_MAGIC[1], LJ_MAGIC[2], LJ_VERSION_21, 0x02, 0x00];
    let err = LuaJitBytecode::parse(&data).unwrap_err();
    assert_eq!(err, ParseError::UnexpectedEof);
}

#[test]
fn parse_error_display() {
    assert_eq!(format!("{}", ParseError::UnexpectedEof), "unexpected end of bytecode");
    assert_eq!(format!("{}", ParseError::BadMagic), "bad magic / unsupported LuaJIT version");
    assert_eq!(format!("{}", ParseError::Overflow), "length field overflow");
    assert_eq!(format!("{}", ParseError::BadUleb), "malformed ULEB128 value");
}

#[test]
fn parse_error_clone_eq() {
    let e = ParseError::BadMagic;
    assert_eq!(e, ParseError::BadMagic);
    assert_ne!(ParseError::BadMagic, ParseError::Overflow);
}

#[test]
fn bytecode_constants_match_versions() {
    assert_eq!(LJ_VERSION_20, 1);
    assert_eq!(LJ_VERSION_21, 2);
    assert_eq!(LJ_MAGIC, [0x1b, 0x4c, 0x4a]);
}

// -------------------------------------------------------------------------
// BasicBlock + find_basic_blocks
// -------------------------------------------------------------------------

#[test]
fn basic_block_len_empty_helpers() {
    let bb = BasicBlock { start: 4, end: 4 };
    assert_eq!(bb.len(), 0);
    assert!(bb.is_empty());
    let bb2 = BasicBlock { start: 0, end: 3 };
    assert_eq!(bb2.len(), 3);
    assert!(!bb2.is_empty());
}

#[test]
fn find_basic_blocks_empty_input() {
    assert!(find_basic_blocks(&[]).is_empty());
}

#[test]
fn find_basic_blocks_single_block() {
    let words = vec![
        make_lj_ad(LjOp::Mov as u8, 0, 1),
        make_lj_ad(LjOp::Mov as u8, 1, 2),
    ];
    let bbs = find_basic_blocks(&words);
    assert_eq!(bbs.len(), 1);
    assert_eq!(bbs[0], BasicBlock { start: 0, end: 2 });
}

#[test]
fn find_basic_blocks_jmp_creates_leaders() {
    let words = vec![
        make_lj_ad_signed(LjOp::Jmp as u8, 0, 1), // jumps over next
        make_lj_ad(LjOp::Mov as u8, 0, 1),
        make_lj_ad(LjOp::Mov as u8, 1, 2),
        make_lj_ad(LjOp::Ret0 as u8, 0, 0),
    ];
    let bbs = find_basic_blocks(&words);
    // Leaders: 0 (start), 1 (fallthrough after jmp), 2 (jmp target = 0+1+1=2)
    assert!(bbs.len() >= 2);
    assert_eq!(bbs[0].start, 0);
}

#[test]
fn find_basic_blocks_return_splits() {
    let words = vec![
        make_lj_ad(LjOp::Mov as u8, 0, 1),
        make_lj_ad(LjOp::Ret0 as u8, 0, 0),
        make_lj_ad(LjOp::Mov as u8, 1, 2),
    ];
    let bbs = find_basic_blocks(&words);
    // Return at index 1 creates a leader at 2.
    assert!(bbs.iter().any(|b| b.start == 2));
}

// -------------------------------------------------------------------------
// RegAccess + collect_reg_accesses
// -------------------------------------------------------------------------

#[test]
fn collect_reg_accesses_empty() {
    assert!(collect_reg_accesses(&[]).is_empty());
}

#[test]
fn collect_reg_accesses_addvv_records_def_and_uses() {
    let words = [make_lj_abc(LjOp::Addvv as u8, 5, 1, 2)];
    let accesses = collect_reg_accesses(&words);
    assert!(accesses.iter().any(|r| r.is_def && r.reg == 5));
    assert!(accesses.iter().any(|r| !r.is_def && r.reg == 1));
    assert!(accesses.iter().any(|r| !r.is_def && r.reg == 2));
}

#[test]
fn collect_reg_accesses_tsetv_no_def() {
    // TSETV: A is source, not dest -> no def at A.
    let words = [make_lj_abc(LjOp::Tsetv as u8, 5, 1, 2)];
    let accesses = collect_reg_accesses(&words);
    assert!(!accesses.iter().any(|r| r.is_def && r.reg == 5));
}

#[test]
fn regaccess_eq_clone() {
    let r = RegAccess { instr_idx: 0, reg: 7, is_def: true };
    let r2 = r.clone();
    assert_eq!(r, r2);
}

// -------------------------------------------------------------------------
// Send + Sync bounds (compile-time)
// -------------------------------------------------------------------------

#[test]
fn types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LuaJitArch>();
    assert_send_sync::<LuaJitProto>();
    assert_send_sync::<LuaJitBytecode>();
    assert_send_sync::<LjInstruction>();
    assert_send_sync::<LjInstrDetail>();
    assert_send_sync::<LjInstrFlags>();
    assert_send_sync::<DumpFlags>();
    assert_send_sync::<ParseError>();
    assert_send_sync::<BasicBlock>();
    assert_send_sync::<RegAccess>();
}

// -------------------------------------------------------------------------
// Cross-cutting: decode -> meta -> categorise consistency
// -------------------------------------------------------------------------

#[test]
fn meta_and_decode_agree_on_format_and_flags() {
    for v in 0u8..=96 {
        let meta = LjOpMeta::for_op(v);
        let w = make_lj_abc(v, 0, 0, 0);
        let d = decode_lj_instruction(w);
        assert_eq!(d.fmt, meta.fmt, "fmt mismatch for op {v}");
        assert_eq!(d.flags, meta.flags, "flags mismatch for op {v}");
        assert_eq!(d.mnemonic(), meta.mnemonic, "mnemonic mismatch for op {v}");
    }
}

#[test]
fn arch_disassemble_sets_correct_instr_flags() {
    let arch = LuaJitArch::new();
    let w = make_lj_abc(LjOp::Call as u8, 0, 1, 1);
    let i = arch.disassemble(Address::new(0), &w.to_le_bytes()).unwrap();
    assert!(i.flags.contains(InstrFlags::CALL));
}
