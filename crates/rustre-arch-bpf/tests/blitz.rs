//! Exhaustive blitz tests for `rustre-arch-bpf`.
//!
//! Exercises the public surface: instruction decoding, disassembly, helper
//! tables, map/program type enums, cBPF, BTF, CO-RE, security analysis, ELF
//! object parsing, and the verifier simulator.

use std::collections::HashMap;

use rustre_arch_bpf::*;
use rustre_core::arch::{Architecture, InstrFlags};
use rustre_core::address::Address;

// -- helpers --------------------------------------------------------------

fn enc(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> Vec<u8> {
    let mut v = vec![op, (src << 4) | (dst & 0x0f)];
    v.extend_from_slice(&off.to_le_bytes());
    v.extend_from_slice(&imm.to_le_bytes());
    v
}

fn enc_lddw(dst: u8, value: i64) -> Vec<u8> {
    let lo = value as i32;
    let hi = (value >> 32) as i32;
    let mut v = enc(0x18, dst, 0, 0, lo);
    v.extend_from_slice(&[0u8; 4]);
    v.extend_from_slice(&hi.to_le_bytes());
    v
}

// ============================ BpfClass / BpfSize / BpfMode ===============

#[test]
fn class_roundtrip_all() {
    for op in 0u8..=7u8 {
        assert!(BpfClass::from_opcode(op).is_some(), "missing class for {op}");
    }
    assert_eq!(BpfClass::from_opcode(0x07), Some(BpfClass::Alu64));
    assert_eq!(BpfClass::from_opcode(0x05), Some(BpfClass::Jmp));
}

#[test]
fn class_name_nonempty() {
    let classes = [
        BpfClass::Ld, BpfClass::Ldx, BpfClass::St, BpfClass::Stx,
        BpfClass::Alu, BpfClass::Jmp, BpfClass::Alu64, BpfClass::Jmp32,
    ];
    for c in classes {
        assert!(c.name().starts_with("BPF_"));
    }
}

#[test]
fn size_roundtrip_bytes() {
    assert_eq!(BpfSize::from_opcode(0x00).unwrap().bytes(), 4);
    assert_eq!(BpfSize::from_opcode(0x08).unwrap().bytes(), 2);
    assert_eq!(BpfSize::from_opcode(0x10).unwrap().bytes(), 1);
    assert_eq!(BpfSize::from_opcode(0x18).unwrap().bytes(), 8);
}

#[test]
fn size_suffixes_distinct() {
    let s = [BpfSize::Word, BpfSize::Half, BpfSize::Byte, BpfSize::DWord];
    let names: Vec<_> = s.iter().map(|x| x.suffix()).collect();
    let unique: std::collections::HashSet<_> = names.iter().collect();
    assert_eq!(unique.len(), 4);
}

#[test]
fn mode_decode_all_known() {
    for m in [0x00u8, 0x20, 0x40, 0x60, 0xc0] {
        assert!(BpfMode::from_opcode(m).is_some());
    }
    // Unknown modes (e.g. XADD 0x80, RESERVED 0xa0, 0xe0) should yield None.
    assert_eq!(BpfMode::from_opcode(0x80), None);
    assert_eq!(BpfMode::from_opcode(0xa0), None);
    assert_eq!(BpfMode::from_opcode(0xe0), None);
}

// ============================ BpfAluOp / BpfJmpOp =========================

#[test]
fn alu_op_all_decode() {
    for code in (0u8..=0xd0).step_by(0x10) {
        assert!(BpfAluOp::from_opcode(code).is_some(), "missing alu op {code:#x}");
    }
    assert_eq!(BpfAluOp::from_opcode(0xe0), None);
}

#[test]
fn alu_op_mnemonics_distinct() {
    let ops = [
        BpfAluOp::Add, BpfAluOp::Sub, BpfAluOp::Mul, BpfAluOp::Div,
        BpfAluOp::Or, BpfAluOp::And, BpfAluOp::Lsh, BpfAluOp::Rsh,
        BpfAluOp::Neg, BpfAluOp::Mod, BpfAluOp::Xor, BpfAluOp::Mov,
        BpfAluOp::Arsh, BpfAluOp::End,
    ];
    let mnes: std::collections::HashSet<_> = ops.iter().map(|o| o.mnemonic()).collect();
    assert_eq!(mnes.len(), ops.len());
}

#[test]
fn jmp_op_conditional_classification() {
    assert!(!BpfJmpOp::Ja.is_conditional());
    assert!(!BpfJmpOp::Call.is_conditional());
    assert!(!BpfJmpOp::Exit.is_conditional());
    assert!(BpfJmpOp::Jeq.is_conditional());
    assert!(BpfJmpOp::Jsle.is_conditional());
}

#[test]
fn jmp_op_all_decode_and_distinct_mnemonics() {
    let ops = [
        0x00u8,0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,0x90,0xa0,0xb0,0xc0,0xd0,
    ];
    let mut seen = std::collections::HashSet::new();
    for c in ops {
        let o = BpfJmpOp::from_opcode(c).unwrap();
        seen.insert(o.mnemonic());
    }
    assert_eq!(seen.len(), ops.len());
    assert_eq!(BpfJmpOp::from_opcode(0xe0), None);
}

// ============================ BpfInstruction decode ======================

#[test]
fn decode_truncated_empty() {
    assert_eq!(BpfInstruction::decode(&[]), Err(BpfDecodeError::Truncated));
}

#[test]
fn decode_truncated_7_bytes() {
    assert_eq!(
        BpfInstruction::decode(&[0u8; 7]),
        Err(BpfDecodeError::Truncated)
    );
}

#[test]
fn decode_8_bytes_consumes_8() {
    let bytes = enc(0x07, 1, 0, 0, 123);
    let (i, sz) = BpfInstruction::decode(&bytes).unwrap();
    assert_eq!(sz, 8);
    assert_eq!(i.imm, 123);
    assert_eq!(i.dst_reg, 1);
    assert!(i.wide_imm.is_none());
}

#[test]
fn decode_lddw_full_wide_imm() {
    let bytes = enc_lddw(2, 0x1122_3344_5566_7788);
    let (i, sz) = BpfInstruction::decode(&bytes).unwrap();
    assert_eq!(sz, 16);
    assert_eq!(i.wide_imm, Some(0x1122_3344_5566_7788));
    assert_eq!(i.dst_reg, 2);
}

#[test]
fn decode_lddw_truncated_at_15() {
    let mut bytes = enc_lddw(0, 1);
    bytes.truncate(15);
    assert_eq!(
        BpfInstruction::decode(&bytes),
        Err(BpfDecodeError::Truncated)
    );
}

#[test]
fn decode_offset_negative_preserved() {
    let bytes = enc(0x05, 0, 0, -7, 0);
    let (i, _) = BpfInstruction::decode(&bytes).unwrap();
    assert_eq!(i.offset, -7);
}

#[test]
fn decode_class_helper() {
    let (i, _) = BpfInstruction::decode(&enc(0x95, 0, 0, 0, 0)).unwrap();
    assert_eq!(i.class(), Some(BpfClass::Jmp));
}

#[test]
fn decode_extra_bytes_not_consumed() {
    let mut bytes = enc(0x07, 0, 0, 0, 1);
    bytes.extend_from_slice(&[0xff; 8]);
    let (_, sz) = BpfInstruction::decode(&bytes).unwrap();
    assert_eq!(sz, 8);
}

// ============================ reg_name ==================================

#[test]
fn reg_name_known_and_unknown() {
    assert_eq!(reg_name(0), "r0");
    assert_eq!(reg_name(10), "r10");
    assert_eq!(reg_name(11), "r?");
    assert_eq!(reg_name(255), "r?");
}

// ============================ disasm_instr ==============================

fn helpers() -> HashMap<i32, &'static str> { known_helpers() }

#[test]
fn disasm_unknown_opcode_returns_err() {
    // class 0x07 (Alu64) but with reserved code 0xe0 -> UnknownOpcode
    let bytes = enc(0xe7, 0, 0, 0, 0);
    let (i, _) = BpfInstruction::decode(&bytes).unwrap();
    assert!(matches!(
        disasm_instr(&i, &helpers()),
        Err(BpfDecodeError::UnknownOpcode(_))
    ));
}

#[test]
fn disasm_call_known_helper_contains_name() {
    let bytes = enc(0x85, 0, 0, 0, 1);
    let (i, _) = BpfInstruction::decode(&bytes).unwrap();
    let (mne, ops, flags) = disasm_instr(&i, &helpers()).unwrap();
    assert_eq!(mne, "call");
    assert!(ops.contains("bpf_map_lookup_elem"));
    assert!(flags.contains(InstrFlags::CALL));
}

#[test]
fn disasm_exit_flag_ret() {
    let (i, _) = BpfInstruction::decode(&enc(0x95, 0, 0, 0, 0)).unwrap();
    let (mne, _, flags) = disasm_instr(&i, &helpers()).unwrap();
    assert_eq!(mne, "exit");
    assert!(flags.contains(InstrFlags::RET));
}

#[test]
fn disasm_ja_branch_not_conditional() {
    let (i, _) = BpfInstruction::decode(&enc(0x05, 0, 0, 1, 0)).unwrap();
    let (mne, _, flags) = disasm_instr(&i, &helpers()).unwrap();
    assert_eq!(mne, "ja");
    assert!(flags.contains(InstrFlags::BRANCH));
    assert!(!flags.contains(InstrFlags::CONDITIONAL));
}

#[test]
fn disasm_jeq_conditional() {
    let (i, _) = BpfInstruction::decode(&enc(0x15, 1, 0, 5, 42)).unwrap();
    let (mne, _, flags) = disasm_instr(&i, &helpers()).unwrap();
    assert_eq!(mne, "jeq");
    assert!(flags.contains(InstrFlags::CONDITIONAL));
    assert!(flags.contains(InstrFlags::BRANCH));
}

#[test]
fn disasm_alu32_suffix() {
    let (i, _) = BpfInstruction::decode(&enc(0x04, 0, 0, 0, 1)).unwrap();
    let (mne, _, _) = disasm_instr(&i, &helpers()).unwrap();
    assert_eq!(mne, "add32");
}

#[test]
fn disasm_ldx_mem_word_read() {
    // LDX | MEM | W = 0x01 | 0x60 | 0x00 = 0x61
    let (i, _) = BpfInstruction::decode(&enc(0x61, 1, 2, 4, 0)).unwrap();
    let (mne, _, flags) = disasm_instr(&i, &helpers()).unwrap();
    assert!(mne.starts_with("ldx"));
    assert!(flags.contains(InstrFlags::READ_MEM));
}

#[test]
fn disasm_stx_mem_word_write() {
    // STX | MEM | W = 0x03 | 0x60 | 0x00 = 0x63
    let (i, _) = BpfInstruction::decode(&enc(0x63, 1, 2, 0, 0)).unwrap();
    let (_, _, flags) = disasm_instr(&i, &helpers()).unwrap();
    assert!(flags.contains(InstrFlags::WRITE_MEM));
}

#[test]
fn disasm_lddw_format() {
    let bytes = enc_lddw(3, 0x1234_5678);
    let (i, _) = BpfInstruction::decode(&bytes).unwrap();
    let (mne, ops, _) = disasm_instr(&i, &helpers()).unwrap();
    assert_eq!(mne, "lddw");
    assert!(ops.contains("r3"));
}

// ============================ known_helpers =============================

#[test]
fn known_helpers_includes_classics() {
    let h = known_helpers();
    assert_eq!(h.get(&1).copied(), Some("bpf_map_lookup_elem"));
    assert_eq!(h.get(&2).copied(), Some("bpf_map_update_elem"));
    assert_eq!(h.get(&3).copied(), Some("bpf_map_delete_elem"));
    assert_eq!(h.get(&12).copied(), Some("bpf_tail_call"));
}

#[test]
fn known_helpers_size_reasonable() {
    let h = known_helpers();
    assert!(h.len() >= 200, "expected 200+, got {}", h.len());
}

// ============================ BpfMapType / BpfProgType ==================

#[test]
fn map_type_u32_roundtrip_all() {
    for v in 0u32..=32u32 {
        let t = BpfMapType::from_u32(v).unwrap_or_else(|| panic!("missing {v}"));
        assert!(t.name().starts_with("BPF_MAP_TYPE_"));
    }
    assert!(BpfMapType::from_u32(33).is_none());
    assert!(BpfMapType::from_u32(u32::MAX).is_none());
}

#[test]
fn prog_type_names_distinct() {
    let pts = [
        BpfProgType::Unspec, BpfProgType::SocketFilter, BpfProgType::Kprobe,
        BpfProgType::Xdp, BpfProgType::Syscall,
    ];
    let names: std::collections::HashSet<_> = pts.iter().map(|p| p.name()).collect();
    assert_eq!(names.len(), pts.len());
    assert_eq!(BpfProgType::Xdp.name(), "BPF_PROG_TYPE_XDP");
}

// ============================ cBPF ======================================

#[test]
fn cbpf_class_decode_range() {
    for v in 0u16..=7u16 {
        assert!(CbpfOpClass::from_op(v).is_some());
    }
}

#[test]
fn cbpf_instruction_decode_basic() {
    let mut bytes = vec![0x06u8, 0x00, 0x00, 0x00];
    bytes.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    let i = CbpfInstruction::decode(&bytes).unwrap();
    assert_eq!(i.opcode, 0x06);
    assert_eq!(i.k, 0xffff_ffff);
    assert!(i.disasm().contains("RET"));
}

#[test]
fn cbpf_instruction_decode_truncated() {
    assert!(CbpfInstruction::decode(&[0u8; 7]).is_err());
}

#[test]
fn cbpf_disasm_tax_txa() {
    // class=MISC (7), misc_code = 0 -> TAX
    let tax = CbpfInstruction { opcode: 0x07, jt: 0, jf: 0, k: 0 };
    assert_eq!(tax.disasm(), "TAX");
    // misc_code=0x80 -> TXA
    let txa = CbpfInstruction { opcode: 0x87, jt: 0, jf: 0, k: 0 };
    assert_eq!(txa.disasm(), "TXA");
}

// ============================ BtfKind / BtfTypeHeader ===================

#[test]
fn btf_kind_roundtrip() {
    for v in 1u32..=19u32 {
        let k = BtfKind::from_u32(v).unwrap_or_else(|| panic!("missing kind {v}"));
        assert!(!k.name().is_empty());
    }
    assert!(BtfKind::from_u32(0).is_none());
    assert!(BtfKind::from_u32(20).is_none());
}

#[test]
fn btf_type_header_decode_and_fields() {
    let kind = 4u32; // STRUCT
    let vlen = 3u32;
    let info = (kind << 24) | vlen;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&42u32.to_le_bytes()); // name_off
    bytes.extend_from_slice(&info.to_le_bytes());
    bytes.extend_from_slice(&12u32.to_le_bytes()); // size
    let h = BtfTypeHeader::decode(&bytes).unwrap();
    assert_eq!(h.name_off, 42);
    assert_eq!(h.size_or_type, 12);
    assert_eq!(h.kind(), Some(BtfKind::Struct));
    assert_eq!(h.vlen(), 3);
    assert!(!h.kind_flag());
}

#[test]
fn btf_type_header_kind_flag_bit() {
    let info = (1u32 << 24) | (1u32 << 31);
    let mut bytes = vec![0u8; 4];
    bytes.extend_from_slice(&info.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 4]);
    let h = BtfTypeHeader::decode(&bytes).unwrap();
    assert!(h.kind_flag());
}

#[test]
fn btf_type_header_truncated() {
    assert!(BtfTypeHeader::decode(&[0u8; 11]).is_err());
}

// ============================ BpfArch / Architecture trait ==============

#[test]
fn arch_basic_attributes() {
    let a = BpfArch::new_ebpf();
    assert_eq!(a.name(), "ebpf");
    assert_eq!(a.pointer_size(), 8);
    let cb = BpfArch::new_cbpf();
    assert_eq!(cb.name(), "cbpf");
    assert!(a.helper_count() >= 200);
    assert_eq!(a.helper_name(1), Some("bpf_map_lookup_elem"));
    assert_eq!(a.helper_name(99_999), None);
}

#[test]
fn arch_default_is_ebpf() {
    let a = BpfArch::default();
    assert_eq!(a.name(), "ebpf");
}

#[test]
fn arch_all_helpers_sorted() {
    let a = BpfArch::new_ebpf();
    let all = a.all_helpers();
    for w in all.windows(2) {
        assert!(w[0].0 <= w[1].0);
    }
}

#[test]
fn arch_disassemble_exit() {
    let a = BpfArch::new_ebpf();
    let bytes = enc(0x95, 0, 0, 0, 0);
    let instr = a.disassemble(Address::new(0), &bytes).unwrap();
    assert_eq!(instr.mnemonic, "exit");
    assert!(instr.flags.contains(InstrFlags::RET));
}

#[test]
fn arch_registers_count_11() {
    let a = BpfArch::new_ebpf();
    let regs = a.registers();
    assert_eq!(regs.len(), 11);
}

#[test]
fn arch_calling_conventions_ebpf_call() {
    let a = BpfArch::new_ebpf();
    let cc = a.calling_conventions();
    assert_eq!(cc.len(), 1);
}

#[test]
fn arch_get_branches_for_call_is_empty() {
    let a = BpfArch::new_ebpf();
    let bytes = enc(0x85, 0, 0, 0, 1);
    let instr = a.disassemble(Address::new(0), &bytes).unwrap();
    assert!(a.get_branches(&instr).is_empty());
}

#[test]
fn arch_get_branches_for_unconditional_jump() {
    let a = BpfArch::new_ebpf();
    let bytes = enc(0x05, 0, 0, 2, 0);
    let instr = a.disassemble(Address::new(0x100), &bytes).unwrap();
    let br = a.get_branches(&instr);
    assert_eq!(br.len(), 1);
}

// ============================ Linear disassembler =======================

#[test]
fn linear_disasm_two_instrs() {
    let a = BpfArch::new_ebpf();
    let mut bytes = enc(0xb7, 0, 0, 0, 42); // mov64 r0, 42
    bytes.extend_from_slice(&enc(0x95, 0, 0, 0, 0)); // exit
    let dis = BpfLinearDisassembler::new(&a, &bytes, Address::new(0));
    let res: Vec<_> = dis.collect();
    assert_eq!(res.len(), 2);
    assert!(res.iter().all(std::result::Result::is_ok));
}

#[test]
fn linear_disasm_offset_advances() {
    let a = BpfArch::new_ebpf();
    let bytes = enc(0x95, 0, 0, 0, 0);
    let mut dis = BpfLinearDisassembler::new(&a, &bytes, Address::new(10));
    assert_eq!(dis.offset(), 0);
    assert_eq!(dis.current_address(), Address::new(10));
    let _ = dis.next();
    assert_eq!(dis.offset(), 8);
    assert_eq!(dis.current_address(), Address::new(18));
}

#[test]
fn linear_disasm_on_bad_byte_advances_one() {
    let a = BpfArch::new_ebpf();
    // 0xff is not a known opcode top-half for class 0x07 (alu64) but
    // 0xff & 7 = 7 (alu64); alu64 code 0xf0 is unknown -> error.
    let bytes = vec![0xffu8; 8];
    let mut dis = BpfLinearDisassembler::new(&a, &bytes, Address::new(0));
    let r = dis.next().unwrap();
    assert!(r.is_err());
    // On error, exactly one byte should have been consumed.
    assert_eq!(dis.offset(), 1);
}

// ============================ BpfProgramStats ===========================

#[test]
fn program_stats_counts_exit() {
    let a = BpfArch::new_ebpf();
    let mut bytes = enc(0xb7, 0, 0, 0, 0);
    bytes.extend_from_slice(&enc(0x95, 0, 0, 0, 0));
    let s = BpfProgramStats::from_bytes(&a, &bytes).unwrap();
    assert_eq!(s.instruction_count, 2);
    assert!(s.has_exit);
}

#[test]
fn program_stats_counts_branches() {
    let a = BpfArch::new_ebpf();
    let mut bytes = enc(0x15, 1, 0, 1, 0); // jeq cond
    bytes.extend_from_slice(&enc(0x05, 0, 0, 0, 0)); // ja unconditional
    bytes.extend_from_slice(&enc(0x95, 0, 0, 0, 0)); // exit
    let s = BpfProgramStats::from_bytes(&a, &bytes).unwrap();
    assert_eq!(s.conditional_branch_count, 1);
    assert_eq!(s.unconditional_branch_count, 1);
}

#[test]
fn program_stats_default_empty() {
    let s = BpfProgramStats::default();
    assert_eq!(s.instruction_count, 0);
    assert!(!s.has_exit);
}

// ============================ XdpAction =================================

#[test]
fn xdp_action_roundtrip() {
    for v in 0u32..=4u32 {
        let a = XdpAction::from_u32(v).unwrap();
        assert!(a.name().starts_with("XDP_"));
    }
    assert!(XdpAction::from_u32(5).is_none());
}

// ============================ MapOp / SkFilterAction ====================

#[test]
fn map_op_names() {
    assert_eq!(MapOp::Lookup.name(), "lookup");
    assert_eq!(MapOp::Update.name(), "update");
    assert_eq!(MapOp::Delete.name(), "delete");
    assert_eq!(MapOp::GetNextKey.name(), "get_next_key");
}

#[test]
fn sk_filter_action_variants() {
    let a = SkFilterAction::Accept(64);
    if let SkFilterAction::Accept(n) = a { assert_eq!(n, 64); } else { panic!() }
    let d = SkFilterAction::Drop;
    assert_eq!(d, SkFilterAction::Drop);
}

// ============================ BpfProgramAnalyzer ========================

#[test]
fn analyzer_detects_map_lookup() {
    // lddw r1, 1 ; call 1 (lookup); exit
    let mut prog = enc_lddw(1, 1);
    prog.extend_from_slice(&enc(0x85, 0, 0, 0, 1));
    prog.extend_from_slice(&enc(0x95, 0, 0, 0, 0));
    let r = BpfProgramAnalyzer::analyze(&prog);
    assert!(r.instruction_count >= 2);
    assert_eq!(r.helper_calls, vec![1]);
    assert_eq!(r.map_accesses.len(), 1);
    assert_eq!(r.map_accesses[0].operation, MapOp::Lookup);
}

#[test]
fn analyzer_security_note_for_probe_write_user() {
    // call helper 28 (bpf_probe_write_user per analyzer's mapping)
    let mut prog = enc(0x85, 0, 0, 0, 28);
    prog.extend_from_slice(&enc(0x95, 0, 0, 0, 0));
    let r = BpfProgramAnalyzer::analyze(&prog);
    assert!(r.security_notes.iter().any(|n| n.contains("probe_write_user")));
}

#[test]
fn analyzer_detects_backward_branch_as_loop() {
    let mut prog = enc(0xb7, 0, 0, 0, 0); // mov64 r0,0
    prog.extend_from_slice(&enc(0x15, 0, 0, -2, 0)); // jeq backward
    prog.extend_from_slice(&enc(0x95, 0, 0, 0, 0));
    let r = BpfProgramAnalyzer::analyze(&prog);
    assert!(r.uses_loops);
}

#[test]
fn analyzer_complexity_baseline_1() {
    let prog = enc(0x95, 0, 0, 0, 0);
    let r = BpfProgramAnalyzer::analyze(&prog);
    assert_eq!(r.complexity, 1);
}

#[test]
fn analyzer_empty_program_no_panic() {
    let r = BpfProgramAnalyzer::analyze(&[]);
    assert_eq!(r.instruction_count, 0);
    assert_eq!(r.complexity, 1);
}

// ============================ BpfVerifierSimulator ======================

#[test]
fn verifier_detects_invalid_register() {
    let (mut i, _) = BpfInstruction::decode(&enc(0x07, 0, 0, 0, 0)).unwrap();
    i.dst_reg = 11;
    let errs = BpfVerifierSimulator::check_bounds(&[i]);
    assert!(errs.iter().any(|e| e.message.contains("invalid dst")));
}

#[test]
fn verifier_detects_stack_oob_store() {
    // STX r10, +4, r1 -> offset 4 > 0 -> out of bounds
    let (i, _) = BpfInstruction::decode(&enc(0x63, 10, 1, 4, 0)).unwrap();
    let errs = BpfVerifierSimulator::check_bounds(&[i]);
    assert!(errs.iter().any(|e| e.message.contains("stack access out of bounds")));
}

#[test]
fn verifier_accepts_in_bounds_stack_store() {
    let (i, _) = BpfInstruction::decode(&enc(0x63, 10, 1, -8, 0)).unwrap();
    let errs = BpfVerifierSimulator::check_bounds(&[i]);
    assert!(errs.is_empty());
}

#[test]
fn verifier_detects_backward_branch() {
    let (i, _) = BpfInstruction::decode(&enc(0x15, 0, 0, -1, 0)).unwrap();
    let errs = BpfVerifierSimulator::check_bounds(&[i]);
    assert!(errs.iter().any(|e| e.message.contains("backward")));
}

// ============================ BpfDisassembler (text) ====================

#[test]
fn disassembler_text_includes_exit_marker() {
    let bytes = enc(0x95, 0, 0, 0, 0);
    let helpers_full = all_helpers();
    let text = BpfDisassembler::disassemble(&bytes, &helpers_full);
    assert!(text.contains("exit"));
}

#[test]
fn disassembler_text_handles_lddw() {
    let bytes = enc_lddw(1, 0x4242);
    let helpers_full = all_helpers();
    let text = BpfDisassembler::disassemble(&bytes, &helpers_full);
    assert!(text.contains("ll") || text.contains("LDDW"));
}

// ============================ BpfObjectParser ===========================

#[test]
fn obj_parser_rejects_non_elf() {
    let r = BpfObjectParser::parse_elf(b"\x00\x00\x00\x00xxx");
    assert_eq!(r.err(), Some(BpfObjectError::NotElf));
}

#[test]
fn obj_parser_rejects_truncated_magic() {
    let r = BpfObjectParser::parse_elf(&[0x7f, b'E']);
    assert_eq!(r.err(), Some(BpfObjectError::NotElf));
}

#[test]
fn obj_parser_rejects_elf32() {
    // ELF magic + EI_CLASS=1 (32-bit) -> MalformedElf
    let mut d = vec![0u8; 64];
    d[0..4].copy_from_slice(b"\x7fELF");
    d[4] = 1; // 32-bit
    d[5] = 1;
    let r = BpfObjectParser::parse_elf(&d);
    assert!(matches!(r, Err(BpfObjectError::MalformedElf(_))));
}

#[test]
fn obj_parser_rejects_big_endian() {
    let mut d = vec![0u8; 64];
    d[0..4].copy_from_slice(b"\x7fELF");
    d[4] = 2;
    d[5] = 2; // BE
    let r = BpfObjectParser::parse_elf(&d);
    assert!(matches!(r, Err(BpfObjectError::MalformedElf(_))));
}

#[test]
fn obj_parser_rejects_wrong_machine() {
    // Valid ELF64 LE but e_type/e_machine wrong.
    let mut d = vec![0u8; 64];
    d[0..4].copy_from_slice(b"\x7fELF");
    d[4] = 2; d[5] = 1;
    // e_type at 16 = 1 (REL)
    d[16] = 1;
    // e_machine at 18 = 3 (i386) - should fail
    d[18] = 3;
    let r = BpfObjectParser::parse_elf(&d);
    assert!(matches!(r, Err(BpfObjectError::MalformedElf(_))));
}

// ============================ BtfParser =================================

#[test]
fn btf_parser_constants() {
    assert_eq!(BTF_MAGIC, 0xEB9F);
    assert_eq!(BTF_VERSION, 1);
}

#[test]
fn btf_parser_is_valid_correct_header() {
    let mut blob = vec![0u8; 24];
    blob[0..2].copy_from_slice(&0xEB9Fu16.to_le_bytes());
    blob[2] = 1;
    assert!(BtfParser::is_valid(&blob));
}

#[test]
fn btf_parser_is_valid_bad_magic() {
    let blob = [0u8; 24];
    assert!(!BtfParser::is_valid(&blob));
}

#[test]
fn btf_parser_is_valid_bad_version() {
    let mut blob = vec![0u8; 24];
    blob[0..2].copy_from_slice(&0xEB9Fu16.to_le_bytes());
    blob[2] = 99;
    assert!(!BtfParser::is_valid(&blob));
}

#[test]
fn btf_parser_count_types_invalid_returns_zero() {
    assert_eq!(BtfParser::count_types(&[]), 0);
    assert_eq!(BtfParser::count_types(&[0u8; 4]), 0);
}

#[test]
fn btf_parser_find_section_non_elf_none() {
    assert!(BtfParser::find_btf_section(&[]).is_none());
    assert!(BtfParser::find_btf_section(b"not elf").is_none());
}

// ============================ helper lookups (full table) ===============

#[test]
fn lookup_helper_unspec_unknown_high() {
    // id 1 should resolve to the first real helper
    assert!(lookup_helper(1).is_some());
    assert!(lookup_helper(99_999).is_none());
}

#[test]
fn lookup_helper_by_name_known() {
    let r = lookup_helper_by_name("bpf_map_lookup_elem");
    assert!(r.is_some());
    assert!(lookup_helper_by_name("totally_made_up").is_none());
}

#[test]
fn pkt_access_iter_subset_of_all() {
    let all = all_helpers().len();
    let pa = pkt_access_helpers().count();
    assert!(pa <= all);
}

#[test]
fn sleepable_iter_subset_of_all() {
    let all = all_helpers().len();
    let sl = sleepable_helpers().count();
    assert!(sl <= all);
}

// ============================ Severity ordering =========================

#[test]
fn severity_ordering_increases() {
    assert!(Severity::Info < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn severity_label_distinct() {
    let s = [Severity::Info, Severity::Low, Severity::Medium, Severity::High, Severity::Critical];
    let labels: std::collections::HashSet<_> = s.iter().map(|x| x.label()).collect();
    assert_eq!(labels.len(), s.len());
}

// ============================ CoreRelocKind =============================

#[test]
fn core_reloc_kind_roundtrip() {
    for v in 0u32..=11u32 {
        let k = CoreRelocKind::from_u32(v).unwrap();
        assert!(!k.name().is_empty());
    }
    assert!(CoreRelocKind::from_u32(12).is_none());
}

// ============================ extract_map_usages ========================

#[test]
fn extract_map_usages_empty_input() {
    let usages = extract_map_usages(&[]);
    assert!(usages.is_empty());
}

#[test]
fn extract_map_usages_detects_update_after_lddw() {
    // lddw r1, fd ; call 2 (update)
    let bytes_lddw = enc_lddw(1, 0x1000);
    let (i0, _) = BpfInstruction::decode(&bytes_lddw).unwrap();
    let (i1, _) = BpfInstruction::decode(&enc(0x85, 0, 0, 0, 2)).unwrap();
    let usages = extract_map_usages(&[i0, i1]);
    assert_eq!(usages.len(), 1);
    assert_eq!(usages[0].operation, MapOp::Update);
    assert_eq!(usages[0].map_reg, 1);
}

// ============================ BpfVariant ================================

#[test]
fn bpf_variant_eq_hash() {
    assert_eq!(BpfVariant::Classic, BpfVariant::Classic);
    assert_ne!(BpfVariant::Classic, BpfVariant::Extended);
}

// ============================ BpfRegType.name ===========================

#[test]
fn reg_type_names_distinct() {
    let types = [
        BpfRegType::NotInit, BpfRegType::Scalar, BpfRegType::PtrToCtx,
        BpfRegType::PtrToStack, BpfRegType::PtrToPacket, BpfRegType::PtrToMapValue,
    ];
    let names: std::collections::HashSet<_> = types.iter().map(|t| t.name()).collect();
    assert_eq!(names.len(), types.len());
}

// ============================ cbpf_to_ebpf module API ===================

#[test]
fn cbpf_to_ebpf_accept_all_roundtrip() {
    use rustre_arch_bpf::cbpf_to_ebpf::*;
    let cbpf = cbpf_accept_all();
    let (ebpf, report) = migration_report(&cbpf);
    assert!(report.success);
    assert!(!ebpf.is_empty());
    assert_eq!(report.cbpf_insn_count, 1);
}

#[test]
fn cbpf_to_ebpf_filter_ipv4_expansion() {
    use rustre_arch_bpf::cbpf_to_ebpf::*;
    let cbpf = cbpf_filter_ipv4();
    let (ebpf, report) = migration_report(&cbpf);
    assert!(report.success);
    assert!(ebpf.len() >= cbpf.len());
    assert!(report.expansion_ratio >= 1.0);
}

#[test]
fn cbpf_to_ebpf_insn_map_within_bounds() {
    use rustre_arch_bpf::cbpf_to_ebpf::*;
    let cbpf = cbpf_filter_ipv4();
    let (ebpf, report) = migration_report(&cbpf);
    for &idx in &report.insn_map {
        assert!(idx < ebpf.len());
    }
    // ebpf_range_for should produce valid ranges
    for i in 0..cbpf.len() {
        let (s, e) = report.ebpf_range_for(i).expect("range");
        assert!(s <= e);
        assert!(e <= ebpf.len());
    }
}

#[test]
fn ebpf_insn_to_bytes_layout() {
    use rustre_arch_bpf::cbpf_to_ebpf::EbpfInsn;
    let i = EbpfInsn::new(0xB7, 3, 5, -1, 0x1234_5678);
    let b = i.to_bytes();
    assert_eq!(b[0], 0xB7);
    assert_eq!(b[1] & 0x0f, 3);
    assert_eq!((b[1] >> 4) & 0x0f, 5);
    assert_eq!(i16::from_le_bytes([b[2], b[3]]), -1);
    assert_eq!(i32::from_le_bytes([b[4], b[5], b[6], b[7]]), 0x1234_5678);
}

#[test]
fn cbpf_insn_display_format() {
    use rustre_arch_bpf::cbpf_to_ebpf::CbpfInsn;
    let i = CbpfInsn::new(0x06, 0, 0, 0xff);
    let s = format!("{i}");
    assert!(s.contains("cBPF"));
    assert!(s.contains("000000ff"));
}

// ============================ Send/Sync invariants ======================

#[test]
fn arch_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<BpfArch>();
    assert_send_sync::<BpfInstruction>();
    assert_send_sync::<BpfDecodeError>();
    assert_send_sync::<BpfMapType>();
}

// ============================ Debug/Display on errors ===================

#[test]
fn decode_error_display_truncated() {
    let e = BpfDecodeError::Truncated;
    assert_eq!(format!("{e}"), "truncated eBPF instruction");
}

#[test]
fn decode_error_display_unknown_opcode_hex() {
    let e = BpfDecodeError::UnknownOpcode(0xab);
    assert_eq!(format!("{e}"), "unknown opcode: 0xab");
}

#[test]
fn obj_error_display_not_elf() {
    assert_eq!(format!("{}", BpfObjectError::NotElf), "not an ELF file");
}
