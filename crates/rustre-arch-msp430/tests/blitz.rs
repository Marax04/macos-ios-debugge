//! Exhaustive blitz tests for `rustre-arch-msp430` lib.rs public API.
//! Focus: addressing modes, constant generator, ALU, emulator semantics,
//! encoder/decoder round-trips, MSP430X extension helpers, CFG.

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_msp430::{
    AddrMode, AluResult, BasicBlock, FlatMemory, InterruptVector, Msp430Arch,
    Msp430Emulator, Msp430LinearDisassembler, RegisterFile, alu_add, alu_addc, alu_and, alu_bis,
    alu_rra, alu_rrc, alu_sub, alu_subc, alu_swpb, alu_sxt, alu_xor, build_cfg, bw_suffix,
    check_emulated, constant_generator, decode, encode_jump, encode_single_op, encode_two_op,
    format_dst, format_src, msp430x, reg_name, regs, sr_bits, src_addr_mode,
};
use rustre_core::address::Address;

// ── AddrMode ─────────────────────────────────────────────────────────────────

#[test]
fn addrmode_ext_words_register_indirect_constant_zero() {
    assert_eq!(AddrMode::Register.ext_words(), 0);
    assert_eq!(AddrMode::Indirect.ext_words(), 0);
    assert_eq!(AddrMode::IndirectAutoInc.ext_words(), 0);
    assert_eq!(AddrMode::Constant(5).ext_words(), 0);
}

#[test]
fn addrmode_ext_words_memory_modes_one() {
    assert_eq!(AddrMode::Indexed.ext_words(), 1);
    assert_eq!(AddrMode::Absolute.ext_words(), 1);
    assert_eq!(AddrMode::Immediate.ext_words(), 1);
    assert_eq!(AddrMode::Symbolic.ext_words(), 1);
}

#[test]
fn addrmode_name_all_variants() {
    assert_eq!(AddrMode::Register.name(), "Register");
    assert_eq!(AddrMode::Indexed.name(), "Indexed");
    assert_eq!(AddrMode::Absolute.name(), "Absolute");
    assert_eq!(AddrMode::Indirect.name(), "Indirect");
    assert_eq!(AddrMode::IndirectAutoInc.name(), "IndirectAutoInc");
    assert_eq!(AddrMode::Immediate.name(), "Immediate");
    assert_eq!(AddrMode::Constant(0).name(), "Constant");
    assert_eq!(AddrMode::Symbolic.name(), "Symbolic");
}

#[test]
fn addrmode_symbolic_writes_memory() {
    assert!(AddrMode::Symbolic.writes_memory());
}

// ── constant_generator ───────────────────────────────────────────────────────

#[test]
fn cg_sr_modes_not_constant() {
    assert_eq!(constant_generator(2, 0), None);
    assert_eq!(constant_generator(2, 1), None);
}

#[test]
fn cg_all_general_regs_no_constant() {
    for r in 4u8..=15 {
        for a in 0u8..=3 {
            assert_eq!(constant_generator(r, a), None, "r={r} a={a}");
        }
    }
}

// ── src_addr_mode ────────────────────────────────────────────────────────────

#[test]
fn src_mode_as0_register() {
    assert_eq!(src_addr_mode(0, 4), AddrMode::Register);
}

#[test]
fn src_mode_as1_reg2_is_absolute() {
    assert_eq!(src_addr_mode(1, 2), AddrMode::Absolute);
}

#[test]
fn src_mode_as1_other_is_indexed() {
    // r0 with as=1: not absolute, must be Indexed (symbolic, but lib calls it Indexed).
    assert_eq!(src_addr_mode(1, 0), AddrMode::Indexed);
    assert_eq!(src_addr_mode(1, 5), AddrMode::Indexed);
}

#[test]
fn src_mode_as2_indirect() {
    assert_eq!(src_addr_mode(2, 4), AddrMode::Indirect);
}

#[test]
fn src_mode_as3_reg0_immediate() {
    assert_eq!(src_addr_mode(3, 0), AddrMode::Immediate);
}

#[test]
fn src_mode_as3_other_autoinc() {
    assert_eq!(src_addr_mode(3, 4), AddrMode::IndirectAutoInc);
}

#[test]
fn src_mode_constant_generator_priority() {
    // r=3, as=3 → CG value -1 (takes priority over autoinc).
    assert_eq!(src_addr_mode(3, 3), AddrMode::Constant(-1));
}

// ── reg_name ─────────────────────────────────────────────────────────────────

#[test]
fn reg_name_all_known_regs() {
    let expected = ["PC", "SP", "SR", "CG", "R4", "R5", "R6", "R7", "R8", "R9",
                    "R10", "R11", "R12", "R13", "R14", "R15"];
    for (i, name) in expected.iter().enumerate() {
        assert_eq!(reg_name(u8::try_from(i).unwrap()), *name);
    }
}

#[test]
fn reg_name_unknown() {
    assert_eq!(reg_name(16), "Rx");
    assert_eq!(reg_name(255), "Rx");
}

// ── bw_suffix ────────────────────────────────────────────────────────────────

#[test]
fn bw_suffix_word_byte() {
    assert_eq!(bw_suffix(0), ".W");
    assert_eq!(bw_suffix(1), ".B");
    assert_eq!(bw_suffix(99), ".B"); // any nonzero
}

// ── format_src / format_dst ──────────────────────────────────────────────────

#[test]
fn format_src_register() {
    assert_eq!(format_src(0, 4, None), "R4");
}

#[test]
fn format_src_indexed_signed_offset() {
    // ext = 0xFFFE → -2 as i16
    assert_eq!(format_src(1, 4, Some(0xFFFE)), "-2(R4)");
}

#[test]
fn format_src_absolute() {
    assert_eq!(format_src(1, 2, Some(0x1234)), "&0x1234");
}

#[test]
fn format_src_immediate_hex() {
    assert_eq!(format_src(3, 0, Some(0xCAFE)), "#0xCAFE");
}

#[test]
fn format_src_constant_gen() {
    assert_eq!(format_src(3, 3, None), "#-1");
    assert_eq!(format_src(2, 2, None), "#4");
    assert_eq!(format_src(3, 2, None), "#8");
    assert_eq!(format_src(0, 3, None), "#0");
}

#[test]
fn format_dst_register_mode() {
    assert_eq!(format_dst(0, 5, None), "R5");
}

#[test]
fn format_dst_absolute_reg2() {
    assert_eq!(format_dst(1, 2, Some(0x0200)), "&0x0200");
}

#[test]
fn format_dst_indexed_signed() {
    assert_eq!(format_dst(1, 5, Some(0xFFFF)), "-1(R5)");
}

// ── check_emulated ───────────────────────────────────────────────────────────

#[test]
fn emulated_ret_from_mov_atsp_pc() {
    assert_eq!(check_emulated(4, 1, 0, 3, 0, 0), Some("RET"));
}

#[test]
fn emulated_clr_via_cg_r3() {
    assert_eq!(check_emulated(4, 3, 5, 0, 0, 0), Some("CLR.W"));
    assert_eq!(check_emulated(4, 3, 5, 0, 0, 1), Some("CLR.B"));
}

#[test]
fn emulated_inc_dec() {
    assert_eq!(check_emulated(5, 3, 4, 1, 0, 0), Some("INC"));
    assert_eq!(check_emulated(5, 3, 4, 3, 0, 0), Some("DEC"));
}

#[test]
fn emulated_inv_via_xor_neg1() {
    assert_eq!(check_emulated(14, 3, 4, 3, 0, 0), Some("INV"));
}

#[test]
fn emulated_nop_mov_same_reg() {
    assert_eq!(check_emulated(4, 5, 5, 0, 0, 0), Some("NOP"));
}

#[test]
fn emulated_none_for_normal_mov() {
    assert_eq!(check_emulated(4, 4, 5, 0, 0, 0), None);
}

// ── decode error paths ───────────────────────────────────────────────────────

#[test]
fn decode_empty_bytes_errors() {
    assert!(decode(&[], 0x4000).is_err());
}

#[test]
fn decode_single_byte_errors() {
    assert!(decode(&[0x12], 0x4000).is_err());
}

#[test]
fn decode_unknown_data_word() {
    // opcode4 < 4 and not jump/single-op → DC.W
    let d = decode(&[0x00, 0x00], 0x4000).unwrap();
    assert_eq!(d.mnemonic, "DC.W");
    assert_eq!(d.size, 2);
}

#[test]
fn decode_jump_size_is_2() {
    let d = decode(&[0x00, 0x3C], 0x4000).unwrap();
    assert_eq!(d.size, 2);
    assert!(d.branch_target.is_some());
}

#[test]
fn decode_jmp_negative_offset_sign_extended() {
    // JMP with offset = -1 (0x3FF): raw bits 0x3FF → cond=7
    // word = 0x2000 | (7<<10) | 0x3FF = 0x3FFF
    let d = decode(&[0xFF, 0x3F], 0x4000).unwrap();
    assert_eq!(d.mnemonic, "JMP");
    // target = pc + 2 + (-1)*2 = 0x4000
    assert_eq!(d.branch_target, Some(0x4000));
}

#[test]
fn decode_reti_recognized() {
    let d = decode(&[0x00, 0x13], 0x4000).unwrap();
    assert_eq!(d.mnemonic, "RETI");
    assert!(d.flags.contains(InstrFlags::RET));
}

#[test]
fn decode_call_immediate_size() {
    let d = decode(&[0xB0, 0x12, 0x00, 0x44], 0x4000).unwrap();
    assert_eq!(d.mnemonic, "CALL");
    assert_eq!(d.size, 4);
    assert!(d.flags.contains(InstrFlags::CALL));
}

#[test]
fn decode_mov_indexed_to_indexed_size_6() {
    // MOV.W 0(R4), 0(R5): src indexed (1 ext), dst indexed (1 ext) → size 6
    // opcode=4, src=R4(4), ad=1, bw=0, as=1, dst=5
    // word = (4<<12) | (4<<8) | (1<<7) | (0<<6) | (1<<4) | 5 = 0x4495
    let bytes = [0x95, 0x44, 0x00, 0x00, 0x00, 0x00];
    let d = decode(&bytes, 0x4000).unwrap();
    assert_eq!(d.size, 6);
    assert_eq!(d.mnemonic, "MOV.W");
}

#[test]
fn decode_mov_immediate_nonzero_must_not_become_clr() {
    // BUG GUARD: per check_emulated() docstring, MOV #imm,dst with as=3,src=R0 is only
    // CLR when the immediate extension word is 0. The decoder must read the ext word
    // and bail out of the emulated form when it's nonzero.
    // Bytes encode `MOV.W #0x1234, R4` (immediate = 0x1234, definitely NOT zero).
    // opcode=4, src=R0(0), ad=0, bw=0, as=3, dst=4 → word = 0x4034
    let d = decode(&[0x34, 0x40, 0x34, 0x12], 0x4000).unwrap();
    assert_eq!(d.mnemonic, "MOV.W",
        "MOV.W #0x1234,R4 was disassembled as `{}`, losing the immediate value", d.mnemonic);
}

#[test]
fn decode_truncated_extension_does_not_panic() {
    // Just ensure no panic when ext word can't be read. Use ADD.W #imm,R4 so we
    // avoid the CLR emulated form trap (opcode=5, not 4).
    // opcode=5 src=R0 ad=0 bw=0 as=3 dst=4 → 0x5034
    let _ = decode(&[0x34, 0x50, 0x00], 0x4000).unwrap();
}

// ── encode_* round-trip ──────────────────────────────────────────────────────

#[test]
fn encode_jump_jmp_zero() {
    let w = encode_jump(7, 0).unwrap();
    let bytes = w.to_le_bytes();
    let d = decode(&bytes, 0x4000).unwrap();
    assert_eq!(d.mnemonic, "JMP");
}

#[test]
fn encode_jump_min_max_offsets() {
    assert!(encode_jump(0, -512).is_ok());
    assert!(encode_jump(0, 511).is_ok());
    assert!(encode_jump(0, -513).is_err());
    assert!(encode_jump(0, 512).is_err());
}

#[test]
fn encode_two_op_boundaries() {
    assert!(encode_two_op(4, 0, 0, 0, 0, 0).is_ok());
    assert!(encode_two_op(15, 0, 0, 0, 0, 0).is_ok());
    assert!(encode_two_op(16, 0, 0, 0, 0, 0).is_err());
    assert!(encode_two_op(3, 0, 0, 0, 0, 0).is_err());
}

#[test]
fn encode_single_op_boundaries() {
    assert!(encode_single_op(0, 0, 0, 0).is_ok());
    assert!(encode_single_op(6, 0, 0, 0).is_ok());
    assert!(encode_single_op(7, 0, 0, 0).is_err());
}

#[test]
fn encode_decode_roundtrip_add_reg_reg() {
    // ADD.W R4, R5 → opcode=5, src=4, ad=0, bw=0, as=0, dst=5
    let w = encode_two_op(5, 4, 0, 0, 0, 5).unwrap();
    let d = decode(&w.to_le_bytes(), 0x4000).unwrap();
    assert_eq!(d.mnemonic, "ADD.W");
    assert!(d.operands.contains("R4"));
    assert!(d.operands.contains("R5"));
}

// ── ALU ──────────────────────────────────────────────────────────────────────

#[test]
fn alu_add_zero_zero() {
    let r = alu_add(0, 0);
    assert_eq!(r.result, 0);
    assert!(r.zero);
    assert!(!r.carry);
    assert!(!r.overflow);
    assert!(!r.negative);
}

#[test]
fn alu_addc_with_carry_in() {
    let r = alu_addc(0, 0, true);
    assert_eq!(r.result, 1);
    assert!(!r.carry);
}

#[test]
fn alu_addc_carry_in_triggers_carry_out() {
    let r = alu_addc(0xFFFF, 0, true);
    assert_eq!(r.result, 0);
    assert!(r.carry);
}

#[test]
fn alu_sub_borrow_clears_carry() {
    // 0 - 1 → underflow; MSP430 carry = NOT borrow, so carry should be false.
    let r = alu_sub(1, 0);
    assert_eq!(r.result, 0xFFFF);
    assert!(!r.carry);
    assert!(r.negative);
}

#[test]
fn alu_subc_basic() {
    // dst - src with carry-in = 1 == regular sub
    let r = alu_subc(1, 5, true);
    assert_eq!(r.result, 4);
}

#[test]
fn alu_and_zero_result_sets_zero_flag() {
    let r = alu_and(0xFF00, 0x00FF);
    assert_eq!(r.result, 0);
    assert!(r.zero);
}

#[test]
fn alu_bis_or() {
    let r = alu_bis(0xF000, 0x000F);
    assert_eq!(r.result, 0xF00F);
    assert!(!r.carry);
}

#[test]
fn alu_xor_negative_negative_overflow() {
    // Both operands have bit 15 set → overflow flag set per impl.
    let r = alu_xor(0x8000, 0x8000);
    assert_eq!(r.result, 0);
    assert!(r.zero);
    assert!(r.overflow);
}

#[test]
fn alu_rrc_carry_out_lsb() {
    let r = alu_rrc(0x0001, false);
    assert_eq!(r.result, 0);
    assert!(r.carry);
    assert!(r.zero);
}

#[test]
fn alu_rra_zero() {
    let r = alu_rra(0);
    assert_eq!(r.result, 0);
    assert!(!r.carry);
}

#[test]
fn alu_swpb_zero() {
    assert_eq!(alu_swpb(0), 0);
}

#[test]
fn alu_swpb_idempotent_twice() {
    let v = 0xDEADu16;
    assert_eq!(alu_swpb(alu_swpb(v)), v);
}

#[test]
fn alu_sxt_clears_high_bits_when_positive() {
    let r = alu_sxt(0xFF7F); // high byte should be discarded since bit7=0
    assert_eq!(r.result, 0x007F);
}

#[test]
fn aluresult_from_word_zero_negative_inferred() {
    let r = AluResult::from_word(0x8000, false, false);
    assert!(!r.zero);
    assert!(r.negative);
}

// ── RegisterFile ─────────────────────────────────────────────────────────────

#[test]
fn register_file_default_equals_new() {
    let a = RegisterFile::default();
    let b = RegisterFile::new();
    assert_eq!(a, b);
}

#[test]
fn register_file_set_sr_bit_clear() {
    let mut rf = RegisterFile::new();
    rf.set_sr_bit(sr_bits::C, true);
    assert!(rf.carry());
    rf.set_sr_bit(sr_bits::C, false);
    assert!(!rf.carry());
}

#[test]
fn register_file_update_flags_word_negative() {
    let mut rf = RegisterFile::new();
    rf.update_flags_word(0x8000, false, false);
    assert!(rf.negative());
    assert!(!rf.zero());
}

#[test]
fn register_file_update_flags_byte() {
    let mut rf = RegisterFile::new();
    rf.update_flags_byte(0x80, false, false);
    assert!(rf.negative());
    rf.update_flags_byte(0, false, false);
    assert!(rf.zero());
    assert!(!rf.negative());
}

#[test]
fn register_file_push_wraps() {
    let mut rf = RegisterFile::new();
    rf.set_sp(0x0000);
    let new_sp = rf.push();
    assert_eq!(new_sp, 0xFFFE); // wrapping_sub(2)
}

#[test]
fn register_file_pop_wraps() {
    let mut rf = RegisterFile::new();
    rf.set_sp(0xFFFE);
    let old = rf.pop();
    assert_eq!(old, 0xFFFE);
    assert_eq!(rf.sp(), 0x0000); // wrapping_add(2)
}

#[test]
#[should_panic(expected = "index out of bounds")]
fn register_file_read_out_of_range_panics() {
    // Documented panic behavior — exercising the panic path.
    let rf = RegisterFile::new();
    let _ = rf.read(16);
}

// ── FlatMemory ───────────────────────────────────────────────────────────────

#[test]
fn flat_memory_default_zero() {
    let m = FlatMemory::default();
    assert_eq!(m.read_byte(0), 0);
    assert_eq!(m.read_byte(0xFFFF), 0);
}

#[test]
fn flat_memory_word_wraps_high_byte() {
    let mut m = FlatMemory::new();
    m.write_word(0xFFFF, 0xABCD);
    // low byte at 0xFFFF, high byte wraps to 0x0000.
    assert_eq!(m.read_byte(0xFFFF), 0xCD);
    assert_eq!(m.read_byte(0x0000), 0xAB);
    assert_eq!(m.read_word(0xFFFF), 0xABCD);
}

#[test]
fn flat_memory_as_slice_full_size() {
    let m = FlatMemory::new();
    assert_eq!(m.as_slice().len(), 0x10000);
}

#[test]
#[should_panic(expected = "would wrap past end of address space")]
fn flat_memory_load_overflow_panics() {
    let mut m = FlatMemory::new();
    let big = vec![0u8; 0x100];
    // Loading 0x100 bytes at 0xFFFF would overflow → must panic per assert.
    m.load(0xFFFF, &big);
}

#[test]
fn flat_memory_load_max_size_ok() {
    let mut m = FlatMemory::new();
    let data: Vec<u8> = (0..=255).cycle().take(0x10000).collect();
    m.load(0, &data); // exactly fits
    assert_eq!(m.read_byte(0xFFFF), data[0xFFFF]);
}

// ── Msp430Arch ───────────────────────────────────────────────────────────────

#[test]
fn arch_default_is_16() {
    let a = Msp430Arch::default();
    assert_eq!(a.bits, 16);
    assert!(!a.is_msp430x());
    assert_eq!(a.max_addr(), 0xFFFF);
}

#[test]
fn arch_20bit_max_addr() {
    let a = Msp430Arch::new_20();
    assert_eq!(a.max_addr(), 0x000F_FFFF);
}

#[test]
fn arch_interrupt_vectors_contains_reset() {
    let a = Msp430Arch::new_16();
    assert!(a.interrupt_vectors().contains(&InterruptVector::Reset));
}

#[test]
fn arch_registers_first_is_pc() {
    let a = Msp430Arch::new_16();
    let regs = a.registers();
    assert_eq!(regs[0].name, "PC");
    assert_eq!(regs[0].id, regs::PC);
}

// ── InterruptVector ──────────────────────────────────────────────────────────

#[test]
fn interrupt_vector_addresses_distinct() {
    let all = InterruptVector::all();
    let mut addrs: Vec<u16> = all.iter().map(|v| v.address()).collect();
    addrs.sort_unstable();
    let len = addrs.len();
    addrs.dedup();
    assert_eq!(addrs.len(), len, "interrupt vector addresses must be unique");
}

#[test]
fn interrupt_vector_names_distinct() {
    let all = InterruptVector::all();
    let mut names: Vec<&str> = all.iter().map(|v| v.name()).collect();
    names.sort_unstable();
    let len = names.len();
    names.dedup();
    assert_eq!(names.len(), len);
}

#[test]
fn interrupt_vector_reset_at_fffe() {
    assert_eq!(InterruptVector::Reset.address(), 0xFFFE);
}

// ── msp430x submodule ────────────────────────────────────────────────────────

#[test]
fn msp430x_is_extension_word_full_range() {
    // Any word with top 5 bits = 0b0_0011 (i.e. 0x1800..=0x1FFF).
    for w in 0x1800u16..=0x1FFF {
        assert!(msp430x::is_extension_word(w), "0x{w:04X}");
    }
    assert!(!msp430x::is_extension_word(0x17FF));
    assert!(!msp430x::is_extension_word(0x2000));
}

#[test]
fn msp430x_decode_format_a_mnemonics() {
    // bits 11-8 select op: 0=MOVA,1=CMPA,2=ADDA,3=SUBA
    assert_eq!(msp430x::decode_format_a(0x0000), Some("MOVA"));
    assert_eq!(msp430x::decode_format_a(0x0100), Some("CMPA"));
    assert_eq!(msp430x::decode_format_a(0x0200), Some("ADDA"));
    assert_eq!(msp430x::decode_format_a(0x0300), Some("SUBA"));
    assert_eq!(msp430x::decode_format_a(0x0400), None);
}

#[test]
fn msp430x_encode_extension_word_sets_bits() {
    let w = msp430x::encode_extension_word(true, true, true, 0xF, 0xF);
    assert_eq!(w & (1 << 8), 1 << 8); // ZC
    assert_eq!(w & (1 << 7), 1 << 7); // SX
    assert_eq!(w & (1 << 6), 1 << 6); // A/L
    assert_eq!(w & 0x000F, 0x000F); // src_high
    assert_eq!((w >> 4) & 0xF, 0xF); // dst_high
    assert!(msp430x::is_extension_word(w));
}

#[test]
fn msp430x_decode_rotate_extended_rrcm() {
    // ext_word valid, opcode3=0 → RRCM
    let ext = 0x1800; // valid ext, al=0
    let base = 0u16; // opcode3 = (0>>7)&7 = 0
    assert_eq!(msp430x::decode_rotate_extended(ext, base), Some("RRCM.W"));
    // with al bit set
    let ext_al = 0x1840;
    assert_eq!(msp430x::decode_rotate_extended(ext_al, base), Some("RRCM.A"));
}

#[test]
fn msp430x_decode_rotate_extended_invalid_ext_returns_none() {
    assert_eq!(msp430x::decode_rotate_extended(0x4000, 0), None);
}

#[test]
fn msp430x_decode_pushm_n_minus_one_translation() {
    // PUSHM #1 means n-1=0 → mnemonic n must be 1.
    // Real MSP430X layout: bits[15:10]=000101, bit9=0 (PUSHM), bit8=A/L,
    // bits[7:4]=n-1, bits[3:0]=dst. PUSHM.A #1, R0 = 0x1400.
    // The old literal 0b00010_000_0000_0000 (= 0x1000) came from the previous
    // decode, whose opcode and count fields overlapped at bit 11.
    let word: u16 = 0x1400;
    let (mn, n, dst, al) = msp430x::decode_pushm_popm(word).unwrap();
    assert_eq!(mn, "PUSHM");
    assert_eq!(n, 1);
    assert_eq!(dst, 0);
    assert!(!al);
}

#[test]
fn msp430x_decode_popm() {
    // POPM.A #1, R0 = 0x1600 (bit9 = 1 selects POPM). The old 0x1800 relied on
    // the overlapping-field decode and additionally reported n = 9, because
    // POPM's opcode bit was being read as the count's high bit.
    let word: u16 = 0x1600;
    let (mn, _, _, _) = msp430x::decode_pushm_popm(word).unwrap();
    assert_eq!(mn, "POPM");
}

// ── Disassembler ─────────────────────────────────────────────────────────────

#[test]
fn linear_disassembler_offset_advances() {
    let a = Msp430Arch::new_16();
    let code = [0x04u8, 0x45, 0x04, 0x55];
    let mut dis = Msp430LinearDisassembler::new(&a, &code, Address::new(0x4000));
    assert_eq!(dis.offset(), 0);
    assert!(!dis.is_done());
    let _ = dis.next().unwrap().unwrap();
    assert_eq!(dis.offset(), 2);
    let _ = dis.next().unwrap().unwrap();
    assert!(dis.is_done());
    assert!(dis.next().is_none());
}

#[test]
fn linear_disassembler_empty_returns_none() {
    let a = Msp430Arch::new_16();
    let mut dis = Msp430LinearDisassembler::new(&a, &[], Address::new(0));
    assert!(dis.is_done());
    assert!(dis.next().is_none());
}

// ── Architecture trait round-trip ────────────────────────────────────────────

#[test]
fn arch_disassemble_call_get_branches_target() {
    use rustre_core::arch::BranchKind;
    let a = Msp430Arch::new_16();
    let instr = a.disassemble(Address::new(0x4000), &[0xB0, 0x12, 0x00, 0x44]).unwrap();
    let br = a.get_branches(&instr);
    assert_eq!(br.len(), 1);
    assert_eq!(br[0].kind, BranchKind::Call);
    assert_eq!(br[0].target, Some(0x4400));
}

#[test]
fn arch_disassemble_truncated_propagates_error() {
    let a = Msp430Arch::new_16();
    assert!(a.disassemble(Address::new(0), &[0x12]).is_err());
}

// ── Emulator ─────────────────────────────────────────────────────────────────

#[test]
fn emulator_default_zero_state() {
    let e = Msp430Emulator::default();
    assert_eq!(e.regs.pc(), 0);
    assert_eq!(e.instr_count, 0);
}

#[test]
fn emulator_reset_loads_pc_from_vector() {
    let mut e = Msp430Emulator::new();
    e.mem.write_word(0xFFFE, 0x4400);
    // pollute SR first
    e.regs.regs[2] = 0xFFFF;
    e.reset();
    assert_eq!(e.regs.pc(), 0x4400);
    assert_eq!(e.regs.regs[2], 0); // cleared
}

#[test]
fn emulator_mov_imm_to_reg() {
    // MOV.W #0x1234, R5
    // opcode=4, src=R0(0), ad=0, bw=0, as=3, dst=5 → word = 0x4035
    let mut e = Msp430Emulator::new();
    e.mem.write_word(0x4000, 0x4035);
    e.mem.write_word(0x4002, 0x1234);
    e.regs.set_pc(0x4000);
    e.step().unwrap();
    assert_eq!(e.regs.read(5), 0x1234);
    assert_eq!(e.regs.pc(), 0x4004);
}

#[test]
fn emulator_sub_sets_zero_flag() {
    // SUB.W R4, R5: opcode=8, src=4, ad=0, bw=0, as=0, dst=5 → 0x8405
    let mut e = Msp430Emulator::new();
    e.mem.write_word(0x4000, 0x8405);
    e.regs.set_pc(0x4000);
    e.regs.write(4, 7);
    e.regs.write(5, 7);
    e.step().unwrap();
    assert_eq!(e.regs.read(5), 0);
    assert!(e.regs.zero());
    assert!(e.regs.carry()); // sub no-borrow
}

#[test]
fn emulator_cmp_does_not_write_dst() {
    // CMP.W R4, R5: opcode=9 → 0x9405
    let mut e = Msp430Emulator::new();
    e.mem.write_word(0x4000, 0x9405);
    e.regs.set_pc(0x4000);
    e.regs.write(4, 1);
    e.regs.write(5, 5);
    e.step().unwrap();
    assert_eq!(e.regs.read(5), 5); // unchanged
}

#[test]
fn emulator_bit_does_not_write_dst() {
    // BIT.W R4, R5: opcode=11 → 0xB405
    let mut e = Msp430Emulator::new();
    e.mem.write_word(0x4000, 0xB405);
    e.regs.set_pc(0x4000);
    e.regs.write(4, 0xFFFF);
    e.regs.write(5, 0x00FF);
    e.step().unwrap();
    assert_eq!(e.regs.read(5), 0x00FF);
}

#[test]
fn emulator_jmp_negative_offset() {
    // JMP -2: cond=7, offset=-2 (0x3FE), word = 0x3FFE.
    let mut e = Msp430Emulator::new();
    e.mem.write_word(0x4000, 0x3FFE);
    e.regs.set_pc(0x4000);
    e.step().unwrap();
    // After step, PC was advanced to 0x4002, then JMP -2 * 2 = -4 → 0x3FFE.
    assert_eq!(e.regs.pc(), 0x3FFE);
}

#[test]
fn emulator_jne_not_taken_when_zero_set() {
    // JNE: cond=0, take iff !zero. Set zero=true so it's not taken.
    let mut e = Msp430Emulator::new();
    e.mem.write_word(0x4000, 0x2300); // JNE with offset = 0x300? cond=0 offset=0x300
    // Use word = (0x2000) | (0<<10) | offset(2) → 0x2002, target if taken = 0x4002+4 = 0x4006
    e.mem.write_word(0x4000, 0x2002);
    e.regs.set_pc(0x4000);
    e.regs.set_sr_bit(sr_bits::Z, true);
    e.step().unwrap();
    assert_eq!(e.regs.pc(), 0x4002); // fell through
}

#[test]
fn emulator_call_pushes_return_address() {
    // CALL #imm: opcode3=5, as=3, reg=0 (immediate) → 0x12B0
    let mut e = Msp430Emulator::new();
    e.regs.set_sp(0x0300);
    e.regs.set_pc(0x4000);
    e.mem.write_word(0x4000, 0x12B0);
    e.mem.write_word(0x4002, 0x4500); // target
    e.step().unwrap();
    // SP decremented by 2.
    assert_eq!(e.regs.sp(), 0x02FE);
    // Return address should be PC after instruction = 0x4004.
    assert_eq!(e.mem.read_word(0x02FE), 0x4004);
    // PC should be the target.
    assert_eq!(e.regs.pc(), 0x4500);
}

#[test]
fn emulator_reti_pops_sr_then_pc() {
    let mut e = Msp430Emulator::new();
    e.regs.set_sp(0x02FC);
    e.mem.write_word(0x02FC, 0x000A); // SR
    e.mem.write_word(0x02FE, 0x4500); // PC
    e.mem.write_word(0x4000, 0x1300); // RETI
    e.regs.set_pc(0x4000);
    e.step().unwrap();
    assert_eq!(e.regs.regs[2], 0x000A);
    assert_eq!(e.regs.pc(), 0x4500);
    assert_eq!(e.regs.sp(), 0x0300);
}

#[test]
fn emulator_indirect_autoinc_advances_register() {
    // MOV.W @R6+, R5: opcode=4, src=R6(6), ad=0, bw=0, as=3, dst=5 → 0x463 5
    // word = (4<<12)|(6<<8)|(0<<7)|(0<<6)|(3<<4)|5 = 0x4635
    let mut e = Msp430Emulator::new();
    e.regs.write(6, 0x0200);
    e.mem.write_word(0x0200, 0xCAFE);
    e.mem.write_word(0x4000, 0x4635);
    e.regs.set_pc(0x4000);
    e.step().unwrap();
    assert_eq!(e.regs.read(5), 0xCAFE);
    assert_eq!(e.regs.read(6), 0x0202); // auto-incremented
}

#[test]
fn emulator_mov_to_indexed_dst() {
    // MOV.W R4, 0(R5): opcode=4, src=R4(4), ad=1, bw=0, as=0, dst=5
    // word = (4<<12)|(4<<8)|(1<<7)|(0<<6)|(0<<4)|5 = 0x4485
    let mut e = Msp430Emulator::new();
    e.regs.write(4, 0xBEEF);
    e.regs.write(5, 0x0200);
    e.mem.write_word(0x4000, 0x4485);
    e.mem.write_word(0x4002, 0x0000); // offset
    e.regs.set_pc(0x4000);
    e.step().unwrap();
    assert_eq!(e.mem.read_word(0x0200), 0xBEEF);
    assert_eq!(e.regs.pc(), 0x4004);
}

#[test]
fn emulator_byte_write_only_low_byte() {
    // MOV.B R4, 0(R5): same as above but bw=1
    // word = (4<<12)|(4<<8)|(1<<7)|(1<<6)|(0<<4)|5 = 0x44C5
    let mut e = Msp430Emulator::new();
    e.regs.write(4, 0xABCD);
    e.regs.write(5, 0x0200);
    e.mem.write_word(0x0200, 0xFFFF); // prefill
    e.mem.write_word(0x4000, 0x44C5);
    e.mem.write_word(0x4002, 0x0000);
    e.regs.set_pc(0x4000);
    e.step().unwrap();
    // Only low byte written.
    assert_eq!(e.mem.read_byte(0x0200), 0xCD);
    assert_eq!(e.mem.read_byte(0x0201), 0xFF);
}

// ── CFG ──────────────────────────────────────────────────────────────────────

#[test]
fn build_cfg_respects_max_blocks() {
    let code: &[u8] = &[0x00, 0x3C]; // JMP +0 self-loop
    let blocks = build_cfg(code, 0x4000, 0x4000, 1).unwrap();
    assert!(blocks.len() <= 1);
}

#[test]
fn build_cfg_entry_out_of_range_returns_empty() {
    let code: &[u8] = &[0x04, 0x45];
    let blocks = build_cfg(code, 0x4000, 0x9000, 16).unwrap();
    assert!(blocks.is_empty());
}

#[test]
fn build_cfg_terminates_on_reti() {
    let code: &[u8] = &[0x04, 0x45, 0x00, 0x13]; // MOV.W R4,R5 ; RETI
    let blocks = build_cfg(code, 0x4000, 0x4000, 16).unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].instrs.len(), 2);
}

#[test]
fn basic_block_new_empty() {
    let b = BasicBlock::new(0x4000);
    assert!(b.is_empty());
    assert_eq!(b.len(), 0);
    assert_eq!(b.start, 0x4000);
    assert_eq!(b.end, 0x4000);
}

// ── regs/sr_bits constants ──────────────────────────────────────────────────

#[test]
fn regs_constants_match_indices() {
    assert_eq!(regs::PC, 0);
    assert_eq!(regs::SP, 1);
    assert_eq!(regs::SR, 2);
    assert_eq!(regs::CG2, 3);
    assert_eq!(regs::R15, 15);
}

#[test]
fn sr_bits_values_are_disjoint_powers_of_two() {
    let all = [sr_bits::C, sr_bits::Z, sr_bits::N, sr_bits::GIE, sr_bits::CPUOFF,
               sr_bits::OSCOFF, sr_bits::SCG0, sr_bits::SCG1, sr_bits::V];
    for &b in &all {
        assert!(b.is_power_of_two(), "{b:#x} should be a single bit");
    }
    let mut ored = 0u16;
    for &b in &all {
        assert_eq!(ored & b, 0, "overlap between bits");
        ored |= b;
    }
}
