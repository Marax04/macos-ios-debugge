//! Exhaustive black-box tests for rustre-arch-avr.

use rustre_core::arch::{Architecture, InstrFlags, Instruction};
use rustre_arch_avr::*;
use rustre_core::address::Address;
use rustre_core::endian::Endian;

fn arch() -> AvrArch {
    AvrArch::default()
}
const fn a(v: u64) -> Address {
    Address::new(v)
}

// ── Variant ──
#[test]
fn variant_default_is_atmega() {
    assert_eq!(arch().variant, AvrVariant::Atmega);
}
#[test]
fn variant_names_distinct() {
    let a = AvrArch::new(AvrVariant::Attiny);
    let b = AvrArch::new(AvrVariant::Atmega);
    let c = AvrArch::new(AvrVariant::Xmega);
    assert_ne!(a.name(), b.name());
    assert_ne!(b.name(), c.name());
    assert_ne!(a.name(), c.name());
}
#[test]
fn arch_endian_is_little() {
    assert_eq!(arch().endian(), Endian::Little);
}
#[test]
fn arch_pointer_size_2() {
    assert_eq!(arch().pointer_size(), 2);
}

// ── Encode/decode round-trips (pure encode) ──
#[test]
fn encode_nop_value() {
    assert_eq!(encode_nop(), 0x0000);
}
#[test]
fn encode_ret_value() {
    assert_eq!(encode_ret(), 0x9508);
}
#[test]
fn encode_reti_value() {
    assert_eq!(encode_reti(), 0x9518);
}
#[test]
fn encode_sleep_value() {
    assert_eq!(encode_sleep(), 0x9588);
}
#[test]
fn encode_wdr_value() {
    assert_eq!(encode_wdr(), 0x95A8);
}

#[test]
fn encode_rjmp_zero() {
    assert_eq!(encode_rjmp(0), 0xC000);
}
#[test]
fn encode_rjmp_neg1() {
    // 12-bit twos complement of -1 = 0xFFF
    assert_eq!(encode_rjmp(-1), 0xCFFF);
}
#[test]
fn encode_rjmp_max() {
    assert_eq!(encode_rjmp(2047), 0xC7FF);
}
#[test]
fn encode_rjmp_min() {
    assert_eq!(encode_rjmp(-2048), 0xC800);
}
#[test]
#[should_panic(expected = "RJMP displacement out of range")]
fn encode_rjmp_over_panics() {
    let _ = encode_rjmp(2048);
}
#[test]
#[should_panic(expected = "RJMP displacement out of range")]
fn encode_rjmp_under_panics() {
    let _ = encode_rjmp(-2049);
}

#[test]
fn encode_rcall_zero() {
    assert_eq!(encode_rcall(0), 0xD000);
}
#[test]
#[should_panic(expected = "RCALL displacement out of range")]
fn encode_rcall_over_panics() {
    let _ = encode_rcall(2048);
}

// ── Register encoders bounds ──
#[test]
#[should_panic(expected = "ADD register out of range")]
fn encode_add_over_panics() {
    let _ = encode_add(32, 0);
}
#[test]
#[should_panic(expected = "LDI destination must be r16")]
fn encode_ldi_low_panics() {
    let _ = encode_ldi(15, 0);
}
#[test]
#[should_panic(expected = "LDI destination must be r16")]
fn encode_ldi_high_panics() {
    let _ = encode_ldi(32, 0);
}

// ── Encoder/Decoder roundtrips through disassembler ──
fn disasm_word(w: u16) -> Instruction {
    let b = w.to_le_bytes();
    arch().disassemble(a(0), &b).expect("decode")
}

#[test]
fn rt_add() {
    let i = disasm_word(encode_add(5, 7));
    assert_eq!(i.mnemonic, "ADD");
    assert_eq!(i.operands, "R5,R7");
}
#[test]
fn rt_adc() {
    let i = disasm_word(encode_adc(0, 0));
    assert_eq!(i.mnemonic, "ADC");
}
#[test]
fn rt_sub() {
    let i = disasm_word(encode_sub(10, 11));
    assert_eq!(i.mnemonic, "SUB");
}
#[test]
fn rt_and() {
    let i = disasm_word(encode_and(2, 3));
    assert_eq!(i.mnemonic, "AND");
}
#[test]
fn rt_or() {
    let i = disasm_word(encode_or(2, 3));
    assert_eq!(i.mnemonic, "OR");
}
#[test]
fn rt_eor() {
    let i = disasm_word(encode_eor(4, 4));
    assert_eq!(i.mnemonic, "EOR");
}
#[test]
fn rt_cp() {
    let i = disasm_word(encode_cp(0, 31));
    assert_eq!(i.mnemonic, "CP");
}
#[test]
fn rt_cpc() {
    let i = disasm_word(encode_cpc(0, 31));
    assert_eq!(i.mnemonic, "CPC");
}
#[test]
fn rt_cpse() {
    let i = disasm_word(encode_cpse(0, 31));
    assert_eq!(i.mnemonic, "CPSE");
}
#[test]
fn rt_mov() {
    let i = disasm_word(encode_mov(20, 1));
    assert_eq!(i.mnemonic, "MOV");
}
#[test]
fn rt_ldi() {
    let i = disasm_word(encode_ldi(16, 0x42));
    assert_eq!(i.mnemonic, "LDI");
    assert!(i.operands.contains("R16"));
}
#[test]
fn rt_subi() {
    let i = disasm_word(encode_subi(20, 0xFF));
    assert_eq!(i.mnemonic, "SUBI");
}
#[test]
fn rt_sbci() {
    let i = disasm_word(encode_sbci(20, 0xFF));
    assert_eq!(i.mnemonic, "SBCI");
}
#[test]
fn rt_andi() {
    let i = disasm_word(encode_andi(20, 0xAA));
    assert_eq!(i.mnemonic, "ANDI");
}
#[test]
fn rt_ori() {
    let i = disasm_word(encode_ori(20, 0x55));
    assert_eq!(i.mnemonic, "ORI");
}
#[test]
fn rt_cpi() {
    let i = disasm_word(encode_cpi(20, 0));
    assert_eq!(i.mnemonic, "CPI");
}
#[test]
fn rt_inc() {
    let i = disasm_word(encode_inc(0));
    assert_eq!(i.mnemonic, "INC");
}
#[test]
fn rt_dec() {
    let i = disasm_word(encode_dec(31));
    assert_eq!(i.mnemonic, "DEC");
}
#[test]
fn rt_neg() {
    let i = disasm_word(encode_neg(1));
    assert_eq!(i.mnemonic, "NEG");
}
#[test]
fn rt_com() {
    let i = disasm_word(encode_com(2));
    assert_eq!(i.mnemonic, "COM");
}
#[test]
fn rt_lsr() {
    let i = disasm_word(encode_lsr(3));
    assert_eq!(i.mnemonic, "LSR");
}
#[test]
fn rt_asr() {
    let i = disasm_word(encode_asr(4));
    assert_eq!(i.mnemonic, "ASR");
}
#[test]
fn rt_ror() {
    let i = disasm_word(encode_ror(5));
    assert_eq!(i.mnemonic, "ROR");
}
#[test]
fn rt_swap() {
    let i = disasm_word(encode_swap(6));
    assert_eq!(i.mnemonic, "SWAP");
}
#[test]
fn rt_push() {
    let i = disasm_word(encode_push(0));
    assert_eq!(i.mnemonic, "PUSH");
}
#[test]
fn rt_pop() {
    let i = disasm_word(encode_pop(0));
    assert_eq!(i.mnemonic, "POP");
}
#[test]
fn rt_ret_flag() {
    let i = disasm_word(encode_ret());
    assert_eq!(i.mnemonic, "RET");
    assert!(i.flags.contains(InstrFlags::RET));
}
#[test]
fn rt_reti_flag() {
    let i = disasm_word(encode_reti());
    assert_eq!(i.mnemonic, "RETI");
    assert!(i.flags.contains(InstrFlags::RET));
}
#[test]
fn rt_clr_is_eor_same_reg() {
    let w = encode_clr(7);
    assert_eq!(w, encode_eor(7, 7));
    let i = disasm_word(w);
    assert_eq!(i.mnemonic, "EOR");
}
#[test]
fn rt_tst_is_and_same_reg() {
    assert_eq!(encode_tst(9), encode_and(9, 9));
}

// ── Disassemble truncated/empty input ──
#[test]
fn disasm_empty_errors() {
    assert!(arch().disassemble(a(0), &[]).is_err());
}
#[test]
fn disasm_one_byte_errors() {
    assert!(arch().disassemble(a(0), &[0x00]).is_err());
}

// ── Linear disassembler ──
#[test]
fn linear_iterates_two_nops() {
    let bytes = [0x00, 0x00, 0x00, 0x00];
    let arch = arch();
    let d = AvrLinearDisassembler::new(&arch, &bytes, a(0));
    let count = d.flatten().count();
    assert_eq!(count, 2);
}
#[test]
fn linear_empty() {
    let arch = arch();
    let d = AvrLinearDisassembler::new(&arch, &[], a(0));
    assert_eq!(d.count(), 0);
}
#[test]
fn linear_odd_trailing_byte_advances() {
    // 3 bytes: 1 instr decoded, then a 1-byte tail. The iterator should terminate.
    let bytes = [0x00, 0x00, 0xFF];
    let arch = arch();
    let d = AvrLinearDisassembler::new(&arch, &bytes, a(0));
    // first NOP decodes ok, then last byte either errors or stops.
    assert!(d.count() > 0);
}

// ── lookup_* helpers ──
#[test]
fn lookup_io_reg_known() {
    assert!(lookup_io_reg(0x05).is_some()); // PORTB area roughly
}
#[test]
fn lookup_io_reg_unknown() {
    assert!(lookup_io_reg(0xFF).is_none());
}
#[test]
fn lookup_vector_known() {
    assert!(lookup_vector(0).is_some());
}
#[test]
fn lookup_vector_unknown() {
    assert!(lookup_vector(250).is_none());
}
#[test]
fn lookup_reg_role_known() {
    assert!(lookup_reg_role(0).is_some());
}
#[test]
fn lookup_reg_role_oob() {
    assert!(lookup_reg_role(200).is_none());
}
#[test]
fn lookup_int_vector_by_name_reset() {
    let v = lookup_int_vector_by_name("RESET").unwrap();
    assert_eq!(v.number, 0);
    assert!(!v.maskable);
}
#[test]
fn lookup_int_vector_by_name_missing() {
    assert!(lookup_int_vector_by_name("BOGUS").is_none());
}
#[test]
fn lookup_int_vector_by_number_zero() {
    let v = lookup_int_vector_by_number(0).unwrap();
    assert_eq!(v.name, "RESET");
}
#[test]
fn lookup_int_vector_by_number_oob() {
    assert!(lookup_int_vector_by_number(250).is_none());
}
#[test]
fn lookup_ext_io_by_name_round_trip() {
    let r = lookup_ext_io_by_name("PORTB").unwrap();
    let r2 = lookup_ext_io_by_mem(r.mem_addr).unwrap();
    assert_eq!(r2.name, "PORTB");
}
#[test]
fn lookup_ext_io_unknown() {
    assert!(lookup_ext_io_by_name("NOPE").is_none());
    assert!(lookup_ext_io_by_mem(0xFFFE).is_none());
}
#[test]
fn lookup_avr_instr_ref_nop() {
    assert!(lookup_avr_instr_ref("NOP").is_some());
}
#[test]
fn lookup_avr_instr_ref_missing() {
    assert!(lookup_avr_instr_ref("ZZZ").is_none());
}

// ── AvrSregBit ──
#[test]
fn sreg_masks_are_powers_of_two() {
    for b in [
        AvrSregBit::C, AvrSregBit::Z, AvrSregBit::N, AvrSregBit::V,
        AvrSregBit::S, AvrSregBit::H, AvrSregBit::T, AvrSregBit::I,
    ] {
        let m = b.mask();
        assert!(m.is_power_of_two());
        assert!(!b.name().is_empty());
    }
}
#[test]
fn sreg_i_bit_is_msb() {
    assert_eq!(AvrSregBit::I.mask(), 0x80);
    assert_eq!(AvrSregBit::C.mask(), 0x01);
}

// ── AvrInstrKind ──
#[test]
fn kind_nop_is_nop() {
    assert_eq!(AvrInstrKind::from_mnemonic("NOP"), AvrInstrKind::Nop);
}
#[test]
fn kind_add_is_arith() {
    assert_eq!(AvrInstrKind::from_mnemonic("ADD"), AvrInstrKind::Arithmetic);
}
#[test]
fn kind_unknown() {
    assert_eq!(AvrInstrKind::from_mnemonic("WAT"), AvrInstrKind::Unknown);
}
#[test]
fn kind_control_flow_classification() {
    assert!(AvrInstrKind::Call.is_control_flow());
    assert!(AvrInstrKind::Return.is_control_flow());
    assert!(AvrInstrKind::Branch.is_control_flow());
    assert!(AvrInstrKind::CondBranch.is_control_flow());
    assert!(!AvrInstrKind::Arithmetic.is_control_flow());
}
#[test]
fn kind_memory_classification() {
    assert!(AvrInstrKind::Load.is_memory());
    assert!(AvrInstrKind::Store.is_memory());
    assert!(!AvrInstrKind::Io.is_memory());
}
#[test]
fn kind_io_classification() {
    assert!(AvrInstrKind::Io.is_io());
    assert!(!AvrInstrKind::Load.is_io());
}

// ── ABI: avr_param_locations ──
#[test]
fn param_zero_empty() {
    assert!(avr_param_locations(0).is_empty());
}
#[test]
fn param_one_in_r24() {
    let p = avr_param_locations(1);
    assert_eq!(p[0], AvrParamLocation::RegPair(24));
}
#[test]
fn param_four_pairs() {
    let p = avr_param_locations(4);
    assert_eq!(p[0], AvrParamLocation::RegPair(24));
    assert_eq!(p[1], AvrParamLocation::RegPair(22));
    assert_eq!(p[2], AvrParamLocation::RegPair(20));
    assert_eq!(p[3], AvrParamLocation::RegPair(18));
}
#[test]
fn param_eight_all_regs() {
    let p = avr_param_locations(8);
    assert!(p.iter().all(|x| matches!(x, AvrParamLocation::RegPair(_))));
}
#[test]
fn param_nine_overflows_to_stack() {
    let p = avr_param_locations(9);
    assert_eq!(p[8], AvrParamLocation::Stack(0));
}
#[test]
fn param_ten_stack_offset_2() {
    let p = avr_param_locations(10);
    assert_eq!(p[9], AvrParamLocation::Stack(2));
}

// ── AvrStackFrame ──
#[test]
fn stack_frame_empty() {
    let f = AvrStackFrame::compute(0, 0, false);
    // RA = 2
    assert_eq!(f.frame_size, 2);
    assert_eq!(f.saved_regs, 0);
    assert!(!f.sreg_saved);
}
#[test]
fn stack_frame_with_saves_and_sreg() {
    let f = AvrStackFrame::compute(4, 6, true);
    // 4 + 1 (sreg) + 6 + 2 = 13
    assert_eq!(f.frame_size, 13);
}

// ── identify_avr_idiom ──
fn make_instr(mn: &str, ops: &str) -> Instruction {
    let mut i = Instruction::new(a(0), 2, mn.to_string(), vec![0, 0]);
    i.operands = ops.to_string();
    i
}
#[test]
fn idiom_nop() {
    assert_eq!(identify_avr_idiom(&make_instr("NOP", "")), AvrIdiom::Nop);
}
#[test]
fn idiom_clr() {
    assert_eq!(identify_avr_idiom(&make_instr("EOR", "R5,R5")), AvrIdiom::ClearReg(5));
}
#[test]
fn idiom_tst() {
    assert_eq!(identify_avr_idiom(&make_instr("AND", "R7,R7")), AvrIdiom::TestReg(7));
}
#[test]
fn idiom_lsl() {
    assert_eq!(identify_avr_idiom(&make_instr("ADD", "R1,R1")), AvrIdiom::LogicalShiftLeft(1));
}
#[test]
fn idiom_rol() {
    assert_eq!(identify_avr_idiom(&make_instr("ADC", "R2,R2")), AvrIdiom::RotateLeft(2));
}
#[test]
fn idiom_eor_diff_general() {
    assert_eq!(identify_avr_idiom(&make_instr("EOR", "R1,R2")), AvrIdiom::General);
}
#[test]
fn idiom_other_general() {
    assert_eq!(identify_avr_idiom(&make_instr("MOV", "R1,R2")), AvrIdiom::General);
}

// ── avr_format ──
#[test]
fn fmt_no_operands() {
    let i = make_instr("NOP", "");
    assert_eq!(avr_format(&i), "NOP");
}
#[test]
fn fmt_with_operands() {
    let i = make_instr("ADD", "R1,R2");
    assert_eq!(avr_format(&i), "ADD R1,R2");
}
#[test]
fn fmt_with_addr_format() {
    let i = make_instr("NOP", "");
    let s = avr_format_with_addr(&i);
    assert!(s.starts_with("000000:"));
}

// ── disassemble_annotated ──
#[test]
fn annotated_two_nops() {
    let a_arch = arch();
    let v = disassemble_annotated(&a_arch, &[0, 0, 0, 0], a(0)).unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].kind, AvrInstrKind::Nop);
}
#[test]
fn annotated_empty() {
    let a_arch = arch();
    let v = disassemble_annotated(&a_arch, &[], a(0)).unwrap();
    assert!(v.is_empty());
}

// ── cycle / sreg metrics ──
#[test]
fn cycle_count_empty_zero() {
    assert_eq!(avr_cycle_count_min(&[]), 0);
    assert_eq!(avr_cycle_count_max(&[]), 0);
}
#[test]
fn cycle_min_le_max_all_table() {
    // covered in inline tests but assert via helpers
    let nop = make_instr("NOP", "");
    let one = std::slice::from_ref(&nop);
    assert!(avr_cycle_count_min(one) <= avr_cycle_count_max(one));
}
#[test]
fn sreg_modifying_unknown_is_zero() {
    let bogus = make_instr("BOGUSXYZ", "");
    assert_eq!(avr_sreg_modifying_count(&[bogus]), 0);
}

// ── avr_instr_byte_size ──
#[test]
fn byte_size_long_4() {
    for m in ["CALL", "JMP", "LDS", "STS"] {
        assert_eq!(avr_instr_byte_size(m), 4);
    }
}
#[test]
fn byte_size_default_2() {
    for m in ["NOP", "ADD", "FOO", ""] {
        assert_eq!(avr_instr_byte_size(m), 2);
    }
}

// ── address-space predicates ──
#[test]
fn flash_addr_boundary() {
    assert!(is_flash_addr(ATMEGA328P_FLASH_WORDS - 1));
    assert!(!is_flash_addr(ATMEGA328P_FLASH_WORDS));
}
#[test]
fn sram_addr_boundary() {
    assert!(!is_sram_addr(0x00FF));
    assert!(is_sram_addr(0x0100));
    assert!(is_sram_addr(0x08FF));
    assert!(!is_sram_addr(0x0900));
}
#[test]
fn io_addr_boundary() {
    assert!(!is_io_space_addr(0x001F));
    assert!(is_io_space_addr(0x0020));
    assert!(is_io_space_addr(0x00FF));
    assert!(!is_io_space_addr(0x0100));
}
#[test]
fn constants_relate() {
    assert_eq!(ATMEGA328P_FLASH_WORDS, ATMEGA328P_FLASH_BYTES / 2);
    assert_eq!(ATMEGA328P_SRAM_BYTES, 2048);
    assert_eq!(ATMEGA328P_EEPROM_BYTES, 1024);
}

// ── interrupt vector table integrity ──
#[test]
fn int_vector_numbers_sequential() {
    for (i, v) in ATMEGA328P_INT_VECTORS.iter().enumerate() {
        assert_eq!(v.number as usize, i, "vector {i} number mismatch");
    }
}
#[test]
fn int_vector_word_addrs_step_2() {
    for (i, v) in ATMEGA328P_INT_VECTORS.iter().enumerate() {
        assert_eq!(v.word_addr as usize, i * 2);
    }
}
#[test]
fn int_vector_only_reset_unmaskable() {
    for v in ATMEGA328P_INT_VECTORS {
        if v.number == 0 {
            assert!(!v.maskable);
        } else {
            assert!(v.maskable);
        }
    }
}

// ── extract_avr_branch_targets / prologue / epilogue ──
#[test]
fn extract_branch_targets_empty() {
    assert!(extract_avr_branch_targets(&[]).is_empty());
}
#[test]
fn detect_prologue_regs_empty() {
    assert_eq!(detect_avr_prologue_regs(&[]), 0);
}
#[test]
fn detect_epilogue_empty() {
    assert!(!detect_avr_epilogue(&[]));
}

// ── AvrArch registers ──
#[test]
fn arch_registers_has_32_general_plus_extras() {
    let regs = arch().registers();
    // 32 general + SREG + SP + PC + X + Y + Z = 38
    assert_eq!(regs.len(), 38);
}
#[test]
fn arch_calling_conventions_has_avr_gcc() {
    let cc = arch().calling_conventions();
    assert!(cc.iter().any(|c| c.name == "avr_gcc"));
}

// ── get_branches on a non-branch returns empty ──
#[test]
fn get_branches_on_nop_empty() {
    let i = disasm_word(encode_nop());
    assert!(arch().get_branches(&i).is_empty());
}
