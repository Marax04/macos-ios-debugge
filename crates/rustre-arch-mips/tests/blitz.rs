//! Integration tests for `rustre-arch-mips`.
//! Exhaustive coverage of encoders, decoders, helpers, and analysis APIs.

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_mips::*;
use rustre_core::address::Address;
use rustre_core::endian::Endian;

fn addr(v: u64) -> Address {
    Address::new(v)
}

// ---------------------------------------------------------------
// MipsArch constructors and trait impls
// ---------------------------------------------------------------

#[test]
fn arch_mips32_le_fields() {
    let a = MipsArch::mips32_le();
    assert_eq!(a.bits, 32);
    assert_eq!(a.endian, MipsEndian::Little);
    assert_eq!(a.abi, MipsAbi::O32);
}

#[test]
fn arch_mips32_be_fields() {
    let a = MipsArch::mips32_be();
    assert_eq!(a.bits, 32);
    assert_eq!(a.endian, MipsEndian::Big);
}

#[test]
fn arch_mips64_le_n64() {
    let a = MipsArch::mips64_le();
    assert_eq!(a.bits, 64);
    assert_eq!(a.abi, MipsAbi::N64);
}

#[test]
fn arch_mips64_be_n64() {
    let a = MipsArch::mips64_be();
    assert_eq!(a.bits, 64);
    assert_eq!(a.endian, MipsEndian::Big);
}

#[test]
fn arch_custom_constructor() {
    let a = MipsArch::custom(32, MipsEndian::Big, MipsAbi::N32);
    assert_eq!(a.bits, 32);
    assert_eq!(a.endian, MipsEndian::Big);
    assert_eq!(a.abi, MipsAbi::N32);
}

#[test]
fn arch_name_strings() {
    assert_eq!(MipsArch::mips32_le().name(), "mips32le");
    assert_eq!(MipsArch::mips32_be().name(), "mips32be");
    assert_eq!(MipsArch::mips64_le().name(), "mips64le");
    assert_eq!(MipsArch::mips64_be().name(), "mips64be");
}

#[test]
fn arch_name_fallback() {
    let a = MipsArch::custom(16, MipsEndian::Big, MipsAbi::O32);
    assert_eq!(a.name(), "mips");
}

#[test]
fn arch_pointer_size() {
    assert_eq!(MipsArch::mips32_le().pointer_size(), 4);
    assert_eq!(MipsArch::mips64_le().pointer_size(), 8);
}

#[test]
fn arch_endian_trait() {
    assert_eq!(MipsArch::mips32_le().endian(), Endian::Little);
    assert_eq!(MipsArch::mips32_be().endian(), Endian::Big);
}

#[test]
fn arch_clone_eq() {
    let a = MipsArch::mips32_le();
    let b = a.clone();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------
// gpr() table
// ---------------------------------------------------------------

#[test]
fn gpr_all_named() {
    let expected = [
        "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3", "$t0", "$t1", "$t2", "$t3",
        "$t4", "$t5", "$t6", "$t7", "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
        "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
    ];
    for (i, name) in expected.iter().enumerate() {
        assert_eq!(gpr(i), *name, "idx {i}");
    }
}

#[test]
fn gpr_out_of_range_returns_unk() {
    assert_eq!(gpr(32), "$unk");
    assert_eq!(gpr(usize::MAX), "$unk");
}

#[test]
fn reg_constants_match_indices() {
    assert_eq!(REG_ZERO, 0);
    assert_eq!(REG_RA, 31);
    assert_eq!(REG_SP, 29);
    assert_eq!(REG_GP, 28);
    assert_eq!(REG_FP, 30);
    assert_eq!(gpr(REG_A0), "$a0");
    assert_eq!(gpr(REG_T9), "$t9");
}

// ---------------------------------------------------------------
// read_word + endianness
// ---------------------------------------------------------------

#[test]
fn read_word_le() {
    let a = MipsArch::mips32_le();
    let bytes = [0x78, 0x56, 0x34, 0x12];
    assert_eq!(a.read_word(&bytes), Some(0x1234_5678));
}

#[test]
fn read_word_be() {
    let a = MipsArch::mips32_be();
    let bytes = [0x12, 0x34, 0x56, 0x78];
    assert_eq!(a.read_word(&bytes), Some(0x1234_5678));
}

#[test]
fn read_word_truncated() {
    let a = MipsArch::mips32_le();
    assert_eq!(a.read_word(&[]), None);
    assert_eq!(a.read_word(&[1, 2, 3]), None);
}

#[test]
fn read_word_extra_bytes_ok() {
    let a = MipsArch::mips32_le();
    let bytes = [0, 0, 0, 0, 0xff, 0xff];
    assert_eq!(a.read_word(&bytes), Some(0));
}

// ---------------------------------------------------------------
// Architecture::disassemble error path
// ---------------------------------------------------------------

#[test]
fn disassemble_truncated_returns_err() {
    let a = MipsArch::mips32_le();
    let r = a.disassemble(addr(0), &[1, 2, 3]);
    assert!(r.is_err());
}

#[test]
fn disassemble_nop() {
    let a = MipsArch::mips32_le();
    let r = a.disassemble(addr(0), &[0, 0, 0, 0]).unwrap();
    // NOP = SLL $zero,$zero,0
    assert_eq!(r.mnemonic, "sll");
}

// ---------------------------------------------------------------
// branch_target_i / branch_target_j
// ---------------------------------------------------------------

#[test]
fn branch_target_i_zero_offset() {
    // PC=0x100, simm16=0 → PC+4
    assert_eq!(branch_target_i(addr(0x100), 0), 0x104);
}

#[test]
fn branch_target_i_positive() {
    assert_eq!(branch_target_i(addr(0x100), 1), 0x108);
    assert_eq!(branch_target_i(addr(0x100), 4), 0x114);
}

#[test]
fn branch_target_i_negative() {
    // simm16=-1 → PC+4-4 = PC
    assert_eq!(branch_target_i(addr(0x100), -1), 0x100);
}

#[test]
fn branch_target_i_wraps() {
    // Make sure no panic on wrap
    let _ = branch_target_i(addr(u64::MAX), 1);
}

#[test]
fn branch_target_j_alignment() {
    // J target26 << 2 within same 256MB region
    let t = branch_target_j(addr(0x0), 0x100);
    assert_eq!(t, 0x400);
}

#[test]
fn branch_target_j_upper_preserved() {
    let t = branch_target_j(addr(0x1000_0000), 0x10);
    // pc+4 = 0x1000_0004; upper (>>28) = 0x1
    assert_eq!(t & 0xF000_0000, 0x1000_0000);
    assert_eq!(t & 0x0FFF_FFFF, 0x40);
}

// ---------------------------------------------------------------
// Encoders: round-trip via decode
// ---------------------------------------------------------------

fn decode_le(arch: &MipsArch, word: u32) -> rustre_core::arch::Instruction {
    let bytes = word.to_le_bytes();
    arch.decode_word(addr(0), word, &bytes)
}

#[test]
fn encode_nop_is_zero() {
    assert_eq!(encode_nop(), 0);
}

#[test]
fn encode_decode_addu() {
    let a = MipsArch::mips32_le();
    let w = encode_addu(/*rd*/ 3, /*rs*/ 1, /*rt*/ 2);
    let i = decode_le(&a, w);
    assert_eq!(i.mnemonic, "addu");
    assert!(i.operands.contains("$v1"));
    assert!(i.operands.contains("$at"));
    assert!(i.operands.contains("$v0"));
}

#[test]
fn encode_decode_subu() {
    let a = MipsArch::mips32_le();
    let w = encode_subu(3, 1, 2);
    let i = decode_le(&a, w);
    assert_eq!(i.mnemonic, "subu");
}

#[test]
fn encode_decode_and_or_xor_nor() {
    let a = MipsArch::mips32_le();
    assert_eq!(decode_le(&a, encode_and(3, 1, 2)).mnemonic, "and");
    assert_eq!(decode_le(&a, encode_or(3, 1, 2)).mnemonic, "or");
    assert_eq!(decode_le(&a, encode_xor(3, 1, 2)).mnemonic, "xor");
    assert_eq!(decode_le(&a, encode_nor(3, 1, 2)).mnemonic, "nor");
    assert_eq!(decode_le(&a, encode_slt(3, 1, 2)).mnemonic, "slt");
    assert_eq!(decode_le(&a, encode_sltu(3, 1, 2)).mnemonic, "sltu");
}

#[test]
fn encode_decode_mult_div() {
    let a = MipsArch::mips32_le();
    assert_eq!(decode_le(&a, encode_mult(1, 2)).mnemonic, "mult");
    assert_eq!(decode_le(&a, encode_div(1, 2)).mnemonic, "div");
    assert_eq!(decode_le(&a, encode_mfhi(3)).mnemonic, "mfhi");
    assert_eq!(decode_le(&a, encode_mflo(3)).mnemonic, "mflo");
}

#[test]
fn encode_decode_jr_jalr() {
    let a = MipsArch::mips32_le();
    let jr = decode_le(&a, encode_jr(31));
    assert_eq!(jr.mnemonic, "jr");
    let jalr = decode_le(&a, encode_jalr(31, 25));
    assert_eq!(jalr.mnemonic, "jalr");
}

#[test]
fn encode_decode_j_jal() {
    let a = MipsArch::mips32_le();
    let j = decode_le(&a, encode_j(0x100));
    assert_eq!(j.mnemonic, "j");
    let jal = decode_le(&a, encode_jal(0x100));
    assert_eq!(jal.mnemonic, "jal");
    assert!(jal.flags.contains(InstrFlags::CALL));
}

#[test]
fn encode_decode_lui() {
    let a = MipsArch::mips32_le();
    let i = decode_le(&a, encode_lui(2, 0x1234));
    assert_eq!(i.mnemonic, "lui");
    assert!(i.operands.contains("0x1234"));
}

#[test]
fn encode_decode_addiu_positive() {
    let a = MipsArch::mips32_le();
    let i = decode_le(&a, encode_addiu(2, 1, 100));
    assert_eq!(i.mnemonic, "addiu");
}

#[test]
fn encode_decode_addiu_negative() {
    let a = MipsArch::mips32_le();
    let i = decode_le(&a, encode_addiu(29, 29, -32));
    assert_eq!(i.mnemonic, "addiu");
    // Sign-extended -32 should appear
    assert!(i.operands.contains("-32"));
}

#[test]
fn encode_decode_lw_sw() {
    let a = MipsArch::mips32_le();
    assert_eq!(decode_le(&a, encode_lw(2, 29, 0)).mnemonic, "lw");
    assert_eq!(decode_le(&a, encode_sw(31, 29, 4)).mnemonic, "sw");
}

#[test]
fn encode_decode_beq_bne() {
    let a = MipsArch::mips32_le();
    let beq = decode_le(&a, encode_beq(1, 2, 4));
    assert_eq!(beq.mnemonic, "beq");
    assert!(beq.flags.contains(InstrFlags::BRANCH));
    let bne = decode_le(&a, encode_bne(1, 2, -4));
    assert_eq!(bne.mnemonic, "bne");
}

#[test]
fn encode_decode_syscall() {
    let a = MipsArch::mips32_le();
    let w = encode_syscall(0x4242);
    let i = decode_le(&a, w);
    assert_eq!(i.mnemonic, "syscall");
}

// ---------------------------------------------------------------
// Encoder bit-layout invariants
// ---------------------------------------------------------------

#[test]
fn encode_rtype_field_layout() {
    let w = encode_rtype(0b1_1111, 0b1_1111, 0b1_1111, 0b1_1111, 0b11_1111);
    // Opcode (top 6 bits) is zero for SPECIAL
    assert_eq!(w >> 26, 0);
    // funct = low 6
    assert_eq!(w & 0x3F, 0x3F);
    // shamt at bits 6..11
    assert_eq!((w >> 6) & 0x1F, 0x1F);
    // rd 11..16, rt 16..21, rs 21..26
    assert_eq!((w >> 11) & 0x1F, 0x1F);
    assert_eq!((w >> 16) & 0x1F, 0x1F);
    assert_eq!((w >> 21) & 0x1F, 0x1F);
}

#[test]
fn encode_jtype_masks_target() {
    let w = encode_jtype(0x02, 0xFFFF_FFFF);
    assert_eq!(w >> 26, 0x02);
    assert_eq!(w & 0x03FF_FFFF, 0x03FF_FFFF);
}

#[test]
fn encode_itype_layout() {
    let w = encode_itype(0x3F, 0x1F, 0x1F, 0xFFFF);
    assert_eq!(w >> 26, 0x3F);
    assert_eq!((w >> 21) & 0x1F, 0x1F);
    assert_eq!((w >> 16) & 0x1F, 0x1F);
    assert_eq!(w & 0xFFFF, 0xFFFF);
}

// ---------------------------------------------------------------
// Endian swap helpers
// ---------------------------------------------------------------

#[test]
fn swap32_basic() {
    assert_eq!(swap32(0x1122_3344), 0x4433_2211);
    assert_eq!(swap32(0), 0);
    assert_eq!(swap32(0xFFFF_FFFF), 0xFFFF_FFFF);
}

#[test]
fn swap16_basic() {
    assert_eq!(swap16(0xABCD), 0xCDAB);
    assert_eq!(swap16(0), 0);
}

#[test]
fn read_be32_oob() {
    let b = [1u8, 2, 3];
    assert_eq!(read_be32(&b, 0), None);
    assert_eq!(read_be32(&b, 100), None);
}

#[test]
fn read_le32_oob() {
    let b = [1u8, 2];
    assert_eq!(read_le32(&b, 0), None);
}

#[test]
fn read_write_round_trip_be() {
    let mut b = vec![0u8; 8];
    write_be32(&mut b, 2, 0xCAFE_BABE);
    assert_eq!(read_be32(&b, 2), Some(0xCAFE_BABE));
}

#[test]
fn read_write_round_trip_le() {
    let mut b = vec![0u8; 8];
    write_le32(&mut b, 0, 0xDEAD_BEEF);
    assert_eq!(read_le32(&b, 0), Some(0xDEAD_BEEF));
}

#[test]
fn write_be32_oob_silently_noop() {
    let mut b = vec![0u8; 2];
    write_be32(&mut b, 0, 0xFFFF_FFFF);
    // Should not panic and should not corrupt within len
    assert_eq!(b, vec![0, 0]);
}

#[test]
fn write_le32_oob_silently_noop() {
    let mut b = vec![0u8; 2];
    write_le32(&mut b, 0, 0xFFFF_FFFF);
    assert_eq!(b, vec![0, 0]);
}

// ---------------------------------------------------------------
// patch_instr / patch_branch
// ---------------------------------------------------------------

#[test]
fn patch_instr_be_le() {
    let mut b = vec![0u8; 4];
    patch_instr(&mut b, 0, 0x1122_3344, MipsEndian::Big);
    assert_eq!(b, vec![0x11, 0x22, 0x33, 0x44]);
    let mut b2 = vec![0u8; 4];
    patch_instr(&mut b2, 0, 0x1122_3344, MipsEndian::Little);
    assert_eq!(b2, vec![0x44, 0x33, 0x22, 0x11]);
}

#[test]
fn patch_branch_j_in_region() {
    let mut buf = encode_j(0).to_be_bytes().to_vec();
    let r = patch_branch(&mut buf, 0, addr(0), 0x40, MipsEndian::Big);
    assert!(r.is_ok());
    let nw = read_be32(&buf, 0).unwrap();
    assert_eq!((nw & 0x03FF_FFFF) << 2, 0x40);
}

#[test]
fn patch_branch_j_out_of_region() {
    let mut buf = encode_j(0).to_be_bytes().to_vec();
    let r = patch_branch(&mut buf, 0, addr(0), 0x2000_0000, MipsEndian::Big);
    assert!(r.is_err());
}

#[test]
fn patch_branch_i_round_trip() {
    let mut buf = encode_beq(1, 2, 0).to_be_bytes().to_vec();
    let r = patch_branch(&mut buf, 0, addr(0x100), 0x104, MipsEndian::Big);
    assert!(r.is_ok());
    // disp_words = (0x104 - 0x104)/4 = 0
    let nw = read_be32(&buf, 0).unwrap();
    assert_eq!(nw & 0xFFFF, 0);
}

#[test]
fn patch_branch_i_negative_disp() {
    let mut buf = encode_beq(1, 2, 0).to_be_bytes().to_vec();
    // target = PC, so disp = -4 bytes = -1 word
    let r = patch_branch(&mut buf, 0, addr(0x100), 0x100, MipsEndian::Big);
    assert!(r.is_ok());
    let nw = read_be32(&buf, 0).unwrap();
    assert_eq!((nw & 0xFFFF) as i16, -1);
}

#[test]
fn patch_branch_offset_oob() {
    let mut buf = vec![0u8; 2];
    let r = patch_branch(&mut buf, 0, addr(0), 0, MipsEndian::Big);
    assert!(r.is_err());
}

#[test]
fn patch_branch_non_branch_opcode() {
    // ADDIU is opcode 0x09 — not a branch
    let mut buf = encode_addiu(1, 1, 0).to_be_bytes().to_vec();
    let r = patch_branch(&mut buf, 0, addr(0), 0x100, MipsEndian::Big);
    assert!(r.is_err());
}

// ---------------------------------------------------------------
// is_valid_mips_word
// ---------------------------------------------------------------

#[test]
fn valid_word_nop() {
    assert!(is_valid_mips_word(0));
}

#[test]
fn valid_word_addiu() {
    assert!(is_valid_mips_word(encode_addiu(1, 1, 1)));
}

#[test]
fn invalid_word_reserved_opcode() {
    // Opcode 0x1D is reserved
    let w = 0x1D << 26;
    assert!(!is_valid_mips_word(w));
}

// ---------------------------------------------------------------
// ABI roles
// ---------------------------------------------------------------

#[test]
fn o32_role_assignments() {
    assert_eq!(gpr_role_o32(0), GprRole::Zero);
    assert_eq!(gpr_role_o32(1), GprRole::At);
    assert_eq!(gpr_role_o32(2), GprRole::ReturnValue);
    assert_eq!(gpr_role_o32(3), GprRole::ReturnValue);
    assert_eq!(gpr_role_o32(4), GprRole::Argument);
    assert_eq!(gpr_role_o32(7), GprRole::Argument);
    assert_eq!(gpr_role_o32(8), GprRole::Temporary);
    assert_eq!(gpr_role_o32(16), GprRole::Saved);
    assert_eq!(gpr_role_o32(26), GprRole::Kernel);
    assert_eq!(gpr_role_o32(28), GprRole::GlobalPointer);
    assert_eq!(gpr_role_o32(29), GprRole::StackPointer);
    assert_eq!(gpr_role_o32(30), GprRole::FramePointer);
    assert_eq!(gpr_role_o32(31), GprRole::ReturnAddress);
}

#[test]
fn n64_extra_arg_regs() {
    // In N64, a4..a7 are arguments (regs 8..11)
    assert_eq!(gpr_role_n64(8), GprRole::Argument);
    assert_eq!(gpr_role_n64(11), GprRole::Argument);
    // r12..15 are temporaries in N64
    assert_eq!(gpr_role_n64(12), GprRole::Temporary);
    assert_eq!(gpr_role_n64(15), GprRole::Temporary);
}

#[test]
fn o32_n64_diverge_on_r8_to_r11() {
    // r8..11 are temporary in O32, but argument in N64
    assert_eq!(gpr_role_o32(8), GprRole::Temporary);
    assert_eq!(gpr_role_n64(8), GprRole::Argument);
}

// ---------------------------------------------------------------
// HI/LO effect classification
// ---------------------------------------------------------------

#[test]
fn hi_lo_effect_known() {
    assert_eq!(hi_lo_effect("mult"), HiLoEffect::MultSigned);
    assert_eq!(hi_lo_effect("multu"), HiLoEffect::MultUnsigned);
    assert_eq!(hi_lo_effect("div"), HiLoEffect::DivSigned);
    assert_eq!(hi_lo_effect("divu"), HiLoEffect::DivUnsigned);
    assert_eq!(hi_lo_effect("madd"), HiLoEffect::MaddSigned);
    assert_eq!(hi_lo_effect("maddu"), HiLoEffect::MaddUnsigned);
    assert_eq!(hi_lo_effect("msub"), HiLoEffect::MsubSigned);
    assert_eq!(hi_lo_effect("msubu"), HiLoEffect::MsubUnsigned);
}

#[test]
fn hi_lo_effect_none() {
    assert_eq!(hi_lo_effect("add"), HiLoEffect::None);
    assert_eq!(hi_lo_effect(""), HiLoEffect::None);
    assert_eq!(hi_lo_effect("nonsense"), HiLoEffect::None);
}

#[test]
fn hi_lo_effect_64bit_variants() {
    assert_eq!(hi_lo_effect("dmult"), HiLoEffect::MultSigned);
    assert_eq!(hi_lo_effect("dmultu"), HiLoEffect::MultUnsigned);
    assert_eq!(hi_lo_effect("ddiv"), HiLoEffect::DivSigned);
    assert_eq!(hi_lo_effect("ddivu"), HiLoEffect::DivUnsigned);
}

// ---------------------------------------------------------------
// MIPS_INSTR_TABLE / lookup
// ---------------------------------------------------------------

#[test]
fn lookup_mips_instr_known() {
    assert!(lookup_mips_instr("add").is_some());
    assert!(lookup_mips_instr("lw").is_some());
    assert!(lookup_mips_instr("jal").is_some());
}

#[test]
fn lookup_mips_instr_unknown() {
    assert!(lookup_mips_instr("not_an_instr").is_none());
    assert!(lookup_mips_instr("").is_none());
}

#[test]
fn instr_table_nonempty() {
    assert!(!MIPS_INSTR_TABLE.is_empty());
}

// ---------------------------------------------------------------
// Linear disassembler + basic blocks
// ---------------------------------------------------------------

#[test]
fn linear_disasm_three_words() {
    let a = MipsArch::mips32_le();
    let ws = [encode_nop(), encode_addu(3, 1, 2), encode_jr(31)];
    let mut bytes = Vec::new();
    for w in ws {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let count = MipsLinearDisassembler::new(&a, &bytes, addr(0)).count();
    assert_eq!(count, 3);
}

#[test]
fn basic_blocks_terminate_after_delay_slot() {
    let a = MipsArch::mips32_le();
    let ws = [
        encode_addu(3, 1, 2), // block 1
        encode_jr(31),        // terminator
        encode_nop(),         // delay slot — last in block 1
        encode_addu(4, 1, 2), // block 2
    ];
    let mut bytes = Vec::new();
    for w in ws {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let blocks = MipsBasicBlock::find_blocks(&a, &bytes, addr(0));
    assert!(blocks.len() >= 2, "expected >=2 blocks, got {}", blocks.len());
    // First block contains the jr and its delay slot (3 instructions).
    assert_eq!(blocks[0].len(), 3);
}

// ---------------------------------------------------------------
// MipsCodeStats
// ---------------------------------------------------------------

#[test]
fn code_stats_counts() {
    let a = MipsArch::mips32_le();
    let ws = [
        encode_addu(3, 1, 2),    // alu
        encode_lw(2, 29, 0),     // load
        encode_sw(31, 29, 4),    // store
        encode_jal(0x100),       // call
        encode_nop(),            // alu (sll)
        encode_mult(1, 2),       // mul_div
    ];
    let mut bytes = Vec::new();
    for w in ws {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let s = MipsCodeStats::from_bytes(&a, &bytes, addr(0));
    assert_eq!(s.total, 6);
    assert_eq!(s.loads, 1);
    assert_eq!(s.stores, 1);
    assert_eq!(s.calls, 1);
    assert_eq!(s.mul_div, 1);
    assert!(s.alu >= 1);
}

// ---------------------------------------------------------------
// Histogram
// ---------------------------------------------------------------

#[test]
fn histogram_total_and_count() {
    let a = MipsArch::mips32_le();
    let ws = [encode_addu(1, 1, 1), encode_addu(1, 1, 1), encode_subu(1, 1, 1)];
    let mut bytes = Vec::new();
    for w in ws {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let h = MipsHistogram::build(&a, &bytes, addr(0));
    assert_eq!(h.total(), 3);
    assert_eq!(h.count("addu"), 2);
    assert_eq!(h.count("subu"), 1);
    assert_eq!(h.count("nope"), 0);
}

#[test]
fn histogram_top_n_descending() {
    let a = MipsArch::mips32_le();
    let mut ws = vec![encode_addu(1, 1, 1); 5];
    ws.push(encode_subu(1, 1, 1));
    let mut bytes = Vec::new();
    for w in ws {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let h = MipsHistogram::build(&a, &bytes, addr(0));
    let top = h.top_n(2);
    assert_eq!(top[0].0, "addu");
    assert_eq!(top[0].1, 5);
    assert!(top[1].1 <= top[0].1);
}

#[test]
fn histogram_empty_top_n() {
    let h = MipsHistogram::build(&MipsArch::mips32_le(), &[], addr(0));
    assert_eq!(h.total(), 0);
    assert!(h.top_n(10).is_empty());
}

// ---------------------------------------------------------------
// scan_constant_pool
// ---------------------------------------------------------------

#[test]
fn scan_constant_pool_finds_invalid_word() {
    let a = MipsArch::mips32_le();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&encode_addu(1, 1, 1).to_le_bytes());
    // opcode 0x1D is reserved
    bytes.extend_from_slice(&(0x1Du32 << 26).to_le_bytes());
    let pool = scan_constant_pool(&a, &bytes, addr(0x1000));
    assert!(pool.iter().any(|e| e.address == 0x1004));
}

#[test]
fn scan_constant_pool_all_valid_yields_empty() {
    let a = MipsArch::mips32_le();
    let mut bytes = Vec::new();
    for _ in 0..4 {
        bytes.extend_from_slice(&encode_nop().to_le_bytes());
    }
    let pool = scan_constant_pool(&a, &bytes, addr(0));
    assert!(pool.is_empty());
}

// ---------------------------------------------------------------
// Preamble detection
// ---------------------------------------------------------------

#[test]
fn detect_preamble_o32_alloc() {
    // addiu $sp, $sp, -32 = 0x27BD_FFE0
    let b = [0x27u8, 0xBD, 0xFF, 0xE0];
    assert_eq!(detect_preamble(&b), Some("O32 frame alloc"));
}

#[test]
fn detect_preamble_none_for_nop() {
    assert_eq!(detect_preamble(&[0, 0, 0, 0]), None);
}

#[test]
fn detect_preamble_too_short() {
    assert_eq!(detect_preamble(&[0x27, 0xBD, 0xFF]), None);
    assert_eq!(detect_preamble(&[]), None);
}

#[test]
fn detect_preamble_save_ra() {
    // sw $ra, 0($sp) = 0xAFBF_0000
    let b = [0xAFu8, 0xBF, 0x00, 0x00];
    assert_eq!(detect_preamble(&b), Some("Save $ra to stack"));
}

#[test]
fn preamble_table_nonempty() {
    assert!(!MIPS_PREAMBLE_PATTERNS.is_empty());
}

// ---------------------------------------------------------------
// RDHWR descriptions
// ---------------------------------------------------------------

#[test]
fn rdhwr_known_regs() {
    assert!(rdhwr_reg_desc(0).contains("CPU"));
    assert!(rdhwr_reg_desc(1).contains("SYNCI"));
    assert!(rdhwr_reg_desc(2).contains("Cycle"));
    assert!(rdhwr_reg_desc(3).contains("Cycle"));
    assert!(rdhwr_reg_desc(29).contains("thread"));
}

#[test]
fn rdhwr_unknown_returns_reserved() {
    assert!(rdhwr_reg_desc(99).contains("Reserved"));
    assert!(rdhwr_reg_desc(4).contains("Reserved"));
}

// ---------------------------------------------------------------
// PrintStyle / print_instr
// ---------------------------------------------------------------

#[test]
fn print_instr_standard() {
    let a = MipsArch::mips32_le();
    let i = decode_le(&a, encode_addu(3, 1, 2));
    let s = print_instr(&i, PrintStyle::Standard);
    assert!(s.starts_with("addu "));
}

#[test]
fn print_instr_with_hex_address() {
    let a = MipsArch::mips32_le();
    let bytes = encode_addu(3, 1, 2).to_le_bytes();
    let i = a.decode_word(addr(0xABCD), encode_addu(3, 1, 2), &bytes);
    let s = print_instr(&i, PrintStyle::WithHexAddress);
    assert!(s.contains("0000abcd"));
}

// ---------------------------------------------------------------
// FormatOptions / format_instruction / format_disassembly
// ---------------------------------------------------------------

#[test]
fn format_options_default() {
    let o = FormatOptions::default();
    assert!(o.use_abi_names);
    assert!(o.annotate_delay_slots);
    assert!(!o.show_bytes);
    assert!(o.operand_column > 0);
}

#[test]
fn format_instruction_no_bytes() {
    let a = MipsArch::mips32_le();
    let i = decode_le(&a, encode_nop());
    let opts = FormatOptions::default();
    let s = format_instruction(&i, false, &opts);
    assert!(s.contains("sll"));
    assert!(!s.contains("delay slot"));
}

#[test]
fn format_instruction_delay_slot_marker() {
    let a = MipsArch::mips32_le();
    let i = decode_le(&a, encode_nop());
    let opts = FormatOptions::default();
    let s = format_instruction(&i, true, &opts);
    assert!(s.contains("<delay slot>"));
}

#[test]
fn format_disassembly_multi() {
    let a = MipsArch::mips32_le();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&encode_nop().to_le_bytes());
    bytes.extend_from_slice(&encode_addu(3, 1, 2).to_le_bytes());
    let s = format_disassembly(&a, &bytes, addr(0), &FormatOptions::default());
    assert!(s.lines().count() >= 2);
}

// ---------------------------------------------------------------
// Prologue/epilogue detection
// ---------------------------------------------------------------

#[test]
fn detect_prologue_simple() {
    let a = MipsArch::mips32_le();
    // addiu $sp,$sp,-32 then sw $ra
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&encode_addiu(29, 29, -32).to_le_bytes());
    bytes.extend_from_slice(&encode_sw(31, 29, 28).to_le_bytes());
    let instrs: Vec<_> = MipsLinearDisassembler::new(&a, &bytes, addr(0))
        .flatten()
        .collect();
    let r = detect_mips_prologue(&instrs);
    assert_eq!(r, Some(32));
}

#[test]
fn detect_prologue_rejects_positive_imm() {
    let a = MipsArch::mips32_le();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&encode_addiu(29, 29, 32).to_le_bytes());
    bytes.extend_from_slice(&encode_nop().to_le_bytes());
    let instrs: Vec<_> = MipsLinearDisassembler::new(&a, &bytes, addr(0))
        .flatten()
        .collect();
    assert_eq!(detect_mips_prologue(&instrs), None);
}

#[test]
fn detect_prologue_empty() {
    assert_eq!(detect_mips_prologue(&[]), None);
}

#[test]
fn detect_epilogue_matches() {
    let a = MipsArch::mips32_le();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&encode_lw(31, 29, 28).to_le_bytes());
    bytes.extend_from_slice(&encode_addiu(29, 29, 32).to_le_bytes());
    bytes.extend_from_slice(&encode_jr(31).to_le_bytes());
    bytes.extend_from_slice(&encode_nop().to_le_bytes());
    let instrs: Vec<_> = MipsLinearDisassembler::new(&a, &bytes, addr(0))
        .flatten()
        .collect();
    assert!(detect_mips_epilogue(&instrs));
}

#[test]
fn detect_epilogue_missing_jr() {
    let a = MipsArch::mips32_le();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&encode_lw(31, 29, 28).to_le_bytes());
    bytes.extend_from_slice(&encode_addiu(29, 29, 32).to_le_bytes());
    let instrs: Vec<_> = MipsLinearDisassembler::new(&a, &bytes, addr(0))
        .flatten()
        .collect();
    assert!(!detect_mips_epilogue(&instrs));
}

// ---------------------------------------------------------------
// MIPS32R2_EXTENSIONS table
// ---------------------------------------------------------------

#[test]
fn mips32r2_extensions_present() {
    assert!(!MIPS32R2_EXTENSIONS.is_empty());
    assert!(MIPS32R2_EXTENSIONS.iter().any(|(n, _)| *n == "seb"));
    assert!(MIPS32R2_EXTENSIONS.iter().any(|(n, _)| *n == "rotr"));
}

// ---------------------------------------------------------------
// Architecture::get_branches
// ---------------------------------------------------------------

#[test]
fn get_branches_for_jal() {
    let a = MipsArch::mips32_le();
    let w = encode_jal(0x100);
    let bytes = w.to_le_bytes();
    let i = a.decode_word(addr(0), w, &bytes);
    let b = a.get_branches(&i);
    assert_eq!(b.len(), 1);
}

#[test]
fn get_branches_nonbranch_empty() {
    let a = MipsArch::mips32_le();
    let i = decode_le(&a, encode_addu(3, 1, 2));
    assert!(a.get_branches(&i).is_empty());
}

#[test]
fn get_branches_beq() {
    let a = MipsArch::mips32_le();
    let w = encode_beq(1, 2, 4);
    let bytes = w.to_le_bytes();
    let i = a.decode_word(addr(0x100), w, &bytes);
    let b = a.get_branches(&i);
    assert_eq!(b.len(), 1);
}

// ---------------------------------------------------------------
// Architecture::registers and calling_conventions
// ---------------------------------------------------------------

#[test]
fn registers_returns_nonempty() {
    let regs = MipsArch::mips32_le().registers();
    assert!(regs.len() >= 32);
}

#[test]
fn registers_64bit_size() {
    let regs = MipsArch::mips64_le().registers();
    // First 32 GPRs should be 8 bytes wide.
    for r in regs.iter().take(32) {
        assert_eq!(r.size, 8, "{:?}", r);
    }
}

// ---------------------------------------------------------------
// Hash / Eq on enums
// ---------------------------------------------------------------

#[test]
fn enums_eq_and_hash() {
    use std::collections::HashSet;
    let mut s: HashSet<MipsEndian> = HashSet::new();
    s.insert(MipsEndian::Big);
    s.insert(MipsEndian::Little);
    s.insert(MipsEndian::Big);
    assert_eq!(s.len(), 2);

    let mut s2: HashSet<MipsAbi> = HashSet::new();
    s2.insert(MipsAbi::O32);
    s2.insert(MipsAbi::N32);
    s2.insert(MipsAbi::N64);
    s2.insert(MipsAbi::O32);
    assert_eq!(s2.len(), 3);
}

// ---------------------------------------------------------------
// encode_syscall layout
// ---------------------------------------------------------------

#[test]
fn encode_syscall_layout() {
    let w = encode_syscall(0x12345);
    // funct field = 0x0C
    assert_eq!(w & 0x3F, 0x0C);
    // code in bits 6..26
    assert_eq!((w >> 6) & 0xFFFFF, 0x12345);
}

// ---------------------------------------------------------------
// Send/Sync exposure
// ---------------------------------------------------------------

#[test]
fn arch_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MipsArch>();
    assert_send_sync::<MipsEndian>();
    assert_send_sync::<MipsAbi>();
    assert_send_sync::<GprRole>();
    assert_send_sync::<HiLoEffect>();
}
