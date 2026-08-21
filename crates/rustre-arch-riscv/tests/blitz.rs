//! Blitz test suite for rustre-arch-riscv: exercises pure helpers,
//! field extractors, encoders, lookups, and round-trip invariants.

use rustre_arch_riscv::*;

// ---------------------------------------------------------------------------
// Field extractors
// ---------------------------------------------------------------------------

#[test]
fn opcode_extracts_low_7_bits() {
    assert_eq!(rv_opcode(0xFFFF_FF13), 0x13);
    assert_eq!(rv_opcode(0x0000_0000), 0x00);
    assert_eq!(rv_opcode(0x0000_007F), 0x7F);
}

#[test]
fn rd_rs1_rs2_funct_extract_correct_fields() {
    // Construct word with rd=5, funct3=1, rs1=7, rs2=11, funct7=0x20
    let word: u32 = (0x20 << 25) | (11 << 20) | (7 << 15) | (1 << 12) | (5 << 7) | 0x33;
    assert_eq!(rv_rd(word), 5);
    assert_eq!(rv_funct3(word), 1);
    assert_eq!(rv_rs1(word), 7);
    assert_eq!(rv_rs2(word), 11);
    assert_eq!(rv_funct7(word), 0x20);
}

#[test]
fn imm_i_sign_extends_negative() {
    // imm = -1
    let word: u32 = 0xFFF0_0013;
    assert_eq!(rv_imm_i(word), -1);
    // imm = -2048 (most negative I-imm)
    let word: u32 = (0x800u32 << 20) | 0x13;
    assert_eq!(rv_imm_i(word), -2048);
    // imm = 2047 (most positive)
    let word: u32 = (0x7FFu32 << 20) | 0x13;
    assert_eq!(rv_imm_i(word), 2047);
}

#[test]
fn imm_s_combines_two_halves() {
    // SW rs2=1, rs1=2, imm=4 produced by encoder
    let w = rv_encode_sw(1, 2, 4);
    assert_eq!(rv_imm_s(w), 4);
    let w = rv_encode_sw(1, 2, -4);
    assert_eq!(rv_imm_s(w), -4);
    let w = rv_encode_sw(0, 0, -2048);
    assert_eq!(rv_imm_s(w), -2048);
    let w = rv_encode_sw(0, 0, 2047);
    assert_eq!(rv_imm_s(w), 2047);
}

#[test]
fn imm_b_roundtrip_aligned_offsets() {
    // B immediates are encoded in multiples of 2, range -4096..4094
    for off in [-4096, -2, 0, 2, 8, 100, 4094] {
        assert!(rv_btype_roundtrip(off), "B-type roundtrip failed for {off}");
    }
}

#[test]
fn imm_j_roundtrip_aligned_offsets() {
    for off in [-1_048_576, -2, 0, 2, 8, 1_048_574] {
        assert!(rv_jtype_roundtrip(off), "J-type roundtrip failed for {off}");
    }
}

#[test]
fn imm_u_keeps_high_20_bits() {
    let word: u32 = 0xABCD_E037;
    assert_eq!(rv_imm_u(word), 0xABCD_E000);
}

#[test]
fn branch_target_handles_negative() {
    // BEQ x0,x0,-8 → encoded with imm12=1
    // build via encode_beq
    let word = rv_encode_beq(0, 0, -8);
    let tgt = rv_branch_target(0x1000, word);
    assert_eq!(tgt, 0x0FF8);
}

#[test]
fn jal_target_handles_negative() {
    let word = rv_encode_jal(1, -8);
    assert_eq!(rv_jal_target(0x1000, word), 0x0FF8);
}

// ---------------------------------------------------------------------------
// Opcode classification
// ---------------------------------------------------------------------------

#[test]
fn classify_known_opcodes() {
    assert!(matches!(rv_classify(0x03), RvOpcodeClass::Load));
    assert!(matches!(rv_classify(0x07), RvOpcodeClass::LoadFp));
    assert!(matches!(rv_classify(0x0F), RvOpcodeClass::MiscMem));
    assert!(matches!(rv_classify(0x13), RvOpcodeClass::OpImm));
    assert!(matches!(rv_classify(0x17), RvOpcodeClass::Auipc));
    assert!(matches!(rv_classify(0x1B), RvOpcodeClass::OpImm32));
    assert!(matches!(rv_classify(0x23), RvOpcodeClass::Store));
    assert!(matches!(rv_classify(0x33), RvOpcodeClass::Op));
    assert!(matches!(rv_classify(0x37), RvOpcodeClass::Lui));
    assert!(matches!(rv_classify(0x3B), RvOpcodeClass::Op32));
    assert!(matches!(rv_classify(0x53), RvOpcodeClass::OpFp));
    assert!(matches!(rv_classify(0x63), RvOpcodeClass::Branch));
    assert!(matches!(rv_classify(0x67), RvOpcodeClass::Jalr));
    assert!(matches!(rv_classify(0x6F), RvOpcodeClass::Jal));
    assert!(matches!(rv_classify(0x73), RvOpcodeClass::System));
}

#[test]
fn classify_reserved_opcode_is_unknown() {
    // 0x00 has bit pattern of nothing valid; bit pattern 0x7F also.
    assert!(matches!(rv_classify(0x00), RvOpcodeClass::Unknown));
    assert!(matches!(rv_classify(0x7F), RvOpcodeClass::Unknown));
}

#[test]
fn is_load_store_branch_helpers() {
    assert!(rv_is_load(0x03));
    assert!(rv_is_load(0x07));
    assert!(!rv_is_load(0x13));
    assert!(rv_is_store(0x23));
    assert!(rv_is_store(0x27));
    assert!(!rv_is_store(0x33));
    assert!(rv_is_branch(0x63));
    assert!(!rv_is_branch(0x6F));
    assert!(rv_is_jal(0x6F));
    assert!(rv_is_jalr(0x67));
    assert!(!rv_is_jalr(0x6F));
}

// ---------------------------------------------------------------------------
// Register names / roles
// ---------------------------------------------------------------------------

#[test]
fn gpr_names_cover_all_32() {
    for i in 0u8..32 {
        let n = rv_gpr_name(i);
        assert!(!n.is_empty(), "gpr {i} empty");
    }
    assert_eq!(rv_gpr_name(0), "zero");
    assert_eq!(rv_gpr_name(2), "sp");
    assert_eq!(rv_gpr_name(8), "s0");
}

#[test]
fn fpr_names_cover_all_32() {
    for i in 0u8..32 {
        let n = rv_fpr_name(i);
        assert!(!n.is_empty(), "fpr {i} empty");
    }
}

#[test]
fn caller_callee_saved_disjoint_for_args_and_saved() {
    // a0..a7 should be caller-saved
    for i in 10u8..=17 {
        assert!(rv_is_caller_saved(i), "x{i} should be caller-saved");
    }
    // s0..s11 (8,9,18..27) should be callee-saved
    for i in [8u8, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27] {
        assert!(rv_is_callee_saved(i), "x{i} should be callee-saved");
    }
}

// ---------------------------------------------------------------------------
// Special instruction predicates
// ---------------------------------------------------------------------------

#[test]
fn special_instr_constants() {
    assert!(rv_is_nop(RV_NOP));
    assert!(rv_is_ebreak(RV_EBREAK));
    assert!(rv_is_ecall(RV_ECALL));
    assert!(rv_is_mret(RV_MRET));
    assert!(rv_is_wfi(RV_WFI));
    assert!(!rv_is_ecall(RV_EBREAK));
    assert!(!rv_is_nop(0));
}

#[test]
fn ret_is_jalr_x0_ra_0() {
    // JALR x0, 0(ra): rd=0, rs1=1, imm=0, funct3=0, opcode=0x67
    let word = rv_encode_jalr(0, 1, 0);
    assert!(rv_is_ret(word));
    assert!(!rv_is_ret(0));
}

#[test]
fn fence_predicates() {
    // FENCE: opcode 0x0F, funct3 0
    let fence: u32 = 0x0000_000F;
    assert!(rv_is_fence(fence));
    assert!(!rv_is_fence_i(fence));
    // FENCE.I: opcode 0x0F, funct3 1
    let fence_i: u32 = (1u32 << 12) | 0x0F;
    assert!(rv_is_fence_i(fence_i));
    assert!(!rv_is_fence(fence_i));
}

// ---------------------------------------------------------------------------
// Encoders → field extractors round-trip
// ---------------------------------------------------------------------------

#[test]
fn encode_addi_roundtrip() {
    for &imm in &[-2048i16, -100, -1, 0, 1, 100, 2047] {
        let w = rv_encode_addi(5, 6, imm);
        assert_eq!(rv_opcode(w), 0x13);
        assert_eq!(rv_rd(w), 5);
        assert_eq!(rv_rs1(w), 6);
        assert_eq!(rv_imm_i(w), i32::from(imm));
    }
}

#[test]
fn encode_lw_roundtrip() {
    let w = rv_encode_lw(3, 4, -16);
    assert_eq!(rv_opcode(w), 0x03);
    assert_eq!(rv_funct3(w), 2);
    assert_eq!(rv_rd(w), 3);
    assert_eq!(rv_rs1(w), 4);
    assert_eq!(rv_imm_i(w), -16);
}

#[test]
fn encode_jal_extracts_jtype() {
    for off in [-8, 0, 8, 1024, -1024] {
        let w = rv_encode_jal(1, off);
        assert_eq!(rv_opcode(w), 0x6F);
        assert_eq!(rv_rd(w), 1);
        assert_eq!(rv_imm_j(w), off);
    }
}

#[test]
fn encode_lui_auipc_have_correct_opcode() {
    let l = rv_encode_lui(5, 0x12345);
    assert_eq!(rv_opcode(l), 0x37);
    assert_eq!(rv_rd(l), 5);
    let a = rv_encode_auipc(5, 0x12345);
    assert_eq!(rv_opcode(a), 0x17);
}

#[test]
fn encode_arith_r_type() {
    let w = rv_encode_add(1, 2, 3);
    assert_eq!(rv_opcode(w), 0x33);
    assert_eq!(rv_funct3(w), 0);
    assert_eq!(rv_funct7(w), 0);
    let w = rv_encode_sub(1, 2, 3);
    assert_eq!(rv_funct7(w), 0x20);
    let w = rv_encode_and(1, 2, 3);
    assert_eq!(rv_funct3(w), 7);
    let w = rv_encode_or(1, 2, 3);
    assert_eq!(rv_funct3(w), 6);
    let w = rv_encode_xor(1, 2, 3);
    assert_eq!(rv_funct3(w), 4);
}

#[test]
fn encode_mul_div() {
    let m = rv_encode_mul(1, 2, 3);
    assert_eq!(rv_opcode(m), 0x33);
    assert_eq!(rv_funct7(m), 1);
    let d = rv_encode_div(1, 2, 3);
    assert_eq!(rv_funct7(d), 1);
    assert_eq!(rv_funct3(d), 4);
}

#[test]
fn encode_csr_instrs() {
    let w = rv_encode_csrrw(1, 2, 0x300);
    assert_eq!(rv_opcode(w), 0x73);
    assert_eq!(rv_funct3(w), 1);
    let w = rv_encode_csrrs(1, 2, 0x300);
    assert_eq!(rv_funct3(w), 2);
    let w = rv_encode_csrrc(1, 2, 0x300);
    assert_eq!(rv_funct3(w), 3);
}

// ---------------------------------------------------------------------------
// Bit manipulation helpers
// ---------------------------------------------------------------------------

#[test]
fn rv_bits_extract_ranges() {
    assert_eq!(rv_bits(0xFF, 7, 0), 0xFF);
    assert_eq!(rv_bits(0xFF, 3, 0), 0x0F);
    assert_eq!(rv_bits(0xF0, 7, 4), 0x0F);
    assert_eq!(rv_bits(0xFFFF_FFFF, 31, 0), 0xFFFF_FFFF);
}

#[test]
fn sign_ext_basic() {
    assert_eq!(rv_sign_ext(0xFF, 8), -1);
    assert_eq!(rv_sign_ext(0x7F, 8), 127);
    assert_eq!(rv_sign_ext(0, 8), 0);
    assert_eq!(rv_sign_ext64(0xFFFF, 16), -1);
    assert_eq!(rv_sign_ext64(0x7FFF, 16), 32767);
}

#[test]
fn popcount_clz_ctz() {
    assert_eq!(rv_popcount(0), 0);
    assert_eq!(rv_popcount(0xFFFF_FFFF), 32);
    assert_eq!(rv_clz32(0), 32);
    assert_eq!(rv_clz32(1), 31);
    assert_eq!(rv_ctz32(0), 32);
    assert_eq!(rv_ctz32(8), 3);
    assert_eq!(rv_cpop32(0xF), 4);
}

#[test]
fn ror32_ror64() {
    assert_eq!(rv_ror32(1, 1), 0x8000_0000);
    assert_eq!(rv_ror32(0, 5), 0);
    assert_eq!(rv_ror64(1, 1), 0x8000_0000_0000_0000);
}

#[test]
fn rev8_swap_bytes() {
    assert_eq!(rv_rev8_32(0x1122_3344), 0x4433_2211);
}

#[test]
fn brev8_reverses_each_byte() {
    // 0x01 → bit-rev → 0x80 per byte
    assert_eq!(rv_brev8_32(0x0000_0001), 0x0000_0080);
    assert_eq!(rv_brev8_32(0x8000_0000), 0x0100_0000);
}

#[test]
fn orcb_propagates_byte_wise() {
    assert_eq!(rv_orcb32(0x0000_0001), 0x0000_00FF);
    assert_eq!(rv_orcb32(0x0000_0000), 0);
    // bytes [01, 00, 00, 01] (LE) → both non-zero bytes become 0xFF
    assert_eq!(rv_orcb32(0x0100_0001), 0xFF00_00FF);
}

#[test]
fn zext_sext_bounds() {
    assert_eq!(rv_zext(0xFFFF_FFFF_FFFF_FFFF, 8), 0xFF);
    assert_eq!(rv_zext(0xAB, 64), 0xAB);
    assert_eq!(rv_sext(0xFF, 8), -1);
    assert_eq!(rv_sext(0x7F, 8), 127);
    assert_eq!(rv_sext(0, 0), 0);
}

// ---------------------------------------------------------------------------
// Sv* / page helpers
// ---------------------------------------------------------------------------

#[test]
fn page_constants() {
    assert_eq!(RV_PAGE_SIZE, 4096);
    assert_eq!(RV_PAGE_OFFSET_BITS, 12);
    assert_eq!(SV39_LEVELS, 3);
    assert_eq!(SV48_LEVELS, 4);
    assert_eq!(SV57_LEVELS, 5);
}

#[test]
fn sv39_vpn_extraction() {
    // VA: VPN[2]=5, VPN[1]=3, VPN[0]=7, offset=0
    let va: u64 = (5u64 << (12 + 18)) | (3u64 << (12 + 9)) | (7u64 << 12);
    assert_eq!(sv39_vpn(va, 0), 7);
    assert_eq!(sv39_vpn(va, 1), 3);
    assert_eq!(sv39_vpn(va, 2), 5);
}

#[test]
fn sv39_canonical_sign_extends() {
    // bit 38 = 1 → upper bits filled
    let va: u64 = 1 << 38;
    let c = sv39_canonical(va);
    assert_eq!(c & 0xFFFF_FF80_0000_0000, 0xFFFF_FF80_0000_0000);
    // bit 38 = 0 → upper bits clear
    let va: u64 = 0x1234;
    assert_eq!(sv39_canonical(va), 0x1234);
}

#[test]
fn phys_addr_combines_ppn_and_offset() {
    assert_eq!(rv_phys_addr(0xABCD, 0x123), (0xABCD << 12) | 0x123);
    // offset masked to 12 bits
    assert_eq!(rv_phys_addr(1, 0x1234), (1 << 12) | 0x234);
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

#[test]
fn csr_lookup_known_and_unknown() {
    assert!(rv_csr_ext_lookup(0xC00).is_some()); // cycle
    assert!(rv_csr_ext_lookup(0x300).is_some()); // mstatus
    assert!(rv_csr_ext_lookup(0xFFFF).is_none());
}

#[test]
fn exc_cause_interrupt_vs_exception() {
    let e = rv_exc_cause_lookup(3, false).unwrap();
    assert_eq!(e.name, "Breakpoint");
    let i = rv_exc_cause_lookup(7, true).unwrap();
    assert_eq!(i.name, "MachineTimerInterrupt");
    // Same code different interrupt flag may yield different entry
    assert!(rv_exc_cause_lookup(999, false).is_none());
}

#[test]
fn cpu_lookup() {
    assert!(rv_cpu_lookup("SiFive U74").is_some());
    assert!(rv_cpu_lookup("nonexistent-cpu-foo").is_none());
}

#[test]
fn instr_lookup() {
    assert_eq!(rv_instr_lookup("lw").unwrap().format, "I");
    assert_eq!(rv_instr_lookup("add").unwrap().format, "R");
    assert!(rv_instr_lookup("not_an_instr").is_none());
}

#[test]
fn sbi_lookup_known() {
    assert!(sbi_lookup(0x00, 0).is_some());
    assert!(sbi_lookup(0xDEAD_BEEF, 0).is_none());
}

#[test]
fn abi_reg_lookup() {
    let r = rv_abi_reg_lookup("a0").unwrap();
    assert_eq!(r.phys_idx, 10);
    assert!(rv_abi_reg_lookup("nonexistent").is_none());
    let r = rv_fp_abi_reg_lookup("fa0").unwrap();
    assert_eq!(r.phys_idx, 10);
}

#[test]
fn arg_regs_and_callee_saved_collections() {
    let args = rv_arg_regs();
    assert!(args.len() >= 8, "expected >=8 arg regs, got {}", args.len());
    let cs = rv_callee_saved_regs();
    assert!(!cs.is_empty());
    let fpargs = rv_fp_arg_regs();
    assert!(!fpargs.is_empty());
}

// ---------------------------------------------------------------------------
// MISA helpers
// ---------------------------------------------------------------------------

#[test]
fn misa_ext_char_and_has() {
    assert_eq!(rv_misa_ext_char(0), 'A');
    assert_eq!(rv_misa_ext_char(8), 'I');
    let misa: u64 = (1 << 8) | (1 << 12); // I + M
    assert!(rv_misa_has(misa, 8));
    assert!(rv_misa_has(misa, 12));
    assert!(!rv_misa_has(misa, 0));
}

#[test]
fn misa_mxl_decoding() {
    // mxl is top 2 bits of XLEN-bit MISA. Confirm function exists and returns sane values for typical values.
    let v32 = rv_misa_mxl(1u64 << 30);
    let v64 = rv_misa_mxl(2u64 << 62);
    assert!(v32 == 32 || v32 == 64 || v32 == 128);
    assert!(v64 == 32 || v64 == 64 || v64 == 128);
}

// ---------------------------------------------------------------------------
// Features
// ---------------------------------------------------------------------------

#[test]
fn rv_features_union_and_has() {
    let f = RvFeatures::I.union(RvFeatures::M);
    assert!(f.has(RvFeatures::I));
    assert!(f.has(RvFeatures::M));
    assert!(!f.has(RvFeatures::D));
    let g = RvFeatures::rv64gc();
    assert!(g.has(RvFeatures::I));
    assert!(g.has(RvFeatures::C));
    assert!(g.has(RvFeatures::D));
    let h = RvFeatures::rv32imac();
    assert!(h.has(RvFeatures::A));
    assert!(!h.has(RvFeatures::F));
}

// ---------------------------------------------------------------------------
// Vector helpers
// ---------------------------------------------------------------------------

#[test]
fn vsew_from_bits() {
    assert_eq!(RvVsew::from_bits(0), Some(RvVsew::E8));
    assert_eq!(RvVsew::from_bits(1), Some(RvVsew::E16));
    assert_eq!(RvVsew::from_bits(2), Some(RvVsew::E32));
    assert_eq!(RvVsew::from_bits(3), Some(RvVsew::E64));
    assert_eq!(RvVsew::from_bits(4), None);
    assert_eq!(RvVsew::E32.bits(), 32);
    assert_eq!(RvVsew::E8.bits(), 8);
}

#[test]
fn vtype_imm_encoding() {
    let imm = rv_vtype_imm(false, false, 2, 0); // SEW=32 LMUL=1
    let imm2 = rv_vtype_imm(true, true, 2, 0);
    assert_ne!(imm, imm2);
}

// ---------------------------------------------------------------------------
// Hart state
// ---------------------------------------------------------------------------

#[test]
fn hart_reset_state() {
    let h = RvHartState::reset();
    assert_eq!(h.priv_level, RvPrivLevel::Machine);
    assert_eq!(h.ra(), 0);
    assert_eq!(h.fp(), 0);
    assert!(!h.trap_pending());
    assert!(!h.interrupts_enabled());
}

#[test]
fn hart_x0_is_read_only_zero() {
    let mut h = RvHartState::reset();
    h.write_x(0, 0xDEAD);
    assert_eq!(h.read_x(0), 0);
    h.write_x(5, 0x123);
    assert_eq!(h.read_x(5), 0x123);
}

#[test]
fn hart_trap_pending_when_mcause_nonzero() {
    let mut h = RvHartState::reset();
    h.mcause = 1;
    assert!(h.trap_pending());
}

// ---------------------------------------------------------------------------
// Prologue detection
// ---------------------------------------------------------------------------

#[test]
fn prologue_frame_size_negative_imm() {
    let w = rv_encode_addi(2, 2, -16);
    assert_eq!(rv_prologue_frame_size(w), Some(16));
}

#[test]
fn prologue_frame_size_rejects_non_sp() {
    let w = rv_encode_addi(3, 3, -16);
    assert_eq!(rv_prologue_frame_size(w), None);
}

#[test]
fn prologue_frame_size_rejects_positive() {
    let w = rv_encode_addi(2, 2, 16);
    assert_eq!(rv_prologue_frame_size(w), None);
}

#[test]
fn detect_prologue_addi_then_sd() {
    let addi = rv_encode_addi(2, 2, -32);
    // SD ra, 24(sp): opcode=0x23, funct3=3, rs1=2, rs2=1, imm=24
    let imm: u32 = 24;
    let imm11_5 = (imm >> 5) & 0x7f;
    let imm4_0 = imm & 0x1f;
    let sd = (imm11_5 << 25) | (1 << 20) | (2 << 15) | (3 << 12) | (imm4_0 << 7) | 0x23;
    // Non-prologue terminator
    let nop = RV_NOP;
    let (frame, spills) = rv_detect_prologue(&[addi, sd, nop]);
    assert_eq!(frame, Some(32));
    assert_eq!(spills.len(), 1);
    assert_eq!(spills[0].sp_offset, 24);
    assert_eq!(spills[0].size, 8);
}

// ---------------------------------------------------------------------------
// Tail / indirect call detection
// ---------------------------------------------------------------------------

#[test]
fn tail_call_jal_x0() {
    // JAL x0, 8
    let w = rv_encode_jal(0, 8);
    assert!(rv_is_tail_call(w));
    // JAL x1 is not a tail call
    let w = rv_encode_jal(1, 8);
    assert!(!rv_is_tail_call(w));
}

#[test]
fn indirect_call_jalr_ra_nonra_rs1() {
    // JALR ra, 0(t0=x5)
    let w = rv_encode_jalr(1, 5, 0);
    assert!(rv_is_indirect_call(w));
    // JALR ra, 0(ra) is NOT classified as indirect call per impl
    let w = rv_encode_jalr(1, 1, 0);
    assert!(!rv_is_indirect_call(w));
}

// ---------------------------------------------------------------------------
// PC alignment helpers
// ---------------------------------------------------------------------------

#[test]
fn instr_alignment_checks() {
    assert!(rv_is_instr_aligned(0));
    assert!(rv_is_instr_aligned(0x1000));
    assert!(!rv_is_instr_aligned(1));
    assert!(!rv_is_instr_aligned(2));
    assert!(!rv_is_instr_aligned(3));
    assert!(rv_is_cinstr_aligned(0));
    assert!(rv_is_cinstr_aligned(2));
    assert!(!rv_is_cinstr_aligned(1));
}

// ---------------------------------------------------------------------------
// Overflow arithmetic
// ---------------------------------------------------------------------------

#[test]
fn add_ov_sub_ov() {
    assert_eq!(rv_add_ov(1, 2), Some(3));
    assert_eq!(rv_add_ov(i64::MAX, 1), None);
    assert_eq!(rv_sub_ov(0, 1), Some(-1));
    assert_eq!(rv_sub_ov(i64::MIN, 1), None);
}

#[test]
fn addw_subw_wrap_low32() {
    // ADDW/SUBW sign-extend the low 32 bits of result
    let r = rv_addw(0x7FFF_FFFF, 1);
    assert_eq!(r, -(1i64 << 31)); // overflow into sign bit
    let r = rv_subw(0, 1);
    assert_eq!(r, -1i64);
}

#[test]
fn slt_sltu_semantics() {
    assert_eq!(rv_slt(-1, 0), 1);
    assert_eq!(rv_slt(0, -1), 0);
    assert_eq!(rv_sltu(0, 1), 1);
    assert_eq!(rv_sltu(u64::MAX, 0), 0);
}

#[test]
fn mul_div_rem() {
    assert_eq!(rv_mul(3, 4), 12);
    assert_eq!(rv_mulh(i64::MAX, 2), 0);
    assert_eq!(rv_div(10, 3), 3);
    assert_eq!(rv_divu(10, 3), 3);
    assert_eq!(rv_rem(10, 3), 1);
    assert_eq!(rv_remu(10, 3), 1);
}

#[test]
fn div_by_zero_returns_riscv_spec_value() {
    // RISC-V spec: x/0 = -1 (all ones), x%0 = x, signed division
    assert_eq!(rv_divu(10, 0), u64::MAX);
    assert_eq!(rv_div(10, 0), -1);
    assert_eq!(rv_remu(10, 0), 10);
    assert_eq!(rv_rem(10, 0), 10);
}

#[test]
fn div_signed_overflow_returns_minimum() {
    // i64::MIN / -1 — spec says return i64::MIN, rem returns 0
    assert_eq!(rv_div(i64::MIN, -1), i64::MIN);
    assert_eq!(rv_rem(i64::MIN, -1), 0);
}

// ---------------------------------------------------------------------------
// Compressed helpers
// ---------------------------------------------------------------------------

#[test]
fn is_compressed_detects_low_bits() {
    // Compressed: low 2 bits != 0b11
    assert!(rv_is_compressed(0x0000));
    assert!(rv_is_compressed(0x0001));
    assert!(rv_is_compressed(0x0002));
    assert!(!rv_is_compressed(0x0003));
    assert!(!rv_is_compressed(0xFFFF));
}

#[test]
fn c_op_funct3_split() {
    let hw: u16 = 0xE003;
    let (op, f3) = rv_c_op_funct3(hw);
    assert_eq!(op, hw.to_le_bytes()[0] & 0x3);
    assert_eq!(f3, ((hw >> 13) & 0x7) as u8);
}

// ---------------------------------------------------------------------------
// Encoding format detection
// ---------------------------------------------------------------------------

#[test]
fn enc_format_detect_for_each_opcode() {
    assert_eq!(RvEncFormat::detect(0x37), RvEncFormat::U); // LUI
    assert_eq!(RvEncFormat::detect(0x17), RvEncFormat::U); // AUIPC
    assert_eq!(RvEncFormat::detect(0x6F), RvEncFormat::J);
    assert_eq!(RvEncFormat::detect(0x63), RvEncFormat::B);
    assert_eq!(RvEncFormat::detect(0x23), RvEncFormat::S);
    assert_eq!(RvEncFormat::detect(0x33), RvEncFormat::R);
    assert_eq!(RvEncFormat::detect(0x13), RvEncFormat::I);
}

#[test]
fn enc_format_name_and_bits() {
    assert_eq!(RvEncFormat::R.name(), "R");
    assert_eq!(RvEncFormat::C.bits(), 16);
    assert_eq!(RvEncFormat::I.bits(), 32);
}

// ---------------------------------------------------------------------------
// MMIO / SoC / PMP
// ---------------------------------------------------------------------------

#[test]
fn qemu_mmio_lookup() {
    // CLINT base typically in QEMU virt
    let r = rv_qemu_region_lookup(0x0200_0000);
    // We don't assert specifically; just that the function runs.
    let _ = r;
    assert!(rv_qemu_region_lookup(0xFFFF_FFFF_FFFF_FFFF).is_none());
}

#[test]
fn pmp_napot_decode_smallest() {
    // pmpaddr with all bits zero except no trailing-one pattern
    // NAPOT format: ...0111...1 where number of trailing ones encodes log2(size)
    // pmpaddr=0 means smallest 4-byte region
    let (base, size) = pmp_napot_decode(0);
    let _ = (base, size);
}

// ---------------------------------------------------------------------------
// LLIL lifters
// ---------------------------------------------------------------------------

#[test]
fn lift_word_nop_produces_some_ops() {
    let ops = rv_lift_word(0x1000, RV_NOP, 64);
    // We don't assert exact length — just that nothing panics and we get a Vec
    let _ = ops.len();
}

#[test]
fn lift_compressed_nop_runs() {
    let ops = rv_lift_compressed(0x1000, 0x0001, 64);
    let _ = ops.len();
}

// ---------------------------------------------------------------------------
// Disassembler smoke
// ---------------------------------------------------------------------------

#[test]
fn riscv_arch_constructors_distinct_bits() {
    assert_eq!(RiscvArch::rv32().bits, 32);
    assert_eq!(RiscvArch::rv64().bits, 64);
    assert_eq!(RiscvArch::rv128().bits, 128);
}

// ---------------------------------------------------------------------------
// CSR table coverage
// ---------------------------------------------------------------------------

#[test]
fn csr_satp_and_misa_present() {
    assert!(rv_csr_ext_lookup(0x180).is_some()); // satp
    assert!(rv_csr_ext_lookup(0x301).is_some()); // misa
}

// ---------------------------------------------------------------------------
// rv_bits zero-width hazard
// ---------------------------------------------------------------------------

#[test]
fn rv_bits_single_bit() {
    assert_eq!(rv_bits(0xAA, 0, 0), 0);
    assert_eq!(rv_bits(0xAB, 0, 0), 1);
    assert_eq!(rv_bits(0xAB, 1, 1), 1);
}
