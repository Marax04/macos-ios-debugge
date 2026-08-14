//! Blitz test suite for rustre-arch-ppc.
//!
//! Focus: encode->decode round trips, branch analyzer edge cases, SPR field
//! encoding, prologue detection, lookup tables, and adversarial inputs.

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_ppc::ppc_branch_analyzer::{
    BranchTarget, BranchType, PpcBranchAnalyzer, decode_bi_field,
};
use rustre_arch_ppc::{
    PpcArch, PpcBranchCond, PpcLinearDisassembler, detect_ppc_preamble, detect_ppc_prologue,
    encode_add, encode_addi, encode_and, encode_b, encode_bl, encode_cmplwi, encode_cmpwi,
    encode_divw, encode_divwu, encode_extsb, encode_extsh, encode_fadd, encode_fcmpu, encode_fdiv,
    encode_fmr, encode_fmul, encode_fsub, encode_lbz, encode_lfs, encode_lha, encode_lhz,
    encode_li, encode_lis, encode_lwz, encode_mfspr, encode_mtspr, encode_mullw, encode_neg,
    encode_nor, encode_or, encode_rlwinm, encode_srawi, encode_stb, encode_stfs, encode_sth,
    encode_stw, encode_stwu, encode_subf, encode_tw, encode_twi, encode_xor, is_valid_ppc_word,
    lookup_spr, ppc_instr_count, ppc_instr_size,
};
use rustre_core::address::Address;
use rustre_core::endian::Endian;

fn arch() -> PpcArch {
    PpcArch::default()
}
const fn a(v: u64) -> Address {
    Address::new(v)
}
fn disasm(word: u32, pc: u64) -> (String, String, InstrFlags) {
    let i = arch().disassemble(a(pc), &word.to_be_bytes()).unwrap();
    (i.mnemonic, i.operands, i.flags)
}

// ─── encoders → decoder round trip ───────────────────────────────────────────

#[test]
fn rt_li() {
    let w = encode_li(3, 0x1234);
    let (m, _, _) = disasm(w, 0);
    assert_eq!(m, "LI");
}

#[test]
fn rt_li_negative() {
    let w = encode_li(7, -1);
    let (m, ops, _) = disasm(w, 0);
    assert_eq!(m, "LI");
    assert!(ops.contains("r7"));
    assert!(ops.contains("-1"));
}

#[test]
fn rt_lis() {
    let w = encode_lis(5, -1);
    let (m, _, _) = disasm(w, 0);
    assert_eq!(m, "LIS");
}

#[test]
fn rt_addi() {
    let w = encode_addi(4, 5, 16);
    let (m, ops, _) = disasm(w, 0);
    assert_eq!(m, "ADDI");
    assert!(ops.contains("r4"));
    assert!(ops.contains("r5"));
    assert!(ops.contains("16"));
}

#[test]
fn rt_addi_ra_zero_decodes_as_li() {
    // ADDI rd, r0, imm should decode as LI per source.
    let w = encode_addi(9, 0, 42);
    let (m, _, _) = disasm(w, 0);
    assert_eq!(m, "LI");
}

#[test]
fn rt_lwz_stw() {
    let lwz = encode_lwz(3, 1, 8);
    let (m, _, f) = disasm(lwz, 0);
    assert_eq!(m, "LWZ");
    assert!(f.contains(InstrFlags::READ_MEM));
    let stw = encode_stw(3, 1, 8);
    let (m2, _, f2) = disasm(stw, 0);
    assert_eq!(m2, "STW");
    assert!(f2.contains(InstrFlags::WRITE_MEM));
}

#[test]
fn rt_stwu_prologue_size() {
    let w = encode_stwu(1, 1, -64);
    let (m, ops, _) = disasm(w, 0);
    assert_eq!(m, "STWU");
    assert!(ops.contains("-64"));
}

#[test]
fn rt_b_forward() {
    let w = encode_b(0x100, false);
    let (m, _, f) = disasm(w, 0x1000);
    assert_eq!(m, "B");
    assert!(f.contains(InstrFlags::BRANCH));
}

#[test]
fn rt_bl_call() {
    let w = encode_bl(0x40);
    let (m, _, f) = disasm(w, 0x1000);
    assert_eq!(m, "BL");
    assert!(f.contains(InstrFlags::CALL));
}

#[test]
fn rt_b_negative_displacement() {
    // backward branch
    let w = encode_b(-16, false);
    let (m, ops, _) = disasm(w, 0x1000);
    assert_eq!(m, "B");
    // target = 0x1000 + (-16) = 0xFF0
    assert!(ops.contains("00000FF0"), "ops={ops}");
}

#[test]
fn rt_add() {
    let w = encode_add(3, 4, 5);
    let (m, _, _) = disasm(w, 0);
    assert_eq!(m, "ADD");
}

#[test]
fn rt_subf() {
    let w = encode_subf(3, 4, 5);
    let (m, _, _) = disasm(w, 0);
    assert_eq!(m, "SUBF");
}

#[test]
fn rt_logical_ops() {
    assert_eq!(disasm(encode_and(3, 4, 5), 0).0, "AND");
    assert_eq!(disasm(encode_or(3, 4, 5), 0).0, "OR");
    assert_eq!(disasm(encode_xor(3, 4, 5), 0).0, "XOR");
    assert_eq!(disasm(encode_nor(3, 4, 5), 0).0, "NOR");
}

#[test]
fn rt_neg() {
    assert_eq!(disasm(encode_neg(3, 4), 0).0, "NEG");
}

#[test]
fn rt_cmpwi_cmplwi() {
    assert_eq!(disasm(encode_cmpwi(0, 3, -1), 0).0, "CMPWI");
    assert_eq!(disasm(encode_cmplwi(0, 3, 0xFFFF), 0).0, "CMPLWI");
}

#[test]
fn rt_rlwinm() {
    let w = encode_rlwinm(3, 4, 8, 0, 23);
    let (m, _, _) = disasm(w, 0);
    assert_eq!(m, "RLWINM");
}

#[test]
fn rt_srawi() {
    let w = encode_srawi(3, 4, 5);
    let (m, _, _) = disasm(w, 0);
    assert_eq!(m, "SRAWI");
}

#[test]
fn rt_mul_div() {
    assert_eq!(disasm(encode_mullw(3, 4, 5), 0).0, "MULLW");
    assert_eq!(disasm(encode_divw(3, 4, 5), 0).0, "DIVW");
    assert_eq!(disasm(encode_divwu(3, 4, 5), 0).0, "DIVWU");
}

#[test]
fn rt_extsb_extsh() {
    assert_eq!(disasm(encode_extsb(3, 4), 0).0, "EXTSB");
    assert_eq!(disasm(encode_extsh(3, 4), 0).0, "EXTSH");
}

#[test]
fn rt_lbz_stb() {
    assert_eq!(disasm(encode_lbz(3, 1, 0), 0).0, "LBZ");
    assert_eq!(disasm(encode_stb(3, 1, 0), 0).0, "STB");
}

#[test]
fn rt_lhz_sth_lha() {
    assert_eq!(disasm(encode_lhz(3, 1, 0), 0).0, "LHZ");
    assert_eq!(disasm(encode_sth(3, 1, 0), 0).0, "STH");
    assert_eq!(disasm(encode_lha(3, 1, 0), 0).0, "LHA");
}

#[test]
fn rt_tw_twi() {
    assert_eq!(disasm(encode_tw(31, 3, 4), 0).0, "TW");
    assert_eq!(disasm(encode_twi(31, 3, 0), 0).0, "TWI");
}

// ─── FP encoders ─────────────────────────────────────────────────────────────

#[test]
fn rt_fmr() {
    let (m, _, _) = disasm(encode_fmr(1, 2), 0);
    assert_eq!(m, "FMR");
}

#[test]
fn rt_fadd_fsub_fmul_fdiv() {
    assert_eq!(disasm(encode_fadd(1, 2, 3), 0).0, "FADDD");
    assert_eq!(disasm(encode_fsub(1, 2, 3), 0).0, "FSUBD");
    assert_eq!(disasm(encode_fmul(1, 2, 3), 0).0, "FMULD");
    assert_eq!(disasm(encode_fdiv(1, 2, 3), 0).0, "FDIVD");
}

#[test]
fn rt_fcmpu() {
    let (m, _, _) = disasm(encode_fcmpu(0, 1, 2), 0);
    assert_eq!(m, "FCMPU");
}

#[test]
fn rt_lfs_stfs() {
    assert_eq!(disasm(encode_lfs(1, 1, 0), 0).0, "LFS");
    assert_eq!(disasm(encode_stfs(1, 1, 0), 0).0, "STFS");
}

// ─── MFSPR / MTSPR (SPR field swap) ──────────────────────────────────────────

#[test]
fn rt_mfspr_lr() {
    // LR == SPR 8
    let w = encode_mfspr(0, 8);
    let (m, _, _) = disasm(w, 0);
    assert_eq!(m, "MFLR");
}

#[test]
fn rt_mtspr_ctr() {
    // CTR == SPR 9
    let w = encode_mtspr(9, 0);
    let (m, _, _) = disasm(w, 0);
    assert_eq!(m, "MTCTR");
}

#[test]
fn rt_mfspr_xer() {
    let w = encode_mfspr(3, 1);
    assert_eq!(disasm(w, 0).0, "MFXER");
}

#[test]
fn rt_mfspr_unknown_decodes_as_generic() {
    // SPR 287 = PVR (not in the special-case list of the decoder)
    let w = encode_mfspr(3, 287);
    let (m, ops, _) = disasm(w, 0);
    assert_eq!(m, "MFSPR");
    assert!(ops.contains("287"), "ops={ops}");
}

// ─── PpcBranchCond ───────────────────────────────────────────────────────────

#[test]
fn branch_cond_always_is_unconditional() {
    assert!(PpcBranchCond::ALWAYS.is_unconditional());
    assert!(!PpcBranchCond::IF_EQ.is_unconditional());
}

#[test]
fn branch_cond_encode_bc() {
    let w = PpcBranchCond::IF_EQ.encode_bc(0);
    // opcode 16
    assert_eq!(w >> 26, 16);
}

// ─── lookup_spr (lib.rs PPC_SPRS) ────────────────────────────────────────────

#[test]
fn lookup_spr_known() {
    let e = lookup_spr(8).expect("LR");
    assert_eq!(e.number, 8);
    assert!(lookup_spr(0xFFFE).is_none());
}

// ─── PpcArch basics ──────────────────────────────────────────────────────────

#[test]
fn arch_names_and_pointer_sizes() {
    assert_eq!(PpcArch::new_32().name(), "ppc");
    assert_eq!(PpcArch::new_64().name(), "ppc64");
    assert_eq!(PpcArch::new_le().name(), "ppcle");
    assert_eq!(PpcArch::new_32().pointer_size(), 4);
    assert_eq!(PpcArch::new_64().pointer_size(), 8);
    assert_eq!(PpcArch::new_32().endian(), Endian::Big);
    assert_eq!(PpcArch::new_le().endian(), Endian::Little);
}

#[test]
fn arch_little_endian_byte_swap() {
    // Write NOP (0x60000000) in little-endian byte order
    let nop_be = 0x6000_0000u32.to_be_bytes();
    let nop_little = 0x6000_0000u32.to_le_bytes();
    let big = PpcArch::new_32().disassemble(a(0), &nop_be).unwrap();
    let lit = PpcArch::new_le().disassemble(a(0), &nop_little).unwrap();
    assert_eq!(big.mnemonic, lit.mnemonic);
    assert_eq!(big.mnemonic, "ORI");
}

#[test]
fn arch_truncated() {
    assert!(arch().disassemble(a(0), &[0x48, 0x00]).is_err());
    assert!(arch().disassemble(a(0), &[]).is_err());
}

#[test]
fn arch_registers_include_sp_and_pc() {
    let regs = arch().registers();
    assert!(regs.iter().any(|r| r.name == "r1"));
    assert!(regs.iter().any(|r| r.name == "PC"));
    assert!(regs.iter().any(|r| r.name == "LR"));
    assert!(regs.iter().any(|r| r.name == "CTR"));
}

// ─── Linear disassembler ─────────────────────────────────────────────────────

#[test]
fn linear_disasm_handles_odd_trailing_bytes() {
    // Provide 6 bytes — only the first 4 form an instruction; trailing 2 stop.
    let mut code = encode_li(3, 1).to_be_bytes().to_vec();
    code.extend_from_slice(&[0xDE, 0xAD]); // 2 trailing bytes
    let v: Vec<_> = PpcLinearDisassembler::new(&arch(), &code, a(0)).collect();
    // First instr decoded; trailing 2 bytes consumed by error-recovery advancing 4
    // which causes Iterator::next to read from offset 4 with only 2 bytes -> Err,
    // then offset becomes 8 (past end). So total 2 results, second is Err.
    assert_eq!(v.len(), 2);
    assert!(v[0].is_ok());
    assert!(v[1].is_err());
}

#[test]
fn linear_disasm_empty() {
    assert!(PpcLinearDisassembler::new(&arch(), &[], a(0)).next().is_none());
}

// ─── PpcBranchAnalyzer ───────────────────────────────────────────────────────

#[test]
fn branch_analyzer_b_forward() {
    let an = PpcBranchAnalyzer::new();
    let raw = encode_b(0x100, false);
    let br = an.analyze_branch(raw, 0x4000).unwrap();
    assert_eq!(br.branch_type, BranchType::Unconditional);
    assert_eq!(br.resolved_target(), Some(0x4100));
}

#[test]
fn branch_analyzer_bl_call() {
    let an = PpcBranchAnalyzer::new();
    let raw = encode_bl(0x40);
    let br = an.analyze_branch(raw, 0x1000).unwrap();
    assert!(br.is_call());
    assert_eq!(br.resolved_target(), Some(0x1040));
}

#[test]
fn branch_analyzer_bclr_is_return() {
    let an = PpcBranchAnalyzer::new();
    // bclr: opcode=19, BO=20, xo=16, LK=0
    let raw: u32 = (19u32 << 26) | (20u32 << 21) | (16u32 << 1);
    let br = an.analyze_branch(raw, 0).unwrap();
    assert!(br.is_return());
    assert!(br.is_indirect());
}

#[test]
fn branch_analyzer_bctr_is_indirect_not_return() {
    let an = PpcBranchAnalyzer::new();
    let raw: u32 = (19u32 << 26) | (20u32 << 21) | (528u32 << 1);
    let br = an.analyze_branch(raw, 0).unwrap();
    assert!(!br.is_return());
    assert!(br.is_indirect());
    assert_eq!(br.target, BranchTarget::Register);
}

#[test]
fn branch_analyzer_non_branch_none() {
    let an = PpcBranchAnalyzer::new();
    assert!(an.analyze_branch(encode_li(3, 1), 0).is_none());
    assert!(an.analyze_branch(encode_add(3, 4, 5), 0).is_none());
}

#[test]
fn branch_analyzer_find_all_filters() {
    let an = PpcBranchAnalyzer::new();
    let mut data = Vec::new();
    data.extend_from_slice(&encode_bl(0x100).to_be_bytes());
    data.extend_from_slice(&encode_b(0x200, false).to_be_bytes());
    data.extend_from_slice(&encode_li(3, 1).to_be_bytes()); // not a branch
    let all = an.find_all_branches(&data, 0);
    assert_eq!(all.len(), 2);
    let calls = an.find_function_calls(&data, 0);
    assert_eq!(calls.len(), 1);
}

#[test]
fn branch_analyzer_call_map() {
    let an = PpcBranchAnalyzer::new();
    let data = encode_bl(0x1000).to_be_bytes();
    let m = an.call_map(&data, 0x4000);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0], (0x4000, 0x5000));
}

#[test]
fn branch_analyzer_probability_always() {
    let p = PpcBranchAnalyzer::compute_branch_probability(0b10100);
    assert!((p - 1.0).abs() < 1e-9);
}

#[test]
fn decode_bi_field_basics() {
    assert_eq!(decode_bi_field(0), (0, "LT"));
    assert_eq!(decode_bi_field(1), (0, "GT"));
    assert_eq!(decode_bi_field(2), (0, "EQ"));
    assert_eq!(decode_bi_field(3), (0, "SO"));
    assert_eq!(decode_bi_field(8), (2, "LT"));
}

// ─── detect_ppc_prologue ─────────────────────────────────────────────────────

#[test]
fn detect_prologue_full() {
    let arch = arch();
    let mflr = arch.disassemble(a(0), &0x7C08_02A6_u32.to_be_bytes()).unwrap();
    let stw = arch
        .disassemble(a(4), &encode_stw(0, 1, 4).to_be_bytes())
        .unwrap();
    let stwu = arch
        .disassemble(a(8), &encode_stwu(1, 1, -32).to_be_bytes())
        .unwrap();
    let sz = detect_ppc_prologue(&[mflr, stw, stwu]);
    assert_eq!(sz, Some(32));
}

#[test]
fn detect_prologue_short_input() {
    assert!(detect_ppc_prologue(&[]).is_none());
}

#[test]
fn detect_preamble_recognizes_mflr() {
    // 0x7C0802A6
    let s = detect_ppc_preamble(&[0x7C, 0x08, 0x02, 0xA6]);
    assert_eq!(s, Some("MFLR r0"));
}

#[test]
fn detect_preamble_unknown() {
    assert!(detect_ppc_preamble(&[0x00, 0x00, 0x00, 0x00]).is_none());
    assert!(detect_ppc_preamble(&[0x12, 0x34]).is_none());
}

// ─── is_valid_ppc_word ───────────────────────────────────────────────────────

#[test]
fn is_valid_known_good_and_bad() {
    assert!(is_valid_ppc_word(0x6000_0000)); // ORI
    assert!(is_valid_ppc_word(0x4800_0000)); // B
    // opcode 1 reserved
    assert!(!is_valid_ppc_word(0x0400_0000));
    // opcode 4 reserved
    assert!(!is_valid_ppc_word(0x1000_0000));
}

// ─── ppc_instr_size / ppc_instr_count ────────────────────────────────────────

#[test]
fn instr_size_const() {
    assert_eq!(ppc_instr_size(), 4);
}

#[test]
fn instr_count_math() {
    assert_eq!(ppc_instr_count(0), 0);
    assert_eq!(ppc_instr_count(4), 1);
    assert_eq!(ppc_instr_count(7), 1); // floor
    assert_eq!(ppc_instr_count(16), 4);
}

// ─── calling conventions ─────────────────────────────────────────────────────

#[test]
fn calling_conventions_sysv_int_args() {
    let ccs = arch().calling_conventions();
    let cc = &ccs[0];
    assert_eq!(cc.name, "ppc_sysv");
    assert!(cc.int_args.contains(&"r3".to_string()));
    assert!(cc.return_regs.contains(&"r3".to_string()));
}

// ─── get_branches integration ────────────────────────────────────────────────

#[test]
fn arch_get_branches_for_b() {
    let arch = arch();
    let i = arch
        .disassemble(a(0x1000), &encode_b(0x40, false).to_be_bytes())
        .unwrap();
    let branches = arch.get_branches(&i);
    assert_eq!(branches.len(), 1);
}

#[test]
fn arch_get_branches_empty_for_non_branch() {
    let arch = arch();
    let i = arch
        .disassemble(a(0), &encode_li(3, 1).to_be_bytes())
        .unwrap();
    assert!(arch.get_branches(&i).is_empty());
}

// ─── Edge / bug-hunting tests ────────────────────────────────────────────────

#[test]
fn rt_b_max_positive_displacement() {
    // LI field is 26 bits sign-extended, lower 2 bits zero.
    // Max positive displacement = 0x01FF_FFFC bytes.
    let disp: i32 = 0x01FF_FFFC;
    let w = encode_b(disp, false);
    let (m, ops, _) = disasm(w, 0);
    assert_eq!(m, "B");
    // target = 0 + disp
    let expected = format!("{disp:08X}");
    assert!(ops.contains(&expected), "ops={ops} expected~{expected}");
}

#[test]
fn rt_b_max_negative_displacement() {
    // Most negative = -0x0200_0000
    let disp: i32 = -0x0200_0000;
    let w = encode_b(disp, false);
    let pc = 0x0200_0000u64;
    let (m, ops, _) = disasm(w, pc);
    assert_eq!(m, "B");
    // target = 0
    assert!(ops.contains("00000000"), "ops={ops}");
}

#[test]
fn branch_target_wraps_at_low_addr() {
    // Backward branch from low address should still decode
    let w = encode_b(-4, false);
    let (m, _ops, _) = disasm(w, 0x100);
    assert_eq!(m, "B");
}

#[test]
fn cmpwi_with_negative_imm() {
    let w = encode_cmpwi(0, 3, -1);
    let (m, ops, _) = disasm(w, 0);
    assert_eq!(m, "CMPWI");
    assert!(ops.contains("-1"), "ops={ops}");
}

#[test]
fn cmplwi_with_max_unsigned() {
    let w = encode_cmplwi(7, 5, 0xFFFF);
    let (m, ops, _) = disasm(w, 0);
    assert_eq!(m, "CMPLWI");
    assert!(ops.contains("65535"), "ops={ops}");
    assert!(ops.contains("cr7"), "ops={ops}");
}

#[test]
fn rlwinm_max_fields() {
    let w = encode_rlwinm(31, 31, 31, 31, 31);
    let (m, ops, _) = disasm(w, 0);
    assert_eq!(m, "RLWINM");
    assert!(ops.contains("r31"));
}

#[test]
fn linear_disasm_error_recovery_advances() {
    // Provide truncated 3 bytes: iterator should produce one Err then stop.
    let v: Vec<_> = PpcLinearDisassembler::new(&arch(), &[0, 0, 0], a(0)).collect();
    assert_eq!(v.len(), 1);
    assert!(v[0].is_err());
}

#[test]
fn arch_get_branches_empty_for_return() {
    let arch = arch();
    // BCLR
    let i = arch.disassemble(a(0), &[0x4E, 0x80, 0x00, 0x20]).unwrap();
    assert!(i.flags.contains(InstrFlags::RET));
    assert!(arch.get_branches(&i).is_empty());
}
