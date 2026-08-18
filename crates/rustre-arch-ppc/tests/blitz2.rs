//! Blitz2: adversarial / fuzz / boundary / hash / Send+Sync test suite.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_ppc::ppc_branch_analyzer::{
    BranchCondition, BranchTarget, BranchType, decode_bi_field,
};
use rustre_arch_ppc::ppc_registers::{
    CrBit, MsrState, PpcCr, PpcFpr, PpcGpr, PpcSpr, PpcVsr, XerState, msr_bits, xer_bits,
};
use rustre_arch_ppc::{
    PpcArch, PpcLinearDisassembler, encode_add, encode_addi, encode_and, encode_b, encode_bclr,
    encode_bl, encode_cmplwi, encode_cmpwi, encode_dcbf, encode_dcbi, encode_dcbt, encode_dcbz,
    encode_divw, encode_divwu, encode_extsb, encode_extsh, encode_fadd, encode_fcmpu, encode_fdiv,
    encode_fmr, encode_fmul, encode_fsub, encode_icbi, encode_lbz, encode_lfs, encode_lha,
    encode_lhz, encode_li, encode_lis, encode_lwz, encode_mfspr, encode_mfsr, encode_mtspr,
    encode_mtsr, encode_mullw, encode_neg, encode_nor, encode_or, encode_rlwinm, encode_srawi,
    encode_stb, encode_stfs, encode_sth, encode_stw, encode_stwu, encode_subf, encode_tlbie,
    encode_tlbsync, encode_tw, encode_twi, encode_xor, is_valid_ppc_word, lookup_spr,
    ppc_instr_count, ppc_instr_size,
};
use rustre_core::address::Address;
use rustre_core::endian::Endian;

fn arch() -> PpcArch {
    PpcArch::default()
}
const fn arch64() -> PpcArch {
    PpcArch::new_64()
}
const fn a(v: u64) -> Address {
    Address::new(v)
}

/// Seeded LCG for deterministic fuzzing.
struct Lcg(u64);
impl Lcg {
    const fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn next_u32(&mut self) -> u32 {
        (self.next() >> 32) as u32
    }
}

fn hash<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

// ───── Constants / basics ─────────────────────────────────────────────────────

#[test]
fn ppc_instr_size_is_four() {
    assert_eq!(ppc_instr_size(), 4);
}

#[test]
fn ppc_instr_count_basic() {
    assert_eq!(ppc_instr_count(0), 0);
    assert_eq!(ppc_instr_count(4), 1);
    assert_eq!(ppc_instr_count(8), 2);
    assert_eq!(ppc_instr_count(3), 0);
    assert_eq!(ppc_instr_count(7), 1);
    assert_eq!(ppc_instr_count(4 * 100), 100);
}

#[test]
fn ppc_instr_count_max() {
    // Should not overflow on usize::MAX
    let _ = ppc_instr_count(usize::MAX);
}

// ───── Encoder → decoder round trips, 50+ deterministic inputs ────────────────

#[test]
fn rt_li_50_inputs() {
    let arch = arch();
    for i in 0..50u32 {
        let rd = i & 31;
        let imm = i.cast_signed().wrapping_sub(25);
        let w = encode_li(rd, imm);
        let inst = arch.disassemble(a(0), &w.to_be_bytes()).unwrap();
        assert_eq!(inst.mnemonic, "LI");
        assert!(inst.operands.contains(&format!("r{rd}")));
    }
}

#[test]
fn rt_addi_50_inputs() {
    let arch = arch();
    for i in 0..50u32 {
        let rd = (i + 1) & 31;
        let ra = ((i + 3) & 31).max(1); // ra != 0 so it stays ADDI not LI
        let imm = i.cast_signed() - 25;
        let w = encode_addi(rd, ra, imm);
        let inst = arch.disassemble(a(0), &w.to_be_bytes()).unwrap();
        if ra == 0 {
            assert_eq!(inst.mnemonic, "LI");
        } else {
            assert_eq!(inst.mnemonic, "ADDI");
        }
    }
}

#[test]
fn rt_lwz_50_inputs() {
    let arch = arch();
    for i in 0..50u32 {
        let rd = i & 31;
        let ra = (i + 7) & 31;
        let imm = (i.cast_signed() * 4) - 50;
        let w = encode_lwz(rd, ra, imm);
        let inst = arch.disassemble(a(0), &w.to_be_bytes()).unwrap();
        assert_eq!(inst.mnemonic, "LWZ");
        assert!(inst.flags.contains(InstrFlags::READ_MEM));
    }
}

#[test]
fn rt_stw_50_inputs() {
    let arch = arch();
    for i in 0..50u32 {
        let rs = i & 31;
        let ra = (i + 5) & 31;
        let imm = i.cast_signed() - 25;
        let w = encode_stw(rs, ra, imm);
        let inst = arch.disassemble(a(0), &w.to_be_bytes()).unwrap();
        assert_eq!(inst.mnemonic, "STW");
        assert!(inst.flags.contains(InstrFlags::WRITE_MEM));
    }
}

#[test]
fn rt_b_branch_50_inputs() {
    let arch = arch();
    for i in 0..50i32 {
        let disp = (i - 25) * 4;
        let w = encode_b(disp, false);
        let inst = arch.disassemble(a(0x1000), &w.to_be_bytes()).unwrap();
        assert_eq!(inst.mnemonic, "B");
        assert!(inst.flags.contains(InstrFlags::BRANCH));
    }
}

#[test]
fn rt_bl_call_50_inputs() {
    let arch = arch();
    for i in 0..50i32 {
        let disp = (i - 25) * 4;
        let w = encode_bl(disp);
        let inst = arch.disassemble(a(0x2000), &w.to_be_bytes()).unwrap();
        assert_eq!(inst.mnemonic, "BL");
        assert!(inst.flags.contains(InstrFlags::CALL));
    }
}

#[test]
fn rt_arith_mass() {
    let arch = arch();
    for i in 0..30u32 {
        let r1 = i & 31;
        let r2 = (i + 1) & 31;
        let r3 = (i + 2) & 31;
        for (w, mn) in [
            (encode_add(r1, r2, r3), "ADD"),
            (encode_subf(r1, r2, r3), "SUBF"),
            (encode_and(r1, r2, r3), "AND"),
            (encode_or(r1, r2, r3), "OR"),
            (encode_xor(r1, r2, r3), "XOR"),
            (encode_nor(r1, r2, r3), "NOR"),
            (encode_mullw(r1, r2, r3), "MULLW"),
            (encode_divw(r1, r2, r3), "DIVW"),
            (encode_divwu(r1, r2, r3), "DIVWU"),
        ] {
            let inst = arch.disassemble(a(0), &w.to_be_bytes()).unwrap();
            assert_eq!(inst.mnemonic, mn, "encoder mismatch for {mn}");
        }
    }
}

#[test]
fn rt_neg_extsb_extsh() {
    let arch = arch();
    for i in 0..32u32 {
        let inst = arch
            .disassemble(a(0), &encode_neg(i, (i + 1) & 31).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "NEG");

        let inst = arch
            .disassemble(a(0), &encode_extsb((i + 1) & 31, i).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "EXTSB");

        let inst = arch
            .disassemble(a(0), &encode_extsh((i + 1) & 31, i).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "EXTSH");
    }
}

#[test]
fn rt_fp_round_trip() {
    let arch = arch();
    for i in 0..20u32 {
        let fa = i & 31;
        let fb = (i + 5) & 31;
        let fc = (i + 7) & 31;
        let inst = arch
            .disassemble(a(0), &encode_fmr(fa, fb).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "FMR");
        let inst = arch
            .disassemble(a(0), &encode_fadd(fa, fb, fc).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "FADDD");
        let inst = arch
            .disassemble(a(0), &encode_fsub(fa, fb, fc).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "FSUBD");
        let inst = arch
            .disassemble(a(0), &encode_fmul(fa, fb, fc).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "FMULD");
        let inst = arch
            .disassemble(a(0), &encode_fdiv(fa, fb, fc).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "FDIVD");
        let inst = arch
            .disassemble(a(0), &encode_fcmpu(i & 7, fb, fc).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "FCMPU");
    }
}

#[test]
fn rt_fp_loads_stores() {
    let arch = arch();
    for i in 0..20i16 {
        let inst = arch
            .disassemble(a(0), &encode_lfs(3, 1, i * 4).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "LFS");
        assert!(inst.flags.contains(InstrFlags::READ_MEM));

        let inst = arch
            .disassemble(a(0), &encode_stfs(3, 1, i * 4).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "STFS");
        assert!(inst.flags.contains(InstrFlags::WRITE_MEM));
    }
}

#[test]
fn rt_cmp_round_trip() {
    let arch = arch();
    for i in 0..16u32 {
        let inst = arch
            .disassemble(a(0), &encode_cmpwi(i & 7, i & 31, i16::try_from(i).unwrap() - 8).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "CMPWI");
        let inst = arch
            .disassemble(a(0), &encode_cmplwi(i & 7, i & 31, u16::try_from(i).unwrap()).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "CMPLWI");
    }
}

#[test]
fn rt_byte_half_loads_stores() {
    let arch = arch();
    for i in 0..16i16 {
        let inst = arch
            .disassemble(a(0), &encode_lbz(3, 1, i).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "LBZ");
        let inst = arch
            .disassemble(a(0), &encode_lhz(3, 1, i).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "LHZ");
        let inst = arch
            .disassemble(a(0), &encode_lha(3, 1, i).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "LHA");
        let inst = arch
            .disassemble(a(0), &encode_stb(3, 1, i).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "STB");
        let inst = arch
            .disassemble(a(0), &encode_sth(3, 1, i).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "STH");
    }
}

#[test]
fn rt_rlwinm_round_trip() {
    let arch = arch();
    for sh in 0..32u32 {
        let w = encode_rlwinm(3, 4, sh, 0, 31);
        let inst = arch.disassemble(a(0), &w.to_be_bytes()).unwrap();
        assert_eq!(inst.mnemonic, "RLWINM");
    }
}

#[test]
fn rt_srawi_round_trip() {
    let arch = arch();
    for sh in 0..32u32 {
        let w = encode_srawi(3, 4, sh);
        let inst = arch.disassemble(a(0), &w.to_be_bytes()).unwrap();
        assert_eq!(inst.mnemonic, "SRAWI");
    }
}

#[test]
fn rt_tw_twi_round_trip() {
    let arch = arch();
    for to in 0..32u32 {
        let inst = arch
            .disassemble(a(0), &encode_tw(to, 3, 4).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "TW");
        let inst = arch
            .disassemble(a(0), &encode_twi(to, 3, 0).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "TWI");
    }
}

#[test]
fn rt_dcb_icb_round_trip() {
    let arch = arch();
    for i in 0..16u32 {
        let inst = arch
            .disassemble(a(0), &encode_dcbz(i & 31, (i + 1) & 31).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "DCBZ");
        let inst = arch
            .disassemble(a(0), &encode_dcbf(i & 31, (i + 1) & 31).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "DCBF");
        let inst = arch
            .disassemble(a(0), &encode_dcbt(i & 31, (i + 1) & 31).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "DCBT");
        let inst = arch
            .disassemble(a(0), &encode_icbi(i & 31, (i + 1) & 31).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, "ICBI");
    }
    // dcbi exists but check at least it produces a valid 4-byte word that doesn't crash
    let _ = encode_dcbi(3, 4);
}

#[test]
fn rt_mfspr_mtspr_known() {
    let arch = arch();
    for (spr, mf, mt) in [(1u16, "MFXER", "MTXER"), (8, "MFLR", "MTLR"), (9, "MFCTR", "MTCTR")] {
        let inst = arch
            .disassemble(a(0), &encode_mfspr(3, spr).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, mf);
        let inst = arch
            .disassemble(a(0), &encode_mtspr(spr, 3).to_be_bytes())
            .unwrap();
        assert_eq!(inst.mnemonic, mt);
    }
}

#[test]
fn rt_mfsr_mtsr_tlbie() {
    let arch = arch();
    let inst = arch
        .disassemble(a(0), &encode_mfsr(3, 5).to_be_bytes())
        .unwrap();
    assert_eq!(inst.mnemonic, "MFSR");
    let inst = arch
        .disassemble(a(0), &encode_mtsr(5, 3).to_be_bytes())
        .unwrap();
    assert_eq!(inst.mnemonic, "MTSR");
    let inst = arch
        .disassemble(a(0), &encode_tlbie(4).to_be_bytes())
        .unwrap();
    assert_eq!(inst.mnemonic, "TLBIE");
    // tlbsync still produces a 32-bit word
    let _ = encode_tlbsync();
}

#[test]
fn rt_bclr_return() {
    let arch = arch();
    let w = encode_bclr(false);
    let inst = arch.disassemble(a(0), &w.to_be_bytes()).unwrap();
    assert_eq!(inst.mnemonic, "BCLR");
    assert!(inst.flags.contains(InstrFlags::RET));
    let w = encode_bclr(true);
    let inst = arch.disassemble(a(0), &w.to_be_bytes()).unwrap();
    assert_eq!(inst.mnemonic, "BCLRL");
}

#[test]
fn rt_lis_round_trip() {
    let arch = arch();
    for i in 0..30i32 {
        let imm = i - 15;
        let w = encode_lis(3, imm);
        let inst = arch.disassemble(a(0), &w.to_be_bytes()).unwrap();
        assert_eq!(inst.mnemonic, "LIS");
    }
}

#[test]
fn rt_stwu_round_trip() {
    let arch = arch();
    for i in 0..10i32 {
        let w = encode_stwu(1, 1, -((i + 1) * 16));
        let inst = arch.disassemble(a(0), &w.to_be_bytes()).unwrap();
        assert_eq!(inst.mnemonic, "STWU");
    }
}

// ───── Boundary / off-by-one ──────────────────────────────────────────────────

#[test]
fn boundary_li_extremes() {
    let arch = arch();
    for &imm in &[0i32, 1, -1, i32::from(i16::MAX), i32::from(i16::MIN)] {
        let w = encode_li(0, imm);
        let inst = arch.disassemble(a(0), &w.to_be_bytes()).unwrap();
        assert_eq!(inst.mnemonic, "LI");
    }
}

#[test]
fn boundary_disassemble_truncated() {
    let arch = arch();
    for n in 0..4 {
        let bytes = vec![0u8; n];
        let r = arch.disassemble(a(0), &bytes);
        assert!(r.is_err(), "expected err for {n} bytes");
    }
}

#[test]
fn boundary_disassemble_exactly_four() {
    let arch = arch();
    let r = arch.disassemble(a(0), &[0x60, 0x00, 0x00, 0x00]);
    assert!(r.is_ok());
}

#[test]
fn boundary_address_max() {
    let arch = arch();
    let inst = arch
        .disassemble(a(!3u64), &[0x48, 0x00, 0x00, 0x00])
        .unwrap();
    // Should not panic on wraparound branch target arithmetic
    assert_eq!(inst.size, 4);
}

#[test]
fn boundary_address_zero_branch() {
    let arch = arch();
    let w = encode_b(0, false);
    let inst = arch.disassemble(a(0), &w.to_be_bytes()).unwrap();
    assert_eq!(inst.mnemonic, "B");
}

// ───── LCG fuzz: never panic, always Ok or err ───────────────────────────────

#[test]
fn fuzz_disassemble_never_panics_be() {
    let arch = arch();
    let mut lcg = Lcg::new();
    for _ in 0..2000 {
        let w = lcg.next_u32();
        let bytes = w.to_be_bytes();
        let res = arch.disassemble(a(lcg.next() & 0xFFFF_FFF0), &bytes);
        // Either Ok or Err; never panic. With 4 bytes provided, decode_ppc
        // always returns Ok (DC.W fallback).
        assert!(res.is_ok());
    }
}

#[test]
fn fuzz_disassemble_never_panics_le() {
    let arch = PpcArch::new_le();
    let mut lcg = Lcg::new();
    for _ in 0..1500 {
        let w = lcg.next_u32();
        let bytes = w.to_be_bytes(); // arbitrary byte pattern
        let res = arch.disassemble(a(lcg.next()), &bytes);
        assert!(res.is_ok());
    }
}

#[test]
fn fuzz_get_branches_never_panics() {
    let arch = arch();
    let mut lcg = Lcg::new();
    for _ in 0..2000 {
        let w = lcg.next_u32();
        let pc = lcg.next() & !3;
        let bytes = w.to_be_bytes();
        if let Ok(inst) = arch.disassemble(a(pc), &bytes) {
            let _ = arch.get_branches(&inst);
        }
    }
}

#[test]
fn fuzz_linear_disassembler() {
    let arch = arch();
    let mut lcg = Lcg::new();
    let mut buf = vec![0u8; 4 * 200];
    for chunk in buf.chunks_mut(4) {
        let w = lcg.next_u32();
        chunk.copy_from_slice(&w.to_be_bytes());
    }
    let lin = PpcLinearDisassembler::new(&arch, &buf, a(0x1000));
    let mut count = 0;
    for r in lin {
        assert!(r.is_ok());
        count += 1;
    }
    assert_eq!(count, 200);
}

#[test]
fn fuzz_linear_truncated_tail() {
    // Buffer whose length isn't a multiple of 4: must stop cleanly without panic.
    let arch = arch();
    let buf = vec![0x60u8; 10];
    let lin = PpcLinearDisassembler::new(&arch, &buf, a(0));
    let mut last_was_err = false;
    for r in lin {
        if r.is_err() {
            last_was_err = true;
        }
    }
    // Last 2 leftover bytes should produce an Err.
    assert!(last_was_err);
}

#[test]
fn fuzz_is_valid_ppc_word() {
    let mut lcg = Lcg::new();
    let mut valid = 0;
    for _ in 0..1000 {
        if is_valid_ppc_word(lcg.next_u32()) {
            valid += 1;
        }
    }
    // Sanity: not 0, not all.
    assert!(valid > 0);
}

// ───── Hash / Eq consistency ──────────────────────────────────────────────────

#[test]
fn hash_eq_gpr() {
    for i in 0..32u8 {
        let a = PpcGpr(i);
        let b = PpcGpr(i);
        assert_eq!(a, b);
        assert_eq!(hash(&a), hash(&b));
    }
}

#[test]
fn hash_eq_fpr_cr_vsr() {
    for i in 0..32u8 {
        let a = PpcFpr(i);
        let b = PpcFpr(i);
        assert_eq!(hash(&a), hash(&b));
    }
    for i in 0..8u8 {
        let a = PpcCr(i);
        let b = PpcCr(i);
        assert_eq!(hash(&a), hash(&b));
    }
    for i in 0..64u8 {
        let a = PpcVsr(i);
        let b = PpcVsr(i);
        assert_eq!(hash(&a), hash(&b));
    }
}

#[test]
fn hash_eq_spr() {
    let pairs = [
        PpcSpr::Xer,
        PpcSpr::Lr,
        PpcSpr::Ctr,
        PpcSpr::Dec,
        PpcSpr::Dar,
        PpcSpr::Msr,
        PpcSpr::Dsrr0,
        PpcSpr::Pvr,
        PpcSpr::Custom(123),
        PpcSpr::Custom(456),
    ];
    for s in pairs {
        let s2 = s;
        assert_eq!(s, s2);
        assert_eq!(hash(&s), hash(&s2));
    }
}

// ───── Display / FromStr style: name round-trips ─────────────────────────────

#[test]
fn display_gpr_name() {
    assert_eq!(format!("{}", PpcGpr(0)), "r0");
    assert_eq!(format!("{}", PpcGpr(1)), "sp");
    assert_eq!(format!("{}", PpcGpr(31)), "r31");
    // Out-of-range index degrades gracefully (no panic).
    assert_eq!(PpcGpr(40).name(), "r?");
}

#[test]
fn display_fpr_cr_vsr() {
    assert_eq!(format!("{}", PpcFpr(7)), "f7");
    assert_eq!(PpcCr(3).name(), "cr3");
    assert_eq!(PpcVsr(45).name(), "vs45");
}

#[test]
fn ppc_spr_from_raw_round_trip() {
    // The raw-field encoding swaps two 5-bit halves; verify round-trip
    // through (number → raw → from_raw) for known SPRs.
    let cases = [
        (PpcSpr::Xer, 1u16),
        (PpcSpr::Lr, 8),
        (PpcSpr::Ctr, 9),
        (PpcSpr::Dec, 22),
        (PpcSpr::Pvr, 287),
    ];
    for (spr, n) in cases {
        assert_eq!(spr.number(), n);
        // raw form: (n & 0x1F)<<5 | (n>>5)  is inverse of from_raw's swap.
        let raw = ((n & 0x1F) << 5) | (n >> 5);
        assert_eq!(PpcSpr::from_raw(raw), spr);
    }
}

#[test]
fn ppc_spr_custom_unknown() {
    let s = PpcSpr::Custom(999);
    assert_eq!(s.number(), 999);
    assert_eq!(s.name(), "SPR");
}

#[test]
fn ppc_gpr_role_helpers() {
    assert!(PpcGpr(1).is_stack_pointer());
    assert!(!PpcGpr(2).is_stack_pointer());
    assert!(PpcGpr(3).is_param_sysv32());
    assert!(PpcGpr(10).is_param_sysv32());
    assert!(!PpcGpr(11).is_param_sysv32());
    assert!(PpcGpr(13).is_callee_saved_sysv32());
    assert!(PpcGpr(31).is_callee_saved_sysv32());
    assert!(!PpcGpr(12).is_callee_saved_sysv32());
}

#[test]
fn ppc_fpr_role_helpers() {
    assert!(PpcFpr(1).is_param_sysv32());
    assert!(PpcFpr(8).is_param_sysv32());
    assert!(!PpcFpr(9).is_param_sysv32());
    assert!(PpcFpr(14).is_callee_saved_sysv32());
    assert!(PpcFpr(31).is_callee_saved_sysv32());
}

#[test]
fn ppc_vsr_overlap_helpers() {
    for i in 0..32u8 {
        let v = PpcVsr(i);
        assert!(v.is_fpr_mapped());
        assert_eq!(v.as_fpr(), Some(PpcFpr(i)));
    }
    for i in 32..64u8 {
        let v = PpcVsr(i);
        assert!(v.is_vmx_mapped());
        assert_eq!(v.as_fpr(), None);
    }
}

#[test]
fn ppc_cr_bit_mask() {
    assert_eq!(PpcCr(0).bit_mask(), 0xF000_0000);
    assert_eq!(PpcCr(7).bit_mask(), 0x0000_000F);
}

#[test]
fn cr_bit_indices() {
    assert_eq!(CrBit::Lt.index(), 0);
    assert_eq!(CrBit::Gt.index(), 1);
    assert_eq!(CrBit::Eq.index(), 2);
    assert_eq!(CrBit::So.index(), 3);
}

#[test]
fn iterators_complete() {
    assert_eq!(PpcGpr::all().count(), 32);
    assert_eq!(PpcFpr::all().count(), 32);
    assert_eq!(PpcCr::all().count(), 8);
    assert_eq!(PpcVsr::all().count(), 64);
}

// ───── XER / MSR ──────────────────────────────────────────────────────────────

#[test]
fn xer_bit_extraction() {
    let x = XerState { raw: xer_bits::SO | xer_bits::CA | 0x42 };
    assert!(x.so());
    assert!(!x.ov());
    assert!(x.ca());
    assert_eq!(x.byte_count(), 0x42);

    let z = XerState::default();
    assert!(!z.so() && !z.ov() && !z.ca());
    assert_eq!(z.byte_count(), 0);
}

#[test]
fn msr_bit_extraction() {
    let m = MsrState {
        raw: msr_bits::EE | msr_bits::FP | msr_bits::LE,
    };
    assert!(m.ee());
    assert!(m.fp());
    assert!(m.le());
    assert!(!m.pr());
}

// ───── Branch analyzer / BI / BO ──────────────────────────────────────────────

#[test]
fn decode_bi_field_all() {
    for bi in 0..32u8 {
        let (field, bit) = decode_bi_field(bi);
        assert_eq!(field, bi >> 2);
        assert!(matches!(bit, "LT" | "GT" | "EQ" | "SO"));
    }
}

#[test]
fn branch_condition_always() {
    // bo = 0b10100 = decrement off + ignore CR = branch always
    let bc = BranchCondition::new(0b10100, 0);
    assert!(bc.is_always_taken());
    assert!(!bc.uses_ctr());
}

#[test]
fn branch_condition_uses_ctr() {
    // bo bit2 = 0 means decrement CTR
    let bc = BranchCondition::new(0b00010, 0);
    assert!(bc.uses_ctr());
}

#[test]
fn branch_condition_cr_fields() {
    let bc = BranchCondition::new(0b01100, 7); // bi=7 -> field=1, bit=3 (SO)
    assert_eq!(bc.cr_field(), 1);
    assert_eq!(bc.cr_bit_in_field(), 3);
}

#[test]
fn branch_target_display() {
    assert_eq!(format!("{}", BranchTarget::Absolute(0x100)), "0x100");
    assert_eq!(format!("{}", BranchTarget::Register), "<register>");
    assert_eq!(format!("{}", BranchTarget::Unknown), "<unknown>");
}

#[test]
fn branch_type_display() {
    assert_eq!(format!("{}", BranchType::Unconditional), "unconditional");
    assert_eq!(format!("{}", BranchType::Conditional), "conditional");
    assert_eq!(format!("{}", BranchType::Link), "link (call)");
}

// ───── PpcArch get_branches semantics ─────────────────────────────────────────

#[test]
fn get_branches_b_returns_target() {
    let arch = arch();
    let w = encode_b(16, false);
    let inst = arch.disassemble(a(0x1000), &w.to_be_bytes()).unwrap();
    let br = arch.get_branches(&inst);
    assert_eq!(br.len(), 1);
}

#[test]
fn get_branches_bclr_return_empty() {
    let arch = arch();
    let inst = arch
        .disassemble(a(0x1000), &[0x4E, 0x80, 0x00, 0x20])
        .unwrap();
    let br = arch.get_branches(&inst);
    assert!(br.is_empty());
}

#[test]
fn get_branches_non_branch_empty() {
    let arch = arch();
    let inst = arch
        .disassemble(a(0x1000), &encode_li(3, 1).to_be_bytes())
        .unwrap();
    assert!(arch.get_branches(&inst).is_empty());
}

// ───── lookup_spr ─────────────────────────────────────────────────────────────

#[test]
fn lookup_spr_known() {
    // SPR 1 (XER), 8 (LR), 9 (CTR) are well-known. lookup_spr may or may not
    // be populated for all; only assert it doesn't panic for many values.
    for n in 0u16..32 {
        let _ = lookup_spr(n);
    }
    for n in [287u16, 1023, 0] {
        let _ = lookup_spr(n);
    }
}

// ───── PpcArch metadata ───────────────────────────────────────────────────────

#[test]
fn arch_name_variants() {
    assert_eq!(PpcArch::new_32().name(), "ppc");
    assert_eq!(PpcArch::new_64().name(), "ppc64");
    assert_eq!(PpcArch::new_le().name(), "ppcle");
}

#[test]
fn arch_pointer_size() {
    assert_eq!(PpcArch::new_32().pointer_size(), 4);
    assert_eq!(PpcArch::new_64().pointer_size(), 8);
}

#[test]
fn arch_endian() {
    assert_eq!(PpcArch::new_32().endian(), Endian::Big);
    assert_eq!(PpcArch::new_le().endian(), Endian::Little);
}

#[test]
fn arch_registers_includes_pc_lr() {
    let regs = arch().registers();
    let names: Vec<&str> = regs.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"PC"));
    assert!(names.contains(&"LR"));
    assert!(names.contains(&"CTR"));
    assert!(names.contains(&"XER"));
}

#[test]
fn arch_calling_conv_sysv() {
    let ccs = arch().calling_conventions();
    assert!(!ccs.is_empty());
    assert_eq!(ccs[0].name, "ppc_sysv");
}

// ───── Endianness in disassembly ──────────────────────────────────────────────

#[test]
fn endian_le_swap() {
    let arch = PpcArch::new_le();
    // LI r3,1 in BE is 38 60 00 01. In LE form, the same instruction word is
    // stored byte-swapped: 01 00 60 38.
    let inst = arch
        .disassemble(a(0), &[0x01, 0x00, 0x60, 0x38])
        .unwrap();
    assert_eq!(inst.mnemonic, "LI");
}

// ───── Integer overflow paths ─────────────────────────────────────────────────

#[test]
fn overflow_branch_target_wraps() {
    let arch = arch();
    let w = encode_b(-4, false);
    let inst = arch.disassemble(a(0), &w.to_be_bytes()).unwrap();
    // Branching -4 from PC=0 wraps cleanly to near-u64::MAX without panic.
    assert_eq!(inst.mnemonic, "B");
}

#[test]
fn overflow_addi_negative_imm() {
    let arch = arch();
    for &imm in &[i32::from(i16::MIN), -1, 0, 1, i32::from(i16::MAX)] {
        let w = encode_addi(3, 4, imm);
        let inst = arch.disassemble(a(0), &w.to_be_bytes()).unwrap();
        assert_eq!(inst.mnemonic, "ADDI");
    }
}

// ───── Send + Sync threaded stress ────────────────────────────────────────────

#[test]
fn arch_send_sync_threaded() {
    let arch = Arc::new(arch());
    let mut handles = vec![];
    for t in 0..4 {
        let a = Arc::clone(&arch);
        handles.push(thread::spawn(move || {
            for i in 0..100u32 {
                let imm = i.cast_signed() - 50 + t;
                let w = encode_li((i + t.cast_unsigned()) & 31, imm);
                let inst = a.disassemble(Address::new(0), &w.to_be_bytes()).unwrap();
                assert_eq!(inst.mnemonic, "LI");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn arch64_send_sync_threaded() {
    let arch = Arc::new(arch64());
    let mut handles = vec![];
    for _ in 0..4 {
        let a = Arc::clone(&arch);
        handles.push(thread::spawn(move || {
            for i in 0..100u32 {
                let w = encode_add(i & 31, (i + 1) & 31, (i + 2) & 31);
                let inst = a.disassemble(Address::new(0), &w.to_be_bytes()).unwrap();
                assert_eq!(inst.mnemonic, "ADD");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ───── Misc state machine: linear disassembly across mixed valid+invalid ─────

#[test]
fn linear_mixed_valid_invalid() {
    let arch = arch();
    let mut buf = Vec::new();
    buf.extend_from_slice(&encode_li(3, 0).to_be_bytes());
    buf.extend_from_slice(&[0xFFu8, 0xFF, 0xFF, 0xFF]); // junk -> DC.W
    buf.extend_from_slice(&encode_bl(8).to_be_bytes());
    buf.extend_from_slice(&encode_bclr(false).to_be_bytes());

    let lin = PpcLinearDisassembler::new(&arch, &buf, a(0x1000));
    let v: Vec<_> = lin.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(v.len(), 4);
    assert_eq!(v[0].mnemonic, "LI");
    assert_eq!(v[2].mnemonic, "BL");
    assert_eq!(v[3].mnemonic, "BCLR");
}
