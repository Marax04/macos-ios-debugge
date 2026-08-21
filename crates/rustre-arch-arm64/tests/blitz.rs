//! Blitz integration tests for `rustre-arch-arm64`.
//!
//! Adversarial coverage of the public API surface in `lib.rs`:
//! decode helpers, bit-field decoders, lookup tables, classification enums,
//! the linear disassembler, and the `Architecture` impl.

use rustre_arch_arm64::*;
use rustre_core::address::Address;
use rustre_core::arch::{Architecture, InstrFlags};
use rustre_core::endian::Endian;

// ────────────────────────── Arm64Arch metadata ──────────────────────────

#[test]
fn arch_name_is_aarch64() {
    assert_eq!(Arm64Arch::new().name(), "aarch64");
}

#[test]
fn arch_pointer_size_8() {
    assert_eq!(Arm64Arch::new().pointer_size(), 8);
}

#[test]
fn arch_endian_little() {
    assert_eq!(Arm64Arch::new().endian(), Endian::Little);
}

#[test]
fn arch_default_equals_new() {
    assert_eq!(Arm64Arch, Arm64Arch::new());
}

// ────────────────────────── disassemble: errors ─────────────────────────

#[test]
fn disasm_empty_errors() {
    assert!(Arm64Arch::new().disassemble(Address::new(0), &[]).is_err());
}

#[test]
fn disasm_three_bytes_errors() {
    assert!(Arm64Arch::new()
        .disassemble(Address::new(0), &[0, 1, 2])
        .is_err());
}

#[test]
fn disasm_extra_bytes_ignored() {
    // NOP + garbage: only first 4 bytes consumed.
    let bytes = [0x1f, 0x20, 0x03, 0xd5, 0xff, 0xff, 0xff, 0xff];
    let instr = Arm64Arch::new()
        .disassemble(Address::new(0x10), &bytes)
        .unwrap();
    assert_eq!(instr.size, 4);
    assert_eq!(instr.bytes.len(), 4);
}

// ─────────────────── disassemble: known good encodings ──────────────────

#[test]
fn disasm_ret() {
    let i = Arm64Arch::new()
        .disassemble(Address::new(0), &[0xc0, 0x03, 0x5f, 0xd6])
        .unwrap();
    assert_eq!(i.mnemonic, "ret");
    assert!(i.flags.contains(InstrFlags::RET));
}

#[test]
fn disasm_b_unconditional() {
    let i = Arm64Arch::new()
        .disassemble(Address::new(0), &[0x01, 0x00, 0x00, 0x14])
        .unwrap();
    assert_eq!(i.mnemonic, "b");
    assert!(i.flags.contains(InstrFlags::BRANCH));
    assert!(!i.flags.contains(InstrFlags::CALL));
}

#[test]
fn disasm_bl_call() {
    let i = Arm64Arch::new()
        .disassemble(Address::new(0), &[0x01, 0x00, 0x00, 0x94])
        .unwrap();
    assert_eq!(i.mnemonic, "bl");
    assert!(i.flags.contains(InstrFlags::CALL | InstrFlags::BRANCH));
}

#[test]
fn disasm_br_indirect() {
    let i = Arm64Arch::new()
        .disassemble(Address::new(0), &[0x00, 0x00, 0x1f, 0xd6])
        .unwrap();
    assert!(i.flags.contains(InstrFlags::BRANCH | InstrFlags::INDIRECT));
}

// ─────────────────────── get_branches semantics ─────────────────────────

#[test]
fn branches_bl_target() {
    let arch = Arm64Arch::new();
    let i = arch
        .disassemble(Address::new(0x1000), &[0x01, 0x00, 0x00, 0x94])
        .unwrap();
    let b = arch.get_branches(&i);
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].target.unwrap(), 0x1004);
    assert!(b[0].kind.is_call());
}

#[test]
fn branches_b_negative_offset() {
    // B #-4: imm26 = 0x03ff_ffff → -4. encoding = 0x17ffffff
    let bytes = 0x17ff_ffff_u32.to_le_bytes();
    let arch = Arm64Arch::new();
    let i = arch.disassemble(Address::new(0x2000), &bytes).unwrap();
    let b = arch.get_branches(&i);
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].target.unwrap(), 0x1ffc);
}

#[test]
fn branches_ret_emits_ret_branch() {
    let arch = Arm64Arch::new();
    let i = arch
        .disassemble(Address::new(0), &[0xc0, 0x03, 0x5f, 0xd6])
        .unwrap();
    let b = arch.get_branches(&i);
    assert_eq!(b.len(), 1, "RET should emit a single ret BranchInfo");
}

#[test]
fn branches_blr_indirect_empty() {
    let arch = Arm64Arch::new();
    let i = arch
        .disassemble(Address::new(0), &[0x00, 0x00, 0x3f, 0xd6])
        .unwrap();
    assert!(arch.get_branches(&i).is_empty());
}

#[test]
fn branches_short_bytes_returns_empty() {
    use rustre_core::arch::Instruction;
    let mut i = Instruction::new(Address::new(0), 2, "nop".to_string(), vec![0, 0]);
    i.flags = InstrFlags::NONE;
    assert!(Arm64Arch::new().get_branches(&i).is_empty());
}

// ───────────────────────── register table ───────────────────────────────

#[test]
fn registers_unique_ids() {
    let regs = Arm64Arch::new().registers();
    let mut ids: Vec<u32> = regs.iter().map(|r| r.id).collect();
    ids.sort_unstable();
    let n = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), n);
}

#[test]
fn registers_contain_core_set() {
    let regs = Arm64Arch::new().registers();
    let names: std::collections::HashSet<_> = regs.iter().map(|r| r.name.as_str()).collect();
    for must in &["x0", "x30", "sp", "pc", "xzr", "wzr", "wsp", "v0", "v31", "nzcv"] {
        assert!(names.contains(*must), "missing {must}");
    }
}

#[test]
fn registers_sp_is_8_bytes() {
    let regs = Arm64Arch::new().registers();
    let sp = regs.iter().find(|r| r.name == "sp").unwrap();
    assert_eq!(sp.size, 8);
}

// ───────────────────────── calling conventions ──────────────────────────

#[test]
fn cc_has_aapcs64_and_apple() {
    let ccs = Arm64Arch::new().calling_conventions();
    assert!(ccs.iter().any(|c| c.name == "aapcs64"));
    assert!(ccs.iter().any(|c| c.name == "apple_arm64"));
}

#[test]
fn cc_aapcs64_args_x0_to_x7() {
    let ccs = Arm64Arch::new().calling_conventions();
    let a = ccs.iter().find(|c| c.name == "aapcs64").unwrap();
    assert_eq!(a.int_args, vec!["x0","x1","x2","x3","x4","x5","x6","x7"]);
    assert_eq!(a.return_regs, vec!["x0","x1"]);
}

// ──────────────────── Arm64LinearDisassembler ──────────────────────────

#[test]
fn ld_offset_starts_zero() {
    let ld = Arm64LinearDisassembler::new(&[], Address::new(0x100));
    assert_eq!(ld.offset(), 0);
    assert!(ld.is_done());
}

#[test]
fn ld_addresses_increment_by_4() {
    let code: Vec<u8> = std::iter::repeat_n([0x1fu8, 0x20, 0x03, 0xd5], 5)
        .flatten()
        .collect();
    let base = 0x4000u64;
    for (i, r) in Arm64LinearDisassembler::new(&code, Address::new(base)).enumerate() {
        let ins = r.unwrap();
        assert_eq!(ins.address.as_u64(), base + 4 * (i as u64));
    }
}

#[test]
fn ld_current_address_uses_base_plus_offset() {
    let ld = Arm64LinearDisassembler::new(&[0; 16], Address::new(0x2000));
    assert_eq!(ld.current_address().as_u64(), 0x2000);
}

#[test]
fn ld_truncated_tail_yields_err_then_none() {
    // 4 valid NOP bytes + 2 truncated bytes
    let mut code = vec![0x1f, 0x20, 0x03, 0xd5];
    code.extend_from_slice(&[0x00, 0x00]);
    let mut iter = Arm64LinearDisassembler::new(&code, Address::new(0));
    assert!(iter.next().unwrap().is_ok()); // NOP
    assert!(iter.next().unwrap().is_err()); // truncated -> err
    assert!(iter.next().is_none()); // done
}

#[test]
fn ld_invalid_word_yields_err_but_iterator_continues() {
    // 0xFFFF_FFFF is unallocated in AArch64 → decode error.
    // After advancing by 4, next 4 bytes (NOP) should still decode.
    let code = [0xff, 0xff, 0xff, 0xff, 0x1f, 0x20, 0x03, 0xd5];
    let mut iter = Arm64LinearDisassembler::new(&code, Address::new(0));
    let first = iter.next().expect("first item present");
    assert!(first.is_err(), "0xFFFFFFFF must be a decode error");
    let second = iter.next().expect("second item present");
    assert!(second.is_ok(), "iterator must continue past errors");
}

// ───────────────────── Arm64InstrCategory ──────────────────────────────

#[test]
fn cat_branch_variants() {
    use Arm64InstrCategory::Branch;
    for m in ["b", "bl", "br", "blr", "ret", "eret", "cbz", "cbnz", "tbz", "tbnz", "b.eq", "b.al"] {
        assert_eq!(Arm64InstrCategory::classify(m), Branch, "{m}");
    }
}

#[test]
fn cat_barrier_variants() {
    use Arm64InstrCategory::Barrier;
    for m in ["dmb", "dsb", "isb", "sb"] {
        assert_eq!(Arm64InstrCategory::classify(m), Barrier, "{m}");
    }
}

#[test]
fn cat_atomic_variants() {
    use Arm64InstrCategory::AtomicMemory;
    for m in ["ldxr", "stxr", "ldaxr", "stlxr", "cas", "swp", "ldadd"] {
        assert_eq!(Arm64InstrCategory::classify(m), AtomicMemory, "{m}");
    }
}

#[test]
fn cat_case_insensitive() {
    assert_eq!(
        Arm64InstrCategory::classify("ADD"),
        Arm64InstrCategory::DataProcessing
    );
    assert_eq!(
        Arm64InstrCategory::classify("RET"),
        Arm64InstrCategory::Branch
    );
}

#[test]
fn cat_unknown_is_misc() {
    assert_eq!(
        Arm64InstrCategory::classify("notarealmnemonic_zzz"),
        Arm64InstrCategory::Miscellaneous
    );
}

#[test]
fn cat_hash_and_eq_consistency() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(Arm64InstrCategory::Branch);
    set.insert(Arm64InstrCategory::Branch);
    assert_eq!(set.len(), 1);
}

// ───────────────────────── Arm64SysReg ──────────────────────────────────

#[test]
fn sysreg_lookup_known() {
    let r = arm64_sysreg_lookup("NZCV").unwrap();
    assert_eq!(r.name, "NZCV");
    assert_eq!(r.op0, 3);
}

#[test]
fn sysreg_lookup_case_insensitive() {
    assert!(arm64_sysreg_lookup("nzcv").is_some());
    assert!(arm64_sysreg_lookup("Sctlr_El1").is_some());
}

#[test]
fn sysreg_lookup_missing() {
    assert!(arm64_sysreg_lookup("does_not_exist").is_none());
}

#[test]
fn sysreg_encoded_nzcv() {
    // NZCV: op0=3, op1=3, CRn=4, CRm=2, op2=0
    let r = arm64_sysreg_lookup("NZCV").unwrap();
    let e = r.encoded();
    // op0(3) << 14 | op1(3) << 11 | CRn(4) << 7 | CRm(2) << 3 | op2(0)
    let expected = (3u16 << 14) | (3u16 << 11) | (4u16 << 7) | (2u16 << 3);
    assert_eq!(e, expected);
}

#[test]
fn sysreg_table_size_at_least_20() {
    assert!(ARM64_SYS_REGS.len() >= 20);
}

// ───────────────────────────── NZCV ─────────────────────────────────────

#[test]
fn nzcv_individual_bits() {
    // N=1: 0b1000 -> 0x8 -> 0x8 << 28 = 0x8000_0000
    assert!(Nzcv::from_u32(0x8000_0000).n());
    assert!(Nzcv::from_u32(0x4000_0000).z());
    assert!(Nzcv::from_u32(0x2000_0000).c());
    assert!(Nzcv::from_u32(0x1000_0000).v());
}

#[test]
fn nzcv_all_zero() {
    let n = Nzcv::from_u32(0);
    assert!(!n.n() && !n.z() && !n.c() && !n.v());
    assert_eq!(n.to_u32(), 0);
}

#[test]
fn nzcv_roundtrip_all_set() {
    let n = Nzcv::from_u32(0xf000_0000);
    assert!(n.n() && n.z() && n.c() && n.v());
    assert_eq!(n.to_u32(), 0xf000_0000);
}

#[test]
fn nzcv_ignores_low_bits() {
    // Only bits[31:28] should affect the flags.
    let n = Nzcv::from_u32(0x0fff_ffff);
    assert!(!n.n() && !n.z() && !n.c() && !n.v());
}

// ───────────────────────────── A64Cond ──────────────────────────────────

#[test]
fn cond_from_bits_round_trip_table() {
    let pairs = [
        (0, A64Cond::Eq),
        (1, A64Cond::Ne),
        (2, A64Cond::Cs),
        (3, A64Cond::Cc),
        (4, A64Cond::Mi),
        (5, A64Cond::Pl),
        (6, A64Cond::Vs),
        (7, A64Cond::Vc),
        (8, A64Cond::Hi),
        (9, A64Cond::Ls),
        (10, A64Cond::Ge),
        (11, A64Cond::Lt),
        (12, A64Cond::Gt),
        (13, A64Cond::Le),
        (14, A64Cond::Al),
        (15, A64Cond::Nv),
    ];
    for (b, c) in pairs {
        assert_eq!(A64Cond::from_bits(b), c);
    }
}

#[test]
fn cond_from_bits_masks_upper() {
    // high bits ignored
    assert_eq!(A64Cond::from_bits(0xf0), A64Cond::Eq);
    assert_eq!(A64Cond::from_bits(0xff), A64Cond::Nv);
}

#[test]
fn cond_al_and_nv_always_true() {
    // Architecture: AL and NV are both "always" in the encoding.
    let z = Nzcv::from_u32(0);
    assert!(A64Cond::Al.evaluate(z));
    assert!(A64Cond::Nv.evaluate(z));
}

#[test]
fn cond_eq_ne_complementary() {
    for raw in (0u32..=0xf).map(|n| n << 28) {
        let nzcv = Nzcv::from_u32(raw);
        assert_ne!(A64Cond::Eq.evaluate(nzcv), A64Cond::Ne.evaluate(nzcv));
    }
}

#[test]
fn cond_cs_cc_complementary() {
    for raw in (0u32..=0xf).map(|n| n << 28) {
        let nzcv = Nzcv::from_u32(raw);
        assert_ne!(A64Cond::Cs.evaluate(nzcv), A64Cond::Cc.evaluate(nzcv));
    }
}

#[test]
fn cond_ge_lt_complementary() {
    for raw in (0u32..=0xf).map(|n| n << 28) {
        let nzcv = Nzcv::from_u32(raw);
        assert_ne!(A64Cond::Ge.evaluate(nzcv), A64Cond::Lt.evaluate(nzcv));
    }
}

#[test]
fn cond_suffix_lowercase_two_chars() {
    for b in 0u8..16 {
        let s = A64Cond::from_bits(b).suffix();
        assert_eq!(s.len(), 2);
        assert!(s.chars().all(|c| c.is_ascii_lowercase()));
    }
}

// ───────────────────────── AAPCS64 roles ────────────────────────────────

#[test]
fn aapcs64_role_full_table() {
    assert_eq!(aapcs64_role(0), Aapcs64Role::Parameter);
    assert_eq!(aapcs64_role(7), Aapcs64Role::Parameter);
    assert_eq!(aapcs64_role(8), Aapcs64Role::IndirectResult);
    assert_eq!(aapcs64_role(9), Aapcs64Role::Temporary);
    assert_eq!(aapcs64_role(15), Aapcs64Role::Temporary);
    assert_eq!(aapcs64_role(16), Aapcs64Role::IntraProcedureCall);
    assert_eq!(aapcs64_role(17), Aapcs64Role::IntraProcedureCall);
    assert_eq!(aapcs64_role(18), Aapcs64Role::Platform);
    assert_eq!(aapcs64_role(19), Aapcs64Role::CalleeSaved);
    assert_eq!(aapcs64_role(28), Aapcs64Role::CalleeSaved);
    assert_eq!(aapcs64_role(29), Aapcs64Role::FramePointer);
    assert_eq!(aapcs64_role(30), Aapcs64Role::LinkRegister);
    assert_eq!(aapcs64_role(31), Aapcs64Role::StackPointerOrZero);
}

#[test]
fn aapcs64_fp_role_boundaries() {
    assert_eq!(aapcs64_fp_role(0), Aapcs64FpRole::Argument);
    assert_eq!(aapcs64_fp_role(7), Aapcs64FpRole::Argument);
    assert_eq!(aapcs64_fp_role(8), Aapcs64FpRole::CalleeSaved);
    assert_eq!(aapcs64_fp_role(15), Aapcs64FpRole::CalleeSaved);
    assert_eq!(aapcs64_fp_role(16), Aapcs64FpRole::Temporary);
    assert_eq!(aapcs64_fp_role(31), Aapcs64FpRole::Temporary);
}

// ──────────────────────────── A64Group ──────────────────────────────────

#[test]
fn a64_group_b_is_branch_sys() {
    assert_eq!(a64_group(0x1400_0000), A64Group::BranchExcSys);
}

#[test]
fn a64_group_add_imm() {
    assert_eq!(a64_group(0x9100_0000), A64Group::DpImm);
}

#[test]
fn a64_group_ldr_is_loadstore() {
    assert_eq!(a64_group(0xf940_0000), A64Group::LoadsStores);
}

#[test]
fn a64_group_fadd_is_fp_simd() {
    // 0x1E202820 — FADD S0, S1, S0; bits[28:25] = 0b1111
    assert_eq!(a64_group(0x1E20_2820), A64Group::DpFpSimd);
}

#[test]
fn a64_group_unallocated_zero() {
    // word=0 → bits[28:25]=0b0000 → Unallocated
    assert_eq!(a64_group(0), A64Group::Unallocated);
}

// ─────────────────────────── LSE table ──────────────────────────────────

#[test]
fn lse_cas_no_ordering() {
    let o = lse_lookup("cas").unwrap();
    assert!(!o.acquire && !o.release);
}

#[test]
fn lse_casal_acquire_and_release() {
    let o = lse_lookup("casal").unwrap();
    assert!(o.acquire && o.release);
}

#[test]
fn lse_swpl_release_only() {
    let o = lse_lookup("swpl").unwrap();
    assert!(!o.acquire && o.release);
}

#[test]
fn lse_case_insensitive() {
    assert!(lse_lookup("CASAL").is_some());
}

#[test]
fn lse_unknown() {
    assert!(lse_lookup("xyzzy").is_none());
}

// ────────────────────────── PacKind helpers ─────────────────────────────

#[test]
fn pac_paciasp_is_sign_and_instr() {
    let p = PacKind::from_mnemonic("paciasp").unwrap();
    assert_eq!(p, PacKind::PacIA);
    assert!(p.is_sign());
    assert!(!p.is_authenticate());
    assert!(p.is_instruction_addr());
}

#[test]
fn pac_autib_is_auth() {
    let p = PacKind::from_mnemonic("autib").unwrap();
    assert!(p.is_authenticate());
    assert!(!p.is_sign());
    assert!(p.is_instruction_addr());
}

#[test]
fn pac_xpacd_is_data_addr() {
    let p = PacKind::from_mnemonic("xpacd").unwrap();
    assert!(!p.is_sign());
    assert!(!p.is_authenticate());
    assert!(!p.is_instruction_addr());
}

#[test]
fn pac_xpaclri_canonicalizes_to_xpaci() {
    assert_eq!(PacKind::from_mnemonic("xpaclri"), Some(PacKind::XPacI));
}

#[test]
fn pac_unknown_returns_none() {
    assert!(PacKind::from_mnemonic("add").is_none());
}

#[test]
fn pac_data_variants() {
    assert_eq!(PacKind::from_mnemonic("pacda"), Some(PacKind::PacDA));
    assert_eq!(PacKind::from_mnemonic("autda"), Some(PacKind::AutDA));
}

// ─────────────────────── SimdArrangement helpers ────────────────────────

#[test]
fn simd_8b() {
    let a = SimdArrangement::V8B;
    assert_eq!(a.lane_bits(), 8);
    assert_eq!(a.lane_count(), 8);
    assert_eq!(a.register_bits(), 64);
    assert_eq!(a.suffix(), "8b");
}

#[test]
fn simd_16b() {
    let a = SimdArrangement::V16B;
    assert_eq!(a.register_bits(), 128);
    assert_eq!(a.lane_count(), 16);
}

#[test]
fn simd_4h() {
    let a = SimdArrangement::V4H;
    assert_eq!(a.lane_bits(), 16);
    assert_eq!(a.lane_count(), 4);
    assert_eq!(a.register_bits(), 64);
}

#[test]
fn simd_2d() {
    let a = SimdArrangement::V2D;
    assert_eq!(a.lane_bits(), 64);
    assert_eq!(a.lane_count(), 2);
    assert_eq!(a.register_bits(), 128);
}

#[test]
fn simd_1q() {
    let a = SimdArrangement::V1Q;
    assert_eq!(a.lane_bits(), 128);
    assert_eq!(a.lane_count(), 1);
    assert_eq!(a.register_bits(), 128);
}

#[test]
fn simd_from_q_size_full_table() {
    let cases = [
        (false, 0, Some(SimdArrangement::V8B)),
        (true, 0, Some(SimdArrangement::V16B)),
        (false, 1, Some(SimdArrangement::V4H)),
        (true, 1, Some(SimdArrangement::V8H)),
        (false, 2, Some(SimdArrangement::V2S)),
        (true, 2, Some(SimdArrangement::V4S)),
        (false, 3, Some(SimdArrangement::V1D)),
        (true, 3, Some(SimdArrangement::V2D)),
    ];
    for (q, s, want) in cases {
        assert_eq!(SimdArrangement::from_q_size(q, s), want, "q={q} size={s}");
    }
}

// ───────────────────────── FPCR field extract ───────────────────────────

#[test]
fn fpcr_rmode_extracts_two_bits() {
    let f = FPCR_FIELDS.iter().find(|f| f.name == "RMode").unwrap();
    // Set bits 22..=23 → value 0b11
    let v = 0b11u64 << 22;
    assert_eq!(f.extract(v), 0b11);
}

#[test]
fn fpcr_fz_single_bit() {
    let f = FPCR_FIELDS.iter().find(|f| f.name == "FZ").unwrap();
    assert_eq!(f.extract(1u64 << 24), 1);
    assert_eq!(f.extract(0), 0);
}

#[test]
fn fpcr_table_nonempty() {
    assert!(!FPCR_FIELDS.is_empty());
}

// ────────────────────────── MTE helpers ─────────────────────────────────

#[test]
fn mte_ldg_is_load_not_store() {
    let m = MteInstr::from_mnemonic("ldg").unwrap();
    assert!(m.is_load());
    assert!(!m.is_store());
}

#[test]
fn mte_stg_is_store_not_load() {
    let m = MteInstr::from_mnemonic("stg").unwrap();
    assert!(m.is_store());
    assert!(!m.is_load());
}

#[test]
fn mte_irg_neither_load_nor_store() {
    let m = MteInstr::from_mnemonic("irg").unwrap();
    assert!(!m.is_load());
    assert!(!m.is_store());
}

#[test]
fn mte_unknown_none() {
    assert!(MteInstr::from_mnemonic("nop").is_none());
}

// ──────────────────────── SVE register names ────────────────────────────

#[test]
fn z_reg_masks_to_5_bits() {
    assert_eq!(z_reg(0), "z0");
    assert_eq!(z_reg(31), "z31");
    // 32 wraps to 0 because lower 5 bits used
    assert_eq!(z_reg(32), "z0");
    assert_eq!(z_reg(0xff), "z31");
}

#[test]
fn p_reg_masks_to_4_bits() {
    assert_eq!(p_reg(0), "p0");
    assert_eq!(p_reg(15), "p15");
    assert_eq!(p_reg(16), "p0");
}

#[test]
fn ffr_reg_const() {
    assert_eq!(ffr_reg(), "ffr");
}

#[test]
fn sve_pred_qual_suffixes() {
    assert_eq!(SvePredQual::Merging.suffix(), "/m");
    assert_eq!(SvePredQual::Zeroing.suffix(), "/z");
}

// ───────────────────────── ExceptionLevel ───────────────────────────────

#[test]
fn el_from_bits_table() {
    assert_eq!(ExceptionLevel::from_bits(0), ExceptionLevel::El0);
    assert_eq!(ExceptionLevel::from_bits(1), ExceptionLevel::El1);
    assert_eq!(ExceptionLevel::from_bits(2), ExceptionLevel::El2);
    assert_eq!(ExceptionLevel::from_bits(3), ExceptionLevel::El3);
    // mask
    assert_eq!(ExceptionLevel::from_bits(0xfe), ExceptionLevel::El2);
}

#[test]
fn el_as_str() {
    assert_eq!(ExceptionLevel::El0.as_str(), "EL0");
    assert_eq!(ExceptionLevel::El3.as_str(), "EL3");
}

#[test]
fn el_privileged() {
    assert!(!ExceptionLevel::El0.is_privileged());
    assert!(ExceptionLevel::El1.is_privileged());
    assert!(ExceptionLevel::El2.is_privileged());
    assert!(ExceptionLevel::El3.is_privileged());
}

#[test]
fn el_ordering() {
    assert!(ExceptionLevel::El0 < ExceptionLevel::El1);
    assert!(ExceptionLevel::El3 > ExceptionLevel::El2);
}

// ───────────────────── Branch offset decoders ───────────────────────────

#[test]
fn b_offset_zero() {
    assert_eq!(a64_b_offset(0x1400_0000), 0);
}

#[test]
fn b_offset_positive_one_instr() {
    // imm26=1 → offset = 4
    assert_eq!(a64_b_offset(0x1400_0001), 4);
}

#[test]
fn b_offset_max_positive() {
    // imm26 = 0x01ff_ffff → positive max → (0x01ff_ffff << 2) = 0x7ff_fffc
    assert_eq!(a64_b_offset(0x1400_0000 | 0x01ff_ffff), 0x07ff_fffc);
}

#[test]
fn b_offset_negative_one() {
    // imm26 = 0x03ff_ffff (sign bit set) → -1 → << 2 = -4
    assert_eq!(a64_b_offset(0x17ff_ffff), -4);
}

#[test]
fn b_offset_min_negative() {
    // imm26 = 0x0200_0000 → sign-extended to 0xffff_ffff_fe00_0000 → -33554432
    // shifted left 2 → -0x800_0000 = -134217728
    assert_eq!(a64_b_offset(0x1400_0000 | 0x0200_0000), -0x800_0000);
}

#[test]
fn b_target_wraps_correctly() {
    // pc = 0, B #-4 → 0xffff_ffff_ffff_fffc
    assert_eq!(a64_b_target(0, 0x17ff_ffff), 0xffff_ffff_ffff_fffc);
}

#[test]
fn b19_offset_zero_and_positive() {
    assert_eq!(a64_b19_offset(0), 0);
    // imm19=1 at bits[23:5] → set bit 5
    assert_eq!(a64_b19_offset(1 << 5), 4);
}

#[test]
fn b19_offset_negative() {
    // imm19 sign bit = bit 18 of the field, i.e. bit (5+18)=23 of the word
    let word = 1u32 << 23 | (0x3_ffff << 5);
    // imm19 = 0x7_ffff → sign-extended to -1 → -4
    assert_eq!(a64_b19_offset(word), -4);
}

#[test]
fn b14_offset_zero_and_positive() {
    assert_eq!(a64_b14_offset(0), 0);
    assert_eq!(a64_b14_offset(1 << 5), 4);
}

#[test]
fn b14_offset_negative() {
    // imm14 sign bit = bit 13 of field = bit 18 of word
    let word = (1u32 << 18) | (0x1fff << 5);
    // imm14 = 0x3fff → -1 → -4
    assert_eq!(a64_b14_offset(word), -4);
}

// ─────────────────── ADD/SUB immediate decoder ──────────────────────────

#[test]
fn add_imm_no_shift() {
    // imm12 = 4 at bits[21:10]; bit22 = 0
    let word = 4u32 << 10;
    let (imm, shift) = a64_add_imm(word);
    assert_eq!(imm, 4);
    assert_eq!(shift, 0);
}

#[test]
fn add_imm_shift_12() {
    let word = (1u32 << 22) | (1u32 << 10);
    let (imm, shift) = a64_add_imm(word);
    assert_eq!(imm, 1);
    assert_eq!(shift, 12);
}

#[test]
fn add_imm_value_shift_applied() {
    let word = (1u32 << 22) | (1u32 << 10);
    assert_eq!(a64_add_imm_value(word), 1u64 << 12);
}

#[test]
fn add_imm_max() {
    let word = 0xfffu32 << 10;
    let (imm, shift) = a64_add_imm(word);
    assert_eq!(imm, 0xfff);
    assert_eq!(shift, 0);
}

// ─────────────── load/store unsigned offset decoder ─────────────────────

#[test]
fn ls_uoff_basic() {
    // imm12=1 at bits[21:10], size=8 → 8
    let word = 1u32 << 10;
    assert_eq!(a64_ls_uoff(word, 8), 8);
}

#[test]
fn ls_uoff_size_1() {
    let word = 5u32 << 10;
    assert_eq!(a64_ls_uoff(word, 1), 5);
}

#[test]
fn ls_uoff_max() {
    let word = 0xfffu32 << 10;
    assert_eq!(a64_ls_uoff(word, 4), 0xfff * 4);
}

// ─────────────────────── MOV immediate decoder ──────────────────────────

#[test]
fn mov_imm_hw0() {
    // imm16=5 at bits[20:5], hw=0
    let word = 5u32 << 5;
    let (imm, shift) = a64_mov_imm(word);
    assert_eq!(imm, 5);
    assert_eq!(shift, 0);
}

#[test]
fn mov_imm_hw_max() {
    let word = (3u32 << 21) | (1u32 << 5);
    let (imm, shift) = a64_mov_imm(word);
    assert_eq!(imm, 1);
    assert_eq!(shift, 48);
}

#[test]
fn movz_value_high_word() {
    // hw=3, imm16=1 → 1 << 48
    let word = (3u32 << 21) | (1u32 << 5);
    assert_eq!(a64_movz_value(word), 1u64 << 48);
}

#[test]
fn movz_value_max_imm16() {
    let word = (0xffffu32) << 5;
    assert_eq!(a64_movz_value(word), 0xffff);
}

// ──────────────────────── Send/Sync invariants ──────────────────────────

#[test]
fn arch_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Arm64Arch>();
}
