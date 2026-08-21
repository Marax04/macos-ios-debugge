//! Adversarial deep tests for `rustre-arch-arm64` (blitz2).
//!
//! Round-trips, seeded fuzzing, boundary inputs, hash/eq consistency,
//! Send/Sync stress, and state-machine walks of the linear disassembler.

use rustre_arch_arm64::*;
use rustre_core::address::Address;
use rustre_core::arch::{Architecture, InstrFlags};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ---------------------------------------------------------------------------
// Deterministic LCG
// ---------------------------------------------------------------------------

struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }
    const fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    const fn next_u32(&mut self) -> u32 {
        // Exact: `>> 32` leaves only the high 32 bits, which fit a u32 by
        // construction, so this narrowing cannot lose information.
        (self.next_u64() >> 32) as u32
    }
}

fn arch() -> Arm64Arch {
    Arm64Arch::new()
}

fn word_bytes(w: u32) -> [u8; 4] {
    w.to_le_bytes()
}

// ---------------------------------------------------------------------------
// 1. b_offset / b_target round-trips
// ---------------------------------------------------------------------------

#[test]
fn b_offset_zero_word_is_zero() {
    assert_eq!(a64_b_offset(0x1400_0000), 0);
}

#[test]
fn b_offset_positive_one_word() {
    // imm26 = 1 -> byte offset 4
    assert_eq!(a64_b_offset(0x1400_0001), 4);
}

#[test]
fn b_offset_max_negative() {
    // imm26 = 0x0200_0000 (sign bit set, rest zero) -> -2^25 * 4 = -134217728
    let off = a64_b_offset(0x1600_0000);
    assert_eq!(off, -(1i64 << 27));
}

#[test]
fn b_offset_max_positive() {
    // imm26 = 0x01FF_FFFF -> +0x7FFFFFC
    let off = a64_b_offset(0x15FF_FFFF);
    assert_eq!(off, ((1i64 << 27) - 4));
}

#[test]
fn b_target_pc_plus_offset() {
    let pc: u64 = 0x1_0000;
    let word = 0x1400_0002; // +8
    assert_eq!(a64_b_target(pc, word), 0x1_0008);
}

#[test]
fn b_target_wraps_when_negative() {
    let pc: u64 = 0;
    let word = 0x17FF_FFFF; // imm26 = 0x3FFFFFF -> -4
    let t = a64_b_target(pc, word);
    assert_eq!(t, u64::MAX - 3);
}

#[test]
fn b_offset_seeded_lcg_no_panic() {
    let mut g = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let w = g.next_u32();
        let _ = a64_b_offset(w);
        let _ = a64_b_target(0x1000, w);
    }
}

// ---------------------------------------------------------------------------
// 2. b19 / b14 offsets — boundary
// ---------------------------------------------------------------------------

#[test]
fn b19_offset_zero() {
    assert_eq!(a64_b19_offset(0), 0);
}

#[test]
fn b19_offset_positive_one() {
    // imm19 in bits[23:5] = 1 -> +4
    let word = 1u32 << 5;
    assert_eq!(a64_b19_offset(word), 4);
}

#[test]
fn b19_offset_max_negative() {
    // imm19 = 0x40000 -> sign bit only -> -2^18 * 4 = -1048576
    let word = 0x4_0000u32 << 5;
    assert_eq!(a64_b19_offset(word), -(1i64 << 20));
}

#[test]
fn b14_offset_zero() {
    assert_eq!(a64_b14_offset(0), 0);
}

#[test]
fn b14_offset_positive_one() {
    let word = 1u32 << 5;
    assert_eq!(a64_b14_offset(word), 4);
}

#[test]
fn b14_offset_max_negative() {
    // imm14 = 0x2000 -> sign bit -> -2^13*4
    let word = 0x2000u32 << 5;
    assert_eq!(a64_b14_offset(word), -(1i64 << 15));
}

// ---------------------------------------------------------------------------
// 3. add_imm / movz round-trips
// ---------------------------------------------------------------------------

#[test]
fn add_imm_basic() {
    // ADD X0,X0,#0
    let (imm, shift) = a64_add_imm(0x9100_0000);
    assert_eq!(imm, 0);
    assert_eq!(shift, 0);
}

#[test]
fn add_imm_max_imm12() {
    let word = 0x9100_0000 | (0xFFFu32 << 10);
    let (imm, shift) = a64_add_imm(word);
    assert_eq!(imm, 0xFFF);
    assert_eq!(shift, 0);
}

#[test]
fn add_imm_value_shifted() {
    // shift bit 22 set, imm = 1 -> value = 4096
    let word = 0x9100_0000 | (1u32 << 22) | (1u32 << 10);
    assert_eq!(a64_add_imm_value(word), 4096);
}

#[test]
fn movz_value_zero() {
    let word = 0xD280_0000; // MOVZ X0, #0
    assert_eq!(a64_movz_value(word), 0);
}

#[test]
fn movz_value_max_imm16_no_shift() {
    let word = 0xD280_0000 | (0xFFFFu32 << 5);
    assert_eq!(a64_movz_value(word), 0xFFFF);
}

#[test]
fn movz_value_shift_48() {
    // hw = 3 -> shift 48
    let word = 0xD280_0000 | (3u32 << 21) | (1u32 << 5);
    assert_eq!(a64_movz_value(word), 1u64 << 48);
}

#[test]
fn movz_seeded_no_panic() {
    let mut g = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..100 {
        let w = g.next_u32();
        let _ = a64_movz_value(w);
        let _ = a64_add_imm_value(w);
    }
}

// ---------------------------------------------------------------------------
// 4. ls_uoff
// ---------------------------------------------------------------------------

#[test]
fn ls_uoff_scaled_size_8() {
    // imm12=1, size=8 -> 8
    let word = 1u32 << 10;
    assert_eq!(a64_ls_uoff(word, 8), 8);
}

#[test]
fn ls_uoff_zero_size_is_zero() {
    let word = 0xFFFu32 << 10;
    assert_eq!(a64_ls_uoff(word, 0), 0);
}

// ---------------------------------------------------------------------------
// 5. NZCV / A64Cond round-trips
// ---------------------------------------------------------------------------

#[test]
fn nzcv_roundtrip_all_16_values() {
    for v in 0u8..16 {
        let raw = u32::from(v) << 28;
        let n = Nzcv::from_u32(raw);
        assert_eq!(n.to_u32(), raw);
    }
}

#[test]
fn nzcv_individual_flag_bits() {
    let n = Nzcv(0b1010); // N=1, Z=0, C=1, V=0
    assert!(n.n());
    assert!(!n.z());
    assert!(n.c());
    assert!(!n.v());
}

#[test]
fn cond_ne_complement_of_eq() {
    for v in 0u8..16 {
        let raw = u32::from(v) << 28;
        let n = Nzcv::from_u32(raw);
        assert_ne!(A64Cond::Eq.evaluate(n), A64Cond::Ne.evaluate(n));
    }
}

#[test]
fn cond_ge_lt_complementary() {
    for v in 0u8..16 {
        let raw = u32::from(v) << 28;
        let n = Nzcv::from_u32(raw);
        assert_ne!(A64Cond::Ge.evaluate(n), A64Cond::Lt.evaluate(n));
    }
}

#[test]
fn cond_from_bits_roundtrip_via_suffix() {
    let suffixes = [
        "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al",
        "nv",
    ];
    for (i, s) in suffixes.iter().enumerate() {
        // 16 entries, so the index always fits in a u8; check, do not cast.
        let bits = u8::try_from(i).expect("condition index fits in u8");
        let c = A64Cond::from_bits(bits);
        assert_eq!(c.suffix(), *s);
    }
}

#[test]
fn cond_al_and_nv_always_true() {
    let n = Nzcv(0);
    assert!(A64Cond::Al.evaluate(n));
    assert!(A64Cond::Nv.evaluate(n));
}

// ---------------------------------------------------------------------------
// 6. AAPCS64 role full coverage
// ---------------------------------------------------------------------------

#[test]
fn aapcs64_role_all_32_registers() {
    for i in 0u8..32 {
        let r = aapcs64_role(i);
        match i {
            0..=7 => assert_eq!(r, Aapcs64Role::Parameter),
            8 => assert_eq!(r, Aapcs64Role::IndirectResult),
            9..=15 => assert_eq!(r, Aapcs64Role::Temporary),
            16..=17 => assert_eq!(r, Aapcs64Role::IntraProcedureCall),
            18 => assert_eq!(r, Aapcs64Role::Platform),
            19..=28 => assert_eq!(r, Aapcs64Role::CalleeSaved),
            29 => assert_eq!(r, Aapcs64Role::FramePointer),
            30 => assert_eq!(r, Aapcs64Role::LinkRegister),
            _ => assert_eq!(r, Aapcs64Role::StackPointerOrZero),
        }
    }
}

#[test]
fn aapcs64_fp_role_all_32() {
    for i in 0u8..32 {
        let r = aapcs64_fp_role(i);
        match i {
            0..=7 => assert_eq!(r, Aapcs64FpRole::Argument),
            8..=15 => assert_eq!(r, Aapcs64FpRole::CalleeSaved),
            _ => assert_eq!(r, Aapcs64FpRole::Temporary),
        }
    }
}

// ---------------------------------------------------------------------------
// 7. SysReg lookup / encoding
// ---------------------------------------------------------------------------

#[test]
fn sysreg_lookup_known() {
    for name in ["SCTLR_EL1", "NZCV", "TTBR0_EL1", "ELR_EL1", "FAR_EL1"] {
        assert!(arm64_sysreg_lookup(name).is_some(), "missing {name}");
    }
}

#[test]
fn sysreg_lookup_unknown() {
    assert!(arm64_sysreg_lookup("NONEXISTENT_REG").is_none());
    assert!(arm64_sysreg_lookup("").is_none());
}

#[test]
fn sysreg_encoded_unique_per_register() {
    let mut codes: Vec<u16> = ARM64_SYS_REGS.iter().map(|r| r.encoded()).collect();
    codes.sort_unstable();
    let original = codes.len();
    codes.dedup();
    assert_eq!(codes.len(), original, "SysReg encodings must be unique");
}

// ---------------------------------------------------------------------------
// 8. LSE table
// ---------------------------------------------------------------------------

#[test]
fn lse_known_ops() {
    for m in ["cas", "casa", "casl", "casal", "swp", "ldadd", "ldclr"] {
        assert!(lse_lookup(m).is_some(), "missing {m}");
    }
}

#[test]
fn lse_unknown_returns_none() {
    assert!(lse_lookup("not_an_atomic").is_none());
}

#[test]
fn lse_ordering_flags_consistent() {
    let casa = lse_lookup("casa").unwrap();
    assert!(casa.acquire && !casa.release);
    let cas_release = lse_lookup("casl").unwrap();
    assert!(!cas_release.acquire && cas_release.release);
}

// ---------------------------------------------------------------------------
// 9. A64Group classification — seeded LCG
// ---------------------------------------------------------------------------

#[test]
fn a64_group_seeded_no_panic() {
    let mut g = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..500 {
        let w = g.next_u32();
        let _ = a64_group(w);
    }
}

#[test]
fn a64_group_known_classifications() {
    assert_eq!(a64_group(0x1400_0000), A64Group::BranchExcSys);
    assert_eq!(a64_group(0x9400_0000), A64Group::BranchExcSys);
    assert_eq!(a64_group(0xD65F_03C0), A64Group::BranchExcSys);
    assert_eq!(a64_group(0xF940_0000), A64Group::LoadsStores);
    assert_eq!(a64_group(0x9100_0000), A64Group::DpImm);
}

// ---------------------------------------------------------------------------
// 10. PacKind classification
// ---------------------------------------------------------------------------

#[test]
fn pac_kind_recognized() {
    assert_eq!(PacKind::from_mnemonic("paciasp"), Some(PacKind::PacIA));
    assert_eq!(PacKind::from_mnemonic("autibsp"), Some(PacKind::AutIB));
    assert_eq!(PacKind::from_mnemonic("xpaclri"), Some(PacKind::XPacI));
}

#[test]
fn pac_kind_unknown() {
    assert_eq!(PacKind::from_mnemonic("foo"), None);
}

#[test]
fn pac_kind_predicates_consistent() {
    assert!(PacKind::PacIA.is_sign());
    assert!(!PacKind::PacIA.is_authenticate());
    assert!(PacKind::AutIA.is_authenticate());
    assert!(!PacKind::AutIA.is_sign());
    assert!(PacKind::PacIA.is_instruction_addr());
    assert!(!PacKind::PacDA.is_instruction_addr());
}

// ---------------------------------------------------------------------------
// 11. SimdArrangement
// ---------------------------------------------------------------------------

#[test]
fn simd_arrangement_register_bits_consistent() {
    for q in [false, true] {
        for size in 0u8..4 {
            if let Some(arr) = SimdArrangement::from_q_size(q, size) {
                let expected_bits = if q { 128 } else { 64 };
                assert_eq!(arr.register_bits(), expected_bits);
                assert_eq!(
                    u16::from(arr.lane_bits()) * u16::from(arr.lane_count()),
                    expected_bits
                );
            }
        }
    }
}

#[test]
fn simd_arrangement_suffixes_distinct() {
    let v = [
        SimdArrangement::V8B,
        SimdArrangement::V16B,
        SimdArrangement::V4H,
        SimdArrangement::V8H,
        SimdArrangement::V2S,
        SimdArrangement::V4S,
        SimdArrangement::V1D,
        SimdArrangement::V2D,
    ];
    let mut s: Vec<_> = v.iter().map(|a| a.suffix()).collect();
    s.sort_unstable();
    let total = s.len();
    s.dedup();
    assert_eq!(s.len(), total);
}

// ---------------------------------------------------------------------------
// 12. ExceptionLevel
// ---------------------------------------------------------------------------

#[test]
fn exception_level_from_bits_roundtrip() {
    for b in 0u8..4 {
        let el = ExceptionLevel::from_bits(b);
        let s = el.as_str();
        assert!(s.starts_with("EL"));
    }
}

#[test]
fn exception_level_privileged() {
    assert!(!ExceptionLevel::El0.is_privileged());
    assert!(ExceptionLevel::El1.is_privileged());
    assert!(ExceptionLevel::El2.is_privileged());
    assert!(ExceptionLevel::El3.is_privileged());
}

#[test]
fn exception_level_ord() {
    assert!(ExceptionLevel::El0 < ExceptionLevel::El1);
    assert!(ExceptionLevel::El3 > ExceptionLevel::El2);
}

// ---------------------------------------------------------------------------
// 13. Disassembler — seeded fuzzing must never panic
// ---------------------------------------------------------------------------

#[test]
fn disassemble_seeded_random_words_no_panic() {
    let a = arch();
    let mut g = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..300 {
        let w = g.next_u32();
        let bytes = word_bytes(w);
        let _ = a.disassemble(Address::new(0x1000), &bytes);
    }
}

#[test]
fn linear_disassembler_seeded_fuzz_consumes_buffer() {
    let mut g = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    let mut buf = Vec::with_capacity(400);
    for _ in 0..100 {
        let w = g.next_u32();
        buf.extend_from_slice(&w.to_le_bytes());
    }
    let mut count = 0usize;
    for r in Arm64LinearDisassembler::new(&buf, Address::new(0x4000)) {
        let _ = r; // valid Ok or Err — must not panic
        count += 1;
    }
    assert_eq!(count, 100);
}

#[test]
fn disassemble_truncated_returns_err() {
    let a = arch();
    for len in 0..4 {
        let b = vec![0u8; len];
        assert!(a.disassemble(Address::new(0), &b).is_err());
    }
}

#[test]
fn disassemble_oversized_uses_first_4_bytes() {
    let a = arch();
    let mut buf = vec![0x1f, 0x20, 0x03, 0xd5]; // NOP
    buf.extend_from_slice(&[0xff; 100]);
    let i = a.disassemble(Address::new(0), &buf).unwrap();
    assert_eq!(i.size, 4);
    assert!(i.mnemonic == "nop" || i.mnemonic == "hint");
}

// ---------------------------------------------------------------------------
// 14. Linear disassembler state machine
// ---------------------------------------------------------------------------

#[test]
fn linear_disassembler_empty_yields_none() {
    let mut ld = Arm64LinearDisassembler::new(&[], Address::new(0));
    assert!(ld.next().is_none());
    assert!(ld.is_done());
}

#[test]
fn linear_disassembler_partial_trailing_word_is_dropped() {
    // 6 bytes -> 1 instruction; trailing 2 bytes ignored (offset >= len after one step)
    let bytes = [0x1f, 0x20, 0x03, 0xd5, 0xAA, 0xBB];
    let mut ld = Arm64LinearDisassembler::new(&bytes, Address::new(0));
    assert!(ld.next().is_some());
    // Now offset = 4, remaining = 2; disassemble of remaining returns Err and advances by 4.
    let second = ld.next();
    assert!(second.is_some());
    assert!(second.unwrap().is_err());
    assert!(ld.next().is_none());
}

#[test]
fn linear_disassembler_current_address_advances() {
    let nop = [0x1f, 0x20, 0x03, 0xd5];
    let code: Vec<u8> = nop.iter().cycle().take(16).copied().collect();
    let mut ld = Arm64LinearDisassembler::new(&code, Address::new(0x8000));
    for i in 0u64..4 {
        assert_eq!(ld.current_address().as_u64(), 0x8000 + i * 4);
        ld.next().unwrap().unwrap();
    }
    assert!(ld.is_done());
}

// ---------------------------------------------------------------------------
// 15. Classification stability — Arm64InstrCategory Hash/Eq
// ---------------------------------------------------------------------------

fn h<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

#[test]
fn instr_category_hash_eq_consistency() {
    let pairs = [
        ("add", "addv"),    // both data-proc starts? not necessarily same
        ("ldr", "ldr"),     // same
        ("str", "str"),     // same
        ("b", "b"),
        ("bl", "bl"),
        ("ret", "ret"),
        ("dmb", "dmb"),
        ("isb", "isb"),
        ("svc", "svc"),
        ("msr", "msr"),
        ("nop", "nop"),
        ("ldxr", "ldxr"),
        ("stxr", "stxr"),
        ("cas", "cas"),
        ("fadd", "fadd"),
        ("b.eq", "b.eq"),
        ("cbz", "cbz"),
        ("cbnz", "cbnz"),
        ("tbz", "tbz"),
        ("tbnz", "tbnz"),
        ("br", "br"),
        ("blr", "blr"),
        ("ldp", "ldp"),
        ("stp", "stp"),
        ("mov", "mov"),
        ("sub", "sub"),
        ("eor", "eor"),
        ("and", "and"),
        ("orr", "orr"),
        ("eret", "eret"),
    ];
    for (a, b) in pairs {
        let ca = Arm64InstrCategory::classify(a);
        let cb = Arm64InstrCategory::classify(b);
        if ca == cb {
            assert_eq!(h(&ca), h(&cb), "{a} vs {b}");
        }
    }
}

#[test]
fn instr_category_case_insensitive() {
    assert_eq!(
        Arm64InstrCategory::classify("LDR"),
        Arm64InstrCategory::classify("ldr")
    );
    assert_eq!(
        Arm64InstrCategory::classify("RET"),
        Arm64InstrCategory::classify("ret")
    );
}

#[test]
fn instr_category_empty_is_misc() {
    assert_eq!(
        Arm64InstrCategory::classify(""),
        Arm64InstrCategory::Miscellaneous
    );
}

// ---------------------------------------------------------------------------
// 16. Arm64Arch Send + Sync stress
// ---------------------------------------------------------------------------

#[test]
fn arm64arch_threaded_stress() {
    use std::sync::Arc;
    use std::thread;
    let a = Arc::new(Arm64Arch::new());
    let mut handles = Vec::new();
    for t in 0u64..4 {
        let a = Arc::clone(&a);
        handles.push(thread::spawn(move || {
            let mut g = Lcg::new(0xDEAD_BEEF_CAFE_BABE ^ t);
            for _ in 0..100 {
                let w = g.next_u32();
                let _ = a.disassemble(Address::new(0x1000), &word_bytes(w));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ---------------------------------------------------------------------------
// 17. get_branches consistency
// ---------------------------------------------------------------------------

#[test]
fn get_branches_b_targets_50_offsets() {
    let a = arch();
    let pc: u64 = 0x1_0000;
    for i in 0u32..50 {
        // construct B with imm26 = i  (positive)
        let imm26 = i & 0x03FF_FFFF;
        let word: u32 = 0x1400_0000 | imm26;
        let bytes = word.to_le_bytes();
        let instr = a.disassemble(Address::new(pc), &bytes).unwrap();
        let br = a.get_branches(&instr);
        assert_eq!(br.len(), 1);
        let expected = pc.wrapping_add(((i as i64) * 4) as u64);
        assert_eq!(br[0].target.unwrap(), expected);
    }
}

#[test]
fn get_branches_ret_indirect_blr_returns_empty_or_ret() {
    let a = arch();
    // RET
    let ret_bytes = [0xC0, 0x03, 0x5F, 0xD6];
    let i = a.disassemble(Address::new(0), &ret_bytes).unwrap();
    let br = a.get_branches(&i);
    // Either a RET BranchInfo (target None) or no static target
    if !br.is_empty() {
        assert!(br[0].target.is_none() || matches!(br[0].kind, rustre_core::arch::BranchKind::Return));
    }
}

#[test]
fn get_branches_invalid_short_bytes_empty() {
    let a = arch();
    let instr = rustre_core::arch::Instruction::new(Address::new(0), 2, "x", vec![0, 0]);
    let br = a.get_branches(&instr);
    assert!(br.is_empty());
}

// ---------------------------------------------------------------------------
// 18. Registers
// ---------------------------------------------------------------------------

#[test]
fn registers_size_classes_consistent() {
    // Only check classic SIMD/GPR forms: <prefix><digits-only>.
    fn is_numbered(n: &str, prefix: char) -> bool {
        let mut chars = n.chars();
        if chars.next() != Some(prefix) {
            return false;
        }
        let rest: String = chars.collect();
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
    }
    let regs = arch().registers();
    for r in &regs {
        let n = r.name.as_str();
        if is_numbered(n, 'x') {
            assert_eq!(r.size, 8, "{n}");
        } else if is_numbered(n, 'w') {
            assert_eq!(r.size, 4, "{n}");
        } else if is_numbered(n, 'v') || is_numbered(n, 'q') {
            assert_eq!(r.size, 16, "{n}");
        } else if is_numbered(n, 'd') {
            assert_eq!(r.size, 8, "{n}");
        } else if is_numbered(n, 's') {
            assert_eq!(r.size, 4, "{n}");
        } else if is_numbered(n, 'h') {
            assert_eq!(r.size, 2, "{n}");
        } else if is_numbered(n, 'b') {
            assert_eq!(r.size, 1, "{n}");
        }
    }
}

#[test]
fn registers_no_duplicate_names() {
    let regs = arch().registers();
    let mut names: Vec<_> = regs.iter().map(|r| r.name.clone()).collect();
    names.sort();
    let total = names.len();
    names.dedup();
    assert_eq!(names.len(), total, "register names must be unique");
}

// ---------------------------------------------------------------------------
// 19. Calling conventions
// ---------------------------------------------------------------------------

#[test]
fn calling_conventions_apple_and_aapcs_disjoint_names() {
    let ccs = arch().calling_conventions();
    let mut names: Vec<_> = ccs.iter().map(|c| c.name.clone()).collect();
    names.sort();
    let n = names.len();
    names.dedup();
    assert_eq!(names.len(), n);
}

// ---------------------------------------------------------------------------
// 20. Flags consistency between disassemble and category
// ---------------------------------------------------------------------------

#[test]
fn flags_branch_implies_category_branch() {
    let a = arch();
    let samples: &[&[u8]] = &[
        &[0x01, 0x00, 0x00, 0x14], // B
        &[0x01, 0x00, 0x00, 0x94], // BL
        &[0x40, 0x00, 0x00, 0x54], // B.EQ
        &[0x40, 0x00, 0x00, 0xb4], // CBZ
        &[0x00, 0x00, 0x3f, 0xd6], // BLR
        &[0x00, 0x00, 0x1f, 0xd6], // BR
        &[0xc0, 0x03, 0x5f, 0xd6], // RET
    ];
    for b in samples {
        let i = a.disassemble(Address::new(0), b).unwrap();
        let cat = Arm64InstrCategory::classify(&i.mnemonic);
        assert_eq!(cat, Arm64InstrCategory::Branch, "mnemonic={}", i.mnemonic);
        assert!(
            i.flags.contains(InstrFlags::BRANCH)
                || i.flags.contains(InstrFlags::RET),
            "flags={:?}",
            i.flags
        );
    }
}

// ---------------------------------------------------------------------------
// 21. SimdArrangement decode invalid q/size returns None for q=true size=3 1Q
// ---------------------------------------------------------------------------

#[test]
fn simd_arrangement_from_q_size_total_coverage() {
    // The encoding covers all 8 q×size pairs; ensure each produces Some.
    for q in [false, true] {
        for size in 0u8..4 {
            assert!(SimdArrangement::from_q_size(q, size).is_some());
        }
    }
}

// ---------------------------------------------------------------------------
// 22. Architecture trait object equality
// ---------------------------------------------------------------------------

#[test]
fn arm64arch_copy_eq() {
    let a = Arm64Arch::new();
    let b = a;
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// 23. FPCR field extraction
// ---------------------------------------------------------------------------

#[test]
fn fpcr_fields_extract_one_bit_widths() {
    for f in FPCR_FIELDS {
        let width = f.msb - f.lsb + 1;
        if width == 1 {
            // Setting that bit only should yield 1.
            let val = 1u64 << f.lsb;
            assert_eq!(f.extract(val), 1, "{}", f.name);
            assert_eq!(f.extract(0), 0, "{}", f.name);
        }
    }
}

#[test]
fn fpcr_rmode_two_bits() {
    let rmode = FPCR_FIELDS.iter().find(|f| f.name == "RMode").unwrap();
    let v = (0b11u64) << rmode.lsb;
    assert_eq!(rmode.extract(v), 0b11);
}

// ---------------------------------------------------------------------------
// 24. MTE classifier
// ---------------------------------------------------------------------------

#[test]
fn mte_known_mnemonics() {
    assert_eq!(MteInstr::from_mnemonic("irg"), Some(MteInstr::Irg));
    assert_eq!(MteInstr::from_mnemonic("stg"), Some(MteInstr::Stg));
    assert_eq!(MteInstr::from_mnemonic("ldg"), Some(MteInstr::Ldg));
    assert_eq!(MteInstr::from_mnemonic("LDG"), Some(MteInstr::Ldg));
}

#[test]
fn mte_unknown_mnemonic() {
    assert_eq!(MteInstr::from_mnemonic("xxx"), None);
}

#[test]
fn mte_load_store_partition() {
    assert!(MteInstr::Ldg.is_load());
    assert!(!MteInstr::Ldg.is_store());
    assert!(MteInstr::Stg.is_store());
    assert!(!MteInstr::Stg.is_load());
}

// ---------------------------------------------------------------------------
// 25. SVE register name helpers
// ---------------------------------------------------------------------------

#[test]
fn z_reg_modulo_32() {
    assert_eq!(z_reg(0), "z0");
    assert_eq!(z_reg(31), "z31");
    assert_eq!(z_reg(32), "z0"); // wraps
    assert_eq!(z_reg(255), "z31");
}

#[test]
fn p_reg_modulo_16() {
    assert_eq!(p_reg(0), "p0");
    assert_eq!(p_reg(15), "p15");
    assert_eq!(p_reg(16), "p0");
}

#[test]
fn ffr_reg_const() {
    assert_eq!(ffr_reg(), "ffr");
}

#[test]
fn sve_pred_qual_suffix() {
    assert_eq!(SvePredQual::Merging.suffix(), "/m");
    assert_eq!(SvePredQual::Zeroing.suffix(), "/z");
}
