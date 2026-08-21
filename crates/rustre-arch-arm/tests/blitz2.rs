//! blitz2: deep adversarial tests for rustre-arch-arm.
//!
//! Focus: pure-function helpers, decoders, branch helpers, IT decode,
//! saturation, reglist formatting, exclusive decode, exception vectors,
//! Neon/VFP helpers, `parse_imm`, `strip_cond_suffix`, and the LLIL lifter.
//! Uses only a deterministic LCG (no rand, no `std::time`).

use rustre_arch_arm::*;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

// ---------- deterministic LCG ----------
struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    const fn next_u32(&mut self) -> u32 {
        self.next() as u32
    }
    const fn next_u16(&mut self) -> u16 {
        self.next() as u16
    }
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

// ============================================================
// 1. sreg/dreg/qreg — masking and stability
// ============================================================

#[test]
fn sreg_masking_all_32_unique() {
    let names: HashSet<&str> = (0..32).map(sreg).collect();
    assert_eq!(names.len(), 32);
}

#[test]
fn dreg_masking_all_32_unique() {
    let names: HashSet<&str> = (0..32).map(dreg).collect();
    assert_eq!(names.len(), 32);
}

#[test]
fn qreg_masking_all_16_unique() {
    let names: HashSet<&str> = (0..16).map(qreg).collect();
    assert_eq!(names.len(), 16);
}

#[test]
fn sreg_format_correct() {
    for i in 0..32 {
        assert_eq!(sreg(i), format!("s{i}"));
    }
}

#[test]
fn dreg_format_correct() {
    for i in 0..32 {
        assert_eq!(dreg(i), format!("d{i}"));
    }
}

#[test]
fn qreg_format_correct() {
    for i in 0..16 {
        assert_eq!(qreg(i), format!("q{i}"));
    }
}

// ============================================================
// 2. arm_branch_offset / target — round-trip-ish
// ============================================================

#[test]
fn arm_branch_offset_zero() {
    assert_eq!(arm_branch_offset(0xea00_0000), 0);
}

#[test]
fn arm_branch_offset_signs() {
    // Highest bit of imm24 set => negative
    let neg = arm_branch_offset(0xea80_0000);
    assert!(neg < 0);
    let pos = arm_branch_offset(0xea00_0001);
    assert_eq!(pos, 4);
}

#[test]
fn arm_branch_target_pc_relative() {
    // pc=0x1000, offset=0, branch target = pc+8
    assert_eq!(arm_branch_target(0x1000, 0xea00_0000), 0x1008);
    assert_eq!(arm_branch_target(0x1000, 0xea00_0001), 0x100c);
}

#[test]
fn arm_branch_offset_fuzz_never_panics() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let w = lcg.next_u32();
        let off = arm_branch_offset(w);
        // Offset is always 4-byte aligned
        assert_eq!(off & 0x3, 0);
        let _ = arm_branch_target(lcg.next_u32(), w);
    }
}

// ============================================================
// 3. thumb branch offsets — boundary
// ============================================================

#[test]
fn thumb16_cond_branch_offset_zero() {
    assert_eq!(thumb16_cond_branch_offset(0xd000), 0);
}

#[test]
fn thumb16_cond_branch_offset_sign() {
    // imm8 = 0x80 => sign-extended negative * 2 = -256
    assert_eq!(thumb16_cond_branch_offset(0xd080), -256);
    // imm8 = 0x7f => +0xfe
    assert_eq!(thumb16_cond_branch_offset(0xd07f), 0xfe);
}

#[test]
fn thumb16_uncond_branch_offset_max_positive() {
    // imm11=0x3ff
    assert_eq!(thumb16_uncond_branch_offset(0xe3ff), 0x7fe);
}

#[test]
fn thumb16_uncond_branch_offset_negative() {
    // imm11=0x400 (sign bit)
    let v = thumb16_uncond_branch_offset(0xe400);
    assert!(v < 0);
}

#[test]
fn thumb32_bl_offset_zero() {
    assert_eq!(thumb32_bl_offset(0xf000, 0xf800), 0);
}

#[test]
fn thumb32_bl_offset_alignment() {
    let mut lcg = Lcg::new(1);
    for _ in 0..100 {
        let hw1 = lcg.next_u16();
        let hw2 = lcg.next_u16();
        let off = thumb32_bl_offset(hw1, hw2);
        // BL offsets are 2-byte aligned
        assert_eq!(off & 0x1, 0);
    }
}

#[test]
fn thumb32_cond_branch_offset_alignment() {
    let mut lcg = Lcg::new(2);
    for _ in 0..100 {
        let hw1 = lcg.next_u16();
        let hw2 = lcg.next_u16();
        let off = thumb32_cond_branch_offset(hw1, hw2);
        assert_eq!(off & 0x1, 0);
    }
}

// ============================================================
// 4. arm_ssat / arm_usat — saturation correctness
// ============================================================

#[test]
fn arm_ssat_basic() {
    assert_eq!(arm_ssat(0, 8), 0);
    assert_eq!(arm_ssat(127, 8), 127);
    assert_eq!(arm_ssat(128, 8), 127);
    assert_eq!(arm_ssat(-128, 8), -128);
    assert_eq!(arm_ssat(-129, 8), -128);
}

#[test]
fn arm_ssat_32bit_passthrough() {
    assert_eq!(arm_ssat(i64::from(i32::MAX), 32), i32::MAX);
    assert_eq!(arm_ssat(i64::from(i32::MIN), 32), i32::MIN);
}

#[test]
fn arm_usat_basic() {
    assert_eq!(arm_usat(0, 8), 0);
    assert_eq!(arm_usat(255, 8), 255);
    assert_eq!(arm_usat(256, 8), 255);
    assert_eq!(arm_usat(-1, 8), 0);
}

#[test]
fn arm_usat_fuzz_in_range() {
    let mut lcg = Lcg::new(3);
    for _ in 0..200 {
        let val = lcg.next() as i64;
        for n in [1u8, 4, 8, 16, 24, 32] {
            let r = arm_usat(val, n);
            let max = if n == 32 { u32::MAX } else { (1u32 << n) - 1 };
            assert!(r <= max);
        }
    }
}

#[test]
fn arm_ssat_fuzz_in_range() {
    let mut lcg = Lcg::new(4);
    for _ in 0..200 {
        let val = (lcg.next() as i64).wrapping_sub(i64::MAX / 2);
        for n in [1u8, 4, 8, 16, 24, 32] {
            let r = arm_ssat(val, n);
            let max: i64 = (1i64 << (n - 1)) - 1;
            let min: i64 = -(1i64 << (n - 1));
            assert!(i64::from(r) >= min && i64::from(r) <= max);
        }
    }
}

// ============================================================
// 5. format_reglist
// ============================================================

#[test]
fn format_reglist_empty() {
    assert_eq!(format_reglist(0), "{}");
}

#[test]
fn format_reglist_r0_only() {
    assert_eq!(format_reglist(1), "{r0}");
}

#[test]
fn format_reglist_special() {
    assert_eq!(format_reglist(0xe000), "{sp,lr,pc}");
}

#[test]
fn format_reglist_all_16() {
    let s = format_reglist(0xffff);
    // 16 names + 15 commas + braces => no leading comma
    assert!(s.starts_with("{r0,r1,"));
    assert!(s.ends_with("pc}"));
    assert_eq!(s.matches(',').count(), 15);
}

#[test]
fn format_reglist_fuzz_no_leading_comma() {
    let mut lcg = Lcg::new(5);
    for _ in 0..100 {
        let mask = lcg.next_u16();
        let s = format_reglist(mask);
        assert!(s.starts_with('{') && s.ends_with('}'));
        assert!(!s.starts_with("{,"));
    }
}

// ============================================================
// 6. ArmMode / ArmArch
// ============================================================

#[test]
fn arm_mode_hash_consistency() {
    assert_eq!(hash_of(&ArmMode::Arm), hash_of(&ArmMode::Arm));
    assert_eq!(hash_of(&ArmMode::Thumb), hash_of(&ArmMode::Thumb));
    assert_ne!(ArmMode::Arm, ArmMode::Thumb);
}

#[test]
fn arm_arch_default_is_arm_le() {
    let a = ArmArch::default();
    assert_eq!(a.mode, ArmMode::Arm);
    assert!(a.little_endian);
}

#[test]
fn arm_arch_is_thumb() {
    assert!(!ArmArch::new_arm().is_thumb());
    assert!(ArmArch::new_thumb().is_thumb());
}

// ============================================================
// 7. arm_reg_id round-trip
// ============================================================

#[test]
fn arm_reg_id_round_trip_named() {
    for (name, id) in [
        ("r0", 0u32), ("r1", 1), ("r2", 2), ("r3", 3), ("r4", 4),
        ("r5", 5), ("r6", 6), ("r7", 7), ("r8", 8), ("r9", 9),
        ("r10", 10), ("r11", 11), ("r12", 12), ("sp", 13), ("lr", 14), ("pc", 15),
    ] {
        assert_eq!(arm_reg_id(name), Some(id));
    }
}

#[test]
fn arm_reg_id_unknown() {
    assert_eq!(arm_reg_id(""), None);
    assert_eq!(arm_reg_id("xx"), None);
    assert_eq!(arm_reg_id("R0"), None); // case sensitive
    assert_eq!(arm_reg_id("r16"), None);
}

#[test]
fn arm_const_register_ids() {
    assert_eq!(ARM_SP, 13);
    assert_eq!(ARM_LR, 14);
    assert_eq!(ARM_PC, 15);
}

// ============================================================
// 8. parse_imm
// ============================================================

#[test]
fn parse_imm_decimal() {
    assert_eq!(parse_imm("#42"), Some(42));
    assert_eq!(parse_imm("42"), Some(42));
    assert_eq!(parse_imm("0"), Some(0));
}

#[test]
fn parse_imm_hex() {
    assert_eq!(parse_imm("#0x1f"), Some(0x1f));
    assert_eq!(parse_imm("0xff"), Some(0xff));
    assert_eq!(parse_imm("#0X10"), Some(0x10));
}

#[test]
fn parse_imm_bogus() {
    assert_eq!(parse_imm("garbage"), None);
    assert_eq!(parse_imm("#"), None);
    assert_eq!(parse_imm("#0xZZ"), None);
}

#[test]
fn parse_imm_max() {
    assert_eq!(parse_imm("0xffffffffffffffff"), Some(u64::MAX));
}

// ============================================================
// 9. strip_cond_suffix
// ============================================================

#[test]
fn strip_cond_suffix_known() {
    assert_eq!(strip_cond_suffix("addeq"), "add");
    assert_eq!(strip_cond_suffix("subne"), "sub");
    assert_eq!(strip_cond_suffix("bge"), "b");
}

#[test]
fn strip_cond_suffix_no_strip_short() {
    // Mnemonic equal to suffix length must not be stripped to empty.
    assert_eq!(strip_cond_suffix("eq"), "eq");
    assert_eq!(strip_cond_suffix("ne"), "ne");
}

#[test]
fn strip_cond_suffix_no_suffix() {
    assert_eq!(strip_cond_suffix("mov"), "mov");
    assert_eq!(strip_cond_suffix("foo"), "foo");
}

// ============================================================
// 10. ArmFeatures
// ============================================================

#[test]
fn arm_features_has_and_union() {
    let f = ArmFeatures::THUMB.union(ArmFeatures::NEON);
    assert!(f.has(ArmFeatures::THUMB));
    assert!(f.has(ArmFeatures::NEON));
    assert!(!f.has(ArmFeatures::DIVIDE));
}

#[test]
fn arm_features_cortex_profiles() {
    let m4 = ArmFeatures::cortex_m4();
    assert!(m4.has(ArmFeatures::THUMB2));
    assert!(m4.has(ArmFeatures::CORTEX_M));
    let a9 = ArmFeatures::cortex_a9();
    assert!(a9.has(ArmFeatures::NEON));
    assert!(!a9.has(ArmFeatures::CORTEX_M));
}

#[test]
fn arm_features_empty() {
    let f = ArmFeatures::empty();
    for feat in [
        ArmFeatures::THUMB,
        ArmFeatures::NEON,
        ArmFeatures::VFP3,
        ArmFeatures::DIVIDE,
        ArmFeatures::CORTEX_M,
    ] {
        assert!(!f.has(feat));
    }
}

// ============================================================
// 11. CPSR helpers
// ============================================================

#[test]
fn cpsr_flag_helpers() {
    assert!(cpsr_q_flag(1 << 27));
    assert!(!cpsr_q_flag(0));
    assert!(cpsr_thumb_bit(1 << 5));
    assert!(!cpsr_thumb_bit(0));
    assert!(cpsr_irq_masked(1 << 7));
    assert!(!cpsr_irq_masked(0));
}

#[test]
fn cpsr_mode_name_known() {
    assert_eq!(cpsr_mode_name(0b10000), "usr");
}

// ============================================================
// 12. ArmRegBank from CPSR mode
// ============================================================

#[test]
fn arm_reg_bank_from_cpsr_known_modes() {
    assert_eq!(ArmRegBank::from_cpsr_mode(0b10001), ArmRegBank::Fiq);
    assert_eq!(ArmRegBank::from_cpsr_mode(0b10010), ArmRegBank::Irq);
    assert_eq!(ArmRegBank::from_cpsr_mode(0b10011), ArmRegBank::Svc);
    assert_eq!(ArmRegBank::from_cpsr_mode(0b10000), ArmRegBank::User);
}

#[test]
fn arm_reg_bank_banked_counts() {
    assert_eq!(ArmRegBank::Fiq.banked_gpr_count(), 7);
    assert_eq!(ArmRegBank::Irq.banked_gpr_count(), 2);
    assert_eq!(ArmRegBank::User.banked_gpr_count(), 0);
    assert!(!ArmRegBank::User.has_spsr());
    assert!(ArmRegBank::Svc.has_spsr());
}

#[test]
fn arm_reg_bank_fuzz_never_panics() {
    let mut lcg = Lcg::new(6);
    for _ in 0..256 {
        let mode = lcg.next() as u8;
        let b = ArmRegBank::from_cpsr_mode(mode);
        let _ = b.banked_gpr_count();
        let _ = b.has_spsr();
    }
}

// ============================================================
// 13. cortex_m_sysreg
// ============================================================

#[test]
fn cortex_m_sysreg_known() {
    assert_eq!(cortex_m_sysreg(0), "apsr");
    assert_eq!(cortex_m_sysreg(8), "msp");
    assert_eq!(cortex_m_sysreg(16), "primask");
    assert_eq!(cortex_m_sysreg(20), "control");
    assert_eq!(cortex_m_sysreg(200), "sysreg");
}

// ============================================================
// 14. Exception vectors
// ============================================================

#[test]
fn exception_vector_known_offsets() {
    for &off in &[0x00u32, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c] {
        assert!(exception_vector_at(off).is_some(), "missing 0x{off:x}");
    }
}

#[test]
fn exception_vector_fuzz_never_panics() {
    let mut lcg = Lcg::new(7);
    for _ in 0..200 {
        let _ = exception_vector_at(lcg.next_u32());
    }
}

// ============================================================
// 15. NeonElemSize
// ============================================================

#[test]
fn neon_elem_size_from_size_round_trip() {
    let cases = [
        (0u8, NeonElemSize::B8, 8u8, 8u8, 16u8, ".8"),
        (1, NeonElemSize::H16, 16, 4, 8, ".16"),
        (2, NeonElemSize::S32, 32, 2, 4, ".32"),
        (3, NeonElemSize::D64, 64, 1, 2, ".64"),
    ];
    for (bits_in, exp, bits, d, q, sfx) in cases {
        let e = NeonElemSize::from_size(bits_in);
        assert_eq!(e, exp);
        assert_eq!(e.bits(), bits);
        assert_eq!(e.lanes_in_d(), d);
        assert_eq!(e.lanes_in_q(), q);
        assert_eq!(e.type_suffix(), sfx);
    }
}

#[test]
fn neon_elem_size_masks_high_bits() {
    assert_eq!(NeonElemSize::from_size(0xfc), NeonElemSize::B8);
    assert_eq!(NeonElemSize::from_size(0xff), NeonElemSize::D64);
}

// ============================================================
// 16. VfpRoundMode
// ============================================================

#[test]
fn vfp_round_mode_all_decode() {
    assert_eq!(VfpRoundMode::from_bits(0), VfpRoundMode::RoundNearest);
    assert_eq!(VfpRoundMode::from_bits(1), VfpRoundMode::RoundTowardsPlusInfinity);
    assert_eq!(VfpRoundMode::from_bits(2), VfpRoundMode::RoundTowardsMinusInfinity);
    assert_eq!(VfpRoundMode::from_bits(3), VfpRoundMode::RoundTowardsZero);
    // mask high bits
    assert_eq!(VfpRoundMode::from_bits(0xff), VfpRoundMode::RoundTowardsZero);
}

// ============================================================
// 17. arm_ldr_pc_offset
// ============================================================

#[test]
fn arm_ldr_pc_offset_basic() {
    // U=1, imm12=4
    let (o, add) = arm_ldr_pc_offset(0xe59f_0004);
    assert_eq!(o, 4);
    assert!(add);
    // U=0, imm12=0xfff
    let (o, add) = arm_ldr_pc_offset(0xe51f_0fff);
    assert_eq!(o, 0xfff);
    assert!(!add);
}

// ============================================================
// 18. arm_branch_offset/target — invariants
// ============================================================

#[test]
fn arm_branch_target_addition_consistency() {
    let mut lcg = Lcg::new(8);
    for _ in 0..100 {
        let pc = lcg.next_u32() & !0x3;
        let w = lcg.next_u32();
        let off = arm_branch_offset(w);
        let t = arm_branch_target(pc, w);
        assert_eq!(t, pc.wrapping_add(8).wrapping_add(off as u32));
    }
}

// ============================================================
// 19. decode_arm_full / decode_thumb32_full — never panic
// ============================================================

#[test]
fn decode_arm_full_fuzz_never_panics() {
    let mut lcg = Lcg::new(9);
    for _ in 0..500 {
        let w = lcg.next_u32();
        let (mn, _ops, _f) = decode_arm_full(w);
        assert!(!mn.is_empty());
    }
}

#[test]
fn decode_thumb32_full_fuzz_never_panics() {
    let mut lcg = Lcg::new(10);
    for _ in 0..500 {
        let hw1 = lcg.next_u16();
        let hw2 = lcg.next_u16();
        let (mn, _ops, _f) = decode_thumb32_full(hw1, hw2);
        assert!(!mn.is_empty());
    }
}

#[test]
fn decode_cortex_m_thumb16_fuzz() {
    let mut lcg = Lcg::new(11);
    for _ in 0..200 {
        let _ = decode_cortex_m_thumb16(lcg.next_u16());
    }
}

#[test]
fn decode_cortex_m_thumb32_fuzz() {
    let mut lcg = Lcg::new(12);
    for _ in 0..200 {
        let _ = decode_cortex_m_thumb32(lcg.next_u16(), lcg.next_u16());
    }
}

#[test]
fn decode_arm_exclusive_fuzz() {
    let mut lcg = Lcg::new(13);
    for _ in 0..200 {
        let _ = decode_arm_exclusive(lcg.next_u32(), "");
    }
}

#[test]
fn decode_arm_system_fuzz() {
    let mut lcg = Lcg::new(14);
    for _ in 0..200 {
        let _ = decode_arm_system(lcg.next_u32());
    }
}

#[test]
fn decode_arm_coproc_fuzz() {
    let mut lcg = Lcg::new(15);
    for _ in 0..200 {
        let _ = decode_arm_coproc(lcg.next_u32(), "");
    }
}

#[test]
fn decode_neon_a32_fuzz() {
    let mut lcg = Lcg::new(16);
    for _ in 0..200 {
        let _ = decode_neon_a32(lcg.next_u32());
    }
}

// ============================================================
// 20. ArmOpcodeGroup / ThumbWidth / Thumb2Group classifiers
// ============================================================

#[test]
fn arm_opcode_group_fuzz_does_not_panic() {
    let mut lcg = Lcg::new(17);
    for _ in 0..200 {
        let _ = arm_opcode_group(lcg.next_u32());
    }
}

#[test]
fn thumb_width_classification() {
    // Standard Thumb-2 first half-words
    let mut lcg = Lcg::new(18);
    for _ in 0..200 {
        let _ = thumb_width(lcg.next_u16());
    }
}

#[test]
fn thumb2_group_does_not_panic() {
    let mut lcg = Lcg::new(19);
    for _ in 0..200 {
        let _ = thumb2_group(lcg.next_u16(), lcg.next_u16());
    }
}

// ============================================================
// 21. cp15_lookup
// ============================================================

#[test]
fn cp15_lookup_fuzz_never_panics() {
    let mut lcg = Lcg::new(20);
    for _ in 0..200 {
        let crn = (lcg.next() as u8) & 0xf;
        let op1 = (lcg.next() as u8) & 0x7;
        let crm = (lcg.next() as u8) & 0xf;
        let op2 = (lcg.next() as u8) & 0x7;
        let _ = cp15_lookup(crn, op1, crm, op2);
    }
}

// ============================================================
// 22. arm_cond_lookup
// ============================================================

#[test]
fn arm_cond_lookup_all_16() {
    
    assert_eq!((0u8..16).map(arm_cond_lookup).count(), 16);
}

#[test]
fn arm_cond_lookup_masks() {
    // High bits ignored
    let a = arm_cond_lookup(0);
    let b = arm_cond_lookup(0x10);
    assert_eq!(a.code, b.code);
}

// ============================================================
// 23. AAPCS role
// ============================================================

#[test]
fn aapcs_role_known() {
    // r0-r3: args
    let _ = aapcs_role(0);
    let _ = aapcs_role(13);
    let _ = aapcs_role(14);
    let _ = aapcs_role(15);
    // Higher values fall to default
    let _ = aapcs_role(255);
}

// ============================================================
// 24. decode_it_conditions
// ============================================================

#[test]
fn decode_it_conditions_empty_mask() {
    assert!(decode_it_conditions(0b1000, 0).is_empty());
}

#[test]
fn decode_it_conditions_first_only() {
    // mask=0b1000 => only first slot. With firstcond=0, then_flag=0,
    // bit at slot 0 = (mask>>3)&1 = 1, so is_then = (1 == 0) = false → cond ^= 1 → "ne".
    let conds = decode_it_conditions(0b0000, 0b1000);
    assert_eq!(conds.len(), 1);
    assert_eq!(conds[0], "ne");
}

#[test]
fn decode_it_conditions_fuzz_never_panics() {
    let mut lcg = Lcg::new(21);
    for _ in 0..200 {
        let fc = (lcg.next() as u8) & 0xf;
        let m = (lcg.next() as u8) & 0xf;
        let v = decode_it_conditions(fc, m);
        assert!(v.len() <= 4);
    }
}

// ============================================================
// 25. arm_lift_instr — covered scenarios
// ============================================================

use rustre_core::arch::{InstrFlags, Instruction};
use rustre_core::address::Address;
use rustre_core::arch::LlilOp;

fn mk(mn: &str, ops: &str, flags: InstrFlags, addr: u64) -> Instruction {
    let mut i = Instruction::new(Address::from(addr), 4, mn, vec![]);
    i.operands = ops.into();
    i.flags = flags;
    i
}

#[test]
fn lift_nop_family() {
    for mn in ["nop", "yield", "wfe", "wfi", "sev"] {
        let ops = arm_lift_instr(&mk(mn, "", InstrFlags::NONE, 0));
        assert_eq!(ops, vec![LlilOp::Nop]);
    }
}

#[test]
fn lift_bx_lr_is_return() {
    let ops = arm_lift_instr(&mk("bx", "lr", InstrFlags::NONE, 0));
    assert_eq!(ops, vec![LlilOp::Return]);
}

#[test]
fn lift_svc_is_syscall() {
    assert_eq!(
        arm_lift_instr(&mk("svc", "", InstrFlags::NONE, 0)),
        vec![LlilOp::Syscall]
    );
    assert_eq!(
        arm_lift_instr(&mk("swi", "", InstrFlags::NONE, 0)),
        vec![LlilOp::Syscall]
    );
}

#[test]
fn lift_mov_reg_to_reg() {
    let ops = arm_lift_instr(&mk("mov", "r0, r1", InstrFlags::NONE, 0));
    assert_eq!(ops, vec![LlilOp::GetReg(1), LlilOp::SetReg(0)]);
}

#[test]
fn lift_mov_imm() {
    let ops = arm_lift_instr(&mk("mov", "r3, #42", InstrFlags::NONE, 0));
    assert_eq!(ops, vec![LlilOp::Const(42), LlilOp::SetReg(3)]);
}

#[test]
fn lift_add_with_rd() {
    let ops = arm_lift_instr(&mk("add", "r0, r1, r2", InstrFlags::NONE, 0));
    assert_eq!(ops, vec![LlilOp::Add, LlilOp::SetReg(0)]);
}

#[test]
fn lift_cmp_is_subtract_no_setreg() {
    let ops = arm_lift_instr(&mk("cmp", "r0, r1", InstrFlags::NONE, 0));
    assert_eq!(ops, vec![LlilOp::Sub]);
}

#[test]
fn lift_unconditional_branch() {
    let ops = arm_lift_instr(&mk(
        "b",
        "8",
        InstrFlags::BRANCH,
        0x1000,
    ));
    assert_eq!(ops, vec![LlilOp::Jump(0x1008)]);
}

#[test]
fn lift_call_bl() {
    let ops = arm_lift_instr(&mk(
        "bl",
        "16",
        InstrFlags::CALL,
        0x100,
    ));
    assert_eq!(ops, vec![LlilOp::Call(0x110)]);
}

#[test]
fn lift_ldr_emits_load_setreg() {
    let ops = arm_lift_instr(&mk("ldr", "r4, [r0]", InstrFlags::READ_MEM, 0));
    assert_eq!(ops, vec![LlilOp::Load, LlilOp::SetReg(4)]);
}

#[test]
fn lift_str_emits_store() {
    let ops = arm_lift_instr(&mk("str", "r4, [r0]", InstrFlags::WRITE_MEM, 0));
    assert_eq!(ops, vec![LlilOp::Store]);
}

#[test]
fn lift_unknown_is_empty() {
    let ops = arm_lift_instr(&mk("xyzzy", "", InstrFlags::NONE, 0));
    assert!(ops.is_empty());
}

#[test]
fn lift_with_condition_suffix() {
    // moveq r0, r1 => GetReg(1), SetReg(0)
    let ops = arm_lift_instr(&mk("moveq", "r0, r1", InstrFlags::NONE, 0));
    assert_eq!(ops, vec![LlilOp::GetReg(1), LlilOp::SetReg(0)]);
}

#[test]
fn lift_width_suffix_w() {
    let ops = arm_lift_instr(&mk("add.w", "r0, r1, r2", InstrFlags::NONE, 0));
    assert_eq!(ops, vec![LlilOp::Add, LlilOp::SetReg(0)]);
}

// ============================================================
// 26. Send + Sync sanity for ArmArch
// ============================================================

#[test]
fn arm_arch_threaded_stress() {
    use std::sync::Arc;
    use std::thread;
    let a = Arc::new(ArmArch::new_arm());
    let mut handles = vec![];
    for _ in 0..4 {
        let a = Arc::clone(&a);
        handles.push(thread::spawn(move || {
            let mut acc = 0u64;
            for i in 0..100u32 {
                if a.is_thumb() {
                    acc = acc.wrapping_add(u64::from(i));
                } else {
                    acc = acc.wrapping_add(u64::from(i) * 2);
                }
            }
            acc
        }));
    }
    for h in handles {
        let _ = h.join().unwrap();
    }
}

// ============================================================
// 27. Hash/Eq consistency on Hash-implementing types
// ============================================================

#[test]
fn hash_eq_arm_mode() {
    let pairs = [
        (ArmMode::Arm, ArmMode::Arm),
        (ArmMode::Thumb, ArmMode::Thumb),
    ];
    for (a, b) in pairs {
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
}

// ============================================================
// 28. shift_as_instruction — pure helper
// ============================================================

#[test]
fn shift_as_instruction_fuzz_never_panics() {
    let mut lcg = Lcg::new(22);
    for _ in 0..200 {
        let _ = shift_as_instruction(lcg.next_u32(), "", "");
    }
}

// ============================================================
// 29. a32_read_regs / a32_write_reg never panic
// ============================================================

#[test]
fn a32_read_regs_fuzz() {
    let mut lcg = Lcg::new(23);
    for _ in 0..200 {
        let _ = a32_read_regs(lcg.next_u32());
    }
}

#[test]
fn a32_write_reg_fuzz() {
    let mut lcg = Lcg::new(24);
    for _ in 0..200 {
        let _ = a32_write_reg(lcg.next_u32());
    }
}

// ============================================================
// 30. neon_size_suffix / su / type_suffix / byte
// ============================================================

#[test]
fn neon_size_suffix_all() {
    for s in 0..4u32 {
        let _ = neon_size_suffix(s);
    }
    for s in 0..4u32 {
        for u in 0..2u32 {
            let _ = neon_su_suffix(s, u);
        }
    }
    for s in 0..4u8 {
        let _ = neon_size_suffix_byte(s);
        let _ = neon_type_suffix(true, s);
        let _ = neon_type_suffix(false, s);
    }
}

// ============================================================
// 31. vfp_lookup — known + unknown
// ============================================================

#[test]
fn vfp_lookup_unknown_returns_none() {
    assert!(vfp_lookup("not-a-vfp-instr").is_none());
}

// ============================================================
// 32. Equality robustness across constructors
// ============================================================

#[test]
fn arm_arch_constructor_aliases_match() {
    let a = ArmArch::new_arm();
    let b = ArmArch::arm();
    assert_eq!(a.mode, b.mode);
    assert_eq!(a.little_endian, b.little_endian);
    let c = ArmArch::new_thumb();
    let d = ArmArch::thumb();
    assert_eq!(c.mode, d.mode);
    assert_eq!(c.little_endian, d.little_endian);
}
