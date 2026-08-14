//! Blitz test suite for rustre-arch-arm.
//! Targets pure-function APIs to surface bugs.

use rustre_arch_arm::*;

// ---------------- ArmMode / ArmArch constructors ----------------

#[test]
fn arm_mode_eq_hash() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(ArmMode::Arm);
    s.insert(ArmMode::Thumb);
    s.insert(ArmMode::Arm);
    assert_eq!(s.len(), 2);
}

#[test]
fn arm_arch_constructors() {
    assert_eq!(ArmArch::new_arm().mode, ArmMode::Arm);
    assert!(ArmArch::new_arm().little_endian);
    assert_eq!(ArmArch::new_thumb().mode, ArmMode::Thumb);
    assert!(ArmArch::new_thumb().little_endian);
    assert_eq!(ArmArch::new_arm_be().mode, ArmMode::Arm);
    assert!(!ArmArch::new_arm_be().little_endian);
    assert_eq!(ArmArch::arm().mode, ArmMode::Arm);
    assert_eq!(ArmArch::thumb().mode, ArmMode::Thumb);
}

// ---------------- sreg / dreg / qreg ----------------

#[test]
fn sreg_basic() {
    assert_eq!(sreg(0), "s0");
    assert_eq!(sreg(31), "s31");
}

#[test]
fn dreg_basic() {
    assert_eq!(dreg(0), "d0");
    assert_eq!(dreg(31), "d31");
}

#[test]
fn qreg_basic() {
    assert_eq!(qreg(0), "q0");
    assert_eq!(qreg(15), "q15");
}

// ---------------- arm_branch_offset / target ----------------

#[test]
fn arm_branch_offset_zero() {
    assert_eq!(arm_branch_offset(0xeb00_0000), 0);
}

#[test]
fn arm_branch_offset_positive() {
    // raw 1 -> 4
    assert_eq!(arm_branch_offset(0xeb00_0001), 4);
}

#[test]
fn arm_branch_offset_negative_max() {
    // 0x800000 -> negative MSB set
    let raw = 0x0080_0000_u32;
    let expected = ((raw | 0xff00_0000) as i32) << 2;
    assert_eq!(arm_branch_offset(raw), expected);
}

#[test]
fn arm_branch_offset_minus_one() {
    // 24-bit -1 = 0xFFFFFF -> sign-ext = -1, shl 2 = -4
    assert_eq!(arm_branch_offset(0x00ff_ffff), -4);
}

#[test]
fn arm_branch_target_basic() {
    // BL +0 at pc=0x1000 -> 0x1008
    assert_eq!(arm_branch_target(0x1000, 0xeb00_0000), 0x1008);
}

#[test]
fn arm_branch_target_back() {
    // offset -4 at pc=0x1000 -> 0x1000 + 8 - 4 = 0x1004
    assert_eq!(arm_branch_target(0x1000, 0x00ff_ffff), 0x1004);
}

// ---------------- thumb branch helpers ----------------

#[test]
fn thumb16_cond_branch_offset_zero() {
    assert_eq!(thumb16_cond_branch_offset(0xd000), 0);
}

#[test]
fn thumb16_cond_branch_offset_positive() {
    // imm8=1 -> 2
    assert_eq!(thumb16_cond_branch_offset(0xd001), 2);
}

#[test]
fn thumb16_cond_branch_offset_negative() {
    // imm8=0xff = -1 -> -2
    assert_eq!(thumb16_cond_branch_offset(0xd0ff), -2);
}

#[test]
fn thumb16_cond_branch_offset_neg_max() {
    // imm8=0x80 -> -128, *2 = -256
    assert_eq!(thumb16_cond_branch_offset(0xd080), -256);
}

#[test]
fn thumb16_uncond_branch_offset_zero() {
    assert_eq!(thumb16_uncond_branch_offset(0xe000), 0);
}

#[test]
fn thumb16_uncond_branch_offset_neg() {
    // imm11 = 0x7ff -> -1 -> *2 = -2
    assert_eq!(thumb16_uncond_branch_offset(0xe7ff), -2);
}

#[test]
fn thumb32_bl_offset_known() {
    // hw1=0xF000, hw2=0xD000 -> S=0,J1=0,J2=0,imm10=0,imm11=0
    // i1 = !(0^0)&1 = 1, i2 = 1 -> raw = (1<<23) | (1<<22) = 0xC00000
    assert_eq!(thumb32_bl_offset(0xf000, 0xd000), 0x00c0_0000);
}

// ---------------- arm_ssat / arm_usat ----------------

#[test]
fn ssat_in_range() {
    assert_eq!(arm_ssat(0, 8), 0);
    assert_eq!(arm_ssat(127, 8), 127);
    assert_eq!(arm_ssat(-128, 8), -128);
}

#[test]
fn ssat_clamps_high() {
    assert_eq!(arm_ssat(1000, 8), 127);
}

#[test]
fn ssat_clamps_low() {
    assert_eq!(arm_ssat(-1000, 8), -128);
}

#[test]
fn ssat_32bit() {
    assert_eq!(arm_ssat(i64::MAX, 32), i32::MAX);
    assert_eq!(arm_ssat(i64::MIN, 32), i32::MIN);
}

#[test]
fn usat_basic() {
    assert_eq!(arm_usat(0, 8), 0);
    assert_eq!(arm_usat(255, 8), 255);
    assert_eq!(arm_usat(-1, 8), 0);
    assert_eq!(arm_usat(1000, 8), 255);
}

#[test]
fn usat_32bit() {
    assert_eq!(arm_usat(i64::MAX, 32), u32::MAX);
    assert_eq!(arm_usat(-1, 32), 0);
}

// ---------------- cpsr bits ----------------

#[test]
fn cpsr_q() {
    assert!(!cpsr_q_flag(0));
    assert!(cpsr_q_flag(1 << 27));
    assert!(!cpsr_q_flag(1 << 26));
}

#[test]
fn cpsr_thumb() {
    assert!(!cpsr_thumb_bit(0));
    assert!(cpsr_thumb_bit(1 << 5));
}

#[test]
fn cpsr_irq() {
    assert!(!cpsr_irq_masked(0));
    assert!(cpsr_irq_masked(1 << 7));
}

// ---------------- arm_ldr_pc_offset ----------------

#[test]
fn ldr_pc_offset_add() {
    let (off, add) = arm_ldr_pc_offset(0x008000ab);
    assert_eq!(off, 0xab);
    assert!(add);
}

#[test]
fn ldr_pc_offset_sub() {
    let (off, add) = arm_ldr_pc_offset(0x000000ab);
    assert_eq!(off, 0xab);
    assert!(!add);
}

// ---------------- aapcs_role ----------------

#[test]
fn aapcs_arg() {
    for r in 0..=3 {
        assert_eq!(aapcs_role(r), AapcsRole::Argument);
    }
}

#[test]
fn aapcs_callee_saved() {
    for r in 4..=11 {
        assert_eq!(aapcs_role(r), AapcsRole::CalleeSaved);
    }
}

#[test]
fn aapcs_special() {
    assert_eq!(aapcs_role(12), AapcsRole::Scratch);
    assert_eq!(aapcs_role(13), AapcsRole::StackPointer);
    assert_eq!(aapcs_role(14), AapcsRole::LinkRegister);
    assert_eq!(aapcs_role(15), AapcsRole::ProgramCounter);
}

#[test]
fn aapcs_masks_high_bits() {
    // 0x1f & 0xf = 0xf -> PC
    assert_eq!(aapcs_role(0x1f), AapcsRole::ProgramCounter);
    assert_eq!(aapcs_role(0xf0), AapcsRole::Argument);
}

// ---------------- arm_cond_lookup ----------------

#[test]
fn cond_lookup_basic() {
    assert_eq!(arm_cond_lookup(0).suffix, "eq");
    assert_eq!(arm_cond_lookup(14).suffix, "al");
    assert_eq!(arm_cond_lookup(15).suffix, "nv");
}

#[test]
fn cond_lookup_masks() {
    // 0x10 -> 0 -> eq
    assert_eq!(arm_cond_lookup(0x10).suffix, "eq");
}

// ---------------- cp15_lookup ----------------

#[test]
fn cp15_midr() {
    let r = cp15_lookup(0, 0, 0, 0).unwrap();
    assert_eq!(r.name, "MIDR");
}

#[test]
fn cp15_sctlr() {
    let r = cp15_lookup(1, 0, 0, 0).unwrap();
    assert_eq!(r.name, "SCTLR");
}

#[test]
fn cp15_missing() {
    assert!(cp15_lookup(99, 0, 0, 0).is_none());
}

// ---------------- exception_vector_at ----------------

#[test]
fn excvec_reset() {
    let v = exception_vector_at(0x00).unwrap();
    assert_eq!(v.name, "Reset");
}

#[test]
fn excvec_irq() {
    let v = exception_vector_at(0x18).unwrap();
    assert_eq!(v.name, "IRQ");
}

#[test]
fn excvec_missing() {
    assert!(exception_vector_at(0x100).is_none());
}

// ---------------- thumb_width ----------------

#[test]
fn thumb_width_narrow() {
    assert_eq!(thumb_width(0x0000), ThumbWidth::Narrow);
    assert_eq!(thumb_width(0xe7ff), ThumbWidth::Narrow);
}

#[test]
fn thumb_width_wide() {
    assert_eq!(thumb_width(0xe800), ThumbWidth::Wide);
    assert_eq!(thumb_width(0xf000), ThumbWidth::Wide);
    assert_eq!(thumb_width(0xffff), ThumbWidth::Wide);
}

// ---------------- arm_opcode_group ----------------

#[test]
fn opcode_group_branch() {
    // bits 27:25 = 101 -> branch
    let w: u32 = 0b101 << 25;
    assert_eq!(arm_opcode_group(w), ArmOpcodeGroup::Branch);
}

#[test]
fn opcode_group_swi() {
    // 111 with b24=1 -> SWI
    let w: u32 = (0b111 << 25) | (1 << 24);
    assert_eq!(arm_opcode_group(w), ArmOpcodeGroup::Swi);
}

// ---------------- ArmFeatures ----------------

#[test]
fn features_empty() {
    let f = ArmFeatures::empty();
    assert!(!f.has(ArmFeatures::NEON));
}

#[test]
fn features_union() {
    let f = ArmFeatures::empty().union(ArmFeatures::NEON);
    assert!(f.has(ArmFeatures::NEON));
    assert!(!f.has(ArmFeatures::VFP3));
}

#[test]
fn features_cortex_a9() {
    let f = ArmFeatures::cortex_a9();
    assert!(f.has(ArmFeatures::NEON));
    assert!(f.has(ArmFeatures::THUMB2));
    assert!(f.has(ArmFeatures::DIVIDE));
    assert!(!f.has(ArmFeatures::CORTEX_M));
}

#[test]
fn features_cortex_m4() {
    let f = ArmFeatures::cortex_m4();
    assert!(f.has(ArmFeatures::CORTEX_M));
    assert!(f.has(ArmFeatures::VFP2));
    assert!(!f.has(ArmFeatures::NEON));
}

#[test]
fn features_cortex_m0() {
    let f = ArmFeatures::cortex_m0();
    assert!(f.has(ArmFeatures::THUMB));
    assert!(f.has(ArmFeatures::CORTEX_M));
    assert!(!f.has(ArmFeatures::THUMB2));
}

// ---------------- format_reglist ----------------

#[test]
fn reglist_empty() {
    assert_eq!(format_reglist(0), "{}");
}

#[test]
fn reglist_single() {
    assert_eq!(format_reglist(1), "{r0}");
}

#[test]
fn reglist_lr_pc() {
    assert_eq!(format_reglist((1<<14) | (1<<15)), "{lr,pc}");
}

#[test]
fn reglist_all() {
    let s = format_reglist(0xffff);
    assert!(s.starts_with("{r0,r1,"));
    assert!(s.ends_with("sp,lr,pc}"));
}

// ---------------- arm_reg_id ----------------

#[test]
fn reg_id_basic() {
    assert_eq!(arm_reg_id("r0"), Some(0));
    assert_eq!(arm_reg_id("r12"), Some(12));
    assert_eq!(arm_reg_id("sp"), Some(13));
    assert_eq!(arm_reg_id("lr"), Some(14));
    assert_eq!(arm_reg_id("pc"), Some(15));
}

#[test]
fn reg_id_bad() {
    assert_eq!(arm_reg_id(""), None);
    assert_eq!(arm_reg_id("r16"), None);
    assert_eq!(arm_reg_id("R0"), None); // case-sensitive
}

#[test]
fn reg_id_constants() {
    assert_eq!(ARM_SP, 13);
    assert_eq!(ARM_LR, 14);
    assert_eq!(ARM_PC, 15);
}

// ---------------- strip_cond_suffix ----------------

#[test]
fn strip_cond_basic() {
    assert_eq!(strip_cond_suffix("moveq"), "mov");
    assert_eq!(strip_cond_suffix("addne"), "add");
    assert_eq!(strip_cond_suffix("ble"), "b");
}

#[test]
fn strip_cond_no_suffix() {
    assert_eq!(strip_cond_suffix("mov"), "mov");
    assert_eq!(strip_cond_suffix("add"), "add");
}

#[test]
fn strip_cond_short_skipped() {
    // mn.len() must exceed suffix.len(); "eq" alone stays "eq"
    assert_eq!(strip_cond_suffix("eq"), "eq");
}

// ---------------- parse_imm ----------------

#[test]
fn parse_imm_decimal() {
    assert_eq!(parse_imm("#42"), Some(42));
    assert_eq!(parse_imm("42"), Some(42));
}

#[test]
fn parse_imm_hex() {
    assert_eq!(parse_imm("#0x1f"), Some(0x1f));
    assert_eq!(parse_imm("0xff"), Some(0xff));
    assert_eq!(parse_imm("#0Xab"), Some(0xab));
}

#[test]
fn parse_imm_bad() {
    assert_eq!(parse_imm("#abc"), None);
    assert_eq!(parse_imm(""), None);
    assert_eq!(parse_imm("#"), None);
}

// ---------------- cpsr_mode_name ----------------

#[test]
fn cpsr_mode_user() {
    // 0b10000 = User (returns "usr" abbreviation)
    let s = cpsr_mode_name(0b10000);
    assert!(s == "usr" || s == "user", "got {s}");
}

// ---------------- ArmRegBank::from_cpsr_mode ----------------

#[test]
fn regbank_modes() {
    assert_eq!(ArmRegBank::from_cpsr_mode(0b10001), ArmRegBank::Fiq);
    assert_eq!(ArmRegBank::from_cpsr_mode(0b10010), ArmRegBank::Irq);
    assert_eq!(ArmRegBank::from_cpsr_mode(0b10000), ArmRegBank::User);
    assert_eq!(ArmRegBank::from_cpsr_mode(0b11010), ArmRegBank::Hyp);
}

#[test]
fn regbank_banked_count() {
    assert_eq!(ArmRegBank::Fiq.banked_gpr_count(), 7);
    assert_eq!(ArmRegBank::Irq.banked_gpr_count(), 2);
    assert_eq!(ArmRegBank::User.banked_gpr_count(), 0);
}

#[test]
fn regbank_spsr() {
    assert!(!ArmRegBank::User.has_spsr());
    assert!(ArmRegBank::Fiq.has_spsr());
    assert!(ArmRegBank::Hyp.has_spsr());
}

// ---------------- NeonElemSize ----------------

#[test]
fn neon_elem_size_from() {
    assert_eq!(NeonElemSize::from_size(0), NeonElemSize::B8);
    assert_eq!(NeonElemSize::from_size(1), NeonElemSize::H16);
    assert_eq!(NeonElemSize::from_size(2), NeonElemSize::S32);
    assert_eq!(NeonElemSize::from_size(3), NeonElemSize::D64);
    assert_eq!(NeonElemSize::from_size(7), NeonElemSize::D64); // mask
}

#[test]
fn neon_elem_bits() {
    assert_eq!(NeonElemSize::B8.bits(), 8);
    assert_eq!(NeonElemSize::D64.bits(), 64);
}

#[test]
fn neon_elem_lanes() {
    assert_eq!(NeonElemSize::B8.lanes_in_d(), 8);
    assert_eq!(NeonElemSize::B8.lanes_in_q(), 16);
    assert_eq!(NeonElemSize::D64.lanes_in_d(), 1);
    assert_eq!(NeonElemSize::D64.lanes_in_q(), 2);
}

#[test]
fn neon_elem_suffix() {
    assert_eq!(NeonElemSize::B8.type_suffix(), ".8");
    assert_eq!(NeonElemSize::H16.type_suffix(), ".16");
    assert_eq!(NeonElemSize::S32.type_suffix(), ".32");
    assert_eq!(NeonElemSize::D64.type_suffix(), ".64");
}

// ---------------- neon_size_suffix / su ----------------

#[test]
fn neon_size_suffix_works() {
    assert_eq!(neon_size_suffix(0), ".8");
    assert_eq!(neon_size_suffix(1), ".16");
    assert_eq!(neon_size_suffix(2), ".32");
    assert_eq!(neon_size_suffix(3), ".64");
}

// ---------------- ItState ----------------

#[test]
fn it_state_default_inactive() {
    let s = ItState::new();
    assert!(!s.active());
}

#[test]
fn it_state_begin_single() {
    let mut s = ItState::new();
    s.begin(0, 0b1000); // mask & 0x1 == 0, & 0x2 == 0, & 0x4 == 0 -> remaining=1
    assert_eq!(s.remaining, 1);
}

#[test]
fn it_state_begin_4_slots() {
    let mut s = ItState::new();
    s.begin(0, 0b0001);
    assert_eq!(s.remaining, 4);
}

#[test]
fn it_state_consume_returns_cond() {
    let mut s = ItState::new();
    s.begin(0, 0b1000); // firstcond=0 (eq), one slot
    let c = s.consume();
    assert_eq!(c, "eq");
    assert!(!s.active());
}

#[test]
fn it_state_consume_inactive() {
    let mut s = ItState::new();
    assert_eq!(s.consume(), "");
}

#[test]
fn it_mnemonic_basic() {
    assert_eq!(ItState::it_mnemonic(0b1000), "it");
}

// ---------------- decode_it_conditions ----------------

#[test]
fn decode_it_empty() {
    assert!(decode_it_conditions(0, 0).is_empty());
}

#[test]
fn decode_it_one_slot() {
    let v = decode_it_conditions(0, 0b1000);
    assert_eq!(v.len(), 1);
}

// ---------------- a32_read_regs / write_reg ----------------

#[test]
fn a32_write_reg_str_none() {
    // STR r0, [r1] = 0xe5810000 -> rn=1, opcode bits, store -> None
    assert_eq!(a32_write_reg(0xe581_0000), None);
}

#[test]
fn a32_write_reg_ldr_some() {
    // LDR r0, [r1] = 0xe5910000 -> Rt=0
    assert_eq!(a32_write_reg(0xe591_0000), Some(0));
}

// ---------------- thumb2_group ----------------

#[test]
fn thumb2_group_smoke() {
    // just verify the function returns a value (no panic) for varied input
    let _ = thumb2_group(0xe800, 0);
    let _ = thumb2_group(0xf000, 0x8000);
    let _ = thumb2_group(0xfa00, 0);
}

// ---------------- vfp_lookup ----------------

#[test]
fn vfp_lookup_some() {
    // Just check it doesn't panic; behavior - returns Option
    let _ = vfp_lookup("vadd");
    let r = vfp_lookup("nonexistent_mnemonic_xyz");
    assert!(r.is_none());
}

// ---------------- Send/Sync ----------------

#[test]
fn arch_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ArmArch>();
    assert_send_sync::<ArmMode>();
    assert_send_sync::<ArmFeatures>();
    assert_send_sync::<ItState>();
}

// ---------------- thumb32_bl_offset signedness ----------------

#[test]
fn thumb32_bl_offset_sign() {
    // S=1, J1=0, J2=0 -> i1=!(0^1)&1=0, i2=0 -> raw has S bit set, sign-extends negative
    let off = thumb32_bl_offset(0xf400, 0x9000);
    assert!(off < 0, "expected negative, got {off}");
}
