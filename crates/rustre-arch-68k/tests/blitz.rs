//! Blitz test suite for rustre-arch-68k. Exercises public API surface to surface bugs.

use rustre_core::arch::{Architecture, InstrFlags, Instruction};
use rustre_arch_68k::*;
use rustre_core::address::Address;

fn arch() -> Mc68kArch {
    Mc68kArch::default()
}

const fn a(v: u64) -> Address {
    Address::new(v)
}

// ── Mc68kVariant ──────────────────────────────────────────────────────────────

#[test]
fn variant_name_unique() {
    let vs = [
        Mc68kVariant::M68000,
        Mc68kVariant::M68010,
        Mc68kVariant::M68020,
        Mc68kVariant::M68030,
        Mc68kVariant::M68040,
        Mc68kVariant::M68060,
        Mc68kVariant::ColdFire,
    ];
    let names: Vec<&str> = vs.iter().map(|v| v.name()).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "variant names not unique");
}

#[test]
fn variant_has_fpu() {
    assert!(!Mc68kVariant::M68000.has_fpu());
    assert!(!Mc68kVariant::M68020.has_fpu());
    assert!(Mc68kVariant::M68040.has_fpu());
    assert!(Mc68kVariant::M68060.has_fpu());
}

#[test]
fn variant_is_32bit() {
    assert!(!Mc68kVariant::M68000.is_32bit());
    assert!(!Mc68kVariant::M68010.is_32bit());
    assert!(Mc68kVariant::M68020.is_32bit());
    assert!(Mc68kVariant::M68040.is_32bit());
}

#[test]
fn variant_has_mmu() {
    assert!(!Mc68kVariant::M68000.has_mmu());
    assert!(!Mc68kVariant::M68020.has_mmu());
    assert!(Mc68kVariant::M68030.has_mmu());
    assert!(Mc68kVariant::M68040.has_mmu());
}

#[test]
fn variant_has_bitfield_matches_is_32bit() {
    for v in [
        Mc68kVariant::M68000,
        Mc68kVariant::M68020,
        Mc68kVariant::M68040,
    ] {
        assert_eq!(v.has_bitfield(), v.is_32bit());
    }
}

#[test]
fn variant_address_space() {
    assert_eq!(Mc68kVariant::M68000.address_space_bytes(), 0x0100_0000);
    assert_eq!(Mc68kVariant::M68010.address_space_bytes(), 0x0100_0000);
    assert_eq!(Mc68kVariant::M68020.address_space_bytes(), 0x1_0000_0000);
}

// ── Size ──────────────────────────────────────────────────────────────────────

#[test]
fn size_suffix_bytes() {
    assert_eq!(Size::Byte.suffix(), ".B");
    assert_eq!(Size::Word.suffix(), ".W");
    assert_eq!(Size::Long.suffix(), ".L");
    assert_eq!(Size::Quad.suffix(), ".Q");
    assert_eq!(Size::Byte.bytes(), 1);
    assert_eq!(Size::Word.bytes(), 2);
    assert_eq!(Size::Long.bytes(), 4);
    assert_eq!(Size::Quad.bytes(), 8);
}

#[test]
fn size_from_bits2() {
    assert_eq!(Size::from_bits2(0), Size::Byte);
    assert_eq!(Size::from_bits2(1), Size::Word);
    assert_eq!(Size::from_bits2(2), Size::Long);
    assert_eq!(Size::from_bits2(3), Size::Long); // fallback to Long
    // upper bits masked off
    assert_eq!(Size::from_bits2(0xFC), Size::Byte);
    assert_eq!(Size::from_bits2(0xFD), Size::Word);
}

// ── CondCode ──────────────────────────────────────────────────────────────────

#[test]
fn condcode_roundtrip_bits() {
    let codes = [
        CondCode::T, CondCode::F, CondCode::Hi, CondCode::Ls,
        CondCode::Cc, CondCode::Cs, CondCode::Ne, CondCode::Eq,
        CondCode::Vc, CondCode::Vs, CondCode::Pl, CondCode::Mi,
        CondCode::Ge, CondCode::Lt, CondCode::Gt, CondCode::Le,
    ];
    for (i, &c) in codes.iter().enumerate() {
        assert_eq!(CondCode::from_bits(i as u8), c, "code {i}");
    }
}

#[test]
fn condcode_from_bits_masks_upper() {
    assert_eq!(CondCode::from_bits(0xF0), CondCode::T);
    assert_eq!(CondCode::from_bits(0xFF), CondCode::Le);
}

#[test]
fn condcode_mnemonics_unique() {
    let codes = [
        CondCode::T, CondCode::F, CondCode::Hi, CondCode::Ls,
        CondCode::Cc, CondCode::Cs, CondCode::Ne, CondCode::Eq,
        CondCode::Vc, CondCode::Vs, CondCode::Pl, CondCode::Mi,
        CondCode::Ge, CondCode::Lt, CondCode::Gt, CondCode::Le,
    ];
    let mut m: Vec<&str> = codes.iter().map(|c| c.mnemonic()).collect();
    m.sort_unstable();
    m.dedup();
    assert_eq!(m.len(), 16);
}

#[test]
fn condcode_is_unconditional() {
    assert!(CondCode::T.is_unconditional());
    assert!(!CondCode::F.is_unconditional());
    assert!(!CondCode::Eq.is_unconditional());
}

#[test]
fn invert_cond_involution() {
    let codes = [
        CondCode::T, CondCode::F, CondCode::Hi, CondCode::Ls,
        CondCode::Cc, CondCode::Cs, CondCode::Ne, CondCode::Eq,
        CondCode::Vc, CondCode::Vs, CondCode::Pl, CondCode::Mi,
        CondCode::Ge, CondCode::Lt, CondCode::Gt, CondCode::Le,
    ];
    for c in codes {
        assert_eq!(invert_cond(invert_cond(c)), c);
    }
    assert_eq!(invert_cond(CondCode::Eq), CondCode::Ne);
    assert_eq!(invert_cond(CondCode::T), CondCode::F);
}

// ── EaKind / parse_ea ─────────────────────────────────────────────────────────

#[test]
fn parse_ea_data_reg() {
    let (k, n) = parse_ea(0, 3, Size::Word, &[]).unwrap();
    assert_eq!(k, EaKind::DataReg(3));
    assert_eq!(n, 0);
}

#[test]
fn parse_ea_addr_reg_modes() {
    assert_eq!(parse_ea(1, 0, Size::Word, &[]).unwrap().0, EaKind::AddrReg(0));
    assert_eq!(parse_ea(2, 1, Size::Word, &[]).unwrap().0, EaKind::AddrInd(1));
    assert_eq!(parse_ea(3, 2, Size::Word, &[]).unwrap().0, EaKind::AddrIndPost(2));
    assert_eq!(parse_ea(4, 7, Size::Word, &[]).unwrap().0, EaKind::AddrIndPre(7));
}

#[test]
fn parse_ea_disp_truncated_errors() {
    assert!(parse_ea(5, 0, Size::Word, &[]).is_err());
    assert!(parse_ea(5, 0, Size::Word, &[0x12]).is_err());
}

#[test]
fn parse_ea_disp_ok() {
    let (k, n) = parse_ea(5, 1, Size::Word, &[0x00, 0x10]).unwrap();
    assert_eq!(k, EaKind::AddrIndDisp(1, 0x10));
    assert_eq!(n, 2);
}

#[test]
fn parse_ea_abs_short_long() {
    let (k, n) = parse_ea(7, 0, Size::Word, &[0x12, 0x34]).unwrap();
    assert_eq!(k, EaKind::AbsShort(0x1234));
    assert_eq!(n, 2);

    let (k, n) = parse_ea(7, 1, Size::Long, &[0x00, 0x10, 0x20, 0x30]).unwrap();
    assert_eq!(k, EaKind::AbsLong(0x0010_2030));
    assert_eq!(n, 4);
}

#[test]
fn parse_ea_abs_truncated() {
    assert!(parse_ea(7, 0, Size::Word, &[0x00]).is_err());
    assert!(parse_ea(7, 1, Size::Long, &[0x00, 0x00, 0x00]).is_err());
}

#[test]
fn parse_ea_pc_disp() {
    let (k, _) = parse_ea(7, 2, Size::Word, &[0xFF, 0xFE]).unwrap();
    assert_eq!(k, EaKind::PcDisp(-2));
}

#[test]
fn parse_ea_immediate_sizes() {
    let (k, n) = parse_ea(7, 4, Size::Byte, &[0x00, 0x42]).unwrap();
    assert_eq!(k, EaKind::Immediate(0x42));
    assert_eq!(n, 2);

    let (k, n) = parse_ea(7, 4, Size::Word, &[0x12, 0x34]).unwrap();
    assert_eq!(k, EaKind::Immediate(0x1234));
    assert_eq!(n, 2);

    let (k, n) = parse_ea(7, 4, Size::Long, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
    assert_eq!(k, EaKind::Immediate(0xDEAD_BEEF));
    assert_eq!(n, 4);
}

#[test]
fn parse_ea_invalid_mode_and_subreg() {
    assert!(parse_ea(8, 0, Size::Word, &[]).is_err());
    assert!(parse_ea(7, 5, Size::Word, &[]).is_err());
    assert!(parse_ea(7, 7, Size::Word, &[]).is_err());
}

#[test]
fn eakind_display() {
    assert_eq!(EaKind::DataReg(3).display(), "D3");
    assert_eq!(EaKind::AddrReg(7).display(), "A7");
    assert_eq!(EaKind::AddrInd(1).display(), "(A1)");
    assert_eq!(EaKind::AddrIndPost(0).display(), "(A0)+");
    assert_eq!(EaKind::AddrIndPre(2).display(), "-(A2)");
    assert_eq!(EaKind::AbsShort(0x1234).display(), "$1234.W");
    assert_eq!(EaKind::AbsLong(0xCAFE).display(), "$0000CAFE.L");
    assert_eq!(EaKind::Immediate(0x42).display(), "#$00000042");
}

#[test]
fn eakind_is_indirect() {
    assert!(!EaKind::DataReg(0).is_indirect());
    assert!(!EaKind::AddrReg(0).is_indirect());
    assert!(!EaKind::Immediate(0).is_indirect());
    assert!(!EaKind::AbsShort(0).is_indirect());
    assert!(!EaKind::AbsLong(0).is_indirect());
    assert!(EaKind::AddrInd(0).is_indirect());
    assert!(EaKind::AddrIndDisp(0, 0).is_indirect());
    assert!(EaKind::PcDisp(0).is_indirect());
    assert!(EaKind::PcIdx.is_indirect());
}

// ── Encoders ──────────────────────────────────────────────────────────────────

#[test]
fn encode_basic_words() {
    assert_eq!(encode_nop(), [0x4E, 0x71]);
    assert_eq!(encode_rts(), [0x4E, 0x75]);
    assert_eq!(encode_rte(), [0x4E, 0x73]);
}

#[test]
fn encode_moveq_roundtrip() {
    let bytes = encode_moveq(0, 42);
    let i = arch().disassemble(a(0), &bytes).unwrap();
    assert_eq!(i.mnemonic, "MOVEQ");

    let bytes = encode_moveq(7, -1);
    assert_eq!(bytes[0], 0x7E);
    assert_eq!(bytes[1], 0xFF);
}

#[test]
#[should_panic(expected = "MOVEQ")]
fn encode_moveq_invalid_dn_panics() {
    let _ = encode_moveq(8, 0);
}

#[test]
fn encode_bra16_zero_ok() {
    // BRA word form can have any displacement
    let bytes = encode_bra16(0);
    assert_eq!(bytes[0], 0x60);
    assert_eq!(bytes[1], 0x00);
}

#[test]
#[should_panic]
fn encode_bra8_zero_panics() {
    let _ = encode_bra8(0);
}

#[test]
fn encode_bsr8_basic() {
    let b = encode_bsr8(8);
    assert_eq!(b[0], 0x61);
    assert_eq!(b[1], 0x08);
}

#[test]
fn encode_trap_range() {
    for v in 0..16 {
        let b = encode_trap(v);
        let i = arch().disassemble(a(0), &b).unwrap();
        assert!(i.mnemonic.starts_with("TRAP"), "vector {v} got {}", i.mnemonic);
    }
}

#[test]
#[should_panic]
fn encode_trap_overflow_panics() {
    let _ = encode_trap(16);
}

#[test]
fn encode_clr_sizes() {
    let b = encode_clr(Size::Byte, 0);
    let i = arch().disassemble(a(0), &b).unwrap();
    assert_eq!(i.mnemonic, "CLR.B");
    let b = encode_clr(Size::Word, 3);
    let i = arch().disassemble(a(0), &b).unwrap();
    assert_eq!(i.mnemonic, "CLR.W");
    let b = encode_clr(Size::Long, 7);
    let i = arch().disassemble(a(0), &b).unwrap();
    assert_eq!(i.mnemonic, "CLR.L");
}

#[test]
fn encode_addi_word_form() {
    let b = encode_addi_word(0x1234, 2);
    assert_eq!(b.len(), 4);
    // header 0x0640 | dn
    let word = u16::from_be_bytes([b[0], b[1]]);
    assert_eq!(word, 0x0642);
}

#[test]
fn encode_subq_valid_range() {
    for d in 1u8..=8 {
        let b = encode_subq_word(d, 0);
        assert_eq!(b.len(), 2);
    }
}

#[test]
#[should_panic]
fn encode_subq_zero_panics() {
    let _ = encode_subq_word(0, 0);
}

#[test]
#[should_panic]
fn encode_subq_too_big_panics() {
    let _ = encode_subq_word(9, 0);
}

#[test]
fn encode_jmp_jsr_abs_long() {
    let jmp = encode_jmp_abs_long(0x0001_2345);
    assert_eq!(&jmp[..2], &[0x4E, 0xF9]);
    assert_eq!(&jmp[2..], &[0x00, 0x01, 0x23, 0x45]);
    let i = arch().disassemble(a(0), &jmp).unwrap();
    assert_eq!(i.mnemonic, "JMP");

    let jsr = encode_jsr_abs_long(0xCAFE_BABE);
    assert_eq!(&jsr[..2], &[0x4E, 0xB9]);
    let i = arch().disassemble(a(0), &jsr).unwrap();
    assert_eq!(i.mnemonic, "JSR");
}

#[test]
fn encode_movem_push_pop() {
    let p = encode_movem_push(0x00FF);
    assert_eq!(&p[..2], &[0x48, 0xE7]);
    let q = encode_movem_pop(0x00FF);
    assert_eq!(&q[..2], &[0x4C, 0xDF]);
}

#[test]
fn encode_link_unlk() {
    let b = encode_link(6, -16);
    assert_eq!(&b[..2], &[0x4E, 0x56]);
    let u = encode_unlk(6);
    assert_eq!(u, [0x4E, 0x5E]);
}

#[test]
#[should_panic]
fn encode_link_invalid_reg_panics() {
    let _ = encode_link(8, 0);
}

#[test]
fn encode_dbra_form() {
    let b = encode_dbra(0, -2);
    assert_eq!(&b[..2], &[0x51, 0xC8]);
}

// ── lookup_opcode ─────────────────────────────────────────────────────────────

#[test]
fn lookup_opcode_nop() {
    let e = lookup_opcode(0x4E71);
    assert!(e.is_some());
}

#[test]
fn lookup_opcode_rts() {
    assert!(lookup_opcode(0x4E75).is_some());
}

// ── decode_register_mask / encode_register_mask ──────────────────────────────

#[test]
fn register_mask_roundtrip_normal() {
    let regs = vec!["D0", "D3", "A0", "A7"];
    let mask = encode_register_mask(&regs, false);
    let s = decode_register_mask(mask, false);
    assert!(s.contains("D0"));
    assert!(s.contains("D3"));
    assert!(s.contains("A0"));
    assert!(s.contains("A7"));
}

#[test]
fn register_mask_sp_alias() {
    let m1 = encode_register_mask(&["A7"], false);
    let m2 = encode_register_mask(&["SP"], false);
    assert_eq!(m1, m2);
}

#[test]
fn register_mask_predecrement_reversed() {
    let m_normal = encode_register_mask(&["D0"], false);
    let m_pre = encode_register_mask(&["D0"], true);
    assert_eq!(m_normal.reverse_bits(), m_pre);
}

#[test]
fn register_mask_empty_zero() {
    assert_eq!(encode_register_mask(&[], false), 0);
    assert_eq!(decode_register_mask(0, false), "");
}

#[test]
fn register_mask_unknown_name_ignored() {
    let m = encode_register_mask(&["BOGUS", "D0"], false);
    assert_eq!(m, 1);
}

// ── moveq_value / addq_value ──────────────────────────────────────────────────

#[test]
fn moveq_value_sign_extend() {
    assert_eq!(moveq_value(0x7000), 0);
    assert_eq!(moveq_value(0x707F), 127);
    assert_eq!(moveq_value(0x70FF), -1);
    assert_eq!(moveq_value(0x7080), -128);
}

#[test]
fn addq_value_zero_means_eight() {
    assert_eq!(addq_value(0x0000), 8);
    assert_eq!(addq_value(0x0200), 1);
    assert_eq!(addq_value(0x0E00), 7);
}

// ── classify_ea_mode, is_data_alterable, is_control, is_movable_dst ──────────

#[test]
fn classify_ea_modes() {
    assert_eq!(classify_ea_mode(0, 0), AddressCategory::Register);
    assert_eq!(classify_ea_mode(1, 0), AddressCategory::AddressRegister);
    assert_eq!(classify_ea_mode(2, 0), AddressCategory::Memory);
    assert_eq!(classify_ea_mode(7, 2), AddressCategory::PcRelative);
    assert_eq!(classify_ea_mode(7, 3), AddressCategory::PcRelative);
    assert_eq!(classify_ea_mode(7, 4), AddressCategory::Immediate);
    assert_eq!(classify_ea_mode(7, 0), AddressCategory::Memory);
    assert_eq!(classify_ea_mode(7, 1), AddressCategory::Memory);
}

#[test]
fn is_data_alterable_ea_checks() {
    assert!(is_data_alterable_ea(0, 0));
    assert!(!is_data_alterable_ea(1, 0)); // An direct: not data alterable
    assert!(is_data_alterable_ea(2, 0));
    assert!(is_data_alterable_ea(7, 0));
    assert!(is_data_alterable_ea(7, 1));
    assert!(!is_data_alterable_ea(7, 2)); // PC-relative not alterable
    assert!(!is_data_alterable_ea(7, 4)); // Immediate not alterable
}

#[test]
fn is_control_ea_checks() {
    assert!(is_control_ea(2, 0));
    assert!(is_control_ea(5, 0));
    assert!(is_control_ea(6, 0));
    assert!(!is_control_ea(0, 0));
    assert!(!is_control_ea(1, 0));
    assert!(!is_control_ea(3, 0)); // post-inc
    assert!(!is_control_ea(4, 0)); // pre-dec
    assert!(is_control_ea(7, 0));
    assert!(is_control_ea(7, 1));
    assert!(is_control_ea(7, 2));
    assert!(is_control_ea(7, 3));
    assert!(!is_control_ea(7, 4));
}

#[test]
fn is_movable_dst_ea_checks() {
    for m in 0..=6 {
        assert!(is_movable_dst_ea(m, 0));
    }
    assert!(is_movable_dst_ea(7, 0));
    assert!(is_movable_dst_ea(7, 1));
    assert!(!is_movable_dst_ea(7, 2));
    assert!(!is_movable_dst_ea(7, 4)); // immediate not a dest
}

// ── branch_displacement ──────────────────────────────────────────────────────

#[test]
fn branch_displacement_forward() {
    // from 0x1000, target 0x1010: pc+2 = 0x1002, diff = 0x0E
    let d = branch_displacement(0x1000, 0x1010, false).unwrap();
    assert_eq!(d, 0x0E);
}

#[test]
fn branch_displacement_backward() {
    let d = branch_displacement(0x1000, 0x0FF0, false).unwrap();
    assert_eq!(d, -0x12);
}

#[test]
fn branch_displacement_out_of_word_range() {
    // > i16 range
    let d = branch_displacement(0x1000, 0x1000 + 100_000, false);
    assert_eq!(d, None);
}

#[test]
fn branch_displacement_long_form() {
    let d = branch_displacement(0x1000, 0x1000 + 100_000, true);
    assert!(d.is_some());
}

// ── count_movem_regs / movem_reg_names ───────────────────────────────────────

#[test]
fn count_movem_regs_basic() {
    assert_eq!(count_movem_regs(0), 0);
    assert_eq!(count_movem_regs(0xFFFF), 16);
    assert_eq!(count_movem_regs(0x00FF), 8);
}

#[test]
fn movem_reg_names_order() {
    let n = movem_reg_names(0b0000_0001_0000_0001);
    // bit 0 = D0, bit 8 = A0
    assert_eq!(n, vec!["D0".to_string(), "A0".to_string()]);
}

// ── decode_shift_count ───────────────────────────────────────────────────────

#[test]
fn decode_shift_count_immediate_8() {
    // count_field 0 -> 8
    let (c, ur) = decode_shift_count(0x0000);
    assert_eq!(c, 8);
    assert!(!ur);
}

#[test]
fn decode_shift_count_register_form() {
    let (_c, use_reg) = decode_shift_count(0x0020);
    assert!(use_reg);
}

#[test]
fn decode_shift_count_range() {
    for n in 1u16..=7 {
        let w = n << 9;
        let (c, _) = decode_shift_count(w);
        assert_eq!(u16::from(c), n);
    }
}

// ── trap_vector ──────────────────────────────────────────────────────────────

#[test]
fn trap_vector_decode() {
    assert_eq!(trap_vector(0x4E40), Some(0));
    assert_eq!(trap_vector(0x4E4F), Some(15));
    assert_eq!(trap_vector(0x4E50), None); // LINK
    assert_eq!(trap_vector(0x4E71), None); // NOP
}

// ── KnownTrap ────────────────────────────────────────────────────────────────

#[test]
fn known_trap_identify() {
    assert_eq!(KnownTrap::identify(0), KnownTrap::AmigaExec);
    assert_eq!(KnownTrap::identify(1), KnownTrap::Gemdos);
    assert_eq!(KnownTrap::identify(13), KnownTrap::AtariBios);
    assert_eq!(KnownTrap::identify(14), KnownTrap::AtariXbios);
    assert_eq!(KnownTrap::identify(15), KnownTrap::MacToolbox);
    assert_eq!(KnownTrap::identify(7), KnownTrap::Unknown(7));
}

// ── ExceptionVector ──────────────────────────────────────────────────────────

#[test]
fn exception_vector_offset() {
    assert_eq!(ExceptionVector::ResetSSP.table_offset(), 0);
    assert_eq!(ExceptionVector::ResetPC.table_offset(), 4);
    assert_eq!(ExceptionVector::BusError.table_offset(), 8);
    assert_eq!(ExceptionVector::Trap0.table_offset(), 32 * 4);
}

#[test]
fn exception_vector_names_nonempty() {
    assert!(!ExceptionVector::ResetSSP.name().is_empty());
    assert!(!ExceptionVector::IllegalInstruction.name().is_empty());
}

// ── BCD arithmetic ───────────────────────────────────────────────────────────

#[test]
fn abcd_simple() {
    let (r, c, _v) = abcd_byte(0x25, 0x37, false);
    assert_eq!(r, 0x62);
    assert!(!c);
}

#[test]
fn abcd_with_extend() {
    let (r, _c, _v) = abcd_byte(0x25, 0x37, true);
    assert_eq!(r, 0x63);
}

#[test]
fn abcd_carry_out() {
    let (_r, c, _) = abcd_byte(0x99, 0x01, false);
    assert!(c);
}

#[test]
fn sbcd_simple() {
    let (r, c) = sbcd_byte(0x05, 0x37, false);
    assert_eq!(r, 0x32);
    assert!(!c);
}

#[test]
fn sbcd_with_borrow() {
    let (_r, c) = sbcd_byte(0x05, 0x03, false);
    assert!(c);
}

// ── nop_sled / patch_call_target ─────────────────────────────────────────────

#[test]
fn nop_sled_too_short() {
    let mut b = [0u8; 1];
    assert_eq!(nop_sled(&mut b), PatchResult::TooShort);
}

#[test]
fn nop_sled_odd_count() {
    let mut b = [0u8; 3];
    assert_eq!(nop_sled(&mut b), PatchResult::OddCount);
}

#[test]
fn nop_sled_ok() {
    let mut b = [0xFFu8; 8];
    assert_eq!(nop_sled(&mut b), PatchResult::Ok);
    for c in b.chunks_exact(2) {
        assert_eq!(c, &[0x4E, 0x71]);
    }
}

#[test]
fn patch_call_target_jsr() {
    let mut b = encode_jsr_abs_long(0).to_vec();
    assert!(patch_call_target(&mut b, 0xDEAD_BEEF));
    assert_eq!(&b[2..6], &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn patch_call_target_jmp() {
    let mut b = encode_jmp_abs_long(0).to_vec();
    assert!(patch_call_target(&mut b, 0x1122_3344));
    assert_eq!(&b[2..6], &[0x11, 0x22, 0x33, 0x44]);
}

#[test]
fn patch_call_target_unknown_returns_false() {
    let mut b = [0x4E, 0x71, 0, 0, 0, 0]; // NOP, not a call
    assert!(!patch_call_target(&mut b, 0));
}

#[test]
#[should_panic]
fn patch_call_target_buf_too_short_panics() {
    let mut b = [0u8; 4];
    let _ = patch_call_target(&mut b, 0);
}

// ── Mc68kArch / Architecture trait ───────────────────────────────────────────

#[test]
fn arch_default_is_m68000() {
    let a = Mc68kArch::default();
    assert_eq!(a.variant, Mc68kVariant::M68000);
    assert_eq!(a.ptr_size(), 4);
    assert_eq!(a.pointer_size(), 4);
}

#[test]
fn arch_endian_big() {
    use rustre_core::endian::Endian;
    assert!(matches!(arch().endian(), Endian::Big));
}

#[test]
fn arch_registers_include_basic() {
    let regs = arch().registers();
    let names: Vec<&str> = regs.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"D0"));
    assert!(names.contains(&"SP"));
    assert!(names.contains(&"PC"));
    assert!(names.contains(&"SR"));
}

#[test]
fn arch_fpu_variant_includes_fp_regs() {
    let regs = Mc68kArch::new(Mc68kVariant::M68040).registers();
    let names: Vec<&str> = regs.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"FP0"));
    assert!(names.contains(&"FPSR"));
}

#[test]
fn arch_calling_conventions_nonempty() {
    let cvs = arch().calling_conventions();
    assert!(!cvs.is_empty());
}

#[test]
fn calling_conventions_for_fpu_variant_has_extra() {
    let no_fpu = calling_conventions_for(Mc68kVariant::M68000).len();
    let with_fpu = calling_conventions_for(Mc68kVariant::M68040).len();
    assert!(with_fpu > no_fpu);
}

// ── Decoder happy paths via Architecture::disassemble ────────────────────────

#[test]
fn decode_truncated_errors() {
    assert!(arch().disassemble(a(0), &[]).is_err());
    assert!(arch().disassemble(a(0), &[0x4E]).is_err());
}

#[test]
fn decode_nop_via_decode_68k() {
    let (mn, ops, sz, fl) = decode_68k(&[0x4E, 0x71], 0).unwrap();
    assert_eq!(mn, "NOP");
    assert_eq!(ops, "");
    assert_eq!(sz, 2);
    assert!(!fl.contains(InstrFlags::BRANCH));
}

#[test]
fn decode_bra_returns_branch_flag() {
    let (_mn, _ops, _sz, fl) = decode_68k(&[0x60, 0x10], 0x1000).unwrap();
    assert!(fl.contains(InstrFlags::BRANCH));
}

// ── AnalysisResult / analyze ─────────────────────────────────────────────────

#[test]
fn analyze_empty() {
    let r = analyze(a(0), &[]);
    assert_eq!(r.instr_count(), 0);
    assert_eq!(r.code_size(), 0);
    assert!(!r.has_calls());
    assert_eq!(r.errors, 0);
}

#[test]
fn analyze_nop_sequence() {
    let bytes = vec![0x4E, 0x71, 0x4E, 0x71, 0x4E, 0x71];
    let r = analyze(a(0x1000), &bytes);
    assert_eq!(r.instr_count(), 3);
    assert_eq!(r.code_size(), 6);
}

#[test]
fn analyze_picks_up_jsr_call_target() {
    let jsr = encode_jsr_abs_long(0x0000_2000);
    let mut bytes = jsr.to_vec();
    bytes.extend_from_slice(&[0x4E, 0x75]); // RTS
    let r = analyze(a(0x1000), &bytes);
    assert!(r.has_calls());
    assert_eq!(r.returns.len(), 1);
}

// ── Linear disassembler ──────────────────────────────────────────────────────

#[test]
fn linear_disasm_iterates_all() {
    let arch = arch();
    let bytes = vec![0x4E, 0x71, 0x4E, 0x71, 0x4E, 0x75];
    let lin = Mc68kLinearDisassembler::new(&arch, &bytes, a(0));
    let v: Vec<_> = lin.collect();
    assert_eq!(v.len(), 3);
    assert!(v.iter().all(Result::is_ok));
}

#[test]
fn linear_disasm_offset_progress() {
    let arch = arch();
    let bytes = vec![0x4E, 0x71, 0x4E, 0x75];
    let mut lin = Mc68kLinearDisassembler::new(&arch, &bytes, a(0));
    assert!(!lin.is_done());
    assert_eq!(lin.offset(), 0);
    let _ = lin.next();
    assert_eq!(lin.offset(), 2);
}

// ── Recursive disassembler ───────────────────────────────────────────────────

#[test]
fn recursive_disasm_walks_through_rts() {
    let arch = arch();
    let bytes = vec![0x4E, 0x71, 0x4E, 0x71, 0x4E, 0x75];
    let mut r = Mc68kRecursiveDisassembler::new(&arch, &bytes, a(0), 0);
    r.run();
    assert!(r.count() >= 1);
    let instrs = r.instructions();
    assert!(!instrs.is_empty());
}

#[test]
fn recursive_disasm_oob_entry_safe() {
    let arch = arch();
    let bytes = vec![0x4E, 0x71];
    let mut r = Mc68kRecursiveDisassembler::new(&arch, &bytes, a(0), 999);
    r.run();
    assert_eq!(r.count(), 0);
}

// ── InstrStats ───────────────────────────────────────────────────────────────

#[test]
fn instr_stats_empty() {
    let s = InstrStats::from_instrs(&[]);
    assert_eq!(s.total(), 0);
}

#[test]
fn instr_stats_counts_nop_sequence() {
    let arch = arch();
    let bytes = vec![0x4E, 0x71, 0x4E, 0x71];
    let v: Vec<Instruction> = Mc68kLinearDisassembler::new(&arch, &bytes, a(0))
        .filter_map(Result::ok)
        .collect();
    let _s = InstrStats::from_instrs(&v);
    // NOP isn't one of the counted categories, but total() must be defined.
}

// ── DisasmOptions / format_instr ─────────────────────────────────────────────

#[test]
fn format_instr_uppercase_default() {
    let i = arch().disassemble(a(0x1000), &[0x4E, 0x71]).unwrap();
    let s = format_instr(&i, &DisasmOptions::default());
    assert!(s.contains("NOP"));
    assert!(s.contains("00001000"));
}

#[test]
fn format_instr_lowercase() {
    let i = arch().disassemble(a(0x1000), &[0x4E, 0x71]).unwrap();
    let opts = DisasmOptions { show_bytes: false, mnemonic_width: 4, uppercase: false, show_address: false };
    let s = format_instr(&i, &opts);
    assert!(s.to_lowercase().contains("nop"));
}

#[test]
fn format_listing_joins_with_newline() {
    let arch = arch();
    let bytes = vec![0x4E, 0x71, 0x4E, 0x71];
    let v: Vec<Instruction> = Mc68kLinearDisassembler::new(&arch, &bytes, a(0))
        .filter_map(Result::ok)
        .collect();
    let s = format_listing(&v, &DisasmOptions::default());
    assert!(s.contains('\n'));
}

// ── find_stack_frames ────────────────────────────────────────────────────────

#[test]
fn find_stack_frames_none() {
    let arch = arch();
    let i = arch.disassemble(a(0), &[0x4E, 0x71]).unwrap();
    assert!(find_stack_frames(&[i]).is_empty());
}

// ── Prologue/epilogue ────────────────────────────────────────────────────────

#[test]
fn detect_prologue_none_for_nop() {
    let arch = arch();
    let i = arch.disassemble(a(0), &[0x4E, 0x71]).unwrap();
    assert_eq!(detect_prologue(&[i], 4), PrologueKind::None);
}

#[test]
fn detect_epilogue_finds_rts() {
    let arch = arch();
    let nop = arch.disassemble(a(0), &[0x4E, 0x71]).unwrap();
    let rts = arch.disassemble(a(2), &[0x4E, 0x75]).unwrap();
    assert!(detect_epilogue(&[nop, rts]));
}

#[test]
fn detect_epilogue_no_rts() {
    let arch = arch();
    let i = arch.disassemble(a(0), &[0x4E, 0x71]).unwrap();
    assert!(!detect_epilogue(&[i]));
}

// ── Patterns / find_idioms / instr_matches ───────────────────────────────────

#[test]
fn pattern_matches_basic() {
    let arch = arch();
    let nop = arch.disassemble(a(0), &[0x4E, 0x71]).unwrap();
    let pat = Pattern { mnemonics: &["NOP"], name: "single_nop" };
    assert!(pat.matches(&[nop]));
}

#[test]
fn pattern_wildcard_prefix() {
    let arch = arch();
    let nop = arch.disassemble(a(0), &[0x4E, 0x71]).unwrap();
    let pat = Pattern { mnemonics: &["N*"], name: "n_anything" };
    assert!(pat.matches(&[nop]));
}

#[test]
fn pattern_too_short_no_match() {
    let pat = Pattern { mnemonics: &["NOP", "RTS"], name: "x" };
    assert!(!pat.matches(&[]));
}

#[test]
fn instr_matches_exact_and_wildcard() {
    let arch = arch();
    let nop = arch.disassemble(a(0), &[0x4E, 0x71]).unwrap();
    assert!(instr_matches(&nop, "NOP"));
    assert!(instr_matches(&nop, "N*"));
    assert!(!instr_matches(&nop, "RTS"));
}

#[test]
fn find_idioms_empty_input() {
    assert!(find_idioms(&[]).is_empty());
}

// ── Xref / build_xrefs ──────────────────────────────────────────────────────

#[test]
fn build_xrefs_jsr() {
    let bytes = encode_jsr_abs_long(0x0000_2000);
    let i = arch().disassemble(a(0x1000), &bytes).unwrap();
    let x = build_xrefs(&[i]);
    assert_eq!(x.len(), 1);
    assert!(x[0].is_call);
    assert_eq!(x[0].to.as_u64(), 0x2000);
}

// ── Symbol / SymbolTable ─────────────────────────────────────────────────────

#[test]
fn symbol_table_basic() {
    let mut t = SymbolTable::default();
    assert!(t.is_empty());
    t.add(Symbol::function(a(0x100), "f1"));
    t.add(Symbol::data(a(0x200), "d1"));
    assert_eq!(t.len(), 2);
    assert!(!t.is_empty());
    assert!(t.by_address(a(0x100)).is_some());
    assert_eq!(t.by_name("f1").unwrap().address.as_u64(), 0x100);
    assert!(t.by_name("nope").is_none());
    assert_eq!(t.functions().len(), 1);
}

// ── BasicBlock / build_cfg ──────────────────────────────────────────────────

#[test]
fn build_cfg_empty() {
    assert!(build_cfg(&[]).is_empty());
}

#[test]
fn build_cfg_single_nop() {
    let i = arch().disassemble(a(0x1000), &[0x4E, 0x71]).unwrap();
    let cfg = build_cfg(&[i]);
    assert_eq!(cfg.len(), 1);
    assert_eq!(cfg[0].start.as_u64(), 0x1000);
}

#[test]
fn basic_block_size_saturating() {
    let bb = BasicBlock { start: a(10), end: a(5), successors: vec![], ends_with_call: false, ends_with_return: false };
    assert_eq!(bb.size(), 0);
}

// ── FpRegister / FpuRegFile ─────────────────────────────────────────────────

#[test]
fn fp_register_is_zero_default() {
    let r = FpRegister::default();
    assert!(r.is_zero());
}

#[test]
fn fp_register_from_f64_is_simplified_zero() {
    // simplified impl stores zero — record current behavior; flag if changed
    let r = FpRegister::from_f64(3.14);
    assert!(r.is_zero(), "from_f64 currently always returns zero");
}

#[test]
fn fpu_regfile_flags() {
    let mut f = FpuRegFile::default();
    assert!(!f.is_zero());
    f.fpsr = 1 << 26;
    assert!(f.is_zero());
    f.fpsr = 1 << 27;
    assert!(f.is_negative());
    f.fpsr = 1 << 24;
    assert!(f.is_nan());
    f.fpsr = 1 << 25;
    assert!(f.is_infinity());
}

// ── decode_muldiv_info ──────────────────────────────────────────────────────

#[test]
fn decode_muldiv_info_none_for_nop() {
    assert!(decode_muldiv_info(0x4E71).is_none());
}

// ── MulDivInfo: just exercise construction ───────────────────────────────────

#[test]
fn muldiv_struct_fields() {
    let m = MulDivInfo { is_signed: true, is_divide: true, result_reg: 3 };
    assert!(m.is_signed);
    assert_eq!(m.result_reg, 3);
}

// ── branch_hint ──────────────────────────────────────────────────────────────

#[test]
fn branch_hint_non_branch_unknown() {
    let i = arch().disassemble(a(0x1000), &[0x4E, 0x71]).unwrap();
    assert_eq!(branch_hint(&i, 0x2000), BranchHint::Unknown);
}

#[test]
fn branch_hint_unconditional_bra() {
    let bytes = encode_bra16(0x10);
    let i = arch().disassemble(a(0x1000), &bytes).unwrap();
    assert_eq!(branch_hint(&i, 0x1100), BranchHint::AlwaysTaken);
}

// ── is_amiga_library_call / amiga_lvo ────────────────────────────────────────

#[test]
fn is_amiga_library_call_neg() {
    let i = arch().disassemble(a(0x1000), &[0x4E, 0x71]).unwrap();
    assert!(!is_amiga_library_call(&i));
    assert!(amiga_lvo(&i).is_none());
}

// ── branch_category ──────────────────────────────────────────────────────────

#[test]
fn branch_category_strings() {
    use rustre_core::arch::BranchInfo;
    assert_eq!(branch_category(&BranchInfo::call(0)), "call");
    assert_eq!(branch_category(&BranchInfo::unconditional_jump(0)), "jump");
}

// ── RegisterUsage ────────────────────────────────────────────────────────────

#[test]
fn register_usage_writes_count() {
    let mut u = RegisterUsage::default();
    u.write_d(0);
    u.write_d(1);
    u.write_a(7);
    assert_eq!(u.data_regs_written(), 2);
    assert_eq!(u.addr_regs_written(), 1);
}

#[test]
fn register_usage_high_reg_masked() {
    let mut u = RegisterUsage::default();
    u.write_d(15); // should mask to D7
    assert_eq!(u.data_write, 1 << 7);
}

// ── is_nop / is_control_transfer / modifies_ccr ──────────────────────────────

#[test]
fn is_nop_true() {
    let i = arch().disassemble(a(0), &[0x4E, 0x71]).unwrap();
    assert!(is_nop(&i));
    assert!(!modifies_ccr(&i)); // NOP doesn't modify CCR
}

#[test]
fn is_control_transfer_rts() {
    let i = arch().disassemble(a(0), &[0x4E, 0x75]).unwrap();
    assert!(is_control_transfer(&i));
}
