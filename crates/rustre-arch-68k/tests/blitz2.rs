//! Second blitz test suite for rustre-arch-68k.
//! Adversarial coverage of encoders, decoders, helpers, and analysis.

use rustre_arch_68k::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn h<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

// Seeded LCG fuzzer
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

// ── Variant Hash/Eq consistency ──────────────────────────────────────────────

#[test]
fn variant_hash_eq_consistency() {
    let vs = [
        Mc68kVariant::M68000,
        Mc68kVariant::M68010,
        Mc68kVariant::M68020,
        Mc68kVariant::M68030,
        Mc68kVariant::M68040,
        Mc68kVariant::M68060,
        Mc68kVariant::ColdFire,
    ];
    for a in vs {
        for b in vs {
            if a == b {
                assert_eq!(h(&a), h(&b));
            }
        }
    }
}

#[test]
fn variant_address_space_monotone() {
    // 32-bit variants have 4 GiB
    for v in [
        Mc68kVariant::M68020,
        Mc68kVariant::M68030,
        Mc68kVariant::M68040,
        Mc68kVariant::M68060,
        Mc68kVariant::ColdFire,
    ] {
        assert_eq!(v.address_space_bytes(), 0x1_0000_0000);
    }
}

// ── Size invariants ──────────────────────────────────────────────────────────

#[test]
fn size_from_bits2_full_byte_sweep() {
    // Only the low 2 bits matter; sweep all 256
    for b in 0u8..=255 {
        let s = Size::from_bits2(b);
        let expect = match b & 3 {
            0 => Size::Byte,
            1 => Size::Word,
            _ => Size::Long,
        };
        assert_eq!(s, expect, "byte=0x{b:02X}");
    }
}

#[test]
fn size_bytes_suffix_consistent() {
    for s in [Size::Byte, Size::Word, Size::Long, Size::Quad] {
        assert!(s.bytes() > 0);
        assert!(s.suffix().starts_with('.'));
    }
}

#[test]
fn size_hash_eq() {
    let sizes = [Size::Byte, Size::Word, Size::Long, Size::Quad];
    for a in sizes {
        for b in sizes {
            if a == b {
                assert_eq!(h(&a), h(&b));
            }
        }
    }
}

// ── CondCode round-trip ──────────────────────────────────────────────────────

#[test]
fn cond_code_from_bits_round_trip() {
    let codes = [
        CondCode::T,
        CondCode::F,
        CondCode::Hi,
        CondCode::Ls,
        CondCode::Cc,
        CondCode::Cs,
        CondCode::Ne,
        CondCode::Eq,
        CondCode::Vc,
        CondCode::Vs,
        CondCode::Pl,
        CondCode::Mi,
        CondCode::Ge,
        CondCode::Lt,
        CondCode::Gt,
        CondCode::Le,
    ];
    for (i, c) in codes.iter().enumerate() {
        let decoded = CondCode::from_bits(i as u8);
        assert_eq!(decoded, *c, "bits={i}");
        // Upper bits ignored
        assert_eq!(CondCode::from_bits(i as u8 | 0xF0), *c);
    }
}

#[test]
fn cond_code_mnemonic_unique() {
    let codes = [
        CondCode::T, CondCode::F, CondCode::Hi, CondCode::Ls,
        CondCode::Cc, CondCode::Cs, CondCode::Ne, CondCode::Eq,
        CondCode::Vc, CondCode::Vs, CondCode::Pl, CondCode::Mi,
        CondCode::Ge, CondCode::Lt, CondCode::Gt, CondCode::Le,
    ];
    let mut ms: Vec<&str> = codes.iter().map(|c| c.mnemonic()).collect();
    ms.sort_unstable();
    let n = ms.len();
    ms.dedup();
    assert_eq!(ms.len(), n);
}

#[test]
fn cond_invert_is_involution() {
    let codes = [
        CondCode::T, CondCode::F, CondCode::Hi, CondCode::Ls,
        CondCode::Cc, CondCode::Cs, CondCode::Ne, CondCode::Eq,
        CondCode::Vc, CondCode::Vs, CondCode::Pl, CondCode::Mi,
        CondCode::Ge, CondCode::Lt, CondCode::Gt, CondCode::Le,
    ];
    for c in codes {
        assert_eq!(invert_cond(invert_cond(c)), c);
        // Never equal to itself
        assert_ne!(invert_cond(c), c);
    }
}

#[test]
fn cond_unconditional_only_t() {
    assert!(CondCode::T.is_unconditional());
    for c in [CondCode::F, CondCode::Hi, CondCode::Eq, CondCode::Ne] {
        assert!(!c.is_unconditional());
    }
}

// ── Encoder round-trips ──────────────────────────────────────────────────────

#[test]
fn encode_nop_rts_rte_bytes() {
    assert_eq!(encode_nop(), [0x4E, 0x71]);
    assert_eq!(encode_rts(), [0x4E, 0x75]);
    assert_eq!(encode_rte(), [0x4E, 0x73]);
}

#[test]
fn encode_nop_decodes_as_nop() {
    let b = encode_nop();
    let (mn, _, sz, _) = decode_68k(&b, 0).unwrap();
    assert_eq!(mn, "NOP");
    assert_eq!(sz, 2);
}

#[test]
fn encode_rts_lookup_opcode() {
    let b = encode_rts();
    let word = u16::from_be_bytes([b[0], b[1]]);
    let entry = lookup_opcode(word).expect("RTS in table");
    assert_eq!(entry.mnemonic, "RTS");
}

#[test]
fn encode_moveq_all_regs() {
    for dn in 0u8..8 {
        for imm in [-128i8, -1, 0, 1, 42, 127] {
            let b = encode_moveq(dn, imm);
            let word = u16::from_be_bytes([b[0], b[1]]);
            // Top nibble must be 0x7
            assert_eq!(word >> 12, 0x7);
            // Register field
            assert_eq!(((word >> 9) & 7) as u8, dn);
            // moveq_value extracts the i8 back
            assert_eq!(moveq_value(word), i32::from(imm));
        }
    }
}

#[test]
fn encode_bra8_round_trip() {
    for disp in [-128i8, -64, -1, 1, 42, 127] {
        let b = encode_bra8(disp);
        assert_eq!(b[0], 0x60);
        assert_eq!(b[1] as i8, disp);
    }
}

#[test]
#[should_panic]
fn encode_bra8_zero_panics() {
    let _ = encode_bra8(0);
}

#[test]
#[should_panic]
fn encode_bsr8_zero_panics() {
    let _ = encode_bsr8(0);
}

#[test]
#[should_panic]
fn encode_moveq_bad_reg_panics() {
    let _ = encode_moveq(8, 0);
}

#[test]
#[should_panic]
fn encode_trap_bad_vec_panics() {
    let _ = encode_trap(16);
}

#[test]
fn encode_trap_all_vectors() {
    for v in 0u8..16 {
        let b = encode_trap(v);
        let word = u16::from_be_bytes([b[0], b[1]]);
        assert_eq!(word & 0xFFF0, 0x4E40);
        assert_eq!(trap_vector(word), Some(v));
    }
}

#[test]
fn trap_vector_non_trap_returns_none() {
    assert_eq!(trap_vector(0x4E71), None); // NOP
    assert_eq!(trap_vector(0x0000), None);
    assert_eq!(trap_vector(0x4E50), None); // LINK
}

#[test]
fn encode_clr_all_sizes_regs() {
    for dn in 0u8..8 {
        for sz in [Size::Byte, Size::Word, Size::Long] {
            let b = encode_clr(sz, dn);
            let word = u16::from_be_bytes([b[0], b[1]]);
            // CLR pattern 0x4200 | size_bits<<6 | dn
            assert_eq!(word & 0xFF00, 0x4200);
            assert_eq!((word & 7) as u8, dn);
        }
    }
}

#[test]
fn encode_bra16_round_trip() {
    for disp in [i16::MIN, -1000, -1, 0, 1, 1000, i16::MAX] {
        let b = encode_bra16(disp);
        assert_eq!(&b[..2], &[0x60, 0x00]);
        let got = i16::from_be_bytes([b[2], b[3]]);
        assert_eq!(got, disp);
    }
}

#[test]
fn encode_jmp_jsr_abs_long_round_trip() {
    let mut g = lcg();
    for _ in 0..50 {
        let addr = (g() & 0xFFFF_FFFF) as u32;
        let j = encode_jmp_abs_long(addr);
        assert_eq!(&j[..2], &[0x4E, 0xF9]);
        assert_eq!(u32::from_be_bytes([j[2], j[3], j[4], j[5]]), addr);
        let s = encode_jsr_abs_long(addr);
        assert_eq!(&s[..2], &[0x4E, 0xB9]);
        assert_eq!(u32::from_be_bytes([s[2], s[3], s[4], s[5]]), addr);
    }
}

#[test]
fn encode_link_unlk_dbra() {
    for an in 0u8..8 {
        let u = encode_unlk(an);
        assert_eq!(u16::from_be_bytes([u[0], u[1]]) & 0xFFF8, 0x4E58);
        let l = encode_link(an, -8);
        let word = u16::from_be_bytes([l[0], l[1]]);
        assert_eq!(word & 0xFFF8, 0x4E50);
        let disp = i16::from_be_bytes([l[2], l[3]]);
        assert_eq!(disp, -8);
    }
    for dn in 0u8..8 {
        let d = encode_dbra(dn, 16);
        let word = u16::from_be_bytes([d[0], d[1]]);
        assert_eq!(word & 0xFFF8, 0x51C8);
        assert_eq!(i16::from_be_bytes([d[2], d[3]]), 16);
    }
}

#[test]
#[should_panic]
fn encode_link_bad_reg_panics() {
    let _ = encode_link(8, 0);
}

#[test]
fn encode_addi_subq_basics() {
    let a = encode_addi_word(0x1234, 3);
    assert_eq!(u16::from_be_bytes([a[0], a[1]]), 0x0643);
    assert_eq!(u16::from_be_bytes([a[2], a[3]]), 0x1234);

    // SUBQ data range 1..=8
    for d in 1u8..=8 {
        for dn in 0u8..8 {
            let b = encode_subq_word(d, dn);
            let word = u16::from_be_bytes([b[0], b[1]]);
            assert_eq!(word & 0xF000, 0x5000);
            assert_eq!((word & 7) as u8, dn);
        }
    }
}

#[test]
#[should_panic]
fn encode_subq_zero_panics() {
    let _ = encode_subq_word(0, 0);
}

#[test]
#[should_panic]
fn encode_subq_nine_panics() {
    let _ = encode_subq_word(9, 0);
}

// ── moveq_value / addq_value ─────────────────────────────────────────────────

#[test]
fn moveq_value_sign_extends() {
    assert_eq!(moveq_value(0x7000), 0);
    assert_eq!(moveq_value(0x7001), 1);
    assert_eq!(moveq_value(0x707F), 127);
    assert_eq!(moveq_value(0x7080), -128);
    assert_eq!(moveq_value(0x70FF), -1);
}

#[test]
fn addq_value_encodes_zero_as_eight() {
    // bits 11..9
    assert_eq!(addq_value(0x0000), 8);
    assert_eq!(addq_value(0x0200), 1);
    assert_eq!(addq_value(0x0E00), 7);
}

// ── MOVEM mask helpers ───────────────────────────────────────────────────────

#[test]
fn count_movem_regs_known() {
    assert_eq!(count_movem_regs(0), 0);
    assert_eq!(count_movem_regs(0xFFFF), 16);
    assert_eq!(count_movem_regs(0x0001), 1);
    assert_eq!(count_movem_regs(0x8001), 2);
}

#[test]
fn movem_reg_names_basic() {
    let names = movem_reg_names(0x0001);
    assert_eq!(names, vec!["D0".to_string()]);
    let names = movem_reg_names(0x0100);
    assert_eq!(names, vec!["A0".to_string()]);
    let names = movem_reg_names(0x8000);
    assert_eq!(names, vec!["A7".to_string()]);
    let names = movem_reg_names(0xFFFF);
    assert_eq!(names.len(), 16);
}

#[test]
fn encode_register_mask_round_trip_post_increment() {
    // Without predecrement, decode_register_mask should round-trip
    let regs = ["D0", "D3", "A0", "A6"];
    let mask = encode_register_mask(&regs, false);
    assert_eq!(mask, 0x0001 | 0x0008 | 0x0100 | 0x4000);
    let s = decode_register_mask(mask, false);
    assert!(s.contains("D0"));
    assert!(s.contains("D3"));
    assert!(s.contains("A0"));
    assert!(s.contains("A6"));
}

#[test]
fn encode_register_mask_predecrement_reverses() {
    // encode_register_mask predecrement reverses, decode_register_mask predecrement reverses
    let regs = ["D0", "A7"];
    let mask = encode_register_mask(&regs, true);
    let s = decode_register_mask(mask, true);
    assert!(s.contains("D0"));
    assert!(s.contains("A7"));
}

#[test]
fn encode_register_mask_unknown_ignored() {
    let mask = encode_register_mask(&["D0", "BOGUS", "A0"], false);
    assert_eq!(mask, 0x0001 | 0x0100);
}

#[test]
fn encode_movem_push_pop_bytes() {
    let p = encode_movem_push(0x1234);
    assert_eq!(&p[..2], &[0x48, 0xE7]);
    assert_eq!(u16::from_be_bytes([p[2], p[3]]), 0x1234);
    let q = encode_movem_pop(0x5678);
    assert_eq!(&q[..2], &[0x4C, 0xDF]);
    assert_eq!(u16::from_be_bytes([q[2], q[3]]), 0x5678);
}

// ── branch_displacement ──────────────────────────────────────────────────────

#[test]
fn branch_displacement_basic() {
    // pc=0x1000 target=0x1010 → 0x1010 - (0x1000+2) = 0x0E = 14
    assert_eq!(branch_displacement(0x1000, 0x1010, false), Some(14));
    assert_eq!(branch_displacement(0x1000, 0x1010, true), Some(14));
}

#[test]
fn branch_displacement_unreachable_word() {
    // i16 max range is -32768..32767. A 100k offset is too far for word.
    let from = 0x1000u64;
    let target = from + 2 + 100_000;
    assert_eq!(branch_displacement(from, target, false), None);
    // But with use_long it fits.
    assert_eq!(branch_displacement(from, target, true), Some(100_000));
}

#[test]
fn branch_displacement_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..50 {
        let from = g();
        let to = g();
        let _ = branch_displacement(from, to, false);
        let _ = branch_displacement(from, to, true);
    }
}

// ── ABCD/SBCD ────────────────────────────────────────────────────────────────

#[test]
fn abcd_known_cases() {
    // 0x25 + 0x37 = 0x62, no carry
    let (r, c, _) = abcd_byte(0x25, 0x37, false);
    assert_eq!(r, 0x62);
    assert!(!c);
    // 0x50 + 0x50 = 0x100 → wraps to 0x00 with carry
    let (r, c, _) = abcd_byte(0x50, 0x50, false);
    assert_eq!(r, 0x00);
    assert!(c);
    // 0x99 + 0x01 = 0x100 → wraps to 0x00, carry
    let (r, c, _) = abcd_byte(0x99, 0x01, false);
    assert_eq!(r, 0x00);
    assert!(c);
}

#[test]
fn sbcd_known_cases() {
    // 50 - 25 = 25
    let (r, c) = sbcd_byte(0x25, 0x50, false);
    assert_eq!(r, 0x25);
    assert!(!c);
    // 0 - 1 = 99 with borrow
    let (r, c) = sbcd_byte(0x01, 0x00, false);
    assert_eq!(r, 0x99);
    assert!(c);
}

#[test]
fn abcd_sbcd_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..200 {
        let a = (g() & 0xFF) as u8;
        let b = (g() & 0xFF) as u8;
        let x = (g() & 1) != 0;
        let _ = abcd_byte(a, b, x);
        let _ = sbcd_byte(a, b, x);
    }
}

// ── decode_shift_count / decode_muldiv_info ──────────────────────────────────

#[test]
fn decode_shift_count_imm_vs_reg() {
    // count_field=0 → 8 (imm mode)
    let (c, r) = decode_shift_count(0x0000);
    assert_eq!(c, 8);
    assert!(!r);
    // count_field=3 → 3
    let (c, r) = decode_shift_count(0x0600);
    assert_eq!(c, 3);
    assert!(!r);
    // reg bit
    let (_, r) = decode_shift_count(0x0020);
    assert!(r);
}

#[test]
fn decode_muldiv_info_recognises_groups() {
    // hi4=0x8, bits6..11=0x03 → DIV
    // Alternate hand-rolled encoding: hi4=8, signed flag bit 8 set, bits 6..7 = 11.
    let w_divs: u16 = 0x81C0; // 0x8000 | (0<<9) | (0x07<<6) — DIVS-style sanity bits.
    // The hand-rolled `w_divs` must still classify as a divide once normalised
    // by clearing the register field (bits 9..11) so the (hi4, low6) shape matches.
    let w_divs_norm = w_divs & !(0x7 << 9);
    let info_alt = decode_muldiv_info(w_divs_norm).expect("DIVS alt encoding");
    assert!(info_alt.is_divide);
    assert!(info_alt.is_signed);
    // construct manually: hi4=8 (bit 15..12 = 1000), bits 6..11 == 3 (binary 000011), reg in 9..11
    // bits encoding: word>>6 & 0x3F == 0b000011 = 3 → bits 6=1, 7=1, others 0 → 0xC0
    let div_word: u16 = (0x8 << 12) | 0xC0;
    let info = decode_muldiv_info(div_word).expect("DIVU");
    assert!(info.is_divide);
    assert!(!info.is_signed);
    let div_word_s = div_word | 0x0100;
    let info = decode_muldiv_info(div_word_s).expect("DIVS");
    assert!(info.is_signed);

    let mul_word: u16 = (0xC_u16 << 12) | 0xC0;
    let info = decode_muldiv_info(mul_word).expect("MULU");
    assert!(!info.is_divide);
    assert!(!info.is_signed);

    // Non-mul/div → None
    assert!(decode_muldiv_info(0x0000).is_none());
    assert!(decode_muldiv_info(0x4E71).is_none());
}

// ── classify_ea_mode / is_data_alterable_ea / is_control_ea / is_movable_dst_ea ─

#[test]
fn classify_ea_mode_categories() {
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
fn ea_validators_known() {
    // Data alterable: mode 0, 2..=6, mode 7 with reg 0 or 1
    assert!(is_data_alterable_ea(0, 0));
    assert!(is_data_alterable_ea(2, 0));
    assert!(is_data_alterable_ea(6, 0));
    assert!(is_data_alterable_ea(7, 0));
    assert!(is_data_alterable_ea(7, 1));
    assert!(!is_data_alterable_ea(7, 2));
    assert!(!is_data_alterable_ea(1, 0));

    // Control EA: mode 2, 5, 6, or 7 reg 0..=3
    assert!(is_control_ea(2, 0));
    assert!(is_control_ea(5, 0));
    assert!(is_control_ea(6, 0));
    assert!(is_control_ea(7, 3));
    assert!(!is_control_ea(7, 4));
    assert!(!is_control_ea(0, 0));

    // Movable dst: mode 0..=6, or 7 reg 0/1
    for m in 0u8..=6 {
        assert!(is_movable_dst_ea(m, 0));
    }
    assert!(is_movable_dst_ea(7, 0));
    assert!(is_movable_dst_ea(7, 1));
    assert!(!is_movable_dst_ea(7, 2));
}

// ── lookup_opcode ───────────────────────────────────────────────────────────

#[test]
fn lookup_opcode_known_words() {
    assert_eq!(lookup_opcode(0x4E71).unwrap().mnemonic, "NOP");
    assert_eq!(lookup_opcode(0x4E75).unwrap().mnemonic, "RTS");
    assert_eq!(lookup_opcode(0x4E73).unwrap().mnemonic, "RTE");
    assert_eq!(lookup_opcode(0x4E77).unwrap().mnemonic, "RTR");
    assert_eq!(lookup_opcode(0x4E70).unwrap().mnemonic, "RESET");
}

#[test]
fn lookup_opcode_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..200 {
        let w = (g() & 0xFFFF) as u16;
        let _ = lookup_opcode(w);
    }
}

// ── parse_ea ────────────────────────────────────────────────────────────────

#[test]
fn parse_ea_simple_modes() {
    let (k, n) = parse_ea(0, 3, Size::Long, &[]).unwrap();
    assert_eq!(k, EaKind::DataReg(3));
    assert_eq!(n, 0);
    let (k, n) = parse_ea(1, 5, Size::Long, &[]).unwrap();
    assert_eq!(k, EaKind::AddrReg(5));
    assert_eq!(n, 0);
    let (k, n) = parse_ea(2, 0, Size::Long, &[]).unwrap();
    assert_eq!(k, EaKind::AddrInd(0));
    assert_eq!(n, 0);
    let (k, n) = parse_ea(3, 7, Size::Long, &[]).unwrap();
    assert_eq!(k, EaKind::AddrIndPost(7));
    assert_eq!(n, 0);
    let (k, n) = parse_ea(4, 1, Size::Long, &[]).unwrap();
    assert_eq!(k, EaKind::AddrIndPre(1));
    assert_eq!(n, 0);
}

#[test]
fn parse_ea_disp16_and_abs() {
    let (k, n) = parse_ea(5, 0, Size::Word, &[0x12, 0x34]).unwrap();
    assert!(matches!(k, EaKind::AddrIndDisp(0, 0x1234)));
    assert_eq!(n, 2);
    let (k, n) = parse_ea(7, 0, Size::Word, &[0x00, 0x10]).unwrap();
    assert_eq!(k, EaKind::AbsShort(0x0010));
    assert_eq!(n, 2);
    let (k, n) = parse_ea(7, 1, Size::Long, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
    assert_eq!(k, EaKind::AbsLong(0xDEAD_BEEF));
    assert_eq!(n, 4);
}

#[test]
fn parse_ea_immediate_sizes() {
    let (k, n) = parse_ea(7, 4, Size::Byte, &[0x00, 0x55]).unwrap();
    assert_eq!(k, EaKind::Immediate(0x55));
    assert_eq!(n, 2);
    let (k, n) = parse_ea(7, 4, Size::Word, &[0x12, 0x34]).unwrap();
    assert_eq!(k, EaKind::Immediate(0x1234));
    assert_eq!(n, 2);
    let (k, n) = parse_ea(7, 4, Size::Long, &[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
    assert_eq!(k, EaKind::Immediate(0xAABB_CCDD));
    assert_eq!(n, 4);
}

#[test]
fn parse_ea_truncation_errors() {
    assert!(parse_ea(5, 0, Size::Word, &[]).is_err());
    assert!(parse_ea(5, 0, Size::Word, &[0x12]).is_err());
    assert!(parse_ea(6, 0, Size::Word, &[]).is_err());
    assert!(parse_ea(7, 0, Size::Word, &[]).is_err());
    assert!(parse_ea(7, 1, Size::Word, &[0, 0, 0]).is_err());
    assert!(parse_ea(7, 2, Size::Word, &[]).is_err());
    assert!(parse_ea(7, 4, Size::Long, &[0, 0, 0]).is_err());
    assert!(parse_ea(7, 5, Size::Long, &[]).is_err()); // invalid mode 7 reg
    assert!(parse_ea(8, 0, Size::Long, &[]).is_err()); // invalid mode
}

#[test]
fn parse_ea_fuzz_no_panic() {
    let mut g = lcg();
    let mut buf = vec![0u8; 16];
    for _ in 0..200 {
        let v = g();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((v >> (i % 8 * 8)) & 0xFF) as u8;
        }
        let mode = (g() & 0x7) as u8;
        let reg = (g() & 0x7) as u8;
        let size = Size::from_bits2((g() & 0x3) as u8);
        // Must return Ok or specific Err — never panic
        let _ = parse_ea(mode, reg, size, &buf);
        // Also try truncated
        let _ = parse_ea(mode, reg, size, &buf[..1]);
        let _ = parse_ea(mode, reg, size, &[]);
    }
}

// ── EaKind display ─────────────────────────────────────────────────────────

#[test]
fn eakind_display_basic() {
    assert_eq!(EaKind::DataReg(3).display(), "D3");
    assert_eq!(EaKind::AddrReg(7).display(), "A7");
    assert_eq!(EaKind::AddrInd(2).display(), "(A2)");
    assert_eq!(EaKind::AddrIndPost(0).display(), "(A0)+");
    assert_eq!(EaKind::AddrIndPre(1).display(), "-(A1)");
    assert_eq!(EaKind::AbsShort(0x10).display(), "$0010.W");
    assert_eq!(EaKind::AbsLong(0xDEAD_BEEF).display(), "$DEADBEEF.L");
    assert_eq!(EaKind::Immediate(42).display(), "#$0000002A");
    assert_eq!(EaKind::PcIdx.display(), "(PC,Xn)");
}

#[test]
fn eakind_is_indirect_classification() {
    assert!(!EaKind::DataReg(0).is_indirect());
    assert!(!EaKind::AddrReg(0).is_indirect());
    assert!(!EaKind::Immediate(0).is_indirect());
    assert!(!EaKind::AbsShort(0).is_indirect());
    assert!(!EaKind::AbsLong(0).is_indirect());
    assert!(EaKind::AddrInd(0).is_indirect());
    assert!(EaKind::PcDisp(0).is_indirect());
    assert!(EaKind::PcIdx.is_indirect());
}

// ── decode_68k fuzz / truncation ───────────────────────────────────────────

#[test]
fn decode_68k_truncation() {
    assert!(decode_68k(&[], 0).is_err());
    assert!(decode_68k(&[0x4E], 0).is_err());
}

#[test]
fn decode_68k_fuzz_no_panic() {
    let mut g = lcg();
    let mut buf = vec![0u8; 32];
    for _ in 0..400 {
        let v = g();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((v.wrapping_mul(i as u64 + 1)) & 0xFF) as u8;
        }
        // Truncated and full versions must not panic, just return Ok/Err.
        let _ = decode_68k(&buf, g());
        let _ = decode_68k(&buf[..2], g());
        let _ = decode_68k(&buf[..4], g());
    }
}

#[test]
fn decode_68k_nop_sequence() {
    let buf = [0x4E, 0x71, 0x4E, 0x75]; // NOP, RTS
    let (mn, _, sz, _) = decode_68k(&buf, 0).unwrap();
    assert_eq!(mn, "NOP");
    assert_eq!(sz, 2);
    let (mn2, _, sz2, _) = decode_68k(&buf[2..], 2).unwrap();
    assert_eq!(mn2, "RTS");
    assert_eq!(sz2, 2);
}

// ── nop_sled / patch_call_target ────────────────────────────────────────────

#[test]
fn nop_sled_results() {
    let mut buf = [0u8; 6];
    assert_eq!(nop_sled(&mut buf), PatchResult::Ok);
    assert_eq!(buf, [0x4E, 0x71, 0x4E, 0x71, 0x4E, 0x71]);

    let mut small = [0u8; 1];
    assert_eq!(nop_sled(&mut small), PatchResult::TooShort);

    let mut odd = [0u8; 5];
    assert_eq!(nop_sled(&mut odd), PatchResult::OddCount);

    let mut empty: [u8; 0] = [];
    assert_eq!(nop_sled(&mut empty), PatchResult::TooShort);
}

#[test]
fn patch_call_target_jsr_jmp() {
    // Set up JSR abs.L
    let mut buf = encode_jsr_abs_long(0x1111_1111).to_vec();
    assert!(patch_call_target(&mut buf, 0xAABB_CCDD));
    assert_eq!(u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]), 0xAABB_CCDD);

    let mut buf2 = encode_jmp_abs_long(0).to_vec();
    assert!(patch_call_target(&mut buf2, 0xDEAD_BEEF));
    assert_eq!(u32::from_be_bytes([buf2[2], buf2[3], buf2[4], buf2[5]]), 0xDEAD_BEEF);

    // Non-JSR/JMP returns false
    let mut nop = vec![0x4E, 0x71, 0, 0, 0, 0];
    assert!(!patch_call_target(&mut nop, 1));
}

#[test]
#[should_panic]
fn patch_call_target_too_short_panics() {
    let mut buf = [0u8; 4];
    let _ = patch_call_target(&mut buf, 0);
}

// ── PatchResult hash/eq ─────────────────────────────────────────────────────

#[test]
fn patch_result_eq_consistency() {
    let xs = [PatchResult::Ok, PatchResult::TooShort, PatchResult::OddCount];
    for a in xs {
        for b in xs {
            if a == b {
                // both PartialEq+Eq → reflexive
                assert_eq!(a, b);
            }
        }
    }
}

// ── calling_conventions_for ────────────────────────────────────────────────

#[test]
fn calling_conventions_per_variant() {
    for v in [
        Mc68kVariant::M68000,
        Mc68kVariant::M68020,
        Mc68kVariant::M68040,
        Mc68kVariant::M68060,
        Mc68kVariant::ColdFire,
    ] {
        let ccs = calling_conventions_for(v);
        // Just ensure it doesn't panic and returns a vec we can hash via length
        let _ = ccs.len();
    }
}

// ── Send/Sync for Mc68kVariant ──────────────────────────────────────────────

#[test]
fn variant_send_sync_thread_stress() {
    use std::sync::Arc;
    use std::thread;
    let v = Arc::new(Mc68kVariant::M68040);
    let mut handles = vec![];
    for _ in 0..4 {
        let v = Arc::clone(&v);
        handles.push(thread::spawn(move || {
            let mut acc = 0u64;
            for _ in 0..100 {
                if v.has_fpu() { acc += 1; }
                if v.is_32bit() { acc += 1; }
                acc += v.address_space_bytes();
            }
            acc
        }));
    }
    let mut total = 0u64;
    for h in handles {
        total = total.wrapping_add(h.join().unwrap());
    }
    assert!(total > 0);
}

// ── Size send/sync ──────────────────────────────────────────────────────────

#[test]
fn size_thread_stress() {
    use std::sync::Arc;
    use std::thread;
    let s = Arc::new(Size::Long);
    let mut handles = vec![];
    for _ in 0..4 {
        let s = Arc::clone(&s);
        handles.push(thread::spawn(move || {
            let mut acc = 0usize;
            for _ in 0..100 {
                acc += s.bytes();
                acc += s.suffix().len();
            }
            acc
        }));
    }
    let mut sum = 0usize;
    for h in handles {
        sum += h.join().unwrap();
    }
    assert_eq!(sum, 4 * 100 * (4 + 2));
}

// ── State machine: PatchResult ─────────────────────────────────────────────

#[test]
fn nop_sled_boundary_sizes() {
    for n in 0usize..=10 {
        let mut buf = vec![0u8; n];
        let r = nop_sled(&mut buf);
        match n {
            0 | 1 => assert_eq!(r, PatchResult::TooShort),
            x if x % 2 == 1 => assert_eq!(r, PatchResult::OddCount),
            _ => {
                assert_eq!(r, PatchResult::Ok);
                for chunk in buf.chunks(2) {
                    assert_eq!(chunk, &[0x4E, 0x71]);
                }
            }
        }
    }
}

// ── branch_displacement integer overflow ───────────────────────────────────

#[test]
fn branch_displacement_at_u64_extremes() {
    let _ = branch_displacement(u64::MAX, 0, false);
    let _ = branch_displacement(0, u64::MAX, true);
    let _ = branch_displacement(u64::MAX - 1, u64::MAX, false);
}

// ── Pattern matching ───────────────────────────────────────────────────────

#[test]
fn pattern_known_patterns_unique_names() {
    let mut names: Vec<&str> = KNOWN_PATTERNS.iter().map(|p| p.name).collect();
    names.sort_unstable();
    let n = names.len();
    names.dedup();
    assert_eq!(names.len(), n);
}

// ── Many fuzz iterations on combined helpers ────────────────────────────────

#[test]
fn combined_helpers_fuzz() {
    let mut g = lcg();
    for _ in 0..100 {
        let w = (g() & 0xFFFF) as u16;
        let _ = lookup_opcode(w);
        let _ = trap_vector(w);
        let _ = decode_muldiv_info(w);
        let _ = decode_shift_count(w);
        let _ = moveq_value(w);
        let _ = addq_value(w);
        let _ = count_movem_regs(w);
        let _ = movem_reg_names(w);
        let _ = decode_register_mask(w, true);
        let _ = decode_register_mask(w, false);
    }
}
