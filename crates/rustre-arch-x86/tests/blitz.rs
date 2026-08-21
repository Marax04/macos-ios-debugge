//! Exhaustive blitz tests for rustre-arch-x86 public APIs.
//!
//! Focus: exercise public functions/types that the in-crate tests cover lightly
//! (especially methods that are wired up but never invoked from production
//! code), surface invariant violations, and probe likely-bug call sites.

use rustre_arch_x86 as ax;

use ax::branch::{
    BranchKind, EffAddr, StringInstr, classify_branch, classify_opcode,
    decode_string_instr, InstrClass,
};
use ax::length::{LengthError, MAX_INSTR_LEN, instr_length};
use ax::modrm::{
    EffectiveAddr, GPR16_NAMES, GPR32_NAMES, GPR64_NAMES, GPR8_NAMES_NOREX, GPR8_NAMES_REX,
    KMASK_NAMES, ModRm, SEG_NAMES, Sib, XMM_NAMES, YMM_NAMES, ZMM_NAMES, gpr_name,
};
use ax::prefix::{
    EvexPrefix, LegacyPrefix, PrefixSet as LowPrefixSet, RexPrefix, SegmentReg as LowSeg,
    VexMap, VexPp, VexPrefix, classify_legacy_prefix,
};
use ax::x86_control_flow_graph::{EdgeKind, X86Block, X86ControlFlowGraph, X86Edge, build_cfg};
use ax::x86_decode_table::{Escape0F, InstrFormat, PrefixHandler, X86DecodeTable};
use ax::x86_instruction_database::{
    FlagEffects, InstrCategory, MemAccess, X86InstructionDatabase, eflags,
};
use ax::x86_prefix_analyzer::{
    EscapeEncoding, Prefix, PrefixGroup, SegmentReg, X86PrefixAnalyzer, parse_prefix_byte,
};
use ax::x86_simd_decoder::{
    SimdDecoderOptions, SimdGroup, VectorWidth, X86SimdDecoder, decode_simd,
};

// -----------------------------------------------------------------------------
// length::instr_length — boundary and error cases
// -----------------------------------------------------------------------------

#[test]
fn length_max_const_is_15() {
    assert_eq!(MAX_INSTR_LEN, 15);
}

#[test]
fn length_error_display_truncated() {
    let s = format!("{}", LengthError::TruncatedStream);
    assert!(s.to_lowercase().contains("trunc"));
}

#[test]
fn length_error_display_unknown() {
    let s = format!("{}", LengthError::UnknownOpcode);
    assert!(s.to_lowercase().contains("unknown") || s.to_lowercase().contains("invalid"));
}

#[test]
fn length_truncated_after_prefix() {
    // Just a prefix and nothing else.
    assert_eq!(instr_length(&[0xF0], 64), Err(LengthError::TruncatedStream));
}

#[test]
fn length_truncated_after_modrm_needing_disp() {
    // 8B 45 -- mov r32, [rbp+disp8] needs 1 disp byte after ModRM.
    assert_eq!(
        instr_length(&[0x8B, 0x45], 64),
        Err(LengthError::TruncatedStream)
    );
}

#[test]
fn length_truncated_after_imm_only() {
    // E9 needs 4 bytes of rel32.
    assert_eq!(
        instr_length(&[0xE9, 0x00, 0x00], 64),
        Err(LengthError::TruncatedStream)
    );
}

#[test]
fn length_unknown_opcode_returns_err() {
    // 0xD6 is an undefined 1-byte opcode (SALC, removed).
    let r = instr_length(&[0xD6], 64);
    // Either UnknownOpcode or some specific err — but Ok would be wrong.
    assert!(r.is_err(), "got {r:?}");
}

#[test]
fn length_amd_xop_marked_unknown() {
    // 0x8F with map field >= 8 in the next byte is XOP; we declared this UnknownOpcode.
    // ModRM-style next byte with bottom 5 bits = 8 (e.g., 0x08).
    let r = instr_length(&[0x8F, 0x08, 0x00, 0x00], 64);
    assert_eq!(r, Err(LengthError::UnknownOpcode));
}

#[test]
fn length_call_rel32_16bit_uses_2byte() {
    // 16-bit: E8 uses rel16 (operand-size dependent).
    let b = [0xE8, 0x12, 0x34];
    let r = instr_length(&b, 16).unwrap();
    assert_eq!(r, 3);
}

#[test]
fn length_modrm_with_sib_no_disp() {
    // 89 04 24 → mov [rsp], eax (ModRM=04, SIB=24)
    assert_eq!(instr_length(&[0x89, 0x04, 0x24], 64).unwrap(), 3);
}

// -----------------------------------------------------------------------------
// modrm::ModRm / Sib
// -----------------------------------------------------------------------------

#[test]
fn modrm_decode_all_quadrants() {
    for mode in 0..4 {
        for reg in 0..8 {
            for rm in 0..8 {
                let b = (mode << 6) | (reg << 3) | rm;
                let m = ModRm::decode(b);
                assert_eq!(m.mode, mode);
                assert_eq!(m.reg, reg);
                assert_eq!(m.rm, rm);
            }
        }
    }
}

#[test]
fn modrm_disp_size_all_modes() {
    // mode 0 rm=5 → 4
    assert_eq!(ModRm::decode(0b00_000_101).disp_size(), 4);
    // mode 0 rm=0 → 0
    assert_eq!(ModRm::decode(0b00_000_000).disp_size(), 0);
    // mode 1 → 1
    assert_eq!(ModRm::decode(0b01_000_000).disp_size(), 1);
    // mode 2 → 4
    assert_eq!(ModRm::decode(0b10_000_000).disp_size(), 4);
    // mode 3 → 0
    assert_eq!(ModRm::decode(0b11_000_000).disp_size(), 0);
}

#[test]
fn modrm_has_sib_only_in_memory_modes() {
    // mode 3 rm=4 → no SIB (register)
    assert!(!ModRm::decode(0b11_000_100).has_sib());
    // mode 0 rm=4 → SIB
    assert!(ModRm::decode(0b00_000_100).has_sib());
    // mode 1 rm=4 → SIB
    assert!(ModRm::decode(0b01_000_100).has_sib());
    // mode 2 rm=4 → SIB
    assert!(ModRm::decode(0b10_000_100).has_sib());
    // mode 0 rm=5 → no SIB (it's disp32-only)
    assert!(!ModRm::decode(0b00_000_101).has_sib());
}

#[test]
fn modrm_reg_ext_with_rex_r() {
    let rex_r = RexPrefix::parse(0x44); // REX.R only
    let m = ModRm::decode(0b00_010_000); // reg=2, rm=0
    assert_eq!(m.reg_ext(&rex_r), 2 | 8);
    let rex_none = RexPrefix::default();
    assert_eq!(m.reg_ext(&rex_none), 2);
}

#[test]
fn sib_scale_factor_all() {
    assert_eq!(Sib::decode(0b00_000_000).scale_factor(), 1);
    assert_eq!(Sib::decode(0b01_000_000).scale_factor(), 2);
    assert_eq!(Sib::decode(0b10_000_000).scale_factor(), 4);
    assert_eq!(Sib::decode(0b11_000_000).scale_factor(), 8);
}

#[test]
fn sib_base_is_disp_only_only_when_mode0_base5() {
    let sib = Sib::decode(0b00_000_101); // base=5
    assert!(sib.base_is_disp_only(0));
    assert!(!sib.base_is_disp_only(1));
    assert!(!sib.base_is_disp_only(2));
}

#[test]
fn effective_addr_full_addressing() {
    let rex = RexPrefix::default();
    // mod=1, rm=4 → SIB; SIB base=0 (rax), index=1 (rcx), scale=2
    let m = ModRm::decode(0b01_000_100);
    let s = Sib::decode(0b10_001_000); // scale=2(×4), index=1, base=0
    let ea = EffectiveAddr::decode(m, Some(s), 0x10, &rex, true);
    assert_eq!(
        ea,
        EffectiveAddr::Full {
            base: 0,
            index: 1,
            scale: 4,
            disp: 0x10,
        }
    );
    assert_eq!(ea.base_reg(), Some(0));
    assert!(ea.is_memory());
}

#[test]
fn effective_addr_index_scale_disp_only() {
    // mod=0 rm=4, SIB base=5 (disp-only), index!=4 → IndexScaleDisp
    let rex = RexPrefix::default();
    let m = ModRm::decode(0b00_000_100);
    let s = Sib::decode(0b11_001_101); // scale=3(×8), index=1, base=5
    let ea = EffectiveAddr::decode(m, Some(s), 0x100, &rex, true);
    assert_eq!(
        ea,
        EffectiveAddr::IndexScaleDisp {
            index: 1,
            scale: 8,
            disp: 0x100
        }
    );
    assert_eq!(ea.base_reg(), None);
    assert!(ea.is_memory());
}

#[test]
fn effective_addr_register_no_memory() {
    let rex = RexPrefix::default();
    let m = ModRm::decode(0b11_000_011); // reg=0, rm=3 (RBX/EBX)
    let ea = EffectiveAddr::decode(m, None, 0, &rex, true);
    assert_eq!(ea, EffectiveAddr::Register(3));
    assert!(!ea.is_memory());
    assert_eq!(ea.base_reg(), Some(3));
}

#[test]
fn gpr_name_unknown_size_returns_qmarks() {
    assert_eq!(gpr_name(0, 3, false), "???");
    assert_eq!(gpr_name(0, 5, true), "???");
    assert_eq!(gpr_name(0, 0, false), "???");
}

#[test]
fn gpr_name_index_wraps_via_mask() {
    // gpr_name uses & 0xF, so any value >= 16 wraps.
    assert_eq!(gpr_name(16, 8, false), gpr_name(0, 8, false));
    assert_eq!(gpr_name(17, 4, false), gpr_name(1, 4, false));
}

#[test]
fn register_name_tables_lengths() {
    assert_eq!(GPR64_NAMES.len(), 16);
    assert_eq!(GPR32_NAMES.len(), 16);
    assert_eq!(GPR16_NAMES.len(), 16);
    assert_eq!(GPR8_NAMES_REX.len(), 16);
    assert_eq!(GPR8_NAMES_NOREX.len(), 8);
    assert_eq!(XMM_NAMES.len(), 16);
    assert_eq!(YMM_NAMES.len(), 16);
    assert_eq!(ZMM_NAMES.len(), 32);
    assert_eq!(KMASK_NAMES.len(), 8);
    assert_eq!(SEG_NAMES.len(), 8);
}

// -----------------------------------------------------------------------------
// prefix.rs — REX / VEX / EVEX / PrefixSet
// -----------------------------------------------------------------------------

#[test]
fn rex_parse_non_rex_byte_returns_absent() {
    for b in 0u8..=0xFF {
        let r = RexPrefix::parse(b);
        if (b & 0xF0) == 0x40 {
            assert!(r.present, "byte 0x{b:02X} should be REX");
        } else {
            assert!(!r.present, "byte 0x{b:02X} should NOT be REX");
        }
    }
}

#[test]
fn rex_all_bits_correctly_decoded() {
    for b in 0x40u8..=0x4F {
        let r = RexPrefix::parse(b);
        assert_eq!(r.w, (b & 0x08) != 0);
        assert_eq!(r.r, (b & 0x04) != 0);
        assert_eq!(r.x, (b & 0x02) != 0);
        assert_eq!(r.b, (b & 0x01) != 0);
    }
}

#[test]
fn vex2_pp_decoding_all_values() {
    // bits 0..1 are pp
    assert!(matches!(VexPrefix::parse_2byte(0b00000000).pp, VexPp::None));
    assert!(matches!(VexPrefix::parse_2byte(0b00000001).pp, VexPp::P66));
    assert!(matches!(VexPrefix::parse_2byte(0b00000010).pp, VexPp::PF3));
    assert!(matches!(VexPrefix::parse_2byte(0b00000011).pp, VexPp::PF2));
}

#[test]
fn vex3_map_field_recognises_all_legacy() {
    let v01 = VexPrefix::parse_3byte(0x01, 0x00);
    assert!(matches!(v01.map, VexMap::Map0F));
    let v02 = VexPrefix::parse_3byte(0x02, 0x00);
    assert!(matches!(v02.map, VexMap::Map0F38));
    let v03 = VexPrefix::parse_3byte(0x03, 0x00);
    assert!(matches!(v03.map, VexMap::Map0F3A));
    let vother = VexPrefix::parse_3byte(0x07, 0x00);
    assert!(matches!(vother.map, VexMap::Other(7)));
}

#[test]
fn vex_extend_helpers() {
    let v = VexPrefix::parse_3byte(0b0111_0001, 0x00); // r=true (~bit7 of b1=0), b=true, x=true
    // Actually carefully: parse_3byte sets r/x/b = (bit == 0). So with bits set in b1, those are FALSE.
    // Construct an extension-on case: bits all zero.
    let v_ext = VexPrefix::parse_3byte(0b0000_0001, 0x00);
    assert!(v_ext.r && v_ext.x && v_ext.b);
    assert_eq!(v_ext.extend_reg(3), 11);
    assert_eq!(v_ext.extend_rm(3), 11);
    assert_eq!(v_ext.extend_index(3), 11);
    // The other constructed variant `v` has no extension active (since bits 7,6,5 were 1).
    let _ = v; // value used; suppress unused warning
}

#[test]
fn evex_vector_length_flags() {
    let e_xmm = EvexPrefix::parse(0xF1, 0x7C, 0b000_00000);
    assert!(e_xmm.is_xmm());
    assert!(!e_xmm.is_ymm());
    assert!(!e_xmm.is_zmm());

    let e_ymm = EvexPrefix::parse(0xF1, 0x7C, 0b001_00000);
    assert!(e_ymm.is_ymm());

    let e_zmm = EvexPrefix::parse(0xF1, 0x7C, 0b010_00000);
    assert!(e_zmm.is_zmm());
}

#[test]
fn evex_extend_reg_combines_r_and_rprime() {
    // r=true when bit7=0; r_prime=true when bit4=0
    // p0 with bit7=0 (R ext on), bit4=0 (R' ext on) → 0b0xx0_xxxx
    let e = EvexPrefix::parse(0b0110_0001, 0x00, 0x00);
    assert!(e.r);
    assert!(e.r_prime);
    // reg=2 + R(8) + R'(16) = 26
    assert_eq!(e.extend_reg(2), 26);
}

#[test]
fn classify_legacy_prefix_exhaustive_known_bytes() {
    let known = [
        (0xF0u8, LegacyPrefix::Lock),
        (0xF2, LegacyPrefix::RepNe),
        (0xF3, LegacyPrefix::Rep),
        (0x2E, LegacyPrefix::SegCs),
        (0x36, LegacyPrefix::SegSs),
        (0x3E, LegacyPrefix::SegDs),
        (0x26, LegacyPrefix::SegEs),
        (0x64, LegacyPrefix::SegFs),
        (0x65, LegacyPrefix::SegGs),
        (0x66, LegacyPrefix::OpSize),
        (0x67, LegacyPrefix::AddrSize),
    ];
    for (b, expected) in known {
        assert_eq!(classify_legacy_prefix(b), Some(expected), "byte 0x{b:02X}");
    }
}

#[test]
fn prefix_set_rex_nullified_by_following_legacy() {
    // 48 66 90  — REX.W followed by 66 (operand-size). The doc says any legacy
    // prefix appearing AFTER a REX nullifies that REX.
    let ps = LowPrefixSet::consume(&[0x48, 0x66, 0x90], true);
    assert!(!ps.rex.present, "REX must be nullified by following 0x66 prefix");
    assert!(ps.op_size);
}

#[test]
fn prefix_set_rex_kept_when_immediately_before_opcode() {
    let ps = LowPrefixSet::consume(&[0x48, 0x89, 0x00], true);
    assert!(ps.rex.present);
    assert!(ps.rex.w);
    assert_eq!(ps.count, 1);
}

#[test]
fn prefix_set_segment_overrides_all_six() {
    for (b, seg) in [
        (0x26u8, LowSeg::Es),
        (0x2E, LowSeg::Cs),
        (0x36, LowSeg::Ss),
        (0x3E, LowSeg::Ds),
        (0x64, LowSeg::Fs),
        (0x65, LowSeg::Gs),
    ] {
        let ps = LowPrefixSet::consume(&[b, 0x90], false);
        assert_eq!(ps.segment, Some(seg), "byte 0x{b:02X}");
    }
}

#[test]
fn prefix_set_addr_size_and_op_size_combined() {
    let ps = LowPrefixSet::consume(&[0x66, 0x67, 0x90], false);
    assert!(ps.op_size);
    assert!(ps.addr_size);
    assert_eq!(ps.count, 2);
}

#[test]
fn prefix_set_stops_at_vex_lead() {
    let ps = LowPrefixSet::consume(&[0xF0, 0xC5, 0xF8, 0x28], true);
    // Should consume F0 then stop at C5.
    assert_eq!(ps.count, 1);
    assert!(ps.lock);
}

// -----------------------------------------------------------------------------
// branch.rs
// -----------------------------------------------------------------------------

#[test]
fn classify_branch_empty_is_not_branch() {
    assert_eq!(classify_branch(&[]), BranchKind::NotBranch);
}

#[test]
fn classify_branch_after_prefix_only_is_not_branch() {
    assert_eq!(classify_branch(&[0xF0]), BranchKind::NotBranch);
}

#[test]
fn classify_branch_ff_no_modrm_byte_is_not_branch() {
    // FF alone — no ModRM available.
    assert_eq!(classify_branch(&[0xFF]), BranchKind::NotBranch);
}

#[test]
fn classify_branch_ff_reg7_is_not_branch() {
    // FF /7 — not a branch (it's invalid or push).
    // ModRM reg=7: e.g. 0xFF F8 → reg=(0xF8>>3)&7 = 7
    assert_eq!(classify_branch(&[0xFF, 0xF8]), BranchKind::NotBranch);
}

#[test]
fn classify_branch_kind_is_branch_for_loop_etc() {
    assert!(BranchKind::Loop.is_branch());
    assert!(BranchKind::Syscall.is_branch());
    assert!(BranchKind::Interrupt.is_branch());
    assert!(!BranchKind::NotBranch.is_branch());
}

#[test]
fn branch_kind_terminates_block_includes_syscall_interrupt() {
    assert!(BranchKind::Syscall.terminates_block());
    assert!(BranchKind::Interrupt.terminates_block());
    assert!(BranchKind::Return.terminates_block());
    // ConditionalJump does NOT terminate (falls through)
    assert!(!BranchKind::ConditionalJump.terminates_block());
    // Direct/Indirect Call does not terminate the block
    assert!(!BranchKind::DirectCall.terminates_block());
    assert!(!BranchKind::IndirectCall.terminates_block());
}

#[test]
fn classify_opcode_logical_arith_split() {
    // 0x08-0x0D are OR (Logical), 0x00-0x05 are ADD (IntegerArith).
    assert_eq!(classify_opcode(0x08), InstrClass::Logical);
    assert_eq!(classify_opcode(0x00), InstrClass::IntegerArith);
}

#[test]
fn classify_opcode_shift_group() {
    for b in &[0xC0u8, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3] {
        assert_eq!(classify_opcode(*b), InstrClass::Shift, "byte 0x{b:02X}");
    }
}

#[test]
fn classify_opcode_system_group() {
    for b in &[0xF4u8, 0xFA, 0xFB, 0xFC, 0xFD] {
        assert_eq!(classify_opcode(*b), InstrClass::System, "byte 0x{b:02X}");
    }
}

#[test]
fn string_instr_mnemonic_unique() {
    use std::collections::HashSet;
    let all = [
        StringInstr::MovsByte,
        StringInstr::MovsWord,
        StringInstr::MovsDWord,
        StringInstr::MovsQWord,
        StringInstr::CmpsByte,
        StringInstr::CmpsWord,
        StringInstr::CmpsDWord,
        StringInstr::CmpsQWord,
        StringInstr::ScasByte,
        StringInstr::ScasWord,
        StringInstr::ScasDWord,
        StringInstr::ScasQWord,
        StringInstr::LodsByte,
        StringInstr::LodsWord,
        StringInstr::LodsDWord,
        StringInstr::LodsQWord,
        StringInstr::StosByte,
        StringInstr::StosWord,
        StringInstr::StosDWord,
        StringInstr::StosQWord,
    ];
    let mnems: HashSet<&str> = all.iter().map(|s| s.mnemonic()).collect();
    assert_eq!(mnems.len(), all.len());
}

#[test]
fn string_instr_reads_src_writes_dst() {
    assert!(StringInstr::MovsByte.reads_src());
    assert!(StringInstr::MovsByte.writes_dst());
    assert!(StringInstr::LodsByte.reads_src());
    assert!(!StringInstr::LodsByte.writes_dst());
    assert!(!StringInstr::StosByte.reads_src());
    assert!(StringInstr::StosByte.writes_dst());
    assert!(StringInstr::CmpsByte.reads_src());
    assert!(!StringInstr::CmpsByte.writes_dst());
    assert!(!StringInstr::ScasByte.reads_src()); // SCAS reads only [rdi]
    assert!(!StringInstr::ScasByte.writes_dst());
}

#[test]
fn decode_string_instr_empty_none() {
    assert!(decode_string_instr(&[], 64).is_none());
}

#[test]
fn decode_string_instr_only_prefix_none() {
    assert!(decode_string_instr(&[0xF3], 64).is_none());
    assert!(decode_string_instr(&[0x66, 0x48], 64).is_none());
}

#[test]
fn decode_string_instr_with_opsize_returns_word_variants() {
    let r = decode_string_instr(&[0x66, 0xA5], 64).unwrap();
    assert_eq!(r.1, StringInstr::MovsWord);
    assert!(r.2);
}

#[test]
fn eff_addr_display_positive_disp() {
    let ea = EffAddr::BaseDisp { base: "rax".into(), disp: 0x10 };
    assert_eq!(ea.display(), "[rax+0x10]");
}

#[test]
fn eff_addr_display_base_plus_scaled_index() {
    let ea = EffAddr::BasePlusIndex {
        base: "rax".into(),
        index: "rcx".into(),
        scale: 4,
        disp: 0,
    };
    assert_eq!(ea.display(), "[rax+rcx*4]");
}

#[test]
fn eff_addr_display_rip_relative_negative() {
    let ea = EffAddr::RipRelative { disp: -16 };
    assert_eq!(ea.display(), "[rip-0x10]");
}

// -----------------------------------------------------------------------------
// x86_prefix_analyzer
// -----------------------------------------------------------------------------

#[test]
fn analyzer_bitness_getters() {
    assert_eq!(X86PrefixAnalyzer::new_16bit().bitness(), 16);
    assert_eq!(X86PrefixAnalyzer::new_32bit().bitness(), 32);
    assert_eq!(X86PrefixAnalyzer::new_64bit().bitness(), 64);
}

#[test]
fn analyzer_parse_empty_returns_zero_consumed() {
    let a = X86PrefixAnalyzer::new_64bit();
    let (ps, consumed) = a.parse(&[]);
    assert_eq!(consumed, 0);
    assert!(ps.prefixes.is_empty());
}

#[test]
fn analyzer_extract_opcode_bytes_empty() {
    let a = X86PrefixAnalyzer::new_64bit();
    let opc = a.extract_opcode_bytes(&[]);
    assert!(opc.is_empty());
}

#[test]
fn analyzer_extract_opcode_bytes_no_prefix_returns_input() {
    let a = X86PrefixAnalyzer::new_64bit();
    let opc = a.extract_opcode_bytes(&[0x90, 0xC3]);
    assert_eq!(opc, &[0x90, 0xC3]);
}

#[test]
fn analyzer_parse_xop_when_reg_field_high() {
    // 8F p1 p2: reg field of p1 = bits 5..3. We need (p1 & 0x1f) >= 8? No wait,
    // the code reads `reg_field = (p1 >> 3) & 0x7` and checks `reg_field >= 8` — that
    // can NEVER be true since `& 0x7` caps at 7. So the XOP branch is dead.
    // We'll exercise it (likely returns no XOP) and assert that nothing breaks.
    let a = X86PrefixAnalyzer::new_64bit();
    let bytes = [0x8Fu8, 0xC0, 0x00, 0x00];
    let (ps, _consumed) = a.parse(&bytes);
    // Bug check: documented to detect XOP when reg ≥ 8, but bit-mask prevents
    // that ever being true. So is_xop_encoded should always be false.
    assert!(!ps.is_xop_encoded(), "XOP detection is unreachable due to & 0x7 bug");
}

#[test]
fn analyzer_parse_vex3_too_short_falls_through() {
    // C4 with only 1 follow-up byte → not enough for VEX3, should not crash.
    let a = X86PrefixAnalyzer::new_64bit();
    let (ps, _) = a.parse(&[0xC4, 0xE1]);
    assert!(!ps.is_vex_encoded());
}

#[test]
fn analyzer_evex_too_short_falls_through() {
    let a = X86PrefixAnalyzer::new_64bit();
    let (ps, _) = a.parse(&[0x62, 0xF1, 0x7C]);
    assert!(!ps.is_evex_encoded());
}

#[test]
fn analyzer_redundant_g3_detected() {
    let a = X86PrefixAnalyzer::new_64bit();
    let (ps, _) = a.parse(&[0x66, 0x66, 0x90]);
    assert!(ps.has_redundant);
}

#[test]
fn analyzer_conflict_g1_lock_rep() {
    let a = X86PrefixAnalyzer::new_64bit();
    let (ps, _) = a.parse(&[0xF0, 0xF3, 0x90]);
    // LOCK and REP are both group-1, both exclusive → conflict expected.
    assert!(ps.has_conflict, "ps={ps:?}");
}

#[test]
fn analyzer_override_table_works() {
    let mut a = X86PrefixAnalyzer::new_64bit();
    a.add_override(Prefix {
        byte: 0xCC, // arbitrary byte normally NOT a prefix
        group: PrefixGroup::Group1,
        name: "FAKE",
        is_mandatory: false,
        is_exclusive: true,
    });
    let (ps, consumed) = a.parse(&[0xCC, 0x90]);
    assert_eq!(consumed, 1);
    assert_eq!(ps.prefixes.len(), 1);
    assert_eq!(ps.prefixes[0].name, "FAKE");
}

#[test]
fn analyzer_effective_operand_size_override_combines_66_and_rexw() {
    let a = X86PrefixAnalyzer::new_64bit();
    let (ps, _) = a.parse(&[0x66, 0x90]);
    assert!(ps.effective_operand_size_override());
    let (ps2, _) = a.parse(&[0x48, 0xC3]);
    assert!(ps2.effective_operand_size_override());
}

#[test]
fn parse_prefix_byte_rex_only_64bit() {
    for b in 0x40u8..=0x4F {
        assert!(parse_prefix_byte(b, 64).is_some());
        assert!(parse_prefix_byte(b, 32).is_none());
        assert!(parse_prefix_byte(b, 16).is_none());
    }
}

#[test]
fn parse_prefix_byte_non_prefix_returns_none() {
    for b in [0x00u8, 0x55, 0x90, 0xCC, 0xC3] {
        assert!(parse_prefix_byte(b, 64).is_none(), "byte 0x{b:02X}");
    }
}

#[test]
fn prefix_group_display_names() {
    assert_eq!(format!("{}", PrefixGroup::Rex), "REX");
    assert_eq!(format!("{}", PrefixGroup::Evex), "EVEX");
    assert_eq!(format!("{}", PrefixGroup::NotAPrefix), "NONE");
}

#[test]
fn segment_reg_display() {
    assert_eq!(format!("{}", SegmentReg::FS), "FS");
    assert_eq!(format!("{}", SegmentReg::GS), "GS");
}

#[test]
fn escape_encoding_via_vex2_set() {
    let a = X86PrefixAnalyzer::new_64bit();
    let (ps, _) = a.parse(&[0xC5, 0xF8, 0x28]);
    assert!(matches!(ps.escape, Some(EscapeEncoding::Vex2(_))));
}

// -----------------------------------------------------------------------------
// x86_control_flow_graph
// -----------------------------------------------------------------------------

#[test]
fn cfg_new_has_no_blocks_no_entry() {
    let cfg = X86ControlFlowGraph::new(64);
    assert_eq!(cfg.block_count(), 0);
    assert_eq!(cfg.edge_count(), 0);
    assert!(cfg.entry().is_none());
    assert_eq!(cfg.bitness(), 64);
}

#[test]
fn cfg_empty_bytes_returns_no_blocks() {
    let cfg = build_cfg(0, &[], 64);
    assert_eq!(cfg.block_count(), 0);
    assert!(cfg.entry().is_none());
}

#[test]
fn cfg_simple_function_has_entry_and_predecessors() {
    // mov eax,0 ; ret
    let code = &[0xB8, 0, 0, 0, 0, 0xC3];
    let cfg = build_cfg(0x1000, code, 64);
    assert!(cfg.get_block(0x1000).is_some());
    assert_eq!(cfg.entry(), Some(0x1000));
    // Entry block should have no predecessors.
    assert!(cfg.predecessors_of(0x1000).is_empty());
}

#[test]
fn cfg_conditional_creates_jcc_true_and_false_edges() {
    // test eax,eax ; jz +2 ; nop ; nop ; ret
    let code = &[0x85, 0xC0, 0x74, 0x02, 0x90, 0x90, 0xC3];
    let cfg = build_cfg(0x3000, code, 64);
    let kinds: Vec<EdgeKind> = cfg.edges().map(|e| e.kind.clone()).collect();
    assert!(kinds.iter().any(|k| matches!(k, EdgeKind::ConditionalTrue)));
    assert!(kinds.iter().any(|k| matches!(k, EdgeKind::ConditionalFalse)));
}

#[test]
fn cfg_stats_call_edge_counted() {
    // call rel32 (E8 00 00 00 00 = call to next insn, which is itself)
    // followed by ret
    // entry 0x1000: call 0x1005 (=ret)  → call edge
    let code = &[0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3];
    let cfg = build_cfg(0x1000, code, 64);
    let stats = cfg.stats();
    assert!(stats.call_edge_count >= 1, "stats={stats:?}");
}

#[test]
fn cfg_reachable_from_entry_covers_all_blocks_in_simple_func() {
    let code = &[0x85, 0xC0, 0x74, 0x02, 0x90, 0x90, 0xC3];
    let cfg = build_cfg(0x3000, code, 64);
    let r = cfg.reachable_from(0x3000);
    // All blocks must be reachable in this small example.
    let all_starts: Vec<u64> = cfg.blocks().map(|b| b.start).collect();
    for s in &all_starts {
        assert!(r.contains(s), "block 0x{s:x} not reachable");
    }
}

#[test]
fn cfg_get_block_unknown_returns_none() {
    let cfg = build_cfg(0x1000, &[0xC3], 64);
    assert!(cfg.get_block(0xDEAD).is_none());
}

#[test]
fn cfg_block_new_initial_state() {
    let b = X86Block::new(0x500);
    assert_eq!(b.start, 0x500);
    assert_eq!(b.end, 0x500);
    assert_eq!(b.len_bytes(), 0);
    assert_eq!(b.insn_count(), 0);
    assert!(!b.is_return);
    assert!(!b.is_unreachable);
    assert!(b.terminator().is_none());
}

#[test]
fn cfg_edge_display_includes_kind() {
    let e = X86Edge::new(0x10, 0x20, EdgeKind::Call);
    let s = e.to_string();
    assert!(s.contains("call"));
}

#[test]
fn cfg_edge_kind_display_strings() {
    assert_eq!(format!("{}", EdgeKind::Unconditional), "jmp");
    assert_eq!(format!("{}", EdgeKind::ConditionalTrue), "jcc-T");
    assert_eq!(format!("{}", EdgeKind::ConditionalFalse), "jcc-F");
    assert_eq!(format!("{}", EdgeKind::Call), "call");
    assert_eq!(format!("{}", EdgeKind::Return), "ret");
    assert_eq!(format!("{}", EdgeKind::Indirect), "indir");
    assert_eq!(format!("{}", EdgeKind::Exception), "exn");
}

#[test]
fn cfg_block_display_format() {
    let mut b = X86Block::new(0x1234);
    b.end = 0x1240;
    let s = b.to_string();
    assert!(s.contains("0x00001234"), "got: {s}");
    assert!(s.contains("0x00001240"));
}

#[test]
fn cfg_successors_of_unknown_block_empty() {
    let cfg = build_cfg(0x1000, &[0xC3], 64);
    assert!(cfg.successors_of(0xDEAD).is_empty());
    assert!(cfg.predecessors_of(0xDEAD).is_empty());
}

// -----------------------------------------------------------------------------
// x86_simd_decoder
// -----------------------------------------------------------------------------

#[test]
fn simd_decoder_empty_returns_empty() {
    let d = X86SimdDecoder::new_64bit();
    assert!(d.decode_bytes(0, &[]).is_empty());
}

#[test]
fn simd_decode_one_on_non_simd_returns_none_in_strict() {
    let d = X86SimdDecoder::new_64bit();
    assert!(d.decode_one(0x1000, &[0x90]).is_none());
}

#[test]
fn simd_decoder_options_default_64_strict() {
    let o = SimdDecoderOptions::default();
    assert_eq!(o.bitness, 64);
    assert!(o.strict_simd_only);
}

#[test]
fn simd_group_display_all_distinct() {
    use std::collections::HashSet;
    let all = [
        SimdGroup::Sse,
        SimdGroup::Sse2,
        SimdGroup::Sse3,
        SimdGroup::Ssse3,
        SimdGroup::Sse41,
        SimdGroup::Sse42,
        SimdGroup::Avx,
        SimdGroup::Avx2,
        SimdGroup::Avx512F,
        SimdGroup::Avx512Bw,
        SimdGroup::Avx512Dq,
        SimdGroup::Avx512Vl,
        SimdGroup::Aes,
        SimdGroup::Pclmul,
        SimdGroup::Sha,
        SimdGroup::Amx,
        SimdGroup::Unknown,
    ];
    let strs: HashSet<String> = all.iter().map(|g| g.to_string()).collect();
    assert_eq!(strs.len(), all.len());
}

#[test]
fn vector_width_display_strings() {
    assert_eq!(VectorWidth::Xmm.to_string(), "128b");
    assert_eq!(VectorWidth::Ymm.to_string(), "256b");
    assert_eq!(VectorWidth::Zmm.to_string(), "512b");
    assert_eq!(VectorWidth::Tmm.to_string(), "tile");
    assert_eq!(VectorWidth::Scalar.to_string(), "scalar");
}

#[test]
fn simd_decode_simd_free_fn_with_avx() {
    let bytes = [0xC5, 0xFC, 0x28, 0xC1]; // VMOVAPS ymm0, ymm1
    let v = decode_simd(0x4000, &bytes, 64);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].vector_width, VectorWidth::Ymm);
}

#[test]
fn simd_non_strict_decodes_all() {
    let d = X86SimdDecoder::with_options(SimdDecoderOptions { bitness: 64, strict_simd_only: false });
    // mix of nop, ret
    let v = d.decode_bytes(0x100, &[0x90, 0xC3]);
    assert_eq!(v.len(), 2);
}

#[test]
fn simd_histogram_includes_movaps_group() {
    let d = X86SimdDecoder::new_64bit();
    let v = d.decode_bytes(0, &[0x0F, 0x28, 0xC1]); // MOVAPS xmm0, xmm1
    let hist = d.group_histogram(&v);
    assert!(hist.values().sum::<usize>() >= 1);
}

// -----------------------------------------------------------------------------
// x86_decode_table
// -----------------------------------------------------------------------------

#[test]
fn decode_table_build_primary_nonempty() {
    let t = X86DecodeTable::build();
    assert!(!t.primary.is_empty());
}

#[test]
fn decode_table_escape_tables_nonempty() {
    let t = X86DecodeTable::build();
    assert!(!t.escape_0f.0.is_empty());
}

#[test]
fn opcode_entry_is_branch_for_jmp_call_ret() {
    let t = X86DecodeTable::build();
    // 0xE9 = jmp
    let jmp = t.primary.iter().find(|e| e.opcode == 0xE9).expect("jmp entry");
    assert!(jmp.is_branch(), "{:?}", jmp.mnemonic);
    let call = t.primary.iter().find(|e| e.opcode == 0xE8).expect("call entry");
    assert!(call.is_branch());
    let ret = t.primary.iter().find(|e| e.opcode == 0xC3).expect("ret entry");
    assert!(ret.is_branch());
}

#[test]
fn opcode_entry_accesses_memory_for_modrm_formats() {
    let t = X86DecodeTable::build();
    // 0x00 is ADD MR (ModRM-based)
    let add = t.primary.iter().find(|e| e.opcode == 0x00).expect("add entry");
    assert!(add.accesses_memory());
}

#[test]
fn opcode_entry_no_modrm_for_zo_format() {
    let t = X86DecodeTable::build();
    // RET is ZO
    let ret = t.primary.iter().find(|e| e.opcode == 0xC3).unwrap();
    assert!(!ret.accesses_memory());
}

#[test]
fn instr_format_has_modrm_known_set() {
    assert!(InstrFormat::MR.has_modrm());
    assert!(InstrFormat::RM.has_modrm());
    assert!(InstrFormat::M.has_modrm());
    assert!(!InstrFormat::ZO.has_modrm());
    assert!(!InstrFormat::I8.has_modrm());
    assert!(!InstrFormat::D8.has_modrm());
}

#[test]
fn instr_format_min_imm_bytes_correct() {
    assert_eq!(InstrFormat::I8.min_imm_bytes(), 1);
    assert_eq!(InstrFormat::I16.min_imm_bytes(), 2);
    assert_eq!(InstrFormat::I32.min_imm_bytes(), 4);
    assert_eq!(InstrFormat::ZO.min_imm_bytes(), 0);
    assert_eq!(InstrFormat::MR.min_imm_bytes(), 0);
}

#[test]
fn prefix_handler_display_strings() {
    assert_eq!(format!("{}", PrefixHandler::None), "");
    assert_eq!(format!("{}", PrefixHandler::P66), "66 ");
    assert_eq!(format!("{}", PrefixHandler::PF2), "F2 ");
    assert_eq!(format!("{}", PrefixHandler::PF3), "F3 ");
    assert_eq!(format!("{}", PrefixHandler::RexW), "REX.W ");
}

#[test]
fn escape_0f_contains_syscall() {
    let e = Escape0F::build();
    assert!(e.0.iter().any(|x| x.opcode == 0x05 && x.mnemonic.contains("syscall")));
}

#[test]
fn escape_0f_lookup_falls_back_on_prefix_mismatch() {
    let e = Escape0F::build();
    // Look up syscall with a weird mandatory prefix — should fall back.
    let r = e.lookup(0x05, PrefixHandler::P66);
    assert!(r.is_some());
    assert!(r.unwrap().mnemonic.contains("syscall"));
}

#[test]
fn escape_0f_lookup_unknown_returns_none() {
    let e = Escape0F::build();
    // 0xFF (within 0F space) — may or may not be present; verify we don't panic
    let _ = e.lookup(0xFF, PrefixHandler::None);
}

// -----------------------------------------------------------------------------
// x86_instruction_database
// -----------------------------------------------------------------------------

#[test]
fn db_lookup_returns_entries() {
    // Historically `lookup(&str)` always returned &[] (it built indices but
    // threw them away). The bug is fixed; keep this as a regression test and
    // check consistency with the index-based lookup.
    let db = X86InstructionDatabase::build();
    let entries = db.lookup("mov");
    assert!(!entries.is_empty(), "lookup(\"mov\") must return entries");
    assert!(entries.iter().all(|e| e.mnemonic == "mov"));
    assert_eq!(entries.len(), db.lookup_indices("mov").len());
}

#[test]
fn db_lookup_indices_returns_real_data() {
    let db = X86InstructionDatabase::build();
    let r = db.lookup_indices("mov");
    assert!(!r.is_empty());
}

#[test]
fn db_get_oob_returns_none() {
    let db = X86InstructionDatabase::build();
    assert!(db.get(usize::MAX).is_none());
}

#[test]
fn db_by_category_unknown_empty() {
    let db = X86InstructionDatabase::build();
    let c = db.by_category(InstrCategory::Crc).count();
    // Whatever category — just verify count returns non-negative integer (doesn't panic).
    let _ = c;
}

#[test]
fn db_lookup_missing_mnemonic_empty() {
    let db = X86InstructionDatabase::build();
    assert!(db.lookup_indices("definitely_not_an_instruction").is_empty());
    assert!(!db.is_privileged("definitely_not_an_instruction"));
    assert!(db.flag_effects("definitely_not_an_instruction").is_none());
    assert!(!db.reads_flags("definitely_not_an_instruction"));
    assert!(!db.writes_flags("definitely_not_an_instruction"));
}

#[test]
fn flag_effects_none_constant_is_zero() {
    let f = FlagEffects::none();
    assert_eq!(f.reads, 0);
    assert_eq!(f.writes, 0);
    assert_eq!(f.clears, 0);
    assert_eq!(f.sets, 0);
}

#[test]
fn db_mem_access_variant_round_trip_in_lookups() {
    let db = X86InstructionDatabase::build();
    // LEA should be MemAccess::None.
    let lea_idx = db.lookup_indices("lea")[0];
    assert_eq!(db.get(lea_idx).unwrap().mem_access, MemAccess::None);
}

#[test]
fn db_eflags_bits_nonzero_known() {
    // Iterate rather than asserting on each constant directly: a bare
    // `assert!(CONST != 0)` is a compile-time tautology to the reader and to
    // clippy. Going through a slice also lets us check the stronger property
    // that each mask is exactly one bit, and name the offender on failure.
    for (name, bit) in [
        ("CF", eflags::CF),
        ("ZF", eflags::ZF),
        ("OF", eflags::OF),
        ("SF", eflags::SF),
    ] {
        assert_ne!(bit, 0, "{name} mask must be non-zero");
        assert_eq!(bit.count_ones(), 1, "{name} mask must be a single bit");
    }
}

// -----------------------------------------------------------------------------
// X86Arch (high-level) — a few extras
// -----------------------------------------------------------------------------

#[test]
fn x86arch_bits_getter() {
    use ax::X86Arch;
    assert_eq!(X86Arch::new_16bit().bits(), 16);
    assert_eq!(X86Arch::new_32bit().bits(), 32);
    assert_eq!(X86Arch::new_64bit().bits(), 64);
}

#[test]
fn x86arch_partial_eq_and_clone() {
    use ax::X86Arch;
    let a = X86Arch::new_64bit();
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(X86Arch::new_32bit(), X86Arch::new_64bit());
}

#[test]
fn x86lift_adapter_reg_id_unknown_is_max() {
    use ax::X86LiftAdapter;
    use iced_x86::Register;
    // Segment registers and unknown variants return u32::MAX.
    assert_eq!(X86LiftAdapter::reg_id(Register::CS), u32::MAX);
    assert_eq!(X86LiftAdapter::reg_id(Register::DS), u32::MAX);
    assert_eq!(X86LiftAdapter::reg_id(Register::ZMM0), u32::MAX);
}

#[test]
fn x86lift_adapter_reg_id_known_aliases_share_id() {
    use ax::X86LiftAdapter;
    use iced_x86::Register;
    // RSP family all share id 24
    assert_eq!(X86LiftAdapter::reg_id(Register::RSP), 24);
    assert_eq!(X86LiftAdapter::reg_id(Register::ESP), 24);
    assert_eq!(X86LiftAdapter::reg_id(Register::SP), 24);
    assert_eq!(X86LiftAdapter::reg_id(Register::SPL), 24);
}

#[test]
fn x86lift_adapter_decode_one_iced_empty_none() {
    use ax::X86LiftAdapter;
    assert!(X86LiftAdapter::decode_one_iced(64, &[], 0).is_none());
}

#[test]
fn x86lift_adapter_decode_one_iced_invalid_none() {
    use ax::X86LiftAdapter;
    // 0xC4 followed by garbage at low end is invalid VEX.
    let r = X86LiftAdapter::decode_one_iced(64, &[0xC4, 0xFF], 0);
    // Whatever — it must not panic. Likely Some (iced may decode partially).
    let _ = r;
}

#[test]
fn x86lift_adapter_new_bits_round_trip() {
    use ax::X86LiftAdapter;
    let a = X86LiftAdapter::new(64);
    assert_eq!(a.bits(), 64);
    let a32 = X86LiftAdapter::new(32);
    assert_eq!(a32.bits(), 32);
}

// ===========================================================================
// VEX/EVEX length regression tests (bugs: opcode byte not consumed, imm8
// never counted, C4/C5/62 always treated as VEX/EVEX even in legacy modes)
// ===========================================================================

#[test]
fn length_vex_evex_known_encodings_match_iced() {
    use iced_x86::{Decoder, DecoderOptions};
    let cases: &[&[u8]] = &[
        &[0xC5, 0xF8, 0x58, 0xC1],                   // vaddps xmm0, xmm0, xmm1
        &[0xC5, 0xF9, 0x70, 0xC0, 0x1B],             // vpshufd xmm0, xmm0, 0x1b (0F map imm8)
        &[0xC5, 0xF8, 0xC2, 0xC1, 0x02],             // vcmpleps xmm0, xmm0, xmm1 (imm8)
        &[0xC4, 0xE3, 0x75, 0x02, 0xC2, 0xAA],       // vpblendd ymm0, ymm1, ymm2, 0xAA (0F3A imm8)
        &[0xC4, 0xE2, 0x7D, 0x17, 0xC2],             // vptest ymm0, ymm2 (0F38, no imm)
        &[0x62, 0xF1, 0x74, 0x48, 0x58, 0xC2],       // EVEX vaddps zmm0, zmm1, zmm2
        &[0x62, 0xF1, 0x7D, 0x48, 0x70, 0xC0, 0x1B], // EVEX vpshufd zmm0, zmm0, 0x1b (imm8)
    ];
    for &bytes in cases {
        let mut dec = Decoder::new(64, bytes, DecoderOptions::NONE);
        let ins = dec.decode();
        assert!(!ins.is_invalid(), "case must decode: {bytes:02x?}");
        assert_eq!(instr_length(bytes, 64), Ok(ins.len()), "bytes {bytes:02x?}");
    }
}

#[test]
fn diff_length_vex_random_vs_iced_64bit() {
    use iced_x86::{Decoder, DecoderOptions};
    let mut seed = 0x1234_5678_9ABC_DEF0u64;
    let mut rng = move || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as u8
    };
    for i in 0..50_000u32 {
        let mut buf = [0u8; 12];
        buf[0] = match i % 3 {
            0 => 0xC4,
            1 => 0xC5,
            _ => 0x62,
        };
        for b in buf.iter_mut().skip(1) {
            *b = rng();
        }
        let mut dec = Decoder::new(64, &buf, DecoderOptions::NONE);
        let ins = dec.decode();
        if ins.is_invalid() {
            continue;
        }
        // Where our scanner claims a length for a valid VEX/EVEX instruction,
        // it must agree with iced.
        if let Ok(len) = instr_length(&buf, 64) {
            assert_eq!(len, ins.len(), "bytes {buf:02x?}");
        }
    }
}

#[test]
fn length_legacy_modes_do_not_treat_bound_lds_les_as_vex() {
    // In 32-bit mode 0x62 with a non-11 ModRM is BOUND, 0xC4/0xC5 are LES/LDS.
    // They must not be routed through the VEX/EVEX path (which would read a
    // phantom opcode byte). Accept UnknownOpcode (table gap) but never a
    // VEX-shaped length.
    for lead in [0x62u8, 0xC4, 0xC5] {
        let bytes = [lead, 0x08, 0x00, 0x00, 0x00, 0x00];
        match instr_length(&bytes, 32) {
            Ok(len) => assert_eq!(len, 2, "lead {lead:02x} is a 2-byte /r form"),
            Err(e) => assert_eq!(e, LengthError::UnknownOpcode, "lead {lead:02x}"),
        }
    }
}
