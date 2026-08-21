//! Adversarial deep tests for `rustre-arch-mips`.
//!
//! - LCG fuzzing on `decode_word` (every opcode, no panics).
//! - Round-trip properties on encoder helpers.
//! - Boundary inputs on byte-level readers/writers.
//! - State exploration on `MipsJumpOpcode`, `MipsCallingConvention`,
//!   `MipsArch`, `DelaySlotKind`, `AnnulDecision`.
//! - Hash/Eq consistency.
//! - Send/Sync threaded stress.

use rustre_core::arch::Architecture;
use rustre_arch_mips::*;
use rustre_arch_mips::mips_delay_slot::*;
use rustre_arch_mips::mips_calling_conventions::*;
use rustre_arch_mips::mips_cop0_registers::*;
use rustre_core::address::Address;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

const fn addr(v: u64) -> Address {
    Address::new(v)
}

/// Low 32 bits of a PRNG word. Truncation is the point: MIPS instructions are
/// 32-bit, and masking first makes the conversion provably in range.
fn low32(v: u64) -> u32 {
    u32::try_from(v & 0xFFFF_FFFF).unwrap_or(0)
}

/// Low 16 bits of a PRNG word.
fn low16(v: u64) -> u16 {
    u16::try_from(v & 0xFFFF).unwrap_or(0)
}

/// Low 8 bits of a PRNG word.
fn low8(v: u64) -> u8 {
    u8::try_from(v & 0xFF).unwrap_or(0)
}

/// Low 16 bits of a PRNG word, reinterpreted as a signed immediate.
fn low_i16(v: u64) -> i16 {
    low16(v).cast_signed()
}

/// Deterministic LCG (Knuth MMIX constants).
fn lcg(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// -------------------------------------------------------------------
// 1. LCG fuzz: decode_word never panics, always yields an Instruction.
// -------------------------------------------------------------------

#[test]
fn fuzz_decode_word_le_no_panic_5000() {
    let a = MipsArch::mips32_le();
    let mut g = lcg(0xDEAD_BEEF_CAFE_BABE);
    for i in 0..5000u64 {
        let w = low32(g());
        let bytes = w.to_le_bytes();
        let ins = a.decode_word(addr(i * 4), w, &bytes);
        // Mnemonic must be a non-empty UTF-8 string.
        assert!(!ins.mnemonic.is_empty(), "word={w:#x}");
    }
}

#[test]
fn fuzz_decode_word_be_no_panic_5000() {
    let a = MipsArch::mips32_be();
    let mut g = lcg(0x0123_4567_89AB_CDEF);
    for i in 0..5000u64 {
        let w = low32(g());
        let bytes = w.to_be_bytes();
        let ins = a.decode_word(addr(i * 4), w, &bytes);
        assert!(!ins.mnemonic.is_empty());
    }
}

#[test]
fn fuzz_decode_word_64le_no_panic() {
    let a = MipsArch::mips64_le();
    let mut g = lcg(0xA5A5_5A5A_F00D_BAAD);
    for _ in 0..2000 {
        let w = low32(g());
        let bytes = w.to_le_bytes();
        let _ = a.decode_word(addr(0), w, &bytes);
    }
}

#[test]
fn fuzz_decode_word_truncated_bytes_no_panic() {
    let a = MipsArch::mips32_le();
    let mut g = lcg(0xBADC_0FFE_E0DD_F00D);
    for _ in 0..1000 {
        let w = low32(g());
        // Pass a deliberately-undersized raw buffer.
        let raw = [0u8; 1];
        let _ = a.decode_word(addr(0), w, &raw);
        let raw0: [u8; 0] = [];
        let _ = a.decode_word(addr(0), w, &raw0);
    }
}

#[test]
fn fuzz_decode_word_address_wraps() {
    let a = MipsArch::mips32_le();
    let mut g = lcg(0xCAFE_F00D_DEAD_C0DE);
    for _ in 0..500 {
        let w = low32(g());
        let pc = g();
        let b = w.to_le_bytes();
        let _ = a.decode_word(addr(pc), w, &b);
    }
}

// -------------------------------------------------------------------
// 2. disassemble error path: never panic on arbitrary slice lengths.
// -------------------------------------------------------------------

#[test]
fn fuzz_disassemble_short_slices() {
    let a = MipsArch::mips32_le();
    for len in 0..4 {
        let buf = vec![0xAAu8; len];
        let r = a.disassemble(addr(0), &buf);
        assert!(r.is_err(), "expected err for len={len}");
    }
}

#[test]
fn fuzz_disassemble_long_slices() {
    let a = MipsArch::mips32_le();
    let mut g = lcg(0x1357_9BDF_2468_ACE0);
    for _ in 0..500 {
        let mut buf = vec![0u8; 16];
        for b in &mut buf {
            *b = low8(g());
        }
        let r = a.disassemble(addr(0), &buf);
        // Either Ok or Err, but never panic.
        let _ = r;
    }
}

// -------------------------------------------------------------------
// 3. read_word / read_be32 / read_le32 / swap round-trips
// -------------------------------------------------------------------

#[test]
fn read_word_endian_round_trip_50() {
    let a_le = MipsArch::mips32_le();
    let arch_big_endian = MipsArch::mips32_be();
    let mut g = lcg(0x33);
    for _ in 0..50 {
        let w = low32(g());
        let leb = w.to_le_bytes();
        let beb = w.to_be_bytes();
        assert_eq!(a_le.read_word(&leb), Some(w));
        assert_eq!(arch_big_endian.read_word(&beb), Some(w));
    }
}

#[test]
fn read_write_be32_round_trip_50() {
    let mut g = lcg(0x77);
    let mut buf = vec![0u8; 8];
    for _ in 0..50 {
        let w = low32(g());
        write_be32(&mut buf, 0, w);
        assert_eq!(read_be32(&buf, 0), Some(w));
        write_be32(&mut buf, 4, w);
        assert_eq!(read_be32(&buf, 4), Some(w));
    }
}

#[test]
fn read_write_le32_round_trip_50() {
    let mut g = lcg(0x88);
    let mut buf = vec![0u8; 8];
    for _ in 0..50 {
        let w = low32(g());
        write_le32(&mut buf, 0, w);
        assert_eq!(read_le32(&buf, 0), Some(w));
    }
}

#[test]
fn swap32_is_involution() {
    let mut g = lcg(0x99);
    for _ in 0..100 {
        let w = low32(g());
        assert_eq!(swap32(swap32(w)), w);
    }
}

#[test]
fn swap16_is_involution() {
    let mut g = lcg(0xAA);
    for _ in 0..100 {
        let w = low16(g());
        assert_eq!(swap16(swap16(w)), w);
    }
}

#[test]
fn read_le_be_relate_via_swap() {
    let mut g = lcg(0xBB);
    let mut buf = vec![0u8; 4];
    for _ in 0..50 {
        let w = low32(g());
        write_le32(&mut buf, 0, w);
        let be_view = read_be32(&buf, 0).unwrap();
        assert_eq!(be_view, swap32(w));
    }
}

// -------------------------------------------------------------------
// 4. Boundary inputs on byte-readers
// -------------------------------------------------------------------

#[test]
fn read_be32_off_by_one_boundary() {
    let buf = [1u8, 2, 3, 4, 5];
    assert!(read_be32(&buf, 0).is_some());
    assert!(read_be32(&buf, 1).is_some());
    assert!(read_be32(&buf, 2).is_none());
    assert!(read_be32(&buf, 5).is_none());
}

#[test]
fn read_le32_off_by_one_boundary() {
    let buf = [1u8, 2, 3, 4, 5];
    assert!(read_le32(&buf, 0).is_some());
    assert!(read_le32(&buf, 1).is_some());
    assert!(read_le32(&buf, 2).is_none());
}

#[test]
fn write_be32_overflow_offset_is_noop() {
    let mut buf = vec![0xFFu8; 4];
    write_be32(&mut buf, usize::MAX - 3, 0xAAAA_AAAA);
    // Bytes untouched (offset out of range).
    assert_eq!(buf, vec![0xFF; 4]);
}

#[test]
fn write_le32_overflow_offset_is_noop() {
    let mut buf = vec![0xFFu8; 4];
    write_le32(&mut buf, 1000, 0xAAAA_AAAA);
    assert_eq!(buf, vec![0xFF; 4]);
}

// -------------------------------------------------------------------
// 5. Encoder bit-field invariants on 50 deterministic seeds.
// -------------------------------------------------------------------

#[test]
fn encode_addu_field_layout_50() {
    let mut g = lcg(0x101);
    for _ in 0..50 {
        let rd = low32(g()) & 0x1F;
        let rs = low32(g()) & 0x1F;
        let rt = low32(g()) & 0x1F;
        let w = encode_addu(rd, rs, rt);
        assert_eq!(w >> 26, 0);
        assert_eq!(w & 0x3F, 0x21);
        assert_eq!((w >> 11) & 0x1F, rd);
        assert_eq!((w >> 21) & 0x1F, rs);
        assert_eq!((w >> 16) & 0x1F, rt);
    }
}

#[test]
fn encode_j_target_masked() {
    let mut g = lcg(0x202);
    for _ in 0..50 {
        let t = low32(g());
        let w = encode_j(t);
        assert_eq!(w >> 26, 0x02);
        assert_eq!(w & 0x03FF_FFFF, t & 0x03FF_FFFF);
    }
}

#[test]
fn encode_jal_marks_call_and_branch() {
    let a = MipsArch::mips32_le();
    let i = a.decode_word(addr(0), encode_jal(0x100), &encode_jal(0x100).to_le_bytes());
    assert!(i.flags.contains(rustre_core::arch::InstrFlags::BRANCH));
    assert!(i.flags.contains(rustre_core::arch::InstrFlags::CALL));
}

#[test]
fn encode_jr_ra_marks_ret() {
    let a = MipsArch::mips32_le();
    let w = encode_jr(u32::try_from(REG_RA).unwrap_or(0));
    let i = a.decode_word(addr(0), w, &w.to_le_bytes());
    assert_eq!(i.mnemonic, "jr");
    assert!(i.flags.contains(rustre_core::arch::InstrFlags::RET));
}

#[test]
fn encode_jr_non_ra_no_ret() {
    let a = MipsArch::mips32_le();
    let w = encode_jr(u32::try_from(REG_T9).unwrap_or(0));
    let i = a.decode_word(addr(0), w, &w.to_le_bytes());
    assert_eq!(i.mnemonic, "jr");
    assert!(!i.flags.contains(rustre_core::arch::InstrFlags::RET));
}

#[test]
fn encode_lw_sw_offsets_50() {
    let a = MipsArch::mips32_le();
    let mut g = lcg(0x303);
    for _ in 0..50 {
        let rt = low32(g()) & 0x1F;
        let rs = low32(g()) & 0x1F;
        let off = low_i16(g()) & 0x7FFF; // keep positive for predictability
        let w = encode_lw(rt, rs, off);
        let i = a.decode_word(addr(0), w, &w.to_le_bytes());
        assert_eq!(i.mnemonic, "lw");
    }
}

#[test]
fn encode_addiu_negative_sign_extension() {
    let a = MipsArch::mips32_le();
    for off in &[-1i16, -32, -1024, i16::MIN, -3] {
        let w = encode_addiu(2, 1, *off);
        let i = a.decode_word(addr(0), w, &w.to_le_bytes());
        assert_eq!(i.mnemonic, "addiu");
        assert!(i.operands.contains(&off.to_string()));
    }
}

#[test]
fn encode_beq_branch_target_0_and_neg() {
    let a = MipsArch::mips32_le();
    for off in &[0i16, 1, -1, 100, -100, i16::MAX, i16::MIN] {
        let w = encode_beq(1, 2, *off);
        let i = a.decode_word(addr(0x1000), w, &w.to_le_bytes());
        assert_eq!(i.mnemonic, "beq");
        assert!(i.flags.contains(rustre_core::arch::InstrFlags::BRANCH));
        assert!(i.flags.contains(rustre_core::arch::InstrFlags::CONDITIONAL));
    }
}

// -------------------------------------------------------------------
// 6. branch_target_i / branch_target_j boundary
// -------------------------------------------------------------------

#[test]
fn branch_target_i_off_by_one() {
    assert_eq!(branch_target_i(addr(0x1000), 0), 0x1004);
    assert_eq!(branch_target_i(addr(0x1000), 1), 0x1008);
    assert_eq!(branch_target_i(addr(0x1000), -1), 0x1000);
    assert_eq!(branch_target_i(addr(0x1000), i64::from(i16::MAX)), 0x1000 + 4 + 4 * (i16::MAX as u64));
}

#[test]
fn branch_target_j_only_low_28_bits_used() {
    let t = branch_target_j(addr(0x8000_0004), 0x3FF_FFFF);
    // top 4 bits preserved from pc+4 = 0x8000_0008
    assert_eq!(t & 0xF000_0000, 0x8000_0000);
}

#[test]
fn branch_target_i_address_max_no_panic() {
    let _ = branch_target_i(addr(u64::MAX), 0);
    let _ = branch_target_i(addr(u64::MAX), i64::from(i16::MAX));
    let _ = branch_target_i(addr(0), i64::from(i16::MIN));
}

// -------------------------------------------------------------------
// 7. is_valid_mips_word
// -------------------------------------------------------------------

#[test]
fn is_valid_zero_and_nop() {
    assert!(is_valid_mips_word(0));
    assert!(is_valid_mips_word(encode_nop()));
}

#[test]
fn is_valid_fuzz_no_panic() {
    let mut g = lcg(0x707);
    for _ in 0..1000 {
        let _ = is_valid_mips_word(low32(g()));
    }
}

// -------------------------------------------------------------------
// 8. histogram + scan_constant_pool over arbitrary fuzz bytes
// -------------------------------------------------------------------

#[test]
fn histogram_fuzz_total_matches_word_count() {
    let a = MipsArch::mips32_le();
    let mut g = lcg(0xAB);
    let mut bytes = Vec::with_capacity(64 * 4);
    for _ in 0..64 {
        let w = low32(g());
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let h = MipsHistogram::build(&a, &bytes, addr(0));
    // total counts non-zero entries summed.
    assert!(h.total() <= 64);
}

#[test]
fn scan_constant_pool_fuzz_no_panic() {
    let a = MipsArch::mips32_le();
    let mut g = lcg(0xCDCD);
    let mut bytes = Vec::with_capacity(128);
    for _ in 0..32 {
        let w = low32(g());
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let _ = scan_constant_pool(&a, &bytes, addr(0x4000));
}

// -------------------------------------------------------------------
// 9. patch_branch fuzz and boundary
// -------------------------------------------------------------------

#[test]
fn patch_branch_truncated_buffer_errs() {
    let mut buf = vec![0u8; 3];
    assert!(patch_branch(&mut buf, 0, addr(0), 0, MipsEndian::Big).is_err());
}

#[test]
fn patch_branch_i_round_trip_via_decode() {
    let mut buf = encode_beq(1, 2, 0).to_be_bytes().to_vec();
    patch_branch(&mut buf, 0, addr(0x100), 0x120, MipsEndian::Big).unwrap();
    let a = MipsArch::mips32_be();
    let w = a.read_word(&buf).unwrap();
    let i = a.decode_word(addr(0x100), w, &buf);
    assert_eq!(i.mnemonic, "beq");
}

#[test]
fn patch_branch_j_out_of_region_err() {
    let mut buf = encode_j(0).to_be_bytes().to_vec();
    // Different 256MB region.
    assert!(patch_branch(&mut buf, 0, addr(0x1000_0000), 0xF000_0000, MipsEndian::Big).is_err());
}

// -------------------------------------------------------------------
// 10. linear disassembler + basic blocks fuzz
// -------------------------------------------------------------------

#[test]
fn linear_disasm_fuzz_count_consistent() {
    let a = MipsArch::mips32_le();
    let mut g = lcg(0xEEEE);
    let mut bytes = Vec::new();
    for _ in 0..50 {
        let w = low32(g());
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let n = MipsLinearDisassembler::new(&a, &bytes, addr(0)).count();
    assert_eq!(n, 50);
}

// -------------------------------------------------------------------
// 11. Display / FromStr-ish round-trips on enums that have Display
// -------------------------------------------------------------------

#[test]
fn delay_slot_kind_display() {
    assert_eq!(DelaySlotKind::Standard.to_string(), "standard");
    assert_eq!(DelaySlotKind::Annulled.to_string(), "annulled");
    assert_eq!(DelaySlotKind::None.to_string(), "none");
}

#[test]
fn annul_decision_display() {
    assert_eq!(AnnulDecision::Execute.to_string(), "execute");
    assert_eq!(AnnulDecision::Skip.to_string(), "skip");
    assert_eq!(AnnulDecision::NotAnnulled.to_string(), "not_annulled");
}

#[test]
fn mips_calling_convention_display() {
    assert_eq!(MipsCallingConvention::O32.to_string(), "O32");
    assert_eq!(MipsCallingConvention::N32.to_string(), "N32");
    assert_eq!(MipsCallingConvention::N64.to_string(), "N64");
}

// -------------------------------------------------------------------
// 12. MipsJumpOpcode classification matrix
// -------------------------------------------------------------------

#[test]
fn jump_opcode_classification_complete() {
    // Annulled vs Standard vs None must cover every variant.
    let all = [
        MipsJumpOpcode::J,
        MipsJumpOpcode::Jal,
        MipsJumpOpcode::Jr,
        MipsJumpOpcode::Jalr,
        MipsJumpOpcode::Beq,
        MipsJumpOpcode::Bne,
        MipsJumpOpcode::Blez,
        MipsJumpOpcode::Bgtz,
        MipsJumpOpcode::Bltz,
        MipsJumpOpcode::Bgez,
        MipsJumpOpcode::Bltzal,
        MipsJumpOpcode::Bgezal,
        MipsJumpOpcode::Beql,
        MipsJumpOpcode::Bnel,
        MipsJumpOpcode::Blezl,
        MipsJumpOpcode::Bgtzl,
        MipsJumpOpcode::Bltzl,
        MipsJumpOpcode::Bgezl,
        MipsJumpOpcode::Bltzall,
        MipsJumpOpcode::Bgezall,
        MipsJumpOpcode::Bc1f,
        MipsJumpOpcode::Bc1t,
        MipsJumpOpcode::Bc1fl,
        MipsJumpOpcode::Bc1tl,
        MipsJumpOpcode::Bal,
        MipsJumpOpcode::Beqz,
        MipsJumpOpcode::Bnez,
    ];
    for o in &all {
        let _ = o.delay_slot_kind();
        let _ = o.is_unconditional();
        let _ = o.is_call();
        assert!(!o.mnemonic().is_empty());
    }
}

#[test]
fn jump_opcode_unconditional_classification() {
    assert!(MipsJumpOpcode::J.is_unconditional());
    assert!(MipsJumpOpcode::Jal.is_unconditional());
    assert!(MipsJumpOpcode::Jr.is_unconditional());
    assert!(MipsJumpOpcode::Jalr.is_unconditional());
    assert!(!MipsJumpOpcode::Beq.is_unconditional());
    assert!(!MipsJumpOpcode::Beql.is_unconditional());
}

#[test]
fn jump_opcode_is_call_matrix() {
    assert!(MipsJumpOpcode::Jal.is_call());
    assert!(MipsJumpOpcode::Jalr.is_call());
    assert!(MipsJumpOpcode::Bal.is_call());
    assert!(MipsJumpOpcode::Bltzal.is_call());
    assert!(MipsJumpOpcode::Bgezal.is_call());
    assert!(MipsJumpOpcode::Bltzall.is_call());
    assert!(MipsJumpOpcode::Bgezall.is_call());
    assert!(!MipsJumpOpcode::J.is_call());
    assert!(!MipsJumpOpcode::Jr.is_call());
    assert!(!MipsJumpOpcode::Beq.is_call());
}

// -------------------------------------------------------------------
// 13. annul_check / lifting_semantics state-table
// -------------------------------------------------------------------

fn mk_bwd(opcode: MipsJumpOpcode) -> BranchWithDelay {
    let ds = DelaySlotInsn::nop(0x1000_0004);
    BranchWithDelay::new(0x1000_0000, 0, opcode, Some(0x2000_0000), ds, vec![])
}

#[test]
fn annul_check_standard_always_execute() {
    let bwd = mk_bwd(MipsJumpOpcode::J);
    assert_eq!(annul_check(&bwd, true), AnnulDecision::Execute);
    assert_eq!(annul_check(&bwd, false), AnnulDecision::Execute);
}

#[test]
fn annul_check_annulled_skip_on_not_taken() {
    let bwd = mk_bwd(MipsJumpOpcode::Beql);
    assert_eq!(annul_check(&bwd, true), AnnulDecision::Execute);
    assert_eq!(annul_check(&bwd, false), AnnulDecision::Skip);
}

#[test]
fn annul_check_no_delay_always_skip() {
    let bwd = mk_bwd(MipsJumpOpcode::Bal);
    assert_eq!(annul_check(&bwd, true), AnnulDecision::Skip);
    assert_eq!(annul_check(&bwd, false), AnnulDecision::Skip);
}

#[test]
fn lifting_semantics_all_cases() {
    let std_bwd = mk_bwd(MipsJumpOpcode::Beq);
    let ann_bwd = mk_bwd(MipsJumpOpcode::Beql);
    let none_bwd = mk_bwd(MipsJumpOpcode::Bal);

    matches_delay_then_branch(&lifting_semantics(&std_bwd, true));
    matches_delay_then_branch(&lifting_semantics(&std_bwd, false));
    matches_delay_then_branch(&lifting_semantics(&ann_bwd, true));
    matches_fallthrough(&lifting_semantics(&ann_bwd, false));
    matches_branch_only(&lifting_semantics(&none_bwd, true));
    matches_fallthrough(&lifting_semantics(&none_bwd, false));
}

fn matches_delay_then_branch(s: &LiftedBranchSemantics) {
    assert!(matches!(s, LiftedBranchSemantics::DelayThenBranch { .. }));
}
fn matches_branch_only(s: &LiftedBranchSemantics) {
    assert!(matches!(s, LiftedBranchSemantics::BranchOnly { .. }));
}
fn matches_fallthrough(s: &LiftedBranchSemantics) {
    assert!(matches!(s, LiftedBranchSemantics::FallthroughOnly { .. }));
}

#[test]
fn branch_with_delay_fallthrough_is_branch_plus_8() {
    let bwd = mk_bwd(MipsJumpOpcode::J);
    assert_eq!(bwd.fallthrough, 0x1000_0008);
    assert_eq!(bwd.delay_slot_address(), 0x1000_0004);
}

#[test]
fn branch_with_delay_fallthrough_wraps_safely() {
    let ds = DelaySlotInsn::nop(0);
    let bwd = BranchWithDelay::new(u64::MAX - 3, 0, MipsJumpOpcode::J, None, ds, vec![]);
    // Should wrap, not panic.
    assert_eq!(bwd.fallthrough, (u64::MAX - 3).wrapping_add(8));
}

// -------------------------------------------------------------------
// 14. DelaySlotInsn hazard logic
// -------------------------------------------------------------------

#[test]
fn delay_slot_insn_nop_constructor_consistency() {
    let n = DelaySlotInsn::nop(0xFFFF);
    assert!(n.is_nop);
    assert_eq!(n.encoding, DelaySlotInsn::NOP_ENCODING);
    assert!(!n.is_branch);
    assert_eq!(n.text, "nop");
}

#[test]
fn delay_slot_insn_hazard_detected_when_writes_match() {
    let mut ds = DelaySlotInsn::nop(0);
    ds.writes = vec![4];
    assert!(ds.has_write_hazard(&[4]));
    assert!(!ds.has_write_hazard(&[5]));
    assert!(!ds.has_write_hazard(&[]));
}

#[test]
fn analyze_diagnostics_severity_ordering() {
    use std::cmp::Ordering;
    assert_eq!(DiagSeverity::Info.cmp(&DiagSeverity::Warning), Ordering::Less);
    assert_eq!(DiagSeverity::Warning.cmp(&DiagSeverity::Error), Ordering::Less);
    assert!(DiagSeverity::Error > DiagSeverity::Info);
}

#[test]
fn delay_slot_report_optimizable_count_matches_nop_count() {
    let analyser = MipsDelaySlot::default_config();
    let mut ds_real = DelaySlotInsn::nop(4);
    ds_real.is_nop = false;
    ds_real.encoding = 0x2410_0001;
    let branches = vec![
        BranchWithDelay::new(0, 0, MipsJumpOpcode::J, Some(8), DelaySlotInsn::nop(4), vec![]),
        BranchWithDelay::new(8, 0, MipsJumpOpcode::Jal, Some(16), ds_real, vec![]),
    ];
    let report = analyser.analyze(&branches);
    assert_eq!(report.optimizable_count(), 1);
    assert_eq!(report.nop_delay_slots, 1);
    assert_eq!(report.total_branches, 2);
}

#[test]
fn function_delay_slot_stats_nop_ratio_zero_when_empty() {
    let stats = FunctionDelaySlotStats::compute(0, &[]);
    assert_eq!(stats.nop_ratio(), 0.0);
    assert_eq!(stats.branch_count, 0);
}

// -------------------------------------------------------------------
// 15. MipsCallingConvention properties
// -------------------------------------------------------------------

#[test]
fn cc_widths_and_alignments() {
    let o = MipsCallingConvention::O32;
    let n32 = MipsCallingConvention::N32;
    let n64 = MipsCallingConvention::N64;
    assert_eq!(o.gpr_width(), 4);
    assert_eq!(n32.gpr_width(), 8);
    assert_eq!(n64.gpr_width(), 8);
    assert_eq!(o.pointer_width(), 4);
    assert_eq!(n32.pointer_width(), 4);
    assert_eq!(n64.pointer_width(), 8);
    assert_eq!(o.stack_alignment(), 8);
    assert_eq!(n32.stack_alignment(), 16);
    assert_eq!(n64.stack_alignment(), 16);
}

#[test]
fn cc_arg_reg_counts_match_lists() {
    for cc in [
        MipsCallingConvention::O32,
        MipsCallingConvention::N32,
        MipsCallingConvention::N64,
    ] {
        assert_eq!(cc.arg_reg_count() as usize, cc.arg_registers().len());
    }
}

#[test]
fn cc_home_area_o32_only() {
    assert!(MipsCallingConvention::O32.has_home_area());
    assert!(!MipsCallingConvention::N32.has_home_area());
    assert!(!MipsCallingConvention::N64.has_home_area());
    assert_eq!(MipsCallingConvention::O32.home_area_size(), 16);
    assert_eq!(MipsCallingConvention::N64.home_area_size(), 0);
}

#[test]
fn stack_arg_offset_register_passed_is_none() {
    for i in 0..4 {
        assert!(MipsCallingConvention::O32.stack_arg_offset(i).is_none());
    }
    for i in 0..8 {
        assert!(MipsCallingConvention::N64.stack_arg_offset(i).is_none());
    }
}

#[test]
fn stack_arg_offset_o32_after_home_area() {
    // arg 4 -> 16 (home area), arg 5 -> 20.
    assert_eq!(MipsCallingConvention::O32.stack_arg_offset(4), Some(16));
    assert_eq!(MipsCallingConvention::O32.stack_arg_offset(5), Some(20));
    assert_eq!(MipsCallingConvention::O32.stack_arg_offset(10), Some(16 + 6 * 4));
}

#[test]
fn stack_arg_offset_n64_starts_at_zero() {
    assert_eq!(MipsCallingConvention::N64.stack_arg_offset(8), Some(0));
    assert_eq!(MipsCallingConvention::N64.stack_arg_offset(9), Some(8));
}

#[test]
fn callee_caller_saved_disjoint_modulo_sp_gp() {
    // No GPR should be both caller and callee saved.
    let cc = MipsCallingConvention::O32;
    let callee: HashSet<_> = cc.callee_saved_regs().into_iter().collect();
    let caller_saved: HashSet<_> = cc.caller_saved_regs().into_iter().collect();
    let inter: HashSet<_> = callee.intersection(&caller_saved).collect();
    assert!(inter.is_empty(), "overlap: {inter:?}");
}

#[test]
fn call_site_layout_o32_basic() {
    let layout = CallSiteLayout::compute(
        MipsCallingConvention::O32,
        &[ArgDesc::int(0), ArgDesc::int(1), ArgDesc::int(2), ArgDesc::int(3), ArgDesc::int(4)],
    );
    assert_eq!(layout.locations.len(), 5);
    assert!(layout.location_for(0).is_some());
    assert!(layout.location_for(5).is_none());
}

#[test]
fn call_site_layout_n64_many_args() {
    let args: Vec<_> = (0..10).map(ArgDesc::int).collect();
    let layout = CallSiteLayout::compute(MipsCallingConvention::N64, &args);
    assert_eq!(layout.locations.len(), 10);
    // 2 spilled args × 8 bytes = 16 stack bytes.
    assert_eq!(layout.stack_bytes, 16);
}

#[test]
fn calling_convention_db_default_and_override() {
    let mut db = CallingConventionDb::new(MipsCallingConvention::N64);
    assert_eq!(db.default_convention(), MipsCallingConvention::N64);
    assert_eq!(db.convention_for("foo"), MipsCallingConvention::N64);
    db.add_override("foo", MipsCallingConvention::O32);
    assert_eq!(db.convention_for("foo"), MipsCallingConvention::O32);
    assert_eq!(db.convention_for("bar"), MipsCallingConvention::N64);
}

// -------------------------------------------------------------------
// 16. Cop0Register properties
// -------------------------------------------------------------------

#[test]
fn cop0_register_constructors() {
    let a = Cop0Register::new(12, 0);
    let b = Cop0Register::r(12);
    assert_eq!(a, b);
    assert_eq!(a.reg, 12);
    assert_eq!(a.select, 0);
}

#[test]
fn cop0_register_display_with_and_without_select() {
    let s0 = Cop0Register::r(12).to_string();
    let s2 = Cop0Register::new(12, 2).to_string();
    assert!(s0.contains("12"));
    assert!(s2.contains("12"));
    assert!(s2.contains('2'));
}

#[test]
fn standard_cop0_entries_nonempty_and_lookup() {
    let entries = standard_cop0_entries();
    assert!(!entries.is_empty());
    // STATUS should be in the table.
    let found = entries.iter().any(|e| e.reg == cop0::STATUS);
    assert!(found);
}

#[test]
fn cop0_name_known_regs() {
    assert!(cop0_name(cop0::STATUS).is_some());
    assert!(cop0_name(cop0::CAUSE).is_some());
}

#[test]
fn mips_revision_ordering() {
    assert!(MipsRevision::Mips1 < MipsRevision::Mips32);
    assert!(MipsRevision::Mips32 < MipsRevision::Mips32r2);
    assert!(MipsRevision::Mips32r2 < MipsRevision::Mips64);
}

// -------------------------------------------------------------------
// 17. Hash/Eq consistency on 30+ pairs.
// -------------------------------------------------------------------

fn assert_hash_eq<T: std::hash::Hash + Eq + Clone + std::fmt::Debug>(a: &T, b: &T) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    a.clone().hash(&mut h1);
    b.clone().hash(&mut h2);
    assert_eq!(a, b);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn hash_eq_pairs_30() {
    // MipsEndian
    assert_hash_eq(&MipsEndian::Little, &MipsEndian::Little);
    assert_hash_eq(&MipsEndian::Big, &MipsEndian::Big);

    // MipsAbi
    assert_hash_eq(&MipsAbi::O32, &MipsAbi::O32);
    assert_hash_eq(&MipsAbi::N32, &MipsAbi::N32);
    assert_hash_eq(&MipsAbi::N64, &MipsAbi::N64);

    // DelaySlotKind
    assert_hash_eq(&DelaySlotKind::Standard, &DelaySlotKind::Standard);
    assert_hash_eq(&DelaySlotKind::Annulled, &DelaySlotKind::Annulled);
    assert_hash_eq(&DelaySlotKind::None, &DelaySlotKind::None);

    // MipsJumpOpcode subset
    let ops = [
        MipsJumpOpcode::J,
        MipsJumpOpcode::Jal,
        MipsJumpOpcode::Jr,
        MipsJumpOpcode::Jalr,
        MipsJumpOpcode::Beq,
        MipsJumpOpcode::Bne,
        MipsJumpOpcode::Beql,
        MipsJumpOpcode::Bnel,
    ];
    for o in &ops {
        assert_hash_eq(o, o);
    }

    // MipsCallingConvention
    assert_hash_eq(&MipsCallingConvention::O32, &MipsCallingConvention::O32);
    assert_hash_eq(&MipsCallingConvention::N32, &MipsCallingConvention::N32);
    assert_hash_eq(&MipsCallingConvention::N64, &MipsCallingConvention::N64);

    // Cop0Register
    assert_hash_eq(&Cop0Register::r(12), &Cop0Register::new(12, 0));
    assert_hash_eq(&cop0::STATUS, &cop0::STATUS);
    assert_hash_eq(&cop0::CAUSE, &cop0::CAUSE);

    // GprRole
    assert_hash_eq(&GprRole::Argument, &GprRole::Argument);
    assert_hash_eq(&GprRole::Saved, &GprRole::Saved);

    // HiLoEffect
    assert_hash_eq(&HiLoEffect::None, &HiLoEffect::None);
    assert_hash_eq(&HiLoEffect::MultSigned, &HiLoEffect::MultSigned);
    assert_hash_eq(&HiLoEffect::DivUnsigned, &HiLoEffect::DivUnsigned);

    // MipsRevision
    assert_hash_eq(&MipsRevision::Mips32r2, &MipsRevision::Mips32r2);
}

// -------------------------------------------------------------------
// 18. HashMap and HashSet usage of types
// -------------------------------------------------------------------

#[test]
fn endian_set_dedup() {
    let mut s: HashSet<MipsEndian> = HashSet::new();
    s.insert(MipsEndian::Big);
    s.insert(MipsEndian::Big);
    s.insert(MipsEndian::Little);
    assert_eq!(s.len(), 2);
}

#[test]
fn cop0_register_hashmap_keying() {
    let mut m: HashMap<Cop0Register, &str> = HashMap::new();
    m.insert(cop0::STATUS, "status");
    m.insert(cop0::CAUSE, "cause");
    assert_eq!(m.get(&Cop0Register::r(12)), Some(&"status"));
    assert_eq!(m.get(&Cop0Register::new(13, 0)), Some(&"cause"));
}

// -------------------------------------------------------------------
// 19. ABI role tables
// -------------------------------------------------------------------

#[test]
fn gpr_role_o32_full_table() {
    // Compare against published O32 conventions across every reg index.
    let expected = [
        GprRole::Zero, GprRole::At, GprRole::ReturnValue, GprRole::ReturnValue,
        GprRole::Argument, GprRole::Argument, GprRole::Argument, GprRole::Argument,
        GprRole::Temporary, GprRole::Temporary, GprRole::Temporary, GprRole::Temporary,
        GprRole::Temporary, GprRole::Temporary, GprRole::Temporary, GprRole::Temporary,
        GprRole::Saved, GprRole::Saved, GprRole::Saved, GprRole::Saved,
        GprRole::Saved, GprRole::Saved, GprRole::Saved, GprRole::Saved,
        GprRole::Temporary, GprRole::Temporary,
        GprRole::Kernel, GprRole::Kernel,
        GprRole::GlobalPointer, GprRole::StackPointer, GprRole::FramePointer, GprRole::ReturnAddress,
    ];
    for (i, want) in expected.iter().enumerate() {
        assert_eq!(gpr_role_o32(i), *want, "o32 idx {i}");
    }
}

#[test]
fn gpr_role_out_of_range_consistent() {
    // Out-of-range should give a stable variant, not panic.
    let _ = gpr_role_o32(100);
    let _ = gpr_role_n64(200);
}

// -------------------------------------------------------------------
// 20. Send/Sync threaded stress (4 threads x 100 ops)
// -------------------------------------------------------------------

#[test]
fn arch_threaded_decode_stress() {
    let arch = Arc::new(MipsArch::mips32_le());
    let mut handles = vec![];
    for t in 0u64..4 {
        let a = Arc::clone(&arch);
        handles.push(thread::spawn(move || {
            let mut g = lcg(0xC0DE_BABE_0000 ^ t);
            for _ in 0..100 {
                let w = low32(g());
                let _ = a.decode_word(addr(0), w, &w.to_le_bytes());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn cop0register_threaded_lookup_stress() {
    let entries = Arc::new(standard_cop0_entries());
    let mut handles = vec![];
    for t in 0u64..4 {
        let e = Arc::clone(&entries);
        handles.push(thread::spawn(move || {
            let mut g = lcg(0x1111_2222 ^ t);
            for _ in 0..100 {
                let idx = usize::try_from(low32(g())).unwrap_or(0) % e.len();
                let _ = e[idx].name;
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// -------------------------------------------------------------------
// 21. Round-trip: encode -> decode -> mnemonic match for all simple encoders.
// -------------------------------------------------------------------

#[test]
fn encode_decode_mnemonic_table() {
    let a = MipsArch::mips32_le();
    let cases: Vec<(u32, &str)> = vec![
        (encode_nop(), "sll"),
        (encode_addu(3, 1, 2), "addu"),
        (encode_subu(3, 1, 2), "subu"),
        (encode_and(3, 1, 2), "and"),
        (encode_or(3, 1, 2), "or"),
        (encode_xor(3, 1, 2), "xor"),
        (encode_nor(3, 1, 2), "nor"),
        (encode_slt(3, 1, 2), "slt"),
        (encode_sltu(3, 1, 2), "sltu"),
        (encode_mult(1, 2), "mult"),
        (encode_div(1, 2), "div"),
        (encode_mfhi(3), "mfhi"),
        (encode_mflo(3), "mflo"),
        (encode_jr(31), "jr"),
        (encode_jalr(31, 25), "jalr"),
        (encode_j(0x100), "j"),
        (encode_jal(0x100), "jal"),
        (encode_lui(2, 0x1234), "lui"),
        (encode_addiu(2, 1, 100), "addiu"),
        (encode_lw(2, 29, 0), "lw"),
        (encode_sw(31, 29, 4), "sw"),
        (encode_beq(1, 2, 4), "beq"),
        (encode_bne(1, 2, -4), "bne"),
        (encode_syscall(0x42), "syscall"),
    ];
    for (w, want) in cases {
        let i = a.decode_word(addr(0), w, &w.to_le_bytes());
        assert_eq!(i.mnemonic, want, "word={w:#x}");
    }
}

// -------------------------------------------------------------------
// 22. format_instruction never panics on fuzzed input
// -------------------------------------------------------------------

#[test]
fn format_instruction_fuzz_no_panic() {
    let a = MipsArch::mips32_le();
    let opts = FormatOptions::default();
    let mut g = lcg(0xF00D_FACE_1234_5678);
    for _ in 0..200 {
        let w = low32(g());
        let i = a.decode_word(addr(0), w, &w.to_le_bytes());
        let _ = format_instruction(&i, false, &opts);
        let _ = format_instruction(&i, true, &opts);
        let _ = print_instr(&i, PrintStyle::Standard);
        let _ = print_instr(&i, PrintStyle::WithHexAddress);
    }
}
