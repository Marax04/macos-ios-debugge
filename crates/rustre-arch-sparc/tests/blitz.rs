//! Adversarial / edge-case test suite for `rustre-arch-sparc`.
//!
//! Focus: boundary conditions, malformed inputs, lesser-exercised public APIs,
//! and invariants that should hold across the SPARC encoder/decoder/analysis
//! modules.

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_sparc::sparc_delay_slot::{
    self, analyze_branch, AnnulBit, BranchCondition as DSCond, BranchKind, DelayEffect,
    DelaySlotScanner, SparcDelaySlot,
};
use rustre_arch_sparc::sparc_register_windows::{
    self as srw, classify_window_instrs, is_restore, is_save, save_restore_analysis,
    total_physical_regs, RegisterClass, SparcRegisterWindow, WindowEntry, WindowInstr, WindowStats,
};
use rustre_arch_sparc::sparc_trap_table::{
    sparc_v8_trap_map, sparc_v8_trap_table, sparc_v9_trap_map, sparc_v9_trap_table, trap_name,
    trap_name_v9, TrapHandlerScanner, TrapKind,
};
use rustre_arch_sparc::{
    build_epilogue, build_prologue, build_return_seq, disassemble_annotated,
    encode_alu_imm, encode_alu_reg, encode_bicc, encode_call, encode_jmpl, encode_load, encode_nop,
    encode_sethi, encode_store, extract_branch_targets, format_annotated, identify_idiom,
    lookup_asi, lookup_condition, lookup_fp_opcode, lookup_priv_reg, lookup_v8_trap,
    lookup_v9_trap, resolve_branches, sparc_print_gnu, sparc_print_sun, synth_clr, synth_cmp_imm,
    synth_cmp_reg, synth_dec, synth_inc, synth_mov_imm, synth_mov_reg, synth_neg, synth_not,
    synth_set, synth_tst, AnnotatedSparcInstr, SparcArch, SparcAsiEntry, SparcCodeStats,
    SparcIdiom, SparcInstrKind, SparcLinearDisassembler, SparcRawMix, SparcRegSet, SparcStackLayout,
    SparcWindowState, SPARC_ASI_TABLE, SPARC_CONDITIONS, SPARC_FORMATS, SPARC_FP_OPCODES,
    SPARC_V8_INT_ARGS, SPARC_V8_TRAPS, SPARC_V9_FP_ARGS, SPARC_V9_INT_ARGS, SPARC_V9_PRIV_REGS,
    SPARC_V9_TRAPS,
};
use rustre_core::address::Address;
use rustre_core::endian::Endian;

fn a(v: u64) -> Address {
    Address::new(v)
}
fn arch() -> SparcArch {
    SparcArch::default()
}

// ── Disassemble: truncated / empty inputs ─────────────────────────────────────

#[test]
fn disasm_empty_is_err() {
    assert!(arch().disassemble(a(0), &[]).is_err());
}

#[test]
fn disasm_three_bytes_is_err() {
    assert!(arch().disassemble(a(0), &[0, 0, 0]).is_err());
}

#[test]
fn disasm_extra_bytes_only_uses_4() {
    // NOP plus garbage trailing bytes; should consume exactly 4.
    let bytes = [0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF];
    let i = arch().disassemble(a(0), &bytes).unwrap();
    assert_eq!(i.size, 4);
    assert_eq!(i.mnemonic, "NOP");
}

// ── Linear disassembler ──────────────────────────────────────────────────────

#[test]
fn linear_disasm_two_nops() {
    let bytes = [0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    let a_ = arch();
    let it = SparcLinearDisassembler::new(&a_, &bytes, a(0));
    let v: Vec<_> = it.collect();
    assert_eq!(v.len(), 2);
    for r in &v {
        assert_eq!(r.as_ref().unwrap().mnemonic, "NOP");
    }
}

#[test]
fn linear_disasm_empty_yields_nothing() {
    let a_ = arch();
    let it = SparcLinearDisassembler::new(&a_, &[], a(0));
    assert_eq!(it.count(), 0);
}

#[test]
fn linear_disasm_addresses_increment_by_4() {
    let bytes = [0x01u8, 0x00, 0x00, 0x00].repeat(3);
    let a_ = arch();
    let it = SparcLinearDisassembler::new(&a_, &bytes, a(0x1000));
    let v: Vec<_> = it.map(|r| r.unwrap().address.as_u64()).collect();
    assert_eq!(v, vec![0x1000, 0x1004, 0x1008]);
}

// ── Endian variant ───────────────────────────────────────────────────────────

#[test]
fn little_endian_arch_decodes_nop_when_bytes_swapped() {
    let le = SparcArch::new_le();
    // NOP big-endian word 0x01000000; in LE the bytes are reversed.
    let bytes = [0x00, 0x00, 0x00, 0x01];
    let i = le.disassemble(a(0), &bytes).unwrap();
    assert_eq!(i.mnemonic, "NOP");
}

#[test]
fn arch_endian_matches_constructor() {
    assert_eq!(SparcArch::new_v8().endian(), Endian::Big);
    assert_eq!(SparcArch::new_v9().endian(), Endian::Big);
    assert_eq!(SparcArch::new_le().endian(), Endian::Little);
}

#[test]
fn arch_name_variants() {
    assert_eq!(SparcArch::new_v8().name(), "sparc");
    assert_eq!(SparcArch::new_v9().name(), "sparcv9");
    assert_eq!(SparcArch::new_le().name(), "sparcv9le");
}

#[test]
fn arch_pointer_sizes() {
    assert_eq!(SparcArch::new_v8().pointer_size(), 4);
    assert_eq!(SparcArch::new_v9().pointer_size(), 8);
}

// ── Encode helpers: boundary panics & round-trips ────────────────────────────

#[test]
#[should_panic(expected = "CALL displacement must be 4-byte aligned")]
fn encode_call_unaligned_panics() {
    let _ = encode_call(1);
}

/// `encode_bicc` ALIGNS DOWN instead of panicking — a deliberate change
/// (lib.rs:1584: "Silently align to 4 bytes rather than panicking on misaligned
/// input"). This test used to be `#[should_panic(expected = "branch
/// displacement must be 4-byte aligned")]` and was left behind by that change,
/// so it demanded a panic that no longer happens.
///
/// NOTE — sibling inconsistency, deliberately only flagged, not "fixed" here:
/// `encode_call` still PANICS on the same error (see
/// `encode_call_unaligned_panics` above, which passes). Two encoders in one
/// crate answer the same misuse in opposite ways. Unifying them is a real API
/// decision — silent alignment hides caller bugs, panicking is hostile in a
/// library — and belongs to whoever owns this crate's error policy.
#[test]
fn encode_bicc_unaligned_aligns_down() {
    // disp = 2 -> 2 & !3 = 0, so it encodes exactly as disp = 0.
    assert_eq!(encode_bicc(8, false, 2), encode_bicc(8, false, 0));
    // And a genuinely aligned displacement is untouched.
    assert_ne!(encode_bicc(8, false, 4), encode_bicc(8, false, 0));
}

#[test]
fn encode_call_negative_disp() {
    // CALL -4 -> target is pc-4; just ensure encode doesn't panic and disassembly recognises it.
    let enc = encode_call(-4).to_be_bytes();
    let i = arch().disassemble(a(0x2000), &enc).unwrap();
    assert_eq!(i.mnemonic, "CALL");
}

#[test]
fn encode_alu_imm_simm13_negative() {
    // SUBCC %o0, -1, %g0 -> CMP/SUBCC roundtrip
    let enc = encode_alu_imm(0x14, 8, -1, 0).to_be_bytes();
    let i = arch().disassemble(a(0), &enc).unwrap();
    assert_eq!(i.mnemonic, "SUBCC");
    assert!(i.operands.contains("-1"));
}

#[test]
fn encode_alu_reg_masks_fields() {
    // High bits of args must not bleed into other fields.
    let enc = encode_alu_reg(0xFF, 0xFF, 0xFF, 0xFF);
    // rd lives in bits [29:25]: top 5 bits of (0xFF & 31) = 31; check rd==31
    assert_eq!((enc >> 25) & 31, 31);
    // rs1
    assert_eq!((enc >> 14) & 31, 31);
    // rs2 in low 5 bits
    assert_eq!(enc & 31, 31);
    // op3 in bits [24:19] is 6 bits
    assert_eq!((enc >> 19) & 63, 63);
}

#[test]
fn encode_nop_is_canonical_sparc_nop() {
    assert_eq!(encode_nop(), 0x0100_0000);
}

#[test]
fn encode_sethi_imm22_masked() {
    // Pass a value larger than 22 bits — should be masked, not corrupt rd.
    let enc = encode_sethi(8, 0xFFFF_FFFF);
    assert_eq!((enc >> 25) & 31, 8);
    // imm22 field should be 22 1-bits.
    assert_eq!(enc & 0x003F_FFFF, 0x003F_FFFF);
}

// ── Synth helpers: panics on out-of-range ────────────────────────────────────

#[test]
#[should_panic(expected = "out of 13-bit range")]
fn synth_mov_imm_overflow_panics() {
    let _ = synth_mov_imm(5000, 8);
}

#[test]
#[should_panic(expected = "out of 13-bit range")]
fn synth_cmp_imm_underflow_panics() {
    let _ = synth_cmp_imm(8, -5000);
}

#[test]
fn synth_set_boundary_4095_one_word() {
    let w = synth_set(4095, 8);
    assert_eq!(w.len(), 1);
}

#[test]
fn synth_set_boundary_4096_two_words() {
    let w = synth_set(4096, 8);
    // 4096 doesn't fit signed 13-bit (max +4095), so two-word form.
    assert_eq!(w.len(), 2);
}

#[test]
fn synth_set_zero_one_word() {
    let w = synth_set(0, 8);
    assert_eq!(w.len(), 1);
}

#[test]
fn synth_set_large_values_disassemble() {
    // Values whose signed-i32 reinterpretation is outside [-4096, 4095].
    for v in [0x1234_5678u32, 0x8000_0000, 0x0000_4096, 0x7FFF_F000] {
        let sv = v as i32;
        assert!(!(-4096..=4095).contains(&sv), "test setup: {v:#x} should be out of range");
        let words = synth_set(v, 8);
        assert_eq!(words.len(), 2, "expected 2 words for {v:#x}");
        let i0 = arch().disassemble(a(0), &words[0].to_be_bytes()).unwrap();
        let i1 = arch().disassemble(a(4), &words[1].to_be_bytes()).unwrap();
        assert_eq!(i0.mnemonic, "SETHI");
        assert_eq!(i1.mnemonic, "OR");
    }
}

// ── Stack layout invariants ──────────────────────────────────────────────────

#[test]
#[should_panic]
fn stack_layout_v8_below_96_panics() {
    let _ = SparcStackLayout::new_v8(64);
}

#[test]
#[should_panic]
fn stack_layout_v8_unaligned_panics() {
    let _ = SparcStackLayout::new_v8(100); // not multiple of 8
}

#[test]
#[should_panic]
fn stack_layout_v9_below_128_panics() {
    let _ = SparcStackLayout::new_v9(96);
}

#[test]
#[should_panic]
fn stack_layout_v9_unaligned_panics() {
    let _ = SparcStackLayout::new_v9(136); // not multiple of 16
}

#[test]
fn stack_layout_v8_save_offset_zero() {
    let s = SparcStackLayout::new_v8(96);
    assert_eq!(s.save_area_offset(), 0);
    assert_eq!(s.locals_offset(), 128);
    assert_eq!(s.outgoing_args_offset(), 128);
}

#[test]
fn stack_layout_v9_outgoing_args_offset_includes_bias() {
    let s = SparcStackLayout::new_v9(128);
    assert_eq!(s.outgoing_args_offset(), 2047 + 128);
}

// ── Build sequences ──────────────────────────────────────────────────────────

#[test]
#[should_panic]
fn build_prologue_zero_panics() {
    let _ = build_prologue(0);
}

#[test]
#[should_panic]
fn build_prologue_too_big_panics() {
    let _ = build_prologue(4096);
}

#[test]
#[should_panic]
fn build_prologue_unaligned_panics() {
    let _ = build_prologue(12);
}

#[test]
fn build_prologue_4088_max() {
    // Boundary: 4088 is the documented max.
    let _ = build_prologue(4088);
}

#[test]
fn build_epilogue_decodes_to_restore_nop() {
    let [r, n] = build_epilogue();
    let i0 = arch().disassemble(a(0), &r.to_be_bytes()).unwrap();
    let i1 = arch().disassemble(a(4), &n.to_be_bytes()).unwrap();
    assert_eq!(i0.mnemonic, "RESTORE");
    assert_eq!(i1.mnemonic, "NOP");
}

#[test]
fn build_return_seq_decodes_to_return_nop() {
    let [r, n] = build_return_seq();
    let i0 = arch().disassemble(a(0), &r.to_be_bytes()).unwrap();
    let i1 = arch().disassemble(a(4), &n.to_be_bytes()).unwrap();
    assert_eq!(i0.mnemonic, "RETURN");
    assert_eq!(i1.mnemonic, "NOP");
}

// ── SparcRegSet edge cases ───────────────────────────────────────────────────

#[test]
fn regset_out_of_range_is_noop() {
    let mut rs = SparcRegSet::new();
    rs.add_int(64); // out of range
    rs.add_int(100);
    rs.add_fp(64);
    rs.add_fp(255);
    assert!(rs.is_empty());
    assert!(!rs.contains_int(64));
    assert!(!rs.contains_fp(64));
}

#[test]
fn regset_remove_unset_is_noop() {
    let mut rs = SparcRegSet::new();
    rs.remove_int(5);
    assert!(rs.is_empty());
}

#[test]
fn regset_count_includes_fp() {
    let mut rs = SparcRegSet::new();
    rs.add_int(1);
    rs.add_fp(2);
    rs.add_fp(3);
    assert_eq!(rs.count(), 3);
}

#[test]
fn regset_union_is_commutative() {
    let mut a_ = SparcRegSet::new();
    a_.add_int(0);
    a_.add_fp(0);
    let mut b_ = SparcRegSet::new();
    b_.add_int(1);
    b_.add_fp(1);
    let u1 = a_.union(&b_);
    let u2 = b_.union(&a_);
    assert_eq!(u1, u2);
}

// ── SparcWindowState ─────────────────────────────────────────────────────────

#[test]
fn windowstate_save_overflow_does_not_advance_cwp() {
    let mut w = SparcWindowState::new(8);
    // Mark cwp-1 = 7 as invalid
    w.set_wim_bit(7);
    let before = w.cwp;
    let overflow = w.save();
    assert!(overflow);
    assert_eq!(w.cwp, before, "cwp must not change on overflow");
}

#[test]
fn windowstate_restore_underflow_does_not_advance_cwp() {
    let mut w = SparcWindowState::new(8);
    // Mark cwp+1 = 1 as invalid
    w.set_wim_bit(1);
    let before = w.cwp;
    let underflow = w.restore();
    assert!(underflow);
    assert_eq!(w.cwp, before, "cwp must not change on underflow");
}

#[test]
fn windowstate_set_clear_wim_bit_wraps() {
    let mut w = SparcWindowState::new(8);
    w.set_wim_bit(15); // 15 % 8 = 7
    assert!((w.wim >> 7) & 1 == 1);
    w.clear_wim_bit(7);
    assert!((w.wim >> 7) & 1 == 0);
}

// ── SparcInstrKind classification ────────────────────────────────────────────

#[test]
fn instrkind_call_is_control_flow_and_not_memory() {
    let k = SparcInstrKind::Call;
    assert!(k.is_control_flow());
    assert!(!k.is_memory());
}

#[test]
fn instrkind_load_is_memory_not_control_flow() {
    let k = SparcInstrKind::Load;
    assert!(k.is_memory());
    assert!(!k.is_control_flow());
}

#[test]
fn instrkind_unknown_for_garbage() {
    assert_eq!(
        SparcInstrKind::from_mnemonic("ZZZNOTAREALMNEMONIC"),
        SparcInstrKind::Unknown
    );
}

#[test]
fn instrkind_floatop_for_unrecognised_f_prefix() {
    assert_eq!(
        SparcInstrKind::from_mnemonic("FUNKY"),
        SparcInstrKind::FloatOp
    );
}

#[test]
fn instrkind_branch_annulled_classification() {
    // "BA,a" — `from_mnemonic` strips leading non-alpha, but mnemonic starts with 'B'
    // and isn't "BA" exactly (it's "BA,a"); falls to the starts_with('B') CondBranch arm.
    let k = SparcInstrKind::from_mnemonic("BNE,a");
    assert_eq!(k, SparcInstrKind::CondBranch);
}

// ── identify_idiom edge cases ────────────────────────────────────────────────

#[test]
fn idiom_none_for_plain_add() {
    let enc = encode_alu_reg(0x00, 8, 9, 10).to_be_bytes();
    let i = arch().disassemble(a(0), &enc).unwrap();
    assert_eq!(identify_idiom(&i, None), SparcIdiom::None);
}

#[test]
fn idiom_prologue_for_save_with_sp() {
    // SAVE %sp, -96, %sp: op3=0x3C, rs1=14, simm13=-96, rd=14
    let enc = encode_alu_imm(0x3C, 14, -96, 14).to_be_bytes();
    let i = arch().disassemble(a(0), &enc).unwrap();
    assert_eq!(identify_idiom(&i, None), SparcIdiom::Prologue);
}

#[test]
fn idiom_loadimm_via_or_g0_imm() {
    // OR %g0, 7, %o0
    let enc = encode_alu_imm(0x02, 0, 7, 8).to_be_bytes();
    let i = arch().disassemble(a(0), &enc).unwrap();
    assert_eq!(identify_idiom(&i, None), SparcIdiom::LoadImm);
}

// ── Lookup tables: not-found cases ───────────────────────────────────────────

#[test]
fn lookup_v8_trap_unknown_is_none() {
    assert!(lookup_v8_trap(0xFE).is_none());
}

#[test]
fn lookup_v9_trap_unknown_is_none() {
    assert!(lookup_v9_trap(0xFE).is_none());
}

#[test]
fn lookup_fp_opcode_unknown_is_none() {
    assert!(lookup_fp_opcode(0xFFFF).is_none());
}

#[test]
fn lookup_asi_unknown_is_none() {
    assert!(lookup_asi(0x00).is_none());
}

#[test]
fn lookup_asi_known_primary() {
    let e = lookup_asi(0x80).unwrap();
    assert_eq!(e.description, "ASI_PRIMARY");
    assert!(!e.privileged);
}

#[test]
fn lookup_condition_all_16_present_and_unique() {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for c in 0u8..16 {
        let e = lookup_condition(c).unwrap();
        assert!(seen.insert((e.icc_suffix, e.fcc_suffix)) || (e.icc_suffix == e.fcc_suffix));
    }
    assert_eq!(SPARC_CONDITIONS.len(), 16);
}

#[test]
fn priv_reg_writable_for_pstate() {
    // Field 6 commonly = %pstate (writable). Just check at least one writable reg exists.
    assert!(SPARC_V9_PRIV_REGS.iter().any(|r| r.writable));
    assert!(SPARC_V9_PRIV_REGS.iter().any(|r| !r.writable));
}

// ── Format / printer ─────────────────────────────────────────────────────────

#[test]
fn print_gnu_lowercases() {
    let i = arch()
        .disassemble(a(0), &[0x01, 0x00, 0x00, 0x00])
        .unwrap();
    let s = sparc_print_gnu(&i);
    assert_eq!(s, "nop");
}

#[test]
fn print_sun_preserves_case() {
    let i = arch()
        .disassemble(a(0), &[0x01, 0x00, 0x00, 0x00])
        .unwrap();
    let s = sparc_print_sun(&i);
    assert_eq!(s, "NOP");
}

#[test]
fn print_gnu_with_operands_lowercases_both() {
    let enc = encode_alu_reg(0x00, 8, 9, 10).to_be_bytes();
    let i = arch().disassemble(a(0), &enc).unwrap();
    let s = sparc_print_gnu(&i);
    assert!(s.starts_with("add "));
    assert!(s.contains("%o0"));
}

// ── Statistics ───────────────────────────────────────────────────────────────

#[test]
fn code_stats_counts_nop() {
    let bytes = [0x01u8, 0x00, 0x00, 0x00].repeat(5);
    let s = SparcCodeStats::from_bytes(&arch(), &bytes, a(0));
    assert_eq!(s.total, 5);
    assert_eq!(s.nops, 5);
}

#[test]
fn code_stats_empty_bytes() {
    let s = SparcCodeStats::from_bytes(&arch(), &[], a(0));
    assert_eq!(s.total, 0);
    assert_eq!(s.errors, 0);
}

#[test]
fn code_stats_counts_load() {
    let enc = encode_load(0x00, 14, 4, 8).to_be_bytes();
    let s = SparcCodeStats::from_bytes(&arch(), &enc, a(0));
    assert_eq!(s.loads, 1);
}

#[test]
fn code_stats_counts_call() {
    let enc = encode_call(8).to_be_bytes();
    let s = SparcCodeStats::from_bytes(&arch(), &enc, a(0));
    assert_eq!(s.calls, 1);
}

#[test]
fn raw_mix_empty() {
    let m = SparcRawMix::from_bytes(&[]);
    assert_eq!(m.calls, 0);
    assert_eq!(m.branches, 0);
    assert_eq!(m.sethis, 0);
    assert_eq!(m.alu, 0);
    assert_eq!(m.mem, 0);
}

#[test]
fn raw_mix_ignores_trailing_partial_word() {
    // 5 bytes; only one full word counted.
    let enc = encode_nop().to_be_bytes();
    let mut buf = enc.to_vec();
    buf.push(0xAB);
    let m = SparcRawMix::from_bytes(&buf);
    assert_eq!(m.sethis, 1);
}

#[test]
fn extract_branch_targets_handles_partial_trailing() {
    let mut bytes = encode_call(8).to_be_bytes().to_vec();
    bytes.push(0xFF); // partial trailing byte
    let t = extract_branch_targets(&bytes, 0x1000);
    assert_eq!(t.len(), 1);
    assert_eq!(t[0], (0x1000, 0x1008));
}

#[test]
fn extract_branch_targets_negative_call() {
    // CALL -8
    let enc = encode_call(-8).to_be_bytes();
    let t = extract_branch_targets(&enc, 0x1000);
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].1, 0x0FF8);
}

// ── annotated disassembly + branch resolver ──────────────────────────────────

#[test]
fn disassemble_annotated_handles_partial_trailing() {
    // 5 bytes -> one instr decoded, trailing byte ignored.
    let mut bytes = encode_nop().to_be_bytes().to_vec();
    bytes.push(0xAA);
    let res = disassemble_annotated(&arch(), &bytes, a(0)).unwrap();
    assert_eq!(res.len(), 1);
}

#[test]
fn disassemble_annotated_empty() {
    let res = disassemble_annotated(&arch(), &[], a(0)).unwrap();
    assert!(res.is_empty());
}

#[test]
fn resolve_branches_empty_for_no_branches() {
    let nops = [encode_nop().to_be_bytes(); 3].concat();
    let annotated = disassemble_annotated(&arch(), &nops, a(0)).unwrap();
    let br = resolve_branches(&annotated);
    assert!(br.is_empty());
}

#[test]
fn format_annotated_includes_address() {
    let bytes = encode_nop().to_be_bytes();
    let ai = disassemble_annotated(&arch(), &bytes, a(0xABCD0)).unwrap();
    let s = format_annotated(&ai[0]);
    assert!(s.contains("000abcd0"));
}

#[test]
fn annotated_from_instr_nop_has_no_delay_slot() {
    let i = arch()
        .disassemble(a(0), &encode_nop().to_be_bytes())
        .unwrap();
    let ai = AnnotatedSparcInstr::from_instr(i);
    assert!(!ai.delay.has_delay_slot);
}

#[test]
fn annotated_from_instr_call_has_delay_slot() {
    let i = arch()
        .disassemble(a(0), &encode_call(4).to_be_bytes())
        .unwrap();
    let ai = AnnotatedSparcInstr::from_instr(i);
    assert!(ai.delay.has_delay_slot);
}

// ── delay-slot module ────────────────────────────────────────────────────────

#[test]
fn delay_analyze_branch_returns_none_on_add() {
    // Plain ADD (op=10) is not a branch.
    let add = (0b10u32 << 30) | (0u32 << 19);
    assert!(analyze_branch(0, add, 0).is_none());
}

#[test]
fn delay_analyze_call_kind() {
    let call = encode_call(8);
    let ds = analyze_branch(0x1000, call, 0x0100_0000).unwrap();
    assert_eq!(ds.kind, BranchKind::Call);
    assert_eq!(ds.target_pc, 0x1008);
    assert!(ds.delay_is_nop);
}

#[test]
fn delay_negate_involutive_for_all_conditions() {
    for c in [
        DSCond::Equal,
        DSCond::NotEqual,
        DSCond::Less,
        DSCond::GreaterOrEqual,
        DSCond::LessOrEqual,
        DSCond::Greater,
        DSCond::Always,
        DSCond::Never,
        DSCond::CarrySet,
        DSCond::CarryClear,
        DSCond::Negative,
        DSCond::PositiveOrZero,
        DSCond::OverflowSet,
        DSCond::OverflowClear,
        DSCond::LessOrEqualUnsigned,
        DSCond::GreaterUnsigned,
    ] {
        assert_eq!(c.negate().negate(), c, "double-negate failed for {c:?}");
    }
}

#[test]
fn delay_effect_for_call_is_always_executes_no_annul() {
    let call = encode_call(4);
    let ds = analyze_branch(0, call, 0x0100_0000).unwrap();
    assert_eq!(ds.effect(), DelayEffect::AlwaysExecutesNoAnnul);
}

#[test]
fn delay_is_useful_when_not_nop() {
    let bicc = encode_bicc(8, false, 4);
    // delay slot = ADD %g0,%g0,%g0 = 0x80100000
    let add = encode_alu_reg(0x00, 0, 0, 0);
    let ds = analyze_branch(0, bicc, add).unwrap();
    assert!(ds.is_useful_delay());
}

#[test]
fn delay_summary_contains_branch_pc() {
    let bicc = encode_bicc(8, false, 4);
    let ds = analyze_branch(0xABCD, bicc, 0x0100_0000).unwrap();
    let s = ds.summary();
    assert!(s.contains("0x0000abcd"));
}

#[test]
fn delay_scanner_finds_bicc_in_pair() {
    // BA +4 followed by NOP
    let mut bytes = encode_bicc(8, false, 4).to_be_bytes().to_vec();
    bytes.extend_from_slice(&encode_nop().to_be_bytes());
    let sc = DelaySlotScanner::new();
    let res = sc.scan(&bytes, 0);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].kind, BranchKind::IntCondBranch);
}

#[test]
fn delay_scanner_filters_nop_delays_when_disabled() {
    let mut bytes = encode_bicc(8, false, 4).to_be_bytes().to_vec();
    bytes.extend_from_slice(&encode_nop().to_be_bytes());
    let mut sc = DelaySlotScanner::new();
    sc.report_nop_delays = false;
    let res = sc.scan(&bytes, 0);
    assert!(res.is_empty());
}

#[test]
fn delay_nop_branches_only_returns_nop_delays() {
    // Two pairs: one with NOP delay, one with ADD delay.
    let mut bytes = encode_bicc(8, false, 4).to_be_bytes().to_vec();
    bytes.extend_from_slice(&encode_nop().to_be_bytes()); // pair 1: NOP delay
    bytes.extend_from_slice(&encode_bicc(8, false, 4).to_be_bytes());
    bytes.extend_from_slice(&encode_alu_reg(0x00, 0, 0, 0).to_be_bytes()); // pair 2: ADD delay
    let sc = DelaySlotScanner::new();
    let res = sc.nop_delay_branches(&bytes, 0);
    assert!(res.iter().all(|d| d.delay_is_nop));
    assert!(!res.is_empty());
}

#[test]
fn delay_annul_from_word_bit29() {
    assert_eq!(AnnulBit::from_word(1 << 29), AnnulBit::Set);
    assert_eq!(AnnulBit::from_word(0), AnnulBit::NotSet);
    // Other bits set but not bit29.
    assert_eq!(AnnulBit::from_word(!(1u32 << 29)), AnnulBit::NotSet);
}

#[test]
fn delay_branchcondition_unconditional() {
    assert!(DSCond::Always.is_unconditional());
    assert!(DSCond::Never.is_unconditional());
    assert!(!DSCond::Equal.is_unconditional());
}

#[test]
fn delay_evaluate_matrix() {
    assert!(DelayEffect::evaluate(AnnulBit::NotSet, true));
    assert!(DelayEffect::evaluate(AnnulBit::NotSet, false));
    assert!(DelayEffect::evaluate(AnnulBit::Set, true));
    assert!(!DelayEffect::evaluate(AnnulBit::Set, false));
}

#[test]
fn delay_is_nop_recognises_canonical_nop_only() {
    assert!(sparc_delay_slot::is_nop(0x0100_0000));
    assert!(!sparc_delay_slot::is_nop(0));
    assert!(!sparc_delay_slot::is_nop(0x0100_0001));
}

// ── register_windows module ──────────────────────────────────────────────────

#[test]
fn rw_total_physical_regs() {
    assert_eq!(total_physical_regs(8), 136);
    assert_eq!(total_physical_regs(2), 40);
    assert_eq!(total_physical_regs(32), 520);
}

#[test]
fn rw_register_class_prefix_all_variants() {
    assert_eq!(RegisterClass::Global.prefix(), "%g");
    assert_eq!(RegisterClass::Out.prefix(), "%o");
    assert_eq!(RegisterClass::Local.prefix(), "%l");
    assert_eq!(RegisterClass::In.prefix(), "%i");
    assert_eq!(RegisterClass::Float.prefix(), "%f");
    assert_eq!(RegisterClass::Special.prefix(), "%s");
}

#[test]
fn rw_sparcreg_from_str_invalid() {
    assert!(srw::SparcReg::from_str("%xyz").is_none());
    assert!(srw::SparcReg::from_str("%z0").is_none());
    assert!(srw::SparcReg::from_str("%i").is_none());
}

#[test]
fn rw_sparcreg_display_matches_name() {
    let r = srw::SparcReg {
        class: RegisterClass::In,
        number: 7,
    };
    assert_eq!(format!("{r}"), "%i7");
    assert_eq!(r.name(), "%i7");
}

#[test]
fn rw_as_caller_input_only_for_out() {
    let o = srw::SparcReg {
        class: RegisterClass::Out,
        number: 3,
    };
    assert_eq!(
        o.as_caller_input().unwrap(),
        srw::SparcReg {
            class: RegisterClass::In,
            number: 3
        }
    );
    let g = srw::SparcReg {
        class: RegisterClass::Global,
        number: 0,
    };
    assert!(g.as_caller_input().is_none());
}

#[test]
fn rw_as_callee_output_only_for_in() {
    let i = srw::SparcReg {
        class: RegisterClass::In,
        number: 1,
    };
    assert_eq!(
        i.as_callee_output().unwrap(),
        srw::SparcReg {
            class: RegisterClass::Out,
            number: 1
        }
    );
    let l = srw::SparcReg {
        class: RegisterClass::Local,
        number: 0,
    };
    assert!(l.as_callee_output().is_none());
}

#[test]
fn rw_window_entry_input_local_bounds() {
    let mut w = WindowEntry::empty(0, 0);
    w.inputs[2] = Some(42);
    w.locals[5] = Some(100);
    assert_eq!(w.input(2), Some(42));
    assert_eq!(w.input(8), None); // out of range
    assert_eq!(w.local(5), Some(100));
    assert_eq!(w.local(99), None);
}

#[test]
fn rw_window_entry_return_addr_overflow_wraps() {
    let mut w = WindowEntry::empty(0, 0);
    w.inputs[7] = Some(u32::MAX - 4);
    // return_addr = u32::MAX - 4 + 8 should wrap.
    assert_eq!(w.return_addr(), Some(3));
}

#[test]
fn rw_apply_save_then_restore_balance() {
    let mut m = SparcRegisterWindow::new(8);
    let depth0 = m.depth();
    m.apply_save(0x1000);
    assert_eq!(m.depth(), depth0 + 1);
    m.apply_restore(0x1004);
    assert_eq!(m.depth(), depth0);
}

#[test]
fn rw_apply_save_overflow_detected_on_first_save() {
    // On `new(8)`, wim=1 (window 0 invalid). cwp=0; save → new_cwp = (0-1) % 8.
    // In Rust, 0u8.wrapping_sub(1) = 255; 255 % 8 = 7. wim bit 7 = 0 so no overflow.
    // To force overflow on first save: set wim bit 7.
    let mut m = SparcRegisterWindow::new(8);
    m.wim = 1u32 << 7;
    let ovf = m.apply_save(0x1000);
    assert!(ovf);
    assert_eq!(m.overflow_count(), 1);
}

#[test]
fn rw_call_chain_pcs_innermost_first() {
    let mut m = SparcRegisterWindow::new(8);
    m.apply_save(0x1000);
    m.apply_save(0x2000);
    m.apply_save(0x3000);
    let chain = m.call_chain_pcs();
    assert_eq!(chain, vec![0x3000, 0x2000, 0x1000]);
}

#[test]
fn rw_is_window_valid_reflects_wim() {
    let mut m = SparcRegisterWindow::new(8);
    m.wim = 0b0000_0100;
    assert!(!m.is_window_valid(2));
    assert!(m.is_window_valid(3));
}

#[test]
fn rw_is_save_is_restore_for_zero_word() {
    // Zero word: op=00. Neither SAVE nor RESTORE.
    assert!(!is_save(0));
    assert!(!is_restore(0));
}

#[test]
fn rw_classify_window_instrs_assigns_pc_by_index() {
    let save = (0b10u32 << 30) | (0x3C << 19);
    let words = vec![save, 0, save];
    let cls = classify_window_instrs(&words);
    assert_eq!(cls.len(), 3);
    if let WindowInstr::Save { pc } = cls[0] {
        assert_eq!(pc, 0);
    } else {
        panic!("expected Save");
    }
    if let WindowInstr::Other { pc } = cls[1] {
        assert_eq!(pc, 4);
    } else {
        panic!("expected Other");
    }
    if let WindowInstr::Save { pc } = cls[2] {
        assert_eq!(pc, 8);
    } else {
        panic!("expected Save");
    }
}

#[test]
fn rw_save_restore_analysis_empty() {
    let r = save_restore_analysis(&[], 8);
    assert_eq!(r.save_count, 0);
    assert_eq!(r.restore_count, 0);
    assert!(r.is_balanced);
}

#[test]
fn rw_save_restore_analysis_nested() {
    let instrs = vec![
        WindowInstr::Save { pc: 0 },
        WindowInstr::Save { pc: 4 },
        WindowInstr::Restore { pc: 8 },
        WindowInstr::Restore { pc: 12 },
    ];
    let r = save_restore_analysis(&instrs, 8);
    assert!(r.is_balanced);
    assert_eq!(r.max_depth, 2);
}

#[test]
fn rw_windowstats_from_empty_model() {
    let m = SparcRegisterWindow::new(8);
    let s = WindowStats::from_model(&m);
    assert_eq!(s.depth, 0);
    assert_eq!(s.overflow_count, 0);
    assert_eq!(s.nwindows, 8);
    // valid_windows: all except window 0 (initial wim=1).
    assert_eq!(s.valid_windows.len(), 7);
}

#[test]
fn rw_windowstats_cwp_histogram() {
    let mut m = SparcRegisterWindow::new(8);
    m.apply_save(0);
    m.apply_save(4);
    let h = WindowStats::cwp_histogram(&m);
    assert_eq!(h.values().sum::<usize>(), 2);
}

// ── trap_table module ────────────────────────────────────────────────────────

#[test]
fn tt_v8_has_reset_window_traps() {
    let t = sparc_v8_trap_table();
    assert_eq!(t.by_tt(0).unwrap().name, "reset");
    assert!(t.by_tt(0x05).unwrap().kind == TrapKind::WindowOverflow);
}

#[test]
fn tt_v8_software_traps_128() {
    let t = sparc_v8_trap_table();
    assert_eq!(t.software_traps().len(), 128);
}

#[test]
fn tt_v8_interrupts_15() {
    let t = sparc_v8_trap_table();
    assert_eq!(t.interrupts().len(), 15);
}

#[test]
fn tt_trap_name_v8_unknown_returns_none() {
    // tt = 0x10 isn't in our v8 table (interrupts start at 0x11).
    assert!(trap_name(0x10).is_none());
}

#[test]
fn tt_trap_name_v9_clean_windows() {
    assert_eq!(trap_name_v9(0x0C).as_deref(), Some("clean_windows"));
}

#[test]
fn tt_v9_overrides_v8_div_by_zero_tt0c() {
    // v8 has DivisionByZero at 0x0C; v9 replaces with CleanWindows. Verify.
    let v8 = sparc_v8_trap_table();
    let v9 = sparc_v9_trap_table();
    assert_eq!(v8.by_tt(0x0C).unwrap().kind, TrapKind::DivisionByZero);
    assert_eq!(v9.by_tt(0x0C).unwrap().kind, TrapKind::CleanWindows);
}

#[test]
fn tt_trapkind_label_variants() {
    assert_eq!(TrapKind::Reset.label(), "reset");
    assert_eq!(TrapKind::SoftwareTrap(7).label(), "swt_7");
    assert_eq!(TrapKind::Interrupt(15).label(), "irq_15");
}

#[test]
fn tt_trapkind_synchronous_vs_interrupt() {
    assert!(TrapKind::WindowOverflow.is_synchronous());
    assert!(!TrapKind::Reset.is_synchronous());
    assert!(TrapKind::Interrupt(3).is_interrupt());
    assert!(!TrapKind::Reset.is_interrupt());
}

#[test]
fn tt_handler_addr_masks_low_12_bits_of_tbr() {
    let t = sparc_v8_trap_table();
    let e = t.by_tt(0x05).unwrap();
    // table_offset = 0x50; tbr low bits should be ignored.
    let tbr = 0xAABB_CFFFu32; // low 12 = 0xFFF
    let h = e.handler_addr(tbr);
    assert_eq!(h & 0xFFF, 0x050);
    assert_eq!(h & 0xFFFF_F000, 0xAABB_C000);
}

#[test]
fn tt_by_name_is_case_insensitive() {
    let t = sparc_v8_trap_table();
    assert!(t.by_name("RESET").is_some());
    assert!(t.by_name("Reset").is_some());
}

#[test]
fn tt_v8_map_size_matches_table() {
    let t = sparc_v8_trap_table();
    let m = sparc_v8_trap_map();
    // Map keys are unique tt; table may have unique tt too because builder iterates unique tt.
    assert_eq!(m.len(), t.len());
}

#[test]
fn tt_v9_map_contains_data_access_prot() {
    assert!(sparc_v9_trap_map().contains_key(&0x28));
}

#[test]
fn tt_handler_scanner_with_no_tbr_finds_sethi() {
    // A real SETHI %hi(0x100), %o0 should be recognised as a SETHI by any
    // correct heuristic. SPARC SETHI: op=00, op2=0b100; rd is free.
    let sethi = encode_sethi(8, 0x100).to_be_bytes();
    let sc = TrapHandlerScanner::new(None);
    let hits = sc.scan(&sethi, 0);
    assert_eq!(
        hits.len(),
        1,
        "scanner failed to detect SETHI with rd!=0 (heuristic only matches rd==16,17,18,19)"
    );
}

// ── Cross-module: linear sweep matches stats vs raw_mix ──────────────────────

#[test]
fn cross_stats_call_matches_raw_mix() {
    let bytes: Vec<u8> = [encode_nop(), encode_call(4), encode_nop()]
        .iter()
        .flat_map(|w| w.to_be_bytes())
        .collect();
    let s = SparcCodeStats::from_bytes(&arch(), &bytes, a(0));
    let m = SparcRawMix::from_bytes(&bytes);
    assert_eq!(s.calls as u64, m.calls);
    assert_eq!(s.total, 3);
}

// ── Synth round-trips: every synth fn decodes to a sensible mnemonic ────────

#[test]
fn synth_helpers_decode_correctly() {
    let a_ = arch();
    let cases: Vec<(u32, &str)> = vec![
        (synth_mov_imm(7, 8), "OR"),
        (synth_mov_reg(8, 9), "OR"),
        (synth_clr(8), "OR"),
        (synth_not(8, 9), "XNOR"),
        (synth_neg(8, 9), "SUB"),
        (synth_tst(8), "ORCC"),
        (synth_cmp_reg(8, 9), "SUBCC"),
        (synth_cmp_imm(8, 7), "SUBCC"),
        (synth_inc(8), "ADD"),
        (synth_dec(8), "SUB"),
        (encode_jmpl(31, 8, 0), "RETURN"),
    ];
    for (enc, expect) in cases {
        let i = a_.disassemble(a(0), &enc.to_be_bytes()).unwrap();
        assert_eq!(i.mnemonic, expect, "encoding {enc:#x}");
    }
}

// ── Concurrency: SparcArch is Send + Sync ────────────────────────────────────

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn arch_is_send_sync() {
    assert_send_sync::<SparcArch>();
    assert_send_sync::<SparcRegSet>();
    assert_send_sync::<SparcWindowState>();
    assert_send_sync::<SparcStackLayout>();
    assert_send_sync::<SparcRegisterWindow>();
    assert_send_sync::<SparcDelaySlot>();
}

// ── Tables exposed as pub static: basic structural invariants ────────────────

#[test]
fn tables_have_unique_keys() {
    use std::collections::HashSet;
    // V8 traps unique by number.
    let mut s = HashSet::new();
    for e in SPARC_V8_TRAPS {
        assert!(s.insert(e.number), "duplicate v8 trap {:#x}", e.number);
    }
    s.clear();
    for e in SPARC_V9_TRAPS {
        assert!(s.insert(e.number), "duplicate v9 trap {:#x}", e.number);
    }
    // FP opcodes unique.
    let mut s16: HashSet<u16> = HashSet::new();
    for e in SPARC_FP_OPCODES {
        assert!(s16.insert(e.opf), "duplicate opf {:#x}", e.opf);
    }
    // ASIs unique.
    let mut s8: HashSet<u8> = HashSet::new();
    for e in SPARC_ASI_TABLE {
        assert!(s8.insert(e.asi), "duplicate asi {:#x}", e.asi);
    }
    // Priv regs unique by field.
    s8.clear();
    for e in SPARC_V9_PRIV_REGS {
        assert!(s8.insert(e.field), "duplicate priv reg {:#x}", e.field);
    }
    // Conditions unique by code.
    s8.clear();
    for e in SPARC_CONDITIONS {
        assert!(s8.insert(e.code), "duplicate cond {:#x}", e.code);
    }
}

#[test]
fn sparc_formats_three_entries() {
    assert_eq!(SPARC_FORMATS.len(), 3);
}

#[test]
fn sparc_arg_tables_consistent_sizes() {
    assert_eq!(SPARC_V8_INT_ARGS.len(), 6);
    assert!(SPARC_V9_INT_ARGS.len() >= 6);
    assert_eq!(SPARC_V9_FP_ARGS.len(), 16);
    assert!(SPARC_V9_FP_ARGS.iter().all(|a_| a_.is_float));
    assert!(!SPARC_V8_INT_ARGS.iter().any(|a_| a_.is_float));
}

#[test]
fn fp_opcodes_have_nonempty_mnemonic() {
    for e in SPARC_FP_OPCODES {
        assert!(!e.mnemonic.is_empty());
    }
}

#[test]
fn asi_entries_have_nonempty_description() {
    for e in SPARC_ASI_TABLE {
        assert!(!e.description.is_empty());
        // Cross-check lookup_asi
        let look: &SparcAsiEntry = lookup_asi(e.asi).unwrap();
        assert_eq!(look.asi, e.asi);
    }
}

// ── Registers() result contains program counter ──────────────────────────────

#[test]
fn arch_registers_v8_has_pc_psr_y() {
    let regs = arch().registers();
    let names: Vec<_> = regs.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"%pc"));
    assert!(names.contains(&"%psr"));
    assert!(names.contains(&"%y"));
    assert!(names.contains(&"%g0"));
    assert!(names.contains(&"%sp"));
    assert!(names.contains(&"%fp"));
}

#[test]
fn arch_registers_v9_has_more_fp_than_v8() {
    let v8 = SparcArch::new_v8().registers().len();
    let v9 = SparcArch::new_v9().registers().len();
    assert!(v9 > v8, "v9 ({v9}) should have more registers than v8 ({v8})");
}

// ── Calling conventions ──────────────────────────────────────────────────────

#[test]
fn arch_calling_conv_sparc_sysv() {
    let cc = arch().calling_conventions();
    assert!(!cc.is_empty());
    assert_eq!(cc[0].name, "sparc_sysv");
}

// ── get_branches: call target hex parsing ────────────────────────────────────

#[test]
fn get_branches_for_call_returns_target() {
    let enc = encode_call(8).to_be_bytes();
    let i = arch().disassemble(a(0x1000), &enc).unwrap();
    let br = arch().get_branches(&i);
    assert_eq!(br.len(), 1);
}

#[test]
fn get_branches_for_nop_empty() {
    let i = arch()
        .disassemble(a(0), &encode_nop().to_be_bytes())
        .unwrap();
    assert!(arch().get_branches(&i).is_empty());
}

#[test]
fn get_branches_for_return_empty() {
    let enc = encode_jmpl(31, 8, 0).to_be_bytes();
    let i = arch().disassemble(a(0), &enc).unwrap();
    assert!(i.flags.contains(InstrFlags::RET));
    assert!(arch().get_branches(&i).is_empty());
}
