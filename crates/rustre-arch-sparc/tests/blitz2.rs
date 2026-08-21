//! Y004 deep adversarial test suite for `rustre-arch-sparc`.

use rustre_core::arch::Architecture;
use rustre_arch_sparc::sparc_delay_slot::{
    analyze_branch, is_nop, AnnulBit, BranchCondition as DSCond, BranchKind,
};
use rustre_arch_sparc::sparc_trap_table::{
    sparc_v8_trap_map, sparc_v8_trap_table, sparc_v9_trap_map, sparc_v9_trap_table, trap_name,
    trap_name_v9,
};
use rustre_arch_sparc::sparc_v9::{decode_v9_instr, roundtrip_flushw, roundtrip_mulx, V9Encoder};
use rustre_arch_sparc::*;
use rustre_core::address::Address;

fn mk_lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn arch() -> SparcArch {
    SparcArch::default()
}

// ── Encoder round-trips ──────────────────────────────────────────────────────

#[test]
fn encode_call_disp_roundtrip_positive() {
    for d in (0..200i32).map(|i| i * 4) {
        let w = encode_call(d);
        assert_eq!(w >> 30, 1, "CALL fmt bits");
        let targets = extract_branch_targets(&w.to_be_bytes(), 0);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].1, u64::from(d.cast_unsigned()));
    }
}

#[test]
fn encode_call_disp_negative() {
    // negative aligned displacements
    for d in (-200..0).step_by(4) {
        let w = encode_call(d);
        let targets = extract_branch_targets(&w.to_be_bytes(), 0x1_0000);
        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].1,
            (0x1_0000u64).wrapping_add((i64::from(d)).cast_unsigned())
        );
    }
}

#[test]
#[should_panic(expected = "CALL displacement must be 4-byte aligned")]
fn encode_call_unaligned_panics() {
    let _ = encode_call(3);
}

/// Duplicate of the same case in `blitz.rs` — `encode_bicc` aligns down rather
/// than panicking (lib.rs:1584), so the old `#[should_panic]` demanded a panic
/// that no longer happens. Note this copy used a BARE `#[should_panic]` with no
/// `expected =` message, so it would have passed on ANY panic from anywhere in
/// the call — weaker than the blitz.rs copy and worth not restoring in that form.
#[test]
fn encode_bicc_unaligned_aligns_down() {
    // disp = 3 -> 3 & !3 = 0, identical encoding to disp = 0.
    assert_eq!(encode_bicc(8, false, 3), encode_bicc(8, false, 0));
}

#[test]
fn encode_sethi_format_bits() {
    for rd in 0..32u32 {
        for imm in [0u32, 1, 0x3F_FFFF, 0x12_3456] {
            let w = encode_sethi(rd, imm);
            assert_eq!((w >> 22) & 7, 0b100);
            assert_eq!((w >> 25) & 31, rd);
            assert_eq!(w & 0x3F_FFFF, imm & 0x3F_FFFF);
        }
    }
}

#[test]
fn encode_nop_is_sethi_g0_0() {
    assert_eq!(encode_nop(), 0x0100_0000);
    assert!(is_nop(encode_nop()));
}

#[test]
fn encode_alu_reg_format() {
    for rd in 0..32u32 {
        let w = encode_alu_reg(0x00, 1, 2, rd);
        assert_eq!(w >> 30, 0b10);
        assert_eq!((w >> 25) & 31, rd);
        assert_eq!((w >> 19) & 63, 0);
        assert_eq!((w >> 14) & 31, 1);
        assert_eq!((w >> 13) & 1, 0); // i bit clear
        assert_eq!(w & 31, 2);
    }
}

#[test]
fn encode_alu_imm_sets_i_bit() {
    let w = encode_alu_imm(0x00, 1, 5, 8);
    assert_eq!((w >> 13) & 1, 1);
    assert_eq!(w & 0x1FFF, 5);
}

#[test]
fn encode_alu_imm_negative_simm13_lowbits() {
    let w = encode_alu_imm(0x04, 1, -1, 8);
    // -1 occupies all 13 bits
    assert_eq!(w & 0x1FFF, 0x1FFF);
}

#[test]
fn encode_load_store_alias() {
    // encode_store currently delegates to encode_load
    assert_eq!(encode_load(0x00, 8, 16, 9), encode_store(0x00, 8, 16, 9));
}

#[test]
fn encode_jmpl_is_alu_imm_38() {
    let w = encode_jmpl(31, 8, 0);
    assert_eq!((w >> 19) & 63, 0x38);
    assert_eq!((w >> 14) & 31, 31);
    assert_eq!((w >> 13) & 1, 1);
}

#[test]
fn build_prologue_returns_save_encoding() {
    let p = build_prologue(96);
    // SAVE = op=10, op3=0x3C
    assert_eq!(p >> 30, 0b10);
    assert_eq!((p >> 19) & 63, 0x3C);
}

#[test]
#[should_panic(expected = "framesize must be a multiple of 8")]
fn build_prologue_zero_panics() {
    let _ = build_prologue(0);
}

#[test]
#[should_panic(expected = "framesize must be a multiple of 8")]
fn build_prologue_misaligned_panics() {
    let _ = build_prologue(9);
}

#[test]
#[should_panic(expected = "framesize must be a multiple of 8")]
fn build_prologue_too_large_panics() {
    let _ = build_prologue(4096);
}

#[test]
fn build_epilogue_two_words() {
    let e = build_epilogue();
    assert_eq!(e.len(), 2);
    assert_eq!(e[1], encode_nop());
}

#[test]
fn build_return_seq_uses_jmpl_i7_8() {
    let r = build_return_seq();
    // JMPL %i7+8, %g0 then NOP
    assert_eq!((r[0] >> 19) & 63, 0x38);
    assert_eq!((r[0] >> 14) & 31, 31);
    assert_eq!(r[1], encode_nop());
}

// ── Synthetic instruction helpers ────────────────────────────────────────────

#[test]
fn synth_mov_imm_boundaries() {
    let _ = synth_mov_imm(0, 8);
    let _ = synth_mov_imm(4095, 8);
    let _ = synth_mov_imm(-4096, 8);
}

#[test]
#[should_panic(expected = "out of 13-bit range")]
fn synth_mov_imm_overflow_high() {
    let _ = synth_mov_imm(4096, 8);
}

#[test]
#[should_panic(expected = "out of 13-bit range")]
fn synth_mov_imm_overflow_low() {
    let _ = synth_mov_imm(-4097, 8);
}

#[test]
fn synth_set_small_one_word() {
    let v = synth_set(0, 8);
    assert_eq!(v.len(), 1);
    let v2 = synth_set(4095, 8);
    assert_eq!(v2.len(), 1);
}

#[test]
fn synth_set_large_two_words() {
    let v = synth_set(0x1234_5678, 8);
    assert_eq!(v.len(), 2);
    // SETHI then OR
    assert_eq!((v[0] >> 22) & 7, 0b100);
    assert_eq!((v[1] >> 19) & 63, 0x02);
}

#[test]
fn synth_set_max_u32() {
    // u32::MAX as i32 == -1, which fits in signed 13-bit range, so a single
    // `MOV -1, %rd` is emitted (sign-extends to all 1s). This is correct.
    let v = synth_set(u32::MAX, 8);
    assert_eq!(v.len(), 1);
    // A value that genuinely needs both hi22 and lo10 still produces 2 words.
    let v2 = synth_set(0x8000_0000, 8);
    assert_eq!(v2.len(), 2);
}

#[test]
fn synth_clr_neg_inc_dec_round_trip_decode() {
    let a = arch();
    let ad = Address::new(0);
    for &(w, mn) in &[
        (synth_clr(8), "OR"),
        (synth_not(8, 9), "XNOR"),
        (synth_neg(8, 9), "SUB"),
        (synth_tst(8), "ORCC"),
        (synth_cmp_reg(8, 9), "SUBCC"),
        (synth_inc(8), "ADD"),
        (synth_dec(8), "SUB"),
        (synth_mov_reg(8, 9), "OR"),
    ] {
        let bytes = w.to_be_bytes();
        let ins = a.disassemble(ad, &bytes).unwrap();
        assert_eq!(ins.mnemonic, mn, "word={w:08x}");
    }
}

#[test]
#[should_panic(expected = "out of 13-bit range")]
fn synth_cmp_imm_overflow_panics() {
    let _ = synth_cmp_imm(8, 5000);
}

// ── SparcArch ────────────────────────────────────────────────────────────────

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

#[test]
fn arch_disasm_truncated_errors() {
    let a = arch();
    let r = a.disassemble(Address::new(0), &[0u8, 0u8, 0u8]);
    assert!(r.is_err());
}

#[test]
fn arch_disasm_nop_ok() {
    let a = arch();
    let r = a.disassemble(Address::new(0), &encode_nop().to_be_bytes()).unwrap();
    // NOP is SETHI %g0,0 in SPARC
    assert!(r.size > 0);
}

#[test]
fn arch_registers_v8_count() {
    let regs = SparcArch::new_v8().registers();
    // 32 int + 32 fp + pc, npc, psr, wim, tbr, y
    assert_eq!(regs.len(), 32 + 32 + 6);
}

#[test]
fn arch_registers_v9_count() {
    let regs = SparcArch::new_v9().registers();
    // 32 int + 64 fp + 6 system
    assert_eq!(regs.len(), 32 + 64 + 6);
}

#[test]
fn arch_calling_convs_nonempty() {
    let ccs = SparcArch::new_v8().calling_conventions();
    assert!(!ccs.is_empty());
}

// ── Linear disassembler ──────────────────────────────────────────────────────

#[test]
fn linear_disasm_lcg_words_never_panics() {
    let mut g = mk_lcg();
    let mut buf = Vec::with_capacity(4 * 200);
    for _ in 0..200 {
        let w = crate::sparc_narrow::low_u32_of_u64(g()).to_be_bytes();
        buf.extend_from_slice(&w);
    }
    let a = arch();
    let dis = SparcLinearDisassembler::new(&a, &buf, Address::new(0));
    let mut count = 0;
    for r in dis {
        if r.is_ok() {
            count += 1;
        }
    }
    assert!(count > 0);
}

#[test]
fn linear_disasm_empty() {
    let a = arch();
    let dis = SparcLinearDisassembler::new(&a, &[], Address::new(0));
    assert_eq!(dis.count(), 0);
}

#[test]
fn linear_disasm_3byte_buffer_no_panic() {
    let a = arch();
    let bytes = [0u8, 0, 0];
    let dis = SparcLinearDisassembler::new(&a, &bytes, Address::new(0));
    let _ = dis.count();
}

// ── Instruction kinds ────────────────────────────────────────────────────────

#[test]
fn instr_kind_classification() {
    assert_eq!(SparcInstrKind::from_mnemonic("NOP"), SparcInstrKind::Nop);
    assert_eq!(SparcInstrKind::from_mnemonic("ADD"), SparcInstrKind::IntAlu);
    assert_eq!(
        SparcInstrKind::from_mnemonic("UMUL"),
        SparcInstrKind::Multiply
    );
    assert_eq!(
        SparcInstrKind::from_mnemonic("UDIV"),
        SparcInstrKind::Divide
    );
    assert_eq!(SparcInstrKind::from_mnemonic("LD"), SparcInstrKind::Load);
    assert_eq!(SparcInstrKind::from_mnemonic("ST"), SparcInstrKind::Store);
    assert_eq!(SparcInstrKind::from_mnemonic("CALL"), SparcInstrKind::Call);
    assert_eq!(
        SparcInstrKind::from_mnemonic("RETURN"),
        SparcInstrKind::Return
    );
    assert_eq!(
        SparcInstrKind::from_mnemonic("SAVE"),
        SparcInstrKind::WindowOp
    );
    assert_eq!(
        SparcInstrKind::from_mnemonic("BA"),
        SparcInstrKind::Branch
    );
}

#[test]
fn instr_kind_predicates() {
    assert!(SparcInstrKind::Call.is_control_flow());
    assert!(SparcInstrKind::Branch.is_control_flow());
    assert!(SparcInstrKind::Return.is_control_flow());
    assert!(!SparcInstrKind::IntAlu.is_control_flow());
    assert!(SparcInstrKind::Load.is_memory());
    assert!(SparcInstrKind::Store.is_memory());
    assert!(!SparcInstrKind::IntAlu.is_memory());
}

#[test]
fn instr_kind_unknown_for_garbage() {
    assert_eq!(
        SparcInstrKind::from_mnemonic("ZZZZ"),
        SparcInstrKind::Unknown
    );
}

// ── Window state ─────────────────────────────────────────────────────────────

#[test]
fn window_state_save_restore_no_overflow() {
    let mut ws = SparcWindowState::new(8);
    assert_eq!(ws.cwp, 0);
    let overflow = ws.save();
    assert!(!overflow);
    assert_eq!(ws.cwp, 7); // decremented mod 8
    let underflow = ws.restore();
    assert!(!underflow);
    assert_eq!(ws.cwp, 0);
}

#[test]
fn window_state_wim_traps_save() {
    let mut ws = SparcWindowState::new(8);
    ws.set_wim_bit(7); // next save target is 7
    let overflow = ws.save();
    assert!(overflow);
    assert_eq!(ws.cwp, 0, "cwp must not advance on trap");
}

#[test]
fn window_state_set_and_clear_wim() {
    let mut ws = SparcWindowState::new(8);
    ws.set_wim_bit(3);
    assert_ne!(ws.wim & (1 << 3), 0);
    ws.clear_wim_bit(3);
    assert_eq!(ws.wim & (1 << 3), 0);
}

// ── Lookup tables ────────────────────────────────────────────────────────────

#[test]
fn lookup_v8_trap_present() {
    assert!(lookup_v8_trap(0x00).is_some());
    assert_eq!(lookup_v8_trap(0x02).unwrap().description, "illegal_instruction");
}

#[test]
fn lookup_v8_trap_missing_returns_none() {
    // 0xAA is a software trap region not in the static V8 table
    assert!(lookup_v8_trap(0xAA).is_none());
}

#[test]
fn lookup_v9_trap_present() {
    assert!(lookup_v9_trap(0x00).is_some());
}

#[test]
fn lookup_fp_opcode_known() {
    assert_eq!(lookup_fp_opcode(0x041).unwrap().mnemonic, "FADDS");
    assert_eq!(lookup_fp_opcode(0x001).unwrap().mnemonic, "FMOVS");
}

#[test]
fn lookup_fp_opcode_unknown_none() {
    assert!(lookup_fp_opcode(0xFFFF).is_none());
}

#[test]
fn lookup_asi_known() {
    assert_eq!(lookup_asi(0x80).unwrap().description, "ASI_PRIMARY");
    assert!(!lookup_asi(0x80).unwrap().privileged);
    assert!(lookup_asi(0x04).unwrap().privileged);
}

#[test]
fn lookup_asi_unknown_none() {
    assert!(lookup_asi(0xFF).is_none());
}

#[test]
fn lookup_condition_table_covers_0_15() {
    for c in 0u8..=15 {
        assert!(lookup_condition(c).is_some());
    }
    // All 4-bit codes lookup find entry
}

#[test]
fn lookup_priv_reg_present() {
    assert_eq!(lookup_priv_reg(0).unwrap().name, "%tpc");
    assert_eq!(lookup_priv_reg(31).unwrap().name, "%ver");
    assert!(!lookup_priv_reg(31).unwrap().writable);
}

// ── Branch target extraction ─────────────────────────────────────────────────

#[test]
fn extract_branch_targets_call_at_offset() {
    let w = encode_call(0).to_be_bytes();
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0u8; 8]);
    buf.extend_from_slice(&w);
    let t = extract_branch_targets(&buf, 0x1000);
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].0, 0x1008);
    assert_eq!(t[0].1, 0x1008);
}

#[test]
fn extract_branch_targets_bicc_negative_disp() {
    // Bicc backwards displacement -8
    let w = encode_bicc(8, false, -8).to_be_bytes();
    let t = extract_branch_targets(&w, 0x2000);
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].1, 0x2000 - 8);
}

#[test]
fn extract_branch_targets_truncated_no_panic() {
    let bytes = [0xAA, 0xBB, 0xCC];
    let t = extract_branch_targets(&bytes, 0);
    assert!(t.is_empty());
}

#[test]
fn extract_branch_targets_lcg_fuzz() {
    let mut g = mk_lcg();
    let mut buf = Vec::new();
    for _ in 0..400 {
        buf.extend_from_slice(&crate::sparc_narrow::low_u32_of_u64(g()).to_be_bytes());
    }
    // must not panic
    let _ = extract_branch_targets(&buf, 0x4000_0000);
}

// ── Raw mix counter ──────────────────────────────────────────────────────────

#[test]
fn raw_mix_call_count() {
    let mut buf = Vec::new();
    for _ in 0..5 {
        buf.extend_from_slice(&encode_call(4).to_be_bytes());
    }
    let m = SparcRawMix::from_bytes(&buf);
    assert_eq!(m.calls, 5);
}

#[test]
fn raw_mix_alu_branch_load() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&encode_alu_reg(0, 1, 2, 3).to_be_bytes());
    buf.extend_from_slice(&encode_bicc(8, false, 4).to_be_bytes());
    buf.extend_from_slice(&encode_load(0, 14, 0, 8).to_be_bytes());
    let m = SparcRawMix::from_bytes(&buf);
    assert_eq!(m.alu, 1);
    assert_eq!(m.branches, 1);
    assert_eq!(m.mem, 1);
}

#[test]
fn raw_mix_lcg_never_panics() {
    let mut g = mk_lcg();
    let mut buf = Vec::with_capacity(4000);
    for _ in 0..1000 {
        buf.extend_from_slice(&crate::sparc_narrow::low_u32_of_u64(g()).to_be_bytes());
    }
    let m = SparcRawMix::from_bytes(&buf);
    let total = m.calls + m.branches + m.sethis + m.alu + m.mem;
    assert!(total > 0);
}

// ── Delay slot module ────────────────────────────────────────────────────────

#[test]
fn ds_annul_bit_from_word() {
    let w_no = encode_bicc(8, false, 4);
    let w_yes = encode_bicc(8, true, 4);
    assert_eq!(AnnulBit::from_word(w_no), AnnulBit::NotSet);
    assert_eq!(AnnulBit::from_word(w_yes), AnnulBit::Set);
    assert!(AnnulBit::Set.is_set());
    assert!(!AnnulBit::NotSet.is_set());
}

#[test]
fn ds_branch_condition_decode_all_16() {
    for b in 0u8..16 {
        let c = DSCond::from_cond_bits(b);
        let _ = c.mnemonic(); // non-panic
        let _ = c.negate();
    }
}

#[test]
fn ds_branch_condition_negate_involution() {
    for b in 0u8..16 {
        let c = DSCond::from_cond_bits(b);
        assert_eq!(c.negate().negate(), c, "neg-neg = id for {c:?}");
    }
}

#[test]
fn ds_unconditional_classes() {
    assert!(DSCond::Always.is_unconditional());
    assert!(DSCond::Never.is_unconditional());
    assert!(!DSCond::Equal.is_unconditional());
}

#[test]
fn ds_is_nop_only_for_0x01000000() {
    assert!(is_nop(0x0100_0000));
    assert!(!is_nop(0));
    assert!(!is_nop(0xFFFF_FFFF));
}

#[test]
fn ds_analyze_branch_call() {
    let w = encode_call(8); // +8 displacement
    let ds = analyze_branch(0x1000, w, encode_nop()).unwrap();
    assert_eq!(ds.kind, BranchKind::Call);
    assert_eq!(ds.target_pc, 0x1008);
    assert!(ds.delay_is_nop);
}

#[test]
fn ds_analyze_branch_bicc_taken() {
    let w = encode_bicc(9, false, 16);
    let ds = analyze_branch(0x2000, w, encode_nop()).unwrap();
    assert_eq!(ds.kind, BranchKind::IntCondBranch);
    assert_eq!(ds.condition, DSCond::NotEqual);
    assert_eq!(ds.target_pc, 0x2010);
    assert!(!ds.annul.is_set());
}

#[test]
fn ds_analyze_branch_returns_none_for_alu() {
    let alu = encode_alu_reg(0, 1, 2, 3);
    assert!(analyze_branch(0, alu, 0).is_none());
}

#[test]
fn ds_analyze_branch_lcg_no_panic() {
    let mut g = mk_lcg();
    for _ in 0..500 {
        let b = crate::sparc_narrow::low_u32_of_u64(g());
        let d = crate::sparc_narrow::low_u32_of_u64(g());
        let _ = analyze_branch(0x1000, b, d);
    }
}

// ── V9 decoder/encoder ───────────────────────────────────────────────────────

#[test]
fn v9_roundtrip_mulx_various() {
    for &(rs1, imm, rd) in &[(1u8, 0i32, 8u8), (5, 100, 9), (31, -1, 0), (0, -4096, 7)] {
        let r = roundtrip_mulx(rs1, imm, rd).unwrap();
        assert_eq!(r.rd, Some(rd));
        assert_eq!(r.rs1, Some(rs1));
    }
}

#[test]
fn v9_roundtrip_flushw_ok() {
    let r = roundtrip_flushw().unwrap();
    assert!(matches!(r.opcode, rustre_arch_sparc::sparc_v9::V9Opcode::Flushw));
}

#[test]
fn v9_decode_returns_none_for_non_v9() {
    // a CALL (fmt=1) cannot be a V9 ALU
    assert!(decode_v9_instr(encode_call(0)).is_none());
}

#[test]
fn v9_decode_lcg_never_panics() {
    let mut g = mk_lcg();
    for _ in 0..500 {
        let _ = decode_v9_instr(crate::sparc_narrow::low_u32_of_u64(g()));
    }
}

#[test]
fn v9_encode_membar_carries_mask() {
    let w = V9Encoder::encode_membar(0x4F);
    assert_eq!(w & 0x7F, 0x4F);
}

#[test]
fn v9_encode_udivx_format_bits() {
    let w = V9Encoder::encode_udivx(1, 16, 8);
    assert_eq!((w >> 19) & 63, 0x0D);
    assert_eq!((w >> 13) & 1, 1);
}

// ── Trap tables ──────────────────────────────────────────────────────────────

#[test]
fn trap_v8_table_has_known_traps() {
    let t = sparc_v8_trap_table();
    let by_tt = t.entries.iter().map(|e| e.tt).collect::<Vec<_>>();
    assert!(by_tt.contains(&0x00));
    assert!(by_tt.contains(&0x02));
    assert!(by_tt.contains(&0x05));
    assert_eq!(t.version, 8);
}

#[test]
fn trap_v9_overrides_v8() {
    let v8 = sparc_v8_trap_table();
    let v9 = sparc_v9_trap_table();
    // 0x0C in v8 is div_by_zero; in v9 is clean_windows
    let v8e = v8.entries.iter().find(|e| e.tt == 0x0C).unwrap();
    let v9e = v9.entries.iter().find(|e| e.tt == 0x0C).unwrap();
    assert_ne!(v8e.name, v9e.name);
    assert_eq!(v9.version, 9);
}

#[test]
fn trap_name_lookup() {
    assert_eq!(trap_name(0x02).as_deref(), Some("illegal_instruction"));
    assert!(trap_name(0x99).is_some() || trap_name(0x99).is_none()); // doesn't panic
    let v9 = trap_name_v9(0x0C);
    assert_eq!(v9.as_deref(), Some("clean_windows"));
}

#[test]
fn trap_v8_map_round_trip() {
    let map = sparc_v8_trap_map();
    assert!(map.contains_key(&0x00));
    let v9map = sparc_v9_trap_map();
    assert!(v9map.contains_key(&0x00));
}

#[test]
fn trap_v8_software_traps_present() {
    let map = sparc_v8_trap_map();
    // Software traps fill 0x80..=0xFF
    for tt in [0x80u8, 0x90, 0xA5, 0xFF] {
        assert!(map.contains_key(&tt), "missing software trap tt={tt:#x}");
    }
}

// ── Idiom identification ─────────────────────────────────────────────────────

#[test]
fn idiom_prologue_via_disasm() {
    let a = arch();
    let p = build_prologue(96).to_be_bytes();
    let ins = a.disassemble(Address::new(0), &p).unwrap();
    let idiom = identify_idiom(&ins, None);
    assert_eq!(idiom, SparcIdiom::Prologue);
}

#[test]
fn idiom_epilogue_via_disasm() {
    let a = arch();
    let e = build_epilogue();
    let ins = a.disassemble(Address::new(0), &e[0].to_be_bytes()).unwrap();
    assert_eq!(identify_idiom(&ins, None), SparcIdiom::Epilogue);
}

// ── SparcStackLayout ─────────────────────────────────────────────────────────

#[test]
fn stack_layout_v8_bias_zero() {
    let sl = SparcStackLayout::new_v8(96);
    assert_eq!(sl.stack_bias, 0);
    assert_eq!(sl.save_area_offset(), 0);
    assert_eq!(sl.locals_offset(), 128);
}

#[test]
fn stack_layout_v9_bias_2047() {
    let sl = SparcStackLayout::new_v9(128);
    assert_eq!(sl.stack_bias, 2047);
    assert_eq!(sl.save_area_offset(), 2047);
    assert_eq!(sl.outgoing_args_offset(), 2047 + 128);
}

#[test]
#[should_panic(expected = "V8 frame size must be >= 96")]
fn stack_layout_v8_below_min_panics() {
    let _ = SparcStackLayout::new_v8(80);
}

#[test]
#[should_panic(expected = "V9 frame size must be >= 128")]
fn stack_layout_v9_misaligned_panics() {
    let _ = SparcStackLayout::new_v9(132);
}

// ── Hash/Eq sanity on enums ──────────────────────────────────────────────────

#[test]
fn hash_eq_branch_condition_pairs() {
    use std::collections::HashSet;
    let mut s: HashSet<DSCond> = HashSet::new();
    for b in 0u8..16 {
        s.insert(DSCond::from_cond_bits(b));
    }
    // 16 unique conditions
    assert_eq!(s.len(), 16);
}

#[test]
fn eq_consistency_instr_kind() {
    let pairs = [
        (SparcInstrKind::Nop, SparcInstrKind::Nop, true),
        (SparcInstrKind::Nop, SparcInstrKind::Load, false),
        (SparcInstrKind::Call, SparcInstrKind::Call, true),
        (SparcInstrKind::Return, SparcInstrKind::Call, false),
    ];
    for (a, b, eq) in pairs {
        assert_eq!(a == b, eq);
    }
}

// ── Send/Sync threaded stress ────────────────────────────────────────────────

#[test]
fn send_sync_sparc_arch() {
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<SparcArch>();

    let a = std::sync::Arc::new(SparcArch::new_v8());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let a = std::sync::Arc::clone(&a);
        handles.push(std::thread::spawn(move || {
            let bytes = encode_nop().to_be_bytes();
            let mut ok = 0u32;
            for _ in 0..100 {
                if a.disassemble(Address::new(0), &bytes).is_ok() {
                    ok += 1;
                }
            }
            ok
        }));
    }
    let mut total = 0u32;
    for h in handles {
        total += h.join().unwrap();
    }
    assert_eq!(total, 400);
}

#[test]
fn send_sync_lookup_tables() {
    // Static tables are Send+Sync; run lookups across threads
    let mut handles = Vec::new();
    for _ in 0..4 {
        handles.push(std::thread::spawn(|| {
            let mut acc = 0usize;
            for tt in 0u8..=255 {
                if lookup_v8_trap(tt).is_some() {
                    acc += 1;
                }
            }
            acc
        }));
    }
    let mut sum = 0;
    for h in handles {
        sum += h.join().unwrap();
    }
    assert!(sum > 0);
}
