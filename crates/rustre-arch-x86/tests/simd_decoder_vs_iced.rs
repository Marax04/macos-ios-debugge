//! Differential cross-check: `x86_simd_decoder`'s classification vs `iced_x86`.
//!
//! # Why this file exists
//!
//! `src/x86_simd_decoder.rs` has no callers: `sse.rs` is the SIMD path that
//! actually runs, and the doc comments describe the two as complementary. The
//! 2026-07-23 wiring audit found that framing misleading — the lean legacy
//! module runs, this one does not — and named the concrete capability at stake:
//! **AVX-512 masking and vector-width reporting**.
//!
//! Every field `SimdInsn` claims is independently derivable from the decoder
//! the live path uses, so each claim can be checked rather than trusted:
//!
//! | `SimdInsn` field | independent source |
//! |---|---|
//! | `uses_mask` | `Instruction::op_mask() != Register::None` |
//! | `zero_masking` | `Instruction::zeroing_masking()` |
//! | `broadcast` | `Instruction::is_broadcast()` |
//! | `vector_width` | widest vector register among the operands |
//! | `is_load` / `is_store` | position of the memory operand |
//! | `operand_count` | `Instruction::op_count()` |
//!
//! # Corpus
//!
//! Instructions are ASSEMBLED with `iced_x86`'s encoder — SSE/AVX/AVX-512 forms
//! across xmm/ymm/zmm, with and without `{k1}` masking, `{z}` zeroing and
//! memory operands. Never written as bytes by hand: hand-built encodings were
//! the single largest source of DEFECTIVE TESTS found in this workspace on
//! 2026-07-23.

use std::collections::BTreeMap;

use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, Instruction, MemoryOperand, OpKind, Register,
};
use rustre_arch_x86::x86_simd_decoder::{VectorWidth, X86SimdDecoder};

const BASE: u64 = 0x1000;

/// Widest vector register among an instruction's register operands — computed
/// here from iced directly, so it is a second opinion rather than a copy of the
/// module's own helper.
fn expected_width(insn: &Instruction) -> VectorWidth {
    let mut best = VectorWidth::Scalar;
    for i in 0..insn.op_count() {
        if insn.op_kind(i) != OpKind::Register {
            continue;
        }
        let r = insn.op_register(i) as u32;
        let w = if r >= Register::ZMM0 as u32 && r <= Register::ZMM31 as u32 {
            VectorWidth::Zmm
        } else if r >= Register::YMM0 as u32 && r <= Register::YMM31 as u32 {
            VectorWidth::Ymm
        } else if r >= Register::XMM0 as u32 && r <= Register::XMM31 as u32 {
            VectorWidth::Xmm
        } else {
            continue;
        };
        let rank = |v: VectorWidth| match v {
            VectorWidth::Scalar => 0u8,
            VectorWidth::Xmm => 1,
            VectorWidth::Ymm => 2,
            VectorWidth::Zmm => 3,
            VectorWidth::Tmm => 4,
        };
        if rank(w) > rank(best) {
            best = w;
        }
    }
    best
}

/// Build the corpus: (label, encoded bytes).
fn corpus() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut enc = Encoder::new(64);

    let mut push = |enc: &mut Encoder, label: String, instr: Instruction| {
        if enc.encode(&instr, BASE).is_ok() {
            out.push((label, enc.take_buffer()));
        }
    };

    // Legacy SSE, register and memory forms.
    for (label, code, is_mem) in [
        ("addps xmm", Code::Addps_xmm_xmmm128, false),
        ("mulpd xmm", Code::Mulpd_xmm_xmmm128, false),
        ("movaps load", Code::Movaps_xmm_xmmm128, true),
    ] {
        let instr = if is_mem {
            Instruction::with2(code, Register::XMM0, MemoryOperand::with_base(Register::RAX))
        } else {
            Instruction::with2(code, Register::XMM0, Register::XMM1)
        };
        if let Ok(i) = instr {
            push(&mut enc, label.to_string(), i);
        }
    }
    // Store form: memory destination.
    if let Ok(i) = Instruction::with2(
        Code::Movaps_xmmm128_xmm,
        MemoryOperand::with_base(Register::RAX),
        Register::XMM0,
    ) {
        push(&mut enc, "movaps store".to_string(), i);
    }

    // VEX: 128- and 256-bit.
    if let Ok(i) = Instruction::with3(
        Code::VEX_Vandps_xmm_xmm_xmmm128,
        Register::XMM0,
        Register::XMM1,
        Register::XMM2,
    ) {
        push(&mut enc, "vandps xmm".to_string(), i);
    }
    if let Ok(i) = Instruction::with3(
        Code::VEX_Vandps_ymm_ymm_ymmm256,
        Register::YMM0,
        Register::YMM1,
        Register::YMM2,
    ) {
        push(&mut enc, "vandps ymm".to_string(), i);
    }

    // EVEX: plain, masked, masked+zeroing — the capability the audit named.
    for (label, mask, zeroing) in [
        ("vandps zmm", Register::None, false),
        ("vandps zmm {k1}", Register::K1, false),
        ("vandps zmm {k2}{z}", Register::K2, true),
        ("vandps zmm {k7}{z}", Register::K7, true),
    ] {
        if let Ok(mut i) = Instruction::with3(
            Code::EVEX_Vandps_zmm_k1z_zmm_zmmm512b32,
            Register::ZMM0,
            Register::ZMM1,
            Register::ZMM2,
        ) {
            if mask != Register::None {
                i.set_op_mask(mask);
            }
            i.set_zeroing_masking(zeroing);
            push(&mut enc, label.to_string(), i);
        }
    }

    // EVEX with a memory source and broadcast.
    if let Ok(mut i) = Instruction::with3(
        Code::EVEX_Vandps_zmm_k1z_zmm_zmmm512b32,
        Register::ZMM0,
        Register::ZMM1,
        MemoryOperand::with_base(Register::RAX),
    ) {
        i.set_op_mask(Register::K3);
        i.set_is_broadcast(true);
        push(&mut enc, "vandps zmm {k3} bcast".to_string(), i);
    }

    out
}

#[test]
fn simd_decoder_classification_agrees_with_iced() {
    let dec = X86SimdDecoder::new_64bit();
    let mut by_field: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut compared = 0usize;

    let cases = corpus();
    for (label, bytes) in &cases {
        let Some(got) = dec.decode_one(BASE, bytes) else {
            by_field
                .entry("not classified as SIMD")
                .or_default()
                .push(format!("{label}: decoder returned None"));
            continue;
        };
        let mut d = Decoder::with_ip(64, bytes, BASE, DecoderOptions::NONE);
        let want = d.decode();
        assert!(!want.is_invalid(), "{label}: corpus encoding does not decode");
        compared += 1;

        let want_mask = want.op_mask() != Register::None;
        if got.uses_mask != want_mask {
            by_field.entry("uses_mask").or_default().push(format!(
                "{label}: decoder {} vs iced op_mask {:?}",
                got.uses_mask,
                want.op_mask()
            ));
        }
        if got.zero_masking != want.zeroing_masking() {
            by_field.entry("zero_masking").or_default().push(format!(
                "{label}: decoder {} vs iced {}",
                got.zero_masking,
                want.zeroing_masking()
            ));
        }
        if got.broadcast != want.is_broadcast() {
            by_field.entry("broadcast").or_default().push(format!(
                "{label}: decoder {} vs iced {}",
                got.broadcast,
                want.is_broadcast()
            ));
        }
        let want_width = expected_width(&want);
        if got.vector_width != want_width {
            by_field.entry("vector_width").or_default().push(format!(
                "{label}: decoder {:?} vs operands {:?}",
                got.vector_width, want_width
            ));
        }
        if got.operand_count != want.op_count() {
            by_field.entry("operand_count").or_default().push(format!(
                "{label}: decoder {} vs iced {}",
                got.operand_count,
                want.op_count()
            ));
        }
        // Load/store: the memory operand's POSITION decides direction —
        // destination (operand 0) is a store, anything later is a load.
        let mem_at = (0..want.op_count()).find(|&i| want.op_kind(i) == OpKind::Memory);
        let (want_store, want_load) = match mem_at {
            Some(0) => (true, false),
            Some(_) => (false, true),
            None => (false, false),
        };
        if got.is_store != want_store || got.is_load != want_load {
            by_field.entry("load/store").or_default().push(format!(
                "{label}: decoder store={} load={} vs iced store={want_store} load={want_load}",
                got.is_store, got.is_load
            ));
        }
    }

    // Anti-degeneracy: a cross-check over an empty corpus proves nothing, and
    // the corpus is built by an encoder that can silently refuse a form.
    assert!(
        compared >= 10,
        "cross-check degenerated: only {compared} instructions compared \
         ({} corpus entries)",
        cases.len()
    );

    if !by_field.is_empty() {
        let histogram = by_field
            .iter()
            .map(|(k, v)| format!("{k}: {}", v.len()))
            .collect::<Vec<_>>()
            .join("\n  ");
        let examples = by_field
            .values()
            .flat_map(|v| v.iter().take(4))
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  ");
        panic!(
            "SIMD decoder disagrees with iced over {compared} instructions\n\
             \nBY FIELD (one rule many times, or many distinct bugs?):\n  {histogram}\n\
             \nEXAMPLES:\n  {examples}"
        );
    }

    println!("SIMD decoder vs iced: {compared} instructions agree");
}
