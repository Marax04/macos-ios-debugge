//! Fuzz-lite: deterministic pseudo-random and structured inputs thrown at the
//! ARM decoder helpers. Invariant under test: no panic, no runaway allocation,
//! terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors `rustre-loader-pe/tests/fuzz_lite.rs` (xorshift64* PRNG,
//! fixed seeds, no external crates).
//!
//! These entry points take an already-extracted instruction *word* rather than
//! a byte slice, so the fuzzing target is the encoding space, not buffer
//! length. A32 words are 32 bits — too many to enumerate — but the fields that
//! select behaviour are narrow, so the sweeps below walk the condition,
//! coprocessor and opcode fields exhaustively while randomising the rest.

use rustre_arch_arm::{decode_arm_dsp, decode_arm_system, decode_thumb32_ext, decode_vfp_a32};

/// xorshift64* — deterministic, no external crates.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Low 32 bits of the next value, read from its little-endian byte image
    /// so the narrowing is exact by construction rather than a numeric cast.
    const fn next_u32(&mut self) -> u32 {
        let b = self.next().to_le_bytes();
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    /// Low 16 bits of the next value, by the same rule as [`Rng::next_u32`].
    const fn next_u16(&mut self) -> u16 {
        let b = self.next().to_le_bytes();
        u16::from_le_bytes([b[0], b[1]])
    }
}

/// All 16 A32 condition-code mnemonics, plus deliberately invalid ones.
const CONDS: [&str; 19] = [
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "",
    // Not real condition codes — the decoders must not assume a fixed length.
    "nv", "zzzz", "a-very-long-condition-string",
];

fn exercise_a32(word: u32) {
    for cc in CONDS {
        let _ = decode_vfp_a32(word, cc);
        let _ = decode_arm_dsp(word, cc);
    }
    let _ = decode_arm_system(word);
}

/// Random A32 words against every condition string.
#[test]
fn random_a32_words_never_panic() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for _ in 0..4_000 {
        exercise_a32(rng.next_u32());
    }
}

/// Sweep the coprocessor field (bits 11:8) exhaustively — `decode_vfp_a32`
/// dispatches on it, and cp10/cp11 are the only handled values.
#[test]
fn coprocessor_field_sweep_never_panics() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for coproc in 0u32..16 {
        for _ in 0..64 {
            let base = rng.next_u32();
            let word = (base & !(0xF << 8)) | (coproc << 8);
            exercise_a32(word);
        }
    }
}

/// Sweep the primary opcode field (bits 27:20) exhaustively.
#[test]
fn primary_opcode_field_sweep_never_panics() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for op in 0u32..256 {
        for _ in 0..16 {
            let base = rng.next_u32();
            let word = (base & !(0xFF << 20)) | (op << 20);
            exercise_a32(word);
        }
    }
}

/// Boundary words: all zeros, all ones, single bits set.
#[test]
fn boundary_words_never_panic() {
    exercise_a32(0);
    exercise_a32(u32::MAX);
    for bit in 0..32 {
        exercise_a32(1u32 << bit);
        exercise_a32(!(1u32 << bit));
    }
}

/// Thumb-32: exhaustive sweep of the first halfword's opcode bits against a
/// random second halfword, plus the all-zero/all-one corners.
///
/// A Thumb-32 instruction is two halfwords; a decoder that classifies on `hw1`
/// and then indexes fields of `hw2` without re-checking is the failure mode.
#[test]
fn thumb32_halfword_sweeps_never_panic() {
    let mut rng = Rng(0x0BAD_F00D_1234_5678);
    // Exhaustive over the top 5 bits of hw1 (the Thumb-32 marker plus op1).
    for top in 0u16..32 {
        for _ in 0..128 {
            let hw1 = (top << 11) | ((rng.next_u16()) & 0x07FF);
            let hw2 = rng.next_u16();
            let _ = decode_thumb32_ext(hw1, hw2);
        }
    }
    for hw1 in [0u16, 0xFFFF, 0xE800, 0xF000, 0xF800] {
        for hw2 in [0u16, 0xFFFF, 0x8000, 0x0001] {
            let _ = decode_thumb32_ext(hw1, hw2);
        }
    }
}

/// Fully exhaustive sweep of `hw1` with a fixed `hw2`.
///
/// 65 536 iterations is cheap and covers every possible first halfword.
#[test]
fn thumb32_exhaustive_hw1_never_panics() {
    for hw1 in 0u16..=u16::MAX {
        let _ = decode_thumb32_ext(hw1, 0xFFFF);
    }
}
