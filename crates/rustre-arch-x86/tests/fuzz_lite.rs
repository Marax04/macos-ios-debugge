//! Fuzz-lite: deterministic pseudo-random and mutated inputs thrown at the
//! x86 decoder entry points. Invariant under test: no panic, no runaway
//! allocation, terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors `rustre-loader-pe/tests/fuzz_lite.rs` (xorshift64* PRNG,
//! fixed seeds, no external crates).
//!
//! x86 is the densest decoder in the workspace — variable-length instructions,
//! prefixes, ModRM/SIB, and three operating modes — so random bytes are a
//! genuine exercise of its length and classification paths rather than a
//! formality.

use rustre_arch_x86::branch::{classify_branch, classify_opcode, decode_string_instr};
use rustre_arch_x86::length::instr_length;
use rustre_arch_x86::modrm::ModRm;
use rustre_arch_x86::X86LiftAdapter;

/// xorshift64* — deterministic, no external crates.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            v.extend_from_slice(&self.next().to_le_bytes());
        }
        v.truncate(len);
        v
    }
}

/// Run every decoder entry point over `data`, in all three x86 modes.
fn exercise_parsers(data: &[u8]) {
    for bits in [16u32, 32, 64] {
        let _ = instr_length(data, bits);
        let _ = decode_string_instr(data, bits);
        let _ = X86LiftAdapter::decode_one_iced(bits, data, 0x1000);
    }
    let _ = classify_branch(data);
    if let Some(&b) = data.first() {
        let _ = classify_opcode(b);
        let _ = ModRm::decode(b);
    }
}

/// Pure random noise of assorted lengths.
#[test]
fn pure_noise_never_panics() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for _ in 0..800 {
        let len = (rng.next() % 24) as usize;
        exercise_parsers(&rng.bytes(len));
    }
}

/// Every single byte as a one-byte instruction, in every mode.
///
/// This sweeps the whole one-byte opcode map, including the undefined slots.
#[test]
fn every_single_byte_opcode_never_panics() {
    for b in 0u8..=255 {
        exercise_parsers(&[b]);
    }
}

/// Every two-byte sequence starting with an escape or prefix byte.
///
/// The escape (`0x0F`), REX (`0x40..=0x4F`), and legacy prefix bytes are where
/// a decoder is most likely to walk off the end of a short buffer.
#[test]
fn escape_and_prefix_pairs_never_panic() {
    let leads: [u8; 12] = [
        0x0F, 0x40, 0x48, 0x4F, 0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x64, 0x65,
    ];
    for lead in leads {
        for b in 0u8..=255 {
            exercise_parsers(&[lead, b]);
            exercise_parsers(&[lead, b, 0x00]);
        }
    }
}

/// Long prefix runs — a decoder that loops over prefixes without a bound can
/// be walked off the end or spun by a wall of `0x66`/`0xF3`.
#[test]
fn long_prefix_runs_never_panic() {
    for prefix in [0x66u8, 0x67, 0xF2, 0xF3, 0x2E, 0x40] {
        for len in [1usize, 4, 15, 16, 64, 256] {
            let mut buf = vec![prefix; len];
            exercise_parsers(&buf);
            // Same run followed by a real opcode.
            buf.push(0x90);
            exercise_parsers(&buf);
        }
    }
}

/// Truncations: take a plausible instruction and cut it at every length.
#[test]
fn truncations_never_panic() {
    // A few real encodings: mov rax,[rbx+disp32]; call rel32; movaps xmm0,xmm1;
    // rep movsb; lea with SIB.
    let seeds: [&[u8]; 5] = [
        &[0x48, 0x8B, 0x83, 0x11, 0x22, 0x33, 0x44],
        &[0xE8, 0x00, 0x01, 0x02, 0x03],
        &[0x0F, 0x28, 0xC1],
        &[0xF3, 0xA4],
        &[0x48, 0x8D, 0x04, 0x8B],
    ];
    for seed in seeds {
        for cut in 0..=seed.len() {
            exercise_parsers(&seed[..cut]);
        }
    }
}

/// Single-bit flips of a valid instruction — cheap mutation coverage that
/// reaches encodings pure noise rarely produces.
#[test]
fn bit_flips_never_panic() {
    let base: [u8; 7] = [0x48, 0x8B, 0x83, 0x11, 0x22, 0x33, 0x44];
    for byte_idx in 0..base.len() {
        for bit in 0..8 {
            let mut m = base;
            m[byte_idx] ^= 1 << bit;
            exercise_parsers(&m);
        }
    }
}

/// Oversized buffers of repeated bytes — guards against length paths that scale
/// with the input rather than with the instruction.
#[test]
fn oversized_uniform_buffers_never_panic() {
    for fill in [0x00u8, 0xFF, 0x0F, 0x90] {
        for len in [256usize, 4096] {
            exercise_parsers(&vec![fill; len]);
        }
    }
}
