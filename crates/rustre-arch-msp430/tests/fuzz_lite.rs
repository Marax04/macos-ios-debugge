//! Fuzz-lite: deterministic pseudo-random and mutated inputs thrown at the
//! TI MSP430 decoder. Invariant under test: no panic, no runaway allocation,
//! terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors `rustre-loader-pe/tests/fuzz_lite.rs` (xorshift64* PRNG,
//! fixed seeds, no external crates).
//!
//! The MSP430 is word-oriented with a 16-bit opcode word, so the whole opcode
//! space is enumerable — 65 536 values, swept exhaustively. Instructions carry
//! up to two extension words for source and destination operands, which is
//! where a decoder that trusts the addressing-mode bits about how many
//! extension words follow reads past the end.

use rustre_arch_msp430::decode;

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

fn exercise_parsers(data: &[u8]) {
    let _ = decode(data, 0x1000);
    let _ = decode(data, 0xFFFE);
    let _ = decode(data, u64::MAX);
}

/// Pure random noise of assorted lengths.
#[test]
fn pure_noise_never_panics() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for _ in 0..600 {
        let len = (rng.next() % 16) as usize;
        exercise_parsers(&rng.bytes(len));
    }
}

/// Exhaustive sweep of the 16-bit opcode word with no extension words.
#[test]
fn exhaustive_opcode_sweep_never_panics() {
    for w in 0u16..=u16::MAX {
        let _ = decode(&w.to_le_bytes(), 0x1000);
    }
}

/// Exhaustive sweep again with one extension word present.
///
/// Instructions whose addressing mode implies *two* extension words will find
/// only one here — the truncation case.
#[test]
fn exhaustive_opcode_sweep_one_extension_never_panics() {
    for w in 0u16..=u16::MAX {
        let mut buf = Vec::with_capacity(4);
        buf.extend_from_slice(&w.to_le_bytes());
        buf.extend_from_slice(&[0xFF, 0xFF]);
        let _ = decode(&buf, 0x1000);
    }
}

/// Odd-length buffers: a word-oriented decoder handed an odd byte count.
#[test]
fn odd_length_buffers_never_panic() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for len in [1usize, 3, 5, 7, 9, 11] {
        for _ in 0..64 {
            exercise_parsers(&rng.bytes(len));
        }
    }
}

/// Truncations of real MSP430 encodings.
#[test]
fn truncations_never_panic() {
    let seeds: [&[u8]; 4] = [
        &[0x30, 0x41],                         // ret
        &[0x0F, 0x12],                         // push r15
        &[0xB0, 0x12, 0x00, 0x10],             // call #$1000
        &[0x1F, 0x42, 0x20, 0x01],             // mov &$0120,r15
    ];
    for seed in seeds {
        for cut in 0..=seed.len() {
            exercise_parsers(&seed[..cut]);
        }
    }
}

/// Long uniform buffers.
#[test]
fn oversized_uniform_buffers_never_panic() {
    for fill in [0x00u8, 0x12, 0xFF] {
        for len in [256usize, 4096] {
            exercise_parsers(&vec![fill; len]);
        }
    }
}
