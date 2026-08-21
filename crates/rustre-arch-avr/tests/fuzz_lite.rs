//! Fuzz-lite: deterministic pseudo-random and mutated inputs thrown at the
//! Atmel AVR disassembler. Invariant under test: no panic, no runaway
//! allocation, terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors `rustre-loader-pe/tests/fuzz_lite.rs` (xorshift64* PRNG,
//! fixed seeds, no external crates).
//!
//! `disassemble_annotated` walks a whole byte buffer rather than decoding one
//! instruction, so besides malformed encodings this exercises the *loop*: a
//! decoder that reports a zero or overlong length, or that indexes past the end
//! on the final partial instruction, shows up here and not in single-shot
//! decoding.

use rustre_arch_avr::{disassemble_annotated, AvrArch};
use rustre_core::address::Address;

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

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            v.extend_from_slice(&self.next().to_le_bytes());
        }
        v.truncate(len);
        v
    }
}

fn exercise(data: &[u8]) {
    let arch = AvrArch::default();
    for base in [0u64, 0x1000, u64::MAX - 8, u64::MAX] {
        let _ = disassemble_annotated(&arch, data, Address::new(base));
    }
}

/// Pure random noise of assorted lengths, including empty.
#[test]
fn pure_noise_never_panics() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    exercise(&[]);
    for _ in 0..400 {
        let len = (rng.next() % 64) as usize;
        exercise(&rng.bytes(len));
    }
}

/// Every single byte, and every byte pair built from a stepped sample.
///
/// Short buffers are where the walk hits a partial trailing instruction.
#[test]
fn short_buffers_never_panic() {
    for b in 0u8..=255 {
        exercise(&[b]);
        exercise(&[b, 0xFF]);
        exercise(&[b, 0x00, 0xFF]);
        exercise(&[b, 0xFF, 0xFF, 0xFF]);
    }
}

/// Buffers of every length from 0 to 33, filled with a repeating pattern.
///
/// Catches off-by-one handling of the final instruction for every alignment.
#[test]
fn every_length_prefix_never_panics() {
    let pattern: Vec<u8> = (0u8..64).collect();
    for len in 0..=33usize {
        exercise(&pattern[..len]);
    }
}

/// Long uniform buffers — the walk must terminate and not degrade.
#[test]
fn oversized_uniform_buffers_never_panic() {
    for fill in [0x00u8, 0x55, 0xAA, 0xFF] {
        for len in [256usize, 4096] {
            exercise(&vec![fill; len]);
        }
    }
}

/// Single-bit flips of a repeating pattern.
#[test]
fn bit_flips_never_panic() {
    let base: Vec<u8> = (0u8..16).collect();
    for idx in 0..base.len() {
        for bit in 0..8 {
            let mut m = base.clone();
            m[idx] ^= 1 << bit;
            exercise(&m);
        }
    }
}
