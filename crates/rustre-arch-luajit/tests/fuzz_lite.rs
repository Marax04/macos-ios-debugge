//! Fuzz-lite: deterministic pseudo-random inputs thrown at the LuaJIT bytecode
//! decoder. Invariant under test: no panic, no runaway allocation, terminates
//! fast. Return values are irrelevant.
//!
//! Pattern mirrors `rustre-loader-pe/tests/fuzz_lite.rs` (xorshift64* PRNG,
//! fixed seeds, no external crates).
//!
//! LuaJIT instructions are fixed 32-bit words, so the decoder takes `u32`
//! rather than a byte slice. The whole 32-bit space is too large to enumerate,
//! but the *opcode* field is only the low byte — so all 256 opcodes are swept
//! exhaustively against extreme values of the remaining operand fields, which
//! is where a decoder that indexes a table or a constant slot by an unchecked
//! field goes wrong.

use rustre_arch_luajit::{decode_lj_instruction, disassemble_listing};

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
}

/// Pure random 32-bit words.
#[test]
fn random_words_never_panic() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for _ in 0..20_000 {
        let word = rng.next() as u32;
        let _ = decode_lj_instruction(word);
    }
}

/// Every opcode byte against extreme operand fields.
///
/// The A/B/C/D fields occupy the upper 24 bits; all-zeros and all-ones are the
/// boundary cases for any register or constant index derived from them.
#[test]
fn every_opcode_with_extreme_operands_never_panics() {
    for op in 0u32..=255 {
        for operands in [
            0x0000_0000u32,
            0x0000_FF00,
            0x00FF_0000,
            0xFF00_0000,
            0xFFFF_FF00,
        ] {
            let _ = decode_lj_instruction(op | operands);
        }
    }
}

/// Listings over random word streams — exercises the multi-instruction path.
#[test]
fn random_listings_never_panic() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for len in [0usize, 1, 4, 64, 1024] {
        let words: Vec<u32> = (0..len).map(|_| rng.next() as u32).collect();
        let _ = disassemble_listing(&words);
    }
}

/// Uniform word streams, including all-zeros and all-ones.
#[test]
fn uniform_listings_never_panic() {
    for fill in [0x0000_0000u32, 0xFFFF_FFFF, 0x0000_00FF, 0xDEAD_BEEF] {
        for len in [1usize, 16, 1024] {
            let words = vec![fill; len];
            let _ = disassemble_listing(&words);
        }
    }
}

/// Every opcode as a single-instruction listing.
#[test]
fn every_opcode_listing_never_panics() {
    for op in 0u32..=255 {
        let _ = disassemble_listing(&[op]);
        let _ = disassemble_listing(&[op, 0xFFFF_FF00 | op]);
    }
}
