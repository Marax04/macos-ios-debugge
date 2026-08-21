//! Fuzz-lite: deterministic pseudo-random and mutated inputs thrown at the
//! JVM bytecode decoder entry points. Invariant under test: no panic, no
//! runaway allocation, terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors `rustre-loader-pe/tests/fuzz_lite.rs` (xorshift64* PRNG,
//! fixed seeds, no external crates).
//!
//! The JVM instruction set is mostly fixed-width, but three constructs are not
//! and are where decoders go wrong: `wide` (which changes the *next* opcode's
//! operand width), and `tableswitch`/`lookupswitch` (4-byte aligned, with a
//! count read from the stream). The `pc_offset` parameter matters for the
//! latter two, since the padding depends on it — so every input is decoded at
//! several offsets, not just zero.

use rustre_arch_jvm::wide_opcodes::{
    decode_jvm_insn, decode_lookupswitch, decode_multianewarray, decode_tableswitch, decode_wide,
};
use rustre_arch_jvm::{jvm_build_cfg, opcode_info, JvmInstr};

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

/// Run every decoder entry point over `data`.
///
/// Switch padding depends on `pc_offset % 4`, so all four residues are covered.
fn exercise_parsers(data: &[u8]) {
    for pc in 0usize..4 {
        let _ = JvmInstr::decode_at(data, pc);
        let _ = decode_jvm_insn(data, pc);
        let _ = decode_tableswitch(data, pc);
        let _ = decode_lookupswitch(data, pc);
    }
    let _ = JvmInstr::decode(data);
    let _ = decode_wide(data);
    let _ = decode_multianewarray(data);
    let _ = jvm_build_cfg(data);
    if let Some(&b) = data.first() {
        let _ = opcode_info(b);
    }
}

/// Pure random noise of assorted lengths.
#[test]
fn pure_noise_never_panics() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for _ in 0..600 {
        let len = (rng.next() % 40) as usize;
        exercise_parsers(&rng.bytes(len));
    }
}

/// Every single byte as a one-byte method body, including the reserved
/// `0xca..=0xff` range.
#[test]
fn every_single_opcode_never_panics() {
    for b in 0u8..=255 {
        exercise_parsers(&[b]);
    }
}

/// `wide` (0xC4) followed by every possible sub-opcode, with and without the
/// operand bytes it implies.
#[test]
fn wide_prefix_pairs_never_panic() {
    for b in 0u8..=255 {
        exercise_parsers(&[0xC4, b]);
        exercise_parsers(&[0xC4, b, 0x00]);
        exercise_parsers(&[0xC4, b, 0x00, 0x01]);
        exercise_parsers(&[0xC4, b, 0x00, 0x01, 0x02, 0x03]);
    }
    // wide chained onto itself — a decoder that recurses here can run away.
    exercise_parsers(&[0xC4; 64]);
}

/// `tableswitch` with adversarial low/high bounds, at every alignment.
///
/// `high - low + 1` is the entry count; the extremes make it overflow in i32
/// and the padding varies with the offset.
#[test]
fn tableswitch_extreme_bounds_never_panic() {
    let bounds: [(i32, i32); 6] = [
        (0, 0),
        (0, i32::MAX),
        (i32::MIN, i32::MAX),
        (i32::MIN, 0),
        (i32::MAX, i32::MIN),
        (-1, i32::MAX),
    ];
    for (low, high) in bounds {
        for pad in 0usize..4 {
            let mut code = vec![0xAAu8];
            code.extend_from_slice(&vec![0u8; pad]);
            code.extend_from_slice(&0i32.to_be_bytes()); // default
            code.extend_from_slice(&low.to_be_bytes());
            code.extend_from_slice(&high.to_be_bytes());
            exercise_parsers(&code);
            // Also with a couple of jump-offset entries present.
            code.extend_from_slice(&1i32.to_be_bytes());
            code.extend_from_slice(&2i32.to_be_bytes());
            exercise_parsers(&code);
        }
    }
}

/// `lookupswitch` with adversarial pair counts, at every alignment.
#[test]
fn lookupswitch_extreme_npairs_never_panic() {
    for npairs in [0i32, 1, -1, i32::MIN, i32::MAX] {
        for pad in 0usize..4 {
            let mut code = vec![0xABu8];
            code.extend_from_slice(&vec![0u8; pad]);
            code.extend_from_slice(&0i32.to_be_bytes()); // default
            code.extend_from_slice(&npairs.to_be_bytes());
            exercise_parsers(&code);
            code.extend_from_slice(&7i32.to_be_bytes()); // one match
            code.extend_from_slice(&8i32.to_be_bytes()); // one offset
            exercise_parsers(&code);
        }
    }
}

/// Truncations of real multi-byte instructions.
#[test]
fn truncations_never_panic() {
    let seeds: [&[u8]; 5] = [
        &[0xB6, 0x00, 0x0A],                   // invokevirtual #10
        &[0xC5, 0x00, 0x0B, 0x02],             // multianewarray #11, dims 2
        &[0xC4, 0x15, 0x01, 0x00],             // wide iload
        &[0xBA, 0x00, 0x0C, 0x00, 0x00],       // invokedynamic
        &[0xA7, 0xFF, 0xFE],                   // goto -2
    ];
    for seed in seeds {
        for cut in 0..=seed.len() {
            exercise_parsers(&seed[..cut]);
        }
    }
}

/// Single-bit flips of a small valid method body.
#[test]
fn bit_flips_never_panic() {
    let base: [u8; 8] = [0x2A, 0xB7, 0x00, 0x01, 0xB1, 0x03, 0x3C, 0xA7];
    for byte_idx in 0..base.len() {
        for bit in 0..8 {
            let mut m = base;
            m[byte_idx] ^= 1 << bit;
            exercise_parsers(&m);
        }
    }
}

/// Long uniform bodies — CFG construction walks the whole array, so this is
/// where a quadratic or non-terminating path would show up.
#[test]
fn oversized_uniform_bodies_never_panic() {
    for fill in [0x00u8, 0xA7, 0xAA, 0xAB, 0xC4, 0xFF] {
        for len in [256usize, 4096] {
            exercise_parsers(&vec![fill; len]);
        }
    }
}
