//! Fuzz-lite: deterministic pseudo-random and mutated inputs thrown at the
//! Zilog Z80 decoder. Invariant under test: no panic, no runaway allocation,
//! terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors `rustre-loader-pe/tests/fuzz_lite.rs` (xorshift64* PRNG,
//! fixed seeds, no external crates).
//!
//! The Z80's opcode space is layered behind four prefix bytes — `0xCB` (bit
//! ops), `0xED` (extended), `0xDD`/`0xFD` (IX/IY) — and `0xDD 0xCB dd op` /
//! `0xFD 0xCB dd op` is a *four*-byte form where the opcode comes **after** the
//! displacement byte. That combination is the classic Z80 decoder trap, so it
//! gets swept exhaustively rather than sampled.

use rustre_arch_z80::decode_main;

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

fn exercise_parsers(data: &[u8]) {
    let _ = decode_main(data, 0x1000);
    let _ = decode_main(data, 0xFFFF);
    let _ = decode_main(data, u64::MAX);
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

/// Exhaustive sweep of the unprefixed opcode map with 0–2 operand bytes.
#[test]
fn exhaustive_unprefixed_sweep_never_panics() {
    for op in 0u8..=255 {
        exercise_parsers(&[op]);
        exercise_parsers(&[op, 0xFF]);
        exercise_parsers(&[op, 0xFF, 0xFF]);
    }
}

/// Every prefix byte followed by every second byte, with and without operands.
#[test]
fn exhaustive_prefixed_sweep_never_panics() {
    for prefix in [0xCBu8, 0xED, 0xDD, 0xFD] {
        for op in 0u8..=255 {
            exercise_parsers(&[prefix, op]);
            exercise_parsers(&[prefix, op, 0xFF]);
            exercise_parsers(&[prefix, op, 0xFF, 0xFF]);
        }
    }
}

/// The four-byte `DD CB dd op` / `FD CB dd op` forms, swept over the final
/// opcode byte, plus every truncation of them.
///
/// Here the opcode byte comes *after* the displacement, so a decoder that reads
/// the opcode at the wrong index — or before checking the length — goes wrong.
#[test]
fn ddcb_fdcb_forms_never_panic() {
    for prefix in [0xDDu8, 0xFD] {
        for op in 0u8..=255 {
            let full = [prefix, 0xCB, 0x05, op];
            for cut in 0..=full.len() {
                exercise_parsers(&full[..cut]);
            }
            // Negative displacement too.
            exercise_parsers(&[prefix, 0xCB, 0x80, op]);
            exercise_parsers(&[prefix, 0xCB, 0xFF, op]);
        }
    }
}

/// Long runs of prefix bytes — `DD`/`FD` are legally repeatable on real
/// hardware, so a decoder that recurses per prefix can run away.
#[test]
fn long_prefix_runs_never_panic() {
    for prefix in [0xDDu8, 0xFD, 0xCB, 0xED] {
        for len in [2usize, 8, 64, 256] {
            let mut buf = vec![prefix; len];
            exercise_parsers(&buf);
            buf.push(0x00); // nop after the run
            exercise_parsers(&buf);
        }
    }
}

/// Truncations of real Z80 encodings.
#[test]
fn truncations_never_panic() {
    let seeds: [&[u8]; 5] = [
        &[0x21, 0x34, 0x12],       // ld hl,$1234
        &[0xCD, 0x00, 0x20],       // call $2000
        &[0xED, 0xB0],             // ldir
        &[0xDD, 0x36, 0x05, 0x42], // ld (ix+5),$42
        &[0x18, 0xFE],             // jr -2
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
    for fill in [0x00u8, 0xCB, 0xDD, 0xED, 0xFF] {
        for len in [256usize, 4096] {
            exercise_parsers(&vec![fill; len]);
        }
    }
}
