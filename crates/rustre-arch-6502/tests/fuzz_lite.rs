//! Fuzz-lite: deterministic pseudo-random and mutated inputs thrown at the
//! MOS 6502 disassembler. Invariant under test: no panic, no runaway
//! allocation, terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors `rustre-loader-pe/tests/fuzz_lite.rs` (xorshift64* PRNG,
//! fixed seeds, no external crates).
//!
//! The 6502 has a one-byte opcode and a 256-entry map with many undefined
//! slots, so the opcode space can be swept **exhaustively**. Instructions are
//! 1–3 bytes; the interesting failures come from a 3-byte opcode sitting at the
//! very end of the buffer, and from `disassemble_range` being asked for more
//! instructions than the data can supply.

use rustre_arch_6502::{disassemble_one, disassemble_range};

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

/// Run every entry point over `data`.
fn exercise_parsers(data: &[u8]) {
    let _ = disassemble_one(data, 0, 0x0600);
    // Offsets at, and past, the end must be handled by the `data.get(..)`.
    let _ = disassemble_one(data, data.len(), 0x0600);
    let _ = disassemble_one(data, data.len().saturating_add(1), 0x0600);
    let _ = disassemble_one(data, usize::MAX, 0x0600);
    let _ = disassemble_range(data, 0x0600, 8);
}

/// Pure random noise of assorted lengths.
#[test]
fn pure_noise_never_panics() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for _ in 0..600 {
        let len = (rng.next() % 24) as usize;
        exercise_parsers(&rng.bytes(len));
    }
}

/// Exhaustive sweep of the one-byte opcode map, with 0, 1 and 2 operand bytes.
///
/// A 3-byte absolute-mode opcode with only one operand byte present is the
/// canonical 6502 truncation case.
#[test]
fn exhaustive_opcode_sweep_never_panics() {
    for op in 0u8..=255 {
        let _ = disassemble_one(&[op], 0, 0x0600);
        let _ = disassemble_one(&[op, 0xFF], 0, 0x0600);
        let _ = disassemble_one(&[op, 0xFF, 0xFF], 0, 0x0600);
    }
}

/// Every opcode placed at the very end of a longer buffer.
///
/// This checks the offset path rather than the slice-length path: the decoder
/// must not read past `data.len()` even when the buffer itself is large.
#[test]
fn opcode_at_end_of_buffer_never_panics() {
    for op in 0u8..=255 {
        let mut buf = vec![0xEAu8; 16]; // NOPs
        buf.push(op);
        let last = buf.len() - 1;
        let _ = disassemble_one(&buf, last, 0x0600);
    }
}

/// `disassemble_range` asked for far more instructions than the data holds.
///
/// The count drives a `Vec::with_capacity`, so large values must not be trusted
/// blindly, and the walk must terminate when the data runs out.
#[test]
fn range_overlong_counts_never_panic() {
    let data = [0xA9u8, 0x01, 0x8D, 0x00, 0x02, 0x60]; // lda #1; sta $0200; rts
    for n in [0usize, 1, 8, 1_000, 100_000] {
        let _ = disassemble_range(&data, 0x0600, n);
    }
    // Same, over an empty buffer.
    for n in [0usize, 1, 1_000] {
        let _ = disassemble_range(&[], 0x0600, n);
    }
}

/// Address wrap-around: a 16-bit program counter near the top of memory.
#[test]
fn address_wraparound_never_panics() {
    let data = [0x4Cu8, 0x00, 0x10, 0xA9, 0x42, 0x60];
    for addr in [0u16, 1, 0x7FFF, 0xFFFD, 0xFFFE, 0xFFFF] {
        let _ = disassemble_one(&data, 0, addr);
        let _ = disassemble_range(&data, addr, 16);
    }
}

/// Truncations of real 6502 encodings.
#[test]
fn truncations_never_panic() {
    let seeds: [&[u8]; 5] = [
        &[0xA9, 0x42],             // lda #$42
        &[0x8D, 0x00, 0x02],       // sta $0200
        &[0x20, 0x00, 0x10],       // jsr $1000
        &[0xD0, 0xFE],             // bne -2
        &[0x6C, 0xFF, 0x00],       // jmp ($00ff) — the famous page-boundary bug
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
    for fill in [0x00u8, 0xEA, 0xFF] {
        for len in [256usize, 4096] {
            let buf = vec![fill; len];
            let _ = disassemble_one(&buf, 0, 0x0600);
            let _ = disassemble_range(&buf, 0x0600, 64);
        }
    }
}
