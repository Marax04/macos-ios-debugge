//! Fuzz-lite: deterministic pseudo-random and mutated inputs thrown at the
//! Motorola 68000 decoder. Invariant under test: no panic, no runaway
//! allocation, terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors `rustre-loader-pe/tests/fuzz_lite.rs` (xorshift64* PRNG,
//! fixed seeds, no external crates).
//!
//! The 68k is word-oriented: every instruction starts with a 16-bit opcode
//! word whose top nibble selects the group. That makes the opcode space small
//! enough to enumerate **exhaustively** — all 65 536 words — which is far
//! stronger than random sampling and cheap to run. Extension words follow, so
//! each opcode is also tried with several extension-buffer lengths, since a
//! decoder that trusts the opcode about how many extension bytes exist is the
//! classic 68k out-of-bounds bug.

use rustre_arch_68k::{
    decode_68k, decode_68k_group0, decode_68k_group0_imm, decode_68k_group4,
    decode_68k_group4_misc, decode_68k_group4_unary, decode_68k_group5, decode_68k_group6,
    decode_68k_group8, decode_68k_group9, decode_68k_group_b, parse_ea, Size,
};

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

/// Feed one opcode word plus an extension buffer to every group decoder.
///
/// Each group decoder is called regardless of whether the word belongs to its
/// group: they are public entry points, so they must tolerate any input.
fn exercise_groups(word: u16, ext: &[u8]) {
    let _ = decode_68k_group0(word, ext);
    let _ = decode_68k_group0_imm(word, ext);
    let _ = decode_68k_group4(word, ext);
    let _ = decode_68k_group4_unary(word, ext);
    let _ = decode_68k_group4_misc(word, ext);
    let _ = decode_68k_group5(word, ext, 0x1000);
    let _ = decode_68k_group6(word, ext, 0x1000);
    let _ = decode_68k_group8(word, ext);
    let _ = decode_68k_group9(word, ext);
    let _ = decode_68k_group_b(word, ext);
}

/// Run the whole-slice entry point over `data`.
fn exercise_parsers(data: &[u8]) {
    let _ = decode_68k(data, 0x1000);
    if data.len() >= 2 {
        let word = u16::from_be_bytes([data[0], data[1]]);
        exercise_groups(word, &data[2..]);
    }
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

/// Exhaustive sweep of the whole 16-bit opcode space, with no extension words.
///
/// This is the strongest cheap guarantee available for this architecture: every
/// encoding the CPU can see, including all undefined ones.
#[test]
fn exhaustive_opcode_sweep_no_extension_never_panics() {
    for w in 0u16..=u16::MAX {
        let _ = decode_68k(&w.to_be_bytes(), 0x1000);
    }
}

/// Exhaustive sweep again, this time with a short extension buffer.
///
/// An opcode that expects a 32-bit displacement over two extension bytes is
/// where truncation bugs live.
#[test]
fn exhaustive_opcode_sweep_short_extension_never_panics() {
    for w in 0u16..=u16::MAX {
        let mut buf = Vec::with_capacity(4);
        buf.extend_from_slice(&w.to_be_bytes());
        buf.extend_from_slice(&[0xFF, 0xFF]);
        let _ = decode_68k(&buf, 0x1000);
    }
}

/// Every group decoder over a sparse but structured set of words, at several
/// extension lengths.
///
/// A full 65 536 × 10 sweep would be slow; stepping the word space keeps this
/// fast while still touching every group and addressing-mode field.
#[test]
fn group_decoders_never_panic() {
    let exts: [&[u8]; 5] = [&[], &[0x00], &[0xFF, 0xFF], &[0x00, 0x01, 0x02, 0x03], &[0xFF; 8]];
    let mut w: u32 = 0;
    while w <= u32::from(u16::MAX) {
        for ext in exts {
            exercise_groups(w as u16, ext);
        }
        w += 37; // coprime-ish step: hits every group and many mode/reg fields
    }
}

/// Effective-address parsing across every mode/register pair and size.
#[test]
fn parse_ea_all_modes_never_panics() {
    let exts: [&[u8]; 4] = [&[], &[0x12], &[0x12, 0x34], &[0xFF; 6]];
    for mode in 0u8..8 {
        for reg in 0u8..8 {
            for size in [Size::Byte, Size::Word, Size::Long] {
                for ext in exts {
                    let _ = parse_ea(mode, reg, size, ext);
                }
            }
        }
    }
}

/// Truncations of real 68k encodings.
#[test]
fn truncations_never_panic() {
    let seeds: [&[u8]; 5] = [
        &[0x4E, 0x75],                         // rts
        &[0x4E, 0xB9, 0x00, 0x00, 0x10, 0x00], // jsr $1000
        &[0x20, 0x3C, 0x00, 0x00, 0x00, 0x2A], // move.l #42,d0
        &[0x60, 0xFE],                         // bra.s -2
        &[0x48, 0xE7, 0xFF, 0xFE],             // movem.l regs,-(sp)
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
    for fill in [0x00u8, 0x4E, 0xFF] {
        for len in [256usize, 4096] {
            exercise_parsers(&vec![fill; len]);
        }
    }
}
