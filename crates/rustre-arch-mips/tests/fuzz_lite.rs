//! Fuzz-lite: deterministic pseudo-random and structured inputs thrown at the
//! MIPS decoder. Invariant under test: no panic, no runaway allocation,
//! terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors `rustre-loader-pe/tests/fuzz_lite.rs` (xorshift64* PRNG,
//! fixed seeds, no external crates).
//!
//! MIPS instructions are fixed 32-bit words and `decode_word` is a method on
//! `MipsArch`, so every input is run against all four configurations
//! (MIPS32/64 × little/big endian): the same word can decode differently per
//! width, and a 64-bit-only opcode reached on a 32-bit config is exactly the
//! kind of path that gets missed otherwise.
//!
//! The dispatch fields are narrow — primary opcode (bits 31:26), `funct`
//! (bits 5:0), `rs` (bits 25:21) — so each is swept exhaustively with the rest
//! randomised, which reaches every table branch without enumerating 2^32.

use rustre_arch_mips::MipsArch;
use rustre_core::address::Address;

/// Low 32 bits of a PRNG word — MIPS instructions are 32 bits wide, and
/// masking first makes the conversion provably in range.
fn low32(v: u64) -> u32 {
    u32::try_from(v & 0xFFFF_FFFF).unwrap_or(0)
}

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

/// All four architecture configurations.
fn archs() -> [MipsArch; 4] {
    [
        MipsArch::mips32_le(),
        MipsArch::mips32_be(),
        MipsArch::mips64_le(),
        MipsArch::mips64_be(),
    ]
}

/// Decode `word` under every configuration, with a matching raw byte slice.
fn exercise_word(word: u32) {
    let addr = Address::new(0x1000);
    let le = word.to_le_bytes();
    let be = word.to_be_bytes();
    for arch in archs() {
        let _ = arch.decode_word(addr, word, &le);
        let _ = arch.decode_word(addr, word, &be);
        // A raw slice that is too short must not be trusted either.
        let _ = arch.decode_word(addr, word, &[]);
        let _ = arch.decode_word(addr, word, &le[..2]);
    }
}

/// Random words across all configurations.
#[test]
fn random_words_never_panic() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for _ in 0..4_000 {
        exercise_word(low32(rng.next()));
    }
}

/// Exhaustive sweep of the primary opcode field (bits 31:26).
#[test]
fn primary_opcode_sweep_never_panics() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for op in 0u32..64 {
        for _ in 0..32 {
            let base = low32(rng.next());
            exercise_word((base & 0x03FF_FFFF) | (op << 26));
        }
    }
}

/// Exhaustive sweep of the `funct` field (bits 5:0) under the SPECIAL opcode.
///
/// SPECIAL (opcode 0) dispatches entirely on `funct`, so this reaches a large
/// second table that the primary sweep barely touches.
#[test]
fn special_funct_sweep_never_panics() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for funct in 0u32..64 {
        for _ in 0..32 {
            let base = low32(rng.next());
            // opcode = 0 (SPECIAL), funct in the low 6 bits.
            exercise_word((base & 0x03FF_FFC0) | funct);
        }
    }
    // SPECIAL2 (0x1C) and SPECIAL3 (0x1F) have their own funct tables.
    for special in [0x1Cu32, 0x1F] {
        for funct in 0u32..64 {
            exercise_word((special << 26) | funct);
        }
    }
}

/// Exhaustive sweep of the `rs` field under REGIMM (opcode 1), which
/// dispatches on `rt` instead — another distinct table.
#[test]
fn regimm_field_sweep_never_panics() {
    for rt in 0u32..32 {
        for rs in 0u32..32 {
            exercise_word((1u32 << 26) | (rs << 21) | (rt << 16));
        }
    }
}

/// Boundary words and extreme addresses.
///
/// Branch targets are computed from the address, so values at the ends of the
/// space exercise the wrapping arithmetic.
#[test]
fn boundary_words_and_addresses_never_panic() {
    let words = [0u32, 1, u32::MAX, 0x8000_0000, 0x7FFF_FFFF];
    let addrs = [
        0u64,
        4,
        0x1000,
        0x7FFF_FFFF_FFFF_FFFF,
        0x8000_0000_0000_0000,
        u64::MAX - 3,
        u64::MAX,
    ];
    for &w in &words {
        for &a in &addrs {
            let addr = Address::new(a);
            let raw = w.to_le_bytes();
            for arch in archs() {
                let _ = arch.decode_word(addr, w, &raw);
            }
        }
    }
    for bit in 0..32 {
        exercise_word(1u32 << bit);
        exercise_word(!(1u32 << bit));
    }
}
