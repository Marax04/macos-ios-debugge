//! Fuzz-lite: deterministic pseudo-random and exhaustive inputs thrown at the
//! RISC-V compressed-instruction decoder. Invariant under test: no panic, no
//! runaway allocation, terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors `rustre-loader-pe/tests/fuzz_lite.rs` (xorshift64* PRNG,
//! fixed seeds, no external crates).
//!
//! `decode_compressed` takes a 16-bit halfword, so the *entire* encoding space
//! is 65 536 values and can be swept exhaustively — the strongest guarantee
//! available for a decoder, and cheap. It is swept once per XLEN, because the
//! same halfword decodes differently on RV32/RV64/RV128 (`c.jal` on RV32 is
//! `c.addiw` on RV64, for instance), so a single-XLEN sweep would leave whole
//! branches of the decoder untouched.

use rustre_arch_riscv::decode_compressed;
use rustre_core::address::Address;

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

/// Exhaustive sweep of every 16-bit halfword on RV32.
#[test]
fn exhaustive_rv32_sweep_never_panics() {
    let addr = Address::new(0x1000);
    for hw in 0u16..=u16::MAX {
        let _ = decode_compressed(hw, 32, addr);
    }
}

/// Exhaustive sweep on RV64 — several quadrant-2 encodings mean something
/// different here than on RV32.
#[test]
fn exhaustive_rv64_sweep_never_panics() {
    let addr = Address::new(0x1000);
    for hw in 0u16..=u16::MAX {
        let _ = decode_compressed(hw, 64, addr);
    }
}

/// Exhaustive sweep on RV128, plus nonsense XLEN values.
///
/// XLEN is a parameter, not something read from the instruction, so a caller
/// could pass anything; the decoder must not assume it is 32/64/128.
#[test]
fn exhaustive_rv128_and_bogus_xlen_never_panic() {
    let addr = Address::new(0x1000);
    for hw in 0u16..=u16::MAX {
        let _ = decode_compressed(hw, 128, addr);
    }
    for xlen in [0u32, 1, 8, 16, 31, 33, 63, 65, 255, u32::MAX] {
        for hw in [0u16, 1, 0x4001, 0x8000, 0xFFFF] {
            let _ = decode_compressed(hw, xlen, addr);
        }
    }
}

/// Extreme addresses — branch and jump targets are computed relative to the
/// address, so values near the ends of the space exercise the wrapping paths.
#[test]
fn extreme_addresses_never_panic() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for a in [
        0u64,
        2,
        0x1000,
        0x7FFF_FFFF_FFFF_FFFF,
        0x8000_0000_0000_0000,
        u64::MAX - 1,
        u64::MAX,
    ] {
        let addr = Address::new(a);
        for _ in 0..512 {
            let hw = rng.next() as u16;
            let _ = decode_compressed(hw, 32, addr);
            let _ = decode_compressed(hw, 64, addr);
        }
        // Quadrant boundaries at each address.
        for hw in [0x0000u16, 0x0001, 0x0002, 0x0003, 0xFFFC, 0xFFFF] {
            let _ = decode_compressed(hw, 64, addr);
        }
    }
}

/// Random halfwords across random XLENs and addresses.
#[test]
fn random_words_never_panic() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..20_000 {
        let hw = rng.next() as u16;
        let xlen = (rng.next() % 200) as u32;
        let addr = Address::new(rng.next());
        let _ = decode_compressed(hw, xlen, addr);
    }
}
