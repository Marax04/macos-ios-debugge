//! Fuzz-lite: deterministic and exhaustive inputs thrown at the AArch64
//! immediate-decoding helpers. Invariant under test: no panic, no runaway
//! allocation, terminates fast. Return values are irrelevant.
//!
//! Pattern mirrors `rustre-loader-pe/tests/fuzz_lite.rs` (xorshift64* PRNG,
//! fixed seeds, no external crates).
//!
//! `decode_logical_imm` implements the AArch64 bitmask-immediate encoding —
//! the `N:immr:imms` scheme that turns 13 bits into a 64-bit mask. It is
//! notoriously fiddly: the element size comes from the position of the highest
//! clear bit in `imms`, several field combinations are architecturally
//! *reserved*, and the rotate is modulo the element size. Its whole input
//! space is `2 × 64 × 64 × 2` combinations, so it is swept **exhaustively**
//! rather than sampled — every reserved and boundary encoding included.

use rustre_arch_arm64::{decode_add_sub_imm12, decode_bitmask, decode_logical_imm};

/// Exhaustive sweep of the entire logical-immediate input space.
///
/// `n` is one bit, `rot` (immr) and `size_field` (imms) are six bits each, and
/// `reg_size` selects 32- or 64-bit operation: 2 × 64 × 64 × 2 = 16 384 cases.
#[test]
fn exhaustive_logical_imm_sweep_never_panics() {
    for n in 0u8..2 {
        for rot in 0u8..64 {
            for size_field in 0u8..64 {
                for reg_size in [32u8, 64] {
                    let _ = decode_logical_imm(n, rot, size_field, reg_size);
                    let _ = decode_bitmask(n, rot, size_field, reg_size);
                }
            }
        }
    }
}

/// The same fields with out-of-range values.
///
/// The parameters are `u8`, so a caller can pass values wider than the
/// architectural field width; the decoder must not index or shift by them
/// blindly.
#[test]
fn out_of_range_fields_never_panic() {
    let extremes: [u8; 8] = [0, 1, 31, 32, 63, 64, 128, 255];
    for &n in &extremes {
        for &rot in &extremes {
            for &size_field in &extremes {
                for &reg_size in &extremes {
                    let _ = decode_logical_imm(n, rot, size_field, reg_size);
                    let _ = decode_bitmask(n, rot, size_field, reg_size);
                }
            }
        }
    }
}

/// Every `u8` value in each position, with the others fixed at a valid value.
#[test]
fn single_field_full_u8_sweep_never_panics() {
    for v in 0u8..=255 {
        let _ = decode_logical_imm(v, 0, 0, 64);
        let _ = decode_logical_imm(0, v, 0, 64);
        let _ = decode_logical_imm(0, 0, v, 64);
        let _ = decode_logical_imm(0, 0, 0, v);
        let _ = decode_bitmask(v, v, v, v);
    }
}

/// Exhaustive sweep of `decode_add_sub_imm12`.
///
/// `imm12` is architecturally 12 bits and `shift` selects a 0 or 12 bit shift,
/// but both are wider types here — so the whole `u16` range is swept against
/// every `u8` shift, which is 2^16 × a handful of shifts and still fast.
#[test]
fn exhaustive_add_sub_imm12_sweep_never_panics() {
    for shift in [0u8, 1, 2, 12, 13, 63, 64, 255] {
        for imm12 in 0u16..=u16::MAX {
            let _ = decode_add_sub_imm12(imm12, shift);
        }
    }
}

/// Boundary values around the architectural 12-bit limit.
#[test]
fn add_sub_imm12_boundaries_never_panic() {
    for imm12 in [0u16, 1, 0xFFE, 0xFFF, 0x1000, 0x1001, u16::MAX] {
        for shift in 0u8..=255 {
            let _ = decode_add_sub_imm12(imm12, shift);
        }
    }
}
