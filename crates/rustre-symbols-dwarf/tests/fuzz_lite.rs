//! Fuzz-lite for the DWARF parsers: deterministic pseudo-random and
//! structured-noise inputs. Invariant: no panic, no runaway allocation,
//! fast termination — return values are irrelevant.

use rustre_symbols_dwarf::dwarf_abbrev::{
    parse_abbrev_table, parse_all_abbrev_tables, read_sleb128, read_uleb128,
};
use rustre_symbols_dwarf::dwarf_call_frame::decode_cfa_insns;
use rustre_symbols_dwarf::dwarf_location_expr::parse_location_expr;
use rustre_symbols_dwarf::dwarf_unwind::parse_cie;
use rustre_symbols_dwarf::type_units::parse_type_unit_header;

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

fn exercise(data: &[u8]) {
    let mut pos = 0usize;
    let _ = read_uleb128(data, &mut pos);
    let mut pos = 0usize;
    let _ = read_sleb128(data, &mut pos);
    let _ = parse_abbrev_table(data, 0);
    let _ = parse_all_abbrev_tables(data);
    for addr_size in [4u8, 8u8] {
        let _ = parse_location_expr(data, addr_size);
        let mut pos = 0usize;
        let _ = decode_cfa_insns(data, &mut pos, data.len(), addr_size);
        let _ = parse_cie(data, 0, true, addr_size);
        let _ = parse_cie(data, 0, false, addr_size);
    }
    let _ = parse_type_unit_header(data, 0);
}

/// Pure random noise at several sizes, including empty and tiny inputs.
#[test]
fn random_noise_never_panics() {
    let mut rng = Rng(0xD1CE_D00D_FEED_BEEF);
    for &len in &[0usize, 1, 2, 4, 7, 11, 16, 32, 64, 512, 4096, 65_536] {
        for _ in 0..8 {
            exercise(&rng.bytes(len));
        }
    }
}

/// Location expressions built from every possible leading opcode byte followed
/// by noise — probes each DW_OP_* operand decoder.
#[test]
fn every_opcode_prefix_never_panics() {
    let mut rng = Rng(0xA5A5_5A5A_A5A5_5A5A);
    for op in 0u8..=255 {
        let mut expr = vec![op];
        expr.extend_from_slice(&rng.bytes(24));
        let _ = parse_location_expr(&expr, 8);
        let _ = parse_location_expr(&expr, 4);
    }
}

/// ULEB128 lengths at maximum magnitude embedded mid-stream (the overflow
/// class fixed on 2026-07-21) plus random tails.
#[test]
fn huge_uleb_lengths_never_panic() {
    const ULEB_U64_MAX: [u8; 10] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
    let mut rng = Rng(0x1BAD_B002_0D15_EA5E);
    for op in [0x9Eu8, 0xA3, 0x93, 0x9D] {
        // implicit_value / entry_value / piece / bit_piece
        let mut expr = vec![op];
        expr.extend_from_slice(&ULEB_U64_MAX);
        expr.extend_from_slice(&rng.bytes(16));
        let _ = parse_location_expr(&expr, 8);
    }
}
