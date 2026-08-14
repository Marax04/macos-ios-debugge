//! Invariants of the Dalvik opcode table and bytecode disassembler.
//!
//! `DalvikOpcode::from_byte` documents that "every value in `0x00..=0xff` is
//! mapped, this branch is unreachable in practice". That is a claim about all
//! 256 inputs, and it is cheap to check exhaustively rather than trust — a gap
//! would be a panic reachable from any hostile DEX file.

use rustre_mobile_smali::{DalvikOpcode, SmaliDisassembler};

/// The documented claim: no byte value panics.
#[test]
fn every_byte_decodes_to_an_opcode() {
    for b in 0u8..=255 {
        // A panic here fails the test with the offending byte in the message.
        let op = DalvikOpcode::from_byte(b);
        let _ = format!("{op:?}");
    }
}

/// Deterministic noise — reproducible failures, no external crates.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut s = seed;
    (0..n)
        .map(|_| {
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (s >> 24) as u8
        })
        .collect()
}

/// Disassembly terminates and cannot invent instructions.
///
/// DEX code is an array of 16-bit units, so `n` bytes hold at most `n / 2`
/// instructions: a longer result means something is not consuming input.
#[test]
fn disassembly_is_bounded_by_the_code_length() {
    for len in [0usize, 2, 4, 8, 32, 256, 4096] {
        for seed in [0x1u64, 0xDEAD_BEEF, 0x5555_AAAA_5555_AAAA] {
            let code = noise(len, seed);
            let out = SmaliDisassembler::disassemble_bytecode(&code, 0);
            assert!(
                out.len() <= len / 2 + 1,
                "{} instructions from {len} bytes (max {}) — the decoder is not \
                 consuming code units",
                out.len(),
                len / 2 + 1
            );
        }
    }
}

/// Every decoded instruction must start inside the code it came from.
#[test]
fn instruction_offsets_stay_inside_the_code() {
    for len in [2usize, 8, 64, 1024] {
        let code = noise(len, 0xC0FF_EE00_1234_5678);
        for ins in SmaliDisassembler::disassemble_bytecode(&code, 0) {
            assert!(
                ins.offset < len,
                "instruction at offset {} but the code is only {len} bytes",
                ins.offset
            );
        }
    }
}

/// Guards the two bounds above against passing vacuously on empty output.
#[test]
fn the_disassembler_actually_produces_instructions() {
    let code = noise(4096, 0x7777_7777_7777_7777);
    let out = SmaliDisassembler::disassemble_bytecode(&code, 0);
    assert!(
        out.len() >= 8,
        "only {} instructions from 4096 bytes of code — the bounds above would \
         hold without decoding anything",
        out.len()
    );
}
