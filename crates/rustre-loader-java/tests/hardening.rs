//! Hardening tests for `rustre-loader-java`.
//!
//! These cover the two defect classes audited across the loader crates:
//!
//! * **Allocation `DoS`** — a count field read straight out of the input used as
//!   `Vec::with_capacity` without being bounded by the bytes that remain. A JVM
//!   `lookupswitch` carries a 32-bit `npairs`, so a handful of bytes could
//!   otherwise request tens of gigabytes.
//! * **Integer overflow** — `high - low + 1` for `tableswitch` evaluated in
//!   `i32`, which panics in debug builds and wraps silently in release.
//!
//! Every test asserts the parser *survives*; the exact instruction list a
//! malformed input decodes to is deliberately not pinned down.

use rustre_loader_java::bytecode_disasm::BcDisassembler;
use rustre_loader_java::bytecode_disassembler::BytecodeDisassembler;

/// `lookupswitch` (0xAB) with `npairs = 0xFFFF_FFFF` in a tiny buffer.
///
/// Before the alloc cap this reserved `npairs * 8` bytes (~32 GiB).
#[test]
fn lookupswitch_huge_npairs_does_not_allocate() {
    let mut code = vec![0xABu8]; // lookupswitch at pc 0
    // Pad to the 4-byte alignment the JVM spec mandates.
    while !code.len().is_multiple_of(4) {
        code.push(0);
    }
    code.extend_from_slice(&0i32.to_be_bytes()); // default
    code.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // npairs

    let d = BytecodeDisassembler::new();
    let insns = d.disassemble_code(&code);
    // No pair can be decoded — there are no bytes left for one.
    assert!(insns.len() <= 2);
}

/// `tableswitch` (0xAA) with a range that spans the whole i32 domain.
#[test]
fn tableswitch_huge_range_does_not_allocate() {
    let mut code = vec![0xAAu8];
    while !code.len().is_multiple_of(4) {
        code.push(0);
    }
    code.extend_from_slice(&0i32.to_be_bytes()); // default
    code.extend_from_slice(&i32::MIN.to_be_bytes()); // low
    code.extend_from_slice(&i32::MAX.to_be_bytes()); // high

    let d = BytecodeDisassembler::new();
    let insns = d.disassemble_code(&code);
    assert!(insns.len() <= 2);
}

/// The same adversarial `tableswitch` bounds through the other disassembler,
/// where `high - low + 1` used to be computed in `i32`.
#[test]
fn tableswitch_range_overflow_is_widened() {
    let mut code = vec![0xAAu8];
    while !code.len().is_multiple_of(4) {
        code.push(0);
    }
    code.extend_from_slice(&0i32.to_be_bytes()); // default
    code.extend_from_slice(&(-1i32).to_be_bytes()); // low
    code.extend_from_slice(&i32::MAX.to_be_bytes()); // high  → range = 2^31

    let instrs = BcDisassembler::disassemble(&code);
    // The switch cannot be completed (no offset bytes follow), but the range
    // computation must not overflow on the way there.
    assert!(instrs.len() <= 2);
}

/// A well-formed `lookupswitch` still decodes correctly — the cap must bound
/// the allocation, not truncate legitimate input.
#[test]
fn lookupswitch_wellformed_still_parses() {
    let mut code = vec![0xABu8];
    while !code.len().is_multiple_of(4) {
        code.push(0);
    }
    code.extend_from_slice(&7i32.to_be_bytes()); // default
    code.extend_from_slice(&2u32.to_be_bytes()); // npairs = 2
    code.extend_from_slice(&1i32.to_be_bytes()); // key 0
    code.extend_from_slice(&10i32.to_be_bytes()); // offset 0
    code.extend_from_slice(&2i32.to_be_bytes()); // key 1
    code.extend_from_slice(&20i32.to_be_bytes()); // offset 1

    let d = BytecodeDisassembler::new();
    let insns = d.disassemble_code(&code);
    let sw = insns
        .iter()
        .find(|i| i.mnemonic == "lookupswitch")
        .expect("lookupswitch should decode");
    assert_eq!(sw.opcode, 0xAB);
}

/// A well-formed `tableswitch` still decodes correctly.
#[test]
fn tableswitch_wellformed_still_parses() {
    let mut code = vec![0xAAu8];
    while !code.len().is_multiple_of(4) {
        code.push(0);
    }
    code.extend_from_slice(&5i32.to_be_bytes()); // default
    code.extend_from_slice(&0i32.to_be_bytes()); // low
    code.extend_from_slice(&1i32.to_be_bytes()); // high → 2 entries
    code.extend_from_slice(&11i32.to_be_bytes());
    code.extend_from_slice(&22i32.to_be_bytes());

    let d = BytecodeDisassembler::new();
    let insns = d.disassemble_code(&code);
    let sw = insns
        .iter()
        .find(|i| i.mnemonic == "tableswitch")
        .expect("tableswitch should decode");
    assert_eq!(sw.opcode, 0xAA);
}

/// Pure random noise through both disassemblers must never panic.
#[test]
fn random_noise_never_panics() {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    let d = BytecodeDisassembler::new();
    for _ in 0..200 {
        let len = (next() % 256) as usize;
        let buf: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
        let _ = d.disassemble_code(&buf);
        let _ = BcDisassembler::disassemble(&buf);
    }
}

/// Truncations of a valid switch instruction must not panic at any length.
#[test]
fn truncated_switch_never_panics() {
    let mut code = vec![0xABu8, 0, 0, 0];
    code.extend_from_slice(&0i32.to_be_bytes());
    code.extend_from_slice(&3u32.to_be_bytes());
    for _ in 0..3 {
        code.extend_from_slice(&1i32.to_be_bytes());
        code.extend_from_slice(&2i32.to_be_bytes());
    }

    let d = BytecodeDisassembler::new();
    for cut in 0..code.len() {
        let _ = d.disassemble_code(&code[..cut]);
        let _ = BcDisassembler::disassemble(&code[..cut]);
    }
}
