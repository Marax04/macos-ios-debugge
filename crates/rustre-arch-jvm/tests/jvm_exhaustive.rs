//! Exhaustive properties of the JVM bytecode decoder.
//!
//! A JVM opcode is a single byte, so the domain is 256 values and can be
//! checked completely — nothing here is sampled.
//!
//! `JvmInstr::decode` documents its own contract precisely: it returns
//! `Truncated` when the slice is too short, `Reserved` "for
//! implementation-defined opcodes in the range `0xca..=0xff`", and
//! `UnknownOpcode` for invalid sub-opcodes inside `Wide`.  That doc comment is
//! a specification already written down, so it is checked against the whole
//! opcode domain rather than trusted.
//!
//! Modelled on `arch-avr/tests/avr_exhaustive.rs`.

use rustre_arch_jvm::{JvmDecodeError, JvmInstr};

/// Operand bytes appended after the opcode so that the multi-byte forms are not
/// all rejected for lack of operands.  Generous, because `invokedynamic` and
/// the `wide` forms consume several.
const TAIL: [u8; 16] = [0; 16];

fn probe(opcode: u8) -> Vec<u8> {
    let mut bytes = vec![opcode];
    bytes.extend_from_slice(&TAIL);
    bytes
}

/// The documented reserved range is exactly `0xca..=0xff` — no wider, no
/// narrower.  A decoder that reserved less would accept an implementation
/// -defined opcode as a real instruction; one that reserved more would refuse
/// a valid one.
#[test]
fn the_reserved_range_is_exactly_as_documented() {
    for opcode in 0u8..=0xFF {
        let bytes = probe(opcode);
        let is_reserved = matches!(
            JvmInstr::decode(&bytes),
            Err(JvmDecodeError::Reserved { .. })
        );

        if opcode >= 0xCA {
            assert!(
                is_reserved,
                "opcode {opcode:#04x} is inside the documented reserved range \
                 0xca..=0xff but was not reported as Reserved"
            );
        } else {
            assert!(
                !is_reserved,
                "opcode {opcode:#04x} is below the documented reserved range \
                 0xca..=0xff but was reported as Reserved"
            );
        }
    }
}

/// Whatever decodes must report a byte count that matches the bytes it kept,
/// and must not claim more than it was given.  A mismatch here desynchronises
/// any linear walk over a method's bytecode array.
#[test]
fn consumed_length_matches_the_raw_bytes() {
    let mut decoded = 0usize;

    for opcode in 0u8..=0xFF {
        let bytes = probe(opcode);
        let Ok((insn, consumed)) = JvmInstr::decode(&bytes) else { continue };
        decoded += 1;

        assert_eq!(
            consumed,
            insn.raw.len(),
            "opcode {opcode:#04x} ({}) reported {consumed} bytes consumed but \
             kept {} raw bytes — a linear walk would desynchronise",
            insn.mnemonic,
            insn.raw.len()
        );
        assert!(
            consumed >= 1 && consumed <= bytes.len(),
            "opcode {opcode:#04x} ({}) consumed {consumed} of {} bytes supplied",
            insn.mnemonic,
            bytes.len()
        );
        assert_eq!(
            insn.raw[0], opcode,
            "opcode {opcode:#04x} decoded but its first raw byte is {:#04x}",
            insn.raw[0]
        );
        assert!(
            !insn.mnemonic.is_empty(),
            "opcode {opcode:#04x} decoded with an empty mnemonic"
        );
    }

    assert!(
        decoded >= 200,
        "only {decoded} of 256 opcodes decoded — the assertions above would be \
         holding trivially"
    );
}

/// An empty slice is documented to yield `Truncated`, not a panic and not a
/// zero-length instruction.
#[test]
fn an_empty_slice_is_truncated() {
    assert!(matches!(
        JvmInstr::decode(&[]),
        Err(JvmDecodeError::Truncated { .. })
    ));
}

/// An opcode whose operands are missing is truncated, not short: a decoder that
/// reported a length here would read past the buffer it was handed.
#[test]
fn a_missing_operand_does_not_over_consume() {
    for opcode in 0u8..=0xFF {
        if let Ok((insn, consumed)) = JvmInstr::decode(&[opcode]) {
            assert_eq!(
                consumed, 1,
                "opcode {opcode:#04x} ({}) claimed {consumed} bytes from a \
                 1-byte buffer",
                insn.mnemonic
            );
            assert_eq!(insn.raw.len(), 1, "opcode {opcode:#04x} kept extra bytes");
        }
    }
}
