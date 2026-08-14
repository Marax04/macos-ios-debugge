//! Exhaustive properties of the 6502-family decoders.
//!
//! An NMOS 6502 opcode is a single byte, so the domain is 256 values and can be
//! checked completely — nothing here is sampled.  The crate carries three
//! independent decoders (NMOS `Mos6502Disassembler`, `decode_65c02`,
//! `decode_65816`), which is the shape that drifts: each stays self-consistent
//! with whatever it believes, so only enumerating the whole domain can show
//! where one of them disagrees with its own documentation.
//!
//! Modelled on `arch-avr/tests/avr_exhaustive.rs`.
//!
//! Note on what is deliberately *not* asserted: the 65C02 redefines several
//! opcodes the NMOS part treats as illegal (`$0F` is `SLO abs` on NMOS and
//! `BBR0` on CMOS), so cross-decoder *length* agreement is not a property of
//! these two parts and asserting it would manufacture a false failure.

use rustre_arch_6502::decoder_65c02::decode_65c02;
use rustre_arch_6502::mos6502_disassembler::Mos6502Disassembler;

/// Operand bytes appended after the opcode so that 2- and 3-byte forms are not
/// all rejected for lack of an operand.
const TAIL: [u8; 3] = [0xAB, 0xCD, 0xEF];

fn probe(opcode: u8) -> Vec<u8> {
    let mut bytes = vec![opcode];
    bytes.extend_from_slice(&TAIL);
    bytes
}

/// The NMOS 6502 has no undefined opcodes: every one of the 256 byte values is
/// an instruction, the 105 unofficial ones included (that is what the `illegal`
/// flag is for).  A hole in the table would make a linear sweep stop dead.
#[test]
fn every_opcode_decodes_on_nmos() {
    let dis = Mos6502Disassembler::new();
    for opcode in 0u8..=0xFF {
        let bytes = probe(opcode);
        assert!(
            dis.decode_one(&bytes, 0x600, 0).is_some(),
            "opcode {opcode:#04x} does not decode — the NMOS 6502 has no \
             undefined opcodes, only unofficial ones"
        );
    }
}

/// `Mos6502Insn::bytes` documents itself as "All bytes consumed (1–3)".
/// Checked against every opcode rather than trusted.
#[test]
fn nmos_length_is_always_one_to_three() {
    let dis = Mos6502Disassembler::new();
    let mut decoded = 0usize;

    for opcode in 0u8..=0xFF {
        let bytes = probe(opcode);
        let Some(insn) = dis.decode_one(&bytes, 0x600, 0) else { continue };
        decoded += 1;

        assert!(
            (1..=3).contains(&insn.bytes.len()),
            "opcode {opcode:#04x} ({}) consumed {} bytes — the field documents \
             itself as 1-3",
            insn.mnemonic,
            insn.bytes.len()
        );
        assert!(
            insn.bytes.len() <= bytes.len(),
            "opcode {opcode:#04x} consumed {} bytes with only {} supplied",
            insn.bytes.len(),
            bytes.len()
        );
        assert_eq!(
            insn.opcode, opcode,
            "opcode {opcode:#04x} decoded but reports opcode {:#04x}",
            insn.opcode
        );
        assert_eq!(
            insn.bytes[0], opcode,
            "opcode {opcode:#04x} decoded but its first consumed byte is {:#04x}",
            insn.bytes[0]
        );
        assert!(
            !insn.mnemonic.is_empty(),
            "opcode {opcode:#04x} decoded with an empty mnemonic"
        );
    }

    assert_eq!(
        decoded, 256,
        "only {decoded} of 256 opcodes decoded — the assertions above would be \
         holding trivially"
    );
}

/// `Decoded65C02::size` documents itself as "Total instruction byte count
/// (1–3)", and `bytes` is a fixed `[u8; 3]`, so a size outside that range would
/// index past the array it describes.
#[test]
fn cmos_length_is_always_one_to_three() {
    let mut decoded = 0usize;

    for opcode in 0u8..=0xFF {
        let bytes = probe(opcode);
        let Some(insn) = decode_65c02(&bytes) else { continue };
        decoded += 1;

        assert!(
            (1..=3).contains(&insn.size),
            "opcode {opcode:#04x} reported size {} — the field documents itself \
             as 1-3",
            insn.size
        );
        assert_eq!(
            insn.bytes[0], opcode,
            "opcode {opcode:#04x} decoded but its first byte is {:#04x}",
            insn.bytes[0]
        );
    }

    assert!(
        decoded >= 200,
        "only {decoded} of 256 opcodes decoded on CMOS — the assertions above \
         would be holding trivially"
    );
}

/// An empty buffer holds no opcode; no decoder may invent one.
#[test]
fn an_empty_buffer_is_rejected() {
    assert!(Mos6502Disassembler::new().decode_one(&[], 0x600, 0).is_none());
    assert!(decode_65c02(&[]).is_none());
}

/// A multi-byte instruction with its operand missing is truncated, not short:
/// reporting a length here would read past the buffer that was supplied.
#[test]
fn a_missing_operand_does_not_over_consume() {
    let dis = Mos6502Disassembler::new();
    for opcode in 0u8..=0xFF {
        if let Some(insn) = dis.decode_one(&[opcode], 0x600, 0) {
            assert_eq!(
                insn.bytes.len(),
                1,
                "opcode {opcode:#04x} ({}) claimed {} bytes from a 1-byte buffer",
                insn.mnemonic,
                insn.bytes.len()
            );
        }
        if let Some(insn) = decode_65c02(&[opcode]) {
            assert_eq!(
                insn.size, 1,
                "opcode {opcode:#04x} claimed size {} from a 1-byte buffer",
                insn.size
            );
        }
    }
}
