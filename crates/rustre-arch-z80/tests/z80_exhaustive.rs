//! Exhaustive properties of the two Z80 decoders, and their agreement.
//!
//! A Z80 instruction is at most four bytes, but every one of them is selected
//! by its first two: a single opcode, or a prefix (`CB`/`DD`/`ED`/`FD`) plus
//! one more.  Enumerating those two bytes is 65 536 cases — the whole
//! instruction-selection domain — so nothing is sampled here.
//!
//! The crate contains *two* independent implementations, `Z80Decoder` and
//! `Z80Disassembler`, which is exactly the shape that drifts: each stays
//! self-consistent with whatever it believes, so only comparing them can
//! surface a disagreement.  Modelled on `arch-avr/tests/avr_exhaustive.rs`.

use rustre_arch_z80::z80_decoder::Z80Decoder;
use rustre_arch_z80::z80_disassembler::Z80Disassembler;

/// Bytes appended after the two selector bytes so that the longer forms
/// (`DD CB dd op`, `LD dd,nn`, …) are not all rejected for lack of operands.
const TAIL: [u8; 4] = [0xAB, 0xCD, 0xEF, 0x01];

fn probe(hi: u8, lo: u8) -> Vec<u8> {
    let mut bytes = vec![hi, lo];
    bytes.extend_from_slice(&TAIL);
    bytes
}

/// `Z80Instr::len` documents itself as "Length of the instruction in bytes
/// (1-4)".  Checked against the whole selector domain rather than trusted.
#[test]
fn decoder_length_is_always_one_to_four() {
    let dec = Z80Decoder::new();
    let mut decoded = 0usize;

    for hi in 0u8..=0xFF {
        for lo in 0u8..=0xFF {
            let bytes = probe(hi, lo);
            if let Some(insn) = dec.decode(0x100, &bytes) {
                decoded += 1;
                assert!(
                    (1..=4).contains(&insn.len),
                    "opcode {hi:#04x} {lo:#04x} ({}) reported len {} — the field \
                     documents itself as 1-4",
                    insn.mnemonic,
                    insn.len
                );
                assert!(
                    usize::from(insn.len) <= bytes.len(),
                    "opcode {hi:#04x} {lo:#04x} reported len {} with only {} bytes supplied",
                    insn.len,
                    bytes.len()
                );
                assert!(
                    !insn.mnemonic.is_empty(),
                    "opcode {hi:#04x} {lo:#04x} decoded with an empty mnemonic"
                );
            }
        }
    }

    assert!(
        decoded >= 30_000,
        "only {decoded} of 65536 selector pairs decoded — the assertions above \
         would be holding trivially"
    );
}

/// Whatever the decoder accepts, the disassembler must also render, and the two
/// must agree on how many bytes were consumed.  A disagreement means one of them
/// would desynchronise a linear sweep against the other.
#[test]
fn decoder_and_disassembler_agree_on_length() {
    let dec = Z80Decoder::new();
    let dis = Z80Disassembler::with_defaults();
    let mut compared = 0usize;

    for hi in 0u8..=0xFF {
        for lo in 0u8..=0xFF {
            let bytes = probe(hi, lo);
            let Some(insn) = dec.decode(0x100, &bytes) else { continue };
            let Some(line) = dis.disasm_one(0x100, &bytes) else {
                panic!(
                    "opcode {hi:#04x} {lo:#04x} decodes as {} but the \
                     disassembler rejects it",
                    insn.mnemonic
                );
            };
            compared += 1;
            assert_eq!(
                line.bytes.len(),
                usize::from(insn.len),
                "opcode {hi:#04x} {lo:#04x}: decoder says {} bytes ({}), \
                 disassembler consumed {} ({}) — a linear sweep would \
                 desynchronise",
                insn.len,
                insn.mnemonic,
                line.bytes.len(),
                line.text
            );
            assert!(
                !line.mnemonic.is_empty(),
                "opcode {hi:#04x} {lo:#04x} rendered with an empty mnemonic"
            );
        }
    }

    assert!(
        compared >= 30_000,
        "only {compared} selector pairs compared — the assertions above would be \
         holding trivially"
    );
}

/// An empty buffer holds no opcode; neither implementation may invent one.
#[test]
fn an_empty_buffer_is_rejected() {
    assert!(Z80Decoder::new().decode(0x100, &[]).is_none());
    assert!(Z80Disassembler::with_defaults().disasm_one(0x100, &[]).is_none());
}

/// A prefix byte with nothing after it is a truncated instruction, not a
/// one-byte one: reporting a length here would over-consume the buffer.
#[test]
fn a_lone_prefix_byte_does_not_over_consume() {
    let dec = Z80Decoder::new();
    for prefix in [0xCBu8, 0xDD, 0xED, 0xFD] {
        if let Some(insn) = dec.decode(0x100, &[prefix]) {
            assert!(
                usize::from(insn.len) <= 1,
                "lone prefix {prefix:#04x} decoded as {} claiming {} bytes from a \
                 1-byte buffer",
                insn.mnemonic,
                insn.len
            );
        }
    }
}
