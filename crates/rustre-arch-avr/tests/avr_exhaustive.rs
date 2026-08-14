//! Exhaustive properties of the two AVR decoders, and their agreement.
//!
//! An AVR opcode is one 16-bit word, so the whole domain is 65 536 values and
//! can be checked completely. The crate contains *two* independent decoders —
//! `AvrDecoder` and `AvrDisassembler` — which is exactly the shape that drifts:
//! each is internally consistent with whatever it believes, so only comparing
//! them can show a disagreement.

use rustre_arch_avr::avr_decoder::AvrDecoder;
use rustre_arch_avr::avr_disassembler::AvrDisassembler;

/// Bytes appended after the opcode word so that 32-bit instructions are not all
/// rejected for lack of a second word.
const TAIL: [u8; 4] = [0xAB, 0xCD, 0xEF, 0x01];

/// `AvrInstr::len` is documented as "Instruction length in bytes (2 or 4)".
/// Checked against every opcode rather than trusted.
#[test]
fn decoder_length_is_always_two_or_four() {
    let mut decoded = 0usize;

    for dec in [AvrDecoder::new(), AvrDecoder::new_large()] {
        for w in 0u16..=u16::MAX {
            let mut bytes = w.to_le_bytes().to_vec();
            bytes.extend_from_slice(&TAIL);

            if let Some(insn) = dec.decode(0x100, &bytes) {
                decoded += 1;
                assert!(
                    insn.len == 2 || insn.len == 4,
                    "opcode {w:#06x} ({}) reported len {} — the field documents \
                     itself as 2 or 4",
                    insn.mnemonic,
                    insn.len
                );
                assert!(
                    usize::from(insn.len) <= bytes.len(),
                    "opcode {w:#06x} reported len {} with only {} bytes supplied",
                    insn.len,
                    bytes.len()
                );
                assert!(
                    !insn.mnemonic.is_empty(),
                    "opcode {w:#06x} decoded with an empty mnemonic"
                );
            }
        }
    }

    assert!(
        decoded >= 2000,
        "only {decoded} opcodes decoded across both device classes — the \
         assertions above would be holding trivially"
    );
}

/// Fewer than two bytes cannot hold an opcode word.
#[test]
fn a_truncated_word_is_rejected() {
    let dec = AvrDecoder::new();
    for short in [vec![], vec![0x0Cu8]] {
        assert!(
            dec.decode(0x100, &short).is_none(),
            "{} byte(s) decoded as an instruction",
            short.len()
        );
    }
}

/// `AvrDisassembler::decode` returns an `AvrInsn` unconditionally — it claims
/// to be total. Checked over the whole word domain, with and without a second
/// word, since a 32-bit instruction consumes one.
#[test]
fn disassembler_is_total_over_every_word() {
    let dis = AvrDisassembler;
    let mut named = 0usize;

    for w in 0u16..=u16::MAX {
        for w2 in [None, Some(0xBEEFu16)] {
            let insn = dis.decode(w, w2, 0x100);
            assert!(
                !insn.mnemonic.is_empty(),
                "word {w:#06x} (second word {w2:?}) produced an empty mnemonic"
            );
            assert_eq!(insn.raw, w, "word {w:#06x} was not preserved in `raw`");
            if insn.mnemonic != "???" && insn.mnemonic != ".word" {
                named += 1;
            }
        }
    }

    assert!(
        named >= 2000,
        "only {named} words produced a real mnemonic — the totality check would \
         pass even if everything decoded to a placeholder"
    );
}

/// The two decoders must agree on which opcodes are 32-bit.
///
/// `AvrDecoder` says so via `len == 4`; `AvrDisassembler` says so by consuming a
/// second word (`raw2.is_some()`). A disagreement means one of them advances the
/// program counter by the wrong amount, and every later instruction in the
/// stream is decoded from the wrong offset.
#[test]
fn the_two_decoders_agree_on_instruction_width() {
    let dec = AvrDecoder::new();
    let dis = AvrDisassembler;
    let mut compared = 0usize;

    for w in 0u16..=u16::MAX {
        let mut bytes = w.to_le_bytes().to_vec();
        bytes.extend_from_slice(&TAIL);

        let Some(a) = dec.decode(0x100, &bytes) else { continue };
        let b = dis.decode(w, Some(0xBEEF), 0x100);

        // Only compare where the disassembler recognised the word; a
        // placeholder carries no width claim.
        if b.mnemonic == "???" || b.mnemonic == ".word" {
            continue;
        }
        compared += 1;

        assert_eq!(
            a.len == 4,
            b.raw2.is_some(),
            "opcode {w:#06x}: AvrDecoder says len={} ({}), AvrDisassembler {} a \
             second word ({}) — they disagree on the instruction width",
            a.len,
            a.mnemonic,
            if b.raw2.is_some() { "consumes" } else { "does not consume" },
            b.mnemonic
        );
    }

    assert!(
        compared >= 1000,
        "only {compared} opcodes were comparable — the agreement check would be \
         vacuous"
    );
}
