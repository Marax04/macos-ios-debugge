//! Exhaustive properties of the MSP430 decoders, and their agreement.
//!
//! An MSP430 instruction is selected entirely by its first 16-bit word, so the
//! domain is 65 536 values and can be checked completely — nothing here is
//! sampled.
//!
//! The crate carries *two* independently written decoders, `decoder` and
//! `msp430_decoder`, which is exactly the shape that drifts: each stays
//! self-consistent with whatever it believes, so only comparing them across the
//! whole domain can show a disagreement.  Both document the same instruction
//! widths — `Msp430Insn::size` says "Total byte width (2, 4, or 6)" and
//! `Msp430Instr::length` says "Total byte length (2 or 4, rarely 6)" — so those
//! doc comments are a specification already written down, and are checked
//! rather than trusted.
//!
//! Modelled on `arch-avr/tests/avr_exhaustive.rs`.

use rustre_arch_msp430::decoder::decode_insn;
use rustre_arch_msp430::msp430_decoder::Msp430Decoder;

/// Extension words appended after the opcode word so that the 4- and 6-byte
/// forms are not all rejected for lack of operands.
const TAIL: [u8; 6] = [0x34, 0x12, 0x78, 0x56, 0xBC, 0x9A];

fn probe(word: u16) -> Vec<u8> {
    let mut bytes = word.to_le_bytes().to_vec();
    bytes.extend_from_slice(&TAIL);
    bytes
}

/// `Msp430Insn::size` documents itself as "Total byte width (2, 4, or 6)".
#[test]
fn decoder_width_is_always_two_four_or_six() {
    let mut decoded = 0usize;

    for word in 0u16..=u16::MAX {
        let bytes = probe(word);
        let Ok(insn) = decode_insn(&bytes, 0x1000) else { continue };
        decoded += 1;

        assert!(
            matches!(insn.size, 2 | 4 | 6),
            "word {word:#06x} ({}) reported size {} — the field documents itself \
             as 2, 4 or 6",
            insn.mnemonic(),
            insn.size
        );
        assert!(
            insn.size <= bytes.len(),
            "word {word:#06x} reported size {} with only {} bytes supplied",
            insn.size,
            bytes.len()
        );
        assert_eq!(
            insn.raw, word,
            "word {word:#06x} decoded but reports raw word {:#06x}",
            insn.raw
        );
        assert!(
            !insn.mnemonic().is_empty(),
            "word {word:#06x} decoded with an empty mnemonic"
        );
    }

    assert!(
        decoded >= 30_000,
        "only {decoded} of 65536 words decoded — the assertions above would be \
         holding trivially"
    );
}

/// `Msp430Instr::length` documents itself as "Total byte length (2 or 4, rarely
/// 6)".
#[test]
fn second_decoder_length_is_always_two_four_or_six() {
    let dec = Msp430Decoder;
    let mut decoded = 0usize;

    for word in 0u16..=u16::MAX {
        let bytes = probe(word);
        let Ok(insn) = dec.decode(&bytes, 0x1000) else { continue };
        decoded += 1;

        assert!(
            matches!(insn.length, 2 | 4 | 6),
            "word {word:#06x} ({}) reported length {} — the field documents \
             itself as 2, 4 or 6",
            insn.mnemonic,
            insn.length
        );
        assert_eq!(
            insn.opcode, word,
            "word {word:#06x} decoded but reports opcode {:#06x}",
            insn.opcode
        );
        assert!(
            !insn.mnemonic.is_empty(),
            "word {word:#06x} decoded with an empty mnemonic"
        );
    }

    assert!(
        decoded >= 30_000,
        "only {decoded} of 65536 words decoded — the assertions above would be \
         holding trivially"
    );
}

/// Where both decoders accept a word they must agree on how many bytes it
/// occupies.  A disagreement means a linear sweep driven by one of them would
/// desynchronise against the other.
#[test]
fn the_two_decoders_agree_on_instruction_width() {
    let dec = Msp430Decoder;
    let mut compared = 0usize;

    for word in 0u16..=u16::MAX {
        let bytes = probe(word);
        let (Ok(a), Ok(b)) = (decode_insn(&bytes, 0x1000), dec.decode(&bytes, 0x1000)) else {
            continue;
        };
        compared += 1;
        assert_eq!(
            a.size,
            usize::from(b.length),
            "word {word:#06x}: `decoder` says {} bytes ({}), `msp430_decoder` \
             says {} ({}) — a linear sweep would desynchronise",
            a.size,
            a.mnemonic(),
            b.length,
            b.mnemonic
        );
    }

    assert!(
        compared >= 30_000,
        "only {compared} words decoded by both — the assertion above would be \
         holding trivially"
    );
}

/// Fewer than two bytes cannot hold an opcode word; neither decoder may invent
/// one.
#[test]
fn a_truncated_word_is_rejected() {
    let dec = Msp430Decoder;
    for short in [&[][..], &[0x30][..]] {
        assert!(
            decode_insn(short, 0x1000).is_err(),
            "`decoder` accepted a {}-byte buffer",
            short.len()
        );
        assert!(
            dec.decode(short, 0x1000).is_err(),
            "`msp430_decoder` accepted a {}-byte buffer",
            short.len()
        );
    }
}
