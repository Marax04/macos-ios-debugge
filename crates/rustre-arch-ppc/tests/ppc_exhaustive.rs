//! Exhaustive properties of the two PowerPC decoders, and their agreement.
//!
//! A PowerPC instruction is a fixed 32-bit word, so the full domain is 2^32 and
//! cannot be enumerated.  What *selects* the instruction, though, is only the
//! 6-bit primary opcode and the 10-bit extended opcode field — 65 536
//! combinations — and that whole selection space is enumerated here with the
//! remaining operand fields held at zero.  Nothing is sampled.
//!
//! The crate carries *two* independently written implementations, `PpcDecoder`
//! and `PpcDisassembler`, which is the shape that drifts: each stays
//! self-consistent with whatever it believes, so only comparing them can show a
//! disagreement.  Both are total — neither returns an `Option` — and each has
//! its own sentinel for an unrecognised word (`DC.W` with `PpcForm::Unknown`,
//! and `"unknown"` respectively), so "recognised" is well defined on both sides.
//!
//! Modelled on `arch-avr/tests/avr_exhaustive.rs`.

use rustre_arch_ppc::ppc_decoder::{PpcDecoder, PpcForm};
use rustre_arch_ppc::ppc_disassembler::PpcDisassembler;

/// Build a word from the two fields that select an instruction: the primary
/// opcode (bits 0-5, i.e. `word >> 26`) and the extended opcode (bits 21-30).
const fn selector_word(primary: u32, extended: u32) -> u32 {
    (primary << 26) | (extended << 1)
}

/// Every word the decoder accepts must report back the word it was given and a
/// non-empty mnemonic, and its `primary` field must match the bits it came
/// from.  A `primary` that disagreed with the raw word would make every
/// downstream opcode test wrong.
#[test]
fn decoder_is_self_consistent_over_the_selection_space() {
    let dec = PpcDecoder::default();
    let mut recognised = 0usize;

    for primary in 0u32..64 {
        for extended in 0u32..1024 {
            let word = selector_word(primary, extended);
            let insn = dec.decode_word(0x1000, word);

            assert_eq!(
                insn.raw, word,
                "word {word:#010x} decoded but reports raw {:#010x}",
                insn.raw
            );
            assert_eq!(
                u32::from(insn.primary.0),
                primary,
                "word {word:#010x} has primary opcode {primary} but the decoder \
                 reports {}",
                insn.primary.0
            );
            assert!(
                !insn.mnemonic.is_empty(),
                "word {word:#010x} decoded with an empty mnemonic"
            );
            if insn.form != PpcForm::Unknown {
                recognised += 1;
            }
        }
    }

    assert!(
        recognised >= 1_000,
        "only {recognised} of 65536 selector words were recognised — the \
         assertions above would be holding trivially"
    );
}

/// The disassembler is total too: it must always return the word it was given
/// and a non-empty mnemonic.
#[test]
fn disassembler_is_self_consistent_over_the_selection_space() {
    let mut recognised = 0usize;

    for primary in 0u32..64 {
        for extended in 0u32..1024 {
            let word = selector_word(primary, extended);
            let insn = PpcDisassembler::decode_insn(word, 0x1000);

            assert_eq!(
                insn.raw, word,
                "word {word:#010x} decoded but reports raw {:#010x}",
                insn.raw
            );
            assert!(
                !insn.mnemonic.is_empty(),
                "word {word:#010x} decoded with an empty mnemonic"
            );
            if insn.mnemonic != "unknown" {
                recognised += 1;
            }
        }
    }

    assert!(
        recognised >= 1_000,
        "only {recognised} of 65536 selector words were recognised — the \
         assertions above would be holding trivially"
    );
}

/// A four-byte buffer holds exactly one instruction, and a shorter one holds
/// none: `PpcDecoder::decode` is the fallible entry point and must say so.
#[test]
fn a_truncated_word_is_rejected() {
    let dec = PpcDecoder::default();
    assert!(dec.decode(0x1000, &[]).is_none());
    assert!(dec.decode(0x1000, &[0x38]).is_none());
    assert!(dec.decode(0x1000, &[0x38, 0x60]).is_none());
    assert!(dec.decode(0x1000, &[0x38, 0x60, 0x00]).is_none());
    // `addi r3, r0, 1` — big-endian, four bytes, must decode.
    assert!(dec.decode(0x1000, &[0x38, 0x60, 0x00, 0x01]).is_some());
}

/// The byte-slice entry point and the word entry point must not disagree: the
/// first is documented as a thin big-endian wrapper over the second.
#[test]
fn the_slice_and_word_entry_points_agree() {
    let dec = PpcDecoder::default();
    let mut compared = 0usize;

    for primary in 0u32..64 {
        for extended in 0u32..1024 {
            let word = selector_word(primary, extended);
            let from_slice = dec
                .decode(0x1000, &word.to_be_bytes())
                .expect("four bytes always hold one PowerPC instruction");
            let from_word = dec.decode_word(0x1000, word);
            compared += 1;

            assert_eq!(
                from_slice.mnemonic, from_word.mnemonic,
                "word {word:#010x}: the slice entry point says {} but the word \
                 entry point says {}",
                from_slice.mnemonic, from_word.mnemonic
            );
            assert_eq!(from_slice.raw, from_word.raw, "word {word:#010x}: raw differs");
        }
    }

    assert_eq!(
        compared, 65_536,
        "the selection space was not fully enumerated"
    );
}
