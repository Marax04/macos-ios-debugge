//! Exhaustive properties of the 68000 instruction decoder.
//!
//! The opcode is one 16-bit word, so the whole first-word domain is 65 536
//! values — checkable completely rather than by sampling. "No opcode makes the
//! decoder panic" then becomes a fact about every possible instruction word,
//! and the reported size can be checked against invariants of the ISA itself.

use rustre_arch_68k::decode_68k;

/// Extension bytes appended after the opcode word, so that instructions which
/// legitimately need operands are not all rejected as truncated.
const EXT: [u8; 10] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22];

/// Every opcode word decodes without panicking, and any size it reports obeys
/// the ISA's own rules.
///
/// A `CoreError` is a legitimate answer — an illegal encoding *should* be
/// rejected. What must not happen is an abort, or a size that the caller cannot
/// trust to advance the program counter.
#[test]
fn every_opcode_word_is_decoded_safely() {
    let mut decoded = 0usize;

    for w in 0u16..=u16::MAX {
        let mut bytes = Vec::with_capacity(2 + EXT.len());
        bytes.extend_from_slice(&w.to_be_bytes());
        bytes.extend_from_slice(&EXT);

        if let Ok((mnemonic, _operands, size, _flags)) = decode_68k(&bytes, 0x1000) {
            decoded += 1;

            assert!(
                size >= 2,
                "opcode {w:#06x} ({mnemonic}) reported size {size}: an \
                 instruction is at least one 16-bit word"
            );
            assert!(
                size <= bytes.len(),
                "opcode {w:#06x} ({mnemonic}) reported size {size} but only {} \
                 bytes were supplied — the caller would advance past the input",
                bytes.len()
            );
            assert_eq!(
                size % 2,
                0,
                "opcode {w:#06x} ({mnemonic}) reported an odd size {size}: 68000 \
                 instructions are whole 16-bit words"
            );
            assert!(
                !mnemonic.is_empty(),
                "opcode {w:#06x} decoded successfully but with an empty mnemonic"
            );
        }
    }

    // Anti-vacuity: a decoder that rejected everything would satisfy all the
    // assertions above without ever decoding an instruction.
    assert!(
        decoded >= 1000,
        "only {decoded} of 65536 opcode words decoded — the properties above \
         would be holding trivially"
    );
}

/// A truncated instruction must be reported as an error, never decoded.
#[test]
fn a_truncated_word_is_rejected() {
    for short in [vec![], vec![0x4Eu8]] {
        assert!(
            decode_68k(&short, 0x1000).is_err(),
            "{} byte(s) cannot hold an opcode word, but decoding succeeded",
            short.len()
        );
    }
}

/// Decoding is deterministic: the same bytes must always give the same answer.
///
/// Cheap to check, and it catches any accidental dependence on global or
/// interior-mutable state in the decode path.
#[test]
fn decoding_is_deterministic() {
    for w in (0u16..=u16::MAX).step_by(97) {
        let mut bytes = w.to_be_bytes().to_vec();
        bytes.extend_from_slice(&EXT);

        let a = decode_68k(&bytes, 0x1000).ok().map(|(m, o, s, _)| (m, o, s));
        let b = decode_68k(&bytes, 0x1000).ok().map(|(m, o, s, _)| (m, o, s));
        assert_eq!(a, b, "opcode {w:#06x} decoded differently on a second call");
    }
}
