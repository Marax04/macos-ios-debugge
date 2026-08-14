//! Exhaustive properties of the `ETMv4` atom-byte classifier.
//!
//! `AtomPattern::decode_etm4` maps a single byte to an atom pattern, so its
//! domain is 256 values and can be checked completely — nothing here is
//! sampled.
//!
//! The invariants asserted below are taken from the field documentation on
//! `AtomPattern` itself, which is a specification already written down:
//!
//! * `en_bits` — "E/N bits (1 = taken/Execute, 0 = Not-taken)"
//! * `count`   — "Number of valid atom bits"
//!
//! Read together, those two say `en_bits` is a bitmask of which only the low
//! `count` bits are meaningful — so a pattern reporting E/N bits above its own
//! count is describing atoms it also says are not there.
//!
//! Modelled on `arch-avr/tests/avr_exhaustive.rs`.

use rustre_trace_coresight::etm_decoder::AtomPattern;

/// Every accepted byte must report itself back, and must claim at least one
/// atom: a zero-atom pattern would advance a trace walk by nothing.
#[test]
fn accepted_bytes_are_self_consistent() {
    let mut accepted = 0usize;

    for b in 0u8..=0xFF {
        let Some(p) = AtomPattern::decode_etm4(b) else { continue };
        accepted += 1;

        assert_eq!(
            p.raw, b,
            "byte {b:#04x} decoded but reports raw {:#04x}",
            p.raw
        );
        assert!(
            p.count >= 1,
            "byte {b:#04x} ({:?}) decoded with count 0 — a pattern must carry \
             at least one atom",
            p.format
        );
    }

    assert!(
        accepted >= 64,
        "only {accepted} of 256 bytes were accepted as atom packets — the \
         assertions above would be holding trivially"
    );
}

/// `count` is documented as "Number of valid atom bits" and `en_bits` as the
/// E/N bits, so every set bit of `en_bits` must lie inside `count`.
///
/// **This test currently fails and is ignored on purpose.**  Byte `0xC3` takes
/// the F6 arm, where `count = ((b >> 2) & 0xF) + 1` is 1 while
/// `en_bits = b & 0b11` is `0b11` — two E/N bits for one declared atom.  A
/// consumer reading that pair either drops a real atom or invents one.
///
/// It is left failing rather than "fixed" because deciding *which* side is
/// wrong — the count or the mask — requires ARM IHI0064H (ETMv4), and guessing
/// the encoding would be worse than recording the inconsistency.  The same
/// document is needed to settle two doc-vs-code contradictions found alongside
/// it: `AtomFormat::F4` is documented as "four atoms" while the code emits
/// `count: 5`, and `F5` is documented as "5–23 atoms" while the code emits
/// `count: 1`.  Remove the `#[ignore]` once the encoding is confirmed.
#[test]
#[ignore = "known inconsistency at byte 0xC3 (F6); needs ARM IHI0064H to resolve"]
fn en_bits_fit_within_the_declared_count() {
    for b in 0u8..=0xFF {
        let Some(p) = AtomPattern::decode_etm4(b) else { continue };

        // `count` can legitimately reach 24, beyond a u32 shift's comfort.
        let width = u32::from(p.count).min(32);
        let limit = if width >= 32 { u32::MAX } else { (1u32 << width) - 1 };

        assert!(
            p.en_bits <= limit,
            "byte {b:#04x} ({:?}) reports en_bits {:#b} with count {} — bits \
             above the count describe atoms the pattern says are not there",
            p.format,
            p.en_bits,
            p.count
        );
    }
}

/// The classifier is a pure function of the byte: decoding twice must give the
/// same answer.  Cheap to state, and it pins the absence of hidden state.
#[test]
fn the_classifier_is_pure() {
    for b in 0u8..=0xFF {
        let first = AtomPattern::decode_etm4(b);
        let second = AtomPattern::decode_etm4(b);
        assert_eq!(
            first.is_some(),
            second.is_some(),
            "byte {b:#04x} classified inconsistently across two calls"
        );
        if let (Some(a), Some(c)) = (first, second) {
            assert_eq!(a.count, c.count, "byte {b:#04x}: count differs across calls");
            assert_eq!(a.en_bits, c.en_bits, "byte {b:#04x}: en_bits differ across calls");
            assert_eq!(a.format, c.format, "byte {b:#04x}: format differs across calls");
        }
    }
}
