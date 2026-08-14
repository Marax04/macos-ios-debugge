//! Regression tests for logic defects found by the wave-2 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact symptom the audit predicted.

use rustre_deobf_string::stack_string_recovery::{
    ByteAssignment, PlacementStyle, StackStringScanner,
};

fn assign(insn_addr: u64, offset: i32, byte: u8) -> ByteAssignment {
    ByteAssignment {
        insn_addr,
        frame_register: "rbp".to_string(),
        offset,
        bytes: vec![byte],
        style: PlacementStyle::MovImm8,
    }
}

/// Writing `XXXX` to `[rbp-8 .. rbp-5]` and then overwriting the same four
/// slots with `Hi!\0`.
fn overwritten() -> Vec<ByteAssignment> {
    vec![
        assign(0x1000, -8, b'X'),
        assign(0x1001, -7, b'X'),
        assign(0x1002, -6, b'X'),
        assign(0x1003, -5, b'X'),
        assign(0x1010, -8, b'H'),
        assign(0x1011, -7, b'i'),
        assign(0x1012, -6, b'!'),
        assign(0x1013, -5, 0),
    ]
}

/// A later write to the same stack slot REPLACES the earlier one — that is what
/// a store does. `build_pattern` sorts the slots by offset with a STABLE sort
/// and then `dedup_by_key`s them, and `dedup_by_key` keeps the FIRST of each
/// run: the earliest write wins and the string is reconstructed as it was
/// before being overwritten.
///
/// Obfuscators write decoy bytes and overwrite them precisely to defeat naive
/// recovery, so this is the case the pass exists for.
#[test]
fn the_last_write_to_a_slot_wins() {
    let patterns = StackStringScanner::with_defaults().scan(&overwritten());
    assert_eq!(patterns.len(), 1, "one contiguous region was written");

    assert_eq!(
        patterns[0].bytes,
        b"Hi!\0",
        "the second round of writes overwrote the first; got {:?}",
        String::from_utf8_lossy(&patterns[0].bytes)
    );
}

/// Without an overwrite the reconstruction is unchanged.
#[test]
fn a_plain_string_is_still_recovered() {
    let a = vec![
        assign(0x1000, -8, b'H'),
        assign(0x1001, -7, b'e'),
        assign(0x1002, -6, b'l'),
        assign(0x1003, -5, b'p'),
        assign(0x1004, -4, 0),
    ];
    let patterns = StackStringScanner::with_defaults().scan(&a);
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns[0].bytes, b"Help\0");
}

/// Bytes must stay ordered by stack offset, not by write order.
#[test]
fn bytes_are_ordered_by_offset_not_by_write_order() {
    // Written back-to-front, as a compiler may well emit.
    let a = vec![
        assign(0x1000, -5, b'p'),
        assign(0x1001, -6, b'l'),
        assign(0x1002, -7, b'e'),
        assign(0x1003, -8, b'H'),
    ];
    let patterns = StackStringScanner::with_defaults().scan(&a);
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns[0].bytes, b"Help");
}

// ── Poly1305: the final reduction picked the wrong branch ────────────────

use rustre_deobf_string::chacha20::Poly1305;

/// With an all-zero key and an empty message the accumulator `h` is 0 and the
/// pad `s` is 0, so the tag is 16 zero bytes.
///
/// The final "conditional subtract" computes `g = h + 5` and keeps `g` only
/// when `h >= 2^130 - 5`. The mask was built as
/// `!((g[4] >> 31).wrapping_sub(1))`, and that leading `!` INVERTS it with
/// respect to the reference (poly1305-donna uses `(g4 >> 31) - 1`): when the
/// subtraction borrows — i.e. `h < p`, so `h` must be kept — the code selected
/// `g` instead, and the tag came out `05 00 00 …`.
///
/// A MAC that is wrong on the empty message is wrong wherever `h` lands below
/// the prime, which is most of the time; the empty message is simply the
/// smallest input that exhibits it.
#[test]
fn poly1305_of_the_empty_message_with_a_zero_key_is_zero() {
    let tag = Poly1305::new(&[0u8; 32]).finalize();
    assert_eq!(
        tag,
        [0u8; 16],
        "h = 0 and s = 0, so the tag is zero; a non-zero tag means the \
         conditional subtract kept h + 5"
    );
}

// NOTE: a companion test feeding a real message cannot be written today —
// `Poly1305` exposes only `new` and `finalize`, `process_block` is private, and
// nothing in the crate constructs one. The type is public API with no way to
// absorb a message; reported separately.
