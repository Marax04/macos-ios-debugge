//! The CRC window is masked three different ways (T3c).
//!
//! # Three behaviours for one field
//!
//! | site | masked bytes are… | buffer length |
//! |---|---|---|
//! | `flirt_gen::CrcTail::compute` (generator) | **dropped** | shorter |
//! | `flirt_apply::compute_flirt_crc` (validator) | **zeroed** | unchanged |
//! | `FlirtScanner::scan_fast` (the path actually used) | **not masked at all** | unchanged |
//!
//! Any two of these produce different bytes, hence different CRCs, whenever a
//! relocation falls inside the CRC window. The algorithm was unified in
//! iterations 2–3; the *input* to it was not.
//!
//! # Why this is the missing half of an earlier measurement
//!
//! Iteration 21 measured that 74.1% of the rust-stdlib database carries a CRC,
//! yet only **2 of 240** matches came from a CRC-bearing signature. That was
//! recorded as "their tails correctly disagree". These tests check the
//! alternative explanation: that a CRC computed over a *dropped-bytes* buffer
//! can never equal one computed over a *zeroed* or *unmasked* buffer, so
//! CRC-bearing signatures are being rejected by construction rather than on the
//! evidence.
//!
//! The tests do not assume which behaviour is right — IDA's own choice is not
//! established here (see T1/T15). They pin the divergence so it is a recorded
//! fact rather than a suspicion, and they will fail when it is resolved.

use rustre_flirt::crc::flirt_tail;

/// The generator's rule: skip masked offsets entirely.
fn crc_dropping_masked(data: &[u8], masked: &[usize]) -> u16 {
    let stable: Vec<u8> = data
        .iter()
        .enumerate()
        .filter(|(i, _)| !masked.contains(i))
        .map(|(_, b)| *b)
        .collect();
    flirt_tail(&stable)
}

/// The validator's rule: keep the length, zero the masked bytes.
fn crc_zeroing_masked(data: &[u8], masked: &[usize]) -> u16 {
    let mut buf = data.to_vec();
    for &i in masked {
        if i < buf.len() {
            buf[i] = 0;
        }
    }
    flirt_tail(&buf)
}

/// The scanner's rule: no masking.
fn crc_unmasked(data: &[u8]) -> u16 {
    flirt_tail(data)
}

const TAIL: &[u8] = &[0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0x48, 0x89, 0xC7];

#[test]
fn dropping_and_zeroing_disagree_whenever_a_byte_is_masked() {
    // A relocation typically covers 4 bytes of a RIP-relative displacement.
    let masked = [3usize, 4, 5, 6];
    let dropped = crc_dropping_masked(TAIL, &masked);
    let zeroed = crc_zeroing_masked(TAIL, &masked);
    assert_ne!(
        dropped, zeroed,
        "generatore e validatore concordano su questo input: la divergenza \
         potrebbe essere stata risolta — aggiorna il test e PROGRESS.md"
    );
}

#[test]
fn the_scanner_disagrees_with_both_when_a_byte_is_masked() {
    let masked = [3usize, 4, 5, 6];
    let unmasked = crc_unmasked(TAIL);
    assert_ne!(unmasked, crc_dropping_masked(TAIL, &masked));
    assert_ne!(unmasked, crc_zeroing_masked(TAIL, &masked));
}

/// The three rules agree exactly when there is nothing to mask — which is why
/// the divergence is invisible on the signatures that have no relocations, and
/// why a spot check on a simple function would never reveal it.
#[test]
fn all_three_agree_when_no_byte_is_masked() {
    let none: [usize; 0] = [];
    let a = crc_dropping_masked(TAIL, &none);
    let b = crc_zeroing_masked(TAIL, &none);
    let c = crc_unmasked(TAIL);
    assert_eq!(a, b);
    assert_eq!(b, c);
}

/// A masked byte that happens to already be zero is the one case where zeroing
/// is a no-op — so a test built on such data would *also* miss the divergence.
/// Recorded because it is exactly the kind of accidental corpus that makes a
/// broken invariant look sound.
#[test]
fn zeroing_is_a_no_op_only_when_the_masked_byte_was_already_zero() {
    let data = [0x48u8, 0x00, 0x00, 0x00, 0x00, 0xC3];
    let masked = [1usize, 2, 3, 4];
    assert_eq!(
        crc_zeroing_masked(&data, &masked),
        crc_unmasked(&data),
        "azzerare byte gia' nulli non cambia nulla"
    );
    // But dropping them still shortens the buffer, so the generator still differs.
    assert_ne!(
        crc_dropping_masked(&data, &masked),
        crc_unmasked(&data),
        "scartare i byte accorcia comunque il buffer"
    );
}

/// The practical consequence, stated as a test: a signature whose CRC window
/// contains a relocation cannot be validated by the scanner, whatever its bytes.
#[test]
fn a_signature_with_a_masked_crc_window_can_never_validate() {
    let masked = [2usize, 3];
    // What the generator would store.
    let stored = crc_dropping_masked(TAIL, &masked);
    // What the scanner computes when it meets the same bytes again.
    let recomputed = crc_unmasked(TAIL);
    assert_ne!(
        stored, recomputed,
        "se questi coincidessero, la firma validerebbe e T3c sarebbe risolto"
    );
}

// ─── the field's meaning is ambiguous too ────────────────────────────────────

/// `crc_length` means two different things on the two sides.
///
/// The generator stores `stable.len()` — **how many bytes it actually hashed**
/// after dropping the masked ones. The scanner reads `data[start..start+crc_len]`
/// — **how many contiguous bytes to hash**. Those coincide only when nothing was
/// masked.
///
/// Supporting measurements, all recorded:
/// * 49 780 of the 67 168 database patterns carry a CRC, with `crc_length`
///   scattered across 16, 1, 4, 7, 2, 6 … — consistent with a count of survivors,
///   not with a fixed window;
/// * 31 533 patterns (47%) contain wildcards;
/// * iteration 21 measured that only **2 of 240** matches came from a
///   CRC-bearing signature, though 74.1% of the database has one.
///
/// Together those make a strong case that CRC-bearing signatures are rejected
/// **by construction** rather than on the evidence. It is not proof: closing it
/// needs an end-to-end generate→scan run on a function with a relocation inside
/// its CRC window, which is T14.
#[test]
fn a_stable_byte_count_and_a_window_length_are_not_interchangeable() {
    let masked = [2usize, 3, 4, 5];
    let window_len = TAIL.len();
    let stable_count = window_len - masked.len();

    assert_ne!(
        stable_count, window_len,
        "con byte mascherati i due significati divergono"
    );

    // What the generator stored: hash of the survivors, labelled `stable_count`.
    let stored_crc = crc_dropping_masked(TAIL, &masked);
    // What a scanner does with that label: hash the first `stable_count`
    // contiguous bytes — a different set entirely.
    let scanner_crc = crc_unmasked(&TAIL[..stable_count]);

    assert_ne!(
        stored_crc, scanner_crc,
        "se coincidessero, i due significati di crc_length sarebbero compatibili"
    );
}
