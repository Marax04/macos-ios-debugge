//! Soundness of constant-based crypto detection.
//!
//! Two obligations that pull in opposite directions, and a detector is only
//! useful if it meets both: it must FIND a known constant table that is really
//! present, and it must NOT claim one that is not. A detector that always says
//! "yes" and one that always says "no" each satisfy half of this, and each
//! would look fine under a suite that only tests its favoured direction.

use rustre_crypto_id::cipher_detection::BlockCipherDetector;
use rustre_crypto_id::{CryptoAlgorithm, AES_SBOX};

/// Deterministic noise — no external crates, reproducible failures.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut s = seed;
    (0..n)
        .map(|_| {
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (s >> 24) as u8
        })
        .collect()
}

/// A buffer that really contains the AES S-box must be recognised as AES,
/// wherever in the buffer it sits.
#[test]
fn the_aes_sbox_is_found_wherever_it_sits() {
    for prefix_len in [0usize, 1, 7, 64, 512] {
        let mut data = noise(prefix_len, 0xA5A5_1234_5678_9ABC);
        data.extend_from_slice(&AES_SBOX);
        data.extend_from_slice(&noise(32, 0x1111_2222_3333_4444));

        assert!(
            BlockCipherDetector::detects(&data, CryptoAlgorithm::Aes128)
                || BlockCipherDetector::detects(&data, CryptoAlgorithm::Aes256),
            "the AES S-box is present at offset {prefix_len} but was not detected"
        );
    }
}

/// Pure noise must not be reported as AES.
///
/// Checked over several seeds: a single lucky seed would prove nothing, and a
/// detector with a loose threshold fails here rather than in production.
#[test]
fn noise_is_not_mistaken_for_aes() {
    for (i, seed) in [0x1u64, 0xDEAD_BEEF, 0x0F0F_0F0F_0F0F_0F0F, 0x7777_7777].iter().enumerate() {
        let data = noise(4096, *seed);
        assert!(
            !BlockCipherDetector::detects(&data, CryptoAlgorithm::Aes128)
                && !BlockCipherDetector::detects(&data, CryptoAlgorithm::Aes256),
            "noise sample {i} (seed {seed:#x}) was reported as AES"
        );
    }
}

/// An S-box with a single byte corrupted is not the AES S-box.
///
/// This is the discriminating case: a detector matching on "looks like a
/// permutation of 0..=255" rather than on the actual table would accept it.
#[test]
fn a_corrupted_sbox_is_not_the_aes_sbox() {
    let mut table = AES_SBOX;
    table.swap(0, 1); // still a permutation of 0..=255, but not AES's
    let mut data = noise(16, 0xC0FF_EE00_1234_5678);
    data.extend_from_slice(&table);

    // Not asserting a specific verdict — only that a swapped table is not
    // treated as identical to the real one.
    let real_hit = {
        let mut d = noise(16, 0xC0FF_EE00_1234_5678);
        d.extend_from_slice(&AES_SBOX);
        BlockCipherDetector::detects(&d, CryptoAlgorithm::Aes128)
            || BlockCipherDetector::detects(&d, CryptoAlgorithm::Aes256)
    };
    let swapped_hit = BlockCipherDetector::detects(&data, CryptoAlgorithm::Aes128)
        || BlockCipherDetector::detects(&data, CryptoAlgorithm::Aes256);

    assert!(real_hit, "the genuine S-box must be detected for this test to mean anything");
    assert!(
        !swapped_hit,
        "a table with two bytes swapped was accepted as the AES S-box — the \
         detector is matching a shape, not the constants"
    );
}

/// Guards the tests above: the detector must produce *some* finding for a
/// genuine table, otherwise "no false positives" would hold trivially.
#[test]
fn the_detector_is_not_simply_silent() {
    let mut data = noise(8, 0x5555_AAAA_5555_AAAA);
    data.extend_from_slice(&AES_SBOX);
    let map = BlockCipherDetector::scan(&data);
    assert!(
        !map.is_empty(),
        "the detector reported nothing at all for a buffer containing the AES \
         S-box — every negative assertion in this file would pass vacuously"
    );
}
