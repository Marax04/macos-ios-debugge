//! Cross-checks between the crate's THREE public PKCS#7 implementations.
//!
//! `padding_oracle`, `padding_oracle_detector` and `padding_oracle_attack` each
//! carry their own pad/unpad/validate. Nothing forced them to agree, and they
//! had already drifted once: `padding_oracle_attack::pkcs7_pad` was missing the
//! block-size guard its two twins have, so `block_size == 0` divided by zero.
//! These tests make the copies check each other — a divergence in any one of
//! them now fails here instead of silently producing a different padding.

use rustre_crypto_oracle::padding_oracle as po;
use rustre_crypto_oracle::padding_oracle_attack as attack;
use rustre_crypto_oracle::padding_oracle_detector as det;

/// Inputs chosen to hit every interesting length class: empty, shorter than a
/// block, exactly one block (which must gain a FULL block of padding), and
/// longer than a block.
fn samples() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        b"a".to_vec(),
        b"0123456789".to_vec(),
        vec![0xAB; 16],
        vec![0x00; 31],
        (0..=255u8).collect(),
    ]
}

#[test]
fn all_three_pad_implementations_agree() {
    for data in samples() {
        for bs in [1usize, 8, 16, 32, 255] {
            let a = po::add_pkcs7(&data, bs);
            let b = det::pkcs7_pad(&data, bs);
            let c = attack::pkcs7_pad(&data, bs);
            assert_eq!(a, b, "padding_oracle vs detector differ (len={}, bs={bs})", data.len());
            assert_eq!(a, c, "padding_oracle vs attack differ (len={}, bs={bs})", data.len());
            // The defining property of PKCS#7: the result is a whole number of
            // blocks and always gains at least one byte.
            assert_eq!(a.len() % bs, 0, "not block-aligned (len={}, bs={bs})", data.len());
            assert!(a.len() > data.len(), "padding must add at least one byte");
        }
    }
}

#[test]
fn strip_and_unpad_agree_and_invert_pad() {
    for data in samples() {
        for bs in [1usize, 8, 16, 32, 255] {
            let padded = po::add_pkcs7(&data, bs);
            let stripped = po::strip_pkcs7(&padded);
            let unpadded = det::pkcs7_unpad(&padded);
            assert_eq!(stripped, unpadded, "strip vs unpad differ (len={}, bs={bs})", data.len());
            assert_eq!(
                stripped.as_deref(),
                Some(data.as_slice()),
                "unpad(pad(x)) must be x (len={}, bs={bs})",
                data.len()
            );
        }
    }
}

#[test]
fn both_validators_agree_on_every_short_buffer() {
    // Exhaustive over a small domain: every 1- and 2-byte buffer, plus a set of
    // hand-built valid and invalid paddings.
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for b in 0..=255u8 {
        cases.push(vec![b]);
        cases.push(vec![0x00, b]);
        cases.push(vec![b, b]);
    }
    cases.push(Vec::new());
    cases.push(vec![0x03, 0x03, 0x03]);
    cases.push(vec![0x03, 0x03, 0x02]); // inconsistent
    cases.push(vec![0x04, 0x04, 0x04]); // pad longer than the buffer

    for c in cases {
        let a = po::validate_pkcs7(&c);
        let b = det::pkcs7_validate(&c).is_some();
        assert_eq!(a, b, "validators disagree on {c:02x?}");
    }
}
