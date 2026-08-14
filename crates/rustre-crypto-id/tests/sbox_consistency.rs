//! Self-consistency of the hand-transcribed cryptographic S-boxes.
//!
//! These tables are 256 hand-written bytes each and exist in more than one copy
//! (`lib.rs` and `constant_db.rs`, plus an `AES_INV_SBOX_V2`). Nothing in the
//! crate would notice a single mistyped entry: the scanners would simply stop
//! recognising the algorithm they are meant to find. The AES pair carries its
//! own oracle — the inverse S-box is defined as the inverse permutation of the
//! S-box — so correctness can be asserted without an external table.

use rustre_crypto_id::{AES_INV_SBOX, AES_SBOX, SM4_SBOX};
use rustre_crypto_id::constant_db;

fn is_permutation(t: &[u8; 256]) -> bool {
    let mut seen = [false; 256];
    for &b in t.iter() {
        if seen[b as usize] {
            return false;
        }
        seen[b as usize] = true;
    }
    true
}

#[test]
fn aes_inv_sbox_is_the_inverse_permutation_of_aes_sbox() {
    assert!(is_permutation(&AES_SBOX), "AES S-box must be a permutation");
    assert!(is_permutation(&AES_INV_SBOX), "AES inverse S-box must be a permutation");
    for i in 0..256usize {
        let fwd = AES_SBOX[i] as usize;
        assert_eq!(
            AES_INV_SBOX[fwd] as usize, i,
            "AES_INV_SBOX[AES_SBOX[{i}]] must be {i}"
        );
    }
    // Anchor on the first row of FIPS-197 Fig. 7 so a wholesale replacement of
    // both tables by some other consistent pair would still be caught.
    assert_eq!(
        &AES_SBOX[..8],
        &[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]
    );
    assert_eq!(
        &AES_INV_SBOX[..8],
        &[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38]
    );
}

#[test]
fn duplicate_sbox_copies_agree() {
    assert_eq!(constant_db::AES_SBOX, AES_SBOX, "constant_db copy of the AES S-box drifted");
    assert_eq!(
        constant_db::AES_INV_SBOX, AES_INV_SBOX,
        "constant_db copy of the AES inverse S-box drifted"
    );
}

#[test]
fn sm4_sbox_is_a_permutation() {
    assert!(is_permutation(&SM4_SBOX), "SM4 S-box must be a permutation");
    // First entries of the SM4 S-box (GB/T 32907-2016).
    assert_eq!(&SM4_SBOX[..8], &[0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7]);
}
