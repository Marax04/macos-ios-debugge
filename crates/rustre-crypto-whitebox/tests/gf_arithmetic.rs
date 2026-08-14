//! Exact-oracle checks for the GF(2^8) arithmetic used by the AES attacks.
//!
//! The crate carries four hand-written copies of the same multiply (in
//! `bge_attack`, `bge_attacker`, `dfa_attacker` and `dfa_full`) plus two
//! precomputed times-2/times-3 tables. The field itself is the oracle: AES
//! works in GF(2^8) modulo x^8+x^4+x^3+x+1, so every property below is exact
//! and needs no reference implementation. Without these, a wrong reduction
//! constant would not break any build — the attacks would simply stop
//! recovering keys, which is a silent failure.

use rustre_crypto_whitebox::bge_attack::{gf_inv, gf_mul};
use rustre_crypto_whitebox::dfa_full::RoundKeyExtractor;

#[test]
fn gf_mul_obeys_the_field_axioms() {
    // Identity and absorbing element, over the whole domain.
    for a in 0..=255u8 {
        assert_eq!(gf_mul(a, 1), a, "a*1 must be a (a={a})");
        assert_eq!(gf_mul(a, 0), 0, "a*0 must be 0 (a={a})");
    }
    // Commutativity over the entire 256x256 domain.
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            assert_eq!(gf_mul(a, b), gf_mul(b, a), "commutativity failed at ({a},{b})");
        }
    }
    // Distributivity over XOR, the property AES MixColumns actually relies on.
    for a in 0..=255u8 {
        for b in (0..=255u8).step_by(17) {
            for c in (0..=255u8).step_by(23) {
                assert_eq!(
                    gf_mul(a, b ^ c),
                    gf_mul(a, b) ^ gf_mul(a, c),
                    "distributivity failed at ({a},{b},{c})"
                );
            }
        }
    }
}

#[test]
fn gf_mul_matches_known_values() {
    // Anchors from FIPS-197 §4.2: axioms alone would also hold for a field
    // built on a different (wrong) reduction polynomial.
    assert_eq!(gf_mul(0x57, 0x83), 0xc1);
    assert_eq!(gf_mul(0x57, 0x13), 0xfe);
    // x * 0x80 must reduce by 0x1b.
    assert_eq!(gf_mul(0x80, 0x02), 0x1b);
}

#[test]
fn gf_inv_is_the_multiplicative_inverse() {
    assert_eq!(gf_inv(0), 0, "0 has no inverse; the code returns 0 by convention");
    for a in 1..=255u8 {
        assert_eq!(gf_mul(a, gf_inv(a)), 1, "a * a^-1 must be 1 (a={a})");
        assert_eq!(gf_inv(gf_inv(a)), a, "inversion must be an involution (a={a})");
    }
}

#[test]
fn duplicate_gf_mul_copies_agree() {
    // `dfa_full` keeps its own copy of the same routine.
    for a in 0..=255u8 {
        for b in (0..=255u8).step_by(7) {
            assert_eq!(
                RoundKeyExtractor::gf_mul(a, b),
                gf_mul(a, b),
                "dfa_full copy drifted from bge_attack at ({a},{b})"
            );
        }
    }
}
