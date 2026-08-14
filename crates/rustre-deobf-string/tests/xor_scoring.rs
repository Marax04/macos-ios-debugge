//! Regression tests for the plaintext scorer used by every XOR key search.
//!
//! Written BEFORE the fix and confirmed to fail with the exact symptom measured
//! by the rank diagnostic: `score_plaintext` is monotone in the WRONG direction
//! — it rewards strings with few letters, so punctuation noise outranks English.

use rustre_deobf_string::xor_string_decoder::{
    brute_force_xor, score_plaintext, XorKey, XorStringDecoder,
};

/// The defect, stated at its smallest: real English must outscore noise.
///
/// `-<..*2/9lon` is what key 0x1f produces from the `decoder_scan` fixture. It
/// is fully printable but contains three letters, so the chi-squared term is
/// computed against near-zero expected counts and stays tiny — which the
/// current formula reads as "excellent English".
#[test]
fn english_outscores_printable_noise() {
    let english = score_plaintext(b"password123");
    let noise = score_plaintext(b"-<..*2/9lon");

    assert!(
        english > noise,
        "English scored {english:.4} but printable noise scored {noise:.4}; \
         the scorer rewards having FEWER letters"
    );
}

/// The scorer must not be improvable by deleting letters.
///
/// Same sentence, progressively stripped of alphabetic content. A metric that
/// claims to detect English cannot rank the mutilated versions higher.
#[test]
fn removing_letters_does_not_improve_the_score() {
    let full = score_plaintext(b"the quick brown fox jumps");
    let fewer = score_plaintext(b"t.. q...k b____ f.. j____");

    assert!(
        full > fewer,
        "full English scored {full:.4}, letter-stripped scored {fewer:.4}"
    );
}

/// The correct key must rank first for unambiguous English plaintext.
#[test]
fn correct_key_ranks_first_for_english() {
    for (plain, key) in [
        (&b"password123"[..], 0x42u8),
        (&b"Hello, World!"[..], 0x55),
        (&b"This is a secret message"[..], 0x5c),
    ] {
        let ct: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let ranked = brute_force_xor(&ct);
        assert_eq!(
            ranked[0].0,
            XorKey::single(key),
            "for {:?} the winner was {} decoding to {:?}",
            String::from_utf8_lossy(plain),
            ranked[0].0,
            String::from_utf8_lossy(&ranked[0].2),
        );
    }
}

/// `scan` consumes only the top-ranked key per window (`.next()` on 256 sorted
/// results), so a correct-but-second-place key is computed and then discarded.
/// Ranking it first is necessary; surviving the scan is what callers observe.
#[test]
fn scan_reports_the_key_that_decodes_to_english() {
    let plaintext = b"password123";
    let key = 0x42_u8;
    let ct: Vec<u8> = plaintext.iter().map(|&b| b ^ key).collect();

    let mut decoder = XorStringDecoder::new();
    decoder.scan(&ct);

    assert!(
        decoder.candidates.iter().any(|c| c.key == XorKey::single(key)),
        "key 0x{key:02x} absent; candidates were {:?}",
        decoder
            .candidates
            .iter()
            .map(|c| (format!("{}", c.key), c.text.clone(), c.score))
            .collect::<Vec<_>>()
    );
}
