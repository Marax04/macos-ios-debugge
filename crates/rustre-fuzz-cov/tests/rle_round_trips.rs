//! `rle_encode`/`rle_decode` are the codec coverage bitmaps are persisted with
//! between fuzzing runs, so a one-sided change would not crash — it would
//! restore the wrong coverage and silently steer the fuzzer.
//!
//! The run length is stored in a `u16`, so the interesting inputs are the ones
//! that straddle that boundary: a run of exactly 65 535 bytes, and one of
//! 65 536, where the encoder must split into two triples. An encoder that
//! allowed `run` to reach 65 536 would wrap to 0; one that stopped at 65 534
//! would still be correct but wasteful. Only the round trip distinguishes them.

use rustre_fuzz_cov::coverage_persistence::{rle_decode, rle_encode};

/// Inputs chosen around the `u16` run-length boundary and the degenerate cases.
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", Vec::new()),
        ("single byte", vec![0xAA]),
        ("two identical", vec![7, 7]),
        ("two different", vec![1, 2]),
        ("short run", vec![0xFF; 10]),
        ("alternating", (0..64).map(|i| u8::from(i % 2 == 0)).collect()),
        ("all distinct", (0..=255).collect()),
        ("run of 65535", vec![0x5A; 65_535]),
        ("run of 65536", vec![0x5A; 65_536]),
        ("run of 65537", vec![0x5A; 65_537]),
        ("two max runs", vec![0xC3; 131_070]),
        ("sparse bitmap", {
            let mut v = vec![0u8; 65_536];
            v[0] = 1;
            v[32_768] = 1;
            v[65_535] = 1;
            v
        }),
    ]
}

#[test]
fn every_input_survives_the_rle_round_trip() {
    let cases = corpus();
    let mut checked = 0usize;
    let mut divergences = Vec::new();

    for (label, data) in &cases {
        let encoded = rle_encode(data);
        match rle_decode(&encoded, data.len()) {
            Err(e) => divergences.push(format!("{label}: our own output was rejected: {e:?}")),
            Ok(back) => {
                if &back != data {
                    divergences.push(format!(
                        "{label}: {} bytes in, {} bytes back",
                        data.len(),
                        back.len()
                    ));
                }
            }
        }
        checked += 1;
    }

    assert_eq!(checked, 12, "anti-vacuity: the whole corpus is exercised");
    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

#[test]
fn the_encoding_is_triples_and_actually_compresses_runs() {
    // Premise: the round trip above is not passing because the codec is the
    // identity. A long run must collapse, and the output must be whole triples.
    let long = vec![0x11; 1000];
    let encoded = rle_encode(&long);
    assert_eq!(encoded.len(), 3, "1000 identical bytes must become one triple");
    assert_eq!(
        encoded.len() % 3,
        0,
        "the encoding is (u16 count, u8 value) triples"
    );

    // And the u16 boundary really is a boundary: 65 536 cannot fit one triple.
    let over = vec![0x22; 65_536];
    assert_eq!(
        rle_encode(&over).len(),
        6,
        "a run past u16::MAX must split into exactly two triples"
    );
    assert_eq!(rle_encode(&vec![0x22; 65_535]).len(), 3);
}

#[test]
fn the_decoder_rejects_input_it_did_not_produce() {
    let data = vec![9u8; 100];
    let good = rle_encode(&data);

    assert!(
        rle_decode(&good, data.len()).is_ok(),
        "premise: a well-formed buffer must decode"
    );
    assert!(
        rle_decode(&good, data.len() + 1).is_err(),
        "a length that disagrees with the payload must be an error, not a short buffer"
    );
    assert!(
        rle_decode(&good[..good.len() - 1], data.len()).is_err(),
        "a truncated triple must be rejected"
    );
    assert!(
        rle_decode(&[0u8; 2], 0).is_err(),
        "a partial triple must be rejected even when nothing is expected"
    );
}
