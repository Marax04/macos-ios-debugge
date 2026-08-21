//! Exhaustive and structural properties of the RISC-V compressed decoder.
//!
//! The compressed decoder takes a `u16`, so its entire input domain is 65 536
//! values — small enough to check completely rather than sample. "Decoding
//! never panics" then stops being a hope and becomes a fact about every
//! possible instruction word, which matters because these words come from
//! whatever binary is being analysed.

use rustre_arch_riscv::riscv_compressed_decoder::{decode_stream, RiscvCompressedDecoder};

/// Every one of the 65 536 halfwords decodes without panicking, on both XLENs.
///
/// A `Result::Err` is a fine answer — an invalid encoding *should* be rejected.
/// What must not happen is an abort.
#[test]
fn every_halfword_decodes_without_panic() {
    for rv64 in [false, true] {
        let dec = RiscvCompressedDecoder::new(rv64);
        let mut ok = 0usize;
        for w in 0u16..=u16::MAX {
            if dec.decode(w).is_ok() { ok += 1 }
        }
        // Anti-vacuity: a decoder that rejected everything would satisfy
        // "never panics" without decoding anything at all.
        assert!(
            ok >= 1000,
            "rv64={rv64}: only {ok} of 65536 halfwords decoded successfully — \
             the no-panic property would be holding trivially"
        );
    }
}

/// Deterministic noise — reproducible failures, no external crates.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut s = seed;
    (0..n)
        .map(|_| {
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (s >> 24).to_le_bytes()[0]
        })
        .collect()
}

/// Streaming decode terminates, stays inside the input, and never reports more
/// instructions than there are 2-byte units.
#[test]
fn decode_stream_is_bounded_and_in_range() {
    for len in [0usize, 1, 2, 3, 8, 64, 4096] {
        for seed in [0x1u64, 0xDEAD_BEEF, 0x0F0F_0F0F_0F0F_0F0F] {
            let bytes = noise(len, seed);
            let out = decode_stream(&bytes, true);

            assert!(
                out.len() <= len / 2,
                "{} entries from {len} bytes — a compressed instruction is two \
                 bytes, so nothing is being consumed",
                out.len()
            );
            for (off, _) in &out {
                assert!(*off < len, "offset {off} lies outside the {len}-byte input");
                assert_eq!(off % 2, 0, "offset {off} is not on a 2-byte boundary");
            }
        }
    }
}

/// Offsets must be strictly increasing: a repeated or backwards offset means
/// the stream cursor failed to advance.
#[test]
fn decode_stream_offsets_strictly_increase() {
    let bytes = noise(4096, 0xC0FF_EE00_1234_5678);
    let out = decode_stream(&bytes, false);
    let mut prev: Option<usize> = None;
    for (off, _) in &out {
        if let Some(p) = prev {
            assert!(*off > p, "offset {off} does not advance past {p}");
        }
        prev = Some(*off);
    }
}

/// Guards the stream tests: real noise must yield some decoded entries.
#[test]
fn the_stream_actually_decodes_something() {
    let bytes = noise(4096, 0x5555_AAAA_5555_AAAA);
    let out = decode_stream(&bytes, true);
    assert!(
        out.len() >= 16,
        "only {} entries from 4096 bytes — the bounds above would hold without \
         decoding anything",
        out.len()
    );
}
