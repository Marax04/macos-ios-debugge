//! `to_bytes`/`from_bytes` on the coverage bitmaps are an inverse pair, and
//! coverage bitmaps are persisted between fuzzing runs — so a one-sided change
//! would not crash, it would silently resurrect the wrong coverage and make the
//! fuzzer re-explore or skip paths.
//!
//! Both formats are magic + little-endian length + payload, so the interesting
//! inputs are the boundaries of the length field: a capacity that is not a
//! multiple of 8 (the bitmap packs 8 blocks per byte), an empty bitmap, and
//! inputs truncated inside each part of the header.

use rustre_fuzz_cov::block_coverage_tracker::{BlockCovBitmap, BlockCovId};
use rustre_fuzz_cov::edge_coverage_tracker::EdgeBitmap;

/// Capacities chosen around the 8-bit packing boundary, where a `div_ceil`
/// mistake on either side would show up.
const CAPACITIES: [u32; 8] = [0, 1, 7, 8, 9, 15, 16, 1000];

#[test]
fn a_block_bitmap_survives_serialisation_for_every_capacity() {
    let mut divergences = Vec::new();
    let mut checked = 0usize;

    for cap in CAPACITIES {
        let mut bm = BlockCovBitmap::new(cap);
        // Set a spread of blocks, including the last one, where an off-by-one
        // in the byte count would drop the final bit.
        for id in [0u32, 1, 7, 8, cap.saturating_sub(1)] {
            if id < cap {
                bm.set(BlockCovId(id));
            }
        }

        let bytes = bm.to_bytes();
        match BlockCovBitmap::from_bytes(&bytes) {
            None => divergences.push(format!("capacity {cap}: our own output was rejected")),
            Some(back) => {
                let before: Vec<BlockCovId> = bm.iter_set().collect();
                let after: Vec<BlockCovId> = back.iter_set().collect();
                if before != after {
                    divergences.push(format!(
                        "capacity {cap}: set blocks {before:?} came back as {after:?}"
                    ));
                }
            }
        }
        checked += 1;
    }

    assert_eq!(checked, 8, "anti-vacuity: every capacity exercised");
    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

#[test]
fn a_block_bitmap_rejects_malformed_input() {
    let mut bm = BlockCovBitmap::new(64);
    bm.set(BlockCovId(3));
    let good = bm.to_bytes();

    assert!(
        BlockCovBitmap::from_bytes(&good).is_some(),
        "premise: a well-formed buffer must be accepted"
    );
    assert!(BlockCovBitmap::from_bytes(&[]).is_none(), "empty input");
    assert!(BlockCovBitmap::from_bytes(&good[..4]).is_none(), "header only");
    assert!(
        BlockCovBitmap::from_bytes(&good[..good.len() - 1]).is_none(),
        "a payload one byte short must be rejected, not silently accepted"
    );

    let mut wrong_magic = good.clone();
    wrong_magic[0] = b'X';
    assert!(BlockCovBitmap::from_bytes(&wrong_magic).is_none(), "wrong magic");
}

#[test]
fn an_edge_bitmap_survives_serialisation_for_every_size() {
    let mut divergences = Vec::new();
    let mut checked = 0usize;

    for size in [1usize, 2, 7, 8, 64, 65536] {
        let mut bm = EdgeBitmap::new(size);
        for slot in [0usize, 1, size / 2, size - 1] {
            bm.record_raw(slot);
        }

        let bytes = bm.to_bytes();
        match EdgeBitmap::from_bytes(&bytes) {
            None => divergences.push(format!("size {size}: our own output was rejected")),
            Some(back) => {
                if back.as_bytes() != bm.as_bytes() {
                    divergences.push(format!("size {size}: payload changed across the round trip"));
                }
            }
        }
        checked += 1;
    }

    assert_eq!(checked, 6, "anti-vacuity: every size exercised");
    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

#[test]
fn an_edge_bitmap_rejects_malformed_input() {
    let mut bm = EdgeBitmap::new(32);
    bm.record_raw(5);
    let good = bm.to_bytes();

    assert!(
        EdgeBitmap::from_bytes(&good).is_some(),
        "premise: a well-formed buffer must be accepted"
    );
    assert!(EdgeBitmap::from_bytes(&[]).is_none(), "empty input");
    assert!(EdgeBitmap::from_bytes(&good[..7]).is_none(), "truncated header");
    assert!(
        EdgeBitmap::from_bytes(&good[..good.len() - 1]).is_none(),
        "a payload one byte short must be rejected, not silently accepted"
    );

    let mut wrong_magic = good.clone();
    wrong_magic[1] = b'X';
    assert!(EdgeBitmap::from_bytes(&wrong_magic).is_none(), "wrong magic");
}
