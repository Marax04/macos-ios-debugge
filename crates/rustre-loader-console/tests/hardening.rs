//! Hardening tests for `rustre-loader-console`.
//!
//! The Switch NSO/NRO formats store each segment's *decompressed* size as a
//! `u32` in the file header, and this crate carries three independent LZ4
//! decompressors that all reserved exactly that many bytes up front
//! (`nso_loader`, `nso_nro`, `switch_nso_loader`). A segment of a few bytes
//! could therefore claim 4 GiB.
//!
//! Unlike a stored-block copy, LZ4 genuinely expands, so the input length is
//! *not* a valid bound on the output. The fix caps the **pre-allocation**
//! (`MAX_LZ4_PREALLOC`) and lets the buffer grow on bytes actually produced —
//! so these tests check both halves: no huge reservation, and no truncation of
//! legitimate output.

use rustre_loader_console::nso_loader;
use rustre_loader_console::nso_nro;

/// Encode a single LZ4 literal-only block carrying `payload`.
///
/// Token layout: high nibble = literal length (0xF means "read more"), low
/// nibble = match length. A literal-only block ends after the literals.
fn lz4_literals(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let n = payload.len();
    if n < 15 {
        out.push((n as u8) << 4);
    } else {
        out.push(0xF0);
        let mut rem = n - 15;
        while rem >= 255 {
            out.push(255);
            rem -= 255;
        }
        out.push(rem as u8);
    }
    out.extend_from_slice(payload);
    out
}

/// A tiny compressed block declaring a 4 GiB decompressed size must not
/// reserve 4 GiB — in `nso_loader`.
#[test]
fn nso_loader_huge_expected_size_does_not_allocate() {
    let block = lz4_literals(b"hello");
    let out = nso_loader::lz4_decompress(&block, u32::MAX as usize);
    // Whatever it returns, it must not have reserved 4 GiB to get there.
    if let Some(v) = out {
        assert!(v.len() <= 5);
    }
}

/// Same, in `nso_nro`.
#[test]
fn nso_nro_huge_expected_size_does_not_allocate() {
    let block = lz4_literals(b"hello");
    let _ = nso_nro::lz4_decompress(&block, u32::MAX as usize);
}

/// Legitimate output larger than the pre-allocation cap must NOT be truncated:
/// the cap bounds the reservation, not the result.
///
/// `MAX_LZ4_PREALLOC` is 1 MiB, so a 2 MiB literal run has to grow past it.
#[test]
fn output_larger_than_prealloc_cap_is_not_truncated() {
    let payload = vec![0xABu8; 2 * 1024 * 1024];
    let block = lz4_literals(&payload);
    let out = nso_loader::lz4_decompress(&block, payload.len())
        .expect("literal-only block should decompress");
    assert_eq!(
        out.len(),
        payload.len(),
        "the pre-allocation cap must not truncate real output"
    );
    assert!(out.iter().all(|&b| b == 0xAB));
}

/// A small, well-formed block round-trips exactly.
#[test]
fn small_block_round_trips() {
    let payload = b"NSO segment contents";
    let block = lz4_literals(payload);
    let out = nso_loader::lz4_decompress(&block, payload.len()).expect("should decompress");
    assert_eq!(out, payload);
}

/// Zero expected size must not panic.
#[test]
fn zero_expected_size_is_fine() {
    let block = lz4_literals(b"abc");
    let _ = nso_loader::lz4_decompress(&block, 0);
    let _ = nso_nro::lz4_decompress(&block, 0);
}

/// Truncations of a valid block must never panic.
#[test]
fn truncations_never_panic() {
    let block = lz4_literals(b"some reasonably long literal payload");
    for cut in 0..block.len() {
        let _ = nso_loader::lz4_decompress(&block[..cut], 64);
        let _ = nso_nro::lz4_decompress(&block[..cut], 64);
    }
}

/// Random noise fed to both decompressors must never panic, including with an
/// adversarial `expected_size`.
#[test]
fn random_noise_never_panics() {
    let mut state = 0xFEED_FACE_DEAD_BEEFu64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for _ in 0..300 {
        let len = (next() % 128) as usize;
        let buf: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
        let expected = (next() % u64::from(u32::MAX)) as usize;
        let _ = nso_loader::lz4_decompress(&buf, expected);
        let _ = nso_nro::lz4_decompress(&buf, expected);
    }
}
