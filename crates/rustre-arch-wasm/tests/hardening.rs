//! Hardening tests for `rustre-arch-wasm`.
//!
//! `ResultType::decode` reserved `count` entries from a raw ULEB128 vector
//! length with no bound, so a two-byte input could request gigabytes.
//!
//! The other two places in this crate that read an attacker-controlled WASM
//! vector length — the `br_table` decoders in `lib.rs` and `wasm_lifter.rs` —
//! already enforced `MAX_BR_TABLE_ENTRIES = 65_536`, which is exactly why this
//! third site was easy to miss.

use rustre_arch_wasm::wasm_type_system::ResultType;

/// Encode `v` as ULEB128.
fn uleb(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// A vector claiming ~4 billion value types over a tiny buffer.
#[test]
fn huge_count_does_not_allocate() {
    let data = uleb(0xFFFF_FFFF);
    // Must return None (truncated) rather than reserve gigabytes.
    assert!(ResultType::decode(&data, 0).is_none());
}

/// The maximum a 64-bit ULEB128 can express.
#[test]
fn max_u64_count_does_not_allocate() {
    let data = uleb(u64::MAX);
    let _ = ResultType::decode(&data, 0);
}

/// A count that is large but followed by a few real bytes still must not
/// reserve more than the buffer can hold.
#[test]
fn large_count_with_some_payload_does_not_allocate() {
    let mut data = uleb(1_000_000_000);
    data.extend_from_slice(&[0x7F, 0x7E, 0x7D]); // i32, i64, f32
    let _ = ResultType::decode(&data, 0);
}

/// A well-formed result type still decodes — the cap bounds the reservation,
/// not the result.
#[test]
fn wellformed_result_type_still_decodes() {
    let mut data = uleb(3);
    data.extend_from_slice(&[0x7F, 0x7E, 0x7D]); // i32, i64, f32
    let (rt, consumed) = ResultType::decode(&data, 0).expect("should decode");
    assert_eq!(consumed, data.len());
    let _ = rt;
}

/// An empty vector (count = 0) is valid.
#[test]
fn empty_result_type_decodes() {
    let data = uleb(0);
    let (_rt, consumed) = ResultType::decode(&data, 0).expect("empty vector is valid");
    assert_eq!(consumed, 1);
}

/// Decoding from an offset past the end must not underflow the cap arithmetic.
#[test]
fn offset_past_end_does_not_panic() {
    let data = [0x03u8, 0x7F];
    let _ = ResultType::decode(&data, 999);
}

/// Random noise must never panic.
#[test]
fn random_noise_never_panics() {
    let mut state = 0x7A5E_1234_ABCD_EF01u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for _ in 0..300 {
        let len = (next() % 96) as usize;
        let buf: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
        let pos = (next() as usize) % (buf.len() + 1);
        let _ = ResultType::decode(&buf, pos);
    }
}

/// Truncations of a well-formed vector must never panic.
#[test]
fn truncations_never_panic() {
    let mut data = uleb(4);
    data.extend_from_slice(&[0x7F, 0x7E, 0x7D, 0x7C]);
    for cut in 0..data.len() {
        let _ = ResultType::decode(&data[..cut], 0);
    }
}
