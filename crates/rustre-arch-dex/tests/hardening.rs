//! Hardening tests for `rustre-arch-dex`.
//!
//! `DexTypeSystem::from_dex` reserved `type_ids_size` and `proto_ids_size`
//! entries up front. Both are `u32` fields taken verbatim from the DEX header,
//! so a crafted header could request multiple gigabytes before the first
//! bounds check inside the loop was reached.
//!
//! `dex_string_pool` already capped its own equivalent count (with a comment
//! naming the `DoS`), which is why this one went unnoticed: the crate *looked*
//! hardened.

use rustre_arch_dex::dex_type_system::DexTypeSystem;

/// A header claiming ~4 billion type IDs over an empty buffer.
#[test]
fn huge_type_ids_size_does_not_allocate() {
    let data = [0u8; 64];
    let strings: Vec<String> = Vec::new();
    let ts = DexTypeSystem::from_dex(&data, 0, u32::MAX, 0, 0, &strings);
    // 64 bytes hold at most 16 four-byte type IDs, so the result is bounded —
    // the point is that we reached this assertion at all.
    assert!(ts.get_type(16).is_none());
}

/// A header claiming ~4 billion proto IDs.
#[test]
fn huge_proto_ids_size_does_not_allocate() {
    let data = [0u8; 64];
    let strings: Vec<String> = Vec::new();
    let _ = DexTypeSystem::from_dex(&data, 0, 0, 0, u32::MAX, &strings);
}

/// Both counts maximal at once, with offsets past the end of the buffer.
#[test]
fn huge_counts_with_bogus_offsets_do_not_allocate() {
    let data = [0u8; 32];
    let strings: Vec<String> = Vec::new();
    let _ = DexTypeSystem::from_dex(&data, u32::MAX, u32::MAX, u32::MAX, u32::MAX, &strings);
}

/// A well-formed pair of tables still parses — the caps bound the reservation,
/// not the result.
#[test]
fn wellformed_tables_still_parse() {
    // Two type IDs (string indices 0 and 1), then one proto ID (12 bytes).
    let mut data = Vec::new();
    data.extend_from_slice(&0u32.to_le_bytes()); // type id 0 → "I"
    data.extend_from_slice(&1u32.to_le_bytes()); // type id 1 → "Ljava/lang/String;"
    let protos_off = u32::try_from(data.len()).expect("fixture is small");
    data.extend_from_slice(&0u32.to_le_bytes()); // shorty idx
    data.extend_from_slice(&0u32.to_le_bytes()); // return type idx
    data.extend_from_slice(&0u32.to_le_bytes()); // params off

    let strings = vec!["I".to_owned(), "Ljava/lang/String;".to_owned()];
    let ts = DexTypeSystem::from_dex(&data, 0, 2, protos_off, 1, &strings);
    assert!(ts.get_type(0).is_some(), "first type ID must still be decoded");
    assert!(ts.get_type(1).is_some(), "second type ID must still be decoded");
    assert!(ts.get_type(2).is_none(), "no phantom third type");
    assert!(ts.get_proto(0).is_some(), "the proto ID must still be decoded");
}

/// Random noise with random counts must never panic.
#[test]
fn random_noise_never_panics() {
    let mut state = 0xDEC0_DE12_3456_789Au64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    let strings = vec!["I".to_owned(), "V".to_owned()];
    for _ in 0..200 {
        let len = (next() % 256) as usize;
        let buf: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
        let t_off = (next() % 0xFFFF) as u32;
        let t_size = (next() % 0xFFFF_FFFF) as u32;
        let p_off = (next() % 0xFFFF) as u32;
        let p_size = (next() % 0xFFFF_FFFF) as u32;
        let _ = DexTypeSystem::from_dex(&buf, t_off, t_size, p_off, p_size, &strings);
    }
}
