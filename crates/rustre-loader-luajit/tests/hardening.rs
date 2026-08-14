//! Hardening tests for `rustre-loader-luajit`.
//!
//! The fixed-length sections of a LuaJIT prototype (bytecode words, upvalue
//! descriptors) were already validated with a total-size check before the
//! allocation. The **variable-length** constant sections — `KGC` (GC objects)
//! and `KNum` (numeric constants) — were not: with no total size to check
//! up front, `Vec::with_capacity(count)` ran on a raw ULEB128 count that can
//! reach `usize::MAX`.
//!
//! These tests drive the public table parsers directly with adversarial counts,
//! and confirm well-formed input still round-trips.

use rustre_loader_luajit::constant_tables::{parse_kgc_table, parse_knum_table};
use rustre_loader_luajit::{LjBytecode, LJ_MAGIC};

/// A KGC table claiming a huge entry count over a tiny buffer.
#[test]
fn kgc_table_huge_count_does_not_allocate() {
    let data = [0x00u8, 0x01, 0x02, 0x03];
    // Must report truncation rather than reserve `usize::MAX` entries.
    assert!(parse_kgc_table(&data, 0, usize::MAX / 64).is_err());
}

/// A KNum table claiming a huge entry count over a tiny buffer.
#[test]
fn knum_table_huge_count_does_not_allocate() {
    let data = [0x00u8, 0x01, 0x02, 0x03];
    assert!(parse_knum_table(&data, 0, usize::MAX / 64).is_err());
}

/// Empty tables with a zero count are still fine.
#[test]
fn empty_tables_still_parse() {
    let data = [0u8; 8];
    let (kgc, _) = parse_kgc_table(&data, 0, 0).expect("empty KGC table");
    assert!(kgc.is_empty());
    let (knum, _) = parse_knum_table(&data, 0, 0).expect("empty KNum table");
    assert!(knum.is_empty());
}

/// An offset past the end of the buffer must not underflow the cap arithmetic.
#[test]
fn offset_past_end_does_not_panic() {
    let data = [0u8; 4];
    let _ = parse_kgc_table(&data, 999, 1_000_000);
    let _ = parse_knum_table(&data, 999, 1_000_000);
}

/// Build a stripped LuaJIT header (magic + version + flags=STRIP).
fn lj_header() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&LJ_MAGIC);
    v.push(2); // bytecode version
    v.push(0x02); // flags: STRIP set → no debug name follows
    v
}

/// A prototype declaring an enormous KGC count must fail cleanly.
#[test]
fn proto_huge_kgc_count_does_not_allocate() {
    let mut data = lj_header();
    // Prototype: length-prefixed. Contents below are deliberately short so the
    // parse must bail once it tries to read the constants.
    let proto = {
        let mut p = Vec::new();
        p.push(0); // flags
        p.push(0); // numparams
        p.push(2); // framesize
        p.push(0); // numuv
        // ULEB128 0xFFFFFFF: a very large numkgc
        p.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0x7F]);
        p.push(0); // numkn
        p.push(0); // numbc
        p
    };
    data.push(proto.len() as u8); // proto length
    data.extend_from_slice(&proto);
    data.push(0); // end-of-protos marker

    // Whatever the outcome, it must not exhaust memory or panic.
    let _ = LjBytecode::parse(&data);
}

/// Random noise behind a valid LuaJIT magic must never panic.
#[test]
fn random_noise_never_panics() {
    let mut state = 0x1234_5678_9ABC_DEF0u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for _ in 0..300 {
        let len = (next() % 200) as usize;
        let noise: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();

        let mut with_hdr = lj_header();
        with_hdr.extend_from_slice(&noise);
        let _ = LjBytecode::parse(&with_hdr);
        let _ = LjBytecode::parse(&noise);

        let off = (next() as usize) % (noise.len() + 1);
        let count = (next() as usize) % 4096;
        let _ = parse_kgc_table(&noise, off, count);
        let _ = parse_knum_table(&noise, off, count);
    }
}

/// Truncations of a header-plus-prototype buffer must never panic.
#[test]
fn truncations_never_panic() {
    let mut data = lj_header();
    let proto = vec![0u8, 0, 2, 0, 1, 1, 1, 0x27, 0x00, 0x00, 0x00];
    data.push(proto.len() as u8);
    data.extend_from_slice(&proto);
    data.push(0);

    for cut in 0..data.len() {
        let _ = LjBytecode::parse(&data[..cut]);
    }
}
