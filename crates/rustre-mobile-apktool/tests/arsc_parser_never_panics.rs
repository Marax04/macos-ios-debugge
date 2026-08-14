//! The ARSC parser must reject hostile input, never crash on it.
//!
//! `resources.arsc` comes out of an APK, which is attacker-controlled by
//! definition — this crate exists to analyse APKs whose authors are the subject
//! of the analysis. Every field the parser reads (chunk sizes, string offsets,
//! entry counts) is written by whoever built the file.
//!
//! The parser's own helpers index directly (`data[off]`, `data[off + 3]`), so a
//! bound that is checked at one call site and forgotten at another turns into a
//! panic rather than an `ArscError`. Returning `Err` is always an acceptable
//! answer here; panicking is not, because a caller cannot handle it.

use rustre_mobile_apktool::arsc_parser::{
    ArscFile, ArscHeader, PackageChunk, ResTableConfig, ResourceEntry, ResourceValue,
};

/// Deterministic noise — reproducible failures, no external crates.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut s = seed;
    (0..n)
        .map(|_| {
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (s >> 24) as u8
        })
        .collect()
}

/// A minimal, structurally plausible ARSC table: header, then a string pool.
///
/// Built by hand so the truncation test has something the parser will actually
/// walk into — a file it rejects at byte 0 would exercise nothing.
fn plausible_arsc() -> Vec<u8> {
    let mut v = Vec::new();
    // RES_TABLE_TYPE header: type 0x0002, header_size 12, chunk_size, package_count
    v.extend_from_slice(&0x0002u16.to_le_bytes());
    v.extend_from_slice(&12u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes()); // chunk_size patched below
    v.extend_from_slice(&1u32.to_le_bytes()); // package_count

    // RES_STRING_POOL_TYPE: type 0x0001, header_size 28
    let pool_start = v.len();
    v.extend_from_slice(&0x0001u16.to_le_bytes());
    v.extend_from_slice(&28u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes()); // chunk_size patched below
    v.extend_from_slice(&2u32.to_le_bytes()); // string_count
    v.extend_from_slice(&0u32.to_le_bytes()); // style_count
    v.extend_from_slice(&(1u32 << 8).to_le_bytes()); // flags: UTF-8
    v.extend_from_slice(&(28u32 + 8).to_le_bytes()); // strings_start
    v.extend_from_slice(&0u32.to_le_bytes()); // styles_start
    // two 4-byte string offsets
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&4u32.to_le_bytes());
    // two UTF-8 strings, each: char_count, byte_len, bytes, NUL
    v.extend_from_slice(&[2, 2, b'h', b'i', 0]);
    v.extend_from_slice(&[2, 2, b'y', b'o', 0]);

    let pool_len = u32::try_from(v.len() - pool_start).unwrap_or(u32::MAX);
    v[pool_start + 4..pool_start + 8].copy_from_slice(&pool_len.to_le_bytes());
    let total = u32::try_from(v.len()).unwrap_or(u32::MAX);
    v[4..8].copy_from_slice(&total.to_le_bytes());
    v
}

/// Every truncation of a plausible file is rejected, not crashed on.
///
/// Truncation is the cheapest hostile input there is, and the one a parser with
/// a forgotten bound check fails on first.
#[test]
fn every_truncation_is_handled() {
    let full = plausible_arsc();
    assert!(full.len() > 40, "the fixture is too small to be worth truncating");

    for len in 0..=full.len() {
        let slice = &full[..len];
        // Either answer is fine; the point is that neither panics.
        let _ = ArscFile::parse(slice);
        let _ = ArscHeader::parse(slice);
    }
}

/// Corrupting any single byte must not turn rejection into a crash.
///
/// This reaches the fields the truncation test cannot: sizes and offsets that
/// point far outside the file rather than just running off the end of it.
#[test]
fn corrupting_any_single_byte_is_handled() {
    let full = plausible_arsc();

    for i in 0..full.len() {
        for patch in [0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
            let mut data = full.clone();
            data[i] = patch;
            let _ = ArscFile::parse(&data);
        }
    }
}

/// Offsets and counts set to their extremes must be refused arithmetically.
///
/// `0xFFFF_FFFF` in a size or count field is what an overflow-based attack looks
/// like: the parser must decide it cannot be satisfied, rather than computing a
/// wrapped bound and indexing with it.
#[test]
fn extreme_sizes_and_counts_are_refused() {
    let full = plausible_arsc();

    // Every 4-byte-aligned field in the header region, blown up to u32::MAX.
    for field in (0..40).step_by(4) {
        if field + 4 > full.len() {
            break;
        }
        let mut data = full.clone();
        data[field..field + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let _ = ArscFile::parse(&data);

        let mut data = full.clone();
        data[field..field + 4].copy_from_slice(&(u32::MAX / 2).to_le_bytes());
        let _ = ArscFile::parse(&data);
    }
}

/// Arbitrary bytes must never crash the parser.
#[test]
fn noise_is_handled() {
    for len in [0usize, 1, 7, 12, 28, 64, 256, 4096] {
        for seed in [0x1u64, 0xDEAD_BEEF, 0x5555_AAAA_5555_AAAA] {
            let data = noise(len, seed);
            let _ = ArscFile::parse(&data);
            let _ = ArscHeader::parse(&data);
        }
    }
}

/// Noise that begins with a valid chunk header gets deeper into the parser.
///
/// Pure noise is usually rejected at the first field; prefixing a well-formed
/// header is what carries the fuzz past the front door.
#[test]
fn noise_behind_a_valid_header_is_handled() {
    for len in [16usize, 64, 512, 4096] {
        for seed in [0x1u64, 0xC0FF_EE00_1234_5678] {
            let mut data = Vec::new();
            data.extend_from_slice(&0x0002u16.to_le_bytes()); // RES_TABLE_TYPE
            data.extend_from_slice(&12u16.to_le_bytes());
            data.extend_from_slice(&u32::try_from(len + 12).unwrap_or(u32::MAX).to_le_bytes());
            data.extend_from_slice(&1u32.to_le_bytes());
            data.extend_from_slice(&noise(len, seed));
            let _ = ArscFile::parse(&data);
        }
    }
}

/// The chunk parsers take an `offset` from their caller and must survive any
/// value of it.
///
/// Each one guards with `offset + SIZE > data.len()` before slicing. That
/// addition is on `usize`, and `offset` is a public parameter: near `usize::MAX`
/// it wraps in release, the comparison then passes with a small wrapped value,
/// and the slice that follows is indexed out of range. The guard has to survive
/// the arithmetic, not just the comparison.
#[test]
fn a_huge_offset_is_refused_by_every_chunk_parser() {
    let data = plausible_arsc();

    for offset in [
        usize::MAX,
        usize::MAX - 1,
        usize::MAX - 7,
        usize::MAX - 8,
        usize::MAX - 28,
        usize::MAX / 2,
        data.len(),
        data.len() + 1,
    ] {
        assert!(
            ResTableConfig::parse(&data, offset).is_err(),
            "ResTableConfig::parse accepted offset {offset}"
        );
        assert!(
            ResourceValue::parse(&data, offset).is_err(),
            "ResourceValue::parse accepted offset {offset}"
        );
        assert!(
            ResourceEntry::parse(&data, offset).is_err(),
            "ResourceEntry::parse accepted offset {offset}"
        );
        assert!(
            PackageChunk::parse(&data, offset).is_err(),
            "PackageChunk::parse accepted offset {offset}"
        );
    }
}

/// Guards the test above: the offsets used must really overflow the guard's own
/// addition, otherwise it proves nothing about the wrapping case.
#[test]
fn the_hostile_offsets_actually_overflow() {
    for size in [8usize, 28, 56] {
        assert!(
            usize::MAX.checked_add(size).is_none(),
            "usize::MAX + {size} does not overflow"
        );
    }
}

/// Guards the tests above: the fixture must actually parse.
///
/// If `plausible_arsc` were rejected at byte 0, every truncation and mutation of
/// it would be rejected there too, and none of the parser would be reached.
#[test]
fn the_fixture_actually_parses() {
    let full = plausible_arsc();
    let header = ArscHeader::parse(&full).expect("the fixture must have a valid header");
    assert_eq!(header.chunk_type, 0x0002, "the fixture is not a resource table");
    assert!(
        ArscFile::parse(&full).is_ok(),
        "the fixture does not parse, so the hostile-input tests never reach the parser"
    );
}
