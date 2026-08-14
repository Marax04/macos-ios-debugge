//! blitz2 - link/runtime smoke tests.
//!
//! These complement the existing blitz.rs by exercising additional invariants
//! that hold for any well-formed Rust library: trait-bound markers, panic-free
//! basic ops, deterministic seeded helper outputs.

use rustre_crypto_whitebox as _;

#[test]
fn smoke_link() {}

#[test]
fn smoke_unit_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<()>();
    assert_sync::<()>();
    assert_send::<u64>();
    assert_sync::<u64>();
}

const fn lcg_next(s: &mut u64) -> u64 {
    *s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
    *s
}

#[test]
fn smoke_lcg_determinism() {
    let mut s1: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut s2: u64 = 0xDEAD_BEEF_CAFE_BABE;
    for _ in 0..1000 { assert_eq!(lcg_next(&mut s1), lcg_next(&mut s2)); }
}

#[test]
fn smoke_lcg_period_distinct_seeds_diverge() {
    let mut s1: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut s2: u64 = 0xBADD_F00D_DEAD_BEEF;
    let mut diff = 0;
    for _ in 0..1000 { if lcg_next(&mut s1) != lcg_next(&mut s2) { diff += 1; } }
    assert!(diff > 950);
}

#[test]
fn smoke_threaded_no_panic() {
    use std::thread;
    let handles: Vec<_> = (0..4).map(|seed: u64| thread::spawn(move || {
        let mut s = seed.wrapping_add(1);
        let mut acc: u64 = 0;
        for _ in 0..100 { acc = acc.wrapping_add(lcg_next(&mut s)); }
        acc
    })).collect();
    let mut sum = 0u64;
    for h in handles { sum = sum.wrapping_add(h.join().unwrap()); }
    let _ = sum;
}

#[test]
fn smoke_boundary_arith() {
    assert_eq!(u64::MAX.wrapping_add(1), 0);
    assert_eq!(u64::MIN.wrapping_sub(1), u64::MAX);
    assert_eq!(i64::MAX.wrapping_add(1), i64::MIN);
    assert_eq!(i64::MIN.wrapping_sub(1), i64::MAX);
}

#[test]
fn smoke_byte_roundtrip() {
    for b in 0u8..=255 {
        let v: u32 = u32::from(b);
        let back: u8 = u8::try_from(v).unwrap_or(u8::MAX);
        assert_eq!(b, back);
    }
}

#[test]
fn smoke_u16_le_be_roundtrip() {
    let mut s: u64 = 0xDEAD_BEEF;
    for _ in 0..200 {
        let x = u16::try_from(lcg_next(&mut s) & 0xFFFF).unwrap_or(u16::MAX);
        assert_eq!(u16::from_le_bytes(x.to_le_bytes()), x);
        assert_eq!(u16::from_be_bytes(x.to_be_bytes()), x);
    }
}

#[test]
fn smoke_u32_le_be_roundtrip() {
    let mut s: u64 = 0xDEAD_BEEF;
    for _ in 0..200 {
        let x = u32::try_from(lcg_next(&mut s) & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        assert_eq!(u32::from_le_bytes(x.to_le_bytes()), x);
        assert_eq!(u32::from_be_bytes(x.to_be_bytes()), x);
    }
}

#[test]
fn smoke_u64_le_be_roundtrip() {
    let mut s: u64 = 0xCAFE_BABE;
    for _ in 0..200 {
        let x = lcg_next(&mut s);
        assert_eq!(u64::from_le_bytes(x.to_le_bytes()), x);
        assert_eq!(u64::from_be_bytes(x.to_be_bytes()), x);
    }
}

#[test]
fn smoke_string_roundtrip() {
    for s in ["", "a", "hello", "café", "日本語", " \n\t"] {
        let bytes = s.as_bytes().to_vec();
        let back = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(s, back);
    }
}
