//! Definitional oracle for `MemorySlice`'s readers.
//!
//! Properties are derived from what the readers MEAN, not from how they are
//! computed:
//!   * `read_u8(base + i) == Some(bytes[i])` for `i < len`; `None` otherwise
//!     (including every address strictly below `base`, which must never wrap).
//!   * `read_u16_le` / `read_u32_le` equal the little-endian composition of the
//!     corresponding `read_u8` results, and are `None` iff any constituent byte
//!     read is `None` (i.e. the read straddles the end).
//!   * No address, however adversarial (near `u64::MAX`), may panic.
//!
//! NEGATIVE CONTROL: set `ORACLE_CORRUPT=u32_end_off_by_one`; the expected
//! `read_u32_le` becomes defined one byte past the true end, so the
//! differential test must FAIL at `base + len - 3`.

use rustre_analysis_fn::MemorySlice;
use rustre_core::address::Address;

fn corrupt(kind: &str) -> bool {
    std::env::var("ORACLE_CORRUPT").is_ok_and(|v| v == kind)
}

/// Oracle: the byte at `addr`, from first principles.
fn oracle_u8(base: u64, bytes: &[u8], addr: u64) -> Option<u8> {
    if addr < base {
        return None;
    }
    let off = addr - base; // exact: addr >= base
    let off = usize::try_from(off).ok()?;
    bytes.get(off).copied()
}

/// Oracle: little-endian composition of N independent byte oracles.
fn oracle_le(base: u64, bytes: &[u8], addr: u64, n: u32) -> Option<u64> {
    let mut acc: u64 = 0;
    for i in 0..u64::from(n) {
        let a = addr.checked_add(i)?;
        let b = oracle_u8(base, bytes, a)?;
        acc |= u64::from(b) << (8 * i);
    }
    Some(acc)
}

fn bases() -> Vec<u64> {
    vec![
        0,
        1,
        7,
        0x1000,
        0x1_4000_1000,
        u64::from(u32::MAX),
        i64::MAX as u64,
        u64::MAX - 8,
        u64::MAX - 4,
        u64::MAX - 1,
        u64::MAX,
    ]
}

#[test]
fn readers_match_definitional_oracle_and_never_panic() {
    let data: Vec<u8> = (0u16..=255).map(|b| b.wrapping_mul(37) as u8).collect();

    for &base in &bases() {
        for len in [0usize, 1, 2, 3, 4, 5, 8, 17, 64] {
            let bytes = &data[..len];
            let ms = MemorySlice::new(Address::new(base), bytes);
            // A region whose end wraps past u64::MAX is not representable in the
            // address space; production maps such offsets anyway (see report).
            // We still exercise it below, but only for the no-panic property.
            let wraps = base.checked_add(len as u64).is_none();

            // Probe every in-range address plus a generous adversarial fringe.
            let mut probes: Vec<u64> = Vec::new();
            for d in 0..(len as u64 + 8) {
                if let Some(a) = base.checked_add(d) {
                    probes.push(a);
                }
            }
            for d in 1..8u64 {
                if let Some(a) = base.checked_sub(d) {
                    probes.push(a);
                }
            }
            probes.extend([0, 1, u64::MAX, u64::MAX - 1, u64::MAX - 3, i64::MAX as u64]);

            for &addr in &probes {
                let a = Address::new(addr);

                if wraps {
                    // No-panic property only.
                    let _ = (ms.read_u8(a), ms.read_u16_le(a), ms.read_u32_le(a));
                    continue;
                }

                assert_eq!(
                    ms.read_u8(a),
                    oracle_u8(base, bytes, addr),
                    "read_u8 base={base:#x} len={len} addr={addr:#x}"
                );

                let mut exp16 = oracle_le(base, bytes, addr, 2).map(|v| v as u16);
                let mut exp32 = oracle_le(base, bytes, addr, 4).map(|v| v as u32);
                if corrupt("u32_end_off_by_one") {
                    // Pretend a 3-byte tail is a legal u32 read.
                    if exp32.is_none() {
                        exp32 = oracle_le(base, bytes, addr, 3).map(|v| v as u32);
                    }
                }
                if corrupt("u16_end_off_by_one") && exp16.is_none() {
                    exp16 = oracle_le(base, bytes, addr, 1).map(|v| v as u16);
                }

                assert_eq!(
                    ms.read_u16_le(a),
                    exp16,
                    "read_u16_le base={base:#x} len={len} addr={addr:#x}"
                );
                assert_eq!(
                    ms.read_u32_le(a),
                    exp32,
                    "read_u32_le base={base:#x} len={len} addr={addr:#x}"
                );
            }

            // Exact boundary: last valid u32 read starts at base + len - 4.
            if len >= 4 && !wraps {
                let last = base.wrapping_add(len as u64 - 4);
                assert!(ms.read_u32_le(Address::new(last)).is_some());
                if let Some(past) = last.checked_add(1) {
                    assert!(ms.read_u32_le(Address::new(past)).is_none());
                }
            }
        }
    }
}
