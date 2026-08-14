//! Endian-aware, typed read/write helpers for [`MemoryProvider`] implementors.
//!
//! Each function returns `None` / `Err` when the target address is not fully
//! mapped or the provider returns an error.  The `write_*` variants return
//! `Result<(), MemError>` mirroring the underlying provider API.
//!
//! # Example
//!
//! ```rust,ignore
//! use rustre_mem::helpers::{read_u32_le_at, write_u32_le_at};
//! use rustre_mem::VirtualMemoryProvider;
//! use rustre_core::address::Address;
//! use rustre_core::permissions::Permissions;
//!
//! let mut p = VirtualMemoryProvider::new();
//! p.map(Address::new(0x1000), vec![0u8; 8], Permissions::READ | Permissions::WRITE);
//! write_u32_le_at(&mut p, Address::new(0x1000), 0xDEADBEEF).unwrap();
//! assert_eq!(read_u32_le_at(&p, Address::new(0x1000)), Some(0xDEADBEEF));
//! ```

use crate::memory_provider::{MemError, MemoryProvider};
use rustre_core::address::{Address, AddressRange};

// ─────────────────────────────────────────────────────────────────────────────
// Read helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Read a single byte at `addr`. Returns `None` on error.
#[must_use]
pub fn read_u8_at(p: &dyn MemoryProvider, addr: Address) -> Option<u8> {
    let bytes = p.read(addr, 1).ok()?;
    bytes.first().copied()
}

/// Read a little-endian `u16` at `addr`. Returns `None` on error.
#[must_use]
pub fn read_u16_le_at(p: &dyn MemoryProvider, addr: Address) -> Option<u16> {
    let bytes = p.read(addr, 2).ok()?;
    let arr: [u8; 2] = bytes.try_into().ok()?;
    Some(u16::from_le_bytes(arr))
}

/// Read a big-endian `u16` at `addr`. Returns `None` on error.
#[must_use]
pub fn read_u16_be_at(p: &dyn MemoryProvider, addr: Address) -> Option<u16> {
    let bytes = p.read(addr, 2).ok()?;
    let arr: [u8; 2] = bytes.try_into().ok()?;
    Some(u16::from_be_bytes(arr))
}

/// Read a little-endian `u32` at `addr`. Returns `None` on error.
#[must_use]
pub fn read_u32_le_at(p: &dyn MemoryProvider, addr: Address) -> Option<u32> {
    let bytes = p.read(addr, 4).ok()?;
    let arr: [u8; 4] = bytes.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

/// Read a big-endian `u32` at `addr`. Returns `None` on error.
#[must_use]
pub fn read_u32_be_at(p: &dyn MemoryProvider, addr: Address) -> Option<u32> {
    let bytes = p.read(addr, 4).ok()?;
    let arr: [u8; 4] = bytes.try_into().ok()?;
    Some(u32::from_be_bytes(arr))
}

/// Read a little-endian `u64` at `addr`. Returns `None` on error.
#[must_use]
pub fn read_u64_le_at(p: &dyn MemoryProvider, addr: Address) -> Option<u64> {
    let bytes = p.read(addr, 8).ok()?;
    let arr: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_le_bytes(arr))
}

/// Read a big-endian `u64` at `addr`. Returns `None` on error.
#[must_use]
pub fn read_u64_be_at(p: &dyn MemoryProvider, addr: Address) -> Option<u64> {
    let bytes = p.read(addr, 8).ok()?;
    let arr: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_be_bytes(arr))
}

/// Read a little-endian `u128` at `addr`. Returns `None` on error.
#[must_use]
pub fn read_u128_le_at(p: &dyn MemoryProvider, addr: Address) -> Option<u128> {
    let bytes = p.read(addr, 16).ok()?;
    let arr: [u8; 16] = bytes.try_into().ok()?;
    Some(u128::from_le_bytes(arr))
}

/// Read a signed byte (`i8`) at `addr`. Returns `None` on error.
#[must_use]
pub fn read_i8_at(p: &dyn MemoryProvider, addr: Address) -> Option<i8> {
    read_u8_at(p, addr).map(|b| b as i8)
}

/// Read a little-endian `i16` at `addr`. Returns `None` on error.
#[must_use]
pub fn read_i16_le_at(p: &dyn MemoryProvider, addr: Address) -> Option<i16> {
    read_u16_le_at(p, addr).map(|v| v as i16)
}

/// Read a little-endian `i32` at `addr`. Returns `None` on error.
#[must_use]
pub fn read_i32_le_at(p: &dyn MemoryProvider, addr: Address) -> Option<i32> {
    read_u32_le_at(p, addr).map(|v| v as i32)
}

/// Read a little-endian `i64` at `addr`. Returns `None` on error.
#[must_use]
pub fn read_i64_le_at(p: &dyn MemoryProvider, addr: Address) -> Option<i64> {
    read_u64_le_at(p, addr).map(|v| v as i64)
}

/// Read a little-endian IEEE-754 `f32` at `addr`. Returns `None` on error.
#[must_use]
pub fn read_f32_le_at(p: &dyn MemoryProvider, addr: Address) -> Option<f32> {
    let bits = read_u32_le_at(p, addr)?;
    Some(f32::from_bits(bits))
}

/// Read a little-endian IEEE-754 `f64` at `addr`. Returns `None` on error.
#[must_use]
pub fn read_f64_le_at(p: &dyn MemoryProvider, addr: Address) -> Option<f64> {
    let bits = read_u64_le_at(p, addr)?;
    Some(f64::from_bits(bits))
}

/// Read a big-endian `f32` at `addr`. Returns `None` on error.
#[must_use]
pub fn read_f32_be_at(p: &dyn MemoryProvider, addr: Address) -> Option<f32> {
    let bits = read_u32_be_at(p, addr)?;
    Some(f32::from_bits(bits))
}

/// Read a big-endian `f64` at `addr`. Returns `None` on error.
#[must_use]
pub fn read_f64_be_at(p: &dyn MemoryProvider, addr: Address) -> Option<f64> {
    let bits = read_u64_be_at(p, addr)?;
    Some(f64::from_bits(bits))
}

// ─────────────────────────────────────────────────────────────────────────────
// Write helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Write `value` as a single byte at `addr`.
pub fn write_u8_at(p: &mut dyn MemoryProvider, addr: Address, value: u8) -> Result<(), MemError> {
    p.write(addr, &[value])
}

/// Write `value` as a little-endian `u16` at `addr`.
pub fn write_u16_le_at(
    p: &mut dyn MemoryProvider,
    addr: Address,
    value: u16,
) -> Result<(), MemError> {
    p.write(addr, &value.to_le_bytes())
}

/// Write `value` as a big-endian `u16` at `addr`.
pub fn write_u16_be_at(
    p: &mut dyn MemoryProvider,
    addr: Address,
    value: u16,
) -> Result<(), MemError> {
    p.write(addr, &value.to_be_bytes())
}

/// Write `value` as a little-endian `u32` at `addr`.
pub fn write_u32_le_at(
    p: &mut dyn MemoryProvider,
    addr: Address,
    value: u32,
) -> Result<(), MemError> {
    p.write(addr, &value.to_le_bytes())
}

/// Write `value` as a big-endian `u32` at `addr`.
pub fn write_u32_be_at(
    p: &mut dyn MemoryProvider,
    addr: Address,
    value: u32,
) -> Result<(), MemError> {
    p.write(addr, &value.to_be_bytes())
}

/// Write `value` as a little-endian `u64` at `addr`.
pub fn write_u64_le_at(
    p: &mut dyn MemoryProvider,
    addr: Address,
    value: u64,
) -> Result<(), MemError> {
    p.write(addr, &value.to_le_bytes())
}

/// Write `value` as a big-endian `u64` at `addr`.
pub fn write_u64_be_at(
    p: &mut dyn MemoryProvider,
    addr: Address,
    value: u64,
) -> Result<(), MemError> {
    p.write(addr, &value.to_be_bytes())
}

/// Write `value` as a little-endian `i32` at `addr`.
pub fn write_i32_le_at(
    p: &mut dyn MemoryProvider,
    addr: Address,
    value: i32,
) -> Result<(), MemError> {
    p.write(addr, &value.to_le_bytes())
}

/// Write `value` as a little-endian `i64` at `addr`.
pub fn write_i64_le_at(
    p: &mut dyn MemoryProvider,
    addr: Address,
    value: i64,
) -> Result<(), MemError> {
    p.write(addr, &value.to_le_bytes())
}

/// Write `value` as a little-endian IEEE-754 `f32` at `addr`.
pub fn write_f32_le_at(
    p: &mut dyn MemoryProvider,
    addr: Address,
    value: f32,
) -> Result<(), MemError> {
    p.write(addr, &value.to_bits().to_le_bytes())
}

/// Write `value` as a little-endian IEEE-754 `f64` at `addr`.
pub fn write_f64_le_at(
    p: &mut dyn MemoryProvider,
    addr: Address,
    value: f64,
) -> Result<(), MemError> {
    p.write(addr, &value.to_bits().to_le_bytes())
}

// ─────────────────────────────────────────────────────────────────────────────
// search_bytes_with_mask
// ─────────────────────────────────────────────────────────────────────────────

/// Search for `pattern` with `mask` in the given address range.
///
/// `mask` must be the same length as `pattern`.  A mask byte of `0x00` is a
/// wildcard; `0xFF` requires an exact byte match; other values perform masked
/// comparison: `(actual_byte & mask) == (pattern_byte & mask)`.
///
/// Returns all start addresses where the pattern matches.
///
/// Returns an empty vec if `pattern` or `mask` is empty, or if their lengths differ.
#[must_use]
pub fn search_bytes_with_mask(
    p: &dyn MemoryProvider,
    pattern: &[u8],
    mask: &[u8],
    range: AddressRange,
) -> Vec<Address> {
    if pattern.is_empty() || pattern.len() != mask.len() {
        return Vec::new();
    }

    if range.is_empty() {
        return Vec::new();
    }

    let range_len = range.len() as usize;
    let Ok(data) = p.read(range.start, range_len) else {
        return Vec::new();
    };

    let pat_len = pattern.len();
    let mut results = Vec::new();

    if pat_len > data.len() {
        return results;
    }

    'outer: for i in 0..=(data.len() - pat_len) {
        for j in 0..pat_len {
            if (data[i + j] & mask[j]) != (pattern[j] & mask[j]) {
                continue 'outer;
            }
        }
        results.push(range.start + i as u64);
    }

    results
}

/// Search for a raw byte sequence (no mask) in the given address range.
///
/// Equivalent to `search_bytes_with_mask` with an all-`0xFF` mask.
#[must_use]
pub fn search_bytes(p: &dyn MemoryProvider, pattern: &[u8], range: AddressRange) -> Vec<Address> {
    if pattern.is_empty() {
        return Vec::new();
    }

    if range.is_empty() {
        return Vec::new();
    }

    let range_len = range.len() as usize;
    let Ok(data) = p.read(range.start, range_len) else {
        return Vec::new();
    };

    let pat_len = pattern.len();
    if pat_len > data.len() {
        return Vec::new();
    }

    let mut results = Vec::new();
    for i in 0..=(data.len() - pat_len) {
        if data[i..i + pat_len] == *pattern {
            results.push(range.start + i as u64);
        }
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtual_memory::VirtualMemoryProvider;
    use rustre_core::address::{Address, AddressRange};
    use rustre_core::permissions::Permissions;

    fn rw(start: u64, data: &[u8]) -> VirtualMemoryProvider {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(start),
            data.to_vec(),
            Permissions::READ | Permissions::WRITE,
        );
        p
    }

    fn empty_provider(start: u64, len: usize) -> VirtualMemoryProvider {
        rw(start, &vec![0u8; len])
    }

    // ── Read helpers ──────────────────────────────────────────────────────────

    #[test]
    fn read_u8_ok() {
        let p = rw(0x100, &[0xAB]);
        assert_eq!(read_u8_at(&p, Address::new(0x100)), Some(0xAB));
    }

    #[test]
    fn read_u8_unmapped() {
        let p = VirtualMemoryProvider::new();
        assert!(read_u8_at(&p, Address::new(0)).is_none());
    }

    #[test]
    fn read_u16_le_ok() {
        let p = rw(0x100, &[0x34, 0x12]);
        assert_eq!(read_u16_le_at(&p, Address::new(0x100)), Some(0x1234));
    }

    #[test]
    fn read_u16_be_ok() {
        let p = rw(0x100, &[0x12, 0x34]);
        assert_eq!(read_u16_be_at(&p, Address::new(0x100)), Some(0x1234));
    }

    #[test]
    fn read_u32_le_ok() {
        let p = rw(0x100, &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(read_u32_le_at(&p, Address::new(0x100)), Some(0x12345678));
    }

    #[test]
    fn read_u32_be_ok() {
        let p = rw(0x100, &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(read_u32_be_at(&p, Address::new(0x100)), Some(0x12345678));
    }

    #[test]
    fn read_u64_le_ok() {
        let val: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let p = rw(0x100, &val.to_le_bytes());
        assert_eq!(read_u64_le_at(&p, Address::new(0x100)), Some(val));
    }

    #[test]
    fn read_u64_be_ok() {
        let val: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let p = rw(0x100, &val.to_be_bytes());
        assert_eq!(read_u64_be_at(&p, Address::new(0x100)), Some(val));
    }

    #[test]
    fn read_u128_le_ok() {
        let val: u128 = 0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0;
        let p = rw(0, &val.to_le_bytes());
        assert_eq!(read_u128_le_at(&p, Address::new(0)), Some(val));
    }

    #[test]
    fn read_i8_negative() {
        let p = rw(0, &[0xFF]);
        assert_eq!(read_i8_at(&p, Address::new(0)), Some(-1i8));
    }

    #[test]
    fn read_i16_le_negative() {
        let val: i16 = -1;
        let p = rw(0, &val.to_le_bytes());
        assert_eq!(read_i16_le_at(&p, Address::new(0)), Some(-1i16));
    }

    #[test]
    fn read_i32_le_negative() {
        let val: i32 = -42;
        let p = rw(0, &val.to_le_bytes());
        assert_eq!(read_i32_le_at(&p, Address::new(0)), Some(-42i32));
    }

    #[test]
    fn read_i64_le_min() {
        let val = i64::MIN;
        let p = rw(0, &val.to_le_bytes());
        assert_eq!(read_i64_le_at(&p, Address::new(0)), Some(val));
    }

    #[test]
    fn read_f32_le_pi() {
        let val = std::f32::consts::PI;
        let p = rw(0, &val.to_le_bytes());
        let got = read_f32_le_at(&p, Address::new(0)).unwrap();
        assert!((got - val).abs() < 1e-6);
    }

    #[test]
    fn read_f64_le_e() {
        let val = std::f64::consts::E;
        let p = rw(0, &val.to_le_bytes());
        let got = read_f64_le_at(&p, Address::new(0)).unwrap();
        assert!((got - val).abs() < 1e-15);
    }

    #[test]
    fn read_f32_be() {
        let val = 1.5f32;
        let p = rw(0, &val.to_be_bytes());
        let got = read_f32_be_at(&p, Address::new(0)).unwrap();
        assert!((got - val).abs() < 1e-6);
    }

    #[test]
    fn read_f64_be() {
        let val = 1.5f64;
        let p = rw(0, &val.to_be_bytes());
        let got = read_f64_be_at(&p, Address::new(0)).unwrap();
        assert!((got - val).abs() < 1e-15);
    }

    // ── Write helpers ─────────────────────────────────────────────────────────

    #[test]
    fn write_u8_ok() {
        let mut p = empty_provider(0, 4);
        write_u8_at(&mut p, Address::new(0), 0xAB).unwrap();
        assert_eq!(read_u8_at(&p, Address::new(0)), Some(0xAB));
    }

    #[test]
    fn write_u16_le_roundtrip() {
        let mut p = empty_provider(0, 4);
        write_u16_le_at(&mut p, Address::new(0), 0xBEEF).unwrap();
        assert_eq!(read_u16_le_at(&p, Address::new(0)), Some(0xBEEF));
    }

    #[test]
    fn write_u16_be_roundtrip() {
        let mut p = empty_provider(0, 4);
        write_u16_be_at(&mut p, Address::new(0), 0xBEEF).unwrap();
        assert_eq!(read_u16_be_at(&p, Address::new(0)), Some(0xBEEF));
    }

    #[test]
    fn write_u32_le_roundtrip() {
        let mut p = empty_provider(0, 8);
        write_u32_le_at(&mut p, Address::new(0), 0xDEAD_BEEF).unwrap();
        assert_eq!(read_u32_le_at(&p, Address::new(0)), Some(0xDEAD_BEEF));
    }

    #[test]
    fn write_u32_be_roundtrip() {
        let mut p = empty_provider(0, 8);
        write_u32_be_at(&mut p, Address::new(0), 0xDEAD_BEEF).unwrap();
        assert_eq!(read_u32_be_at(&p, Address::new(0)), Some(0xDEAD_BEEF));
    }

    #[test]
    fn write_u64_le_roundtrip() {
        let mut p = empty_provider(0, 16);
        write_u64_le_at(&mut p, Address::new(0), 0xCAFE_BABE_DEAD_BEEF).unwrap();
        assert_eq!(
            read_u64_le_at(&p, Address::new(0)),
            Some(0xCAFE_BABE_DEAD_BEEF)
        );
    }

    #[test]
    fn write_u64_be_roundtrip() {
        let mut p = empty_provider(0, 16);
        write_u64_be_at(&mut p, Address::new(0), 0xCAFE_BABE_DEAD_BEEF).unwrap();
        assert_eq!(
            read_u64_be_at(&p, Address::new(0)),
            Some(0xCAFE_BABE_DEAD_BEEF)
        );
    }

    #[test]
    fn write_i32_le_negative() {
        let mut p = empty_provider(0, 8);
        write_i32_le_at(&mut p, Address::new(0), -1234).unwrap();
        assert_eq!(read_i32_le_at(&p, Address::new(0)), Some(-1234));
    }

    #[test]
    fn write_i64_le_negative() {
        let mut p = empty_provider(0, 16);
        write_i64_le_at(&mut p, Address::new(0), -9999999).unwrap();
        assert_eq!(read_i64_le_at(&p, Address::new(0)), Some(-9999999));
    }

    #[test]
    fn write_f32_le_roundtrip() {
        let mut p = empty_provider(0, 8);
        let val = std::f32::consts::TAU;
        write_f32_le_at(&mut p, Address::new(0), val).unwrap();
        let got = read_f32_le_at(&p, Address::new(0)).unwrap();
        assert!((got - val).abs() < 1e-6);
    }

    #[test]
    fn write_f64_le_roundtrip() {
        let mut p = empty_provider(0, 16);
        let val = std::f64::consts::SQRT_2;
        write_f64_le_at(&mut p, Address::new(0), val).unwrap();
        let got = read_f64_le_at(&p, Address::new(0)).unwrap();
        assert!((got - val).abs() < 1e-15);
    }

    // ── search_bytes_with_mask ────────────────────────────────────────────────

    #[test]
    fn search_exact_match() {
        let mut data = vec![0u8; 32];
        data[16] = 0xDE;
        data[17] = 0xAD;
        let p = rw(0x1000, &data);
        let range = AddressRange::new(Address::new(0x1000), Address::new(0x1020));
        let hits = search_bytes_with_mask(&p, &[0xDE, 0xAD], &[0xFF, 0xFF], range);
        assert_eq!(hits, [Address::new(0x1010)]);
    }

    #[test]
    fn search_with_wildcard_mask() {
        let data: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xFF, 0, 0];
        let p = rw(0, &data);
        let range = AddressRange::new(Address::new(0), Address::new(8));
        // Match 0xDE, then any byte.
        let hits = search_bytes_with_mask(&p, &[0xDE, 0x00], &[0xFF, 0x00], range);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0], Address::new(0));
        assert_eq!(hits[1], Address::new(4));
    }

    #[test]
    fn search_no_match() {
        let p = rw(0, &[0xAAu8; 32]);
        let range = AddressRange::new(Address::new(0), Address::new(32));
        let hits = search_bytes_with_mask(&p, &[0xBB], &[0xFF], range);
        assert!(hits.is_empty());
    }

    #[test]
    fn search_multiple_overlapping() {
        // Pattern 0xAA matches at positions 0, 1, 2.
        let p = rw(0, &[0xAAu8; 8]);
        let range = AddressRange::new(Address::new(0), Address::new(8));
        let hits = search_bytes(&p, &[0xAA], range);
        assert_eq!(hits.len(), 8);
    }

    #[test]
    fn search_bytes_empty_range() {
        let p = rw(0, &[0xAAu8; 8]);
        let range = AddressRange::new(Address::new(0), Address::new(0));
        let hits = search_bytes(&p, &[0xAA], range);
        assert!(hits.is_empty());
    }

    #[test]
    fn search_bytes_unmapped_range() {
        let p = VirtualMemoryProvider::new();
        let range = AddressRange::new(Address::new(0xDEAD0000), Address::new(0xDEAD0100));
        let hits = search_bytes(&p, &[0x00], range);
        assert!(hits.is_empty());
    }

    #[test]
    fn search_bytes_pattern_longer_than_range() {
        let p = rw(0, &[0xAAu8; 4]);
        let range = AddressRange::new(Address::new(0), Address::new(4));
        // 8-byte pattern vs 4-byte range.
        let hits = search_bytes(&p, &[0xAAu8; 8], range);
        assert!(hits.is_empty());
    }

    #[test]
    fn read_write_at_non_zero_base() {
        let mut p = empty_provider(0x8000_0000, 16);
        write_u64_le_at(&mut p, Address::new(0x8000_0000), 0x1234_5678_ABCD_EF00).unwrap();
        assert_eq!(
            read_u64_le_at(&p, Address::new(0x8000_0000)),
            Some(0x1234_5678_ABCD_EF00)
        );
    }
}
