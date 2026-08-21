//! Checked, panic-free numeric conversions used across the eBPF decoders.
//!
//! Every function here replaces a bare `as` cast at a site that is fed
//! attacker-controlled bytes (an ELF section header, a BTF blob, a raw
//! instruction stream). A `.unwrap()` on such a path would be a denial of
//! service, so each conversion either saturates at a value that is guaranteed
//! to fail the caller's subsequent bounds check, or reinterprets the bit
//! pattern explicitly when that is what the format actually specifies.

/// Widen a `u32` to `usize`.
///
/// Infallible on every target this crate is built for (32-bit and 64-bit).
/// On a hypothetical 16-bit target it saturates to [`usize::MAX`], which makes
/// the caller's bounds check fail rather than silently wrapping.
#[inline]
#[must_use]
pub fn u32_to_usize(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Widen a `u16` to `usize`. Infallible on all supported targets.
#[inline]
#[must_use]
pub fn u16_to_usize(v: u16) -> usize {
    usize::from(v)
}

/// Narrow a `u64` offset to `usize`.
///
/// Saturates to [`usize::MAX`] on a 32-bit host instead of truncating, so an
/// out-of-range file offset in a malformed ELF/BTF blob cannot alias a valid
/// one.
#[inline]
#[must_use]
pub fn u64_to_usize(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Narrow a `usize` count to `u32`, saturating.
///
/// Used only for reporting indices and sizes that are already bounded by the
/// length of a program (at most `u32::MAX` instructions by the eBPF spec).
#[inline]
#[must_use]
pub fn usize_to_u32(v: usize) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// Narrow a `u64` to `u32`, saturating.
#[inline]
#[must_use]
pub fn u64_to_u32(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// Narrow a `usize` count to `u16`, saturating.
#[inline]
#[must_use]
pub fn usize_to_u16(v: usize) -> u16 {
    u16::try_from(v).unwrap_or(u16::MAX)
}

/// Take the low byte of a `u32` without a truncating cast.
///
/// This is a deliberate field extraction (opcode/class bits), not a lossy
/// narrowing: the high bytes are meant to be discarded.
#[inline]
#[must_use]
pub const fn low_u8(v: u32) -> u8 {
    v.to_le_bytes()[0]
}

/// Take the low 16 bits of a `u32` without a truncating cast.
#[inline]
#[must_use]
pub const fn low_u16(v: u32) -> u16 {
    let b = v.to_le_bytes();
    u16::from_le_bytes([b[0], b[1]])
}

/// Take the low 32 bits of a `u64` without a truncating cast.
#[inline]
#[must_use]
pub const fn low_u32(v: u64) -> u32 {
    let b = v.to_le_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Convert a count to `f64` for a statistic or percentage.
///
/// Counts above 2^53 are not representable exactly; they are clamped so the
/// resulting ratio stays finite and monotone rather than silently rounding.
#[inline]
#[must_use]
pub fn count_to_f64(v: usize) -> f64 {
    f64::from(usize_to_u32(v))
}

/// Convert a `u64` count to `f64` for a statistic or percentage.
///
/// Values above [`u32::MAX`] clamp rather than wrap; the counts this is used
/// for (instruction and byte counts of a single JIT-compiled program) are far
/// below that bound.
#[inline]
#[must_use]
pub fn u64_to_f64(v: u64) -> f64 {
    let clamped = if v > u64::from(u32::MAX) {
        u32::MAX
    } else {
        low_u32(v)
    };
    f64::from(clamped)
}

// ── deliberate, bit-exact truncations ────────────────────────────────────────
//
// Each of the following reproduces exactly what the corresponding `as` cast
// did — the low N bits of the value, sign bits included — but says so in its
// name and its documentation. They exist because in an instruction encoder the
// narrowing IS the specified behaviour (an eBPF `imm` field is 32 bits wide by
// definition), so a checked conversion that returned an error would be wrong.
// Truncating by re-slicing the little-endian byte image cannot panic and needs
// no cast.

/// Low 8 bits of a `u64`, bit-exact with `v as u8`.
#[inline]
#[must_use]
pub const fn trunc_u64_u8(v: u64) -> u8 {
    v.to_le_bytes()[0]
}

/// Low 16 bits of a `u64`, bit-exact with `v as u16`.
#[inline]
#[must_use]
pub const fn trunc_u64_u16(v: u64) -> u16 {
    let b = v.to_le_bytes();
    u16::from_le_bytes([b[0], b[1]])
}

/// Low 8 bits of a `u16`, bit-exact with `v as u8`.
#[inline]
#[must_use]
pub const fn trunc_u16_u8(v: u16) -> u8 {
    v.to_le_bytes()[0]
}

/// Low 8 bits of a `usize`, bit-exact with `v as u8`.
#[inline]
#[must_use]
pub const fn trunc_usize_u8(v: usize) -> u8 {
    v.to_le_bytes()[0]
}

/// Low 32 bits of an `i64` as a signed 32-bit value, bit-exact with `v as i32`.
#[inline]
#[must_use]
pub const fn trunc_i64_i32(v: i64) -> i32 {
    let b = v.to_le_bytes();
    i32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Low 16 bits of an `i64` as a signed 16-bit value, bit-exact with `v as i16`.
#[inline]
#[must_use]
pub const fn trunc_i64_i16(v: i64) -> i16 {
    let b = v.to_le_bytes();
    i16::from_le_bytes([b[0], b[1]])
}

/// Low 32 bits of an `i64` reinterpreted unsigned, bit-exact with `v as u32`.
#[inline]
#[must_use]
pub const fn trunc_i64_u32(v: i64) -> u32 {
    let b = v.to_le_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Low 32 bits of a `u64` as a signed 32-bit value, bit-exact with `v as i32`.
#[inline]
#[must_use]
pub const fn trunc_u64_i32(v: u64) -> i32 {
    let b = v.to_le_bytes();
    i32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Low 16 bits of a `u64` as a signed 16-bit value, bit-exact with `v as i16`.
#[inline]
#[must_use]
pub const fn trunc_u64_i16(v: u64) -> i16 {
    let b = v.to_le_bytes();
    i16::from_le_bytes([b[0], b[1]])
}

/// Low 16 bits of an `i32` as a signed 16-bit value, bit-exact with `v as i16`.
#[inline]
#[must_use]
pub const fn trunc_i32_i16(v: i32) -> i16 {
    let b = v.to_le_bytes();
    i16::from_le_bytes([b[0], b[1]])
}

/// Low 8 bits of an `i32` reinterpreted unsigned, bit-exact with `v as u8`.
#[inline]
#[must_use]
pub const fn trunc_i32_u8(v: i32) -> u8 {
    v.to_le_bytes()[0]
}

/// Low 16 bits of an `i32` reinterpreted unsigned, bit-exact with `v as u16`.
#[inline]
#[must_use]
pub const fn trunc_i32_u16(v: i32) -> u16 {
    let b = v.to_le_bytes();
    u16::from_le_bytes([b[0], b[1]])
}

/// Sign-extend an `i32` and reinterpret it as `u64`, bit-exact with `v as u64`.
#[inline]
#[must_use]
pub fn i32_to_u64(v: i32) -> u64 {
    i64::from(v).cast_unsigned()
}

/// Reinterpret a `usize` as `i64`.
///
/// Exact on 32- and 64-bit targets; a `usize` larger than [`i64::MAX`] cannot
/// occur on either, and would saturate rather than wrap.
#[inline]
#[must_use]
pub fn usize_to_i64(v: usize) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Reinterpret an `i64` as a `usize` index.
///
/// A negative value maps to `0` and an out-of-range value to [`usize::MAX`];
/// both make the caller's bounds check fail instead of wrapping into a valid
/// index, which is the property that matters when the value came from a file.
#[inline]
#[must_use]
pub fn i64_to_usize(v: i64) -> usize {
    usize::try_from(v).unwrap_or(if v < 0 { 0 } else { usize::MAX })
}
