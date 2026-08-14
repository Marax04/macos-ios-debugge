//! Endianness modelling and byte-order-aware I/O helpers.
//!
//! This module provides:
//!
//! - [`Endian`] — a two-variant enum for little / big endian.
//! - Free functions for converting to/from native byte order.
//! - [`EndianRead`] — a trait implemented for `[u8]` enabling ergonomic
//!   offset-based reads of all integer types.
//! - [`EndianBuf`] — an owned, byte-order-aware in-memory buffer.
//! - [`EndianReader<R>`] — an adaptor over any `std::io::Read` that decodes
//!   integers according to a chosen endianness.
//! - [`EndianWriter<W>`] — an adaptor over any `std::io::Write` that encodes
//!   integers in a chosen endianness.
//! - ULEB128 and SLEB128 encode/decode functions.
//! - `swap_endian_*` free functions.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

// ─────────────────────────────────────────────────────────────────────────────
// Endian enum
// ─────────────────────────────────────────────────────────────────────────────

/// Byte order used when reading multi-byte integers from memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endian {
    /// Least-significant byte first (x86, ARM LE, RISC-V, …).
    Little,
    /// Most-significant byte first (MIPS BE, SPARC, big-endian ARM, …).
    Big,
}

impl Endian {
    /// Return `true` if this is little-endian.
    #[must_use]
    pub const fn is_little(self) -> bool {
        matches!(self, Self::Little)
    }

    /// Return `true` if this is big-endian.
    #[must_use]
    pub const fn is_big(self) -> bool {
        matches!(self, Self::Big)
    }

    /// Return the opposite endianness.
    #[must_use]
    pub const fn flip(self) -> Self {
        match self {
            Self::Little => Self::Big,
            Self::Big => Self::Little,
        }
    }

    /// Return the native endianness of the current platform.
    #[must_use]
    pub const fn native() -> Self {
        #[cfg(target_endian = "little")]
        {
            Self::Little
        }
        #[cfg(target_endian = "big")]
        {
            Endian::Big
        }
    }

    /// Return `true` if this matches the native platform endianness.
    #[must_use]
    pub fn is_native(self) -> bool {
        self == Self::native()
    }
}

impl std::fmt::Display for Endian {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Little => write!(f, "little-endian"),
            Self::Big => write!(f, "big-endian"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Swap helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Unconditionally swap the byte order of a `u16`.
#[must_use]
pub const fn swap_endian_u16(v: u16) -> u16 {
    v.swap_bytes()
}

/// Unconditionally swap the byte order of a `u32`.
#[must_use]
pub const fn swap_endian_u32(v: u32) -> u32 {
    v.swap_bytes()
}

/// Unconditionally swap the byte order of a `u64`.
#[must_use]
pub const fn swap_endian_u64(v: u64) -> u64 {
    v.swap_bytes()
}

/// Unconditionally swap the byte order of a `u128`.
#[must_use]
pub const fn swap_endian_u128(v: u128) -> u128 {
    v.swap_bytes()
}

// ─────────────────────────────────────────────────────────────────────────────
// EndianRead trait
// ─────────────────────────────────────────────────────────────────────────────

/// Offset-based, endian-aware read operations over a byte slice.
pub trait EndianRead {
    /// Read a single byte at `offset`.
    fn read_u8(&self, offset: usize) -> Option<u8>;
    /// Read a signed byte at `offset`.
    fn read_i8(&self, offset: usize) -> Option<i8>;

    /// Read a `u16` at `offset` using `endian`.
    fn read_u16(&self, offset: usize, endian: Endian) -> Option<u16>;
    /// Read an `i16` at `offset` using `endian`.
    fn read_i16(&self, offset: usize, endian: Endian) -> Option<i16>;

    /// Read a `u32` at `offset` using `endian`.
    fn read_u32(&self, offset: usize, endian: Endian) -> Option<u32>;
    /// Read an `i32` at `offset` using `endian`.
    fn read_i32(&self, offset: usize, endian: Endian) -> Option<i32>;

    /// Read a `u64` at `offset` using `endian`.
    fn read_u64(&self, offset: usize, endian: Endian) -> Option<u64>;
    /// Read an `i64` at `offset` using `endian`.
    fn read_i64(&self, offset: usize, endian: Endian) -> Option<i64>;

    /// Read a `u128` at `offset` using `endian`.
    fn read_u128(&self, offset: usize, endian: Endian) -> Option<u128>;
    /// Read an `i128` at `offset` using `endian`.
    fn read_i128(&self, offset: usize, endian: Endian) -> Option<i128>;

    /// Read a `f32` at `offset` using `endian`.
    fn read_f32(&self, offset: usize, endian: Endian) -> Option<f32>;
    /// Read a `f64` at `offset` using `endian`.
    fn read_f64(&self, offset: usize, endian: Endian) -> Option<f64>;

    /// Read a pointer-sized unsigned integer.
    fn read_ptr(&self, offset: usize, endian: Endian, ptr_size: usize) -> Option<u64> {
        match ptr_size {
            2 => self.read_u16(offset, endian).map(u64::from),
            4 => self.read_u32(offset, endian).map(u64::from),
            8 => self.read_u64(offset, endian),
            _ => None,
        }
    }
}

impl EndianRead for [u8] {
    #[inline]
    fn read_u8(&self, offset: usize) -> Option<u8> {
        self.get(offset).copied()
    }

    #[inline]
    fn read_i8(&self, offset: usize) -> Option<i8> {
        self.read_u8(offset).map(u8::cast_signed)
    }

    #[inline]
    fn read_u16(&self, offset: usize, endian: Endian) -> Option<u16> {
        let bytes: [u8; 2] = self.get(offset..offset + 2)?.try_into().ok()?;
        Some(match endian {
            Endian::Little => u16::from_le_bytes(bytes),
            Endian::Big => u16::from_be_bytes(bytes),
        })
    }

    #[inline]
    fn read_i16(&self, offset: usize, endian: Endian) -> Option<i16> {
        self.read_u16(offset, endian).map(u16::cast_signed)
    }

    #[inline]
    fn read_u32(&self, offset: usize, endian: Endian) -> Option<u32> {
        let bytes: [u8; 4] = self.get(offset..offset + 4)?.try_into().ok()?;
        Some(match endian {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        })
    }

    #[inline]
    fn read_i32(&self, offset: usize, endian: Endian) -> Option<i32> {
        self.read_u32(offset, endian).map(u32::cast_signed)
    }

    #[inline]
    fn read_u64(&self, offset: usize, endian: Endian) -> Option<u64> {
        let bytes: [u8; 8] = self.get(offset..offset + 8)?.try_into().ok()?;
        Some(match endian {
            Endian::Little => u64::from_le_bytes(bytes),
            Endian::Big => u64::from_be_bytes(bytes),
        })
    }

    #[inline]
    fn read_i64(&self, offset: usize, endian: Endian) -> Option<i64> {
        self.read_u64(offset, endian).map(u64::cast_signed)
    }

    #[inline]
    fn read_u128(&self, offset: usize, endian: Endian) -> Option<u128> {
        let bytes: [u8; 16] = self.get(offset..offset + 16)?.try_into().ok()?;
        Some(match endian {
            Endian::Little => u128::from_le_bytes(bytes),
            Endian::Big => u128::from_be_bytes(bytes),
        })
    }

    #[inline]
    fn read_i128(&self, offset: usize, endian: Endian) -> Option<i128> {
        self.read_u128(offset, endian).map(u128::cast_signed)
    }

    #[inline]
    fn read_f32(&self, offset: usize, endian: Endian) -> Option<f32> {
        let bits = self.read_u32(offset, endian)?;
        Some(f32::from_bits(bits))
    }

    #[inline]
    fn read_f64(&self, offset: usize, endian: Endian) -> Option<f64> {
        let bits = self.read_u64(offset, endian)?;
        Some(f64::from_bits(bits))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EndianBuf
// ─────────────────────────────────────────────────────────────────────────────

/// An owned, byte-order-aware in-memory buffer.
///
/// Combines an `Endian` hint with a `Vec<u8>` and exposes the full
/// [`EndianRead`] interface plus write helpers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndianBuf {
    /// The raw bytes.
    pub data: Vec<u8>,
    /// The endianness to use for multi-byte reads/writes.
    pub endian: Endian,
}

impl EndianBuf {
    /// Create an empty buffer with the given endianness.
    #[must_use]
    pub const fn new(endian: Endian) -> Self {
        Self {
            data: Vec::new(),
            endian,
        }
    }

    /// Wrap an existing byte vector.
    #[must_use]
    pub const fn from_vec(data: Vec<u8>, endian: Endian) -> Self {
        Self { data, endian }
    }

    /// Create a buffer filled with `len` zero bytes.
    #[must_use]
    pub fn zeroed(len: usize, endian: Endian) -> Self {
        Self {
            data: vec![0u8; len],
            endian,
        }
    }

    /// Length of the buffer in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Return `true` if the buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Access the raw bytes as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    // ── Read helpers ──────────────────────────────────────────────────────────

    /// Read a `u8` at `offset`.
    #[must_use]
    pub fn read_u8(&self, offset: usize) -> Option<u8> {
        self.data.as_slice().read_u8(offset)
    }

    /// Read a `u16` at `offset`.
    #[must_use]
    pub fn read_u16(&self, offset: usize) -> Option<u16> {
        self.data.as_slice().read_u16(offset, self.endian)
    }

    /// Read a `u32` at `offset`.
    #[must_use]
    pub fn read_u32(&self, offset: usize) -> Option<u32> {
        self.data.as_slice().read_u32(offset, self.endian)
    }

    /// Read a `u64` at `offset`.
    #[must_use]
    pub fn read_u64(&self, offset: usize) -> Option<u64> {
        self.data.as_slice().read_u64(offset, self.endian)
    }

    /// Read an `i32` at `offset`.
    #[must_use]
    pub fn read_i32(&self, offset: usize) -> Option<i32> {
        self.data.as_slice().read_i32(offset, self.endian)
    }

    /// Read an `i64` at `offset`.
    #[must_use]
    pub fn read_i64(&self, offset: usize) -> Option<i64> {
        self.data.as_slice().read_i64(offset, self.endian)
    }

    // ── Write helpers ─────────────────────────────────────────────────────────

    /// Append a `u8` to the buffer.
    pub fn write_u8(&mut self, v: u8) {
        self.data.push(v);
    }

    /// Append a `u16` in the buffer's endianness.
    pub fn write_u16(&mut self, v: u16) {
        let bytes = match self.endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        self.data.extend_from_slice(&bytes);
    }

    /// Append a `u32` in the buffer's endianness.
    pub fn write_u32(&mut self, v: u32) {
        let bytes = match self.endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        self.data.extend_from_slice(&bytes);
    }

    /// Append a `u64` in the buffer's endianness.
    pub fn write_u64(&mut self, v: u64) {
        let bytes = match self.endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        self.data.extend_from_slice(&bytes);
    }

    /// Append a `u128` in the buffer's endianness.
    pub fn write_u128(&mut self, v: u128) {
        let bytes = match self.endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        self.data.extend_from_slice(&bytes);
    }

    /// Append an `f32` in the buffer's endianness.
    pub fn write_f32(&mut self, v: f32) {
        self.write_u32(v.to_bits());
    }

    /// Append an `f64` in the buffer's endianness.
    pub fn write_f64(&mut self, v: f64) {
        self.write_u64(v.to_bits());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EndianReader<R>
// ─────────────────────────────────────────────────────────────────────────────

/// Adaptor over any `std::io::Read` that decodes integers according to a
/// chosen endianness.
pub struct EndianReader<R: Read> {
    inner: R,
    endian: Endian,
}

impl<R: Read> EndianReader<R> {
    /// Wrap a reader with the given endianness.
    pub const fn new(inner: R, endian: Endian) -> Self {
        Self { inner, endian }
    }

    /// Return the configured endianness.
    #[must_use]
    pub const fn endian(&self) -> Endian {
        self.endian
    }

    /// Consume the adaptor and return the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Read exactly `n` bytes into a `Vec<u8>`.
    ///
    /// # Errors
    /// Returns an I/O error if fewer than `n` bytes are available.
    pub fn read_bytes(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.inner.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Read a single `u8`.
    ///
    /// # Errors
    /// Returns an I/O error on read failure.
    pub fn read_u8(&mut self) -> io::Result<u8> {
        let mut buf = [0u8; 1];
        self.inner.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    /// Read a `u16`.
    ///
    /// # Errors
    /// Returns an I/O error on read failure.
    pub fn read_u16(&mut self) -> io::Result<u16> {
        let mut buf = [0u8; 2];
        self.inner.read_exact(&mut buf)?;
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(buf),
            Endian::Big => u16::from_be_bytes(buf),
        })
    }

    /// Read an `i16`.
    ///
    /// # Errors
    /// Returns an I/O error on read failure.
    pub fn read_i16(&mut self) -> io::Result<i16> {
        self.read_u16().map(u16::cast_signed)
    }

    /// Read a `u32`.
    ///
    /// # Errors
    /// Returns an I/O error on read failure.
    pub fn read_u32(&mut self) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        self.inner.read_exact(&mut buf)?;
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(buf),
            Endian::Big => u32::from_be_bytes(buf),
        })
    }

    /// Read an `i32`.
    ///
    /// # Errors
    /// Returns an I/O error on read failure.
    pub fn read_i32(&mut self) -> io::Result<i32> {
        self.read_u32().map(u32::cast_signed)
    }

    /// Read a `u64`.
    ///
    /// # Errors
    /// Returns an I/O error on read failure.
    pub fn read_u64(&mut self) -> io::Result<u64> {
        let mut buf = [0u8; 8];
        self.inner.read_exact(&mut buf)?;
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(buf),
            Endian::Big => u64::from_be_bytes(buf),
        })
    }

    /// Read an `i64`.
    ///
    /// # Errors
    /// Returns an I/O error on read failure.
    pub fn read_i64(&mut self) -> io::Result<i64> {
        self.read_u64().map(u64::cast_signed)
    }

    /// Read a `u128`.
    ///
    /// # Errors
    /// Returns an I/O error on read failure.
    pub fn read_u128(&mut self) -> io::Result<u128> {
        let mut buf = [0u8; 16];
        self.inner.read_exact(&mut buf)?;
        Ok(match self.endian {
            Endian::Little => u128::from_le_bytes(buf),
            Endian::Big => u128::from_be_bytes(buf),
        })
    }

    /// Read an `i128`.
    ///
    /// # Errors
    /// Returns an I/O error on read failure.
    pub fn read_i128(&mut self) -> io::Result<i128> {
        self.read_u128().map(u128::cast_signed)
    }

    /// Read an `f32`.
    ///
    /// # Errors
    /// Returns an I/O error on read failure.
    pub fn read_f32(&mut self) -> io::Result<f32> {
        self.read_u32().map(f32::from_bits)
    }

    /// Read an `f64`.
    ///
    /// # Errors
    /// Returns an I/O error on read failure.
    pub fn read_f64(&mut self) -> io::Result<f64> {
        self.read_u64().map(f64::from_bits)
    }

    /// Read a ULEB128-encoded `u64`.
    ///
    /// # Errors
    /// Returns an I/O error on read failure or if the value exceeds 10 bytes.
    pub fn read_uleb128(&mut self) -> io::Result<u64> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.read_u8()?;
            let low7 = u64::from(byte & 0x7F);
            // Guard against shift ≥ 64, which would be UB / panic on debug.
            if shift >= 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ULEB128 overflow",
                ));
            }
            let bits = low7
                .checked_shl(shift)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ULEB128 overflow"))?;
            result |= bits;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        Ok(result)
    }

    /// Read a SLEB128-encoded `i64`.
    ///
    /// # Errors
    /// Returns an I/O error on read failure or overflow.
    pub fn read_sleb128(&mut self) -> io::Result<i64> {
        let mut result = 0i64;
        let mut shift = 0u32;
        let mut byte;
        loop {
            byte = self.read_u8()?;
            let low7 = i64::from(byte & 0x7F);
            // Guard against shift ≥ 64, which would be UB / panic on debug.
            if shift >= 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SLEB128 overflow",
                ));
            }
            result |= low7
                .checked_shl(shift)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SLEB128 overflow"))?;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
            if shift >= 70 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SLEB128 overflow",
                ));
            }
        }
        // Sign-extend if the sign bit of the last group is set.
        if shift < 64 && (byte & 0x40) != 0 {
            result |= -(1i64 << shift);
        }
        Ok(result)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EndianWriter<W>
// ─────────────────────────────────────────────────────────────────────────────

/// Adaptor over any `std::io::Write` that encodes integers in a chosen
/// endianness.
pub struct EndianWriter<W: Write> {
    inner: W,
    endian: Endian,
}

impl<W: Write> EndianWriter<W> {
    /// Wrap a writer with the given endianness.
    pub const fn new(inner: W, endian: Endian) -> Self {
        Self { inner, endian }
    }

    /// Return the configured endianness.
    #[must_use]
    pub const fn endian(&self) -> Endian {
        self.endian
    }

    /// Consume the adaptor and return the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Write a `u8`.
    ///
    /// # Errors
    /// Returns an I/O error on write failure.
    pub fn write_u8(&mut self, v: u8) -> io::Result<()> {
        self.inner.write_all(&[v])
    }

    /// Write a `u16`.
    ///
    /// # Errors
    /// Returns an I/O error on write failure.
    pub fn write_u16(&mut self, v: u16) -> io::Result<()> {
        let bytes = match self.endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        self.inner.write_all(&bytes)
    }

    /// Write an `i16`.
    ///
    /// # Errors
    /// Returns an I/O error on write failure.
    pub fn write_i16(&mut self, v: i16) -> io::Result<()> {
        self.write_u16(v.cast_unsigned())
    }

    /// Write a `u32`.
    ///
    /// # Errors
    /// Returns an I/O error on write failure.
    pub fn write_u32(&mut self, v: u32) -> io::Result<()> {
        let bytes = match self.endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        self.inner.write_all(&bytes)
    }

    /// Write an `i32`.
    ///
    /// # Errors
    /// Returns an I/O error on write failure.
    pub fn write_i32(&mut self, v: i32) -> io::Result<()> {
        self.write_u32(v.cast_unsigned())
    }

    /// Write a `u64`.
    ///
    /// # Errors
    /// Returns an I/O error on write failure.
    pub fn write_u64(&mut self, v: u64) -> io::Result<()> {
        let bytes = match self.endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        self.inner.write_all(&bytes)
    }

    /// Write an `i64`.
    ///
    /// # Errors
    /// Returns an I/O error on write failure.
    pub fn write_i64(&mut self, v: i64) -> io::Result<()> {
        self.write_u64(v.cast_unsigned())
    }

    /// Write a `u128`.
    ///
    /// # Errors
    /// Returns an I/O error on write failure.
    pub fn write_u128(&mut self, v: u128) -> io::Result<()> {
        let bytes = match self.endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        self.inner.write_all(&bytes)
    }

    /// Write an `f32`.
    ///
    /// # Errors
    /// Returns an I/O error on write failure.
    pub fn write_f32(&mut self, v: f32) -> io::Result<()> {
        self.write_u32(v.to_bits())
    }

    /// Write an `f64`.
    ///
    /// # Errors
    /// Returns an I/O error on write failure.
    pub fn write_f64(&mut self, v: f64) -> io::Result<()> {
        self.write_u64(v.to_bits())
    }

    /// Write a ULEB128-encoded `u64`.
    ///
    /// # Errors
    /// Returns an I/O error on write failure.
    pub fn write_uleb128(&mut self, mut v: u64) -> io::Result<()> {
        loop {
            let mut byte = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            self.inner.write_all(&[byte])?;
            if v == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Write a SLEB128-encoded `i64`.
    ///
    /// # Errors
    /// Returns an I/O error on write failure.
    pub fn write_sleb128(&mut self, mut v: i64) -> io::Result<()> {
        let mut more = true;
        while more {
            // Mask isolates 7 low bits so the truncation to u8 is safe.
            let mut byte = u8::try_from((v & 0x7F).cast_unsigned()).unwrap_or(0);
            v >>= 7;
            if (v == 0 && (byte & 0x40) == 0) || (v == -1 && (byte & 0x40) != 0) {
                more = false;
            } else {
                byte |= 0x80;
            }
            self.inner.write_all(&[byte])?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ULEB128 / SLEB128 free functions
// ─────────────────────────────────────────────────────────────────────────────

/// Encode `v` as ULEB128 into a `Vec<u8>`.
#[must_use]
pub fn encode_uleb128(mut v: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
    out
}

/// Decode a ULEB128 value from `data` starting at `offset`.
///
/// Returns `(value, bytes_consumed)`, or `None` if the data is truncated or
/// the value overflows a `u64`.
#[must_use]
pub fn decode_uleb128(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    let mut pos = offset;
    loop {
        let byte = *data.get(pos)?;
        pos += 1;
        let low7 = u64::from(byte & 0x7F);
        result = result.checked_add(low7.checked_shl(shift)?)?;
        if byte & 0x80 == 0 {
            return Some((result, pos - offset));
        }
        shift += 7;
        if shift >= 70 {
            return None;
        }
    }
}

/// Encode `v` as SLEB128 into a `Vec<u8>`.
#[must_use]
pub fn encode_sleb128(mut v: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    let mut more = true;
    while more {
        // Mask isolates 7 low bits so the truncation to u8 is safe.
        let mut byte = u8::try_from((v & 0x7F).cast_unsigned()).unwrap_or(0);
        v >>= 7;
        if (v == 0 && (byte & 0x40) == 0) || (v == -1 && (byte & 0x40) != 0) {
            more = false;
        } else {
            byte |= 0x80;
        }
        out.push(byte);
    }
    out
}

/// Decode a SLEB128 value from `data` starting at `offset`.
///
/// Returns `(value, bytes_consumed)`, or `None` if the data is truncated or
/// overflows.
#[must_use]
pub fn decode_sleb128(data: &[u8], offset: usize) -> Option<(i64, usize)> {
    let mut result = 0i64;
    let mut shift = 0u32;
    let mut pos = offset;
    let mut byte;
    loop {
        byte = *data.get(pos)?;
        pos += 1;
        let low7 = i64::from(byte & 0x7F);
        result |= low7 << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift >= 70 {
            return None;
        }
    }
    if shift < 64 && (byte & 0x40) != 0 {
        // (1i64 << 63) is i64::MIN; plain negation would overflow,
        // so use wrapping_neg() which yields i64::MIN itself — the correct
        // sign-extension mask for shift == 63.
        result |= (1i64 << shift).wrapping_neg();
    }
    Some((result, pos - offset))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── Endian enum ───────────────────────────────────────────────────────────

    #[test]
    fn endian_is_little_big() {
        assert!(Endian::Little.is_little());
        assert!(!Endian::Little.is_big());
        assert!(Endian::Big.is_big());
        assert!(!Endian::Big.is_little());
    }

    #[test]
    fn endian_flip() {
        assert_eq!(Endian::Little.flip(), Endian::Big);
        assert_eq!(Endian::Big.flip(), Endian::Little);
    }

    #[test]
    fn endian_native_consistent() {
        let native = Endian::native();
        assert!(native.is_native());
        assert!(!native.flip().is_native());
    }

    #[test]
    fn endian_display() {
        assert_eq!(Endian::Little.to_string(), "little-endian");
        assert_eq!(Endian::Big.to_string(), "big-endian");
    }

    // ── Swap helpers ──────────────────────────────────────────────────────────

    #[test]
    fn swap_u16() {
        assert_eq!(swap_endian_u16(0x0102), 0x0201);
    }

    #[test]
    fn swap_u32() {
        assert_eq!(swap_endian_u32(0x0102_0304), 0x0403_0201);
    }

    #[test]
    fn swap_u64() {
        assert_eq!(
            swap_endian_u64(0x0102_0304_0506_0708),
            0x0807_0605_0403_0201
        );
    }

    #[test]
    fn swap_u128() {
        let v: u128 = 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10;
        let s = swap_endian_u128(v);
        assert_eq!(swap_endian_u128(s), v);
    }

    // ── EndianRead on [u8] ────────────────────────────────────────────────────

    #[test]
    fn slice_read_u8() {
        let data = [0xABu8];
        assert_eq!(data.read_u8(0), Some(0xAB));
        assert_eq!(data.read_u8(1), None);
    }

    #[test]
    fn slice_read_i8() {
        let data = [0xFFu8];
        assert_eq!(data.read_i8(0), Some(-1i8));
    }

    #[test]
    fn slice_read_u16_le() {
        let data = [0x01u8, 0x02];
        assert_eq!(data.read_u16(0, Endian::Little), Some(0x0201));
    }

    #[test]
    fn slice_read_u16_be() {
        let data = [0x01u8, 0x02];
        assert_eq!(data.read_u16(0, Endian::Big), Some(0x0102));
    }

    #[test]
    fn slice_read_u32_bounds() {
        let data = [0u8; 3];
        assert_eq!(data.read_u32(0, Endian::Little), None);
    }

    #[test]
    fn slice_read_f32_le() {
        let v: f32 = std::f32::consts::PI;
        let bits = v.to_le_bytes();
        let result = bits.as_ref().read_f32(0, Endian::Little).unwrap();
        assert!((result - v).abs() < f32::EPSILON);
    }

    #[test]
    fn slice_read_f64_be() {
        let v: f64 = std::f64::consts::E;
        let bits = v.to_be_bytes();
        let result = bits.as_ref().read_f64(0, Endian::Big).unwrap();
        assert!((result - v).abs() < f64::EPSILON);
    }

    #[test]
    fn slice_read_u128() {
        let v: u128 = 0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0;
        let little = v.to_le_bytes();
        assert_eq!(little.as_ref().read_u128(0, Endian::Little), Some(v));
        let big = v.to_be_bytes();
        assert_eq!(big.as_ref().read_u128(0, Endian::Big), Some(v));
    }

    #[test]
    fn slice_read_ptr_32bit() {
        let data = [0x78u8, 0x56, 0x34, 0x12];
        assert_eq!(data.read_ptr(0, Endian::Little, 4), Some(0x1234_5678));
    }

    // ── EndianBuf ─────────────────────────────────────────────────────────────

    #[test]
    fn endian_buf_write_read() {
        let mut buf = EndianBuf::new(Endian::Little);
        buf.write_u32(0xDEAD_BEEF);
        buf.write_u16(0xCAFE);
        assert_eq!(buf.len(), 6);
        assert_eq!(buf.read_u32(0), Some(0xDEAD_BEEF));
        assert_eq!(buf.read_u16(4), Some(0xCAFE));
    }

    #[test]
    fn endian_buf_write_f64() {
        let mut buf = EndianBuf::new(Endian::Big);
        let v = 1.234_567_89_f64;
        buf.write_f64(v);
        let back = buf.as_slice().read_f64(0, Endian::Big).unwrap();
        assert!((back - v).abs() < f64::EPSILON);
    }

    #[test]
    fn endian_buf_zeroed() {
        let buf = EndianBuf::zeroed(16, Endian::Little);
        assert_eq!(buf.len(), 16);
        assert_eq!(buf.read_u64(0), Some(0));
    }

    #[test]
    fn endian_buf_is_empty() {
        let buf = EndianBuf::new(Endian::Little);
        assert!(buf.is_empty());
    }

    // ── EndianReader ──────────────────────────────────────────────────────────

    #[test]
    fn endian_reader_u32_le() {
        let data = [0x01u8, 0x00, 0x00, 0x00];
        let mut r = EndianReader::new(Cursor::new(data), Endian::Little);
        assert_eq!(r.read_u32().unwrap(), 1);
    }

    #[test]
    fn endian_reader_u32_be() {
        let data = [0x00u8, 0x00, 0x00, 0x01];
        let mut r = EndianReader::new(Cursor::new(data), Endian::Big);
        assert_eq!(r.read_u32().unwrap(), 1);
    }

    #[test]
    fn endian_reader_u128() {
        let v: u128 = 0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00;
        let bytes = v.to_be_bytes();
        let mut r = EndianReader::new(Cursor::new(bytes), Endian::Big);
        assert_eq!(r.read_u128().unwrap(), v);
    }

    #[test]
    fn endian_reader_f64() {
        let v: f64 = -273.15;
        let bytes = v.to_le_bytes();
        let mut r = EndianReader::new(Cursor::new(bytes), Endian::Little);
        let back = r.read_f64().unwrap();
        assert!((back - v).abs() < f64::EPSILON);
    }

    #[test]
    fn endian_reader_bytes() {
        let data = vec![1u8, 2, 3, 4, 5];
        let mut r = EndianReader::new(Cursor::new(data), Endian::Little);
        let bytes = r.read_bytes(3).unwrap();
        assert_eq!(bytes, [1, 2, 3]);
    }

    // ── EndianWriter ──────────────────────────────────────────────────────────

    #[test]
    fn endian_writer_roundtrip_le() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = EndianWriter::new(&mut buf, Endian::Little);
            w.write_u32(0xCAFE_BABE).unwrap();
            w.write_u64(0x1234_5678_9ABC_DEF0).unwrap();
        }
        let mut r = EndianReader::new(Cursor::new(&buf), Endian::Little);
        assert_eq!(r.read_u32().unwrap(), 0xCAFE_BABE);
        assert_eq!(r.read_u64().unwrap(), 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn endian_writer_sleb128_roundtrip() {
        for v in [-1i64, 0, 127, -128, 300, -300, i64::MAX, i64::MIN] {
            let encoded = encode_sleb128(v);
            let (decoded, _) = decode_sleb128(&encoded, 0).unwrap();
            assert_eq!(decoded, v, "roundtrip failed for {v}");
        }
    }

    // ── ULEB128 / SLEB128 free functions ──────────────────────────────────────

    #[test]
    fn uleb128_zero() {
        let enc = encode_uleb128(0);
        assert_eq!(enc, [0]);
        let (v, n) = decode_uleb128(&enc, 0).unwrap();
        assert_eq!((v, n), (0, 1));
    }

    #[test]
    fn uleb128_127() {
        let enc = encode_uleb128(127);
        assert_eq!(enc, [127]);
    }

    #[test]
    fn uleb128_128() {
        let enc = encode_uleb128(128);
        assert_eq!(enc, [0x80, 0x01]);
        let (v, n) = decode_uleb128(&enc, 0).unwrap();
        assert_eq!((v, n), (128, 2));
    }

    #[test]
    fn uleb128_large_values() {
        for v in [
            0u64,
            1,
            127,
            128,
            16383,
            16384,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            let enc = encode_uleb128(v);
            let (decoded, _) = decode_uleb128(&enc, 0).unwrap();
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn sleb128_positive() {
        let enc = encode_sleb128(63);
        let (v, _) = decode_sleb128(&enc, 0).unwrap();
        assert_eq!(v, 63);
    }

    #[test]
    fn sleb128_negative() {
        for v in [-1i64, -64, -128, -300, -100_000] {
            let enc = encode_sleb128(v);
            let (decoded, _) = decode_sleb128(&enc, 0).unwrap();
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn sleb128_extremes() {
        for v in [i64::MIN, i64::MAX, 0i64] {
            let enc = encode_sleb128(v);
            let (decoded, _) = decode_sleb128(&enc, 0).unwrap();
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn uleb128_decode_with_offset() {
        let data = [0x00u8, 0x80, 0x01]; // prefix zero, then 128
        let (v, n) = decode_uleb128(&data, 1).unwrap();
        assert_eq!((v, n), (128, 2));
    }

    #[test]
    fn endian_reader_uleb128_sleb128_via_stream() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&encode_uleb128(300));
        buf.extend_from_slice(&encode_sleb128(-150));

        let mut r = EndianReader::new(Cursor::new(buf), Endian::Little);
        assert_eq!(r.read_uleb128().unwrap(), 300);
        assert_eq!(r.read_sleb128().unwrap(), -150);
    }
}
