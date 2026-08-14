//! `stream_reader` — low-level `MSF` stream abstractions and byte-parsing utilities.
//!
//! Provides `StreamReader`, a cursor-based view over a single `MSF` stream, with
//! typed read methods for all `CodeView`/`PDB` primitive types.

use crate::{PdbError, Result};

// ── StreamReader ──────────────────────────────────────────────────────────────

/// A cursor-positioned reader over a byte slice (one `MSF` stream).
#[derive(Debug, Clone)]
pub struct StreamReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> StreamReader<'a> {
    /// Create a new reader at position 0.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Current read position.
    #[must_use]
    pub const fn pos(&self) -> usize {
        self.pos
    }

    /// Total length of the stream.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// True when the cursor is at or past the end.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Number of unread bytes remaining.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Seek to an absolute position.
    pub fn seek(&mut self, pos: usize) {
        self.pos = pos.min(self.data.len());
    }

    /// Advance the cursor by `n` bytes.
    ///
    /// # Errors
    /// Returns an error if parsing/reading fails.
    pub const fn skip(&mut self, n: usize) -> Result<()> {
        if self.pos + n > self.data.len() {
            return Err(PdbError::StreamTooShort);
        }
        self.pos += n;
        Ok(())
    }

    /// Align the cursor to the next `align`-byte boundary (1, 2, or 4).
    pub fn align(&mut self, align: usize) {
        if align <= 1 {
            return;
        }
        let rem = self.pos % align;
        if rem != 0 {
            self.pos = (self.pos + align - rem).min(self.data.len());
        }
    }

    /// Read a slice of `n` bytes without copying.
    ///
    /// # Errors
    /// May fail when reading past the end of stream.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let start = self.pos;
        let end = start + n;
        if end > self.data.len() {
            return Err(PdbError::StreamTooShort);
        }
        self.pos = end;
        Ok(&self.data[start..end])
    }

    /// Peek at `n` bytes without advancing the cursor.
    ///
    /// # Errors
    /// May fail when reading past the end of stream.
    pub fn peek_bytes(&self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos + n;
        if end > self.data.len() {
            return Err(PdbError::StreamTooShort);
        }
        Ok(&self.data[self.pos..end])
    }

    /// Read a little-endian `u8`.
    ///
    /// # Errors
    /// May fail when reading past the end of stream.
    pub fn read_u8(&mut self) -> Result<u8> {
        let b = self
            .data
            .get(self.pos)
            .copied()
            .ok_or(PdbError::StreamTooShort)?;
        self.pos += 1;
        Ok(b)
    }

    /// Read a little-endian `u16`.
    ///
    /// # Errors
    /// May fail when reading past the end of stream.
    pub fn read_u16(&mut self) -> Result<u16> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes(
            b.try_into().map_err(|_| PdbError::CorruptData)?,
        ))
    }

    /// Read a little-endian `i16`.
    ///
    /// # Errors
    /// May fail when reading past the end of stream.
    pub fn read_i16(&mut self) -> Result<i16> {
        self.read_u16().map(u16::cast_signed)
    }

    /// Read a little-endian `u32`.
    ///
    /// # Errors
    /// May fail when reading past the end of stream.
    pub fn read_u32(&mut self) -> Result<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes(
            b.try_into().map_err(|_| PdbError::CorruptData)?,
        ))
    }

    /// Read a little-endian `i32`.
    ///
    /// # Errors
    /// May fail when reading past the end of stream.
    pub fn read_i32(&mut self) -> Result<i32> {
        self.read_u32().map(u32::cast_signed)
    }

    /// Read a little-endian `u64`.
    ///
    /// # Errors
    /// May fail when reading past the end of stream.
    pub fn read_u64(&mut self) -> Result<u64> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_le_bytes(
            b.try_into().map_err(|_| PdbError::CorruptData)?,
        ))
    }

    /// Read a little-endian `i64`.
    ///
    /// # Errors
    /// May fail when reading past the end of stream.
    pub fn read_i64(&mut self) -> Result<i64> {
        self.read_u64().map(u64::cast_signed)
    }

    /// Read a null-terminated UTF-8 string.
    ///
    /// # Errors
    /// May fail when reading past the end of stream.
    pub fn read_cstring(&mut self) -> Result<String> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        let s = String::from_utf8_lossy(&self.data[start..self.pos]).into_owned();
        if self.pos < self.data.len() {
            self.pos += 1; // skip NUL
        }
        Ok(s)
    }

    /// Read a length-prefixed string (u8 length + bytes, no NUL).
    ///
    /// # Errors
    /// May fail when reading past the end of stream.
    pub fn read_length_prefixed_string(&mut self) -> Result<String> {
        let len = self.read_u8()? as usize;
        let bytes = self.read_bytes(len)?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    /// Read a `CodeView` "numeric leaf" — a variable-width value used in type records.
    ///
    /// If the first u16 is < 0x8000, it is the value itself.
    /// Otherwise the type code indicates the width of the following bytes.
    ///
    /// # Errors
    /// May fail when reading past the end of stream.
    pub fn read_numeric_leaf(&mut self) -> Result<i64> {
        let tag = self.read_u16()?;
        if tag < 0x8000 {
            return Ok(i64::from(tag));
        }
        match tag {
            0x8000 | 0x8001 => Ok(i64::from(self.read_i16()?)), // LF_CHAR / LF_SHORT
            0x8002 => Ok(i64::from(self.read_u16()?)),          // LF_USHORT
            0x8003 => Ok(i64::from(self.read_i32()?)),          // LF_LONG
            0x8004 => Ok(i64::from(self.read_u32()?)),          // LF_ULONG
            0x8009 | 0x800A => Ok(self.read_i64()?),            // LF_QUADWORD / LF_UQUADWORD
            _ => {
                // Unknown numeric leaf — return 0 and skip 4 bytes conservatively.
                let _ = self.skip(4);
                Ok(0)
            }
        }
    }

    /// Return the raw slice of the stream from `start` to `end` (non-consuming).
    ///
    /// # Errors
    /// May fail when reading past the end of stream.
    pub fn slice(&self, start: usize, end: usize) -> Result<&'a [u8]> {
        self.data.get(start..end).ok_or(PdbError::StreamTooShort)
    }

    /// Return the remaining data from the current position.
    #[must_use]
    pub fn remaining_data(&self) -> &'a [u8] {
        &self.data[self.pos.min(self.data.len())..]
    }
}

// ── StringTable ───────────────────────────────────────────────────────────────

/// `PDB` string table: maps offsets to string literals.
///
/// Used by the Names stream (`/names`) and various symbol records.
#[derive(Debug, Clone, Default)]
pub struct StringTable {
    /// Raw byte data of the string heap.
    heap: Vec<u8>,
}

impl StringTable {
    /// Create an empty string table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a string table from the raw names-stream data.
    ///
    /// Format: `header(8 bytes)` | `string_data` | `hash_table`
    /// We only care about the string data itself.
    #[must_use]
    pub fn from_stream(data: &[u8]) -> Self {
        // The /names stream starts with a signature (u32) and version (u32).
        // String data follows immediately; offsets are into this data region.
        let heap = if data.len() > 8 {
            data[8..].to_vec()
        } else {
            Vec::new()
        };
        Self { heap }
    }

    /// Retrieve the string at byte `offset` within the string heap.
    #[must_use]
    pub fn get(&self, offset: u32) -> Option<&str> {
        let start = offset as usize;
        if start >= self.heap.len() {
            return None;
        }
        let slice = &self.heap[start..];
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        std::str::from_utf8(&slice[..end]).ok()
    }

    /// Number of bytes in the string heap.
    #[must_use]
    pub const fn heap_size(&self) -> usize {
        self.heap.len()
    }
}

// ── RecordHeader ──────────────────────────────────────────────────────────────

/// Common 4-byte header shared by symbol and type records:
/// ```text
/// u16 length  — size of record including type field but NOT this length field
/// u16 kind    — record type code
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RecordHeader {
    /// Total record length (excludes the 2-byte length field itself).
    pub length: u16,
    /// Record type / leaf type code.
    pub kind: u16,
}

impl RecordHeader {
    /// Read the 4-byte record header.
    ///
    /// # Errors
    /// Returns an error if parsing/reading fails.
    pub fn read(rdr: &mut StreamReader<'_>) -> Result<Self> {
        let length = rdr.read_u16()?;
        let kind = rdr.read_u16()?;
        Ok(Self { length, kind })
    }

    /// Total bytes consumed by this record (header + payload).
    #[must_use]
    pub const fn total_size(self) -> usize {
        // `length` includes the 2-byte `kind` field but NOT the 2-byte `length` itself.
        2 + self.length as usize
    }

    /// Payload size (`total_size` - 4 for header).
    #[must_use]
    pub const fn payload_size(self) -> usize {
        self.total_size().saturating_sub(4)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u8() {
        let data = [0x42u8];
        let mut r = StreamReader::new(&data);
        assert_eq!(r.read_u8().unwrap(), 0x42);
        assert!(r.read_u8().is_err());
    }

    #[test]
    fn test_read_u16() {
        let data = [0x34u8, 0x12];
        let mut r = StreamReader::new(&data);
        assert_eq!(r.read_u16().unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u32() {
        let data = [0x78u8, 0x56, 0x34, 0x12];
        let mut r = StreamReader::new(&data);
        assert_eq!(r.read_u32().unwrap(), 0x1234_5678);
    }

    #[test]
    fn test_read_u64() {
        let data: [u8; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
        let mut r = StreamReader::new(&data);
        assert_eq!(r.read_u64().unwrap(), 1);
    }

    #[test]
    fn test_read_cstring() {
        let data = b"hello\x00world";
        let mut r = StreamReader::new(data);
        let s = r.read_cstring().unwrap();
        assert_eq!(s, "hello");
        assert_eq!(r.pos(), 6);
    }

    #[test]
    fn test_skip_and_remaining() {
        let data = [0u8; 10];
        let mut r = StreamReader::new(&data);
        r.skip(4).unwrap();
        assert_eq!(r.remaining(), 6);
    }

    #[test]
    fn test_align() {
        let data = [0u8; 16];
        let mut r = StreamReader::new(&data);
        r.skip(3).unwrap();
        r.align(4);
        assert_eq!(r.pos(), 4);
    }

    #[test]
    fn test_seek() {
        let data = [0u8; 16];
        let mut r = StreamReader::new(&data);
        r.seek(8);
        assert_eq!(r.pos(), 8);
    }

    #[test]
    fn test_numeric_leaf_small() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0064u16.to_le_bytes()); // 100 < 0x8000
        let mut r = StreamReader::new(&data);
        assert_eq!(r.read_numeric_leaf().unwrap(), 100);
    }

    #[test]
    fn test_numeric_leaf_ulong() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x8004u16.to_le_bytes()); // LF_ULONG
        data.extend_from_slice(&42u32.to_le_bytes());
        let mut r = StreamReader::new(&data);
        assert_eq!(r.read_numeric_leaf().unwrap(), 42);
    }

    #[test]
    fn test_string_table_get() {
        // 8-byte fake header + "hello\0world\0"
        let mut data = vec![0u8; 8];
        data.extend_from_slice(b"hello\0world\0");
        let st = StringTable::from_stream(&data);
        assert_eq!(st.get(0), Some("hello"));
        assert_eq!(st.get(6), Some("world"));
    }

    #[test]
    fn test_record_header_sizes() {
        let hdr = RecordHeader {
            length: 20,
            kind: 0x1100,
        };
        assert_eq!(hdr.total_size(), 22); // 2 + 20
        assert_eq!(hdr.payload_size(), 18); // 22 - 4
    }

    #[test]
    fn test_peek_bytes_no_advance() {
        let data = [1u8, 2, 3, 4];
        let r = StreamReader::new(&data);
        let b = r.peek_bytes(2).unwrap();
        assert_eq!(b, &[1, 2]);
        assert_eq!(r.pos(), 0); // unchanged
    }

    #[test]
    fn test_is_empty_and_len() {
        let data = [0u8; 4];
        let mut r = StreamReader::new(&data);
        assert_eq!(r.len(), 4);
        assert!(!r.is_empty());
        r.skip(4).unwrap();
        assert!(r.is_empty());
    }
}
