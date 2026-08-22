//! IDA FLIRT `.sig` binary format parser.
//!
//! Supports versions 6–10 of the IDA FLIRT `.sig` file format.

use std::fmt;

// ── Constants ─────────────────────────────────────────────────────────────────

/// The magic bytes that begin every IDA FLIRT `.sig` file.
pub const SIG_MAGIC: &[u8] = b"IDASGN";

/// Minimum supported `.sig` version.
pub const SIG_VERSION_MIN: u8 = 6;
/// Maximum supported `.sig` version.
pub const SIG_VERSION_MAX: u8 = 10;

// ── SigParseError ─────────────────────────────────────────────────────────────

/// Errors that can occur while parsing an IDA `.sig` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigParseError {
    /// The magic bytes do not match `IDASGN`.
    InvalidMagic,
    /// The data ended before parsing was complete.
    Truncated,
    /// The version number is outside the supported range.
    UnsupportedVersion(u8),
    /// A structural parse error with a description.
    ParseError(String),
}

impl fmt::Display for SigParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid sig magic"),
            Self::Truncated => write!(f, "sig file truncated"),
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported sig version {v}")
            }
            Self::ParseError(s) => write!(f, "sig parse error: {s}"),
        }
    }
}

impl std::error::Error for SigParseError {}

// ── SigHeader ─────────────────────────────────────────────────────────────────

/// Parsed header of an IDA FLIRT `.sig` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigHeader {
    /// Format version (6–10).
    pub version: u8,
    /// CPU architecture byte.
    pub cpu: u8,
    /// Library flags.
    pub lib_flags: u8,
    /// C-type value.
    pub ctype: u8,
    /// Number of alternate names.
    pub n_alt: u16,
    /// Number of patterns in the database.
    pub n_pats: u32,
    /// Library name.
    pub name: String,
    /// Alternate library names.
    pub alt_names: Vec<String>,
}

// ── SigParser ─────────────────────────────────────────────────────────────────

/// Stateful byte-stream parser for `.sig` files.
pub struct SigParser {
    data: Vec<u8>,
    pos: usize,
}

impl SigParser {
    /// Create a new parser from raw bytes.
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }

    /// Read a single byte.
    ///
    /// # Panics
    ///
    /// Panics if the position is out of bounds. Call this only after bounds
    /// checking with [`Self::remaining`].
    pub fn read_u8(&mut self) -> u8 {
        let b = self.data[self.pos];
        self.pos += 1;
        b
    }

    /// Attempt to read a single byte, returning `None` if at end of data.
    pub fn try_read_u8(&mut self) -> Option<u8> {
        if self.pos < self.data.len() {
            let b = self.data[self.pos];
            self.pos += 1;
            Some(b)
        } else {
            None
        }
    }

    /// Read a 16-bit big-endian unsigned integer.
    ///
    /// # Errors
    ///
    /// Returns `Err` if fewer than 2 bytes remain.
    pub fn read_u16_be(&mut self) -> Result<u16, SigParseError> {
        if self.pos + 2 > self.data.len() {
            return Err(SigParseError::Truncated);
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Read a 32-bit big-endian unsigned integer.
    ///
    /// # Errors
    ///
    /// Returns `Err` if fewer than 4 bytes remain.
    pub fn read_u32_be(&mut self) -> Result<u32, SigParseError> {
        if self.pos + 4 > self.data.len() {
            return Err(SigParseError::Truncated);
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    /// Read a 16-bit little-endian unsigned integer.
    ///
    /// # Errors
    ///
    /// Returns `Err` if fewer than 2 bytes remain.
    pub fn read_u16_le(&mut self) -> Result<u16, SigParseError> {
        if self.pos + 2 > self.data.len() {
            return Err(SigParseError::Truncated);
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Read a 32-bit little-endian unsigned integer.
    ///
    /// # Errors
    ///
    /// Returns `Err` if fewer than 4 bytes remain.
    pub fn read_u32_le(&mut self) -> Result<u32, SigParseError> {
        if self.pos + 4 > self.data.len() {
            return Err(SigParseError::Truncated);
        }
        let v = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    /// Read a NUL-terminated C string.
    ///
    /// Stops at the first `\0` byte or end of data.
    pub fn read_cstr(&mut self) -> String {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        let s = String::from_utf8_lossy(&self.data[start..self.pos]).to_string();
        if self.pos < self.data.len() {
            self.pos += 1; // skip the NUL
        }
        s
    }

    /// Read exactly `n` bytes into a `Vec<u8>`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if fewer than `n` bytes remain.
    pub fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, SigParseError> {
        if self.pos + n > self.data.len() {
            return Err(SigParseError::Truncated);
        }
        let v = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }

    /// How many bytes remain unread.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Current read position.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Parse a complete `.sig` header.
    ///
    /// # Errors
    ///
    /// Returns [`SigParseError`] on malformed input or unsupported version.
    pub fn parse(data: Vec<u8>) -> Result<SigHeader, SigParseError> {
        const MAX_ALT_NAMES: usize = 256;
        let mut p = Self::new(data);

        // Check magic — 6 bytes "IDASGN"
        if p.remaining() < 6 {
            return Err(SigParseError::Truncated);
        }
        let magic = p.read_bytes(6)?;
        if magic.as_slice() != SIG_MAGIC {
            return Err(SigParseError::InvalidMagic);
        }

        // Version
        if p.remaining() == 0 {
            return Err(SigParseError::Truncated);
        }
        let version = p.read_u8();
        if !(SIG_VERSION_MIN..=SIG_VERSION_MAX).contains(&version) {
            return Err(SigParseError::UnsupportedVersion(version));
        }

        // CPU architecture
        if p.remaining() == 0 {
            return Err(SigParseError::Truncated);
        }
        let cpu = p.read_u8();

        // lib_flags
        if p.remaining() == 0 {
            return Err(SigParseError::Truncated);
        }
        let lib_flags = p.read_u8();

        // ctype
        if p.remaining() == 0 {
            return Err(SigParseError::Truncated);
        }
        let ctype = p.read_u8();

        // n_alt (2 bytes, little-endian in v6–v10)
        let n_alt = p.read_u16_le()?;

        // n_pats (4 bytes, little-endian)
        let n_pats = p.read_u32_le()?;

        // crc16 of header (2 bytes) — consumed but not validated here
        let _crc16 = p.read_u16_le()?;

        // ctime (4 bytes) — consumed
        let _ctime = p.read_u32_le()?;

        // v8+ has an additional cpu_name field (cstring)
        if version >= 8 {
            if p.remaining() == 0 {
                return Err(SigParseError::Truncated);
            }
            // Read and discard the cpu_name cstring
            let _cpu_name = p.read_cstr();
        }

        // Library name: max 59 bytes, NUL-terminated
        // Read up to 59 bytes then NUL
        let name = read_bounded_cstr(&mut p, 59);

        // Alternate names: n_alt of them.
        // Cap pre-allocation to avoid memory exhaustion from a crafted n_alt
        // field in an untrusted .sig file (n_alt is a u16 from attacker input).
        let mut alt_names = Vec::with_capacity((n_alt as usize).min(MAX_ALT_NAMES));
        for _ in 0..n_alt {
            if p.remaining() == 0 {
                break;
            }
            let alt = p.read_cstr();
            alt_names.push(alt);
        }

        Ok(SigHeader {
            version,
            cpu,
            lib_flags,
            ctype,
            n_alt,
            n_pats,
            name,
            alt_names,
        })
    }
}

/// Read a NUL-terminated string bounded to `max_bytes` from the parser.
fn read_bounded_cstr(p: &mut SigParser, max_bytes: usize) -> String {
    let mut buf = Vec::with_capacity(max_bytes);
    let mut count = 0;
    loop {
        if count >= max_bytes {
            break;
        }
        match p.try_read_u8() {
            None | Some(0) => break,
            Some(b) => {
                buf.push(b);
                count += 1;
            }
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

// ── Variable-bit reader ───────────────────────────────────────────────────────

/// Read a value encoded with `bits` bits from a byte slice at a byte position.
///
/// This is used for compressed FLIRT tree nodes.  The bit position advances
/// by the number of bits consumed.  The implementation reads full bytes and
/// extracts the upper `bits` bits.
///
/// Returns the decoded value.
#[must_use]
pub fn read_bit_value(data: &[u8], pos: &mut usize, bits: usize) -> u32 {
    if bits == 0 || *pos >= data.len() {
        return 0;
    }
    let bytes_needed = bits.div_ceil(8);
    let mut value: u32 = 0;
    for i in 0..bytes_needed {
        if *pos + i >= data.len() {
            *pos = data.len();
            return 0;
        }
        value = (value << 8) | u32::from(data[*pos + i]);
    }
    *pos += bytes_needed;
    // Shift right to drop any extra low bits
    let extra = bytes_needed * 8 - bits;
    value >> extra
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_header(version: u8, lib_name: &str) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(SIG_MAGIC); // 6 bytes magic
        v.push(version); // version
        v.push(0); // cpu
        v.push(0); // lib_flags
        v.push(0); // ctype
        v.extend_from_slice(&0u16.to_le_bytes()); // n_alt
        v.extend_from_slice(&42u32.to_le_bytes()); // n_pats
        v.extend_from_slice(&0u16.to_le_bytes()); // crc16
        v.extend_from_slice(&0u32.to_le_bytes()); // ctime
        // v8+ has a cpu_name cstring
        if version >= 8 {
            v.extend_from_slice(b"metapc");
            v.push(0);
        }
        // lib_name (bounded 59 bytes, NUL-terminated)
        let name_bytes = lib_name.as_bytes();
        let len = name_bytes.len().min(59);
        v.extend_from_slice(&name_bytes[..len]);
        v.push(0); // NUL terminator
        v
    }

    fn make_valid_header_v8(lib_name: &str) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(SIG_MAGIC);
        v.push(8); // v8+
        v.push(132u8); // cpu = x64
        v.push(0); // lib_flags
        v.push(0); // ctype
        v.extend_from_slice(&0u16.to_le_bytes()); // n_alt
        v.extend_from_slice(&10u32.to_le_bytes()); // n_pats
        v.extend_from_slice(&0u16.to_le_bytes()); // crc16
        v.extend_from_slice(&0u32.to_le_bytes()); // ctime
        // cpu_name cstring (v8+)
        v.extend_from_slice(b"metapc");
        v.push(0);
        // lib_name
        v.extend_from_slice(lib_name.as_bytes());
        v.push(0);
        v
    }

    // ── SigParser::parse ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_valid_v6_header() {
        let data = make_valid_header(6, "libc");
        let hdr = SigParser::parse(data).unwrap();
        assert_eq!(hdr.version, 6);
        assert_eq!(hdr.name, "libc");
        assert_eq!(hdr.n_pats, 42);
    }

    #[test]
    fn test_parse_valid_v9_header() {
        let data = make_valid_header(9, "vcrt");
        let hdr = SigParser::parse(data).unwrap();
        assert_eq!(hdr.version, 9);
        assert_eq!(hdr.name, "vcrt");
    }

    #[test]
    fn test_parse_valid_v10_header() {
        let data = make_valid_header(10, "mylib");
        let hdr = SigParser::parse(data).unwrap();
        assert_eq!(hdr.version, 10);
        assert_eq!(hdr.name, "mylib");
    }

    #[test]
    fn test_parse_v8_with_cpu_name() {
        let data = make_valid_header_v8("cryptlib");
        let hdr = SigParser::parse(data).unwrap();
        assert_eq!(hdr.version, 8);
        assert_eq!(hdr.name, "cryptlib");
        assert_eq!(hdr.cpu, 132);
    }

    #[test]
    fn test_parse_invalid_magic() {
        let mut data = make_valid_header(9, "x");
        data[0] = 0xFF;
        let r = SigParser::parse(data);
        assert_eq!(r, Err(SigParseError::InvalidMagic));
    }

    #[test]
    fn test_parse_unsupported_version_low() {
        let mut data = make_valid_header(5, "x");
        data[6] = 5; // version byte
        let r = SigParser::parse(data);
        assert_eq!(r, Err(SigParseError::UnsupportedVersion(5)));
    }

    #[test]
    fn test_parse_unsupported_version_high() {
        let mut data = make_valid_header(9, "x");
        data[6] = 11;
        let r = SigParser::parse(data);
        assert_eq!(r, Err(SigParseError::UnsupportedVersion(11)));
    }

    #[test]
    fn test_parse_truncated() {
        let data = b"IDASGN".to_vec();
        let r = SigParser::parse(data);
        assert_eq!(r, Err(SigParseError::Truncated));
    }

    #[test]
    fn test_parse_empty() {
        let r = SigParser::parse(vec![]);
        assert_eq!(r, Err(SigParseError::Truncated));
    }

    #[test]
    fn test_parse_n_pats_field() {
        let data = make_valid_header(7, "lib");
        let hdr = SigParser::parse(data).unwrap();
        assert_eq!(hdr.n_pats, 42);
    }

    #[test]
    fn test_parse_lib_name_boundary() {
        let name = "a".repeat(59);
        let data = make_valid_header(9, &name);
        let hdr = SigParser::parse(data).unwrap();
        assert_eq!(hdr.name, name);
    }

    // ── SigParser raw methods ─────────────────────────────────────────────────

    #[test]
    fn test_parser_read_u8() {
        let mut p = SigParser::new(vec![0xAB, 0xCD]);
        assert_eq!(p.read_u8(), 0xAB);
        assert_eq!(p.read_u8(), 0xCD);
    }

    #[test]
    fn test_parser_read_u16_be() {
        let mut p = SigParser::new(vec![0x01, 0x02]);
        assert_eq!(p.read_u16_be().unwrap(), 0x0102);
    }

    #[test]
    fn test_parser_read_u32_be() {
        let mut p = SigParser::new(vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(p.read_u32_be().unwrap(), 0x0102_0304);
    }

    #[test]
    fn test_parser_read_cstr() {
        let mut p = SigParser::new(b"hello\0world\0".to_vec());
        let s = p.read_cstr();
        assert_eq!(s, "hello");
        let s2 = p.read_cstr();
        assert_eq!(s2, "world");
    }

    #[test]
    fn test_parser_remaining() {
        let mut p = SigParser::new(vec![1, 2, 3]);
        assert_eq!(p.remaining(), 3);
        p.read_u8();
        assert_eq!(p.remaining(), 2);
    }

    // ── read_bit_value ────────────────────────────────────────────────────────

    #[test]
    fn test_read_bit_value_one_byte() {
        let data = [0b1111_0000u8];
        let mut pos = 0;
        let v = read_bit_value(&data, &mut pos, 4);
        assert_eq!(v, 0b1111);
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_read_bit_value_zero_bits() {
        let data = [0xFFu8];
        let mut pos = 0;
        let v = read_bit_value(&data, &mut pos, 0);
        assert_eq!(v, 0);
        assert_eq!(pos, 0);
    }

    #[test]
    fn test_read_bit_value_out_of_bounds() {
        let data: &[u8] = &[];
        let mut pos = 0;
        let v = read_bit_value(data, &mut pos, 8);
        assert_eq!(v, 0);
    }

    // ── SigParseError display ─────────────────────────────────────────────────

    #[test]
    fn test_error_display_invalid_magic() {
        assert!(!SigParseError::InvalidMagic.to_string().is_empty());
    }

    #[test]
    fn test_error_display_truncated() {
        assert!(!SigParseError::Truncated.to_string().is_empty());
    }

    #[test]
    fn test_error_display_unsupported_version() {
        let e = SigParseError::UnsupportedVersion(3);
        assert!(e.to_string().contains('3'));
    }

    #[test]
    fn test_error_display_parse_error() {
        let e = SigParseError::ParseError("bad field".to_string());
        assert!(e.to_string().contains("bad field"));
    }
}
