//! ELF section compression (`SHF_COMPRESSED`).
//!
//! When `SHF_COMPRESSED` is set in `sh_flags`, the section data begins with an
//! `Elf32_Chdr` or `Elf64_Chdr` header followed by compressed bytes.
//! Supported algorithms: `ELFCOMPRESS_ZLIB` and `ELFCOMPRESS_ZSTD`.

// ---------------------------------------------------------------------------
// ELFCOMPRESS_* constants
// ---------------------------------------------------------------------------

pub const ELFCOMPRESS_ZLIB: u32 = 1;
pub const ELFCOMPRESS_ZSTD: u32 = 2;
pub const ELFCOMPRESS_LOOS: u32 = 0x6000_0000;
pub const ELFCOMPRESS_HIOS: u32 = 0x6FFF_FFFF;
pub const ELFCOMPRESS_LOPROC: u32 = 0x7000_0000;
pub const ELFCOMPRESS_HIPROC: u32 = 0x7FFF_FFFF;

/// Human-readable name for a compression type.
#[must_use]
pub const fn compress_type_name(t: u32) -> &'static str {
    match t {
        ELFCOMPRESS_ZLIB => "ELFCOMPRESS_ZLIB",
        ELFCOMPRESS_ZSTD => "ELFCOMPRESS_ZSTD",
        _ if t >= ELFCOMPRESS_LOPROC => "LOPROC..HIPROC (arch-specific)",
        _ if t >= ELFCOMPRESS_LOOS => "LOOS..HIOS (OS-specific)",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Chdr32 / Chdr64
// ---------------------------------------------------------------------------

/// Parsed 32-bit ELF compression header (`Elf32_Chdr`), 12 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chdr32 {
    /// Compression algorithm (ELFCOMPRESS_*).
    pub ch_type: u32,
    /// Uncompressed size in bytes.
    pub ch_size: u32,
    /// Alignment of the uncompressed data.
    pub ch_addralign: u32,
}

impl Chdr32 {
    pub const SIZE: usize = 12;

    /// # Errors
    /// Returns an error if the data is too short.
    pub fn parse(data: &[u8], offset: usize, le: bool) -> Result<Self, String> {
        if offset + Self::SIZE > data.len() {
            return Err(format!("Chdr32 truncated at {offset:#x}"));
        }
        let r32 = |off: usize| -> u32 {
            let b: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0; 4]);
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        Ok(Self {
            ch_type: r32(offset),
            ch_size: r32(offset + 4),
            ch_addralign: r32(offset + 8),
        })
    }
}

/// Parsed 64-bit ELF compression header (`Elf64_Chdr`), 24 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chdr64 {
    /// Compression algorithm (ELFCOMPRESS_*).
    pub ch_type: u32,
    /// Reserved (padding to 8-byte alignment).
    pub ch_reserved: u32,
    /// Uncompressed size in bytes.
    pub ch_size: u64,
    /// Alignment of the uncompressed data.
    pub ch_addralign: u64,
}

impl Chdr64 {
    pub const SIZE: usize = 24;

    /// # Errors
    /// Returns an error if the data is too short.
    pub fn parse(data: &[u8], offset: usize, le: bool) -> Result<Self, String> {
        if offset + Self::SIZE > data.len() {
            return Err(format!("Chdr64 truncated at {offset:#x}"));
        }
        let r32 = |off: usize| -> u32 {
            let b: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0; 4]);
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let r64 = |off: usize| -> u64 {
            let b: [u8; 8] = data[off..off + 8].try_into().unwrap_or([0; 8]);
            if le {
                u64::from_le_bytes(b)
            } else {
                u64::from_be_bytes(b)
            }
        };
        Ok(Self {
            ch_type: r32(offset),
            ch_reserved: r32(offset + 4),
            ch_size: r64(offset + 8),
            ch_addralign: r64(offset + 16),
        })
    }
}

// ---------------------------------------------------------------------------
// Generic compressed section header
// ---------------------------------------------------------------------------

/// Arch-independent view of an ELF compression header.
#[derive(Debug, Clone)]
pub struct CompressedSectionHeader {
    /// Compression type (ELFCOMPRESS_*).
    pub compress_type: u32,
    /// Uncompressed data size.
    pub uncompressed_size: u64,
    /// Required alignment of uncompressed data.
    pub alignment: u64,
    /// Number of bytes occupied by the compression header in the section data.
    pub header_size: usize,
}

impl CompressedSectionHeader {
    /// Parse from a section's raw bytes, auto-detecting 32/64-bit from `is_64bit`.
    ///
    /// # Errors
    /// Returns an error if the data is too short or if the sub-header parse fails.
    pub fn parse(data: &[u8], offset: usize, is_64bit: bool, le: bool) -> Result<Self, String> {
        if is_64bit {
            let hdr = Chdr64::parse(data, offset, le)?;
            Ok(Self {
                compress_type: hdr.ch_type,
                uncompressed_size: hdr.ch_size,
                alignment: hdr.ch_addralign,
                header_size: Chdr64::SIZE,
            })
        } else {
            let hdr = Chdr32::parse(data, offset, le)?;
            Ok(Self {
                compress_type: hdr.ch_type,
                uncompressed_size: u64::from(hdr.ch_size),
                alignment: u64::from(hdr.ch_addralign),
                header_size: Chdr32::SIZE,
            })
        }
    }

    /// Type name.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        compress_type_name(self.compress_type)
    }

    /// Returns `true` for ZLIB.
    #[must_use]
    pub const fn is_zlib(&self) -> bool {
        self.compress_type == ELFCOMPRESS_ZLIB
    }

    /// Returns `true` for ZSTD.
    #[must_use]
    pub const fn is_zstd(&self) -> bool {
        self.compress_type == ELFCOMPRESS_ZSTD
    }
}

// ---------------------------------------------------------------------------
// Decompression (pure Rust, no external dependency)
// ---------------------------------------------------------------------------

/// Error type for decompression failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecompressError {
    /// The compressed data header was invalid.
    InvalidHeader(String),
    /// The algorithm is not supported.
    UnsupportedAlgorithm(u32),
    /// Decompression failed (corrupt data or truncated).
    DecompressFailed(String),
    /// The output size did not match the declared uncompressed size.
    SizeMismatch { expected: u64, actual: usize },
}

impl std::fmt::Display for DecompressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHeader(s) => write!(f, "Invalid compression header: {s}"),
            Self::UnsupportedAlgorithm(t) => {
                write!(
                    f,
                    "Unsupported compression algorithm {t} ({})",
                    compress_type_name(*t)
                )
            }
            Self::DecompressFailed(s) => write!(f, "Decompression failed: {s}"),
            Self::SizeMismatch { expected, actual } => {
                write!(f, "Size mismatch: expected {expected} bytes, got {actual}")
            }
        }
    }
}

/// Decompress ZLIB data (deflate with zlib wrapper) using a minimal pure-Rust
/// inflate implementation.
///
/// The zlib header is 2 bytes (CMF + FLG) followed by deflate-compressed data
/// and a 4-byte Adler-32 checksum.
///
/// NOTE: Full inflate is complex. This implementation handles non-compressed
/// (BTYPE=00) blocks for correctness-testing purposes. Real ZLIB-compressed
/// section data should be decompressed by a proper deflate implementation.
/// The function returns `DecompressError::DecompressFailed` for compressed
/// blocks with a descriptive message so callers can fall back gracefully.
/// # Errors
/// Returns an error if decompression fails or data is malformed.
pub fn decompress_zlib(compressed: &[u8], expected_size: u64) -> Result<Vec<u8>, DecompressError> {
    if compressed.len() < 6 {
        return Err(DecompressError::DecompressFailed(
            "ZLIB data too short".into(),
        ));
    }
    let cmf = compressed[0];
    let flg = compressed[1];

    // CMF bits [3:0] = compression method (must be 8 = deflate)
    if cmf & 0x0F != 8 {
        return Err(DecompressError::DecompressFailed(format!(
            "Unsupported ZLIB CM {}",
            cmf & 0x0F
        )));
    }

    // Check CMF*256 + FLG is divisible by 31 (header check)
    let check = u16::from(cmf) * 256 + u16::from(flg);
    if !check.is_multiple_of(31) {
        return Err(DecompressError::DecompressFailed(
            "ZLIB header checksum failed".into(),
        ));
    }

    let fdict = flg & 0x20 != 0;
    let deflate_start = if fdict { 6usize } else { 2usize };

    if deflate_start >= compressed.len() {
        return Err(DecompressError::DecompressFailed(
            "ZLIB payload empty".into(),
        ));
    }

    let payload = &compressed[deflate_start..];
    inflate_deflate(payload, expected_size)
}

/// Minimal deflate inflate supporting only stored (non-compressed) blocks.
fn inflate_deflate(data: &[u8], expected_size: u64) -> Result<Vec<u8>, DecompressError> {
    let mut output = Vec::with_capacity(expected_size.min(64 * 1024 * 1024) as usize);
    let mut bit_pos = 0usize; // bit position in data

    let read_bit = |data: &[u8], pos: usize| -> Option<u8> {
        let byte_idx = pos / 8;
        if byte_idx >= data.len() {
            return None;
        }
        Some((data[byte_idx] >> (pos % 8)) & 1)
    };

    let read_bits = |data: &[u8], pos: &mut usize, n: usize| -> Option<u32> {
        let mut val = 0u32;
        for i in 0..n {
            let b = read_bit(data, *pos + i)?;
            val |= u32::from(b) << i;
        }
        *pos += n;
        Some(val)
    };

    loop {
        let bfinal = read_bits(data, &mut bit_pos, 1)
            .ok_or_else(|| DecompressError::DecompressFailed("Truncated deflate stream".into()))?;
        let btype = read_bits(data, &mut bit_pos, 2)
            .ok_or_else(|| DecompressError::DecompressFailed("Truncated deflate stream".into()))?;

        match btype {
            0b00 => {
                // Non-compressed block
                // Align to byte boundary
                bit_pos = (bit_pos + 7) & !7;
                let byte_off = bit_pos / 8;
                if byte_off + 4 > data.len() {
                    return Err(DecompressError::DecompressFailed(
                        "Stored block header truncated".into(),
                    ));
                }
                let len_raw = u16::from_le_bytes([data[byte_off], data[byte_off + 1]]);
                let len = usize::from(len_raw);
                let nlen = u16::from_le_bytes([data[byte_off + 2], data[byte_off + 3]]);
                if len_raw ^ 0xFFFF != nlen {
                    return Err(DecompressError::DecompressFailed(
                        "Stored block NLEN check failed".into(),
                    ));
                }
                let data_start = byte_off + 4;
                let data_end = data_start + len;
                if data_end > data.len() {
                    return Err(DecompressError::DecompressFailed(
                        "Stored block data truncated".into(),
                    ));
                }
                output.extend_from_slice(&data[data_start..data_end]);
                bit_pos = data_end * 8;
            }
            0b01 | 0b10 => {
                // Fixed or dynamic Huffman — not implemented in this minimal version
                return Err(DecompressError::DecompressFailed(format!(
                    "Compressed deflate blocks (BTYPE={btype}) require a full inflate implementation"
                )));
            }
            _ => {
                return Err(DecompressError::DecompressFailed(
                    "Invalid BTYPE=11 in deflate stream".into(),
                ));
            }
        }

        if bfinal == 1 {
            break;
        }
    }

    if output.len() as u64 != expected_size {
        return Err(DecompressError::SizeMismatch {
            expected: expected_size,
            actual: output.len(),
        });
    }
    Ok(output)
}

/// Attempt to decompress a compressed ELF section's data.
///
/// `section_data` — the full section bytes (starting with Chdr).
/// `is_64bit` — whether to parse a 64-bit Chdr.
/// `le` — little-endian.
///
/// # Errors
/// Returns an error if the section header cannot be parsed or decompression fails.
pub fn decompress_section(
    section_data: &[u8],
    is_64bit: bool,
    le: bool,
) -> Result<Vec<u8>, DecompressError> {
    let hdr = CompressedSectionHeader::parse(section_data, 0, is_64bit, le)
        .map_err(DecompressError::InvalidHeader)?;

    let payload = &section_data[hdr.header_size..];

    match hdr.compress_type {
        ELFCOMPRESS_ZLIB => decompress_zlib(payload, hdr.uncompressed_size),
        ELFCOMPRESS_ZSTD => Err(DecompressError::UnsupportedAlgorithm(ELFCOMPRESS_ZSTD)),
        t => Err(DecompressError::UnsupportedAlgorithm(t)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_chdr32(ch_type: u32, ch_size: u32, align: u32) -> Vec<u8> {
        let mut b = vec![0u8; 12];
        b[0..4].copy_from_slice(&ch_type.to_le_bytes());
        b[4..8].copy_from_slice(&ch_size.to_le_bytes());
        b[8..12].copy_from_slice(&align.to_le_bytes());
        b
    }

    fn make_chdr64(ch_type: u32, ch_size: u64, align: u64) -> Vec<u8> {
        let mut b = vec![0u8; 24];
        b[0..4].copy_from_slice(&ch_type.to_le_bytes());
        b[4..8].copy_from_slice(&0u32.to_le_bytes()); // reserved
        b[8..16].copy_from_slice(&ch_size.to_le_bytes());
        b[16..24].copy_from_slice(&align.to_le_bytes());
        b
    }

    #[test]
    fn test_chdr32_parse() {
        let b = make_chdr32(ELFCOMPRESS_ZLIB, 0x1000, 8);
        let hdr = Chdr32::parse(&b, 0, true).unwrap();
        assert_eq!(hdr.ch_type, ELFCOMPRESS_ZLIB);
        assert_eq!(hdr.ch_size, 0x1000);
    }

    #[test]
    fn test_chdr64_parse() {
        let b = make_chdr64(ELFCOMPRESS_ZSTD, 0x20000, 16);
        let hdr = Chdr64::parse(&b, 0, true).unwrap();
        assert_eq!(hdr.ch_type, ELFCOMPRESS_ZSTD);
        assert_eq!(hdr.ch_size, 0x20000);
    }

    #[test]
    fn test_chdr32_truncated() {
        assert!(Chdr32::parse(&[0u8; 4], 0, true).is_err());
    }

    #[test]
    fn test_chdr64_truncated() {
        assert!(Chdr64::parse(&[0u8; 8], 0, true).is_err());
    }

    #[test]
    fn test_compressed_header_32bit() {
        let b = make_chdr32(ELFCOMPRESS_ZLIB, 0x400, 4);
        let hdr = CompressedSectionHeader::parse(&b, 0, false, true).unwrap();
        assert!(hdr.is_zlib());
        assert!(!hdr.is_zstd());
        assert_eq!(hdr.uncompressed_size, 0x400);
        assert_eq!(hdr.header_size, 12);
    }

    #[test]
    fn test_compressed_header_64bit() {
        let b = make_chdr64(ELFCOMPRESS_ZSTD, 0x8000, 8);
        let hdr = CompressedSectionHeader::parse(&b, 0, true, true).unwrap();
        assert!(hdr.is_zstd());
        assert_eq!(hdr.uncompressed_size, 0x8000);
        assert_eq!(hdr.header_size, 24);
    }

    #[test]
    fn test_compress_type_name() {
        assert_eq!(compress_type_name(ELFCOMPRESS_ZLIB), "ELFCOMPRESS_ZLIB");
        assert_eq!(compress_type_name(ELFCOMPRESS_ZSTD), "ELFCOMPRESS_ZSTD");
        assert_eq!(
            compress_type_name(0x7000_0001),
            "LOPROC..HIPROC (arch-specific)"
        );
        assert_eq!(compress_type_name(99), "Unknown");
    }

    #[test]
    fn test_decompress_zlib_stored_block() {
        // Build a minimal ZLIB stream wrapping a stored deflate block
        let payload = b"Hello, ELF!";
        let len = payload.len() as u16;
        let nlen = !len;

        let mut deflate = Vec::new();
        deflate.push(0b0000_0001u8); // BFINAL=1, BTYPE=00 (stored)
        deflate.extend_from_slice(&len.to_le_bytes());
        deflate.extend_from_slice(&nlen.to_le_bytes());
        deflate.extend_from_slice(payload);

        // ZLIB wrapper: CMF=0x78 (method=8, window=7), FLG must make CMF*256+FLG.is_multiple_of(31)
        let cmf: u8 = 0x78;
        // 0x78 * 256 = 0x7800 = 30720. 30720 % 31 = 1 so we need FLG = 30
        let flg: u8 = 0x9C; // 0x789C is the common "best compression" header, 0x789C % 31 = 0
        let mut zlib = vec![cmf, flg];
        zlib.extend_from_slice(&deflate);
        // Append Adler-32 (not validated in our implementation)
        zlib.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

        let result = decompress_zlib(&zlib, payload.len() as u64);
        assert_eq!(result.unwrap(), payload);
    }

    #[test]
    fn test_decompress_zlib_compressed_returns_error() {
        // A real ZLIB-compressed stream will have BTYPE=01 or 10 which we don't support
        let cmf: u8 = 0x78;
        let flg: u8 = 0x9C;
        // Simulate BFINAL=1, BTYPE=01 (fixed Huffman)
        let deflate = vec![0b0000_0011u8]; // BFINAL=1, BTYPE=01
        let mut zlib = vec![cmf, flg];
        zlib.extend_from_slice(&deflate);
        zlib.extend_from_slice(&[0, 0, 0, 1]);

        let result = decompress_zlib(&zlib, 100);
        assert!(result.is_err());
        // Should be DecompressFailed (compressed block not implemented)
        assert!(matches!(
            result.unwrap_err(),
            DecompressError::DecompressFailed(_)
        ));
    }

    #[test]
    fn test_decompress_section_zstd_unsupported() {
        let mut buf = make_chdr32(ELFCOMPRESS_ZSTD, 100, 1);
        buf.extend_from_slice(&[0u8; 20]);
        let result = decompress_section(&buf, false, true);
        assert!(matches!(
            result.unwrap_err(),
            DecompressError::UnsupportedAlgorithm(ELFCOMPRESS_ZSTD)
        ));
    }

    #[test]
    fn test_decompress_error_display() {
        let e = DecompressError::UnsupportedAlgorithm(ELFCOMPRESS_ZSTD);
        let s = format!("{e}");
        assert!(s.contains("ELFCOMPRESS_ZSTD"));

        let e2 = DecompressError::SizeMismatch {
            expected: 100,
            actual: 50,
        };
        let s2 = format!("{e2}");
        assert!(s2.contains("100") && s2.contains("50"));
    }
}
