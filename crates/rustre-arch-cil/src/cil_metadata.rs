//! CLI metadata reader for ECMA-335 Partition II §24.
//!
//! Parses the `MetadataRoot` structure and its stream headers from the
//! `#~` / `#Strings` / `#GUID` / `#Blob` / `#US` heap region embedded
//! in a .NET PE image.

// ── MetadataRoot ──────────────────────────────────────────────────────────────

/// Error type for metadata parsing failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataError {
    /// The buffer is too short to contain a valid header.
    TooShort,
    /// The magic number is not "BSJB" (0x424A5342).
    BadMagic(u32),
    /// A stream header contains an out-of-range offset or size.
    InvalidStream(String),
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "metadata buffer too short"),
            Self::BadMagic(m) => write!(f, "bad metadata magic: {m:#010x} (expected 0x424a5342)"),
            Self::InvalidStream(s) => write!(f, "invalid stream: {s}"),
        }
    }
}

impl std::error::Error for MetadataError {}

/// Expected magic bytes for a CLI metadata root: "BSJB".
pub const METADATA_MAGIC: u32 = 0x424A_5342;

/// The CLI metadata root header (ECMA-335 §II.24.2.1).
#[derive(Debug, Clone)]
pub struct MetadataRoot {
    /// Magic signature (must equal [`METADATA_MAGIC`]).
    pub magic: u32,
    /// Major version (currently 1).
    pub major_version: u16,
    /// Minor version (currently 1).
    pub minor_version: u16,
    /// Reserved — always 0.
    pub reserved: u32,
    /// Version string (UTF-8, padded to 4-byte boundary).
    pub version: String,
    /// Flags (always 0 in ECMA-335).
    pub flags: u16,
    /// Number of stream headers that follow.
    pub streams: u16,
}

impl MetadataRoot {
    /// Parse the metadata root from `data` (starting at the magic bytes).
    ///
    /// # Errors
    /// Returns [`MetadataError::TooShort`] or [`MetadataError::BadMagic`].
    pub fn parse(data: &[u8]) -> Result<(Self, usize), MetadataError> {
        if data.len() < 16 {
            return Err(MetadataError::TooShort);
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic != METADATA_MAGIC {
            return Err(MetadataError::BadMagic(magic));
        }
        let major_version = u16::from_le_bytes(data[4..6].try_into().unwrap());
        let minor_version = u16::from_le_bytes(data[6..8].try_into().unwrap());
        let reserved = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let version_len = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
        // version_len is the length including null padding (rounded up to 4 bytes)
        let version_end = 16usize.checked_add(version_len).ok_or(MetadataError::TooShort)?;
        if data.len() < version_end.checked_add(4).ok_or(MetadataError::TooShort)? {
            return Err(MetadataError::TooShort);
        }
        let version_bytes = &data[16..version_end];
        let nul_pos = version_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(version_bytes.len());
        let version = String::from_utf8_lossy(&version_bytes[..nul_pos]).into_owned();

        let flags = u16::from_le_bytes(data[version_end..version_end + 2].try_into().unwrap());
        let streams =
            u16::from_le_bytes(data[version_end + 2..version_end + 4].try_into().unwrap());

        let consumed = version_end + 4;
        Ok((
            Self {
                magic,
                major_version,
                minor_version,
                reserved,
                version,
                flags,
                streams,
            },
            consumed,
        ))
    }

    /// Return `true` if this is a valid CLI metadata magic.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.magic == METADATA_MAGIC
    }
}

// ── StreamHeader ──────────────────────────────────────────────────────────────

/// A single CLI metadata stream header (ECMA-335 §II.24.2.2).
#[derive(Debug, Clone)]
pub struct StreamHeader {
    /// Byte offset of the stream data from the start of the `MetadataRoot`.
    pub offset: u32,
    /// Byte size of the stream data.
    pub size: u32,
    /// Stream name (e.g., `"#~"`, `"#Strings"`, `"#Blob"`, `"#GUID"`, `"#US"`).
    pub name: String,
}

impl StreamHeader {
    /// Parse one stream header from `data`, returning it and the number of bytes consumed.
    ///
    /// # Errors
    /// Returns [`MetadataError::TooShort`] or [`MetadataError::InvalidStream`].
    pub fn parse(data: &[u8]) -> Result<(Self, usize), MetadataError> {
        if data.len() < 9 {
            // minimum: 4 (offset) + 4 (size) + 1 (name byte + NUL)
            return Err(MetadataError::TooShort);
        }
        let offset = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let size = u32::from_le_bytes(data[4..8].try_into().unwrap());
        // Name is NUL-terminated, padded to 4-byte boundary.
        let name_start = 8;
        let remaining = &data[name_start..];
        let nul = remaining.iter().position(|&b| b == 0).ok_or_else(|| {
            MetadataError::InvalidStream("stream name not NUL-terminated".to_string())
        })?;
        let name = String::from_utf8_lossy(&remaining[..nul]).into_owned();
        // Include NUL and pad to 4-byte boundary
        let raw_name_len = nul + 1;
        let padded = (raw_name_len + 3) & !3;
        let consumed = name_start + padded;
        if data.len() < consumed {
            return Err(MetadataError::TooShort);
        }
        Ok((Self { offset, size, name }, consumed))
    }
}

// ── CilMetadataReader ─────────────────────────────────────────────────────────

/// Reads and exposes the CLI metadata headers from a raw byte buffer.
pub struct CilMetadataReader {
    /// Parsed metadata root.
    pub root: MetadataRoot,
    /// All stream headers, in declaration order.
    pub stream_headers: Vec<StreamHeader>,
    /// The raw buffer (kept for slice operations).
    raw: Vec<u8>,
}

impl CilMetadataReader {
    /// Parse the full metadata section from `data`.
    ///
    /// `data` must begin at the `BSJB` magic bytes.
    ///
    /// # Errors
    /// Propagates any [`MetadataError`] from sub-parsers.
    pub fn parse(data: Vec<u8>) -> Result<Self, MetadataError> {
        let (root, mut off) = MetadataRoot::parse(&data)?;
        let n = root.streams as usize;
        // Cap allocation: each stream header is at least 9 bytes (4+4+1 NUL-terminated name).
        // An attacker-controlled streams count up to 65535 would allocate ~4 MB of pointers;
        // cap to a realistic maximum to prevent DoS via memory exhaustion.
        const MAX_STREAMS: usize = 256;
        let capacity = n.min(MAX_STREAMS);
        let mut stream_headers = Vec::with_capacity(capacity);
        for _ in 0..n {
            let slice = data.get(off..).ok_or(MetadataError::TooShort)?;
            let (hdr, consumed) = StreamHeader::parse(slice)?;
            off += consumed;
            stream_headers.push(hdr);
        }
        Ok(Self {
            root,
            stream_headers,
            raw: data,
        })
    }

    /// List all stream names in this metadata section.
    #[must_use]
    pub fn stream_names(&self) -> Vec<&str> {
        self.stream_headers
            .iter()
            .map(|h| h.name.as_str())
            .collect()
    }

    /// Find a stream header by name (e.g., `"#~"`).
    #[must_use]
    pub fn find_stream(&self, name: &str) -> Option<&StreamHeader> {
        self.stream_headers.iter().find(|h| h.name == name)
    }

    /// Return the raw bytes of a named stream, or `None` if not found / out of bounds.
    #[must_use]
    pub fn stream_data(&self, name: &str) -> Option<&[u8]> {
        let hdr = self.find_stream(name)?;
        let start = hdr.offset as usize;
        let end = start.checked_add(hdr.size as usize)?;
        self.raw.get(start..end)
    }

    /// Return the metadata version string (e.g., `"v4.0.30319"`).
    #[must_use]
    pub fn version_string(&self) -> &str {
        &self.root.version
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_metadata_root(version: &str, stream_count: u16) -> Vec<u8> {
        let version_bytes = version.as_bytes();
        // Round up to 4-byte boundary
        let padded_len = (version_bytes.len() + 1 + 3) & !3;
        let mut buf = Vec::new();
        buf.extend_from_slice(&METADATA_MAGIC.to_le_bytes()); // magic
        buf.extend_from_slice(&1u16.to_le_bytes()); // major
        buf.extend_from_slice(&1u16.to_le_bytes()); // minor
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
        buf.extend_from_slice(&u32::try_from(padded_len).expect("version string fits in u32").to_le_bytes()); // version_len
        let mut vbytes = version_bytes.to_vec();
        vbytes.resize(padded_len, 0);
        buf.extend_from_slice(&vbytes);
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&stream_count.to_le_bytes()); // streams
        buf
    }

    fn make_stream_header(offset: u32, size: u32, name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&offset.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        let name_bytes = name.as_bytes();
        let raw_len = name_bytes.len() + 1; // NUL
        let padded = (raw_len + 3) & !3;
        let mut name_buf = name_bytes.to_vec();
        name_buf.push(0);
        name_buf.resize(padded, 0);
        buf.extend_from_slice(&name_buf);
        buf
    }

    #[test]
    fn test_metadata_root_bad_magic() {
        let bad = [
            0xFFu8, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, b'v', b'4', 0, 0, 0, 0,
            0, 1,
        ];
        let err = MetadataRoot::parse(&bad).unwrap_err();
        assert!(matches!(err, MetadataError::BadMagic(_)));
    }

    #[test]
    fn test_metadata_root_too_short() {
        let err = MetadataRoot::parse(&[0x42, 0x4A]).unwrap_err();
        assert_eq!(err, MetadataError::TooShort);
    }

    #[test]
    fn test_metadata_root_parses_version() {
        let buf = make_metadata_root("v4.0.30319", 0);
        let (root, _) = MetadataRoot::parse(&buf).unwrap();
        assert_eq!(root.magic, METADATA_MAGIC);
        assert!(root.is_valid());
        assert_eq!(root.version, "v4.0.30319");
        assert_eq!(root.streams, 0);
    }

    #[test]
    fn test_stream_header_parse() {
        let hdr_bytes = make_stream_header(0x100, 0x200, "#~");
        let (hdr, _consumed) = StreamHeader::parse(&hdr_bytes).unwrap();
        assert_eq!(hdr.offset, 0x100);
        assert_eq!(hdr.size, 0x200);
        assert_eq!(hdr.name, "#~");
    }

    #[test]
    fn test_reader_stream_names() {
        let mut buf = make_metadata_root("v4.0.30319", 2);
        buf.extend_from_slice(&make_stream_header(0x200, 0x100, "#~"));
        buf.extend_from_slice(&make_stream_header(0x300, 0x50, "#Strings"));
        // Append some dummy data so stream_data won't OOB
        buf.resize(0x400, 0u8);

        let reader = CilMetadataReader::parse(buf).unwrap();
        let names = reader.stream_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"#~"));
        assert!(names.contains(&"#Strings"));
    }
}
