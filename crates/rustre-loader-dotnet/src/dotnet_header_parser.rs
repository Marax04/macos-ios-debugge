//! Parse .NET PE headers: CLI header, metadata root, and stream headers.
//!
//! This module provides focused, self-contained parsing of the low-level
//! binary structures that precede the ECMA-335 metadata tables.  It does
//! not depend on the high-level [`DotnetLoader`] or [`MetadataTables`] types
//! so it can be used as a lightweight diagnostic tool.
//!
//! # Design note — relation to `pe_clr_header`
//! [`pe_clr_header`] adds serde-serialisable types, typed `ClrFlags` accessors,
//! and richer sub-structure for the stream headers.  This module (`dotnet_header_parser`)
//! is the **dependency-free** alternative — its own `ParseError` type avoids
//! pulling in `DotnetLoaderError` and serde.  Keep both modules: they serve
//! different abstraction levels.

use std::fmt;

// ── ParseError ────────────────────────────────────────────────────────────────

/// Error type for header parsing failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The provided byte slice was too short to parse the expected structure.
    TooShort { expected: usize, actual: usize },
    /// Magic / signature bytes did not match.
    BadMagic { expected: &'static str, found: String },
    /// A numeric field contained an unexpected value.
    InvalidField { field: &'static str, value: u64 },
    /// A string field was not valid UTF-8.
    InvalidString(String),
    /// An RVA could not be resolved against any section.
    UnresolvableRva(u32),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { expected, actual } => {
                write!(f, "buffer too short: expected {expected} bytes, got {actual}")
            }
            Self::BadMagic { expected, found } => {
                write!(f, "bad magic: expected {expected}, found {found}")
            }
            Self::InvalidField { field, value } => {
                write!(f, "invalid field '{field}': {value:#x}")
            }
            Self::InvalidString(s) => write!(f, "invalid string: {s}"),
            Self::UnresolvableRva(rva) => write!(f, "unresolvable RVA {rva:#010x}"),
        }
    }
}

impl std::error::Error for ParseError {}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn rd16(data: &[u8], off: usize) -> Result<u16, ParseError> {
    if off + 2 > data.len() {
        return Err(ParseError::TooShort {
            expected: off + 2,
            actual: data.len(),
        });
    }
    Ok(u16::from_le_bytes([data[off], data[off + 1]]))
}

fn rd32(data: &[u8], off: usize) -> Result<u32, ParseError> {
    if off + 4 > data.len() {
        return Err(ParseError::TooShort {
            expected: off + 4,
            actual: data.len(),
        });
    }
    Ok(u32::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
}

/// Read a little-endian `u64` at `off`.
///
/// # Errors
/// Returns [`ParseError::TooShort`] if `off + 8 > data.len()`.
pub fn rd64(data: &[u8], off: usize) -> Result<u64, ParseError> {
    if off + 8 > data.len() {
        return Err(ParseError::TooShort {
            expected: off + 8,
            actual: data.len(),
        });
    }
    Ok(u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ]))
}

/// Read a NUL-terminated C string from `data` starting at `off`.
///
/// # Errors
/// Returns [`ParseError::TooShort`] if `off` is past the end of `data`.
pub fn read_cstr_at(data: &[u8], off: usize) -> Result<String, ParseError> {
    if off >= data.len() {
        return Err(ParseError::TooShort {
            expected: off + 1,
            actual: data.len(),
        });
    }
    let slice = &data[off..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    std::str::from_utf8(&slice[..end])
        .map(std::borrow::ToOwned::to_owned)
        .map_err(|e| ParseError::InvalidString(e.to_string()))
}

// ── SectionEntry ──────────────────────────────────────────────────────────────

/// A PE section header entry (used for RVA resolution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionEntry {
    /// Section name (up to 8 bytes).
    pub name: String,
    /// Virtual size.
    pub virtual_size: u32,
    /// Virtual address (RVA).
    pub virtual_address: u32,
    /// Raw data size on disk.
    pub raw_size: u32,
    /// Raw data file offset.
    pub raw_offset: u32,
    /// Section characteristics.
    pub characteristics: u32,
}

impl SectionEntry {
    /// Parse one section header from `data` at `off`.
    pub fn parse(data: &[u8], off: usize) -> Result<Self, ParseError> {
        if off + 40 > data.len() {
            return Err(ParseError::TooShort {
                expected: off + 40,
                actual: data.len(),
            });
        }
        let name_bytes = &data[off..off + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
        Ok(Self {
            name,
            virtual_size: rd32(data, off + 8)?,
            virtual_address: rd32(data, off + 12)?,
            raw_size: rd32(data, off + 16)?,
            raw_offset: rd32(data, off + 20)?,
            characteristics: rd32(data, off + 36)?,
        })
    }

    /// Translate `rva` to a file offset, or `None` if outside this section.
    #[must_use]
    pub const fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        if rva >= self.virtual_address
            && rva < self.virtual_address.saturating_add(self.virtual_size)
        {
            let delta = rva - self.virtual_address;
            Some(self.raw_offset as usize + delta as usize)
        } else {
            None
        }
    }

    /// Returns `true` when the section is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }
}

impl fmt::Display for SectionEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} va={:#010x} vs={:#x} raw_off={:#010x}",
            self.name, self.virtual_address, self.virtual_size, self.raw_offset
        )
    }
}

// ── CliHeader ─────────────────────────────────────────────────────────────────

/// Parsed `IMAGE_COR20_HEADER` (CLI header).
///
/// Spec: ECMA-335 §II.25.3.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliHeader {
    /// `cb` — size of this header in bytes.
    pub header_size: u32,
    /// CLR major runtime version.
    pub major_runtime_version: u16,
    /// CLR minor runtime version.
    pub minor_runtime_version: u16,
    /// RVA of the metadata root.
    pub metadata_rva: u32,
    /// Size of the metadata.
    pub metadata_size: u32,
    /// `Flags` field (`CorFlags`).
    pub flags: u32,
    /// Entry-point token (or RVA for native entry points).
    pub entry_point_token: u32,
    /// RVA of the managed-resources blob.
    pub resources_rva: u32,
    /// Size of the managed-resources blob.
    pub resources_size: u32,
    /// RVA of the strong-name hash blob.
    pub strong_name_rva: u32,
    /// Size of the strong-name hash blob.
    pub strong_name_size: u32,
    /// RVA of the `CodeManagerTable` directory.
    pub code_manager_rva: u32,
    /// Size of the `CodeManagerTable` directory.
    pub code_manager_size: u32,
    /// RVA of the `VTableFixups` directory.
    pub vtable_fixups_rva: u32,
    /// Size of the `VTableFixups` directory.
    pub vtable_fixups_size: u32,
    /// RVA of the export address table jumps.
    pub export_address_table_jumps_rva: u32,
    /// Size of the export address table jumps.
    pub export_address_table_jumps_size: u32,
}

impl CliHeader {
    /// Minimum valid CLI header size.
    pub const MIN_SIZE: usize = 28;

    /// Parse a `CliHeader` from `data`.
    ///
    /// # Errors
    ///
    /// Returns `ParseError::TooShort` when `data` is smaller than
    /// [`CliHeader::MIN_SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < Self::MIN_SIZE {
            return Err(ParseError::TooShort {
                expected: Self::MIN_SIZE,
                actual: data.len(),
            });
        }
        let header_size = rd32(data, 0)?;
        let major_runtime_version = rd16(data, 4)?;
        let minor_runtime_version = rd16(data, 6)?;
        let metadata_rva = rd32(data, 8)?;
        let metadata_size = rd32(data, 12)?;
        let flags = rd32(data, 16)?;
        let entry_point_token = rd32(data, 20)?;
        // Optional fields — present only when header is large enough.
        // IMAGE_COR20_HEADER directory order: Resources 24, StrongNameSignature
        // 32, CodeManagerTable 40, VTableFixups 48, ExportAddressTableJumps 56.
        // These offsets previously started one directory too early, so
        // strong_name held Resources and vtable_fixups held the signature.
        let resources_rva = if data.len() >= 28 { rd32(data, 24)? } else { 0 };
        let resources_size = if data.len() >= 32 { rd32(data, 28)? } else { 0 };
        let strong_name_rva = if data.len() >= 36 { rd32(data, 32)? } else { 0 };
        let strong_name_size = if data.len() >= 40 { rd32(data, 36)? } else { 0 };
        let code_manager_rva = if data.len() >= 44 { rd32(data, 40)? } else { 0 };
        let code_manager_size = if data.len() >= 48 { rd32(data, 44)? } else { 0 };
        let vtable_fixups_rva = if data.len() >= 52 { rd32(data, 48)? } else { 0 };
        let vtable_fixups_size = if data.len() >= 56 { rd32(data, 52)? } else { 0 };
        let export_address_table_jumps_rva = if data.len() >= 60 { rd32(data, 56)? } else { 0 };
        let export_address_table_jumps_size = if data.len() >= 64 { rd32(data, 60)? } else { 0 };
        Ok(Self {
            header_size,
            major_runtime_version,
            minor_runtime_version,
            metadata_rva,
            metadata_size,
            flags,
            entry_point_token,
            resources_rva,
            resources_size,
            strong_name_rva,
            strong_name_size,
            code_manager_rva,
            code_manager_size,
            vtable_fixups_rva,
            vtable_fixups_size,
            export_address_table_jumps_rva,
            export_address_table_jumps_size,
        })
    }

    /// Returns `true` when the `IL_ONLY` flag is set.
    #[must_use]
    pub const fn is_il_only(&self) -> bool {
        self.flags & 0x0000_0001 != 0
    }

    /// Returns `true` when a 32-bit process is required.
    #[must_use]
    pub const fn requires_32bit(&self) -> bool {
        self.flags & 0x0000_0002 != 0
    }

    /// Returns `true` when a strong-name signature is present.
    #[must_use]
    pub const fn has_strong_name(&self) -> bool {
        self.strong_name_rva != 0 && self.strong_name_size != 0
    }

    /// Returns `true` when `VTable` fixups are present.
    #[must_use]
    pub const fn has_vtable_fixups(&self) -> bool {
        self.vtable_fixups_rva != 0 && self.vtable_fixups_size != 0
    }

    /// Returns the runtime version string, e.g. `"4.0"`.
    #[must_use]
    pub fn runtime_version(&self) -> String {
        format!("{}.{}", self.major_runtime_version, self.minor_runtime_version)
    }
}

impl fmt::Display for CliHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CliHeader {{ rt={} metadata_rva={:#010x} size={} flags={:#010x} }}",
            self.runtime_version(),
            self.metadata_rva,
            self.metadata_size,
            self.flags,
        )
    }
}

// ── StreamHeader ──────────────────────────────────────────────────────────────

/// A metadata stream header entry (from the metadata root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHeader {
    /// Offset of stream data relative to the metadata root.
    pub offset: u32,
    /// Size of the stream data in bytes.
    pub size: u32,
    /// Null-terminated, 4-byte-aligned name (e.g. `"#~"`, `"#Strings"`).
    pub name: String,
    /// Byte length of the raw name field (including padding).
    pub name_raw_len: usize,
}

impl StreamHeader {
    /// Parse one stream header from `data` at `pos`, advancing `pos` past it.
    pub fn parse(data: &[u8], pos: &mut usize) -> Result<Self, ParseError> {
        let off_start = *pos;
        if off_start + 8 > data.len() {
            return Err(ParseError::TooShort {
                expected: off_start + 8,
                actual: data.len(),
            });
        }
        let offset = rd32(data, *pos)?;
        *pos += 4;
        let size = rd32(data, *pos)?;
        *pos += 4;

        // Name: null-terminated, padded to 4-byte alignment.
        let name_start = *pos;
        let mut name_end = name_start;
        while name_end < data.len() && data[name_end] != 0 {
            name_end += 1;
        }
        let raw_name = &data[name_start..name_end];
        let name = std::str::from_utf8(raw_name)
            .map(std::borrow::ToOwned::to_owned)
            .map_err(|e| ParseError::InvalidString(e.to_string()))?;
        let raw_len = name_end - name_start + 1; // +1 for NUL
        let padded = (raw_len + 3) & !3;
        *pos += padded;

        Ok(Self {
            offset,
            size,
            name,
            name_raw_len: padded,
        })
    }
}

impl fmt::Display for StreamHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "stream '{}' offset={:#x} size={}",
            self.name, self.offset, self.size
        )
    }
}

// ── MetadataRoot ──────────────────────────────────────────────────────────────

/// Parsed ECMA-335 metadata root (`BSJB` signature and stream directory).
#[derive(Debug, Clone)]
pub struct MetadataRoot {
    /// Metadata signature (always `"BSJB"`).
    pub signature: [u8; 4],
    /// Metadata major version.
    pub major_version: u16,
    /// Metadata minor version.
    pub minor_version: u16,
    /// Reserved field (always 0).
    pub reserved: u32,
    /// Version string (e.g. `"v4.0.30319"`).
    pub version_string: String,
    /// `Flags` word (reserved, currently 0).
    pub flags: u16,
    /// Number of stream headers.
    pub stream_count: u16,
    /// All stream headers.
    pub streams: Vec<StreamHeader>,
    /// Byte offset within the file/blob where this metadata root begins.
    pub base_offset: usize,
}

impl MetadataRoot {
    /// BSJB magic bytes.
    pub const MAGIC: &'static [u8; 4] = b"BSJB";

    /// Parse a `MetadataRoot` from `data` starting at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `ParseError::BadMagic` when the BSJB signature is absent.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ParseError> {
        if offset + 16 > data.len() {
            return Err(ParseError::TooShort {
                expected: offset + 16,
                actual: data.len(),
            });
        }

        // Signature check.
        let sig: [u8; 4] = data[offset..offset + 4].try_into().unwrap();
        if &sig != Self::MAGIC {
            return Err(ParseError::BadMagic {
                expected: "BSJB",
                found: format!("{:02X?}", &sig),
            });
        }

        let major_version = rd16(data, offset + 4)?;
        let minor_version = rd16(data, offset + 6)?;
        let reserved = rd32(data, offset + 8)?;
        let version_len = rd32(data, offset + 12)? as usize;

        let version_start = offset + 16;
        let version_end = version_start.saturating_add(version_len);
        if version_end.saturating_add(4) > data.len() {
            return Err(ParseError::TooShort {
                expected: version_end + 4,
                actual: data.len(),
            });
        }

        // Version is zero-padded; trim the trailing NUL bytes.
        let version_bytes = &data[version_start..version_end];
        let version_string = std::str::from_utf8(version_bytes)
            .map(|s| s.trim_end_matches('\0').to_owned())
            .map_err(|e| ParseError::InvalidString(e.to_string()))?;

        let flags = rd16(data, version_end)?;
        let stream_count = rd16(data, version_end + 2)?;

        let mut pos = version_end + 4;
        let mut streams = Vec::with_capacity(stream_count as usize);
        for _ in 0..stream_count {
            let stream = StreamHeader::parse(data, &mut pos)?;
            streams.push(stream);
        }

        Ok(Self {
            signature: sig,
            major_version,
            minor_version,
            reserved,
            version_string,
            flags,
            stream_count,
            streams,
            base_offset: offset,
        })
    }

    /// Find a stream by name.
    #[must_use]
    pub fn find_stream(&self, name: &str) -> Option<&StreamHeader> {
        self.streams.iter().find(|s| s.name == name)
    }

    /// Return the absolute file offset for the given stream.
    #[must_use]
    pub const fn stream_file_offset(&self, stream: &StreamHeader) -> usize {
        self.base_offset.saturating_add(stream.offset as usize)
    }

    /// Version string formatted for display (e.g. `"v4.0"`).
    #[must_use]
    pub fn version_display(&self) -> &str {
        &self.version_string
    }
}

impl fmt::Display for MetadataRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MetadataRoot {{ version='{}' streams={} }}",
            self.version_string,
            self.streams.len()
        )
    }
}

// ── DotnetHeaderParser ────────────────────────────────────────────────────────

/// High-level parser that locates and decodes all .NET-specific PE headers.
///
/// This type wraps a raw byte slice and provides lazy-parsed access to the
/// [`CliHeader`], [`MetadataRoot`], and the list of [`StreamHeader`]s.
#[derive(Debug)]
pub struct DotnetHeaderParser<'a> {
    /// The raw PE/assembly file bytes.
    pub data: &'a [u8],
    /// Parsed PE section headers (for RVA resolution).
    pub sections: Vec<SectionEntry>,
    /// File offset of the PE signature.
    pub pe_offset: usize,
}

impl<'a> DotnetHeaderParser<'a> {
    /// Construct a parser from raw PE bytes.
    ///
    /// # Errors
    ///
    /// Returns `ParseError` if:
    /// - The file does not begin with the MZ signature.
    /// - The PE signature cannot be found.
    pub fn new(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < 64 {
            return Err(ParseError::TooShort {
                expected: 64,
                actual: data.len(),
            });
        }
        if data[0] != 0x4D || data[1] != 0x5A {
            return Err(ParseError::BadMagic {
                expected: "MZ",
                found: format!("{:02X}{:02X}", data[0], data[1]),
            });
        }
        let pe_offset = rd32(data, 60)? as usize;
        if pe_offset + 4 > data.len() {
            return Err(ParseError::TooShort {
                expected: pe_offset + 4,
                actual: data.len(),
            });
        }
        if &data[pe_offset..pe_offset + 4] != b"PE\x00\x00" {
            return Err(ParseError::BadMagic {
                expected: "PE\\x00\\x00",
                found: format!("{:02X?}", &data[pe_offset..pe_offset + 4]),
            });
        }
        let sections = Self::parse_sections(data, pe_offset)?;
        Ok(Self {
            data,
            sections,
            pe_offset,
        })
    }

    fn parse_sections(data: &[u8], pe_off: usize) -> Result<Vec<SectionEntry>, ParseError> {
        let num_secs = rd16(data, pe_off + 6)? as usize;
        let opt_size = rd16(data, pe_off + 20)? as usize;
        let sec_off = pe_off + 24 + opt_size;
        let mut secs = Vec::with_capacity(num_secs);
        for i in 0..num_secs {
            let entry = SectionEntry::parse(data, sec_off + i * 40)?;
            secs.push(entry);
        }
        Ok(secs)
    }

    /// Resolve an RVA to a file offset using the PE sections.
    ///
    /// # Errors
    ///
    /// Returns `ParseError::UnresolvableRva` when no section covers the RVA.
    pub fn rva_to_offset(&self, rva: u32) -> Result<usize, ParseError> {
        self.sections
            .iter()
            .find_map(|s| s.rva_to_offset(rva))
            .ok_or(ParseError::UnresolvableRva(rva))
    }

    /// Locate and parse the CLI header from the PE data directory entry 14.
    ///
    /// # Errors
    ///
    /// Returns `ParseError` if the CLR directory entry is absent or unreadable.
    pub fn parse_cli_header(&self) -> Result<CliHeader, ParseError> {
        let opt_off = self.pe_offset + 24;
        let magic = rd16(self.data, opt_off)?;
        let is_64bit = magic == 0x020B;
        let clr_dir_off = if is_64bit {
            opt_off + 112 + 14 * 8
        } else {
            opt_off + 96 + 14 * 8
        };
        if clr_dir_off + 8 > self.data.len() {
            return Err(ParseError::TooShort {
                expected: clr_dir_off + 8,
                actual: self.data.len(),
            });
        }
        let clr_rva = rd32(self.data, clr_dir_off)?;
        if clr_rva == 0 {
            return Err(ParseError::InvalidField {
                field: "CLR RVA",
                value: 0,
            });
        }
        let clr_off = self.rva_to_offset(clr_rva)?;
        CliHeader::parse(&self.data[clr_off..])
    }

    /// Locate and parse the metadata root using the CLI header.
    ///
    /// # Errors
    ///
    /// Returns `ParseError` if the CLI header or metadata root is malformed.
    pub fn parse_metadata_root(&self) -> Result<MetadataRoot, ParseError> {
        let cli = self.parse_cli_header()?;
        let meta_off = self.rva_to_offset(cli.metadata_rva)?;
        MetadataRoot::parse(self.data, meta_off)
    }

    /// Retrieve the raw bytes of a stream by name.
    ///
    /// # Errors
    ///
    /// Returns `ParseError` if the metadata root or stream cannot be found.
    pub fn stream_bytes(&self, name: &str) -> Result<&[u8], ParseError> {
        let root = self.parse_metadata_root()?;
        let stream = root
            .find_stream(name)
            .ok_or(ParseError::InvalidField {
                field: "stream name",
                value: 0,
            })?;
        let off = root.stream_file_offset(stream);
        let end = off + stream.size as usize;
        if end > self.data.len() {
            return Err(ParseError::TooShort {
                expected: end,
                actual: self.data.len(),
            });
        }
        Ok(&self.data[off..end])
    }

    /// Returns `true` when the file contains a non-zero CLR header RVA.
    #[must_use]
    pub fn is_dotnet(&self) -> bool {
        self.parse_cli_header().is_ok()
    }

    /// Returns `true` when the file is PE32+ (64-bit).
    #[must_use]
    pub fn is_64bit(&self) -> bool {
        rd16(self.data, self.pe_offset + 24) == Ok(0x020B)
    }

    /// Returns the list of section names.
    #[must_use]
    pub fn section_names(&self) -> Vec<&str> {
        self.sections.iter().map(|s| s.name.as_str()).collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cli_header_bytes() -> Vec<u8> {
        let mut v = vec![0u8; 72];
        v[0..4].copy_from_slice(&72u32.to_le_bytes()); // cb
        v[4..6].copy_from_slice(&2u16.to_le_bytes()); // major
        v[6..8].copy_from_slice(&5u16.to_le_bytes()); // minor
        v[8..12].copy_from_slice(&0x2000u32.to_le_bytes()); // metadata_rva
        v[12..16].copy_from_slice(&512u32.to_le_bytes()); // metadata_size
        v[16..20].copy_from_slice(&1u32.to_le_bytes()); // flags (IL_ONLY)
        v[20..24].copy_from_slice(&0u32.to_le_bytes()); // entry_point
        v
    }

    #[test]
    fn cli_header_directories_are_not_shifted() {
        // Every directory gets a distinct value, so a reader that starts one
        // directory too early reports a wrong value instead of a zero that
        // happens to match. `make_cli_header_bytes` fills only up to offset 24,
        // which is why the existing tests could not see the difference.
        let mut v = make_cli_header_bytes();
        v[24..28].copy_from_slice(&0x1100u32.to_le_bytes()); // Resources rva
        v[28..32].copy_from_slice(&11u32.to_le_bytes());
        v[32..36].copy_from_slice(&0x2200u32.to_le_bytes()); // StrongName rva
        v[36..40].copy_from_slice(&22u32.to_le_bytes());
        v[40..44].copy_from_slice(&0x3300u32.to_le_bytes()); // CodeManager rva
        v[44..48].copy_from_slice(&33u32.to_le_bytes());
        v[48..52].copy_from_slice(&0x4400u32.to_le_bytes()); // VTableFixups rva
        v[52..56].copy_from_slice(&44u32.to_le_bytes());
        v[56..60].copy_from_slice(&0x5500u32.to_le_bytes()); // EATJumps rva
        v[60..64].copy_from_slice(&55u32.to_le_bytes());

        let hdr = CliHeader::parse(&v).unwrap();
        assert_eq!(hdr.resources_rva, 0x1100);
        assert_eq!(hdr.resources_size, 11);
        assert_eq!(hdr.strong_name_rva, 0x2200);
        assert_eq!(hdr.strong_name_size, 22);
        assert_eq!(hdr.code_manager_rva, 0x3300);
        assert_eq!(hdr.code_manager_size, 33);
        assert_eq!(hdr.vtable_fixups_rva, 0x4400);
        assert_eq!(hdr.vtable_fixups_size, 44);
        assert_eq!(hdr.export_address_table_jumps_rva, 0x5500);
        assert_eq!(hdr.export_address_table_jumps_size, 55);
    }

    #[test]
    fn cli_header_resources_do_not_look_like_a_signature() {
        // Resources present, no signature: has_strong_name must stay false.
        let mut v = make_cli_header_bytes();
        v[24..28].copy_from_slice(&0x1100u32.to_le_bytes());
        v[28..32].copy_from_slice(&11u32.to_le_bytes());
        let hdr = CliHeader::parse(&v).unwrap();
        assert!(!hdr.has_strong_name());
        assert_eq!(hdr.resources_rva, 0x1100);
    }

    #[test]
    fn cli_header_parse_basic() {
        let data = make_cli_header_bytes();
        let hdr = CliHeader::parse(&data).unwrap();
        assert_eq!(hdr.major_runtime_version, 2);
        assert_eq!(hdr.minor_runtime_version, 5);
        assert_eq!(hdr.metadata_rva, 0x2000);
        assert_eq!(hdr.metadata_size, 512);
        assert!(hdr.is_il_only());
    }

    #[test]
    fn cli_header_too_short() {
        let err = CliHeader::parse(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ParseError::TooShort { .. }));
    }

    #[test]
    fn cli_header_runtime_version() {
        let data = make_cli_header_bytes();
        let hdr = CliHeader::parse(&data).unwrap();
        assert_eq!(hdr.runtime_version(), "2.5");
    }

    #[test]
    fn cli_header_requires_32bit() {
        let mut data = make_cli_header_bytes();
        data[16..20].copy_from_slice(&2u32.to_le_bytes());
        let hdr = CliHeader::parse(&data).unwrap();
        assert!(hdr.requires_32bit());
    }

    #[test]
    fn cli_header_has_strong_name_false_by_default() {
        let data = make_cli_header_bytes();
        let hdr = CliHeader::parse(&data).unwrap();
        assert!(!hdr.has_strong_name());
    }

    #[test]
    fn cli_header_display() {
        let data = make_cli_header_bytes();
        let hdr = CliHeader::parse(&data).unwrap();
        let s = format!("{hdr}");
        assert!(s.contains("CliHeader"));
    }

    #[test]
    fn metadata_root_bad_magic() {
        let data = vec![0u8; 64];
        let err = MetadataRoot::parse(&data, 0).unwrap_err();
        assert!(matches!(err, ParseError::BadMagic { .. }));
    }

    fn make_metadata_root_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"BSJB"); // signature
        v.extend_from_slice(&1u16.to_le_bytes()); // major
        v.extend_from_slice(&1u16.to_le_bytes()); // minor
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved
        let version = b"v4.0.30319\0\0"; // 12 bytes, 4-byte aligned
        v.extend_from_slice(&(version.len() as u32).to_le_bytes()); // version_len
        v.extend_from_slice(version);
        v.extend_from_slice(&0u16.to_le_bytes()); // flags
        v.extend_from_slice(&0u16.to_le_bytes()); // stream_count = 0
        v
    }

    #[test]
    fn metadata_root_parse_basic() {
        let data = make_metadata_root_bytes();
        let root = MetadataRoot::parse(&data, 0).unwrap();
        assert_eq!(root.major_version, 1);
        assert_eq!(root.stream_count, 0);
        assert!(root.version_string.starts_with("v4.0"));
    }

    #[test]
    fn metadata_root_find_stream_none() {
        let data = make_metadata_root_bytes();
        let root = MetadataRoot::parse(&data, 0).unwrap();
        assert!(root.find_stream("#~").is_none());
    }

    #[test]
    fn metadata_root_display() {
        let data = make_metadata_root_bytes();
        let root = MetadataRoot::parse(&data, 0).unwrap();
        let s = format!("{root}");
        assert!(s.contains("MetadataRoot"));
    }

    #[test]
    fn section_entry_parse() {
        let mut data = vec![0u8; 40];
        let name = b".text\0\0\0";
        data[..8].copy_from_slice(name);
        data[8..12].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual_size
        data[12..16].copy_from_slice(&0x2000u32.to_le_bytes()); // virtual_address
        data[16..20].copy_from_slice(&0x0200u32.to_le_bytes()); // raw_size
        data[20..24].copy_from_slice(&0x0400u32.to_le_bytes()); // raw_offset
        data[36..40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // exec | code
        let sec = SectionEntry::parse(&data, 0).unwrap();
        assert_eq!(sec.name, ".text");
        assert_eq!(sec.virtual_address, 0x2000);
        assert!(sec.is_executable());
    }

    #[test]
    fn section_rva_to_offset_in_range() {
        let sec = SectionEntry {
            name: ".text".into(),
            virtual_size: 0x1000,
            virtual_address: 0x2000,
            raw_size: 0x1000,
            raw_offset: 0x0400,
            characteristics: 0,
        };
        assert_eq!(sec.rva_to_offset(0x2100), Some(0x0500));
    }

    #[test]
    fn section_rva_to_offset_out_of_range() {
        let sec = SectionEntry {
            name: ".text".into(),
            virtual_size: 0x1000,
            virtual_address: 0x2000,
            raw_size: 0x1000,
            raw_offset: 0x0400,
            characteristics: 0,
        };
        assert!(sec.rva_to_offset(0x1000).is_none());
    }

    #[test]
    fn parse_error_display() {
        let e = ParseError::TooShort { expected: 10, actual: 4 };
        assert!(e.to_string().contains("10"));
        let e2 = ParseError::BadMagic { expected: "MZ", found: "ZM".into() };
        assert!(e2.to_string().contains("MZ"));
        let e3 = ParseError::UnresolvableRva(0x1234);
        assert!(e3.to_string().contains("0x00001234"));
    }

    #[test]
    fn section_display() {
        let sec = SectionEntry {
            name: ".rdata".into(),
            virtual_size: 0x200,
            virtual_address: 0x3000,
            raw_size: 0x200,
            raw_offset: 0x600,
            characteristics: 0,
        };
        let s = format!("{sec}");
        assert!(s.contains(".rdata"));
    }

    #[test]
    fn stream_header_display() {
        let sh = StreamHeader {
            offset: 0x10,
            size: 0x100,
            name: "#~".into(),
            name_raw_len: 4,
        };
        let s = format!("{sh}");
        assert!(s.contains("#~"));
    }

    #[test]
    fn dotnet_header_parser_rejects_non_mz() {
        let err = DotnetHeaderParser::new(&[0u8; 128]).unwrap_err();
        assert!(matches!(err, ParseError::BadMagic { .. }));
    }

    #[test]
    fn dotnet_header_parser_too_short() {
        let err = DotnetHeaderParser::new(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ParseError::TooShort { .. }));
    }

    #[test]
    fn rd16_rd32_rd64_bounds() {
        let data = vec![0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        assert_eq!(rd16(&data, 0).unwrap(), 0xBBAA);
        assert_eq!(rd32(&data, 0).unwrap(), 0xDDCC_BBAA);
        let v64 = rd64(&data, 0).unwrap();
        assert_eq!(v64, 0x2211_FFEE_DDCC_BBAA);
    }

    #[test]
    fn rd32_out_of_bounds() {
        let data = vec![0u8; 2];
        assert!(rd32(&data, 0).is_err());
    }

    #[test]
    fn metadata_root_version_trim_nul() {
        let data = make_metadata_root_bytes();
        let root = MetadataRoot::parse(&data, 0).unwrap();
        // Version string must not contain embedded NUL characters.
        assert!(!root.version_string.contains('\0'));
    }

    #[test]
    fn metadata_root_base_offset_stored() {
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&make_metadata_root_bytes());
        let root = MetadataRoot::parse(&data, 8).unwrap();
        assert_eq!(root.base_offset, 8);
    }
}
