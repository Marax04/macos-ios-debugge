//! PE CLR header (`IMAGE_COR20_HEADER`) parsing — serde-rich layer.
//!
//! Parses the CLR Runtime Header from PE data directory index 14, including
//! all sub-structures: flags, entry point, metadata root, and stream headers.
//!
//! # Design note — relation to `dotnet_header_parser`
//! [`dotnet_header_parser`] is the **dependency-free** counterpart: it uses
//! its own `ParseError` type and carries no serde derives.  This module
//! (`pe_clr_header`) is the **serde-enabled** layer that exposes typed
//! `ClrFlags` accessors and richer sub-structures for programmatic use in
//! the loader pipeline.  Keep both modules distinct.

use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors from CLR header parsing.
#[derive(Debug)]
pub enum ClrHeaderError {
    TooSmall,
    InvalidMagic,
    InvalidBsjb,
    TruncatedStream,
    BadRva(u32),
    ParseError(String),
}

impl fmt::Display for ClrHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall => write!(f, "buffer too small"),
            Self::InvalidMagic => write!(f, "invalid CLR header magic"),
            Self::InvalidBsjb => write!(f, "invalid BSJB magic"),
            Self::TruncatedStream => write!(f, "truncated stream"),
            Self::BadRva(r) => write!(f, "bad RVA {r:#010x}"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

// ─── ClrFlags ────────────────────────────────────────────────────────────────

/// `IMAGE_COR20_HEADER.Flags` bit definitions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClrFlags(pub u32);

impl ClrFlags {
    /// The CLR loader does not allow the image to be loaded in a partial trust context.
    pub const ILONLY: u32 = 0x0000_0001;
    /// Image can only be loaded into a 32-bit process.
    pub const REQUIRED_32BIT: u32 = 0x0000_0002;
    /// Image has a strong name.
    pub const STRONG_NAME_SIGNED: u32 = 0x0000_0008;
    /// A native entry point exists.
    pub const NATIVE_ENTRY_POINT: u32 = 0x0000_0010;
    /// Reserved for runtime.
    pub const TRACKDEBUGDATA: u32 = 0x0001_0000;
    /// Image supports running in a 32-bit or 64-bit process.
    pub const PREFER_32BIT: u32 = 0x0002_0000;

    #[must_use]
    pub const fn is_il_only(self) -> bool {
        self.0 & Self::ILONLY != 0
    }
    #[must_use]
    pub const fn is_32bit_required(self) -> bool {
        self.0 & Self::REQUIRED_32BIT != 0
    }
    #[must_use]
    pub const fn is_strong_name_signed(self) -> bool {
        self.0 & Self::STRONG_NAME_SIGNED != 0
    }
    #[must_use]
    pub const fn has_native_entry_point(self) -> bool {
        self.0 & Self::NATIVE_ENTRY_POINT != 0
    }
    #[must_use]
    pub const fn prefers_32bit(self) -> bool {
        self.0 & Self::PREFER_32BIT != 0
    }

    /// Return a human-readable list of set flags.
    #[must_use]
    pub fn describe(self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.is_il_only() {
            v.push("ILONLY");
        }
        if self.is_32bit_required() {
            v.push("REQUIRED_32BIT");
        }
        if self.is_strong_name_signed() {
            v.push("STRONG_NAME_SIGNED");
        }
        if self.has_native_entry_point() {
            v.push("NATIVE_ENTRY_POINT");
        }
        if self.prefers_32bit() {
            v.push("PREFER_32BIT");
        }
        v
    }
}

// ─── ClrDataDirectory ────────────────────────────────────────────────────────

/// A CLR data directory (RVA + size pair).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClrDataDirectory {
    pub rva: u32,
    pub size: u32,
}

impl ClrDataDirectory {
    /// Return true if the directory is present.
    #[must_use]
    pub const fn is_present(self) -> bool {
        self.rva != 0
    }

    /// Parse from 8 bytes at `data[offset]`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ClrHeaderError> {
        if offset + 8 > data.len() {
            return Err(ClrHeaderError::TooSmall);
        }
        let rva = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let size = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        Ok(Self { rva, size })
    }
}

// ─── ClrEntryPoint ───────────────────────────────────────────────────────────

/// The CLR entry point token or RVA.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[derive(Default)]
pub enum ClrEntryPoint {
    /// Metadata token (`MethodDef` token for managed entry point).
    Token(u32),
    /// RVA of native entry point (if `NATIVE_ENTRY_POINT` flag is set).
    Rva(u32),
    /// No entry point.
    #[default]
    None,
}


impl ClrEntryPoint {
    /// Parse based on flags.
    #[must_use]
    pub const fn parse(raw: u32, flags: ClrFlags) -> Self {
        if raw == 0 {
            Self::None
        } else if flags.has_native_entry_point() {
            Self::Rva(raw)
        } else {
            Self::Token(raw)
        }
    }

    /// Return as a u32 (0 if None).
    #[must_use]
    pub const fn raw(self) -> u32 {
        match self {
            Self::Token(t) => t,
            Self::Rva(r) => r,
            Self::None => 0,
        }
    }

    /// Return true if a managed entry point is present.
    #[must_use]
    pub const fn is_managed(self) -> bool {
        matches!(self, Self::Token(_))
    }
}

// ─── VTableFixup ─────────────────────────────────────────────────────────────

/// A vtable fixup entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VTableFixup {
    pub rva: u32,
    pub count: u16,
    pub kind: VTableKind,
}

/// `VTable` fixup type flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VTableKind(pub u16);

impl VTableKind {
    pub const COR_VTABLE_32BIT: u16 = 0x01;
    pub const COR_VTABLE_64BIT: u16 = 0x02;
    pub const COR_VTABLE_FROM_UNMANAGED: u16 = 0x04;
    pub const COR_VTABLE_FROM_UNMANAGED_RETAIN_APPDOMAIN: u16 = 0x08;
    pub const COR_VTABLE_CALL_MOST_DERIVED: u16 = 0x10;

    #[must_use]
    pub const fn is_32bit(self) -> bool {
        self.0 & Self::COR_VTABLE_32BIT != 0
    }
    #[must_use]
    pub const fn is_64bit(self) -> bool {
        self.0 & Self::COR_VTABLE_64BIT != 0
    }
    #[must_use]
    pub const fn from_unmanaged(self) -> bool {
        self.0 & Self::COR_VTABLE_FROM_UNMANAGED != 0
    }
}

// ─── ClrHeader ───────────────────────────────────────────────────────────────

/// Parsed `IMAGE_COR20_HEADER` structure.
///
/// All fields correspond to the ECMA-335 specification for the CLI header.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClrHeader {
    /// Size of the header in bytes (should be 0x48).
    pub cb: u32,
    /// Major runtime version required (2 for .NET Framework).
    pub major_runtime_version: u16,
    /// Minor runtime version required.
    pub minor_runtime_version: u16,
    /// RVA and size of the metadata root (BSJB structure).
    pub metadata: ClrDataDirectory,
    /// CLR header flags.
    pub flags: ClrFlags,
    /// Entry point token or RVA.
    pub entry_point_token: ClrEntryPoint,
    /// Resources directory.
    pub resources: ClrDataDirectory,
    /// Strong name signature.
    pub strong_name_signature: ClrDataDirectory,
    /// Code manager table (usually zero).
    pub code_manager_table: ClrDataDirectory,
    /// `VTable` fixups directory.
    pub vtable_fixups: ClrDataDirectory,
    /// Export address table jumps (for unmanaged exports).
    pub export_address_table_jumps: ClrDataDirectory,
    /// Managed native header (for IL+native hybrid images).
    pub managed_native_header: ClrDataDirectory,
}

impl ClrHeader {
    /// Parse a CLR header from raw bytes at `offset`.
    ///
    /// The `offset` should be the file offset resolved from the CLR runtime header RVA.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ClrHeaderError> {
        if offset + 72 > data.len() {
            return Err(ClrHeaderError::TooSmall);
        }

        let cb = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let major = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
        let minor = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);
        let metadata = ClrDataDirectory::parse(data, offset + 8)?;
        let flags_raw = u32::from_le_bytes([
            data[offset + 16],
            data[offset + 17],
            data[offset + 18],
            data[offset + 19],
        ]);
        let flags = ClrFlags(flags_raw);
        let ep_raw = u32::from_le_bytes([
            data[offset + 20],
            data[offset + 21],
            data[offset + 22],
            data[offset + 23],
        ]);
        let entry_point_token = ClrEntryPoint::parse(ep_raw, flags);
        let resources = ClrDataDirectory::parse(data, offset + 24)?;
        let strong_name_signature = ClrDataDirectory::parse(data, offset + 32)?;
        let code_manager_table = ClrDataDirectory::parse(data, offset + 40)?;
        let vtable_fixups = ClrDataDirectory::parse(data, offset + 48)?;
        let export_address_table_jumps = ClrDataDirectory::parse(data, offset + 56)?;
        let managed_native_header = ClrDataDirectory::parse(data, offset + 64)?;

        Ok(Self {
            cb,
            major_runtime_version: major,
            minor_runtime_version: minor,
            metadata,
            flags,
            entry_point_token,
            resources,
            strong_name_signature,
            code_manager_table,
            vtable_fixups,
            export_address_table_jumps,
            managed_native_header,
        })
    }

    /// Return true if this is a pure IL assembly.
    #[must_use]
    pub const fn is_pure_il(&self) -> bool {
        self.flags.is_il_only()
    }

    /// Return true if this assembly is strong-name signed.
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.flags.is_strong_name_signed()
    }

    /// Return the runtime version as a string.
    #[must_use]
    pub fn runtime_version(&self) -> String {
        format!(
            "{}.{}",
            self.major_runtime_version, self.minor_runtime_version
        )
    }
}

// ─── MetadataStreamHeader ────────────────────────────────────────────────────

/// A metadata stream header entry from the BSJB structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataStreamHeader {
    /// Offset from the start of the metadata root.
    pub offset: u32,
    /// Size of the stream.
    pub size: u32,
    /// Stream name (e.g. "#~", "#Strings", "#US", "#GUID", "#Blob").
    pub name: String,
}

impl MetadataStreamHeader {
    /// Return true if this is the tables stream.
    #[must_use]
    pub fn is_tables(&self) -> bool {
        self.name == "#~" || self.name == "#-"
    }

    /// Return true if this is the strings heap.
    #[must_use]
    pub fn is_strings(&self) -> bool {
        self.name == "#Strings"
    }

    /// Return true if this is the US (user strings) heap.
    #[must_use]
    pub fn is_us(&self) -> bool {
        self.name == "#US"
    }

    /// Return true if this is the GUID heap.
    #[must_use]
    pub fn is_guid(&self) -> bool {
        self.name == "#GUID"
    }

    /// Return true if this is the Blob heap.
    #[must_use]
    pub fn is_blob(&self) -> bool {
        self.name == "#Blob"
    }
}

// ─── MetadataRoot ────────────────────────────────────────────────────────────

/// The metadata root (BSJB structure) of a .NET assembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRoot {
    /// Magic signature: should be 0x424A5342 ("BSJB").
    pub magic: u32,
    /// Major version.
    pub major_version: u16,
    /// Minor version.
    pub minor_version: u16,
    /// Reserved (must be 0).
    pub reserved: u32,
    /// Runtime version string length.
    pub version_length: u32,
    /// CLR version string (e.g. "v4.0.30319").
    pub version: String,
    /// Flags (reserved, must be 0).
    pub flags: u16,
    /// Number of streams.
    pub num_streams: u16,
    /// Stream headers.
    pub streams: Vec<MetadataStreamHeader>,
}

impl MetadataRoot {
    /// BSJB magic constant.
    pub const MAGIC: u32 = 0x424A_5342;

    /// Parse the metadata root from `data` at `offset`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ClrHeaderError> {
        if offset + 16 > data.len() {
            return Err(ClrHeaderError::TooSmall);
        }

        let magic = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        if magic != Self::MAGIC {
            return Err(ClrHeaderError::InvalidBsjb);
        }

        let major = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
        let minor = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);
        let reserved = u32::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]);
        let version_length = u32::from_le_bytes([
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]) as usize;

        let ver_end = (offset + 16).saturating_add(version_length).min(data.len());
        let ver_bytes: Vec<u8> = data[offset + 16..ver_end]
            .iter()
            .copied()
            .take_while(|&b| b != 0)
            .collect();
        let version = String::from_utf8_lossy(&ver_bytes).to_string();

        // After version string (padded to 4-byte boundary)
        let padded_ver_len = version_length.saturating_add(3) & !3;
        let mut pos = (offset + 16).saturating_add(padded_ver_len);

        if pos + 4 > data.len() {
            return Err(ClrHeaderError::TooSmall);
        }
        let flags = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let num_streams = u16::from_le_bytes([data[pos + 2], data[pos + 3]]);
        pos += 4;

        let mut streams = Vec::with_capacity(num_streams as usize);
        for _ in 0..num_streams {
            if pos + 8 > data.len() {
                return Err(ClrHeaderError::TruncatedStream);
            }
            let stream_offset =
                u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            let size =
                u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
            pos += 8;

            // Read null-terminated name padded to 4 bytes
            let name_start = pos;
            while pos < data.len() && data[pos] != 0 {
                pos += 1;
            }
            let name = String::from_utf8_lossy(&data[name_start..pos]).to_string();
            // Skip null + padding
            pos += 1;
            pos = (pos + 3) & !3;

            streams.push(MetadataStreamHeader {
                offset: stream_offset,
                size,
                name,
            });
        }

        Ok(Self {
            magic,
            major_version: major,
            minor_version: minor,
            reserved,
            version_length: version_length as u32,
            version,
            flags,
            num_streams,
            streams,
        })
    }

    /// Find a stream header by name.
    #[must_use]
    pub fn find_stream(&self, name: &str) -> Option<&MetadataStreamHeader> {
        self.streams.iter().find(|s| s.name == name)
    }

    /// Return true if this metadata root has the tables stream.
    #[must_use]
    pub fn has_tables(&self) -> bool {
        self.streams.iter().any(MetadataStreamHeader::is_tables)
    }

    /// Return true if this is a valid BSJB root.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_clr_header_bytes() -> Vec<u8> {
        let mut h = vec![0u8; 72];
        // cb = 0x48
        h[0] = 0x48;
        h[1] = 0x00;
        h[2] = 0x00;
        h[3] = 0x00;
        // major = 2, minor = 5
        h[4] = 0x02;
        h[5] = 0x00;
        h[6] = 0x05;
        h[7] = 0x00;
        // metadata RVA = 0x2000, size = 0x1000
        h[8] = 0x00;
        h[9] = 0x20;
        h[10] = 0x00;
        h[11] = 0x00;
        h[12] = 0x00;
        h[13] = 0x10;
        h[14] = 0x00;
        h[15] = 0x00;
        // flags = ILONLY (0x01)
        h[16] = 0x01;
        h[17] = 0x00;
        h[18] = 0x00;
        h[19] = 0x00;
        // EntryPointToken = 0x06000001
        h[20] = 0x01;
        h[21] = 0x00;
        h[22] = 0x00;
        h[23] = 0x06;
        h
    }

    fn build_metadata_root_bytes() -> Vec<u8> {
        let mut m = Vec::new();
        // BSJB magic
        m.extend_from_slice(b"BSJB");
        // major = 1, minor = 1
        m.extend_from_slice(&1u16.to_le_bytes());
        m.extend_from_slice(&1u16.to_le_bytes());
        // reserved
        m.extend_from_slice(&0u32.to_le_bytes());
        // version_length = 12 (padded to 12)
        m.extend_from_slice(&12u32.to_le_bytes());
        // version string "v4.0.30319\0\0"
        m.extend_from_slice(b"v4.0.30319\0\0");
        // flags = 0, num_streams = 1
        m.extend_from_slice(&0u16.to_le_bytes());
        m.extend_from_slice(&1u16.to_le_bytes());
        // stream 0: offset=0x6C, size=0x100, name="#~\0\0"
        m.extend_from_slice(&0x6Cu32.to_le_bytes());
        m.extend_from_slice(&0x100u32.to_le_bytes());
        m.extend_from_slice(b"#~\0\0");
        m
    }

    #[test]
    fn test_clr_header_parse() {
        let bytes = build_clr_header_bytes();
        let hdr = ClrHeader::parse(&bytes, 0).unwrap();
        assert_eq!(hdr.cb, 0x48);
        assert_eq!(hdr.major_runtime_version, 2);
        assert_eq!(hdr.minor_runtime_version, 5);
        assert_eq!(hdr.metadata.rva, 0x2000);
        assert_eq!(hdr.metadata.size, 0x1000);
        assert!(hdr.flags.is_il_only());
    }

    #[test]
    fn test_clr_header_too_small() {
        let bytes = vec![0u8; 10];
        let result = ClrHeader::parse(&bytes, 0);
        assert!(matches!(result, Err(ClrHeaderError::TooSmall)));
    }

    #[test]
    fn test_clr_flags_describe() {
        let f = ClrFlags(ClrFlags::ILONLY | ClrFlags::STRONG_NAME_SIGNED);
        let desc = f.describe();
        assert!(desc.contains(&"ILONLY"));
        assert!(desc.contains(&"STRONG_NAME_SIGNED"));
    }

    #[test]
    fn test_clr_flags_32bit() {
        let f = ClrFlags(ClrFlags::REQUIRED_32BIT);
        assert!(f.is_32bit_required());
        assert!(!f.is_il_only());
    }

    #[test]
    fn test_clr_entry_point_token() {
        let ep = ClrEntryPoint::parse(0x0600_0001, ClrFlags(ClrFlags::ILONLY));
        assert!(matches!(ep, ClrEntryPoint::Token(0x0600_0001)));
        assert!(ep.is_managed());
        assert_eq!(ep.raw(), 0x0600_0001);
    }

    #[test]
    fn test_clr_entry_point_none() {
        let ep = ClrEntryPoint::parse(0, ClrFlags::default());
        assert!(matches!(ep, ClrEntryPoint::None));
        assert_eq!(ep.raw(), 0);
    }

    #[test]
    fn test_clr_entry_point_native() {
        let ep = ClrEntryPoint::parse(0x5000, ClrFlags(ClrFlags::NATIVE_ENTRY_POINT));
        assert!(matches!(ep, ClrEntryPoint::Rva(0x5000)));
        assert!(!ep.is_managed());
    }

    #[test]
    fn test_clr_data_directory_present() {
        let dd = ClrDataDirectory {
            rva: 0x1000,
            size: 0x200,
        };
        assert!(dd.is_present());
    }

    #[test]
    fn test_clr_data_directory_absent() {
        let dd = ClrDataDirectory { rva: 0, size: 0 };
        assert!(!dd.is_present());
    }

    #[test]
    fn test_clr_data_directory_parse() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&0x1234u32.to_le_bytes());
        data[4..8].copy_from_slice(&0xABCDu32.to_le_bytes());
        let dd = ClrDataDirectory::parse(&data, 0).unwrap();
        assert_eq!(dd.rva, 0x1234);
        assert_eq!(dd.size, 0xABCD);
    }

    #[test]
    fn test_metadata_root_parse() {
        let bytes = build_metadata_root_bytes();
        let root = MetadataRoot::parse(&bytes, 0).unwrap();
        assert_eq!(root.magic, MetadataRoot::MAGIC);
        assert!(root.version.starts_with("v4.0"));
        assert_eq!(root.num_streams, 1);
        assert!(root.has_tables());
    }

    #[test]
    fn test_metadata_root_invalid_bsjb() {
        let bytes = vec![0u8; 64];
        let result = MetadataRoot::parse(&bytes, 0);
        assert!(matches!(result, Err(ClrHeaderError::InvalidBsjb)));
    }

    #[test]
    fn test_metadata_stream_header_types() {
        let h_tables = MetadataStreamHeader {
            offset: 0,
            size: 0,
            name: "#~".to_owned(),
        };
        let h_strings = MetadataStreamHeader {
            offset: 0,
            size: 0,
            name: "#Strings".to_owned(),
        };
        let h_us = MetadataStreamHeader {
            offset: 0,
            size: 0,
            name: "#US".to_owned(),
        };
        let h_guid = MetadataStreamHeader {
            offset: 0,
            size: 0,
            name: "#GUID".to_owned(),
        };
        let h_blob = MetadataStreamHeader {
            offset: 0,
            size: 0,
            name: "#Blob".to_owned(),
        };
        assert!(h_tables.is_tables());
        assert!(h_strings.is_strings());
        assert!(h_us.is_us());
        assert!(h_guid.is_guid());
        assert!(h_blob.is_blob());
    }

    #[test]
    fn test_metadata_root_find_stream() {
        let bytes = build_metadata_root_bytes();
        let root = MetadataRoot::parse(&bytes, 0).unwrap();
        assert!(root.find_stream("#~").is_some());
        assert!(root.find_stream("#Strings").is_none());
    }

    #[test]
    fn test_clr_header_runtime_version() {
        let bytes = build_clr_header_bytes();
        let hdr = ClrHeader::parse(&bytes, 0).unwrap();
        assert_eq!(hdr.runtime_version(), "2.5");
    }

    #[test]
    fn test_clr_header_is_pure_il() {
        let bytes = build_clr_header_bytes();
        let hdr = ClrHeader::parse(&bytes, 0).unwrap();
        assert!(hdr.is_pure_il());
    }

    #[test]
    fn test_clr_header_is_signed() {
        let mut bytes = build_clr_header_bytes();
        // Set STRONG_NAME_SIGNED bit
        bytes[16] |= ClrFlags::STRONG_NAME_SIGNED as u8;
        let hdr = ClrHeader::parse(&bytes, 0).unwrap();
        assert!(hdr.is_signed());
    }

    #[test]
    fn test_vtable_kind_flags() {
        let k = VTableKind(VTableKind::COR_VTABLE_32BIT | VTableKind::COR_VTABLE_FROM_UNMANAGED);
        assert!(k.is_32bit());
        assert!(!k.is_64bit());
        assert!(k.from_unmanaged());
    }

    #[test]
    fn test_metadata_root_is_valid() {
        let root = MetadataRoot {
            magic: MetadataRoot::MAGIC,
            major_version: 1,
            minor_version: 1,
            reserved: 0,
            version_length: 0,
            version: String::new(),
            flags: 0,
            num_streams: 0,
            streams: vec![],
        };
        assert!(root.is_valid());
    }

    #[test]
    fn test_clr_data_directory_parse_too_small() {
        let data = vec![0u8; 4];
        let result = ClrDataDirectory::parse(&data, 0);
        assert!(matches!(result, Err(ClrHeaderError::TooSmall)));
    }
}
