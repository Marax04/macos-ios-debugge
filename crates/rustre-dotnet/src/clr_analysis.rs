//! CLR analysis: .NET version detection from PE, CLR header parsing (metadata root,
//! stream headers), entrypoint token, strong name signature, runtime flags.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ClrAnalysisError {
    #[error("not a valid PE file")]
    NotPe,
    #[error("no CLR header found (not a .NET assembly)")]
    NoDotNet,
    #[error("invalid metadata signature (expected 0x424A5342)")]
    BadMetadataSignature,
    #[error("buffer too short at offset {0:#x}")]
    UnexpectedEof(usize),
    #[error("unsupported CLR major version {0}")]
    UnsupportedVersion(u16),
}

pub type ClrResult<T> = Result<T, ClrAnalysisError>;

// ── CLR runtime flags ─────────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ClrFlags: u32 {
        /// IL only (no native code).
        const ILONLY                    = 0x0000_0001;
        /// 32-bit preferred.
        const REQUIRED_32BIT            = 0x0000_0002;
        /// Has strong name signature.
        const STRONG_NAME_SIGNED        = 0x0000_0008;
        /// Native entrypoint.
        const NATIVE_ENTRYPOINT         = 0x0000_0010;
        /// Uses track debug data flag.
        const TRACK_DEBUG_DATA          = 0x0001_0000;
        /// Prefer 32-bit on 64-bit OS.
        const PREFER_32BIT              = 0x0002_0000;
    }
}

impl ClrFlags {
    #[must_use] 
    pub const fn is_il_only(self) -> bool {
        self.contains(Self::ILONLY)
    }

    #[must_use] 
    pub const fn is_32bit(self) -> bool {
        self.contains(Self::REQUIRED_32BIT)
    }

    #[must_use] 
    pub const fn is_strongly_named(self) -> bool {
        self.contains(Self::STRONG_NAME_SIGNED)
    }

    #[must_use] 
    pub const fn has_native_entrypoint(self) -> bool {
        self.contains(Self::NATIVE_ENTRYPOINT)
    }
}

// ── Metadata stream ───────────────────────────────────────────────────────────

/// A metadata stream header, e.g. #~, #Strings, #Blob, #GUID, #US.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataStream {
    pub offset: u32,
    pub size: u32,
    pub name: String,
}

impl MetadataStream {
    #[must_use] 
    pub fn is_table_stream(&self) -> bool {
        self.name == "#~" || self.name == "#-"
    }

    #[must_use] 
    pub fn is_strings(&self) -> bool {
        self.name == "#Strings"
    }

    #[must_use] 
    pub fn is_blob(&self) -> bool {
        self.name == "#Blob"
    }

    #[must_use] 
    pub fn is_guid(&self) -> bool {
        self.name == "#GUID"
    }

    #[must_use] 
    pub fn is_user_strings(&self) -> bool {
        self.name == "#US"
    }
}

// ── Metadata root ─────────────────────────────────────────────────────────────

/// ECMA-335 metadata root header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRoot {
    pub signature: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub reserved: u32,
    pub version_string: String,
    pub flags: u16,
    pub stream_count: u16,
    pub streams: Vec<MetadataStream>,
}

impl MetadataRoot {
    pub const METADATA_SIGNATURE: u32 = 0x424A_5342; // "BSJB"

    #[must_use] 
    pub fn stream_by_name(&self, name: &str) -> Option<&MetadataStream> {
        self.streams.iter().find(|s| s.name == name)
    }

    #[must_use] 
    pub fn table_stream(&self) -> Option<&MetadataStream> {
        self.streams.iter().find(|s| s.is_table_stream())
    }
}

// ── CLR header ────────────────────────────────────────────────────────────────

/// ECMA-335 §25.3.3 — CLR header (`IMAGE_COR20_HEADER`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClrHeader {
    /// Size of this header in bytes (72).
    pub cb: u32,
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    /// RVA and size of the metadata.
    pub metadata_rva: u32,
    pub metadata_size: u32,
    pub flags: ClrFlags,
    /// Token of the entrypoint method or file (for single-file assemblies).
    pub entrypoint_token: u32,
    /// RVA and size of resources.
    pub resources_rva: u32,
    pub resources_size: u32,
    /// RVA and size of the strong name signature hash blob.
    pub strong_name_rva: u32,
    pub strong_name_size: u32,
    pub code_manager_table_rva: u32,
    pub code_manager_table_size: u32,
    pub vtable_fixups_rva: u32,
    pub vtable_fixups_size: u32,
    pub export_address_table_jumps_rva: u32,
    pub export_address_table_jumps_size: u32,
    pub managed_native_header_rva: u32,
    pub managed_native_header_size: u32,
}

impl ClrHeader {
    /// CLR 2.0 = .NET 2.0–3.5; CLR 4.0 = .NET 4.x and 5+.
    #[must_use] 
    pub fn runtime_version(&self) -> String {
        format!("{}.{}", self.major_runtime_version, self.minor_runtime_version)
    }
}

// ── .NET version detection ────────────────────────────────────────────────────

/// Detected .NET version from PE metadata.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DotNetVersion {
    Net11,
    Net20,
    Net35,
    Net40,
    Net45,
    Net46,
    Net47,
    Net48,
    Net50,
    Net60,
    Net70,
    Net80,
    Net90,
    Unknown(String),
}

impl DotNetVersion {
    /// Detect .NET version from the assembly version string in metadata.
    #[must_use] 
    pub fn from_version_string(s: &str) -> Self {
        let s = s.trim();
        if s.starts_with("v4.0") || s.starts_with("v4.5") || s.starts_with("4.0") {
            return if s.contains("4.5") { Self::Net45 }
                   else if s.contains("4.6") { Self::Net46 }
                   else if s.contains("4.7") { Self::Net47 }
                   else if s.contains("4.8") { Self::Net48 }
                   else { Self::Net40 };
        }
        if s.starts_with("v2.0") || s.starts_with("2.0") {
            return Self::Net20;
        }
        if s.starts_with("v1.1") {
            return Self::Net11;
        }
        // .NET 5+ puts "v5.0", "v6.0", etc.
        if let Some(major) = s.strip_prefix('v').and_then(|s| s.split('.').next()) {
            match major {
                "5" => return Self::Net50,
                "6" => return Self::Net60,
                "7" => return Self::Net70,
                "8" => return Self::Net80,
                "9" => return Self::Net90,
                _ => {}
            }
        }
        Self::Unknown(s.to_owned())
    }

    #[must_use] 
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Net11 => ".NET 1.1",
            Self::Net20 => ".NET 2.0",
            Self::Net35 => ".NET 3.5",
            Self::Net40 => ".NET 4.0",
            Self::Net45 => ".NET 4.5",
            Self::Net46 => ".NET 4.6",
            Self::Net47 => ".NET 4.7",
            Self::Net48 => ".NET 4.8",
            Self::Net50 => ".NET 5",
            Self::Net60 => ".NET 6",
            Self::Net70 => ".NET 7",
            Self::Net80 => ".NET 8",
            Self::Net90 => ".NET 9",
            Self::Unknown(s) => s.as_str(),
        }
    }

    #[must_use] 
    pub const fn is_modern(&self) -> bool {
        matches!(self, Self::Net50 | Self::Net60 | Self::Net70 | Self::Net80 | Self::Net90)
    }
}

// ── Strong name ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrongNameInfo {
    pub public_key_token: Vec<u8>,
    pub public_key_token_hex: String,
    pub signature_blob: Vec<u8>,
    pub signature_size: usize,
    pub is_delay_signed: bool,
}

impl StrongNameInfo {
    #[must_use] 
    pub fn from_blob(blob: &[u8]) -> Self {
        let sig_size = blob.len();
        let token = &blob[..blob.len().min(8)];
        let token_hex = token.iter().fold(String::new(), |mut s, b| { use std::fmt::Write; let _ = write!(s, "{b:02x}"); s });
        Self {
            public_key_token: token.to_vec(),
            public_key_token_hex: token_hex,
            signature_blob: blob.to_vec(),
            signature_size: sig_size,
            is_delay_signed: blob.iter().all(|&b| b == 0),
        }
    }
}

// ── PE reader helpers ─────────────────────────────────────────────────────────

pub struct PeReader<'a> {
    data: &'a [u8],
}

impl<'a> PeReader<'a> {
    #[must_use] 
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn u16_at(&self, off: usize) -> ClrResult<u16> {
        if off + 2 > self.data.len() {
            return Err(ClrAnalysisError::UnexpectedEof(off));
        }
        Ok(u16::from_le_bytes(self.data[off..off + 2].try_into().unwrap()))
    }

    fn u32_at(&self, off: usize) -> ClrResult<u32> {
        if off + 4 > self.data.len() {
            return Err(ClrAnalysisError::UnexpectedEof(off));
        }
        Ok(u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap()))
    }

    fn bytes_at(&self, off: usize, len: usize) -> ClrResult<&[u8]> {
        if off + len > self.data.len() {
            return Err(ClrAnalysisError::UnexpectedEof(off));
        }
        Ok(&self.data[off..off + len])
    }

    fn cstr_at(&self, off: usize, max: usize) -> String {
        if off >= self.data.len() { return String::new(); }
        let end = self.data[off..].iter().take(max).position(|&b| b == 0).unwrap_or(max);
        String::from_utf8_lossy(&self.data[off..off + end]).into_owned()
    }

    /// Find the PE header offset.
    /// # Errors
    /// Returns an error when the operation fails.
    pub fn pe_offset(&self) -> ClrResult<usize> {
        if self.data.len() < 0x40 {
            return Err(ClrAnalysisError::NotPe);
        }
        if self.data[0] != b'M' || self.data[1] != b'Z' {
            return Err(ClrAnalysisError::NotPe);
        }
        let pe_off = self.u32_at(0x3C)? as usize;
        if pe_off + 4 > self.data.len() {
            return Err(ClrAnalysisError::NotPe);
        }
        if &self.data[pe_off..pe_off + 4] != b"PE\0\0" {
            return Err(ClrAnalysisError::NotPe);
        }
        Ok(pe_off)
    }

    /// Determine if this is PE32 or PE32+.
    /// # Errors
    /// Returns an error when the operation fails.
    pub fn is_pe32_plus(&self) -> ClrResult<bool> {
        let pe_off = self.pe_offset()?;
        let opt_off = pe_off + 24; // optional header starts here
        let magic = self.u16_at(opt_off)?;
        Ok(magic == 0x020B) // PE32+ magic
    }

    /// Find the data directory entry (0-based index).
    /// # Errors
    /// Returns an error when the operation fails.
    pub fn data_directory(&self, index: usize) -> ClrResult<(u32, u32)> {
        let pe_off = self.pe_offset()?;
        let is_plus = self.is_pe32_plus()?;
        let opt_off = pe_off + 24;
        // Data directories start at offset 96 (PE32) or 112 (PE32+) from opt header start
        let dd_start = opt_off + if is_plus { 112 } else { 96 };
        let dd_off = dd_start + index * 8;
        let rva = self.u32_at(dd_off)?;
        let size = self.u32_at(dd_off + 4)?;
        Ok((rva, size))
    }

    /// Convert RVA to file offset using section headers.
    /// # Errors
    /// Returns an error when the operation fails.
    pub fn rva_to_offset(&self, rva: u32) -> ClrResult<usize> {
        let pe_off = self.pe_offset()?;
        let num_sections = self.u16_at(pe_off + 6)? as usize;
        let opt_size = self.u16_at(pe_off + 20)? as usize;
        let sections_start = pe_off + 24 + opt_size;

        for i in 0..num_sections {
            let sec_off = sections_start + i * 40;
            if sec_off + 40 > self.data.len() {
                break;
            }
            let virtual_address = self.u32_at(sec_off + 12)?;
            let virtual_size = self.u32_at(sec_off + 8)?.max(self.u32_at(sec_off + 16)?); // VirtualSize @8, SizeOfRawData @16: neither alone spans the section
            let raw_offset = self.u32_at(sec_off + 20)?;

            if rva >= virtual_address && rva < virtual_address.saturating_add(virtual_size) {
                let file_off = (rva - virtual_address + raw_offset) as usize;
                return Ok(file_off);
            }
        }
        Err(ClrAnalysisError::UnexpectedEof(rva as usize))
    }

    /// Read the CLR header from the COM descriptor data directory (index 14).
    /// # Errors
    /// Returns an error when the operation fails.
    pub fn clr_header(&self) -> ClrResult<ClrHeader> {
        let (clr_rva, clr_size) = self.data_directory(14)?;
        if clr_rva == 0 || clr_size == 0 {
            return Err(ClrAnalysisError::NoDotNet);
        }
        let off = self.rva_to_offset(clr_rva)?;
        if off + 72 > self.data.len() {
            return Err(ClrAnalysisError::UnexpectedEof(off));
        }

        Ok(ClrHeader {
            cb: self.u32_at(off)?,
            major_runtime_version: self.u16_at(off + 4)?,
            minor_runtime_version: self.u16_at(off + 6)?,
            metadata_rva: self.u32_at(off + 8)?,
            metadata_size: self.u32_at(off + 12)?,
            flags: ClrFlags::from_bits_truncate(self.u32_at(off + 16)?),
            entrypoint_token: self.u32_at(off + 20)?,
            resources_rva: self.u32_at(off + 24)?,
            resources_size: self.u32_at(off + 28)?,
            strong_name_rva: self.u32_at(off + 32)?,
            strong_name_size: self.u32_at(off + 36)?,
            code_manager_table_rva: self.u32_at(off + 40)?,
            code_manager_table_size: self.u32_at(off + 44)?,
            vtable_fixups_rva: self.u32_at(off + 48)?,
            vtable_fixups_size: self.u32_at(off + 52)?,
            export_address_table_jumps_rva: self.u32_at(off + 56)?,
            export_address_table_jumps_size: self.u32_at(off + 60)?,
            managed_native_header_rva: self.u32_at(off + 64)?,
            managed_native_header_size: self.u32_at(off + 68)?,
        })
    }

    /// Parse the metadata root (ECMA-335 §24.2.1).
    /// # Errors
    /// Returns an error when the operation fails.
    pub fn metadata_root(&self, clr_header: &ClrHeader) -> ClrResult<MetadataRoot> {
        let off = self.rva_to_offset(clr_header.metadata_rva)?;
        let signature = self.u32_at(off)?;
        if signature != MetadataRoot::METADATA_SIGNATURE {
            return Err(ClrAnalysisError::BadMetadataSignature);
        }
        let major_version = self.u16_at(off + 4)?;
        let minor_version = self.u16_at(off + 6)?;
        let reserved = self.u32_at(off + 8)?;
        let version_len = self.u32_at(off + 12)? as usize;
        let version_string = self.cstr_at(off + 16, version_len);
        // Align to 4-byte boundary
        let aligned_ver_len = (version_len + 3) & !3;
        let after_version = off + 16 + aligned_ver_len;
        let flags = self.u16_at(after_version)?;
        let stream_count = self.u16_at(after_version + 2)?;

        let mut streams = Vec::with_capacity(stream_count as usize);
        let mut stream_off = after_version + 4;
        for _ in 0..stream_count {
            let stream_offset = self.u32_at(stream_off)?;
            let stream_size = self.u32_at(stream_off + 4)?;
            // Stream name: NUL-terminated, padded to 4-byte boundary
            let name_start = stream_off + 8;
            let name = self.cstr_at(name_start, 32);
            let name_len_padded = ((name.len() + 1 + 3) & !3).max(4);
            stream_off += 8 + name_len_padded;
            streams.push(MetadataStream {
                offset: stream_offset,
                size: stream_size,
                name,
            });
        }

        Ok(MetadataRoot {
            signature,
            major_version,
            minor_version,
            reserved,
            version_string,
            flags,
            stream_count,
            streams,
        })
    }

    /// Read the strong name signature blob.
    #[must_use] 
    pub fn strong_name(&self, clr_header: &ClrHeader) -> Option<StrongNameInfo> {
        if clr_header.strong_name_rva == 0 || clr_header.strong_name_size == 0 {
            return None;
        }
        let off = self.rva_to_offset(clr_header.strong_name_rva).ok()?;
        let blob = self.bytes_at(off, clr_header.strong_name_size as usize).ok()?;
        Some(StrongNameInfo::from_blob(blob))
    }
}

// ── CLR analysis report ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClrAnalysisReport {
    pub dotnet_version: DotNetVersion,
    pub runtime_version: String,
    pub clr_flags: ClrFlags,
    pub is_il_only: bool,
    pub is_32bit_only: bool,
    pub has_native_entrypoint: bool,
    pub entrypoint_token: u32,
    pub entrypoint_table: u8,
    pub entrypoint_row: u32,
    pub metadata_version: String,
    pub streams: Vec<String>,
    pub strong_name: Option<StrongNameInfo>,
    pub metadata_rva: u32,
    pub metadata_size: u32,
    pub resources_rva: u32,
    pub resources_size: u32,
}

impl ClrAnalysisReport {
    /// # Errors
    /// Returns an error when the operation fails.
    pub fn from_pe(data: &[u8]) -> ClrResult<Self> {
        let reader = PeReader::new(data);
        let clr_hdr = reader.clr_header()?;
        let metadata = reader.metadata_root(&clr_hdr)?;
        let strong_name = reader.strong_name(&clr_hdr);

        let version = DotNetVersion::from_version_string(&metadata.version_string);
        let runtime_version = clr_hdr.runtime_version();
        let streams = metadata.streams.iter().map(|s| s.name.clone()).collect();

        let token = clr_hdr.entrypoint_token;
        let entrypoint_table = ((token >> 24) & 0xFF) as u8;
        let entrypoint_row = token & 0x00FF_FFFF;

        Ok(Self {
            dotnet_version: version,
            runtime_version,
            clr_flags: clr_hdr.flags,
            is_il_only: clr_hdr.flags.is_il_only(),
            is_32bit_only: clr_hdr.flags.is_32bit(),
            has_native_entrypoint: clr_hdr.flags.has_native_entrypoint(),
            entrypoint_token: token,
            entrypoint_table,
            entrypoint_row,
            metadata_version: metadata.version_string,
            streams,
            strong_name,
            metadata_rva: clr_hdr.metadata_rva,
            metadata_size: clr_hdr.metadata_size,
            resources_rva: clr_hdr.resources_rva,
            resources_size: clr_hdr.resources_size,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_detection() {
        assert_eq!(DotNetVersion::from_version_string("v4.0.30319"), DotNetVersion::Net40);
        assert_eq!(DotNetVersion::from_version_string("v2.0.50727"), DotNetVersion::Net20);
        assert_eq!(DotNetVersion::from_version_string("v6.0.0"), DotNetVersion::Net60);
        assert_eq!(DotNetVersion::from_version_string("v8.0.0"), DotNetVersion::Net80);
    }

    #[test]
    fn test_version_is_modern() {
        assert!(DotNetVersion::Net60.is_modern());
        assert!(!DotNetVersion::Net48.is_modern());
    }

    #[test]
    fn test_clr_flags() {
        let flags = ClrFlags::ILONLY | ClrFlags::STRONG_NAME_SIGNED;
        assert!(flags.is_il_only());
        assert!(flags.is_strongly_named());
        assert!(!flags.is_32bit());
        assert!(!flags.has_native_entrypoint());
    }

    #[test]
    fn test_strong_name_delay_signed() {
        let zero_blob = vec![0u8; 128];
        let sn = StrongNameInfo::from_blob(&zero_blob);
        assert!(sn.is_delay_signed);
    }

    #[test]
    fn test_strong_name_real() {
        let blob = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let sn = StrongNameInfo::from_blob(&blob);
        assert!(!sn.is_delay_signed);
        assert_eq!(sn.public_key_token_hex, "0102030405060708");
    }

    #[test]
    fn test_pe_not_dotnet() {
        let mut data = vec![0u8; 0x200];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C] = 0x80;
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        let reader = PeReader::new(&data);
        // Should fail because optional header will have garbage magic
        let result = reader.clr_header();
        assert!(result.is_err());
    }

    #[test]
    fn test_metadata_stream_flags() {
        let s = MetadataStream { offset: 0, size: 100, name: "#~".to_owned() };
        assert!(s.is_table_stream());
        assert!(!s.is_strings());

        let s2 = MetadataStream { offset: 0, size: 200, name: "#Strings".to_owned() };
        assert!(s2.is_strings());
        assert!(!s2.is_table_stream());
    }

    #[test]
    fn test_not_pe() {
        let data = b"not a PE file at all";
        let reader = PeReader::new(data);
        assert!(matches!(reader.pe_offset(), Err(ClrAnalysisError::NotPe)));
    }
}
