//! .NET (CLR) PE detection and `IMAGE_COR20_HEADER` parsing.
//!
//! `DataDirectory[14]` points to the CLR header in managed assemblies.
//! Mixed-mode assemblies contain both native and managed code.

use crate::imports::{RvaSection, rva_to_file_offset};

// ---------------------------------------------------------------------------
// COR20 flags
// ---------------------------------------------------------------------------

/// `IMAGE_COR20_HEADER` flags (`COMIMAGE_FLAGS_*`)
pub const COMIMAGE_FLAGS_ILONLY: u32 = 0x0000_0001;
pub const COMIMAGE_FLAGS_32BITREQUIRED: u32 = 0x0000_0002;
pub const COMIMAGE_FLAGS_IL_LIBRARY: u32 = 0x0000_0004;
pub const COMIMAGE_FLAGS_STRONGNAMESIGNED: u32 = 0x0000_0008;
pub const COMIMAGE_FLAGS_NATIVE_ENTRYPOINT: u32 = 0x0000_0010;
pub const COMIMAGE_FLAGS_TRACKDEBUGDATA: u32 = 0x0001_0000;
pub const COMIMAGE_FLAGS_32BITPREFERRED: u32 = 0x0002_0000;

/// Known CLR major version numbers.
pub const CLR_VERSION_1_0: u16 = 1;
pub const CLR_VERSION_2_0: u16 = 2;
pub const CLR_VERSION_4_0: u16 = 4;

// ---------------------------------------------------------------------------
// Data directory within COR20 header
// ---------------------------------------------------------------------------

/// A data directory entry within the CLR header.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Cor20DataDirectory {
    /// RVA of the structure.
    pub virtual_address: u32,
    /// Size of the structure in bytes.
    pub size: u32,
}

impl Cor20DataDirectory {
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

// ---------------------------------------------------------------------------
// IMAGE_COR20_HEADER
// ---------------------------------------------------------------------------

/// Parsed `IMAGE_COR20_HEADER` (72 bytes).
#[derive(Debug, Clone)]
pub struct Cor20Header {
    /// Must be 72.
    pub cb: u32,
    /// Major runtime version required.
    pub major_runtime_version: u16,
    /// Minor runtime version required.
    pub minor_runtime_version: u16,
    /// RVA + size of the metadata root (#~ stream etc.).
    pub meta_data: Cor20DataDirectory,
    /// `COMIMAGE_FLAGS_*` flags.
    pub flags: u32,
    /// If `COMIMAGE_FLAGS_NATIVE_ENTRYPOINT` is set, this is a native RVA;
    /// otherwise it is a `MethodDef` token.
    pub entry_point_token_or_rva: u32,
    /// Managed resources blob.
    pub resources: Cor20DataDirectory,
    /// Strong name signature blob.
    pub strong_name_signature: Cor20DataDirectory,
    /// Code manager table (legacy, usually zero).
    pub code_manager_table: Cor20DataDirectory,
    /// Virtual table fixups (for mixed-mode assemblies).
    pub vtable_fixups: Cor20DataDirectory,
    /// Export address table jumps (mixed-mode).
    pub export_address_table_jumps: Cor20DataDirectory,
    /// Managed native header (for `NGen` images).
    pub managed_native_header: Cor20DataDirectory,
}

impl Cor20Header {
    /// Parse `IMAGE_COR20_HEADER` from `data` at `offset`.
    /// The structure is 72 bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data is too short or the header is invalid.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 72 > data.len() {
            return Err(format!(
                "IMAGE_COR20_HEADER truncated at offset {offset:#x}"
            ));
        }

        let r16 = |off: usize| -> u16 {
            u16::from_le_bytes(data[off..off + 2].try_into().unwrap_or([0; 2]))
        };
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        };
        let rdir = |off: usize| -> Cor20DataDirectory {
            Cor20DataDirectory {
                virtual_address: r32(off),
                size: r32(off + 4),
            }
        };

        let b = offset;
        let cb = r32(b);
        if cb < 72 {
            return Err(format!("IMAGE_COR20_HEADER cb={cb}, expected >= 72"));
        }

        Ok(Self {
            cb,
            major_runtime_version: r16(b + 4),
            minor_runtime_version: r16(b + 6),
            meta_data: rdir(b + 8),
            flags: r32(b + 16),
            entry_point_token_or_rva: r32(b + 20),
            resources: rdir(b + 24),
            strong_name_signature: rdir(b + 32),
            code_manager_table: rdir(b + 40),
            vtable_fixups: rdir(b + 48),
            export_address_table_jumps: rdir(b + 56),
            managed_native_header: rdir(b + 64),
        })
    }

    // ----- Flag accessors ---------------------------------------------------

    /// Pure IL assembly (no native code in the managed binary).
    #[must_use]
    pub const fn is_il_only(&self) -> bool {
        self.flags & COMIMAGE_FLAGS_ILONLY != 0
    }

    /// Requires 32-bit process (ILONLY `32BitRequired` flag).
    #[must_use]
    pub const fn requires_32bit(&self) -> bool {
        self.flags & COMIMAGE_FLAGS_32BITREQUIRED != 0
    }

    /// Prefers 32-bit process even on 64-bit Windows (`32BitPreferred` flag).
    #[must_use]
    pub const fn prefers_32bit(&self) -> bool {
        self.flags & COMIMAGE_FLAGS_32BITPREFERRED != 0
    }

    /// The assembly has a strong name signature.
    #[must_use]
    pub const fn is_strong_name_signed(&self) -> bool {
        self.flags & COMIMAGE_FLAGS_STRONGNAMESIGNED != 0
    }

    /// The entry point is a native RVA rather than a managed `MethodDef` token.
    #[must_use]
    pub const fn has_native_entrypoint(&self) -> bool {
        self.flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0
    }

    /// Mixed-mode: has native virtual table fixups (C++/CLI or IJW).
    #[must_use]
    pub const fn is_mixed_mode(&self) -> bool {
        self.vtable_fixups.is_present()
    }

    /// Returns a human-readable CLR version string.
    #[must_use]
    pub fn clr_version_str(&self) -> String {
        format!(
            "{}.{}",
            self.major_runtime_version, self.minor_runtime_version
        )
    }
}

// ---------------------------------------------------------------------------
// Metadata stream parsing (header only)
// ---------------------------------------------------------------------------

/// The 16-byte CLR metadata root signature.
pub const METADATA_SIGNATURE: u32 = 0x424A_5342; // "BSJB"

/// Metadata root header (partial — just version string and stream count).
#[derive(Debug, Clone)]
pub struct MetadataRoot {
    /// Always `0x424A_5342` ("BSJB").
    pub signature: u32,
    /// Major version (1).
    pub major_version: u16,
    /// Minor version (1).
    pub minor_version: u16,
    /// CLR version string (e.g. "v4.0.30319").
    pub version_string: String,
    /// Number of metadata streams (#~, #Strings, #US, #GUID, #Blob).
    pub stream_count: u16,
}

impl MetadataRoot {
    /// Parse the ECMA-335 metadata root from `data` at `offset`.
    ///
    /// Layout:
    /// - `DWORD` `Signature` (4)  = "BSJB"
    /// - `WORD`  `MajorVersion` (2)
    /// - `WORD`  `MinorVersion` (2)
    /// - `DWORD` `Reserved` (4)
    /// - `DWORD` `Length` (4) — length of version string (padded to 4 bytes)
    /// - `CHAR`  `Version[Length]`
    /// - `WORD`  `Flags` (2)
    /// - `WORD`  `Streams` (2)
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data is too short or the signature is invalid.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 20 > data.len() {
            return Err(format!("Metadata root truncated at offset {offset:#x}"));
        }

        let r16 = |off: usize| -> u16 {
            u16::from_le_bytes(data[off..off + 2].try_into().unwrap_or([0; 2]))
        };
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        };

        let signature = r32(offset);
        if signature != METADATA_SIGNATURE {
            return Err(format!(
                "Bad metadata signature {signature:#010x} at offset {offset:#x}"
            ));
        }

        let major_version = r16(offset + 4);
        let minor_version = r16(offset + 6);
        // offset+8: reserved DWORD (skip)
        let version_len = r32(offset + 12) as usize;

        let ver_start = offset + 16;
        let ver_end = ver_start + version_len;
        if ver_end > data.len() {
            return Err(format!(
                "Metadata version string truncated at offset {ver_start:#x}"
            ));
        }

        // Null-terminated string within the padded buffer
        let raw = &data[ver_start..ver_end];
        let null_pos = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let version_string = String::from_utf8_lossy(&raw[..null_pos]).to_string();

        // After version string (padded to 4): Flags (2) + Streams (2)
        let after_version = ver_start + version_len;
        if after_version + 4 > data.len() {
            return Err(format!(
                "Metadata stream count field truncated at {after_version:#x}"
            ));
        }
        // flags = r16(after_version);  // skip
        let stream_count = r16(after_version + 2);

        Ok(Self {
            signature,
            major_version,
            minor_version,
            version_string,
            stream_count,
        })
    }
}

// ---------------------------------------------------------------------------
// Top-level DotNet info
// ---------------------------------------------------------------------------

/// All .NET information extracted from a PE binary.
#[derive(Debug, Clone)]
pub struct DotNetInfo {
    /// The parsed `IMAGE_COR20_HEADER`.
    pub cor20: Cor20Header,
    /// Metadata root header (if metadata was successfully parsed).
    pub metadata: Option<MetadataRoot>,
    /// Is this a pure IL assembly (no native code)?
    pub is_pure_il: bool,
    /// Is this a mixed-mode (C++/CLI / IJW) assembly?
    pub is_mixed_mode: bool,
    /// Does the assembly have a strong name?
    pub is_strong_name_signed: bool,
    /// CLR runtime version required (e.g. "4.0").
    pub clr_version: String,
    /// Framework version from metadata root (e.g. "v4.0.30319").
    pub framework_version: Option<String>,
}

/// Parse .NET CLR header from a PE binary.
///
/// `clr_dir_rva` and `clr_dir_size` come from `DataDirectory[14]`.
#[must_use]
pub fn parse_dotnet(
    data: &[u8],
    sections: &[RvaSection],
    clr_dir_rva: u32,
    clr_dir_size: u32,
) -> Option<DotNetInfo> {
    if clr_dir_rva == 0 || clr_dir_size < 72 {
        return None;
    }

    let cor20_off = rva_to_file_offset(clr_dir_rva, sections)?;
    let cor20 = Cor20Header::parse(data, cor20_off).ok()?;

    // Optionally parse the metadata root
    let metadata = if cor20.meta_data.is_present() {
        rva_to_file_offset(cor20.meta_data.virtual_address, sections)
            .and_then(|meta_off| MetadataRoot::parse(data, meta_off).ok())
    } else {
        None
    };

    let framework_version = metadata.as_ref().map(|m| m.version_string.clone());
    let is_pure_il = cor20.is_il_only();
    let is_mixed_mode = cor20.is_mixed_mode();
    let is_strong_name_signed = cor20.is_strong_name_signed();
    let clr_version = cor20.clr_version_str();

    Some(DotNetInfo {
        cor20,
        metadata,
        is_pure_il,
        is_mixed_mode,
        is_strong_name_signed,
        clr_version,
        framework_version,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cor20(flags: u32, meta_rva: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 72];
        // cb = 72
        buf[0..4].copy_from_slice(&72u32.to_le_bytes());
        // major/minor = 4.0
        buf[4..6].copy_from_slice(&4u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        // MetaData RVA
        buf[8..12].copy_from_slice(&meta_rva.to_le_bytes());
        buf[12..16].copy_from_slice(&40u32.to_le_bytes()); // MetaData size
        // Flags
        buf[16..20].copy_from_slice(&flags.to_le_bytes());
        buf
    }

    #[test]
    fn test_cor20_parse_il_only() {
        let buf = make_cor20(COMIMAGE_FLAGS_ILONLY, 0);
        let hdr = Cor20Header::parse(&buf, 0).unwrap();
        assert_eq!(hdr.cb, 72);
        assert_eq!(hdr.major_runtime_version, 4);
        assert!(hdr.is_il_only());
        assert!(!hdr.requires_32bit());
        assert!(!hdr.is_mixed_mode());
    }

    #[test]
    fn test_cor20_parse_mixed_mode() {
        let mut buf = make_cor20(0, 0);
        // VTableFixups at offset 48 — set non-zero RVA + size
        buf[48..52].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[52..56].copy_from_slice(&0x20u32.to_le_bytes());
        let hdr = Cor20Header::parse(&buf, 0).unwrap();
        assert!(hdr.is_mixed_mode());
        assert!(!hdr.is_il_only());
    }

    #[test]
    fn test_cor20_parse_strong_name() {
        let buf = make_cor20(COMIMAGE_FLAGS_STRONGNAMESIGNED | COMIMAGE_FLAGS_ILONLY, 0);
        let hdr = Cor20Header::parse(&buf, 0).unwrap();
        assert!(hdr.is_strong_name_signed());
        assert!(hdr.is_il_only());
    }

    #[test]
    fn test_cor20_parse_too_short() {
        assert!(Cor20Header::parse(&[0u8; 10], 0).is_err());
    }

    #[test]
    fn test_cor20_parse_cb_too_small() {
        let mut buf = vec![0u8; 72];
        buf[0..4].copy_from_slice(&20u32.to_le_bytes()); // cb = 20, too small
        assert!(Cor20Header::parse(&buf, 0).is_err());
    }

    #[test]
    fn test_metadata_root_parse() {
        let version = b"v4.0.30319\0\0"; // 12 bytes padded to 4
        let mut buf = Vec::new();
        buf.extend_from_slice(&METADATA_SIGNATURE.to_le_bytes()); // 4
        buf.extend_from_slice(&1u16.to_le_bytes()); // major
        buf.extend_from_slice(&1u16.to_le_bytes()); // minor
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
        buf.extend_from_slice(&u32::try_from(version.len()).unwrap_or(u32::MAX).to_le_bytes()); // length
        buf.extend_from_slice(version);
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&5u16.to_le_bytes()); // streams = 5
        let root = MetadataRoot::parse(&buf, 0).unwrap();
        assert_eq!(root.signature, METADATA_SIGNATURE);
        assert_eq!(root.version_string, "v4.0.30319");
        assert_eq!(root.stream_count, 5);
    }

    #[test]
    fn test_metadata_root_bad_signature() {
        let buf = vec![0u8; 32];
        assert!(MetadataRoot::parse(&buf, 0).is_err());
    }

    #[test]
    fn test_parse_dotnet_no_dir() {
        let result = parse_dotnet(&[], &[], 0, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_dotnet_dir_too_small() {
        let result = parse_dotnet(&[], &[], 0x1000, 10);
        assert!(result.is_none());
    }

    #[test]
    fn test_cor20_data_directory_is_present() {
        let present = Cor20DataDirectory {
            virtual_address: 0x1000,
            size: 40,
        };
        let absent = Cor20DataDirectory::default();
        assert!(present.is_present());
        assert!(!absent.is_present());
    }

    #[test]
    fn test_cor20_clr_version_str() {
        let buf = make_cor20(COMIMAGE_FLAGS_ILONLY, 0);
        let hdr = Cor20Header::parse(&buf, 0).unwrap();
        assert_eq!(hdr.clr_version_str(), "4.0");
    }

    #[test]
    fn test_cor20_native_entrypoint_flag() {
        let buf = make_cor20(COMIMAGE_FLAGS_NATIVE_ENTRYPOINT, 0);
        let hdr = Cor20Header::parse(&buf, 0).unwrap();
        assert!(hdr.has_native_entrypoint());
    }

    #[test]
    fn test_cor20_32bit_flags() {
        let buf = make_cor20(
            COMIMAGE_FLAGS_32BITREQUIRED | COMIMAGE_FLAGS_32BITPREFERRED,
            0,
        );
        let hdr = Cor20Header::parse(&buf, 0).unwrap();
        assert!(hdr.requires_32bit());
        assert!(hdr.prefers_32bit());
    }
}
