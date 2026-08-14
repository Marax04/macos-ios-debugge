//! .NET assembly loader: CLI header, metadata root, stream headers.

use std::fmt;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AssemblyLoadError {
    #[error("data too short: need {need} have {have}")]
    TooShort { need: usize, have: usize },
    #[error("invalid PE magic at offset {0}")]
    InvalidPeMagic(usize),
    #[error("invalid metadata signature: expected BSJB got {0:#010x}")]
    InvalidMetadataSignature(u32),
    #[error("stream '{0}' not found")]
    StreamNotFound(String),
    #[error("invalid CLI header: {0}")]
    InvalidCliHeader(String),
}

// ── DotnetFlags ───────────────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DotnetFlags: u32 {
        const IL_ONLY            = 0x0000_0001;
        const BIT32_REQUIRED     = 0x0000_0002;
        const IL_LIBRARY         = 0x0000_0004;
        const STRONG_NAME_SIGNED = 0x0000_0008;
        const NATIVE_ENTRY_POINT = 0x0000_0010;
        const TRACK_DEBUG_DATA   = 0x0001_0000;
        const PREFER_32BIT       = 0x0002_0000;
    }
}

impl fmt::Display for DotnetFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── CliHeader ────────────────────────────────────────────────────────────────

/// `IMAGE_COR20_HEADER` (ECMA-335 §II.25.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliHeader {
    pub cb: u32,
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    pub metadata_rva: u32,
    pub metadata_size: u32,
    pub flags: u32,
    pub entry_point_token: u32,
    pub resources_rva: u32,
    pub resources_size: u32,
    pub strong_name_signature_rva: u32,
    pub strong_name_signature_size: u32,
}

impl CliHeader {
    pub fn parse(data: &[u8]) -> Result<Self, AssemblyLoadError> {
        ensure_len(data, 48, "CliHeader")?;
        Ok(Self {
            cb: rd32(data, 0),
            major_runtime_version: rd16(data, 4),
            minor_runtime_version: rd16(data, 6),
            metadata_rva: rd32(data, 8),
            metadata_size: rd32(data, 12),
            flags: rd32(data, 16),
            entry_point_token: rd32(data, 20),
            resources_rva: rd32(data, 24),
            resources_size: rd32(data, 28),
            strong_name_signature_rva: rd32(data, 32),
            strong_name_signature_size: rd32(data, 36),
        })
    }

    #[must_use] 
    pub const fn dotnet_flags(&self) -> DotnetFlags {
        DotnetFlags::from_bits_truncate(self.flags)
    }

    #[must_use] 
    pub const fn is_pure_il(&self) -> bool {
        (self.flags & DotnetFlags::IL_ONLY.bits()) != 0
    }

    #[must_use] 
    pub const fn has_strong_name(&self) -> bool {
        self.strong_name_signature_rva != 0 && self.strong_name_signature_size != 0
    }

    #[must_use] 
    pub fn runtime_version_string(&self) -> String {
        format!("{}.{}", self.major_runtime_version, self.minor_runtime_version)
    }
}

impl fmt::Display for CliHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CLR v{} metadata_rva={:#x} flags={:#x}",
            self.runtime_version_string(),
            self.metadata_rva,
            self.flags
        )
    }
}

// ── StreamHeader ─────────────────────────────────────────────────────────────

/// A metadata stream header entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHeader {
    pub offset: u32,
    pub size: u32,
    pub name: String,
}

impl StreamHeader {
    #[must_use] 
    pub fn data<'a>(&self, metadata_base: &'a [u8]) -> &'a [u8] {
        let start = self.offset as usize;
        let end = start + self.size as usize;
        if end <= metadata_base.len() {
            &metadata_base[start..end]
        } else {
            &[]
        }
    }
}

// ── MetadataRoot ──────────────────────────────────────────────────────────────

/// Parsed ECMA-335 metadata root (BSJB header).
#[derive(Debug, Clone)]
pub struct MetadataRoot {
    pub signature: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub version_string: String,
    pub flags: u16,
    pub num_streams: u16,
    pub stream_headers: Vec<StreamHeader>,
}

impl MetadataRoot {
    pub fn parse(data: &[u8]) -> Result<Self, AssemblyLoadError> {
        if data.len() < 16 {
            return Err(AssemblyLoadError::TooShort { need: 16, have: data.len() });
        }
        let signature = rd32(data, 0);
        if signature != 0x424A5342 {
            return Err(AssemblyLoadError::InvalidMetadataSignature(signature));
        }
        let major_version = rd16(data, 4);
        let minor_version = rd16(data, 6);
        let version_len = rd32(data, 12) as usize;
        let need_len = 16usize.saturating_add(version_len).saturating_add(4);
        if need_len > data.len() {
            return Err(AssemblyLoadError::TooShort { need: need_len, have: data.len() });
        }
        let version_bytes = &data[16..16 + version_len];
        let nul = version_bytes.iter().position(|&b| b == 0).unwrap_or(version_bytes.len());
        let version_string = String::from_utf8_lossy(&version_bytes[..nul]).into_owned();
        let after_version = 16 + version_len;
        let flags = rd16(data, after_version);
        let num_streams = rd16(data, after_version + 2);
        let mut pos = after_version + 4;
        let mut stream_headers = Vec::with_capacity(num_streams as usize);
        for _ in 0..num_streams {
            if pos + 8 > data.len() { break; }
            let offset = rd32(data, pos);
            let size = rd32(data, pos + 4);
            pos += 8;
            let name_start = pos;
            let mut name_end = pos;
            while name_end < data.len() && data[name_end] != 0 {
                name_end += 1;
            }
            let name = String::from_utf8_lossy(&data[name_start..name_end]).into_owned();
            let raw_len = name_end - name_start + 1;
            let padded = (raw_len + 3) & !3;
            pos += padded;
            stream_headers.push(StreamHeader { offset, size, name });
        }
        Ok(Self {
            signature,
            major_version,
            minor_version,
            version_string,
            flags,
            num_streams,
            stream_headers,
        })
    }

    #[must_use] 
    pub fn locate_stream(&self, name: &str) -> Option<&StreamHeader> {
        self.stream_headers.iter().find(|s| s.name == name)
    }
}

// ── AssemblyInfo ──────────────────────────────────────────────────────────────

/// High-level assembly identity information.
#[derive(Debug, Clone)]
pub struct AssemblyInfo {
    pub name: String,
    pub version: (u16, u16, u16, u16),
    pub culture: String,
    pub public_key_token: Option<[u8; 8]>,
    pub flags: u32,
}

impl AssemblyInfo {
    #[must_use] 
    pub fn version_string(&self) -> String {
        let (a, b, c, d) = self.version;
        format!("{a}.{b}.{c}.{d}")
    }
    #[must_use] 
    pub const fn is_strong_named(&self) -> bool {
        self.public_key_token.is_some()
    }
}

impl fmt::Display for AssemblyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, Version={}", self.name, self.version_string())
    }
}

// ── DotnetAssemblyLoader ─────────────────────────────────────────────────────

/// Loads and parses .NET assembly headers from raw PE bytes.
pub struct DotnetAssemblyLoader;

impl DotnetAssemblyLoader {
    #[must_use] 
    pub const fn new() -> Self { Self }

    /// Locate and parse the CLI header from a PE file.
    pub fn parse_cli_header(&self, data: &[u8]) -> Result<CliHeader, AssemblyLoadError> {
        let pe_off = self.find_pe_offset(data)?;
        let magic_off = pe_off + 24;
        if magic_off + 2 > data.len() {
            return Err(AssemblyLoadError::TooShort { need: magic_off + 2, have: data.len() });
        }
        let magic = rd16(data, magic_off);
        let is_64 = magic == 0x020B;
        let clr_dir_off = if is_64 {
            pe_off + 24 + 112 + 14 * 8
        } else {
            pe_off + 24 + 96 + 14 * 8
        };
        if clr_dir_off + 8 > data.len() {
            return Err(AssemblyLoadError::TooShort { need: clr_dir_off + 8, have: data.len() });
        }
        let clr_rva = rd32(data, clr_dir_off);
        let sections = self.parse_pe_sections(data, pe_off);
        let Some(clr_off) = rva_to_offset(clr_rva, &sections) else {
            return Err(AssemblyLoadError::InvalidCliHeader(format!("can't resolve CLR RVA {clr_rva:#x}")));
        };
        if clr_off + 48 > data.len() {
            return Err(AssemblyLoadError::TooShort { need: clr_off + 48, have: data.len() });
        }
        CliHeader::parse(&data[clr_off..])
    }

    /// Parse the metadata root from a byte slice that starts at the BSJB magic.
    pub fn parse_metadata_root(&self, metadata_bytes: &[u8]) -> Result<MetadataRoot, AssemblyLoadError> {
        MetadataRoot::parse(metadata_bytes)
    }

    /// Parse stream headers from an already-parsed `MetadataRoot`.
    #[must_use] 
    pub fn parse_stream_headers<'a>(&self, root: &'a MetadataRoot) -> &'a [StreamHeader] {
        &root.stream_headers
    }

    /// Locate a stream by name in the root.
    #[must_use] 
    pub fn locate_stream<'a>(&self, root: &'a MetadataRoot, name: &str) -> Option<&'a StreamHeader> {
        root.locate_stream(name)
    }

    /// Find the PE signature offset from a PE binary.
    fn find_pe_offset(&self, data: &[u8]) -> Result<usize, AssemblyLoadError> {
        if data.len() < 64 {
            return Err(AssemblyLoadError::TooShort { need: 64, have: data.len() });
        }
        let pe_off = rd32(data, 60) as usize;
        if pe_off + 4 > data.len() {
            return Err(AssemblyLoadError::TooShort { need: pe_off + 4, have: data.len() });
        }
        if &data[pe_off..pe_off + 4] != b"PE\x00\x00" {
            return Err(AssemblyLoadError::InvalidPeMagic(pe_off));
        }
        Ok(pe_off)
    }

    fn parse_pe_sections(&self, data: &[u8], pe_off: usize) -> Vec<(u32, u32, u32, u32)> {
        // Returns (va, vs, raw_off, raw_size)
        if pe_off + 6 > data.len() { return vec![]; }
        let num = rd16(data, pe_off + 6) as usize;
        let opt_size = rd16(data, pe_off + 20) as usize;
        let sect_start = pe_off + 24 + opt_size;
        let mut out = Vec::with_capacity(num);
        for i in 0..num {
            let off = sect_start + i * 40;
            if off + 40 > data.len() { break; }
            let vs = rd32(data, off + 8);
            let va = rd32(data, off + 12);
            let raw_sz = rd32(data, off + 16);
            let raw_off = rd32(data, off + 20);
            out.push((va, vs, raw_off, raw_sz));
        }
        out
    }

    /// Find metadata root bytes from a raw PE binary.
    #[must_use] 
    pub fn find_metadata_root<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        let pos = data.windows(4).position(|w| w == b"BSJB")?;
        Some(&data[pos..])
    }
}

impl Default for DotnetAssemblyLoader {
    fn default() -> Self { Self::new() }
}

fn rva_to_offset(rva: u32, sections: &[(u32, u32, u32, u32)]) -> Option<usize> {
    for &(va, vs, raw_off, _) in sections {
        if rva >= va && rva < va.saturating_add(vs) {
            let delta = rva - va;
            let file_off = raw_off.checked_add(delta)?;
            return Some(file_off as usize);
        }
    }
    None
}

fn rd16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() { return 0; }
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn rd32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() { return 0; }
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

const fn ensure_len(data: &[u8], need: usize, _ctx: &str) -> Result<(), AssemblyLoadError> {
    if data.len() < need {
        Err(AssemblyLoadError::TooShort { need, have: data.len() })
    } else {
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn bsjb_header(version: &str) -> Vec<u8> {
        let ver_bytes = version.as_bytes();
        let ver_len = (ver_bytes.len() + 3) & !3;
        // signature(4)+major(2)+minor(2)+reserved(4)+version_len(4)+version(ver_len)+flags(2)+num_streams(2)
        let mut v = Vec::new();
        v.extend_from_slice(b"BSJB");
        v.extend_from_slice(&1u16.to_le_bytes()); // major
        v.extend_from_slice(&1u16.to_le_bytes()); // minor
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved
        v.extend_from_slice(&(ver_len as u32).to_le_bytes()); // version length
        v.extend(ver_bytes.iter().copied());
        v.extend(std::iter::repeat(0u8).take(ver_len - ver_bytes.len())); // padding
        v.extend_from_slice(&0u16.to_le_bytes()); // flags
        v.extend_from_slice(&0u16.to_le_bytes()); // num_streams
        v
    }

    #[test]
    fn test_metadata_root_signature() {
        let data = bsjb_header("v4.0.30319");
        let root = MetadataRoot::parse(&data).unwrap();
        assert_eq!(root.signature, 0x424A5342);
    }

    #[test]
    fn test_metadata_root_version_string() {
        let data = bsjb_header("v4.0.30319");
        let root = MetadataRoot::parse(&data).unwrap();
        assert_eq!(root.version_string, "v4.0.30319");
    }

    #[test]
    fn test_metadata_root_invalid_signature() {
        let mut data = bsjb_header("v2.0");
        data[0] = 0xDE;
        let err = MetadataRoot::parse(&data).unwrap_err();
        assert!(matches!(err, AssemblyLoadError::InvalidMetadataSignature(_)));
    }

    #[test]
    fn test_metadata_root_num_streams_zero() {
        let data = bsjb_header("v4.0");
        let root = MetadataRoot::parse(&data).unwrap();
        assert_eq!(root.num_streams, 0);
    }

    #[test]
    fn test_metadata_root_stream_parsing() {
        let mut base = bsjb_header("v1.0");
        // Patch num_streams to 1
        let ns_off = base.len() - 2;
        base[ns_off] = 1;
        base[ns_off + 1] = 0;
        // Append stream header: offset=0, size=16, name="#~\0\0"
        base.extend_from_slice(&0u32.to_le_bytes()); // offset
        base.extend_from_slice(&16u32.to_le_bytes()); // size
        base.extend_from_slice(b"#~\x00\x00"); // name padded
        let root = MetadataRoot::parse(&base).unwrap();
        assert_eq!(root.stream_headers.len(), 1);
        assert_eq!(root.stream_headers[0].name, "#~");
    }

    #[test]
    fn test_locate_stream_found() {
        let mut base = bsjb_header("v1.0");
        let ns_off = base.len() - 2;
        base[ns_off] = 1;
        base.extend_from_slice(&4u32.to_le_bytes());
        base.extend_from_slice(&8u32.to_le_bytes());
        base.extend_from_slice(b"#Blob\x00\x00\x00"); // 8 bytes
        let root = MetadataRoot::parse(&base).unwrap();
        assert!(root.locate_stream("#Blob").is_some());
    }

    #[test]
    fn test_locate_stream_not_found() {
        let data = bsjb_header("v1.0");
        let root = MetadataRoot::parse(&data).unwrap();
        assert!(root.locate_stream("#~").is_none());
    }

    #[test]
    fn test_cli_header_parse() {
        let mut h = vec![0u8; 72];
        // cb = 72
        h[0..4].copy_from_slice(&72u32.to_le_bytes());
        // major = 2, minor = 5
        h[4..6].copy_from_slice(&2u16.to_le_bytes());
        h[6..8].copy_from_slice(&5u16.to_le_bytes());
        // metadata_rva = 0x2000, metadata_size = 1024
        h[8..12].copy_from_slice(&0x2000u32.to_le_bytes());
        h[12..16].copy_from_slice(&1024u32.to_le_bytes());
        // flags = IL_ONLY | STRONG_NAME_SIGNED
        h[16..20].copy_from_slice(&(DotnetFlags::IL_ONLY | DotnetFlags::STRONG_NAME_SIGNED).bits().to_le_bytes());
        let cli = CliHeader::parse(&h).unwrap();
        assert_eq!(cli.cb, 72);
        assert_eq!(cli.major_runtime_version, 2);
        assert_eq!(cli.minor_runtime_version, 5);
        assert!(cli.is_pure_il());
    }

    #[test]
    fn test_cli_header_runtime_version_string() {
        let mut h = vec![0u8; 48];
        h[4..6].copy_from_slice(&4u16.to_le_bytes());
        h[6..8].copy_from_slice(&0u16.to_le_bytes());
        let cli = CliHeader::parse(&h).unwrap();
        assert_eq!(cli.runtime_version_string(), "4.0");
    }

    #[test]
    fn test_cli_header_no_strong_name() {
        let h = vec![0u8; 48];
        let cli = CliHeader::parse(&h).unwrap();
        assert!(!cli.has_strong_name());
    }

    #[test]
    fn test_cli_header_too_short() {
        let h = vec![0u8; 10];
        assert!(CliHeader::parse(&h).is_err());
    }

    #[test]
    fn test_dotnet_flags_il_only() {
        let flags = DotnetFlags::IL_ONLY | DotnetFlags::PREFER_32BIT;
        assert!(flags.contains(DotnetFlags::IL_ONLY));
        assert!(flags.contains(DotnetFlags::PREFER_32BIT));
    }

    #[test]
    fn test_assembly_info_version_string() {
        let ai = AssemblyInfo {
            name: "MyLib".to_string(),
            version: (1, 2, 3, 4),
            culture: "neutral".to_string(),
            public_key_token: None,
            flags: 0,
        };
        assert_eq!(ai.version_string(), "1.2.3.4");
        assert!(!ai.is_strong_named());
    }

    #[test]
    fn test_assembly_info_strong_named() {
        let ai = AssemblyInfo {
            name: "StrongLib".to_string(),
            version: (2, 0, 0, 0),
            culture: String::new(),
            public_key_token: Some([0xB7, 0x7A, 0x5C, 0x56, 0x19, 0x34, 0xE0, 0x89]),
            flags: 0,
        };
        assert!(ai.is_strong_named());
    }

    #[test]
    fn test_loader_find_metadata_root() {
        let mut data = vec![0u8; 32];
        data.extend_from_slice(b"BSJB");
        data.extend_from_slice(&[0u8; 16]);
        let loader = DotnetAssemblyLoader::new();
        let root_slice = loader.find_metadata_root(&data);
        assert!(root_slice.is_some());
        assert_eq!(&root_slice.unwrap()[..4], b"BSJB");
    }

    #[test]
    fn test_loader_no_metadata() {
        let data = vec![0u8; 64];
        let loader = DotnetAssemblyLoader::new();
        assert!(loader.find_metadata_root(&data).is_none());
    }

    #[test]
    fn test_rd32_helpers() {
        let data = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(rd32(&data, 0), 0x12345678);
    }
}
