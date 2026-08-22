//! UEFI firmware analysis.
//!
//! Parses UEFI Firmware Volumes (FV), Firmware File System (FFS) file entries,
//! sections, and known GUIDs to identify PEI modules, DXE drivers, and
//! firmware volumes by type.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UefiError {
    InvalidFvSignature { got: Vec<u8> },
    TruncatedData { offset: usize, needed: usize },
    InvalidFfsType(u8),
    InvalidSectionType(u8),
    BadAlignment { offset: usize, align: usize },
    FvTooSmall { size: u64 },
    UnknownGuid([u8; 16]),
    CyclicFv,
    InvalidChecksum { expected: u8, actual: u8 },
    TooManyFiles(usize),
    InvalidDepex,
}

impl std::fmt::Display for UefiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFvSignature { got } => write!(f, "invalid FV signature: {got:?}"),
            Self::TruncatedData { offset, needed } => write!(
                f,
                "truncated UEFI data at offset {offset:#x}, need {needed}"
            ),
            Self::InvalidFfsType(t) => write!(f, "invalid FFS file type {t:#04x}"),
            Self::InvalidSectionType(t) => write!(f, "invalid section type {t:#04x}"),
            Self::BadAlignment { offset, align } => {
                write!(f, "offset {offset:#x} not aligned to {align}")
            }
            Self::FvTooSmall { size } => write!(f, "FV size too small: {size:#x}"),
            Self::UnknownGuid(g) => write!(
                f,
                "unknown GUID {:08x}-{:04x}-{:04x}-...",
                u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
                u16::from_le_bytes([g[4], g[5]]),
                u16::from_le_bytes([g[6], g[7]]),
            ),
            Self::CyclicFv => write!(f, "cyclic firmware volume reference"),
            Self::InvalidChecksum { expected, actual } => write!(
                f,
                "FFS checksum: expected {expected:#04x}, actual {actual:#04x}"
            ),
            Self::TooManyFiles(n) => write!(f, "too many FFS files: {n}"),
            Self::InvalidDepex => write!(f, "invalid DEPEX section"),
        }
    }
}

impl std::error::Error for UefiError {}

// ---------------------------------------------------------------------------
// GUID utilities
// ---------------------------------------------------------------------------

pub type Guid = [u8; 16];

/// Format a GUID in the standard `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` form.
#[must_use]
pub fn format_guid(g: &Guid) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15],
    )
}

// ---------------------------------------------------------------------------
// GuidDatabase
// ---------------------------------------------------------------------------

/// Known UEFI GUIDs with friendly names.
#[derive(Debug, Default)]
pub struct GuidDatabase {
    entries: HashMap<[u8; 16], String>,
}

impl GuidDatabase {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the standard set of well-known UEFI GUIDs.
    #[must_use]
    pub fn load_standard() -> Self {
        let mut db = Self::new();
        // FV filesystem GUIDs
        db.insert_str(
            "8c8ce578-8a3d-4f1c-9935-896185c32dd3",
            "EFI_FIRMWARE_FILE_SYSTEM2_GUID",
        );
        db.insert_str(
            "5473c07a-3dcb-4dca-bd6f-1e9689e7349a",
            "EFI_FIRMWARE_FILE_SYSTEM3_GUID",
        );
        db.insert_str(
            "7a9354d9-0468-444a-81ce-0bf617d890df",
            "EFI_SYSTEM_NV_DATA_FV_GUID",
        );
        // Module type GUIDs
        db.insert_str("1b45cc0a-156a-428a-62af-49864db10717", "SEC_CORE");
        db.insert_str("1b578c0a-f86b-4b34-9bdb-8b3b9e3dd3b9", "PEI_CORE");
        db.insert_str("d6a2cb7f-6a18-4e2f-b43b-9920a733700a", "DXE_CORE");
        db.insert_str("fc510ee7-ffdc-11d4-bd41-0080c73c8881", "PEIM_MRC");
        db.insert_str("a210f973-229d-4f4d-aa37-9895e6c9eaba", "DXE_DRIVER_EXAMPLE");
        db
    }

    pub fn insert(&mut self, guid: Guid, name: impl Into<String>) {
        self.entries.insert(guid, name.into());
    }

    fn insert_str(&mut self, guid_str: &str, name: &str) {
        if let Some(guid) = parse_guid_str(guid_str) {
            self.insert(guid, name);
        }
    }

    #[must_use]
    pub fn lookup(&self, guid: &Guid) -> Option<&str> {
        self.entries.get(guid).map(std::string::String::as_str)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn parse_guid_str(s: &str) -> Option<Guid> {
    // Parse "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return None;
    }
    let p0 = u32::from_str_radix(parts[0], 16).ok()?;
    let p1 = u16::from_str_radix(parts[1], 16).ok()?;
    let p2 = u16::from_str_radix(parts[2], 16).ok()?;
    let p3 = u16::from_str_radix(parts[3], 16).ok()?;
    let p4_str = parts[4];
    if p4_str.len() != 12 {
        return None;
    }
    let p4_bytes: Option<Vec<u8>> = (0..6)
        .map(|i| u8::from_str_radix(&p4_str[i * 2..i * 2 + 2], 16).ok())
        .collect();
    let p4_bytes = p4_bytes?;
    let mut g = [0u8; 16];
    g[0..4].copy_from_slice(&p0.to_le_bytes());
    g[4..6].copy_from_slice(&p1.to_le_bytes());
    g[6..8].copy_from_slice(&p2.to_le_bytes());
    g[8..10].copy_from_slice(&p3.to_be_bytes());
    g[10..16].copy_from_slice(&p4_bytes);
    Some(g)
}

// ---------------------------------------------------------------------------
// EfiFfs (FFS file)
// ---------------------------------------------------------------------------

/// FFS file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfsFileType {
    Raw = 0x01,
    Freeform = 0x02,
    SecurityCore = 0x03,
    PeiCore = 0x04,
    DxeCore = 0x05,
    Peim = 0x06,
    Driver = 0x07,
    CombinedPeimDriver = 0x08,
    Application = 0x09,
    Smm = 0x0A,
    VolumeImage = 0x0B,
    CombinedSmm = 0x0C,
    SmmCore = 0x0D,
    OemMin = 0xC0,
    OemMax = 0xDF,
    DebugMin = 0xE0,
    DebugMax = 0xEF,
    FfsPad = 0xF0,
}

impl FfsFileType {
    pub const fn from_u8(v: u8) -> Result<Self, UefiError> {
        match v {
            0x01 => Ok(Self::Raw),
            0x02 => Ok(Self::Freeform),
            0x03 => Ok(Self::SecurityCore),
            0x04 => Ok(Self::PeiCore),
            0x05 => Ok(Self::DxeCore),
            0x06 => Ok(Self::Peim),
            0x07 => Ok(Self::Driver),
            0x08 => Ok(Self::CombinedPeimDriver),
            0x09 => Ok(Self::Application),
            0x0A => Ok(Self::Smm),
            0x0B => Ok(Self::VolumeImage),
            0x0C => Ok(Self::CombinedSmm),
            0x0D => Ok(Self::SmmCore),
            0xF0 => Ok(Self::FfsPad),
            _ => Err(UefiError::InvalidFfsType(v)),
        }
    }

    #[must_use]
    pub const fn is_executable(self) -> bool {
        matches!(
            self,
            Self::SecurityCore
                | Self::PeiCore
                | Self::DxeCore
                | Self::Peim
                | Self::Driver
                | Self::CombinedPeimDriver
                | Self::Application
                | Self::Smm
                | Self::SmmCore
        )
    }
}

// ---------------------------------------------------------------------------
// EfiHiiPackage — Human Interface Infrastructure (HII) database
// ---------------------------------------------------------------------------

/// Type of an HII package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HiiPackageType {
    All = 0x00,
    Guid = 0x01,
    Forms = 0x02,
    Strings = 0x04,
    Fonts = 0x05,
    Images = 0x06,
    SimpleFonts = 0x07,
    DevicePath = 0x08,
    KeyboardLayout = 0x09,
    End = 0xDF,
    SystemBegin = 0xE0,
    SystemEnd = 0xFF,
}

impl HiiPackageType {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Self::All,
            0x01 => Self::Guid,
            0x02 => Self::Forms,
            0x04 => Self::Strings,
            0x05 => Self::Fonts,
            0x06 => Self::Images,
            0x07 => Self::SimpleFonts,
            0x08 => Self::DevicePath,
            0x09 => Self::KeyboardLayout,
            0xDF => Self::End,
            _ if v >= 0xE0 => Self::SystemBegin,
            _ => Self::All,
        }
    }

    #[must_use]
    pub const fn is_user_visible(self) -> bool {
        matches!(
            self,
            Self::Forms | Self::Strings | Self::Images | Self::SimpleFonts
        )
    }
}

/// One HII package.
#[derive(Debug, Clone)]
pub struct HiiPackage {
    pub pkg_type: HiiPackageType,
    pub size: u32,
    pub data: Vec<u8>,
}

impl HiiPackage {
    #[must_use]
    pub const fn new(pkg_type: HiiPackageType, data: Vec<u8>) -> Self {
        let size = data.len() as u32 + 4;
        Self {
            pkg_type,
            size,
            data,
        }
    }
}

// ---------------------------------------------------------------------------
// EfiFvIntegrity — checksum and signature verification
// ---------------------------------------------------------------------------

/// Result of firmware volume integrity verification.
#[derive(Debug, Clone)]
pub struct EfiFvIntegrityResult {
    pub header_checksum_valid: bool,
    pub expected_checksum: u16,
    pub actual_checksum: u16,
    pub signature_present: bool,
}

impl EfiFvIntegrityResult {
    #[must_use]
    pub fn verify_header(hdr_data: &[u8]) -> Self {
        if hdr_data.len() < 56 {
            return Self {
                header_checksum_valid: false,
                expected_checksum: 0,
                actual_checksum: 0,
                signature_present: false,
            };
        }
        // Sum all bytes in the header (should be 0 mod 256 for EFI checksum)
        let sum: u32 = hdr_data.iter().take(56).map(|&b| u32::from(b)).sum();
        let actual = (sum & 0xffff) as u16;
        let stored = u16::from_le_bytes(hdr_data[0x32..0x34].try_into().unwrap_or([0, 0]));
        Self {
            header_checksum_valid: actual == 0 || stored != 0,
            expected_checksum: 0,
            actual_checksum: actual,
            signature_present: &hdr_data[0x28..0x2c] == FV_SIGNATURE,
        }
    }

    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.header_checksum_valid && self.signature_present
    }
}

/// One FFS file entry.
#[derive(Debug, Clone)]
pub struct EfiFfs {
    pub guid: Guid,
    pub file_type: FfsFileType,
    pub attributes: u8,
    pub size: u32,
    pub sections: Vec<EfiSection>,
    pub data_offset: usize,
}

impl EfiFfs {
    #[must_use]
    pub const fn new(guid: Guid, file_type: FfsFileType, size: u32) -> Self {
        Self {
            guid,
            file_type,
            attributes: 0,
            size,
            sections: Vec::new(),
            data_offset: 0,
        }
    }

    #[must_use]
    pub fn guid_str(&self) -> String {
        format_guid(&self.guid)
    }

    #[must_use]
    pub fn find_section(&self, sec_type: EfiSectionType) -> Option<&EfiSection> {
        self.sections.iter().find(|s| s.section_type == sec_type)
    }

    /// `true` if this file contains a PE/COFF image section.
    #[must_use]
    pub fn has_pe(&self) -> bool {
        self.find_section(EfiSectionType::Pe32).is_some()
            || self.find_section(EfiSectionType::Te).is_some()
    }
}

// ---------------------------------------------------------------------------
// EfiSection
// ---------------------------------------------------------------------------

/// EFI section type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EfiSectionType {
    All = 0x00,
    Compression = 0x01,
    GuidDefined = 0x02,
    Disposable = 0x03,
    Pe32 = 0x10,
    Pic = 0x11,
    Te = 0x12,
    DxeDepex = 0x13,
    Version = 0x14,
    UserInterface = 0x15,
    Compatibility16 = 0x16,
    FirmwareVolume = 0x17,
    FreeformSubtype = 0x18,
    Raw = 0x19,
    PeiDepex = 0x1B,
    SmmDepex = 0x1C,
}

impl EfiSectionType {
    pub const fn from_u8(v: u8) -> Result<Self, UefiError> {
        match v {
            0x00 => Ok(Self::All),
            0x01 => Ok(Self::Compression),
            0x02 => Ok(Self::GuidDefined),
            0x10 => Ok(Self::Pe32),
            0x11 => Ok(Self::Pic),
            0x12 => Ok(Self::Te),
            0x13 => Ok(Self::DxeDepex),
            0x14 => Ok(Self::Version),
            0x15 => Ok(Self::UserInterface),
            0x16 => Ok(Self::Compatibility16),
            0x17 => Ok(Self::FirmwareVolume),
            0x18 => Ok(Self::FreeformSubtype),
            0x19 => Ok(Self::Raw),
            0x1B => Ok(Self::PeiDepex),
            0x1C => Ok(Self::SmmDepex),
            _ => Err(UefiError::InvalidSectionType(v)),
        }
    }

    #[must_use]
    pub const fn is_executable(self) -> bool {
        matches!(self, Self::Pe32 | Self::Te | Self::Pic)
    }

    #[must_use]
    pub const fn is_dependency(self) -> bool {
        matches!(self, Self::DxeDepex | Self::PeiDepex | Self::SmmDepex)
    }
}

/// One section within an FFS file.
#[derive(Debug, Clone)]
pub struct EfiSection {
    pub section_type: EfiSectionType,
    pub size: u32,
    pub data_offset: usize,
    pub raw_data: Vec<u8>,
}

impl EfiSection {
    #[must_use]
    pub const fn new(section_type: EfiSectionType, raw_data: Vec<u8>) -> Self {
        let size = raw_data.len() as u32;
        Self {
            section_type,
            size,
            data_offset: 0,
            raw_data,
        }
    }
}

// ---------------------------------------------------------------------------
// EfiFirmwareVolume
// ---------------------------------------------------------------------------

/// FV signature bytes.
pub const FV_SIGNATURE: &[u8] = b"_FVH";

/// Parsed EFI Firmware Volume.
#[derive(Debug, Clone)]
pub struct EfiFirmwareVolume {
    pub guid: Guid,
    pub fv_length: u64,
    pub signature: [u8; 4],
    pub attributes: u32,
    pub header_length: u16,
    pub checksum: u16,
    pub ext_header_offset: u16,
    pub revision: u8,
    pub files: Vec<EfiFfs>,
    pub offset_in_image: usize,
}

impl EfiFirmwareVolume {
    pub const MIN_SIZE: usize = 0x48;

    pub fn parse(data: &[u8], offset: usize) -> Result<Self, UefiError> {
        if data.len() < Self::MIN_SIZE {
            return Err(UefiError::TruncatedData {
                offset,
                needed: Self::MIN_SIZE,
            });
        }
        // Signature is at offset 40 (0x28) in the FV header
        let sig_off = 0x28;
        if sig_off + 4 > data.len() {
            return Err(UefiError::TruncatedData {
                offset: sig_off,
                needed: 4,
            });
        }
        if &data[sig_off..sig_off + 4] != FV_SIGNATURE {
            return Err(UefiError::InvalidFvSignature {
                got: data[sig_off..sig_off + 4].to_vec(),
            });
        }
        let r8 = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
        let r4 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        let r2 = |o: usize| u16::from_le_bytes(data[o..o + 2].try_into().unwrap());

        let mut guid = [0u8; 16];
        guid.copy_from_slice(&data[..16]);

        let fv_length = r8(16 + 8); // FV length is at offset 0x20 in the header
        let attributes = r4(0x2c);
        let header_length = r2(0x30);
        let checksum = r2(0x32);
        let ext_header_offset = r2(0x34);
        let revision = data[0x37];

        let mut sig = [0u8; 4];
        sig.copy_from_slice(&data[sig_off..sig_off + 4]);

        Ok(Self {
            guid,
            fv_length,
            signature: sig,
            attributes,
            header_length,
            checksum,
            ext_header_offset,
            revision,
            files: Vec::new(),
            offset_in_image: offset,
        })
    }

    /// Find a file by GUID.
    #[must_use]
    pub fn find_file(&self, guid: &Guid) -> Option<&EfiFfs> {
        self.files.iter().find(|f| &f.guid == guid)
    }

    /// All executable files.
    #[must_use]
    pub fn executable_files(&self) -> Vec<&EfiFfs> {
        self.files
            .iter()
            .filter(|f| f.file_type.is_executable())
            .collect()
    }

    /// All files with PE sections.
    #[must_use]
    pub fn pe_files(&self) -> Vec<&EfiFfs> {
        self.files.iter().filter(|f| f.has_pe()).collect()
    }
}

// ---------------------------------------------------------------------------
// EfiDepex — DEPEX expression parser
// ---------------------------------------------------------------------------

/// One token in a DEPEX (dependency expression) program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepexToken {
    /// PUSH <GUID>: push a protocol GUID
    Push(Guid),
    /// AND: logical AND of top two stack values
    And,
    /// OR: logical OR of top two stack values
    Or,
    /// NOT: logical NOT of top stack value
    Not,
    /// TRUE: push true
    True,
    /// FALSE: push false
    False,
    /// END: end of expression
    End,
}

/// Parsed DEPEX expression.
#[derive(Debug, Clone, Default)]
pub struct EfiDepex {
    pub tokens: Vec<DepexToken>,
}

impl EfiDepex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a DEPEX section from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, UefiError> {
        let mut tokens = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let opcode = data[pos];
            pos += 1;
            match opcode {
                0x02 => {
                    // PUSH <GUID>
                    if pos + 16 > data.len() {
                        return Err(UefiError::TruncatedData {
                            offset: pos,
                            needed: 16,
                        });
                    }
                    let mut guid = [0u8; 16];
                    guid.copy_from_slice(&data[pos..pos + 16]);
                    pos += 16;
                    tokens.push(DepexToken::Push(guid));
                }
                0x03 => tokens.push(DepexToken::And),
                0x04 => tokens.push(DepexToken::Or),
                0x05 => tokens.push(DepexToken::Not),
                0x06 => tokens.push(DepexToken::True),
                0x07 => tokens.push(DepexToken::False),
                0x08 => {
                    tokens.push(DepexToken::End);
                    break;
                }
                _ => return Err(UefiError::InvalidDepex),
            }
        }
        Ok(Self { tokens })
    }

    /// All GUIDs referenced in PUSH operations.
    #[must_use]
    pub fn referenced_guids(&self) -> Vec<&Guid> {
        self.tokens
            .iter()
            .filter_map(|t| {
                if let DepexToken::Push(g) = t {
                    Some(g)
                } else {
                    None
                }
            })
            .collect()
    }

    /// `true` if the DEPEX always evaluates to true (single TRUE token).
    #[must_use]
    pub fn is_always_true(&self) -> bool {
        self.tokens.iter().any(|t| matches!(t, DepexToken::True))
            && !self.tokens.iter().any(|t| {
                matches!(
                    t,
                    DepexToken::Push(_) | DepexToken::And | DepexToken::Or | DepexToken::Not
                )
            })
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.tokens.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

// ---------------------------------------------------------------------------
// EfiFvBlock — Firmware Volume Block Map
// ---------------------------------------------------------------------------

/// One entry in the firmware volume block map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EfiFvBlockMapEntry {
    /// Number of consecutive blocks with this size.
    pub num_blocks: u32,
    /// Size of each block in bytes.
    pub block_length: u32,
}

impl EfiFvBlockMapEntry {
    #[must_use]
    pub const fn new(num_blocks: u32, block_length: u32) -> Self {
        Self {
            num_blocks,
            block_length,
        }
    }
    /// Total bytes covered by this block map entry.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.num_blocks as u64 * self.block_length as u64
    }
    /// `true` if this is the terminating entry (all zeros).
    #[must_use]
    pub const fn is_terminator(&self) -> bool {
        self.num_blocks == 0 && self.block_length == 0
    }
}

/// Parse a firmware volume block map from raw bytes.
#[must_use]
pub fn parse_fv_block_map(data: &[u8]) -> Vec<EfiFvBlockMapEntry> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos + 8 <= data.len() {
        let num = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        let len = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap());
        let entry = EfiFvBlockMapEntry::new(num, len);
        let term = entry.is_terminator();
        entries.push(entry);
        pos += 8;
        if term {
            break;
        }
    }
    entries
}

// ---------------------------------------------------------------------------
// PeiModule
// ---------------------------------------------------------------------------

/// A PEI-phase module.
#[derive(Debug, Clone)]
pub struct PeiModule {
    pub name: String,
    pub guid: Guid,
    pub entry_point: u64,
    pub load_address: u64,
    pub depex_guids: Vec<Guid>,
    pub is_ppi_installed: bool,
}

impl PeiModule {
    pub fn new(name: impl Into<String>, guid: Guid) -> Self {
        Self {
            name: name.into(),
            guid,
            entry_point: 0,
            load_address: 0,
            depex_guids: Vec::new(),
            is_ppi_installed: false,
        }
    }

    #[must_use]
    pub const fn dependency_count(&self) -> usize {
        self.depex_guids.len()
    }
}

// ---------------------------------------------------------------------------
// DxeDriver
// ---------------------------------------------------------------------------

/// A DXE-phase driver.
#[derive(Debug, Clone)]
pub struct DxeDriver {
    pub name: String,
    pub guid: Guid,
    pub entry_point: u64,
    pub depex_guids: Vec<Guid>,
    pub protocol_guids: Vec<Guid>,
    pub is_smm: bool,
}

impl DxeDriver {
    pub fn new(name: impl Into<String>, guid: Guid) -> Self {
        Self {
            name: name.into(),
            guid,
            entry_point: 0,
            depex_guids: Vec::new(),
            protocol_guids: Vec::new(),
            is_smm: false,
        }
    }

    #[must_use]
    pub const fn protocol_count(&self) -> usize {
        self.protocol_guids.len()
    }
    #[must_use]
    pub const fn is_smm_driver(&self) -> bool {
        self.is_smm
    }
}

// ---------------------------------------------------------------------------
// EfiVariableStore — NVRAM variable store analysis
// ---------------------------------------------------------------------------

/// Attribute flags for an EFI variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EfiVariableAttributes(pub u32);

impl EfiVariableAttributes {
    pub const NON_VOLATILE: u32 = 0x0000_0001;
    pub const BOOT_SERVICES: u32 = 0x0000_0002;
    pub const RUNTIME_ACCESS: u32 = 0x0000_0004;
    pub const HARDWARE_ERROR_RECORD: u32 = 0x0000_0008;
    pub const AUTH_WRITE_ACCESS: u32 = 0x0000_0010;
    pub const TIME_BASED_AUTH: u32 = 0x0000_0020;
    pub const APPEND_WRITE: u32 = 0x0000_0040;

    #[must_use]
    pub const fn is_non_volatile(self) -> bool {
        self.0 & Self::NON_VOLATILE != 0
    }
    #[must_use]
    pub const fn is_runtime(self) -> bool {
        self.0 & Self::RUNTIME_ACCESS != 0
    }
    #[must_use]
    pub const fn is_authenticated(self) -> bool {
        self.0 & Self::TIME_BASED_AUTH != 0
    }
}

/// One NVRAM variable.
#[derive(Debug, Clone)]
pub struct EfiVariable {
    pub name: String,
    pub guid: Guid,
    pub attributes: EfiVariableAttributes,
    pub data: Vec<u8>,
}

impl EfiVariable {
    pub fn new(name: impl Into<String>, guid: Guid, attrs: u32, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            guid,
            attributes: EfiVariableAttributes(attrs),
            data,
        }
    }

    #[must_use]
    pub const fn data_size(&self) -> usize {
        self.data.len()
    }
    #[must_use]
    pub fn is_secure_boot_related(&self) -> bool {
        self.name.contains("Secure") || self.name.contains("PK") || self.name.contains("KEK")
    }
}

/// A parsed NVRAM variable store.
#[derive(Debug, Default)]
pub struct EfiVariableStore {
    pub variables: Vec<EfiVariable>,
}

impl EfiVariableStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, v: EfiVariable) {
        self.variables.push(v);
    }

    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&EfiVariable> {
        self.variables.iter().find(|v| v.name == name)
    }

    #[must_use]
    pub fn runtime_variables(&self) -> Vec<&EfiVariable> {
        self.variables
            .iter()
            .filter(|v| v.attributes.is_runtime())
            .collect()
    }

    #[must_use]
    pub fn secure_boot_variables(&self) -> Vec<&EfiVariable> {
        self.variables
            .iter()
            .filter(|v| v.is_secure_boot_related())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// UefiSecurityReport — high-level security assessment
// ---------------------------------------------------------------------------

/// Security assessment result for a UEFI image.
#[derive(Debug, Clone)]
pub struct UefiSecurityReport {
    pub has_secure_boot_variables: bool,
    pub smm_driver_count: usize,
    pub total_drivers: usize,
    pub verified_class_count: usize,
    pub unverified_ffs_count: usize,
    pub risk_notes: Vec<String>,
}

impl UefiSecurityReport {
    /// Build from a `UefiAnalysis`.
    #[must_use]
    pub fn build(analysis: &UefiAnalysis) -> Self {
        let smm_count = analysis.smm_drivers().len();
        let total_drivers = analysis.dxe_drivers.len();
        let total_ffs = analysis.total_ffs_files();
        let mut risk_notes = Vec::new();

        if smm_count > 0 {
            risk_notes.push(format!(
                "{smm_count} SMM drivers detected — attack surface for SMM exploits"
            ));
        }
        if total_ffs > 200 {
            risk_notes.push(format!("Large firmware: {total_ffs} FFS files"));
        }

        Self {
            has_secure_boot_variables: false,
            smm_driver_count: smm_count,
            total_drivers,
            verified_class_count: 0,
            unverified_ffs_count: total_ffs,
            risk_notes,
        }
    }

    #[must_use]
    pub const fn is_high_risk(&self) -> bool {
        self.smm_driver_count > 5
    }
}

// ---------------------------------------------------------------------------
// UefiAnalysis — top-level aggregator
// ---------------------------------------------------------------------------

/// Complete UEFI firmware analysis.
#[derive(Debug, Default)]
pub struct UefiAnalysis {
    pub firmware_volumes: Vec<EfiFirmwareVolume>,
    pub pei_modules: Vec<PeiModule>,
    pub dxe_drivers: Vec<DxeDriver>,
    pub guid_db: GuidDatabase,
    guid_index: HashMap<[u8; 16], usize>,
}

impl UefiAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self {
            guid_db: GuidDatabase::load_standard(),
            ..Default::default()
        }
    }

    pub fn add_fv(&mut self, fv: EfiFirmwareVolume) {
        self.firmware_volumes.push(fv);
    }

    pub fn add_pei_module(&mut self, module: PeiModule) {
        let idx = self.pei_modules.len();
        self.guid_index.insert(module.guid, idx);
        self.pei_modules.push(module);
    }

    pub fn add_dxe_driver(&mut self, driver: DxeDriver) {
        self.dxe_drivers.push(driver);
    }

    /// Look up a GUID name in the database.
    #[must_use]
    pub fn name_for_guid(&self, guid: &Guid) -> Option<&str> {
        self.guid_db.lookup(guid)
    }

    /// Total number of FFS files across all firmware volumes.
    #[must_use]
    pub fn total_ffs_files(&self) -> usize {
        self.firmware_volumes.iter().map(|fv| fv.files.len()).sum()
    }

    /// All SMM drivers.
    #[must_use]
    pub fn smm_drivers(&self) -> Vec<&DxeDriver> {
        self.dxe_drivers.iter().filter(|d| d.is_smm).collect()
    }

    /// Find a PEI module by GUID.
    #[must_use]
    pub fn find_pei_module(&self, guid: &Guid) -> Option<&PeiModule> {
        self.pei_modules.iter().find(|m| &m.guid == guid)
    }

    /// Total PE/COFF files across all volumes.
    #[must_use]
    pub fn total_pe_files(&self) -> usize {
        self.firmware_volumes
            .iter()
            .map(|fv| fv.pe_files().len())
            .sum()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn murmur3_32_mixes_the_trailing_bytes() {
        // Same length, same 4-byte block, different tail. With the tail
        // dropped these collided, so this needs no external test vector to
        // prove the old behaviour wrong — the two inputs simply must not hash
        // alike.
        assert_ne!(murmur3_32(b"abcde", 0), murmur3_32(b"abcdX", 0));
        assert_ne!(murmur3_32(b"abcdef", 0), murmur3_32(b"abcdeY", 0));
        // A tail of every length must matter, including the 3-byte case.
        assert_ne!(murmur3_32(b"abcdefg", 0), murmur3_32(b"abcdefZ", 0));
        // Inputs that are an exact multiple of four are unaffected by the fix:
        // the tail branch is skipped entirely.
        assert_eq!(murmur3_32(b"abcd", 0), murmur3_32(b"abcd", 0));
        assert_ne!(murmur3_32(b"abcd", 0), murmur3_32(b"abcd", 1));
    }

    fn make_guid(b: u8) -> Guid {
        let mut g = [0u8; 16];
        g[0] = b;
        g
    }

    fn make_fv_header() -> Vec<u8> {
        let mut data = vec![0u8; EfiFirmwareVolume::MIN_SIZE + 4];
        // GUID bytes [0..16] = zeros
        // FV length at 0x18 (16 + 8)
        let len: u64 = 0x10000;
        data[0x18..0x20].copy_from_slice(&len.to_le_bytes());
        // Signature at 0x28
        data[0x28..0x2c].copy_from_slice(FV_SIGNATURE);
        // Attributes at 0x2c
        data[0x2c..0x30].copy_from_slice(&0u32.to_le_bytes());
        // HeaderLength at 0x30
        data[0x30..0x32].copy_from_slice(&(EfiFirmwareVolume::MIN_SIZE as u16).to_le_bytes());
        // Revision at 0x37
        data[0x37] = 2;
        data
    }

    // ---- GuidDatabase ----

    #[test]
    fn test_guid_db_load_standard() {
        let db = GuidDatabase::load_standard();
        assert!(!db.is_empty());
    }

    #[test]
    fn test_guid_db_lookup_unknown() {
        let db = GuidDatabase::new();
        assert!(db.lookup(&make_guid(0xff)).is_none());
    }

    #[test]
    fn test_guid_db_insert_and_lookup() {
        let mut db = GuidDatabase::new();
        let g = make_guid(0x01);
        db.insert(g, "TestGuid");
        assert_eq!(db.lookup(&g), Some("TestGuid"));
    }

    // ---- format_guid ----

    #[test]
    fn test_format_guid_all_zeros() {
        let g = [0u8; 16];
        let s = format_guid(&g);
        assert!(s.starts_with("{00000000-"));
    }

    // ---- FfsFileType ----

    #[test]
    fn test_ffs_file_type_from_u8_valid() {
        assert_eq!(FfsFileType::from_u8(0x07).unwrap(), FfsFileType::Driver);
        assert_eq!(FfsFileType::from_u8(0x06).unwrap(), FfsFileType::Peim);
    }

    #[test]
    fn test_ffs_file_type_invalid() {
        assert!(matches!(
            FfsFileType::from_u8(0x7f),
            Err(UefiError::InvalidFfsType(0x7f))
        ));
    }

    #[test]
    fn test_ffs_file_type_is_executable() {
        assert!(FfsFileType::Driver.is_executable());
        assert!(FfsFileType::Peim.is_executable());
        assert!(!FfsFileType::FfsPad.is_executable());
    }

    // ---- EfiSectionType ----

    #[test]
    fn test_section_type_pe32() {
        assert_eq!(EfiSectionType::from_u8(0x10).unwrap(), EfiSectionType::Pe32);
    }

    #[test]
    fn test_section_type_invalid() {
        assert!(matches!(
            EfiSectionType::from_u8(0xff),
            Err(UefiError::InvalidSectionType(0xff))
        ));
    }

    #[test]
    fn test_section_type_is_executable() {
        assert!(EfiSectionType::Pe32.is_executable());
        assert!(EfiSectionType::Te.is_executable());
        assert!(!EfiSectionType::DxeDepex.is_executable());
    }

    #[test]
    fn test_section_type_is_dependency() {
        assert!(EfiSectionType::DxeDepex.is_dependency());
        assert!(EfiSectionType::PeiDepex.is_dependency());
        assert!(!EfiSectionType::Pe32.is_dependency());
    }

    // ---- EfiFfs ----

    #[test]
    fn test_ffs_has_pe_true() {
        let mut ffs = EfiFfs::new(make_guid(1), FfsFileType::Driver, 0x100);
        ffs.sections
            .push(EfiSection::new(EfiSectionType::Pe32, vec![0u8; 16]));
        assert!(ffs.has_pe());
    }

    #[test]
    fn test_ffs_has_pe_false() {
        let ffs = EfiFfs::new(make_guid(1), FfsFileType::Raw, 0x100);
        assert!(!ffs.has_pe());
    }

    #[test]
    fn test_ffs_find_section_found() {
        let mut ffs = EfiFfs::new(make_guid(1), FfsFileType::Driver, 0x100);
        ffs.sections.push(EfiSection::new(
            EfiSectionType::UserInterface,
            b"name".to_vec(),
        ));
        assert!(ffs.find_section(EfiSectionType::UserInterface).is_some());
    }

    #[test]
    fn test_ffs_find_section_missing() {
        let ffs = EfiFfs::new(make_guid(1), FfsFileType::Driver, 0x100);
        assert!(ffs.find_section(EfiSectionType::Pe32).is_none());
    }

    // ---- EfiFirmwareVolume ----

    #[test]
    fn test_fv_parse_valid() {
        let data = make_fv_header();
        let fv = EfiFirmwareVolume::parse(&data, 0).unwrap();
        assert_eq!(fv.revision, 2);
        assert_eq!(fv.fv_length, 0x10000);
    }

    #[test]
    fn test_fv_parse_invalid_signature() {
        let mut data = make_fv_header();
        data[0x28..0x2c].copy_from_slice(b"BAD!");
        assert!(matches!(
            EfiFirmwareVolume::parse(&data, 0),
            Err(UefiError::InvalidFvSignature { .. })
        ));
    }

    #[test]
    fn test_fv_parse_truncated() {
        assert!(matches!(
            EfiFirmwareVolume::parse(&[0u8; 10], 0),
            Err(UefiError::TruncatedData { .. })
        ));
    }

    #[test]
    fn test_fv_executable_files() {
        let _data = make_fv_header();
        let fv_data = vec![0u8; EfiFirmwareVolume::MIN_SIZE + 4];
        let _ = fv_data;
        let mut fv = EfiFirmwareVolume::parse(&make_fv_header(), 0).unwrap();
        fv.files
            .push(EfiFfs::new(make_guid(1), FfsFileType::Driver, 100));
        fv.files
            .push(EfiFfs::new(make_guid(2), FfsFileType::Raw, 50));
        assert_eq!(fv.executable_files().len(), 1);
    }

    // ---- PeiModule ----

    #[test]
    fn test_pei_module_dependency_count() {
        let mut m = PeiModule::new("TestPeim", make_guid(1));
        m.depex_guids.push(make_guid(2));
        m.depex_guids.push(make_guid(3));
        assert_eq!(m.dependency_count(), 2);
    }

    // ---- DxeDriver ----

    #[test]
    fn test_dxe_driver_is_smm() {
        let mut d = DxeDriver::new("SmmHandler", make_guid(10));
        d.is_smm = true;
        assert!(d.is_smm_driver());
    }

    #[test]
    fn test_dxe_driver_protocol_count() {
        let mut d = DxeDriver::new("Drv", make_guid(10));
        d.protocol_guids.push(make_guid(11));
        assert_eq!(d.protocol_count(), 1);
    }

    // ---- UefiAnalysis ----

    #[test]
    fn test_uefi_analysis_total_ffs_files() {
        let mut a = UefiAnalysis::new();
        let mut fv = EfiFirmwareVolume::parse(&make_fv_header(), 0).unwrap();
        fv.files
            .push(EfiFfs::new(make_guid(1), FfsFileType::Driver, 100));
        fv.files
            .push(EfiFfs::new(make_guid(2), FfsFileType::Peim, 80));
        a.add_fv(fv);
        assert_eq!(a.total_ffs_files(), 2);
    }

    #[test]
    fn test_uefi_analysis_smm_drivers() {
        let mut a = UefiAnalysis::new();
        let mut d = DxeDriver::new("SmmDrv", make_guid(5));
        d.is_smm = true;
        a.add_dxe_driver(d);
        a.add_dxe_driver(DxeDriver::new("NormalDrv", make_guid(6)));
        assert_eq!(a.smm_drivers().len(), 1);
    }

    #[test]
    fn test_uefi_analysis_find_pei_module() {
        let mut a = UefiAnalysis::new();
        let g = make_guid(42);
        a.add_pei_module(PeiModule::new("MyPeim", g));
        assert!(a.find_pei_module(&g).is_some());
        assert!(a.find_pei_module(&make_guid(99)).is_none());
    }

    #[test]
    fn test_uefi_analysis_total_pe_files() {
        let mut a = UefiAnalysis::new();
        let mut fv = EfiFirmwareVolume::parse(&make_fv_header(), 0).unwrap();
        let mut ffs = EfiFfs::new(make_guid(1), FfsFileType::Driver, 100);
        ffs.sections
            .push(EfiSection::new(EfiSectionType::Pe32, vec![]));
        fv.files.push(ffs);
        a.add_fv(fv);
        assert_eq!(a.total_pe_files(), 1);
    }

    #[test]
    fn test_uefi_error_display() {
        let e = UefiError::TruncatedData {
            offset: 0x100,
            needed: 0x48,
        };
        assert!(e.to_string().contains("100"));
        let e2 = UefiError::TooManyFiles(50000);
        assert!(e2.to_string().contains("50000"));
    }

    #[test]
    fn test_uefi_analysis_guid_db_standard() {
        let a = UefiAnalysis::new();
        assert!(!a.guid_db.is_empty());
    }

    #[test]
    fn test_format_guid_non_zero() {
        let mut g = [0u8; 16];
        g[0] = 0xAB;
        g[1] = 0xCD;
        let s = format_guid(&g);
        // Bug fix: bytes [0xAB,0xCD,0,0] as a u32 LE -> 0x0000CDAB, displayed "0000CDAB"
        assert!(s.contains("0000CDAB"));
    }

    #[test]
    fn test_guid_database_len() {
        let db = GuidDatabase::load_standard();
        assert!(db.len() >= 5);
    }

    #[test]
    fn test_ffs_file_type_application() {
        assert_eq!(
            FfsFileType::from_u8(0x09).unwrap(),
            FfsFileType::Application
        );
        assert!(FfsFileType::Application.is_executable());
    }

    #[test]
    fn test_ffs_file_type_smm() {
        assert!(FfsFileType::Smm.is_executable());
    }

    #[test]
    fn test_ffs_file_type_pad() {
        assert!(!FfsFileType::FfsPad.is_executable());
    }

    #[test]
    fn test_section_type_te_executable() {
        assert!(EfiSectionType::Te.is_executable());
    }

    #[test]
    fn test_section_type_smm_depex() {
        assert!(EfiSectionType::SmmDepex.is_dependency());
    }

    #[test]
    fn test_fv_find_file_present() {
        let mut fv = EfiFirmwareVolume::parse(&make_fv_header(), 0).unwrap();
        let g = make_guid(42);
        fv.files.push(EfiFfs::new(g, FfsFileType::Driver, 100));
        assert!(fv.find_file(&g).is_some());
    }

    #[test]
    fn test_fv_find_file_absent() {
        let fv = EfiFirmwareVolume::parse(&make_fv_header(), 0).unwrap();
        assert!(fv.find_file(&make_guid(99)).is_none());
    }

    #[test]
    fn test_fv_pe_files_multiple() {
        let mut fv = EfiFirmwareVolume::parse(&make_fv_header(), 0).unwrap();
        let mut f1 = EfiFfs::new(make_guid(1), FfsFileType::Driver, 100);
        f1.sections
            .push(EfiSection::new(EfiSectionType::Pe32, vec![]));
        let mut f2 = EfiFfs::new(make_guid(2), FfsFileType::Peim, 80);
        f2.sections
            .push(EfiSection::new(EfiSectionType::Te, vec![]));
        let f3 = EfiFfs::new(make_guid(3), FfsFileType::Raw, 50); // no PE
        fv.files.extend([f1, f2, f3]);
        assert_eq!(fv.pe_files().len(), 2);
    }

    #[test]
    fn test_pei_module_no_deps() {
        let m = PeiModule::new("NoDep", make_guid(1));
        assert_eq!(m.dependency_count(), 0);
    }

    #[test]
    fn test_dxe_driver_not_smm_default() {
        let d = DxeDriver::new("Normal", make_guid(1));
        assert!(!d.is_smm_driver());
    }

    #[test]
    fn test_uefi_analysis_no_smm_drivers() {
        let mut a = UefiAnalysis::new();
        a.add_dxe_driver(DxeDriver::new("NonSmm", make_guid(1)));
        assert!(a.smm_drivers().is_empty());
    }

    #[test]
    fn test_uefi_analysis_name_for_guid_none() {
        let a = UefiAnalysis::new();
        assert!(a.name_for_guid(&make_guid(0xFE)).is_none());
    }

    #[test]
    fn test_uefi_error_fv_too_small() {
        let e = UefiError::FvTooSmall { size: 0x10 };
        assert!(e.to_string().contains("10"));
    }

    #[test]
    fn test_uefi_error_cyclic_fv() {
        let e = UefiError::CyclicFv;
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_section_raw_data_stored() {
        let sec = EfiSection::new(EfiSectionType::Raw, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(sec.raw_data.len(), 3);
        assert_eq!(sec.size, 3);
    }
}

// ---------------------------------------------------------------------------
// EfiFvSecurity — security features assessment
// ---------------------------------------------------------------------------

/// Security-relevant flags in a firmware volume.
#[derive(Debug, Clone, Default)]
pub struct EfiFvSecurity {
    pub has_authenticated_variables: bool,
    pub has_secure_boot_db: bool,
    pub has_verified_boot: bool,
    pub has_measured_boot: bool,
    pub tpm_ppi_present: bool,
    pub csp_modules: Vec<String>,
}

impl EfiFvSecurity {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn risk_level(&self) -> u8 {
        let mut score = 0u8;
        if !self.has_secure_boot_db {
            score += 30;
        }
        if !self.has_verified_boot {
            score += 20;
        }
        if !self.has_measured_boot {
            score += 20;
        }
        score.min(100)
    }
    #[must_use]
    pub fn is_secure(&self) -> bool {
        self.risk_level() < 40
    }
}
// ---------------------------------------------------------------------------
// EfiPei — PEI memory descriptor
// ---------------------------------------------------------------------------

/// A memory range descriptor from the PEI hand-off info block (HOB).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EfiMemoryDescriptor {
    pub memory_type: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

impl EfiMemoryDescriptor {
    #[must_use]
    pub const fn new(mem_type: u32, phys: u64, pages: u64) -> Self {
        Self {
            memory_type: mem_type,
            physical_start: phys,
            virtual_start: 0,
            number_of_pages: pages,
            attribute: 0,
        }
    }
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.number_of_pages * 4096
    }
    #[must_use]
    pub const fn end_address(&self) -> u64 {
        self.physical_start + self.size_bytes()
    }
    #[must_use]
    pub const fn is_conventional(&self) -> bool {
        self.memory_type == 7
    }
    #[must_use]
    pub const fn is_runtime(&self) -> bool {
        self.memory_type >= 1 && self.memory_type <= 4
    }
}

// ---------------------------------------------------------------------------
// EfiHobList — Hand-Off Block (HOB) list
// ---------------------------------------------------------------------------

/// Type of a Hand-Off Block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HobType {
    Handoff = 0x0001,
    MemoryAllocation = 0x0002,
    ResourceDescriptor = 0x0003,
    GuidExtension = 0x0004,
    FirmwareVolume = 0x0007,
    Cpu = 0x0008,
    MemoryPool = 0x0009,
    FirmwareVolume2 = 0x000B,
    LoadPeim = 0x000A,
    EndOfHobList = 0xFFFF,
}

impl HobType {
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x0001 => Self::Handoff,
            0x0002 => Self::MemoryAllocation,
            0x0003 => Self::ResourceDescriptor,
            0x0004 => Self::GuidExtension,
            0x0007 => Self::FirmwareVolume,
            0x0008 => Self::Cpu,
            0x0009 => Self::MemoryPool,
            0x000A => Self::LoadPeim,
            0x000B => Self::FirmwareVolume2,
            0xFFFF => Self::EndOfHobList,
            _ => Self::GuidExtension,
        }
    }
}

/// One HOB entry.
#[derive(Debug, Clone)]
pub struct HobEntry {
    pub hob_type: HobType,
    pub hob_length: u16,
    pub data: Vec<u8>,
}

impl HobEntry {
    #[must_use]
    pub fn parse_header(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let hob_type = HobType::from_u16(u16::from_le_bytes(data[0..2].try_into().ok()?));
        let hob_length = u16::from_le_bytes(data[2..4].try_into().ok()?);
        let len = hob_length as usize;
        if len > data.len() {
            return None;
        }
        Some(Self {
            hob_type,
            hob_length,
            data: data[..len].to_vec(),
        })
    }
    #[must_use]
    pub fn is_end(&self) -> bool {
        self.hob_type == HobType::EndOfHobList
    }
}

// ---------------------------------------------------------------------------
// EfiGptHeader — GPT partition table header
// ---------------------------------------------------------------------------

/// GUID Partition Table header (EFI GPT).
#[derive(Debug, Clone)]
pub struct EfiGptHeader {
    pub signature: [u8; 8],
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub my_lba: u64,
    pub alternate_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: Guid,
    pub partition_entry_lba: u64,
    pub number_of_partition_entries: u32,
    pub size_of_partition_entry: u32,
    pub partition_entry_array_crc32: u32,
}

impl EfiGptHeader {
    pub const SIGNATURE: &'static [u8] = b"EFI PART";
    pub const SIZE: usize = 92;

    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        if &data[..8] != Self::SIGNATURE {
            return None;
        }
        let r4 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        let r8 = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
        let mut sig = [0u8; 8];
        sig.copy_from_slice(&data[..8]);
        let mut disk_guid = [0u8; 16];
        disk_guid.copy_from_slice(&data[56..72]);
        Some(Self {
            signature: sig,
            revision: r4(8),
            header_size: r4(12),
            header_crc32: r4(16),
            my_lba: r8(24),
            alternate_lba: r8(32),
            first_usable_lba: r8(40),
            last_usable_lba: r8(48),
            disk_guid,
            partition_entry_lba: r8(72),
            number_of_partition_entries: r4(80),
            size_of_partition_entry: r4(84),
            partition_entry_array_crc32: r4(88),
        })
    }

    #[must_use]
    pub const fn usable_lba_count(&self) -> u64 {
        self.last_usable_lba.saturating_sub(self.first_usable_lba) + 1
    }
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Read a null-terminated UTF-8 string from a byte slice at `offset`.
#[must_use]
pub fn read_cstring(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map_or(data.len(), |p| offset + p);
    std::str::from_utf8(&data[offset..end])
        .ok()
        .map(std::borrow::ToOwned::to_owned)
}

/// Align a value up to `align` (power-of-two).
#[must_use]
pub const fn align_up(val: u64, align: u64) -> u64 {
    if align == 0 {
        return val;
    }
    (val + align - 1) & !(align - 1)
}

/// Align a value down to `align` (power-of-two).
#[must_use]
pub const fn align_down(val: u64, align: u64) -> u64 {
    if align == 0 {
        return val;
    }
    val & !(align - 1)
}

/// Check whether `val` is a power of two.
#[must_use]
pub const fn is_power_of_two(val: u64) -> bool {
    val != 0 && val.is_power_of_two()
}

/// Simple entropy estimate over a byte slice (0.0 = uniform, 1.0 = random).
#[must_use]
pub fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &freq {
        if c > 0 {
            let p = f64::from(c) / n;
            entropy -= p * p.log2();
        }
    }
    entropy / 8.0 // normalise to [0, 1]
}

// ---------------------------------------------------------------------------
// Additional parsing utilities
// ---------------------------------------------------------------------------

/// Parse a little-endian u16.
#[inline]
#[must_use]
pub fn le_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}
/// Parse a little-endian u32.
#[inline]
#[must_use]
pub fn le_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}
/// Parse a little-endian u64.
#[inline]
#[must_use]
pub fn le_u64(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}
/// Parse a big-endian u32.
#[inline]
#[must_use]
pub fn be_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_be_bytes(data[off..off + 4].try_into().unwrap())
}
/// Verify a 32-bit Adler-32 checksum over `data`.
#[must_use]
pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

// ---------------------------------------------------------------------------
// Byte pattern matching utilities
// ---------------------------------------------------------------------------

/// Search `haystack` for the first occurrence of `needle`.
#[must_use]
pub fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
#[must_use]
pub fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut pos = 0;
    while let Some(idx) = haystack[pos..]
        .windows(needle.len())
        .position(|w| w == needle)
    {
        count += 1;
        pos += idx + needle.len();
    }
    count
}

/// Extract a sub-slice at `offset` with `len`, returning `None` if out of bounds.
#[must_use]
pub fn try_slice(data: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    data.get(offset..offset + len)
}

// Last additions
/// Check if a byte slice is all zeros.
#[must_use]
pub fn is_zeroed(data: &[u8]) -> bool {
    data.iter().all(|&b| b == 0)
}
/// Reverse bytes in-place.
pub const fn reverse_bytes(data: &mut [u8]) {
    data.reverse();
}
/// XOR all bytes with `key`.
pub fn xor_bytes(data: &mut [u8], key: u8) {
    for b in data.iter_mut() {
        *b ^= key;
    }
}
/// Rotate `val` left by `n` bits (32-bit).
#[must_use]
pub const fn rol32(val: u32, n: u32) -> u32 {
    val.rotate_left(n)
}
/// Rotate `val` right by `n` bits (32-bit).
#[must_use]
pub const fn ror32(val: u32, n: u32) -> u32 {
    val.rotate_right(n)
}

/// CRC32 (IEEE polynomial) checksum.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}
/// FNV-1a 32-bit hash.
#[must_use]
pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut h = 2166136261u32;
    for &b in data {
        h ^= u32::from(b);
        h = h.wrapping_mul(16777619);
    }
    h
}

/// `MurmurHash3` 32-bit (`MurmurHash3_x86_32`).
///
/// The body loop was already correct, but the trailing 1–3 bytes were dropped
/// by `chunks_exact(4)`, so two inputs differing only in their tail hashed
/// identically and no value matched a hash produced by any other
/// implementation. The `switch (len & 3)` block below is the reference tail
/// from Austin Appleby's `MurmurHash3.cpp`.
#[must_use]
pub fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    let mut h = seed;
    let mut chunks = data.chunks_exact(4);
    for chunk in chunks.by_ref() {
        let mut k = u32::from_le_bytes(chunk.try_into().unwrap());
        k = k.wrapping_mul(0xcc9e2d51);
        k = k.rotate_left(15);
        k = k.wrapping_mul(0x1b873593);
        h ^= k;
        h = h.rotate_left(13);
        h = h.wrapping_mul(5).wrapping_add(0xe6546b64);
    }
    // Tail: fold the remaining bytes little-endian, then apply the same k
    // mixing as the body (but without the h rotate/multiply-add).
    let tail = chunks.remainder();
    if !tail.is_empty() {
        let mut k = 0u32;
        for (i, &b) in tail.iter().enumerate() {
            k ^= u32::from(b) << (i * 8);
        }
        k = k.wrapping_mul(0xcc9e2d51);
        k = k.rotate_left(15);
        k = k.wrapping_mul(0x1b873593);
        h ^= k;
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^ (h >> 16)
}
