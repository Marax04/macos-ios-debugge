//! Nintendo Switch binary format support.
//!
//! Parses NSO (executable), NRO (relocatable object), NSS, and related
//! formats used by Nintendo Switch homebrew and system software.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwitchError {
    InvalidMagic {
        expected: &'static [u8],
        got: Vec<u8>,
    },
    TruncatedData {
        offset: usize,
        needed: usize,
    },
    InvalidSegmentOffset {
        segment: u8,
        offset: u32,
    },
    DecompressionError(String),
    InvalidModOffset(u32),
    NroTooSmall {
        size: u32,
    },
    InvalidBssSize,
    TooManyRelocations(usize),
    InvalidRomFsHeader,
    UnsupportedFlags(u32),
}

impl std::fmt::Display for SwitchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic { expected, got } => {
                write!(f, "invalid magic: expected {expected:?}, got {got:?}")
            }
            Self::TruncatedData { offset, needed } => {
                write!(f, "truncated data at offset {offset:#x}, need {needed}")
            }
            Self::InvalidSegmentOffset { segment, offset } => {
                write!(f, "invalid offset {offset:#x} for segment {segment}")
            }
            Self::DecompressionError(s) => write!(f, "decompression error: {s}"),
            Self::InvalidModOffset(o) => write!(f, "invalid MOD0 offset {o:#x}"),
            Self::NroTooSmall { size } => write!(f, "NRO too small: {size} bytes"),
            Self::InvalidBssSize => write!(f, "invalid BSS size in NRO"),
            Self::TooManyRelocations(n) => write!(f, "too many relocations: {n}"),
            Self::InvalidRomFsHeader => write!(f, "invalid RomFS header"),
            Self::UnsupportedFlags(n) => write!(f, "unsupported flags {n:#010x}"),
        }
    }
}

impl std::error::Error for SwitchError {}

// ---------------------------------------------------------------------------
// NsoHeader
// ---------------------------------------------------------------------------

/// NSO0 file magic.
pub const NSO_MAGIC: &[u8] = b"NSO0";
/// NRO0 file magic.
pub const NRO_MAGIC: &[u8] = b"NRO0";

/// NSO segment descriptor (`offset`, `memory_offset`, `size`, `bss_size`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NsoSegmentInfo {
    pub file_offset: u32,
    pub memory_offset: u32,
    pub size: u32,
}

impl NsoSegmentInfo {
    #[must_use]
    pub const fn new(file_offset: u32, memory_offset: u32, size: u32) -> Self {
        Self {
            file_offset,
            memory_offset,
            size,
        }
    }

    /// `true` if this segment has no data (zero size).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }
}

/// NSO0 file header (full 0x100-byte structure).
#[derive(Debug, Clone)]
pub struct NsoHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub flags: u32,
    pub text_segment: NsoSegmentInfo,
    pub module_name_offset: u32,
    pub rodata_segment: NsoSegmentInfo,
    pub module_name_size: u32,
    pub data_segment: NsoSegmentInfo,
    pub bss_size: u32,
    pub module_id: [u8; 32],
    pub text_file_size: u32,
    pub rodata_file_size: u32,
    pub data_file_size: u32,
    pub api_info_offset: u32,
    pub api_info_size: u32,
    pub dynstr_offset: u32,
    pub dynstr_size: u32,
    pub dynsym_offset: u32,
    pub dynsym_size: u32,
    pub text_hash: [u8; 32],
    pub rodata_hash: [u8; 32],
    pub data_hash: [u8; 32],
}

impl NsoHeader {
    pub const SIZE: usize = 0x100;

    /// Flag: text segment is LZ4-compressed.
    pub const FLAG_TEXT_COMPRESSED: u32 = 1 << 0;
    /// Flag: rodata segment is LZ4-compressed.
    pub const FLAG_RODATA_COMPRESSED: u32 = 1 << 1;
    /// Flag: data segment is LZ4-compressed.
    pub const FLAG_DATA_COMPRESSED: u32 = 1 << 2;
    /// Flag: text hash check enabled.
    pub const FLAG_TEXT_HASH: u32 = 1 << 3;
    /// Flag: rodata hash check enabled.
    pub const FLAG_RODATA_HASH: u32 = 1 << 4;
    /// Flag: data hash check enabled.
    pub const FLAG_DATA_HASH: u32 = 1 << 5;

    /// # Errors
    /// Returns [`SwitchError`] if the data is too short or has invalid magic.
    ///
    /// # Panics
    /// Panics if internal slice conversions fail (should not happen for valid data).
    pub fn parse(data: &[u8]) -> Result<Self, SwitchError> {
        if data.len() < Self::SIZE {
            return Err(SwitchError::TruncatedData {
                offset: 0,
                needed: Self::SIZE,
            });
        }
        if &data[..4] != NSO_MAGIC {
            return Err(SwitchError::InvalidMagic {
                expected: NSO_MAGIC,
                got: data[..4].to_vec(),
            });
        }

        let r4 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[..4]);
        let version = r4(4);
        let flags = r4(12);

        let text_seg = NsoSegmentInfo::new(r4(16), r4(20), r4(24));
        let module_name_offset = r4(28);
        let rodata_seg = NsoSegmentInfo::new(r4(32), r4(36), r4(40));
        let module_name_size = r4(44);
        let data_seg = NsoSegmentInfo::new(r4(48), r4(52), r4(56));
        let bss_size = r4(60);

        let mut module_id = [0u8; 32];
        module_id.copy_from_slice(&data[64..96]);

        let text_file_size = r4(96);
        let rodata_file_size = r4(100);
        let data_file_size = r4(104);
        let api_info_offset = r4(108);
        let api_info_size = r4(112);
        let dynstr_offset = r4(116);
        let dynstr_size = r4(120);
        let dynsym_offset = r4(124);
        let dynsym_size = r4(128);

        let mut text_hash = [0u8; 32];
        let mut rodata_hash = [0u8; 32];
        let mut data_hash = [0u8; 32];
        if data.len() >= 0x100 {
            text_hash.copy_from_slice(&data[0x80..0xa0]);
            rodata_hash.copy_from_slice(&data[0xa0..0xc0]);
            data_hash.copy_from_slice(&data[0xc0..0xe0]);
        }

        Ok(Self {
            magic,
            version,
            flags,
            text_segment: text_seg,
            module_name_offset,
            rodata_segment: rodata_seg,
            module_name_size,
            data_segment: data_seg,
            bss_size,
            module_id,
            text_file_size,
            rodata_file_size,
            data_file_size,
            api_info_offset,
            api_info_size,
            dynstr_offset,
            dynstr_size,
            dynsym_offset,
            dynsym_size,
            text_hash,
            rodata_hash,
            data_hash,
        })
    }

    /// `true` when text segment is LZ4-compressed.
    #[must_use]
    pub const fn text_compressed(&self) -> bool {
        self.flags & Self::FLAG_TEXT_COMPRESSED != 0
    }
    #[must_use]
    pub const fn rodata_compressed(&self) -> bool {
        self.flags & Self::FLAG_RODATA_COMPRESSED != 0
    }
    #[must_use]
    pub const fn data_compressed(&self) -> bool {
        self.flags & Self::FLAG_DATA_COMPRESSED != 0
    }

    /// Total virtual image size (rodata end + data size + bss).
    #[must_use]
    pub fn image_size(&self) -> u64 {
        u64::from(self.data_segment.memory_offset)
            + u64::from(self.data_segment.size)
            + u64::from(self.bss_size)
    }
}

// ---------------------------------------------------------------------------
// NsoApiInfo — API info section parsing
// ---------------------------------------------------------------------------

/// SDK version information from the NSO `.api_info` section.
#[derive(Debug, Clone)]
pub struct NsoApiInfo {
    pub sdk_version: String,
    pub app_type: u8,
    pub platform: String,
}

impl NsoApiInfo {
    /// Parse from raw `.api_info` bytes (null-terminated strings).
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        // API info is a series of null-terminated strings
        let mut strings: Vec<&str> = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let end = data[pos..]
                .iter()
                .position(|&b| b == 0)
                .map_or(data.len(), |p| pos + p);
            if let Ok(s) = std::str::from_utf8(&data[pos..end]) && !s.is_empty() {
                strings.push(s);
            }
            pos = end + 1;
        }
        Some(Self {
            sdk_version: strings.first().copied().unwrap_or("").to_string(),
            app_type: 0,
            platform: strings.get(1).copied().unwrap_or("").to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// NroAsset — NRO asset section
// ---------------------------------------------------------------------------

/// NRO Asset section magic.
pub const ASET_MAGIC: &[u8] = b"ASET";

/// Section descriptor inside an NRO asset section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetSection {
    pub offset: u64,
    pub size: u64,
}

impl AssetSection {
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.size > 0
    }
}

/// NRO asset header (present after the NRO code in homebrew binaries).
#[derive(Debug, Clone)]
pub struct NroAssetHeader {
    pub magic: [u8; 4],
    pub format_version: u32,
    pub romfs: AssetSection,
    pub nacp: AssetSection,
    pub icon: AssetSection,
}

impl NroAssetHeader {
    pub const SIZE: usize = 0x38;

    /// # Panics
    /// Panics if internal slice conversions fail for valid-sized data.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        if &data[..4] != ASET_MAGIC {
            return None;
        }
        let r4 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        let r8 = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[..4]);
        Some(Self {
            magic,
            format_version: r4(4),
            romfs: AssetSection {
                offset: r8(8),
                size: r8(16),
            },
            nacp: AssetSection {
                offset: r8(24),
                size: r8(32),
            },
            icon: AssetSection {
                offset: r8(40),
                size: r8(48).min((data.len() - 40) as u64),
            },
        })
    }

    #[must_use]
    pub const fn has_romfs(&self) -> bool {
        self.romfs.is_present()
    }
    #[must_use]
    pub const fn has_nacp(&self) -> bool {
        self.nacp.is_present()
    }
    #[must_use]
    pub const fn has_icon(&self) -> bool {
        self.icon.is_present()
    }
}

// ---------------------------------------------------------------------------
// SwitchExefsSection — ExeFS section descriptor
// ---------------------------------------------------------------------------

/// One section descriptor in a Nintendo `ExeFS`.
#[derive(Debug, Clone)]
pub struct ExefsSectionHeader {
    pub name: String,
    pub offset: u32,
    pub size: u32,
    pub hash: [u8; 32],
}

impl ExefsSectionHeader {
    pub const ENTRY_SIZE: usize = 48;

    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::ENTRY_SIZE {
            return None;
        }
        let name_end = data[..8].iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&data[..name_end]).into_owned();
        let offset = u32::from_le_bytes(data[8..12].try_into().ok()?);
        let size = u32::from_le_bytes(data[12..16].try_into().ok()?);
        let mut hash = [0u8; 32];
        if data.len() >= 48 {
            hash.copy_from_slice(&data[16..48]);
        }
        Some(Self {
            name,
            offset,
            size,
            hash,
        })
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.name.is_empty() || self.size == 0
    }
}

// ---------------------------------------------------------------------------
// NsoBss
// ---------------------------------------------------------------------------

/// BSS region information extracted from an NSO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NsoBss {
    /// Start memory offset of the BSS region.
    pub offset: u32,
    /// Size in bytes.
    pub size: u32,
}

impl NsoBss {
    #[must_use]
    pub const fn from_header(hdr: &NsoHeader) -> Self {
        let offset = hdr.data_segment.memory_offset + hdr.data_segment.size;
        Self {
            offset,
            size: hdr.bss_size,
        }
    }

    #[must_use]
    pub const fn end_offset(&self) -> u32 {
        self.offset.saturating_add(self.size)
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }
}

// ---------------------------------------------------------------------------
// NsoModuleInfo
// ---------------------------------------------------------------------------

/// MOD0 structure located at `text_base + module_info_offset`.
#[derive(Debug, Clone, Default)]
pub struct NsoModuleInfo {
    /// "MOD0" magic.
    pub magic: u32,
    /// Offset to the dynamic section from MOD0 start.
    pub dynamic_offset: i32,
    /// Offset to the BSS start from MOD0 start.
    pub bss_start_offset: i32,
    /// Offset to the BSS end from MOD0 start.
    pub bss_end_offset: i32,
    /// Offset to the EH frame hdr from MOD0 start.
    pub eh_frame_hdr_start: i32,
    /// Offset to the EH frame hdr end from MOD0 start.
    pub eh_frame_hdr_end: i32,
    /// Offset to the module runtime object from MOD0 start.
    pub runtime_module_ptr: i32,
}

impl NsoModuleInfo {
    pub const MAGIC: u32 = 0x304f_444d; // "MOD0"
    pub const SIZE: usize = 28;

    /// # Errors
    /// Returns [`SwitchError`] if data is too short or magic does not match.
    ///
    /// # Panics
    /// Panics if slice conversion fails (impossible for valid-sized input).
    pub fn parse(data: &[u8]) -> Result<Self, SwitchError> {
        if data.len() < Self::SIZE {
            return Err(SwitchError::TruncatedData {
                offset: 0,
                needed: Self::SIZE,
            });
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic != Self::MAGIC {
            return Err(SwitchError::InvalidModOffset(magic));
        }
        let ri32 = |o: usize| i32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        Ok(Self {
            magic,
            dynamic_offset: ri32(4),
            bss_start_offset: ri32(8),
            bss_end_offset: ri32(12),
            eh_frame_hdr_start: ri32(16),
            eh_frame_hdr_end: ri32(20),
            runtime_module_ptr: ri32(24),
        })
    }

    /// `true` if the magic matches.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

// ---------------------------------------------------------------------------
// NroHeader
// ---------------------------------------------------------------------------

/// NRO0 file header.
#[derive(Debug, Clone)]
pub struct NroHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub size: u32,
    pub flags: u32,
    pub text_offset: u32,
    pub text_size: u32,
    pub rodata_offset: u32,
    pub rodata_size: u32,
    pub data_offset: u32,
    pub data_size: u32,
    pub bss_size: u32,
    /// Build ID (first 16 bytes).
    pub build_id: [u8; 16],
}

impl NroHeader {
    pub const SIZE: usize = 0x70;

    /// # Errors
    /// Returns [`SwitchError`] if data is too short or has invalid magic.
    ///
    /// # Panics
    /// Panics if slice conversion fails (impossible for valid-sized input).
    pub fn parse(data: &[u8]) -> Result<Self, SwitchError> {
        if data.len() < Self::SIZE {
            return Err(SwitchError::TruncatedData {
                offset: 0,
                needed: Self::SIZE,
            });
        }
        if &data[4..8] != NRO_MAGIC && &data[..4] != NRO_MAGIC {
            // NRO magic is at offset 4 (bytes 0-3 are reserved)
            return Err(SwitchError::InvalidMagic {
                expected: NRO_MAGIC,
                got: data[..4].to_vec(),
            });
        }
        let r4 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        let mut magic = [0u8; 4];
        // Try both offsets for magic
        if &data[..4] == NRO_MAGIC {
            magic.copy_from_slice(&data[..4]);
        } else {
            magic.copy_from_slice(&data[4..8]);
        }
        let version = r4(8);
        let size = r4(12);
        let flags = r4(16);
        let text_offset = r4(20);
        let text_size = r4(24);
        let rodata_offset = r4(28);
        let rodata_size = r4(32);
        let data_offset = r4(36);
        let data_size = r4(40);
        let bss_size = r4(44);
        let mut build_id = [0u8; 16];
        if data.len() >= 0x40 {
            build_id.copy_from_slice(&data[0x30..0x40]);
        }
        Ok(Self {
            magic,
            version,
            size,
            flags,
            text_offset,
            text_size,
            rodata_offset,
            rodata_size,
            data_offset,
            data_size,
            bss_size,
            build_id,
        })
    }

    /// Total virtual size: text + rodata + data + bss.
    #[must_use]
    pub const fn total_size(&self) -> u32 {
        self.size.saturating_add(self.bss_size)
    }
}

// ---------------------------------------------------------------------------
// SwitchRomFs
// ---------------------------------------------------------------------------

/// `RomFS` header (v3.0 layout).
#[derive(Debug, Clone)]
pub struct RomFsHeader {
    pub header_size: u64,
    pub dir_hash_table_offset: u64,
    pub dir_hash_table_size: u64,
    pub dir_metadata_offset: u64,
    pub dir_metadata_size: u64,
    pub file_hash_table_offset: u64,
    pub file_hash_table_size: u64,
    pub file_metadata_offset: u64,
    pub file_metadata_size: u64,
    pub data_offset: u64,
}

impl RomFsHeader {
    pub const SIZE: usize = 0x50;
    pub const MAGIC: u32 = 0x36_30_52_49; // "IR06" or similar

    /// # Errors
    /// Returns [`SwitchError`] if data is too short or header size is invalid.
    ///
    /// # Panics
    /// Panics if slice conversion fails (impossible for valid-sized input).
    pub fn parse(data: &[u8]) -> Result<Self, SwitchError> {
        if data.len() < Self::SIZE {
            return Err(SwitchError::TruncatedData {
                offset: 0,
                needed: Self::SIZE,
            });
        }
        let r8 = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
        let header_size = r8(0);
        if header_size < Self::SIZE as u64 {
            return Err(SwitchError::InvalidRomFsHeader);
        }
        Ok(Self {
            header_size,
            dir_hash_table_offset: r8(8),
            dir_hash_table_size: r8(16),
            dir_metadata_offset: r8(24),
            dir_metadata_size: r8(32),
            file_hash_table_offset: r8(40),
            file_hash_table_size: r8(48),
            file_metadata_offset: r8(56),
            file_metadata_size: r8(64),
            data_offset: r8(72),
        })
    }
}

/// A file entry in a `RomFS`.
#[derive(Debug, Clone)]
pub struct RomFsEntry {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub is_directory: bool,
}

impl RomFsEntry {
    pub fn new_file(name: impl Into<String>, offset: u64, size: u64) -> Self {
        Self {
            name: name.into(),
            offset,
            size,
            is_directory: false,
        }
    }

    pub fn new_dir(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            offset: 0,
            size: 0,
            is_directory: true,
        }
    }
}

/// Minimal `RomFS` image representation.
#[derive(Debug, Default)]
pub struct SwitchRomFs {
    pub header: Option<RomFsHeader>,
    pub entries: Vec<RomFsEntry>,
    file_name_index: HashMap<String, usize>,
}

impl SwitchRomFs {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn set_header(&mut self, h: RomFsHeader) {
        self.header = Some(h);
    }

    pub fn add_entry(&mut self, entry: RomFsEntry) {
        let idx = self.entries.len();
        self.file_name_index.insert(entry.name.clone(), idx);
        self.entries.push(entry);
    }

    #[must_use]
    pub fn find(&self, name: &str) -> Option<&RomFsEntry> {
        self.file_name_index.get(name).map(|&i| &self.entries[i])
    }

    #[must_use]
    pub fn file_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.is_directory).count()
    }

    #[must_use]
    pub fn dir_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_directory).count()
    }
}

// ---------------------------------------------------------------------------
// NcaKeyAreaEntry — NCA key area structure
// ---------------------------------------------------------------------------

/// An encrypted key area entry in an NCA.
#[derive(Debug, Clone, Copy)]
pub struct NcaKeyAreaEntry {
    pub key_generation: u8,
    pub encrypted_key: [u8; 16],
}

impl NcaKeyAreaEntry {
    #[must_use]
    pub const fn new(key_gen: u8, key: [u8; 16]) -> Self {
        Self {
            key_generation: key_gen,
            encrypted_key: key,
        }
    }

    /// `true` if the key area is all zeros (no key present).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.encrypted_key == [0u8; 16]
    }
}

// ---------------------------------------------------------------------------
// SwitchNpdm — programme descriptor
// ---------------------------------------------------------------------------

/// Programme descriptor (NPDM) metadata.
#[derive(Debug, Clone)]
pub struct SwitchNpdm {
    pub title_id: u64,
    pub version: u32,
    pub main_thread_priority: u8,
    pub main_thread_core: u8,
    pub main_thread_stack_size: u32,
    pub system_resource_size: u32,
    pub process_category: u8,
    pub address_space_type: u8,
}

impl SwitchNpdm {
    pub const MAGIC: &'static [u8] = b"META";

    #[must_use]
    pub const fn new(title_id: u64) -> Self {
        Self {
            title_id,
            version: 0,
            main_thread_priority: 44,
            main_thread_core: 0,
            main_thread_stack_size: 0x0010_0000,
            system_resource_size: 0,
            process_category: 0,
            address_space_type: 3, // 64-bit
        }
    }

    /// `true` if this runs in 64-bit address space.
    #[must_use]
    pub const fn is_64bit(&self) -> bool {
        self.address_space_type == 3 || self.address_space_type == 1
    }

    /// `true` if this is a system process (category 1).
    #[must_use]
    pub const fn is_system_process(&self) -> bool {
        self.process_category == 1
    }
}

// ---------------------------------------------------------------------------
// SwitchRomFsIter — lazy RomFS entry iterator
// ---------------------------------------------------------------------------

/// Iterator over `RomFS` entries filtered by a predicate.
pub struct RomFsEntryIter<'a, F: Fn(&RomFsEntry) -> bool> {
    entries: &'a [RomFsEntry],
    pos: usize,
    predicate: F,
}

impl<'a, F: Fn(&RomFsEntry) -> bool> RomFsEntryIter<'a, F> {
    #[must_use]
    pub const fn new(entries: &'a [RomFsEntry], predicate: F) -> Self {
        Self {
            entries,
            pos: 0,
            predicate,
        }
    }
}

impl<'a, F: Fn(&RomFsEntry) -> bool> Iterator for RomFsEntryIter<'a, F> {
    type Item = &'a RomFsEntry;
    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.entries.len() {
            let e = &self.entries[self.pos];
            self.pos += 1;
            if (self.predicate)(e) {
                return Some(e);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// SwitchFormats — top-level aggregator
// ---------------------------------------------------------------------------

/// Complete Nintendo Switch format analysis.
#[derive(Debug, Default)]
pub struct SwitchFormats {
    pub nso: Option<NsoHeader>,
    pub nro: Option<NroHeader>,
    pub module_info: Option<NsoModuleInfo>,
    pub bss: Option<NsoBss>,
    pub romfs: Option<SwitchRomFs>,
}

impl SwitchFormats {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse an NSO binary.
    ///
    /// # Errors
    /// Returns [`SwitchError`] if the NSO data is invalid.
    pub fn load_nso(&mut self, data: &[u8]) -> Result<(), SwitchError> {
        let hdr = NsoHeader::parse(data)?;
        self.bss = Some(NsoBss::from_header(&hdr));
        self.nso = Some(hdr);
        Ok(())
    }

    /// Parse an NRO binary.
    ///
    /// # Errors
    /// Returns [`SwitchError`] if the NRO data is invalid.
    pub fn load_nro(&mut self, data: &[u8]) -> Result<(), SwitchError> {
        let hdr = NroHeader::parse(data)?;
        self.nro = Some(hdr);
        Ok(())
    }

    /// `true` if an NSO is loaded.
    #[must_use]
    pub const fn has_nso(&self) -> bool {
        self.nso.is_some()
    }
    /// `true` if an NRO is loaded.
    #[must_use]
    pub const fn has_nro(&self) -> bool {
        self.nro.is_some()
    }

    /// Entry point (NSO: `text_segment.memory_offset`, NRO: `text_offset`).
    #[must_use]
    pub const fn entry_point_offset(&self) -> u32 {
        if let Some(nso) = &self.nso {
            return nso.text_segment.memory_offset;
        }
        if let Some(nro) = &self.nro {
            return nro.text_offset;
        }
        0
    }
}

// ---------------------------------------------------------------------------
// NcaContentType — Nintendo Content Archive types
// ---------------------------------------------------------------------------

/// Type tag for an NCA content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NcaContentType {
    Program = 0,
    Meta = 1,
    Control = 2,
    Manual = 3,
    Data = 4,
    PublicData = 5,
}

impl NcaContentType {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Program),
            1 => Some(Self::Meta),
            2 => Some(Self::Control),
            3 => Some(Self::Manual),
            4 => Some(Self::Data),
            5 => Some(Self::PublicData),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Program => "Program",
            Self::Meta => "Meta",
            Self::Control => "Control",
            Self::Manual => "Manual",
            Self::Data => "Data",
            Self::PublicData => "PublicData",
        }
    }

    #[must_use]
    pub const fn is_executable(self) -> bool {
        matches!(self, Self::Program)
    }
}

// ---------------------------------------------------------------------------
// SwitchPermissions — Section permission flags in NSO/NRO
// ---------------------------------------------------------------------------

/// Memory permissions for a Switch binary section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchPermissions(pub u8);

impl SwitchPermissions {
    pub const READ: u8 = 0x01;
    pub const WRITE: u8 = 0x02;
    pub const EXECUTE: u8 = 0x04;

    #[must_use]
    pub const fn can_read(self) -> bool {
        self.0 & Self::READ != 0
    }
    #[must_use]
    pub const fn can_write(self) -> bool {
        self.0 & Self::WRITE != 0
    }
    #[must_use]
    pub const fn can_execute(self) -> bool {
        self.0 & Self::EXECUTE != 0
    }

    #[must_use]
    pub const fn from_nso_flags(flags: u32) -> Self {
        let mut p = 0u8;
        if flags & 0x01 != 0 {
            p |= Self::READ;
        }
        if flags & 0x02 != 0 {
            p |= Self::WRITE;
        }
        if flags & 0x04 != 0 {
            p |= Self::EXECUTE;
        }
        Self(p)
    }
}

// ---------------------------------------------------------------------------
// SwitchBinaryReport — summary report for Switch binaries
// ---------------------------------------------------------------------------

/// A summary report produced after loading a Switch binary.
#[derive(Debug, Clone)]
pub struct SwitchBinaryReport {
    pub format: SwitchBinaryFormat,
    pub is_compressed: bool,
    pub has_dynamic_section: bool,
    pub entry_point: u32,
    pub text_size: u32,
    pub rodata_size: u32,
    pub data_size: u32,
    pub bss_size: u32,
    pub total_virtual_size: u64,
    pub module_id: Option<[u8; 32]>,
}

/// Which Switch binary format was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchBinaryFormat {
    Nso,
    Nro,
    Unknown,
}

impl SwitchBinaryReport {
    /// Build from a [`SwitchFormats`] analysis.
    #[must_use]
    pub fn build(sf: &SwitchFormats) -> Self {
        if let Some(nso) = &sf.nso {
            return Self {
                format: SwitchBinaryFormat::Nso,
                is_compressed: nso.text_compressed()
                    || nso.rodata_compressed()
                    || nso.data_compressed(),
                has_dynamic_section: sf.module_info.is_some(),
                entry_point: nso.text_segment.memory_offset,
                text_size: nso.text_segment.size,
                rodata_size: nso.rodata_segment.size,
                data_size: nso.data_segment.size,
                bss_size: nso.bss_size,
                total_virtual_size: nso.image_size(),
                module_id: Some(nso.module_id),
            };
        }
        if let Some(nro) = &sf.nro {
            return Self {
                format: SwitchBinaryFormat::Nro,
                is_compressed: false,
                has_dynamic_section: false,
                entry_point: nro.text_offset,
                text_size: nro.text_size,
                rodata_size: nro.rodata_size,
                data_size: nro.data_size,
                bss_size: nro.bss_size,
                total_virtual_size: u64::from(nro.total_size()),
                module_id: None,
            };
        }
        Self {
            format: SwitchBinaryFormat::Unknown,
            is_compressed: false,
            has_dynamic_section: false,
            entry_point: 0,
            text_size: 0,
            rodata_size: 0,
            data_size: 0,
            bss_size: 0,
            total_virtual_size: 0,
            module_id: None,
        }
    }

    #[must_use]
    pub const fn is_nso(&self) -> bool {
        matches!(self.format, SwitchBinaryFormat::Nso)
    }
    #[must_use]
    pub const fn is_nro(&self) -> bool {
        matches!(self.format, SwitchBinaryFormat::Nro)
    }
}

// ---------------------------------------------------------------------------
// SwitchHashVerifier — SHA-256 verification of NSO segments
// ---------------------------------------------------------------------------

/// Verifies segment hashes stored in the NSO header.
pub struct SwitchHashVerifier;

impl SwitchHashVerifier {
    /// A minimal stub that checks whether the expected-hash field is all zeros
    /// (i.e., no hash present).
    #[must_use]
    pub fn has_text_hash(hdr: &NsoHeader) -> bool {
        hdr.flags & NsoHeader::FLAG_TEXT_HASH != 0 && hdr.text_hash != [0u8; 32]
    }

    #[must_use]
    pub fn has_rodata_hash(hdr: &NsoHeader) -> bool {
        hdr.flags & NsoHeader::FLAG_RODATA_HASH != 0 && hdr.rodata_hash != [0u8; 32]
    }

    #[must_use]
    pub fn has_data_hash(hdr: &NsoHeader) -> bool {
        hdr.flags & NsoHeader::FLAG_DATA_HASH != 0 && hdr.data_hash != [0u8; 32]
    }

    /// How many segment hashes are present.
    #[must_use]
    pub fn hash_count(hdr: &NsoHeader) -> usize {
        [
            Self::has_text_hash(hdr),
            Self::has_rodata_hash(hdr),
            Self::has_data_hash(hdr),
        ]
        .iter()
        .filter(|&&b| b)
        .count()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_nso_header(flags: u32) -> Vec<u8> {
        let mut data = vec![0u8; NsoHeader::SIZE];
        data[..4].copy_from_slice(NSO_MAGIC);
        data[12..16].copy_from_slice(&flags.to_le_bytes());
        // text segment: file_offset=0x100, mem_offset=0, size=0x1000
        data[16..20].copy_from_slice(&0x100u32.to_le_bytes());
        data[20..24].copy_from_slice(&0u32.to_le_bytes());
        data[24..28].copy_from_slice(&0x1000u32.to_le_bytes());
        // rodata segment: file_offset=0x1100, mem_offset=0x1000, size=0x800
        data[32..36].copy_from_slice(&0x1100u32.to_le_bytes());
        data[36..40].copy_from_slice(&0x1000u32.to_le_bytes());
        data[40..44].copy_from_slice(&0x800u32.to_le_bytes());
        // data segment: mem_offset=0x2000, size=0x400
        data[48..52].copy_from_slice(&0x1900u32.to_le_bytes());
        data[52..56].copy_from_slice(&0x2000u32.to_le_bytes());
        data[56..60].copy_from_slice(&0x400u32.to_le_bytes());
        // bss_size = 0x200
        data[60..64].copy_from_slice(&0x200u32.to_le_bytes());
        data
    }

    fn make_nro_header() -> Vec<u8> {
        let mut data = vec![0u8; NroHeader::SIZE];
        data[..4].copy_from_slice(NRO_MAGIC);
        data[12..16].copy_from_slice(&0x70u32.to_le_bytes()); // size = 0x70
        data[20..24].copy_from_slice(&0u32.to_le_bytes()); // text_offset
        data[24..28].copy_from_slice(&0x1000u32.to_le_bytes()); // text_size
        data[44..48].copy_from_slice(&0x200u32.to_le_bytes()); // bss_size
        data
    }

    // ---- NsoHeader ----

    #[test]
    fn test_nso_parse_invalid_magic() {
        let data = b"BAD0".repeat(NsoHeader::SIZE / 4);
        assert!(matches!(
            NsoHeader::parse(&data),
            Err(SwitchError::InvalidMagic { .. })
        ));
    }

    #[test]
    fn test_nso_parse_truncated() {
        assert!(matches!(
            NsoHeader::parse(&[0u8; 10]),
            Err(SwitchError::TruncatedData { .. })
        ));
    }

    #[test]
    fn test_nso_parse_ok() {
        let data = make_nso_header(0);
        let hdr = NsoHeader::parse(&data).unwrap();
        assert_eq!(&hdr.magic, NSO_MAGIC);
        assert_eq!(hdr.text_segment.size, 0x1000);
        assert_eq!(hdr.bss_size, 0x200);
    }

    #[test]
    fn test_nso_flags_text_compressed() {
        let data = make_nso_header(NsoHeader::FLAG_TEXT_COMPRESSED);
        let hdr = NsoHeader::parse(&data).unwrap();
        assert!(hdr.text_compressed());
        assert!(!hdr.rodata_compressed());
    }

    #[test]
    fn test_nso_flags_all_compressed() {
        let f = NsoHeader::FLAG_TEXT_COMPRESSED
            | NsoHeader::FLAG_RODATA_COMPRESSED
            | NsoHeader::FLAG_DATA_COMPRESSED;
        let data = make_nso_header(f);
        let hdr = NsoHeader::parse(&data).unwrap();
        assert!(hdr.text_compressed() && hdr.rodata_compressed() && hdr.data_compressed());
    }

    #[test]
    fn test_nso_image_size() {
        let data = make_nso_header(0);
        let hdr = NsoHeader::parse(&data).unwrap();
        // data_mem_offset(0x2000) + data_size(0x400) + bss(0x200) = 0x2600
        assert_eq!(hdr.image_size(), 0x2600);
    }

    #[test]
    fn test_nso_segment_info_empty() {
        let seg = NsoSegmentInfo::new(0, 0, 0);
        assert!(seg.is_empty());
    }

    #[test]
    fn test_nso_segment_info_not_empty() {
        let seg = NsoSegmentInfo::new(0x100, 0, 0x1000);
        assert!(!seg.is_empty());
    }

    // ---- NsoBss ----

    #[test]
    fn test_nso_bss_from_header() {
        let data = make_nso_header(0);
        let hdr = NsoHeader::parse(&data).unwrap();
        let bss = NsoBss::from_header(&hdr);
        assert_eq!(bss.offset, 0x2000 + 0x400); // data_mem + data_size
        assert_eq!(bss.size, 0x200);
        assert_eq!(bss.end_offset(), 0x2400 + 0x200);
    }

    #[test]
    fn test_nso_bss_is_empty() {
        let bss = NsoBss {
            offset: 0x100,
            size: 0,
        };
        assert!(bss.is_empty());
    }

    // ---- NsoModuleInfo ----

    #[test]
    fn test_mod0_parse_invalid_magic() {
        let data = [0xFFu8; NsoModuleInfo::SIZE];
        assert!(matches!(
            NsoModuleInfo::parse(&data),
            Err(SwitchError::InvalidModOffset(_))
        ));
    }

    #[test]
    fn test_mod0_parse_truncated() {
        assert!(matches!(
            NsoModuleInfo::parse(&[0u8; 4]),
            Err(SwitchError::TruncatedData { .. })
        ));
    }

    #[test]
    fn test_mod0_parse_ok() {
        let mut data = vec![0u8; NsoModuleInfo::SIZE];
        data[..4].copy_from_slice(&NsoModuleInfo::MAGIC.to_le_bytes());
        let info = NsoModuleInfo::parse(&data).unwrap();
        assert!(info.is_valid());
        assert_eq!(info.dynamic_offset, 0);
    }

    // ---- NroHeader ----

    #[test]
    fn test_nro_parse_invalid_magic() {
        let data = b"BAD0BAD0".repeat(20);
        assert!(matches!(
            NroHeader::parse(&data),
            Err(SwitchError::InvalidMagic { .. })
        ));
    }

    #[test]
    fn test_nro_parse_truncated() {
        assert!(matches!(
            NroHeader::parse(&[0u8; 10]),
            Err(SwitchError::TruncatedData { .. })
        ));
    }

    #[test]
    fn test_nro_parse_ok() {
        let data = make_nro_header();
        let hdr = NroHeader::parse(&data).unwrap();
        assert_eq!(hdr.text_size, 0x1000);
        assert_eq!(hdr.bss_size, 0x200);
    }

    #[test]
    fn test_nro_total_size() {
        let data = make_nro_header();
        let hdr = NroHeader::parse(&data).unwrap();
        assert_eq!(hdr.total_size(), 0x70 + 0x200);
    }

    // ---- RomFs ----

    #[test]
    fn test_romfs_header_truncated() {
        assert!(matches!(
            RomFsHeader::parse(&[0u8; 10]),
            Err(SwitchError::TruncatedData { .. })
        ));
    }

    #[test]
    fn test_romfs_header_invalid_size() {
        let mut data = vec![0u8; RomFsHeader::SIZE + 16];
        // header_size = 0 → invalid
        data[0..8].copy_from_slice(&0u64.to_le_bytes());
        assert!(matches!(
            RomFsHeader::parse(&data),
            Err(SwitchError::InvalidRomFsHeader)
        ));
    }

    #[test]
    fn test_romfs_header_valid() {
        let mut data = vec![0u8; 0x80];
        data[0..8].copy_from_slice(&(RomFsHeader::SIZE as u64).to_le_bytes());
        let hdr = RomFsHeader::parse(&data).unwrap();
        assert_eq!(hdr.header_size, RomFsHeader::SIZE as u64);
    }

    #[test]
    fn test_switch_romfs_add_and_find() {
        let mut fs = SwitchRomFs::new();
        fs.add_entry(RomFsEntry::new_file("main.npdm", 0x1000, 0x200));
        assert!(fs.find("main.npdm").is_some());
        assert!(fs.find("missing.txt").is_none());
    }

    #[test]
    fn test_switch_romfs_counts() {
        let mut fs = SwitchRomFs::new();
        fs.add_entry(RomFsEntry::new_file("a.dat", 0, 100));
        fs.add_entry(RomFsEntry::new_file("b.dat", 100, 200));
        fs.add_entry(RomFsEntry::new_dir("subdir"));
        assert_eq!(fs.file_count(), 2);
        assert_eq!(fs.dir_count(), 1);
    }

    // ---- SwitchFormats ----

    #[test]
    fn test_switch_formats_load_nso() {
        let mut sf = SwitchFormats::new();
        let data = make_nso_header(0);
        sf.load_nso(&data).unwrap();
        assert!(sf.has_nso());
        assert!(!sf.has_nro());
    }

    #[test]
    fn test_switch_formats_load_nro() {
        let mut sf = SwitchFormats::new();
        let data = make_nro_header();
        sf.load_nro(&data).unwrap();
        assert!(sf.has_nro());
        assert!(!sf.has_nso());
    }

    #[test]
    fn test_switch_formats_entry_point_nso() {
        let mut sf = SwitchFormats::new();
        let data = make_nso_header(0);
        sf.load_nso(&data).unwrap();
        // text_segment.memory_offset = 0
        assert_eq!(sf.entry_point_offset(), 0);
    }

    #[test]
    fn test_switch_formats_entry_point_nro() {
        let mut sf = SwitchFormats::new();
        let data = make_nro_header();
        sf.load_nro(&data).unwrap();
        assert_eq!(sf.entry_point_offset(), 0);
    }

    #[test]
    fn test_switch_formats_default_no_entry() {
        let sf = SwitchFormats::new();
        assert_eq!(sf.entry_point_offset(), 0);
    }

    #[test]
    fn test_switch_error_display() {
        let e = SwitchError::TooManyRelocations(99999);
        assert!(e.to_string().contains("99999"));
        let e2 = SwitchError::NroTooSmall { size: 4 };
        assert!(e2.to_string().contains('4'));
    }

    #[test]
    fn test_nso_version_field() {
        let mut data = make_nso_header(0);
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        let hdr = NsoHeader::parse(&data).unwrap();
        assert_eq!(hdr.version, 1);
    }

    #[test]
    fn test_romfs_entry_is_dir() {
        let e = RomFsEntry::new_dir("textures");
        assert!(e.is_directory);
        assert_eq!(e.size, 0);
    }

    #[test]
    fn test_mod0_is_valid_false() {
        let info = NsoModuleInfo {
            magic: 0xDEAD_BEEF,
            ..Default::default()
        };
        assert!(!info.is_valid());
    }

    #[test]
    fn test_nso_bss_end_offset_no_overflow() {
        let bss = NsoBss {
            offset: u32::MAX,
            size: 1,
        };
        // saturating_add should not panic
        let _ = bss.end_offset();
    }

    #[test]
    fn test_nso_header_module_name_offset() {
        let data = make_nso_header(0);
        let hdr = NsoHeader::parse(&data).unwrap();
        // module_name_offset is at offset 28, was zero-init
        assert_eq!(hdr.module_name_offset, 0);
    }

    #[test]
    fn test_nso_rodata_segment_present() {
        let data = make_nso_header(0);
        let hdr = NsoHeader::parse(&data).unwrap();
        assert_eq!(hdr.rodata_segment.memory_offset, 0x1000);
        assert_eq!(hdr.rodata_segment.size, 0x800);
    }

    #[test]
    fn test_nso_data_segment_present() {
        let data = make_nso_header(0);
        let hdr = NsoHeader::parse(&data).unwrap();
        assert_eq!(hdr.data_segment.memory_offset, 0x2000);
    }

    #[test]
    fn test_nso_hash_flag_text() {
        let f = NsoHeader::FLAG_TEXT_HASH;
        let data = make_nso_header(f);
        let hdr = NsoHeader::parse(&data).unwrap();
        assert!(hdr.flags & NsoHeader::FLAG_TEXT_HASH != 0);
    }

    #[test]
    fn test_romfs_file_count_only_files() {
        let mut fs = SwitchRomFs::new();
        fs.add_entry(RomFsEntry::new_file("a", 0, 10));
        fs.add_entry(RomFsEntry::new_file("b", 10, 20));
        assert_eq!(fs.file_count(), 2);
        assert_eq!(fs.dir_count(), 0);
    }

    #[test]
    fn test_nro_header_build_id_populated() {
        let mut data = make_nro_header();
        data[0x30..0x40].copy_from_slice(&[0xABu8; 16]);
        let hdr = NroHeader::parse(&data).unwrap();
        assert!(hdr.build_id.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_switch_formats_bss_populated_on_nso_load() {
        let mut sf = SwitchFormats::new();
        let data = make_nso_header(0);
        sf.load_nso(&data).unwrap();
        assert!(sf.bss.is_some());
        assert_eq!(sf.bss.as_ref().unwrap().size, 0x200);
    }

    #[test]
    fn test_mod0_dynamic_offset() {
        let mut data = vec![0u8; NsoModuleInfo::SIZE];
        data[..4].copy_from_slice(&NsoModuleInfo::MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&(-0x40i32).to_le_bytes());
        let info = NsoModuleInfo::parse(&data).unwrap();
        assert_eq!(info.dynamic_offset, -0x40);
    }

    #[test]
    fn test_nso_magic_bytes() {
        assert_eq!(NSO_MAGIC, b"NSO0");
    }

    #[test]
    fn test_nro_magic_bytes() {
        assert_eq!(NRO_MAGIC, b"NRO0");
    }

    #[test]
    fn test_romfs_find_missing() {
        let fs = SwitchRomFs::new();
        assert!(fs.find("anything").is_none());
    }

    #[test]
    fn test_switch_error_decompression() {
        let e = SwitchError::DecompressionError("lz4 failed".into());
        assert!(e.to_string().contains("lz4"));
    }

    #[test]
    fn test_switch_formats_module_info_can_be_set() {
        let mut sf = SwitchFormats::new();
        let mut data = vec![0u8; NsoModuleInfo::SIZE];
        data[..4].copy_from_slice(&NsoModuleInfo::MAGIC.to_le_bytes());
        let info = NsoModuleInfo::parse(&data).unwrap();
        sf.module_info = Some(info);
        assert!(sf.module_info.is_some());
    }
}

// ---------------------------------------------------------------------------
// NsoRebaseTable - relocation/rebase table for NSO
// ---------------------------------------------------------------------------

/// One rebase entry in the `.rebase` or `.reloc` section of an NSO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NsoRebaseEntry {
    pub offset: u64,
    pub rebase_type: NsoRebaseType,
}

/// Type of rebase operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsoRebaseType {
    Absolute64,
    Relative32,
    Unknown(u8),
}

impl NsoRebaseType {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Absolute64,
            2 => Self::Relative32,
            n => Self::Unknown(n),
        }
    }
}

impl NsoRebaseEntry {
    #[must_use]
    pub const fn new(offset: u64, t: u8) -> Self {
        Self {
            offset,
            rebase_type: NsoRebaseType::from_u8(t),
        }
    }
}

// ---------------------------------------------------------------------------
// SwitchElfABI - ELF-compatibility shim used in Switch homebrews
// ---------------------------------------------------------------------------

/// Switch homebrew ELF ABI constants.
pub mod switch_elf_abi {
    pub const OS_ABI_HORIZON: u8 = 0xFE;
    pub const ABI_VERSION_NRO: u8 = 0x00;
    pub const MODULE_HEADER_MAGIC: u32 = 0x3044_4F4D; // "MOD0"
}

// ---------------------------------------------------------------------------
// NsoImportSymbol - imported symbol in an NSO dynamic section
// ---------------------------------------------------------------------------

/// An imported symbol resolved from the `__dso_handle` + dynamic section.
#[derive(Debug, Clone)]
pub struct NsoImportSymbol {
    pub name: String,
    pub binding: u8,
    pub sym_type: u8,
    pub value: u64,
}

impl NsoImportSymbol {
    #[must_use]
    pub fn new(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            binding: 1,
            sym_type: 2,
            value,
        }
    }

    #[must_use]
    pub const fn is_function(&self) -> bool {
        self.sym_type == 2
    }
    #[must_use]
    pub const fn is_global(&self) -> bool {
        self.binding == 1
    }
}
// ---------------------------------------------------------------------------
// NsoSymbolTable - symbol table in NSO binary
// ---------------------------------------------------------------------------

/// A symbol entry from an NSO's `.dynsym`-equivalent section.
#[derive(Debug, Clone)]
pub struct NsoSymbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub sym_type: u8,
    pub binding: u8,
}

impl NsoSymbol {
    #[must_use]
    pub fn new(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            value,
            size: 0,
            sym_type: 2,
            binding: 1,
        }
    }
    #[must_use]
    pub const fn is_function(&self) -> bool {
        self.sym_type == 2
    }
    #[must_use]
    pub const fn is_global(&self) -> bool {
        self.binding == 1
    }
}

/// Symbol table for NSO binaries.
#[derive(Debug, Default)]
pub struct NsoSymbolTable {
    pub symbols: Vec<NsoSymbol>,
}

impl NsoSymbolTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, s: NsoSymbol) {
        self.symbols.push(s);
    }
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&NsoSymbol> {
        self.symbols.iter().find(|s| s.name == name)
    }
    #[must_use]
    pub fn functions(&self) -> Vec<&NsoSymbol> {
        self.symbols.iter().filter(|s| s.is_function()).collect()
    }
    #[must_use]
    pub const fn len(&self) -> usize {
        self.symbols.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

// ---------------------------------------------------------------------------
// SwitchFirmwareVersion - firmware version metadata
// ---------------------------------------------------------------------------

/// Nintendo Switch firmware version information.
#[derive(Debug, Clone)]
pub struct SwitchFirmwareVersion {
    pub major: u8,
    pub minor: u8,
    pub micro: u8,
    pub relstep: u8,
    pub platform_string: String,
    pub display_version: String,
    pub display_title: String,
}

impl SwitchFirmwareVersion {
    #[must_use]
    pub fn version_number(&self) -> u32 {
        u32::from(self.major) << 24
            | u32::from(self.minor) << 16
            | u32::from(self.micro) << 8
            | u32::from(self.relstep)
    }
    #[must_use]
    pub const fn is_at_least(&self, major: u8, minor: u8) -> bool {
        self.major > major || (self.major == major && self.minor >= minor)
    }
}

// ---------------------------------------------------------------------------
// SwitchProgramInfo - programme-level metadata aggregation
// ---------------------------------------------------------------------------

/// Programme metadata aggregated from NSO/NRO + NPDM + `RomFS`.
#[derive(Debug, Default)]
pub struct SwitchProgramInfo {
    pub title_id: u64,
    pub version: u32,
    pub sdk_version: Option<String>,
    pub has_romfs: bool,
    pub has_nacp: bool,
    pub text_size: u32,
    pub total_size: u64,
}

impl SwitchProgramInfo {
    #[must_use]
    pub fn new(title_id: u64) -> Self {
        Self {
            title_id,
            ..Default::default()
        }
    }
    #[must_use]
    pub fn title_id_hex(&self) -> String {
        format!("{:016X}", self.title_id)
    }
    #[must_use]
    pub const fn is_system_title(&self) -> bool {
        self.title_id & 0xFFFF_0000_0000_0000 == 0x0100_0000_0000_0000
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

/// Convert `usize` to `f64` for statistics. Uses u32 saturation so the result is exact
/// (u32 fits within f64's 52-bit mantissa); slices larger than 4 GiB saturate to `u32::MAX`.
fn usize_to_f64_stats(n: usize) -> f64 {
    let clamped = u32::try_from(n).unwrap_or(u32::MAX);
    f64::from(clamped)
}

/// Simple entropy estimate over a byte slice (0.0 = uniform, 1.0 = random).
#[must_use]
pub fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[usize::from(b)] += 1;
    }
    let n = usize_to_f64_stats(data.len());
    let mut entropy = 0.0f64;
    for &c in &freq {
        if c > 0 {
            let p = f64::from(c) / n;
            entropy = p.mul_add(-p.log2(), entropy);
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
///
/// # Panics
/// Panics if the slice conversion fails (impossible since bounds are checked).
#[inline]
#[must_use]
pub fn le_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}
/// Parse a little-endian u64.
///
/// # Panics
/// Panics if the slice conversion fails (impossible since bounds are checked).
#[inline]
#[must_use]
pub fn le_u64(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}
/// Parse a big-endian u32.
///
/// # Panics
/// Panics if the slice conversion fails (impossible since bounds are checked).
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
