// pdb_dbi_stream.rs — DBI (Debug Information) stream parser for PDB files
//
// The DBI stream (stream index 3) contains:
//   - DBI header with version, age, symbol stream index, etc.
//   - Module Info substream: per-compilation-unit symbol/line stream info
//   - Section Contribution substream: which sections each module contributes
//   - Section Map substream: logical section descriptions
//   - Source File substream: file name table
//   - Type Server Map substream
//   - EC substream (edit-and-continue)
//   - Optional Debug Header with indices for extra streams

use std::collections::HashMap;
use std::fmt;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors produced while parsing the DBI stream.
#[derive(Debug)]
pub enum DbiError {
    /// The buffer is smaller than the structure being read requires.
    TooShort {
        /// Number of bytes required.
        need: usize,
        /// Number of bytes actually available.
        have: usize,
    },
    /// The DBI signature was not -1 (0xFFFFFFFF).
    BadSignature(i32),
    /// The DBI version is not one of the known versions.
    UnsupportedVersion(u32),
    /// A substream's declared layout is inconsistent with the data.
    BadSubstreamLayout,
    /// A string field contained invalid UTF-8.
    Utf8Error(std::str::Utf8Error),
}

impl fmt::Display for DbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { need, have } => write!(f, "DBI too short: need {need}, have {have}"),
            Self::BadSignature(s) => write!(f, "DBI bad signature: {s:#x}"),
            Self::UnsupportedVersion(v) => write!(f, "DBI unsupported version: {v}"),
            Self::BadSubstreamLayout => write!(f, "DBI substream layout error"),
            Self::Utf8Error(e) => write!(f, "DBI UTF-8 error: {e}"),
        }
    }
}

impl std::error::Error for DbiError {}

impl From<std::str::Utf8Error> for DbiError {
    fn from(e: std::str::Utf8Error) -> Self { Self::Utf8Error(e) }
}

// ── DBI Header ────────────────────────────────────────────────────────────────

/// The DBI stream header (64 bytes)
#[derive(Debug, Clone)]
pub struct DbiHeader {
    /// Always -1 (0xFFFFFFFF as signed i32) for valid DBI streams
    pub signature: i32,
    /// DBI version number
    pub version: u32,
    /// Age of this DBI stream
    pub age: u32,
    /// Stream index of the global symbol hash stream
    pub global_stream_index: u16,
    /// Toolchain version packed into 16 bits
    pub build_number: u16,
    /// Stream index of the public symbol hash stream
    pub public_stream_index: u16,
    /// Version of mspdbXXX.dll used to build this PDB
    pub pdb_dll_version: u16,
    /// Stream index of the symbol records stream
    pub sym_record_stream: u16,
    /// Build major version of rbld
    pub pdb_dll_rbld: u16,
    /// Length of the module info substream in bytes
    pub mod_info_size: u32,
    /// Length of the section contribution substream in bytes
    pub section_contribution_size: u32,
    /// Length of the section map substream in bytes
    pub section_map_size: u32,
    /// Length of the source file substream in bytes
    pub source_file_size: u32,
    /// Length of the type server map substream
    pub type_server_map_size: u32,
    /// Index into the MFC type server lookup table
    pub mfc_type_server_index: u32,
    /// Length of the optional debug header substream
    pub optional_dbg_header_size: u32,
    /// Length of the edit-and-continue substream
    pub ec_substream_size: u32,
    /// Flags
    pub flags: u16,
    /// Machine type (`IMAGE_FILE_MACHINE_xxx`)
    pub machine_type: u16,
    /// Reserved padding
    pub reserved: u32,
}

impl DbiHeader {
    /// Size of the DBI header in bytes.
    pub const SIZE: usize = 64;
    /// Expected signature value (-1) for a valid DBI stream.
    pub const SIGNATURE: i32 = -1i32;
    /// DBI version V4.1 (930803).
    pub const VERSION_V41: u32 = 930_803;
    /// DBI version V5.0 (19960307).
    pub const VERSION_V50: u32 = 19_960_307;
    /// DBI version V6.0 (19970606).
    pub const VERSION_V60: u32 = 19_970_606;
    /// DBI version V7.0 (19990903), the most common modern version.
    pub const VERSION_V70: u32 = 19_990_903;
    /// DBI version V11.0 (20091201).
    pub const VERSION_V110: u32 = 20_091_201;

    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(data: &[u8]) -> Result<Self, DbiError> {
        if data.len() < Self::SIZE {
            return Err(DbiError::TooShort { need: Self::SIZE, have: data.len() });
        }
        let sig = read_i32_le(data, 0)?;
        if sig != Self::SIGNATURE {
            return Err(DbiError::BadSignature(sig));
        }
        let version = read_u32_le(data, 4)?;
        // Match on the named constants, not on bare literals: the five
        // `DbiHeader::VERSION_*` constants were declared and documented and
        // then nothing referenced them, so editing one silently did not change
        // what the parser accepts.
        match version {
            Self::VERSION_V41
            | Self::VERSION_V50
            | Self::VERSION_V60
            | Self::VERSION_V70
            | Self::VERSION_V110 => {}
            _ => return Err(DbiError::UnsupportedVersion(version)),
        }
        Ok(Self {
            signature: sig,
            version,
            age: read_u32_le(data, 8)?,
            global_stream_index: read_u16_le(data, 12)?,
            build_number: read_u16_le(data, 14)?,
            public_stream_index: read_u16_le(data, 16)?,
            pdb_dll_version: read_u16_le(data, 18)?,
            sym_record_stream: read_u16_le(data, 20)?,
            pdb_dll_rbld: read_u16_le(data, 22)?,
            mod_info_size: read_u32_le(data, 24)?,
            section_contribution_size: read_u32_le(data, 28)?,
            section_map_size: read_u32_le(data, 32)?,
            source_file_size: read_u32_le(data, 36)?,
            type_server_map_size: read_u32_le(data, 40)?,
            mfc_type_server_index: read_u32_le(data, 44)?,
            optional_dbg_header_size: read_u32_le(data, 48)?,
            ec_substream_size: read_u32_le(data, 52)?,
            flags: read_u16_le(data, 56)?,
            machine_type: read_u16_le(data, 58)?,
            reserved: read_u32_le(data, 60)?,
        })
    }

    /// Returns true if the incrementally linked bit is set
    #[must_use]
    pub const fn is_incrementally_linked(&self) -> bool { self.flags & 1 != 0 }
    /// Returns true if the stripped flag is set
    #[must_use]
    pub const fn is_stripped(&self) -> bool { self.flags & 2 != 0 }
    /// Returns true if the `CTypes` flag is set
    #[must_use]
    pub const fn has_ctypes(&self) -> bool { self.flags & 4 != 0 }

    /// Decode the `build_number` field into (major, minor, `is_clang`)
    #[must_use]
    pub const fn build_components(&self) -> (u8, u8, bool) {
        let major = ((self.build_number >> 8) & 0x7F) as u8;
        let minor = (self.build_number & 0xFF) as u8;
        let is_clang = (self.build_number & 0x8000) != 0;
        (major, minor, is_clang)
    }

    /// Human-readable machine name
    #[must_use]
    pub const fn machine_name(&self) -> &'static str {
        match self.machine_type {
            0x014C => "x86",
            0x0162 => "MIPS R3000",
            0x0166 => "MIPS R4000",
            0x01A2 => "SH3",
            0x01A4 => "SH3-DSP",
            0x01A6 => "SH3E",
            0x01A8 => "SH4",
            0x01B3 => "SH5",
            0x01C0 => "ARM",
            0x01C2 => "THUMB",
            0x01C4 => "ARMV7",
            0x01D3 => "AM33",
            0x01F0 => "PowerPC",
            0x01F1 => "PowerPC-FP",
            0x0200 => "IA-64",
            0x0266 => "MIPS16",
            0x0284 => "Alpha64",
            0x0366 => "MIPSFPU",
            0x0466 => "MIPSFPU16",
            0x0520 => "TriCore",
            0x0CEF => "CEF",
            0x0EBC => "EFI ByteCode",
            0x8664 => "x86-64",
            0x9041 => "M32R",
            0xAA64 => "ARM64",
            0xC0EE => "CEE",
            _ => "Unknown",
        }
    }
}

// ── Module Info ───────────────────────────────────────────────────────────────

/// One entry in the Module Info substream.
/// Each entry describes a compilation unit (object file / lib member).
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Unused/padding field
    pub unused1: u32,
    /// First section contribution record embedded in the module header
    pub section_contr: SectionContribEntry,
    /// Module flags (written, EC enabled, type server index)
    pub flags: u16,
    /// Stream index for this module's symbol/line data (0xFFFF = none)
    pub module_sym_stream: u16,
    /// Byte count of `CodeView` symbol records in the module sym stream
    pub sym_byte_size: u32,
    /// Byte count of C11 line number info (deprecated)
    pub c11_byte_size: u32,
    /// Byte count of C13 line number info
    pub c13_byte_size: u32,
    /// Number of source file contributions for this module
    pub source_file_count: u16,
    /// Padding
    pub padding: u16,
    /// Offset into the EC substream (edit-and-continue)
    pub unused2: u32,
    /// Offset of the module name in the EC names table
    pub source_file_name_index: u32,
    /// Offset of the compiler PDB path in the EC names table
    pub pdb_file_path_name_index: u32,
    /// Module name (null-terminated C string after fixed header)
    pub module_name: String,
    /// Object file name (null-terminated C string after module name)
    pub obj_file_name: String,
}

impl ModuleInfo {
    /// Fixed header size before the two variable-length strings
    pub const FIXED_SIZE: usize = 4 + SectionContribEntry::SIZE + 2 + 2 + 4 + 4 + 4 + 2 + 2 + 4 + 4 + 4;

    /// Returns true if this module has a symbol stream (index != 0xFFFF).
    #[must_use]
    pub const fn has_symbols(&self) -> bool { self.module_sym_stream != 0xFFFF }
    /// Type server index extracted from the high byte of `flags`.
    #[must_use]
    pub const fn type_server_index(&self) -> u8 { (self.flags >> 8) as u8 }
    /// Returns true if edit-and-continue is enabled for this module.
    #[must_use]
    pub const fn ec_enabled(&self) -> bool { self.flags & 2 != 0 }
}

/// Parse the module info substream into a Vec of `ModuleInfo`
/// # Errors
///
/// Returns an error if parsing fails.
pub fn parse_module_info(data: &[u8]) -> Result<Vec<ModuleInfo>, DbiError> {
    let mut modules = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        if offset + ModuleInfo::FIXED_SIZE > data.len() {
            break;
        }

        let unused1 = read_u32_le(data, offset)?;
        let section_contr = SectionContribEntry::parse(data, offset + 4)?;
        let flags = read_u16_le(data, offset + 4 + SectionContribEntry::SIZE)?;
        let module_sym_stream = read_u16_le(data, offset + 6 + SectionContribEntry::SIZE)?;
        let sym_byte_size = read_u32_le(data, offset + 8 + SectionContribEntry::SIZE)?;
        let c11_byte_size = read_u32_le(data, offset + 12 + SectionContribEntry::SIZE)?;
        let c13_byte_size = read_u32_le(data, offset + 16 + SectionContribEntry::SIZE)?;
        let source_file_count = read_u16_le(data, offset + 20 + SectionContribEntry::SIZE)?;
        let padding = read_u16_le(data, offset + 22 + SectionContribEntry::SIZE)?;
        let unused2 = read_u32_le(data, offset + 24 + SectionContribEntry::SIZE)?;
        let source_file_name_index = read_u32_le(data, offset + 28 + SectionContribEntry::SIZE)?;
        let pdb_file_path_name_index = read_u32_le(data, offset + 32 + SectionContribEntry::SIZE)?;

        let str_start = offset + ModuleInfo::FIXED_SIZE;
        let (module_name, after_mod) = read_cstring_slice(data, str_start);
        let (obj_file_name, after_obj) = read_cstring_slice(data, after_mod);

        // Align to 4-byte boundary
        let end_aligned = align4(after_obj);

        modules.push(ModuleInfo {
            unused1,
            section_contr,
            flags,
            module_sym_stream,
            sym_byte_size,
            c11_byte_size,
            c13_byte_size,
            source_file_count,
            padding,
            unused2,
            source_file_name_index,
            pdb_file_path_name_index,
            module_name,
            obj_file_name,
        });

        offset = end_aligned;
    }

    Ok(modules)
}

// ── Section Contributions ─────────────────────────────────────────────────────

/// Version tag embedded at start of section contribution substream
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SectionContribVersion {
    /// Version 1 (28-byte entries).
    V1 = 0xF12E_BA2D,
    /// Version 2 (32-byte entries with a trailing `ISectCoff` field).
    V2 = 0xF131_51E4,
}

/// One section contribution entry (V1, 28 bytes)
#[derive(Debug, Clone)]
pub struct SectionContribEntry {
    /// Section index (1-based)
    pub section: u16,
    /// Alignment padding after the section index
    pub padding1: u16,
    /// Offset within the section
    pub offset: u32,
    /// Size of the contribution in bytes
    pub size: u32,
    /// Characteristics (`IMAGE_SCN_xxx` flags)
    pub characteristics: u32,
    /// Index into module info array (0-based)
    pub module_index: u16,
    /// Alignment padding after the module index
    pub padding2: u16,
    /// CRC of the contribution data
    pub data_crc: u32,
    /// CRC of the relocation data
    pub reloc_crc: u32,
}

impl SectionContribEntry {
    /// Size of a V1 section contribution entry in bytes.
    pub const SIZE: usize = 28;

    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, DbiError> {
        if offset + Self::SIZE > data.len() {
            return Err(DbiError::TooShort { need: offset + Self::SIZE, have: data.len() });
        }
        Ok(Self {
            section: read_u16_le(data, offset)?,
            padding1: read_u16_le(data, offset + 2)?,
            offset: read_u32_le(data, offset + 4)?,
            size: read_u32_le(data, offset + 8)?,
            characteristics: read_u32_le(data, offset + 12)?,
            module_index: read_u16_le(data, offset + 16)?,
            padding2: read_u16_le(data, offset + 18)?,
            data_crc: read_u32_le(data, offset + 20)?,
            reloc_crc: read_u32_le(data, offset + 24)?,
        })
    }

    /// Returns true if the contribution is code (`IMAGE_SCN_CNT_CODE`).
    #[must_use]
    pub const fn is_code(&self) -> bool { self.characteristics & 0x0000_0020 != 0 }
    /// Returns true if the contribution is initialized data.
    #[must_use]
    pub const fn is_initialized_data(&self) -> bool { self.characteristics & 0x0000_0040 != 0 }
    /// Returns true if the contribution is uninitialized data (BSS).
    #[must_use]
    pub const fn is_uninitialized_data(&self) -> bool { self.characteristics & 0x0000_0080 != 0 }
    /// Returns true if the section is executable (`IMAGE_SCN_MEM_EXECUTE`).
    #[must_use]
    pub const fn is_executable(&self) -> bool { self.characteristics & 0x2000_0000 != 0 }
    /// Returns true if the section is readable (`IMAGE_SCN_MEM_READ`).
    #[must_use]
    pub const fn is_readable(&self) -> bool { self.characteristics & 0x4000_0000 != 0 }
    /// Returns true if the section is writable (`IMAGE_SCN_MEM_WRITE`).
    #[must_use]
    pub const fn is_writable(&self) -> bool { self.characteristics & 0x8000_0000 != 0 }

    /// One-past-the-end offset of the contribution within its section.
    #[must_use]
    pub const fn end_offset(&self) -> u32 { self.offset.saturating_add(self.size) }
    /// Returns true if `rva` falls inside this contribution, given the section's base RVA.
    #[must_use]
    pub const fn contains_rva(&self, section_rva_base: u32, rva: u32) -> bool {
        rva >= section_rva_base.saturating_add(self.offset)
            && rva < section_rva_base.saturating_add(self.offset).saturating_add(self.size)
    }
}

/// V2 section contribution: the 28-byte base plus a trailing `ISectCoff` u32,
/// 32 bytes total (see [`SectionContribEntryV2::SIZE`]).
#[derive(Debug, Clone)]
pub struct SectionContribEntryV2 {
    /// The 28-byte V1 contribution entry
    pub base: SectionContribEntry,
    /// Trailing `ISectCoff` value appended in V2
    pub iso_line: u32,
}

impl SectionContribEntryV2 {
    /// Size of a V2 section contribution entry in bytes.
    pub const SIZE: usize = SectionContribEntry::SIZE + 4;

    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, DbiError> {
        let base = SectionContribEntry::parse(data, offset)?;
        if offset + Self::SIZE > data.len() {
            return Err(DbiError::TooShort { need: offset + Self::SIZE, have: data.len() });
        }
        let iso_line = read_u32_le(data, offset + SectionContribEntry::SIZE)?;
        Ok(Self { base, iso_line })
    }
}

/// Parse the section contribution substream
/// # Errors
///
/// Returns an error if parsing fails.
pub fn parse_section_contributions(data: &[u8]) -> Result<Vec<SectionContribEntry>, DbiError> {
    if data.len() < 4 {
        return Ok(vec![]);
    }
    let version = read_u32_le(data, 0)?;
    let entry_size = if version == SectionContribVersion::V2 as u32 {
        SectionContribEntryV2::SIZE
    } else {
        SectionContribEntry::SIZE
    };

    let body = &data[4..];
    if !body.len().is_multiple_of(entry_size) {
        // Tolerate trailing bytes
    }
    let count = body.len() / entry_size;
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let e = SectionContribEntry::parse(body, i * entry_size)?;
        entries.push(e);
    }
    Ok(entries)
}

// ── Section Map ───────────────────────────────────────────────────────────────

/// Section map header (4 bytes)
#[derive(Debug, Clone)]
pub struct SectionMapHeader {
    /// Total count of segment descriptors
    pub count: u16,
    /// Count of logical segment descriptors
    pub log_count: u16,
}

/// One entry in the section map
#[derive(Debug, Clone)]
pub struct SectionMapEntry {
    /// Descriptor flags (read/write/execute/32-bit/selector/absolute/group)
    pub flags: u16,
    /// Logical overlay number
    pub ovl: u16,
    /// Group index into the descriptor array
    pub group: u16,
    /// Frame index
    pub frame: u16,
    /// Byte index of the segment name in the string table (0xFFFF = none)
    pub section_name: u16,
    /// Byte index of the class name in the string table (0xFFFF = none)
    pub class_name: u16,
    /// Byte offset of the logical segment within the physical segment
    pub offset: u32,
    /// Byte count of the segment or group
    pub section_length: u32,
}

impl SectionMapEntry {
    /// Size of a section map entry in bytes.
    pub const SIZE: usize = 20;

    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, DbiError> {
        if offset + Self::SIZE > data.len() {
            return Err(DbiError::TooShort { need: offset + Self::SIZE, have: data.len() });
        }
        Ok(Self {
            flags: read_u16_le(data, offset)?,
            ovl: read_u16_le(data, offset + 2)?,
            group: read_u16_le(data, offset + 4)?,
            frame: read_u16_le(data, offset + 6)?,
            section_name: read_u16_le(data, offset + 8)?,
            class_name: read_u16_le(data, offset + 10)?,
            offset: read_u32_le(data, offset + 12)?,
            section_length: read_u32_le(data, offset + 16)?,
        })
    }

    /// Returns true if the segment is readable.
    #[must_use]
    pub const fn is_read(&self) -> bool { self.flags & 0x0001 != 0 }
    /// Returns true if the segment is writable.
    #[must_use]
    pub const fn is_write(&self) -> bool { self.flags & 0x0002 != 0 }
    /// Returns true if the segment is executable.
    #[must_use]
    pub const fn is_execute(&self) -> bool { self.flags & 0x0004 != 0 }
    /// Returns true if the descriptor describes a 32-bit linear address.
    #[must_use]
    pub const fn is_32bit(&self) -> bool { self.flags & 0x0008 != 0 }
    /// Returns true if the frame represents a selector.
    #[must_use]
    pub const fn is_selector(&self) -> bool { self.flags & 0x0100 != 0 }
    /// Returns true if the frame represents an absolute address.
    #[must_use]
    pub const fn is_absolute(&self) -> bool { self.flags & 0x0200 != 0 }
    /// Returns true if the descriptor represents a group.
    #[must_use]
    pub const fn is_group(&self) -> bool { self.flags & 0x0400 != 0 }
}

/// Parse the section map substream into its entries.
///
/// # Errors
///
/// Returns an error if parsing fails.
pub fn parse_section_map(data: &[u8]) -> Result<Vec<SectionMapEntry>, DbiError> {
    if data.len() < 4 {
        return Ok(vec![]);
    }
    let count = read_u16_le(data, 0)? as usize;
    // Cap the reservation against what the buffer can actually hold: `count` is
    // file-declared and a truncated substream must not drive the allocation.
    let capped = count.min(data.len().saturating_sub(4) / SectionMapEntry::SIZE);
    let mut entries = Vec::with_capacity(capped);
    for i in 0..count {
        let offset = 4 + i * SectionMapEntry::SIZE;
        if offset + SectionMapEntry::SIZE > data.len() {
            break;
        }
        entries.push(SectionMapEntry::parse(data, offset)?);
    }
    Ok(entries)
}

// ── Source File Table ─────────────────────────────────────────────────────────

/// Parsed source file information for a single module
#[derive(Debug, Clone)]
pub struct ModuleSourceFiles {
    /// Index of the module in the module info array
    pub module_index: usize,
    /// Source file names contributing to this module
    pub file_names: Vec<String>,
}

/// All source file information for the entire PDB
#[derive(Debug, Clone)]
pub struct SourceFileTable {
    /// Map from module index to list of source file names
    pub modules: Vec<ModuleSourceFiles>,
    /// All unique file names, deduplicated
    pub unique_files: Vec<String>,
}

impl SourceFileTable {
    /// Iterate over all unique source file names.
    pub fn all_files(&self) -> impl Iterator<Item = &str> {
        self.unique_files.iter().map(std::string::String::as_str)
    }

    /// Return the source file names for the given module index, if known.
    #[must_use]
    pub fn files_for_module(&self, module_idx: usize) -> Option<&[String]> {
        self.modules.iter()
            .find(|m| m.module_index == module_idx)
            .map(|m| m.file_names.as_slice())
    }

    /// Find all module indices whose source files contain `file_name` (case-insensitive substring).
    #[must_use]
    pub fn find_module_for_file(&self, file_name: &str) -> Vec<usize> {
        let lower = file_name.to_lowercase();
        self.modules.iter()
            .filter(|m| m.file_names.iter().any(|f| f.to_lowercase().contains(&lower)))
            .map(|m| m.module_index)
            .collect()
    }
}

/// Parse the source file substream.
///
/// Layout:
///   u16 `module_count`, u16 `total_source_file_count` (may be saturated to 0xFFFF)
///   u16[`module_count`] `mod_indices` (truncated prefix sums — ignored)
///   u16[`module_count`] `source_file_count_per_module`
///   u32[`total_source_file_count`] `file_name_offsets`
///   followed by string data
/// # Errors
///
/// Returns an error if parsing fails.
pub fn parse_source_file_table(data: &[u8]) -> Result<SourceFileTable, DbiError> {
    if data.len() < 4 {
        return Ok(SourceFileTable { modules: vec![], unique_files: vec![] });
    }
    let module_count = read_u16_le(data, 0)? as usize;
    let header_total_files = read_u16_le(data, 2)? as usize;

    // Real DBI layout after the header: u16 mod_indices[module_count]
    // (truncated prefix sums — ignored), then u16 mod_file_counts[module_count],
    // then u32 file_name_offsets[total_files], then the string buffer.

    // The counts array sits at 4 + module_count*2, *before* the offsets array,
    // so it is reachable without trusting the header count. Parse it first.
    let counts_start = 4 + module_count * 2;
    if data.len() < counts_start + module_count * 2 {
        return Err(DbiError::BadSubstreamLayout);
    }
    let mut module_file_counts = Vec::with_capacity(module_count);
    for i in 0..module_count {
        module_file_counts.push(read_u16_le(data, counts_start + i * 2)? as usize);
    }

    // `NumSourceFiles` is a u16 and is truncated/saturated by the linker once
    // the real count exceeds 65535. The authoritative value is the sum of
    // ModFileCounts; using the header value would put `string_table_start`
    // inside the offsets array and decode offset bytes as filenames.
    let actual_total: usize = module_file_counts.iter().sum();
    let total_files = actual_total.max(header_total_files);

    let offsets_start = 4 + module_count * 4;
    // Degrade rather than failing the whole substream: clamp the offsets array
    // to what the buffer actually holds and emit empty names for the rest.
    let available = data.len().saturating_sub(offsets_start) / 4;
    let readable_files = total_files.min(available);

    let mut file_offsets = Vec::with_capacity(readable_files);
    for i in 0..readable_files {
        file_offsets.push(read_u32_le(data, offsets_start + i * 4)? as usize);
    }

    let string_table_start = offsets_start + total_files * 4;

    // Decode all file names
    let mut all_names = Vec::with_capacity(readable_files);
    for &off in &file_offsets {
        let abs = match string_table_start.checked_add(off) {
            Some(a) if a < data.len() => a,
            _ => {
                all_names.push(String::new());
                continue;
            }
        };
        let (name, _) = read_cstring_slice(data, abs);
        all_names.push(name);
    }

    // Build per-module view
    let mut modules = Vec::with_capacity(module_count);
    let mut file_idx = 0usize;
    for (mod_i, &fc) in module_file_counts.iter().enumerate() {
        let mut names = Vec::with_capacity(fc.min(all_names.len()));
        for _ in 0..fc {
            // Names past the readable prefix come back empty rather than being
            // dropped, so per-module indices stay aligned.
            names.push(all_names.get(file_idx).cloned().unwrap_or_default());
            file_idx += 1;
        }
        modules.push(ModuleSourceFiles { module_index: mod_i, file_names: names });
    }

    // Build unique file set
    let mut seen = HashMap::new();
    let mut unique_files = Vec::new();
    for name in &all_names {
        if !name.is_empty() && !seen.contains_key(name.as_str()) {
            seen.insert(name.clone(), unique_files.len());
            unique_files.push(name.clone());
        }
    }

    Ok(SourceFileTable { modules, unique_files })
}

// ── Optional Debug Header ─────────────────────────────────────────────────────

/// The optional debug header at the end of the DBI stream.
/// Each field is a stream index (0xFFFF = absent).
#[derive(Debug, Clone)]
pub struct OptionalDbgHeader {
    /// Stream index of FPO (frame pointer omission) data
    pub fpo_data: u16,
    /// Stream index of exception data
    pub exception_data: u16,
    /// Stream index of fixup data
    pub fixup_data: u16,
    /// Stream index of OMAP-to-source mapping data
    pub omap_to_src: u16,
    /// Stream index of OMAP-from-source mapping data
    pub omap_from_src: u16,
    /// Stream index of a copy of the PE section headers
    pub section_header_data: u16,
    /// Stream index of the token-to-RID map (managed code)
    pub token_rid_map: u16,
    /// Stream index of a copy of the .xdata section
    pub xdata: u16,
    /// Stream index of a copy of the .pdata section
    pub pdata: u16,
    /// Stream index of new-style FPO data
    pub new_fpo_data: u16,
    /// Stream index of the original (pre-OMAP) section headers
    pub orig_section_header_data: u16,
}

impl OptionalDbgHeader {
    /// Size of the optional debug header in bytes.
    pub const SIZE: usize = 22;
    /// Sentinel stream index meaning "stream absent".
    pub const ABSENT: u16 = 0xFFFF;

    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(data: &[u8]) -> Result<Self, DbiError> {
        if data.len() < Self::SIZE {
            return Err(DbiError::TooShort { need: Self::SIZE, have: data.len() });
        }
        Ok(Self {
            fpo_data: read_u16_le(data, 0)?,
            exception_data: read_u16_le(data, 2)?,
            fixup_data: read_u16_le(data, 4)?,
            omap_to_src: read_u16_le(data, 6)?,
            omap_from_src: read_u16_le(data, 8)?,
            section_header_data: read_u16_le(data, 10)?,
            token_rid_map: read_u16_le(data, 12)?,
            xdata: read_u16_le(data, 14)?,
            pdata: read_u16_le(data, 16)?,
            new_fpo_data: read_u16_le(data, 18)?,
            orig_section_header_data: read_u16_le(data, 20)?,
        })
    }

    /// Returns true if an FPO data stream is present.
    #[must_use]
    pub const fn has_fpo_data(&self) -> bool { self.fpo_data != Self::ABSENT }
    /// Returns true if a section headers copy stream is present.
    #[must_use]
    pub const fn has_section_headers(&self) -> bool { self.section_header_data != Self::ABSENT }
    /// Returns true if an OMAP-to-source stream is present.
    #[must_use]
    pub const fn has_omap_to_src(&self) -> bool { self.omap_to_src != Self::ABSENT }
    /// Returns true if an OMAP-from-source stream is present.
    #[must_use]
    pub const fn has_omap_from_src(&self) -> bool { self.omap_from_src != Self::ABSENT }
    /// Returns true if an .xdata copy stream is present.
    #[must_use]
    pub const fn has_xdata(&self) -> bool { self.xdata != Self::ABSENT }
    /// Returns true if a .pdata copy stream is present.
    #[must_use]
    pub const fn has_pdata(&self) -> bool { self.pdata != Self::ABSENT }
    /// Returns true if a new-style FPO data stream is present.
    #[must_use]
    pub const fn has_new_fpo_data(&self) -> bool { self.new_fpo_data != Self::ABSENT }
}

// ── Compile Flags (from CodeView records) ─────────────────────────────────────

/// Language identifier as stored in `S_COMPILE3` records
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompileLanguage {
    /// C
    C = 0,
    /// C++
    Cpp = 1,
    /// Fortran
    Fortran = 2,
    /// Microsoft Macro Assembler
    Masm = 3,
    /// Pascal
    Pascal = 4,
    /// Basic
    Basic = 5,
    /// COBOL
    Cobol = 6,
    /// Linker-generated module
    Link = 7,
    /// CVTRES resource converter
    Cvtres = 8,
    /// CVTPGD (PGO conversion tool)
    Cvtpgd = 9,
    /// C#
    CSharp = 10,
    /// Visual Basic
    VB = 11,
    /// IL assembler
    ILAsm = 12,
    /// Java
    Java = 13,
    /// `JScript`
    JScript = 14,
    /// Microsoft Intermediate Language
    MSIL = 15,
    /// High-Level Shader Language
    HLSL = 16,
    /// Objective-C
    ObjC = 17,
    /// Objective-C++
    ObjCpp = 18,
    /// Swift
    Swift = 19,
    /// Alias object module
    AliasObj = 20,
    /// Rust
    Rust = 21,
    /// Go
    Go = 22,
    /// Unrecognized language code
    Unknown = 0xFF,
}

impl CompileLanguage {
    /// Decode a raw language byte into a `CompileLanguage`.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::C, 1 => Self::Cpp, 2 => Self::Fortran, 3 => Self::Masm,
            4 => Self::Pascal, 5 => Self::Basic, 6 => Self::Cobol,
            7 => Self::Link, 8 => Self::Cvtres, 9 => Self::Cvtpgd,
            10 => Self::CSharp, 11 => Self::VB, 12 => Self::ILAsm,
            13 => Self::Java, 14 => Self::JScript, 15 => Self::MSIL,
            16 => Self::HLSL, 17 => Self::ObjC, 18 => Self::ObjCpp,
            19 => Self::Swift, 20 => Self::AliasObj, 21 => Self::Rust,
            22 => Self::Go, _ => Self::Unknown,
        }
    }

    /// Human-readable language name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::C => "C", Self::Cpp => "C++", Self::Fortran => "Fortran",
            Self::Masm => "MASM", Self::Pascal => "Pascal", Self::Basic => "Basic",
            Self::Cobol => "COBOL", Self::Link => "LINK", Self::Cvtres => "CVTRES",
            Self::Cvtpgd => "CVTPGD", Self::CSharp => "C#", Self::VB => "Visual Basic",
            Self::ILAsm => "IL ASM", Self::Java => "Java", Self::JScript => "JScript",
            Self::MSIL => "MSIL", Self::HLSL => "HLSL", Self::ObjC => "Objective-C",
            Self::ObjCpp => "Objective-C++", Self::Swift => "Swift",
            Self::AliasObj => "Alias Obj", Self::Rust => "Rust", Self::Go => "Go",
            Self::Unknown => "Unknown",
        }
    }
}

/// Compile3 flags decoded from `S_COMPILE3` symbol record.
///
/// The boolean attributes are stored as a packed bitmask to keep the struct
/// small; access each one via the matching `is_*` / accessor method.
#[derive(Debug, Clone, Copy)]
pub struct CompileFlags3 {
    /// Source language of the compiled module
    pub language: CompileLanguage,
    bits: u32,
}

impl CompileFlags3 {
    const EC_BIT: u32              = 1 << 8;
    const NO_DBG_INFO_BIT: u32     = 1 << 9;
    const LTCG_BIT: u32            = 1 << 10;
    const NO_DATA_ALIGN_BIT: u32   = 1 << 11;
    const MANAGED_PRESENT_BIT: u32 = 1 << 12;
    const SECURITY_CHECKS_BIT: u32 = 1 << 13;
    const HOT_PATCH_BIT: u32       = 1 << 14;
    const CVTCIL_BIT: u32          = 1 << 15;
    const MSIL_MODULE_BIT: u32     = 1 << 16;
    const SDL_BIT: u32             = 1 << 17;
    const PGO_BIT: u32             = 1 << 18;
    const EXP_MODULE_BIT: u32      = 1 << 19;

    /// Compiled with edit-and-continue support.
    #[must_use] pub const fn ec(&self) -> bool { self.bits & Self::EC_BIT != 0 }
    /// Compiled without debug info.
    #[must_use] pub const fn no_dbg_info(&self) -> bool { self.bits & Self::NO_DBG_INFO_BIT != 0 }
    /// Compiled with link-time code generation (/LTCG).
    #[must_use] pub const fn ltcg(&self) -> bool { self.bits & Self::LTCG_BIT != 0 }
    /// Compiled with /bzalign (no data alignment).
    #[must_use] pub const fn no_data_align(&self) -> bool { self.bits & Self::NO_DATA_ALIGN_BIT != 0 }
    /// Managed code or data is present.
    #[must_use] pub const fn managed_present(&self) -> bool { self.bits & Self::MANAGED_PRESENT_BIT != 0 }
    /// Compiled with security checks (/GS).
    #[must_use] pub const fn security_checks(&self) -> bool { self.bits & Self::SECURITY_CHECKS_BIT != 0 }
    /// Compiled with hot-patching support (/hotpatch).
    #[must_use] pub const fn hot_patch(&self) -> bool { self.bits & Self::HOT_PATCH_BIT != 0 }
    /// Converted with CVTCIL.
    #[must_use] pub const fn cvtcil(&self) -> bool { self.bits & Self::CVTCIL_BIT != 0 }
    /// Module is an MSIL netmodule.
    #[must_use] pub const fn msil_module(&self) -> bool { self.bits & Self::MSIL_MODULE_BIT != 0 }
    /// Compiled with SDL checks (/sdl).
    #[must_use] pub const fn sdl(&self) -> bool { self.bits & Self::SDL_BIT != 0 }
    /// Compiled with profile-guided optimization (/ltcg:pgo).
    #[must_use] pub const fn pgo(&self) -> bool { self.bits & Self::PGO_BIT != 0 }
    /// Module is an .exp (export) module.
    #[must_use] pub const fn exp_module(&self) -> bool { self.bits & Self::EXP_MODULE_BIT != 0 }
}

impl CompileFlags3 {
    /// Decode the packed `S_COMPILE3` flags dword.
    #[must_use]
    pub const fn parse(flags: u32) -> Self {
        Self {
            language: CompileLanguage::from_u8((flags & 0xFF) as u8),
            bits: flags,
        }
    }
}

// ── DBI Stream (top-level) ─────────────────────────────────────────────────────

/// Complete parsed DBI stream
#[derive(Debug)]
pub struct DbiStream {
    /// The fixed 64-byte DBI header
    pub header: DbiHeader,
    /// Parsed module info records (one per compilation unit)
    pub modules: Vec<ModuleInfo>,
    /// Parsed section contribution entries
    pub section_contributions: Vec<SectionContribEntry>,
    /// Parsed section map entries
    pub section_map: Vec<SectionMapEntry>,
    /// Parsed source file table
    pub source_files: SourceFileTable,
    /// The optional debug header, if present
    pub optional_dbg_header: Option<OptionalDbgHeader>,
}

impl DbiStream {
    /// Parse the entire DBI stream from raw bytes
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(data: &[u8]) -> Result<Self, DbiError> {
        let header = DbiHeader::parse(data)?;

        let mut offset = DbiHeader::SIZE;

        // Module info substream
        let mi_end = offset + header.mod_info_size as usize;
        if mi_end > data.len() {
            return Err(DbiError::TooShort { need: mi_end, have: data.len() });
        }
        let modules = parse_module_info(&data[offset..mi_end])?;
        offset = mi_end;

        // Section contribution substream
        let sc_end = offset + header.section_contribution_size as usize;
        if sc_end > data.len() {
            return Err(DbiError::TooShort { need: sc_end, have: data.len() });
        }
        let section_contributions = parse_section_contributions(&data[offset..sc_end])?;
        offset = sc_end;

        // Section map substream
        let section_map_end = offset + header.section_map_size as usize;
        if section_map_end > data.len() {
            return Err(DbiError::TooShort { need: section_map_end, have: data.len() });
        }
        let section_map = parse_section_map(&data[offset..section_map_end])?;
        offset = section_map_end;

        // Source file substream
        let source_file_end = offset + header.source_file_size as usize;
        if source_file_end > data.len() {
            return Err(DbiError::TooShort { need: source_file_end, have: data.len() });
        }
        let source_files = parse_source_file_table(&data[offset..source_file_end])?;
        offset = source_file_end;

        // Skip type server map and EC substream
        offset += header.type_server_map_size as usize;
        offset += header.ec_substream_size as usize;

        // Optional debug header
        let odh_size = header.optional_dbg_header_size as usize;
        let optional_dbg_header = if odh_size >= OptionalDbgHeader::SIZE && offset + odh_size <= data.len() {
            Some(OptionalDbgHeader::parse(&data[offset..offset + odh_size])?)
        } else {
            None
        };

        Ok(Self { header, modules, section_contributions, section_map, source_files, optional_dbg_header })
    }

    /// Find a module by its name (exact match)
    #[must_use]
    pub fn find_module_by_name(&self, name: &str) -> Option<&ModuleInfo> {
        self.modules.iter().find(|m| m.module_name == name)
    }

    /// Find a module by its object file name
    #[must_use]
    pub fn find_module_by_obj(&self, obj: &str) -> Option<&ModuleInfo> {
        self.modules.iter().find(|m| m.obj_file_name == obj)
    }

    /// Return all section contributions that belong to the given module index
    pub fn contributions_for_module(&self, module_idx: u16) -> impl Iterator<Item = &SectionContribEntry> {
        self.section_contributions.iter().filter(move |sc| sc.module_index == module_idx)
    }

    /// Enumerate modules that contain code (`sym_byte_size` > 0)
    pub fn code_modules(&self) -> impl Iterator<Item = &ModuleInfo> {
        self.modules.iter().filter(|m| m.sym_byte_size > 0)
    }

    /// Print a human-readable summary
    #[must_use]
    pub const fn summary(&self) -> DbiSummary {
        DbiSummary {
            version: self.header.version,
            machine: self.header.machine_name(),
            module_count: self.modules.len(),
            section_contrib_count: self.section_contributions.len(),
            unique_source_files: self.source_files.unique_files.len(),
            global_stream: self.header.global_stream_index,
            public_stream: self.header.public_stream_index,
            sym_record_stream: self.header.sym_record_stream,
            has_dbg_header: self.optional_dbg_header.is_some(),
        }
    }
}

/// Human-readable summary of a parsed DBI stream.
#[derive(Debug)]
pub struct DbiSummary {
    /// DBI version number
    pub version: u32,
    /// Human-readable machine name
    pub machine: &'static str,
    /// Number of modules
    pub module_count: usize,
    /// Number of section contribution entries
    pub section_contrib_count: usize,
    /// Number of unique source files
    pub unique_source_files: usize,
    /// Stream index of the global symbol hash stream
    pub global_stream: u16,
    /// Stream index of the public symbol hash stream
    pub public_stream: u16,
    /// Stream index of the symbol records stream
    pub sym_record_stream: u16,
    /// Whether the optional debug header is present
    pub has_dbg_header: bool,
}

impl fmt::Display for DbiSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "DBI Stream Summary")?;
        writeln!(f, "  Version           : {}", self.version)?;
        writeln!(f, "  Machine           : {}", self.machine)?;
        writeln!(f, "  Modules           : {}", self.module_count)?;
        writeln!(f, "  Section contribs  : {}", self.section_contrib_count)?;
        writeln!(f, "  Unique source files: {}", self.unique_source_files)?;
        writeln!(f, "  Global stream idx : {}", self.global_stream)?;
        writeln!(f, "  Public stream idx : {}", self.public_stream)?;
        writeln!(f, "  Symbol rec stream : {}", self.sym_record_stream)?;
        write!(f, "  Debug header      : {}", if self.has_dbg_header { "present" } else { "absent" })
    }
}

// ── Compile Flags Scanner ──────────────────────────────────────────────────────

/// Scan a module's symbol stream for `S_COMPILE3` records to extract build metadata
#[must_use]
pub fn scan_module_compile_flags(sym_data: &[u8]) -> Vec<ModuleCompileInfo> {
    const S_COMPILE3: u16 = 0x113C;
    let mut results = Vec::new();
    let mut offset = 0usize;

    while offset + 4 <= sym_data.len() {
        let (Ok(rec_len), Ok(rec_type)) =
            (read_u16_le(sym_data, offset), read_u16_le(sym_data, offset + 2))
        else {
            break;
        };
        let rec_len = rec_len as usize;
        let next = offset + 2 + rec_len;

        if rec_type == S_COMPILE3 && offset + 4 + 8 <= sym_data.len() {
            let body = &sym_data[offset + 4..];
            // Need at least 22 bytes for fields + 1 byte for the NUL-terminated compiler string
            if body.len() >= 23
                && let Ok(info) = parse_compile3_body(body)
            {
                results.push(info);
            }
        }

        if next <= offset || next > sym_data.len() {
            break;
        }
        offset = next;
    }
    results
}

fn parse_compile3_body(body: &[u8]) -> Result<ModuleCompileInfo, DbiError> {
    let flags = CompileFlags3::parse(read_u32_le(body, 0)?);
    let machine = read_u16_le(body, 4)?;
    let fe_version = (
        read_u16_le(body, 6)?,
        read_u16_le(body, 8)?,
        read_u16_le(body, 10)?,
        read_u16_le(body, 12)?,
    );
    let be_version = (
        read_u16_le(body, 14)?,
        read_u16_le(body, 16)?,
        read_u16_le(body, 18)?,
        read_u16_le(body, 20)?,
    );
    let (compiler_version, _) = read_cstring_slice(body, 22);
    Ok(ModuleCompileInfo { flags, machine, fe_version, be_version, compiler_version })
}

/// Build metadata extracted from `S_COMPILE3` symbol records
#[derive(Debug, Clone)]
pub struct ModuleCompileInfo {
    /// Decoded `S_COMPILE3` flags (language + build attributes)
    pub flags: CompileFlags3,
    /// Target machine type (`CV_CPU_TYPE_e`)
    pub machine: u16,
    /// (major, minor, build, QFE) of the front-end compiler
    pub fe_version: (u16, u16, u16, u16),
    /// (major, minor, build, QFE) of the back-end compiler
    pub be_version: (u16, u16, u16, u16),
    /// Compiler version string (e.g. "Microsoft (R) Optimizing Compiler")
    pub compiler_version: String,
}

impl ModuleCompileInfo {
    /// Human-readable name of the module's source language.
    #[must_use]
    pub const fn language_name(&self) -> &'static str { self.flags.language.name() }
    /// Front-end compiler version formatted as "major.minor.build.QFE".
    #[must_use]
    pub fn fe_version_string(&self) -> String {
        let (a, b, c, d) = self.fe_version;
        format!("{a}.{b}.{c}.{d}")
    }
    /// Back-end compiler version formatted as "major.minor.build.QFE".
    #[must_use]
    pub fn be_version_string(&self) -> String {
        let (a, b, c, d) = self.be_version;
        format!("{a}.{b}.{c}.{d}")
    }
    /// Returns true if the module was compiled from Rust.
    #[must_use]
    pub fn is_rust_module(&self) -> bool { self.flags.language == CompileLanguage::Rust }
    /// Returns true if the module was compiled from C++.
    #[must_use]
    pub fn is_cpp_module(&self) -> bool { self.flags.language == CompileLanguage::Cpp }
}

// ── Internal helpers ───────────────────────────────────────────────────────────

// These used to fabricate zeros on an out-of-bounds read, which turned a
// truncated substream into a silently-empty parse (e.g. `parse_section_map`
// reporting `count == 0`). They now surface `DbiError::TooShort` instead.

fn read_bytes<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], DbiError> {
    let end = offset.checked_add(N).ok_or(DbiError::TooShort { need: usize::MAX, have: data.len() })?;
    let slice = data
        .get(offset..end)
        .ok_or(DbiError::TooShort { need: end, have: data.len() })?;
    <[u8; N]>::try_from(slice).map_err(|_| DbiError::TooShort { need: end, have: data.len() })
}

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16, DbiError> {
    Ok(u16::from_le_bytes(read_bytes::<2>(data, offset)?))
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, DbiError> {
    Ok(u32::from_le_bytes(read_bytes::<4>(data, offset)?))
}

fn read_i32_le(data: &[u8], offset: usize) -> Result<i32, DbiError> {
    Ok(i32::from_le_bytes(read_bytes::<4>(data, offset)?))
}

/// Read a null-terminated C string from data at offset. Returns (string, `next_offset`).
fn read_cstring_slice(data: &[u8], offset: usize) -> (String, usize) {
    let start = offset;
    let mut i = offset;
    while i < data.len() && data[i] != 0 {
        i += 1;
    }
    let s = std::str::from_utf8(&data[start..i])
        .map_or_else(|_| String::from_utf8_lossy(&data[start..i]).into_owned(), std::string::ToString::to_string);
    // Only skip the NUL if we actually found one (i < data.len()); if we hit
    // the end of the buffer without a NUL, do not advance past the end.
    let next = if i < data.len() { i + 1 } else { i };
    (s, next)
}

const fn align4(offset: usize) -> usize {
    (offset + 3) & !3
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The five `DbiHeader::VERSION_*` constants were dead: the accept-set was
    /// spelled as bare literals beside them. This pins each named constant to
    /// the accept-set, so the two can no longer drift apart.
    #[test]
    fn every_named_dbi_version_constant_is_accepted() {
        for v in [
            DbiHeader::VERSION_V41,
            DbiHeader::VERSION_V50,
            DbiHeader::VERSION_V60,
            DbiHeader::VERSION_V70,
            DbiHeader::VERSION_V110,
        ] {
            let mut d = vec![0u8; DbiHeader::SIZE];
            d[0..4].copy_from_slice(&DbiHeader::SIGNATURE.to_le_bytes());
            d[4..8].copy_from_slice(&v.to_le_bytes());
            assert!(DbiHeader::parse(&d).is_ok(), "version {v} rejected");
        }
        let mut d = vec![0u8; DbiHeader::SIZE];
        d[0..4].copy_from_slice(&DbiHeader::SIGNATURE.to_le_bytes());
        d[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            DbiHeader::parse(&d),
            Err(DbiError::UnsupportedVersion(1))
        ));
    }

    // ── Bounds-checked scalar readers ────────────────────────────────────────
    // These used to return a fabricated 0 past the end of the buffer, so a
    // truncated substream decoded as a structurally valid one full of zeros.

    #[test]
    fn read_helpers_reject_out_of_bounds_instead_of_returning_zero() {
        let data = [1u8, 2, 3];
        assert_eq!(read_u16_le(&data, 0).unwrap(), 0x0201);
        assert!(read_u16_le(&data, 2).is_err(), "1 byte left, needs 2");
        assert!(read_u16_le(&data, 3).is_err());
        assert!(read_u32_le(&data, 0).is_err(), "3 bytes left, needs 4");
        assert!(read_i32_le(&data, 0).is_err());
        // An offset that would overflow when the width is added must not panic.
        assert!(read_u32_le(&data, usize::MAX).is_err());
    }

    #[test]
    fn section_map_with_bogus_count_does_not_over_allocate() {
        // Header declares 65535 entries but only one entry's worth follows.
        let mut data = vec![0u8; 4 + SectionMapEntry::SIZE];
        data[0..2].copy_from_slice(&u16::MAX.to_le_bytes());
        let entries = parse_section_map(&data).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries.capacity() <= 2, "capacity must track the buffer, not the header");
    }

    fn make_dbi_header_bytes() -> Vec<u8> {
        let mut v = vec![0u8; DbiHeader::SIZE];
        // signature = -1i32
        v[0..4].copy_from_slice(&(-1i32).to_le_bytes());
        // version = V70
        v[4..8].copy_from_slice(&(19_990_903u32).to_le_bytes());
        // age = 1
        v[8..12].copy_from_slice(&1u32.to_le_bytes());
        // global_stream_index = 7
        v[12..14].copy_from_slice(&7u16.to_le_bytes());
        // machine_type = 0x8664 (x86-64)
        v[58..60].copy_from_slice(&0x8664u16.to_le_bytes());
        v
    }

    #[test]
    fn test_dbi_header_parse_valid() {
        let data = make_dbi_header_bytes();
        let hdr = DbiHeader::parse(&data).unwrap();
        assert_eq!(hdr.signature, -1);
        assert_eq!(hdr.version, 19_990_903);
        assert_eq!(hdr.age, 1);
        assert_eq!(hdr.global_stream_index, 7);
        assert_eq!(hdr.machine_name(), "x86-64");
    }

    #[test]
    fn test_dbi_header_bad_signature() {
        let mut data = make_dbi_header_bytes();
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(DbiHeader::parse(&data), Err(DbiError::BadSignature(_))));
    }

    #[test]
    fn test_dbi_header_too_short() {
        let data = vec![0u8; 10];
        assert!(matches!(DbiHeader::parse(&data), Err(DbiError::TooShort { .. })));
    }

    #[test]
    fn test_section_contrib_entry_parse() {
        let mut data = vec![0u8; SectionContribEntry::SIZE];
        data[0..2].copy_from_slice(&1u16.to_le_bytes()); // section = 1
        data[4..8].copy_from_slice(&0x1000u32.to_le_bytes()); // offset = 0x1000
        data[8..12].copy_from_slice(&0x200u32.to_le_bytes()); // size = 0x200
        data[12..16].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // code+exec+read
        let e = SectionContribEntry::parse(&data, 0).unwrap();
        assert_eq!(e.section, 1);
        assert_eq!(e.offset, 0x1000);
        assert_eq!(e.size, 0x200);
        assert!(e.is_code());
        assert!(e.is_readable());
        assert!(e.is_executable());
    }

    #[test]
    fn test_compile_flags3_parse() {
        // language=Rust (21), security_checks=1
        let flags: u32 = 0x15 | (1 << 13);
        let cf = CompileFlags3::parse(flags);
        assert_eq!(cf.language, CompileLanguage::Rust);
        assert!(cf.security_checks());
        assert!(!cf.ltcg());
    }

    #[test]
    fn test_source_file_table_empty() {
        let data = vec![];
        let t = parse_source_file_table(&data).unwrap();
        assert!(t.modules.is_empty());
        assert!(t.unique_files.is_empty());
    }

    #[test]
    fn test_section_contribution_parse_empty_v1() {
        // Just a V1 version tag, no entries
        let mut data = vec![0u8; 4];
        data[0..4].copy_from_slice(&(SectionContribVersion::V1 as u32).to_le_bytes());
        let entries = parse_section_contributions(&data).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_align4() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
    }
}
