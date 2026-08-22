//! PDB DBI (Debug Information) stream reader.
//!
//! The DBI stream (stream index 3) contains module information, section contributions,
//! section map, file information, and other debug metadata.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced while parsing the DBI stream.
#[derive(Debug)]
pub enum DbiError {
    /// The stream ended before the parser could read the required bytes.
    UnexpectedEof {
        /// Offset at which more data was needed.
        offset: usize,
        /// Number of additional bytes required.
        needed: usize,
    },
    /// The DBI signature is not `0xFFFFFFFF`.
    BadSignature {
        /// The signature value actually read.
        got: u32,
    },
    /// The DBI version tag is not a known value.
    BadVersion {
        /// The version value actually read.
        got: i32,
    },
    /// A string in the stream is not valid UTF-8.
    InvalidUtf8 {
        /// Offset of the invalid string.
        offset: usize,
    },
    /// A module name string is missing its NUL terminator.
    InvalidModuleName,
    /// A section index referenced a section that does not exist.
    SectionIndexOutOfRange {
        /// The out-of-range section index.
        index: u16,
    },
}

impl fmt::Display for DbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { offset, needed } =>
                write!(f, "unexpected EOF at offset {offset}: needed {needed} more bytes"),
            Self::BadSignature { got } =>
                write!(f, "bad DBI signature: expected 0xFFFFFFFF, got 0x{got:08X}"),
            Self::BadVersion { got } =>
                write!(f, "unsupported DBI version: {got}"),
            Self::InvalidUtf8 { offset } =>
                write!(f, "invalid UTF-8 at offset {offset}"),
            Self::InvalidModuleName =>
                write!(f, "module name string is malformed"),
            Self::SectionIndexOutOfRange { index } =>
                write!(f, "section index {index} is out of range"),
        }
    }
}

impl std::error::Error for DbiError {}

/// Result alias for DBI stream parsing.
pub type DbiResult<T> = Result<T, DbiError>;

// ---------------------------------------------------------------------------
// DBI Header (new-format)
// ---------------------------------------------------------------------------

/// Fixed-size DBI stream header (64 bytes).
#[derive(Debug, Clone)]
pub struct DbiHeader {
    /// Always 0xFFFFFFFF for the new DBI format.
    pub signature: u32,
    /// Version tag. Common values: 19930803, 19950623, 19960307, 19970606, 19990903, 20091201.
    pub version: i32,
    /// Age: incremented each time the PDB is written.
    pub age: u32,
    /// Global symbol stream index.
    pub global_stream_index: u16,
    /// Build major/minor/PDB DLL version packed field.
    pub build_number: u16,
    /// Public symbol stream index.
    pub public_stream_index: u16,
    /// Version of mspdbXXX.dll that built this PDB.
    pub pdb_dll_version: u16,
    /// Symbol records stream index.
    pub sym_record_stream: u16,
    /// Rebuild-flag: non-zero if the PDB was rebuilt.
    pub pdb_dll_rbld: u16,
    /// Size in bytes of the module info sub-stream.
    pub mod_info_size: i32,
    /// Size in bytes of the section contribution sub-stream.
    pub section_contribution_size: i32,
    /// Size in bytes of the section map sub-stream.
    pub section_map_size: i32,
    /// Size in bytes of the source file info sub-stream.
    pub source_file_info_size: i32,
    /// Size in bytes of the type server map sub-stream.
    pub type_server_map_size: u32,
    /// Index of the MFC type server in the type server map.
    pub mfc_type_server_index: u32,
    /// Size in bytes of the optional debug header sub-stream.
    pub optional_dbg_header_size: i32,
    /// Size in bytes of the edit-and-continue sub-stream.
    pub ec_sub_stream_size: i32,
    /// Misc flags.
    pub flags: u16,
    /// Machine type (`IMAGE_FILE_MACHINE_`* constants).
    pub machine: u16,
    /// Reserved.
    pub padding: u32,
}

/// Infallible little-endian readers used by the record parsers below.
///
/// They replace the `slice.try_into().unwrap()` idiom: `try_into` on a slice of
/// statically-unknown length yields a `Result`, and the `unwrap` made every
/// parser a *documented panic path* even though the length had just been
/// checked. `first_chunk` proves the length to the type system instead, so a
/// truncated or maliciously short DBI record can no longer reach a panic;
/// the caller's own bounds check remains the only error path.
fn le_u16_at(s: &[u8], off: usize) -> Option<u16> {
    s.get(off..)
        .and_then(|t| t.first_chunk::<2>())
        .map(|b| u16::from_le_bytes(*b))
}

/// Little-endian `u32` at `off`, or `None` when fewer than 4 bytes remain.
fn le_u32_at(s: &[u8], off: usize) -> Option<u32> {
    s.get(off..)
        .and_then(|t| t.first_chunk::<4>())
        .map(|b| u32::from_le_bytes(*b))
}

/// Little-endian `i32` at `off`, or `None` when fewer than 4 bytes remain.
fn le_i32_at(s: &[u8], off: usize) -> Option<i32> {
    le_u32_at(s, off).map(u32::cast_signed)
}

impl DbiHeader {
    /// On-disk size of the DBI header in bytes.
    pub const SIZE: usize = 64;

    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(data: &[u8]) -> DbiResult<Self> {
        if data.len() < Self::SIZE {
            return Err(DbiError::UnexpectedEof { offset: 0, needed: Self::SIZE });
        }
        let u16_at = |off: usize| -> DbiResult<u16> {
            le_u16_at(data, off).ok_or(DbiError::UnexpectedEof { offset: off, needed: 2 })
        };
        let u32_at = |off: usize| -> DbiResult<u32> {
            le_u32_at(data, off).ok_or(DbiError::UnexpectedEof { offset: off, needed: 4 })
        };
        let i32_at = |off: usize| -> DbiResult<i32> {
            le_i32_at(data, off).ok_or(DbiError::UnexpectedEof { offset: off, needed: 4 })
        };

        let signature = u32_at(0)?;
        if signature != 0xFFFF_FFFF {
            return Err(DbiError::BadSignature { got: signature });
        }
        let version = i32_at(4)?;
        // Accept known versions. `PdbDbiV41` is 930803 (NOT 19930803); the
        // 19-prefixed values are kept so existing callers/fixtures that were
        // built against the old accept set keep working.
        let known = [
            930_803i32,
            19_930_803,
            19_950_623,
            19_960_307,
            19_970_606,
            19_990_903,
            20_091_201,
        ];
        if !known.contains(&version) {
            return Err(DbiError::BadVersion { got: version });
        }

        Ok(Self {
            signature,
            version,
            age: u32_at(8)?,
            global_stream_index: u16_at(12)?,
            build_number: u16_at(14)?,
            public_stream_index: u16_at(16)?,
            pdb_dll_version: u16_at(18)?,
            sym_record_stream: u16_at(20)?,
            pdb_dll_rbld: u16_at(22)?,
            mod_info_size: i32_at(24)?,
            section_contribution_size: i32_at(28)?,
            section_map_size: i32_at(32)?,
            source_file_info_size: i32_at(36)?,
            type_server_map_size: u32_at(40)?,
            mfc_type_server_index: u32_at(44)?,
            optional_dbg_header_size: i32_at(48)?,
            ec_sub_stream_size: i32_at(52)?,
            flags: u16_at(56)?,
            machine: u16_at(58)?,
            padding: u32_at(60)?,
        })
    }

    /// Returns true if the PDB was built incrementally.
    #[must_use]
    pub const fn is_incremental_link(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// Returns true if private symbols have been stripped.
    #[must_use]
    pub const fn private_syms_stripped(&self) -> bool {
        self.flags & 0x0002 != 0
    }

    /// Returns true if this PDB is associated with a conflicting type server.
    #[must_use]
    pub const fn conflicting_types(&self) -> bool {
        self.flags & 0x0004 != 0
    }
}

// ---------------------------------------------------------------------------
// Module info (MODI_60_Persist in LLVM parlance)
// ---------------------------------------------------------------------------

/// Describes one object-file module contributing to the linked image.
#[derive(Debug, Clone)]
pub struct ModInfo {
    /// Unused (set to 0).
    pub unused1: u32,
    /// Section contribution of this module's first section.
    pub section_contribution: SectionContrib,
    /// Misc flags (`written_since_open` | `ec_enabled` | `type_server_index`).
    pub flags: u16,
    /// Index of the module's symbol stream, or 0xFFFF if none.
    pub module_sym_stream: u16,
    /// Byte count of all `CodeView` symbol records in the module's sym stream.
    pub sym_byte_size: u32,
    /// Byte count of the C11-style line-number data.
    pub c11_byte_size: u32,
    /// Byte count of the C13-style line-number data.
    pub c13_byte_size: u32,
    /// Number of source files contributing to this module.
    pub source_file_count: u16,
    /// Padding.
    pub padding: u16,
    /// Unused.
    pub unused2: u32,
    /// Offset into the names buffer (in the source file info sub-stream).
    pub source_file_name_index: u32,
    /// Offset into the names buffer for this module's PDB path (for type servers).
    pub pdb_file_path_name_index: u32,
    /// Null-terminated module name (object file path).
    pub module_name: String,
    /// Null-terminated object file name (may be empty).
    pub obj_file_name: String,
}

impl ModInfo {
    /// Minimum fixed-size portion before the variable-length strings.
    pub const FIXED_SIZE: usize = 4 + SectionContrib::SIZE + 2 + 2 + 4 + 4 + 4 + 2 + 2 + 4 + 4 + 4;

    /// Parse a `ModInfo` record from `data[offset..]`.  Returns (record, `bytes_consumed`).
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(data: &[u8], offset: usize) -> DbiResult<(Self, usize)> {
        if data.len() < offset + Self::FIXED_SIZE {
            return Err(DbiError::UnexpectedEof { offset, needed: Self::FIXED_SIZE });
        }
        let slice = &data[offset..];

        let u16_at = |off: usize| -> DbiResult<u16> {
            le_u16_at(slice, off)
                .ok_or(DbiError::UnexpectedEof { offset: offset + off, needed: 2 })
        };
        let u32_at = |off: usize| -> DbiResult<u32> {
            le_u32_at(slice, off)
                .ok_or(DbiError::UnexpectedEof { offset: offset + off, needed: 4 })
        };

        let unused1 = u32_at(0)?;
        let section_contribution = SectionContrib::parse(slice, 4)?;
        let sc_size = SectionContrib::SIZE;
        let base = 4 + sc_size;
        let flags = u16_at(base)?;
        let module_sym_stream = u16_at(base + 2)?;
        let sym_byte_size = u32_at(base + 4)?;
        let c11_byte_size = u32_at(base + 8)?;
        let c13_byte_size = u32_at(base + 12)?;
        let source_file_count = u16_at(base + 16)?;
        let padding = u16_at(base + 18)?;
        let unused2 = u32_at(base + 20)?;
        let source_file_name_index = u32_at(base + 24)?;
        let pdb_file_path_name_index = u32_at(base + 28)?;

        let str_start = base + 32;
        let (module_name, n1) = read_cstr(slice, str_start, offset)?;
        let (obj_file_name, n2) = read_cstr(slice, str_start + n1, offset + str_start + n1)?;

        // Align to 4-byte boundary
        let raw_end = str_start + n1 + n2;
        let aligned_end = (raw_end + 3) & !3;
        let consumed = aligned_end;

        Ok((
            Self {
                unused1,
                section_contribution,
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
            },
            consumed,
        ))
    }

    /// Returns the type-server index embedded in `flags`.
    #[must_use]
    pub const fn type_server_index(&self) -> u8 {
        ((self.flags >> 8) & 0xFF) as u8
    }

    /// Returns true if the module has been written since the PDB was opened.
    #[must_use]
    pub const fn written_since_open(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// Returns true if edit-and-continue is enabled for this module.
    #[must_use]
    pub const fn ec_enabled(&self) -> bool {
        self.flags & 0x0002 != 0
    }
}

// ---------------------------------------------------------------------------
// Section contribution
// ---------------------------------------------------------------------------

/// Describes the contribution of a module to one section of the image.
#[derive(Debug, Clone, Default)]
pub struct SectionContrib {
    /// 1-based section index.
    pub section: u16,
    /// Alignment padding.
    pub padding1: u16,
    /// Byte offset within the section.
    pub offset: u32,
    /// Byte size of the contribution.
    pub size: u32,
    /// `IMAGE_SCN_`* characteristics flags.
    pub characteristics: u32,
    /// Index of the module that owns this contribution (0-based).
    pub module_index: u16,
    /// Alignment padding.
    pub padding2: u16,
    /// CRC of the contribution's data (may be 0).
    pub data_crc: u32,
    /// CRC of the contribution's relocations (may be 0).
    pub reloc_crc: u32,
}

impl SectionContrib {
    /// On-disk size of a `Ver60` section contribution record in bytes.
    pub const SIZE: usize = 28;

    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(data: &[u8], offset: usize) -> DbiResult<Self> {
        let s = data.get(offset..offset + Self::SIZE)
            .ok_or(DbiError::UnexpectedEof { offset, needed: Self::SIZE })?;
        let u16_at = |o: usize| le_u16_at(s, o).unwrap_or(0);
        let u32_at = |o: usize| le_u32_at(s, o).unwrap_or(0);
        Ok(Self {
            section: u16_at(0),
            padding1: u16_at(2),
            offset: u32_at(4),
            size: u32_at(8),
            characteristics: u32_at(12),
            module_index: u16_at(16),
            padding2: u16_at(18),
            data_crc: u32_at(20),
            reloc_crc: u32_at(24),
        })
    }

    /// Returns true if this contribution contains executable code.
    #[must_use]
    pub const fn is_code(&self) -> bool {
        self.characteristics & 0x0000_0020 != 0
    }

    /// Returns true if this contribution contains initialised data.
    #[must_use]
    pub const fn is_initialized_data(&self) -> bool {
        self.characteristics & 0x0000_0040 != 0
    }

    /// Returns true if this contribution contains uninitialised data (BSS).
    #[must_use]
    pub const fn is_uninitialized_data(&self) -> bool {
        self.characteristics & 0x0000_0080 != 0
    }
}

// ---------------------------------------------------------------------------
// Section map
// ---------------------------------------------------------------------------

/// One entry in the section map sub-stream.
#[derive(Debug, Clone)]
pub struct SectionMapEntry {
    /// `OMF` segment descriptor flags (read/write/execute/32-bit...).
    pub flags: u16,
    /// Logical overlay number.
    pub ovl: u16,
    /// Group index into the descriptor array.
    pub group: u16,
    /// Frame index (1-based section number).
    pub frame: u16,
    /// Byte index of the segment name in the name table, or 0xFFFF.
    pub section_name: u16,
    /// Byte index of the class name in the name table, or 0xFFFF.
    pub class_name: u16,
    /// Byte offset of the logical segment within the physical segment.
    pub offset: u32,
    /// Byte count of the segment.
    pub section_length: u32,
}

impl SectionMapEntry {
    /// On-disk size of one section map entry in bytes.
    pub const SIZE: usize = 20;

    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(data: &[u8], offset: usize) -> DbiResult<Self> {
        let s = data.get(offset..offset + Self::SIZE)
            .ok_or(DbiError::UnexpectedEof { offset, needed: Self::SIZE })?;
        let u16_at = |o: usize| le_u16_at(s, o).unwrap_or(0);
        let u32_at = |o: usize| le_u32_at(s, o).unwrap_or(0);
        Ok(Self {
            flags: u16_at(0),
            ovl: u16_at(2),
            group: u16_at(4),
            frame: u16_at(6),
            section_name: u16_at(8),
            class_name: u16_at(10),
            offset: u32_at(12),
            section_length: u32_at(16),
        })
    }
}

// ---------------------------------------------------------------------------
// DbiReader — top-level parser
// ---------------------------------------------------------------------------

/// Parsed contents of the DBI stream.
pub struct DbiReader {
    /// Parsed fixed-size DBI header.
    pub header: DbiHeader,
    /// Modules from the module-info sub-stream.
    pub modules: Vec<ModInfo>,
    /// Section contributions from the section-contribution sub-stream.
    pub section_contributions: Vec<SectionContrib>,
    /// Entries from the section map sub-stream.
    pub section_map: Vec<SectionMapEntry>,
    /// Maps module index → module name.
    pub module_index: HashMap<usize, String>,
}

/// Version stamp of the `Ver60` section-contribution sub-stream, whose records
/// carry 4 trailing bytes the older layout does not.
const SC_VERSION_V2: u32 = 0xF131_51E4;

impl DbiReader {
    /// Parse the DBI stream from raw bytes.
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn parse(data: &[u8]) -> DbiResult<Self> {
        let header = DbiHeader::parse(data)?;
        let mut cursor = DbiHeader::SIZE;

        // --- Module info sub-stream ---
        let mod_end = cursor + usize::try_from(header.mod_info_size.max(0)).unwrap_or(0);
        let mut modules = Vec::new();
        let mut module_index = HashMap::new();
        let mut mod_cursor = cursor;
        while mod_cursor < mod_end {
            let (mi, consumed) = ModInfo::parse(data, mod_cursor)?;
            let idx = modules.len();
            module_index.insert(idx, mi.module_name.clone());
            modules.push(mi);
            mod_cursor += consumed;
            if consumed == 0 {
                break; // safety guard
            }
        }
        cursor = mod_end;

        // --- Section contribution sub-stream ---
        let sec_contrib_end = cursor + usize::try_from(header.section_contribution_size.max(0)).unwrap_or(0);
        let mut section_contributions = Vec::new();
        // The sub-stream starts with a version u32. `Ver60` (0xF12EBA2D) uses
        // 28-byte records; `V2` (0xF13151E4) uses 32-byte records — the extra
        // trailing u32 is `ISectCoff`. Using a fixed 28-byte stride on a V2
        // substream reads every record after the first 4 bytes too far left,
        // splicing adjacent entries together.
        if sec_contrib_end > cursor + 4 {
            let version = le_u32_at(data, cursor)
                .ok_or(DbiError::UnexpectedEof { offset: cursor, needed: 4 })?;
            let stride = if version == SC_VERSION_V2 {
                SectionContrib::SIZE + 4
            } else {
                SectionContrib::SIZE
            };
            let mut sc_cursor = cursor + 4;
            // Parse only the leading 28 bytes of each record, but advance by
            // the version-appropriate stride.
            while sc_cursor + SectionContrib::SIZE <= sec_contrib_end
                && sc_cursor + stride <= sec_contrib_end
            {
                let sc = SectionContrib::parse(data, sc_cursor)?;
                section_contributions.push(sc);
                sc_cursor += stride;
            }
        }
        cursor = sec_contrib_end;

        // --- Section map sub-stream ---
        let sec_map_end = cursor + usize::try_from(header.section_map_size.max(0)).unwrap_or(0);
        let mut section_map = Vec::new();
        if sec_map_end > cursor + 4 {
            let count = le_u16_at(data, cursor)
                .ok_or(DbiError::UnexpectedEof { offset: cursor, needed: 2 })? as usize;
            let _log_count = le_u16_at(data, cursor + 2)
                .ok_or(DbiError::UnexpectedEof { offset: cursor + 2, needed: 2 })?;
            let mut sec_map_cursor = cursor + 4;
            for _ in 0..count {
                if sec_map_cursor + SectionMapEntry::SIZE > sec_map_end {
                    break;
                }
                section_map.push(SectionMapEntry::parse(data, sec_map_cursor)?);
                sec_map_cursor += SectionMapEntry::SIZE;
            }
        }

        Ok(Self { header, modules, section_contributions, section_map, module_index })
    }

    /// Find all modules that contribute to a given 1-based section index.
    #[must_use]
    pub fn modules_for_section(&self, section: u16) -> Vec<&ModInfo> {
        self.modules.iter()
            .filter(|m| m.section_contribution.section == section)
            .collect()
    }

    /// Find all section contributions that contain a given RVA.
    /// Requires a section map to convert section+offset to RVA.
    #[must_use]
    pub fn contributions_containing_offset(&self, section: u16, offset: u32) -> Vec<&SectionContrib> {
        self.section_contributions.iter()
            .filter(|sc| {
                sc.section == section
                    && sc.offset <= offset
                    && offset < sc.offset + sc.size
            })
            .collect()
    }

    /// Return total size of all code contributions.
    #[must_use]
    pub fn total_code_size(&self) -> u64 {
        self.section_contributions.iter()
            .filter(|sc| sc.is_code())
            .map(|sc| u64::from(sc.size))
            .sum()
    }

    /// Return total size of all data contributions.
    #[must_use]
    pub fn total_data_size(&self) -> u64 {
        self.section_contributions.iter()
            .filter(|sc| sc.is_initialized_data() || sc.is_uninitialized_data())
            .map(|sc| u64::from(sc.size))
            .sum()
    }

    /// Returns a summary string describing the DBI stream.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "DBI version={} age={} modules={} section_contributions={} sections={}",
            self.header.version,
            self.header.age,
            self.modules.len(),
            self.section_contributions.len(),
            self.section_map.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a null-terminated C string from `slice[offset..]`.
/// Returns (String, `bytes_consumed_including_null`).
fn read_cstr(slice: &[u8], offset: usize, abs_offset: usize) -> DbiResult<(String, usize)> {
    let start = slice.get(offset..).ok_or(DbiError::UnexpectedEof { offset: abs_offset, needed: 1 })?;
    let nul = start.iter().position(|&b| b == 0)
        .ok_or(DbiError::InvalidModuleName)?;
    let s = std::str::from_utf8(&start[..nul])
        .map_err(|_| DbiError::InvalidUtf8 { offset: abs_offset })?;
    Ok((s.to_owned(), nul + 1))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_section_contrib(section: u16, offset: u32, size: u32, chars: u32, module: u16) -> Vec<u8> {
        let mut v = vec![0u8; SectionContrib::SIZE];
        v[0..2].copy_from_slice(&section.to_le_bytes());
        v[4..8].copy_from_slice(&offset.to_le_bytes());
        v[8..12].copy_from_slice(&size.to_le_bytes());
        v[12..16].copy_from_slice(&chars.to_le_bytes());
        v[16..18].copy_from_slice(&module.to_le_bytes());
        v
    }

    #[test]
    fn section_contrib_code_flag() {
        let data = make_section_contrib(1, 0x1000, 0x200, 0x6000_0020, 0);
        let sc = SectionContrib::parse(&data, 0).unwrap();
        assert_eq!(sc.section, 1);
        assert_eq!(sc.offset, 0x1000);
        assert_eq!(sc.size, 0x200);
        assert!(sc.is_code());
        assert!(!sc.is_initialized_data());
    }

    #[test]
    fn section_contrib_data_flag() {
        let data = make_section_contrib(2, 0x5000, 0x400, 0x4000_0040, 1);
        let sc = SectionContrib::parse(&data, 0).unwrap();
        assert!(sc.is_initialized_data());
        assert!(!sc.is_code());
    }

    #[test]
    fn section_contrib_bss_flag() {
        let data = make_section_contrib(3, 0x9000, 0x100, 0x4000_0080, 2);
        let sc = SectionContrib::parse(&data, 0).unwrap();
        assert!(sc.is_uninitialized_data());
    }

    #[test]
    fn read_cstr_basic() {
        let data = b"hello\0world\0";
        let (s, n) = read_cstr(data, 0, 0).unwrap();
        assert_eq!(s, "hello");
        assert_eq!(n, 6);
        let (s2, n2) = read_cstr(data, n, n).unwrap();
        assert_eq!(s2, "world");
        assert_eq!(n2, 6);
    }

    #[test]
    fn read_cstr_empty() {
        let data = b"\0";
        let (s, n) = read_cstr(data, 0, 0).unwrap();
        assert_eq!(s, "");
        assert_eq!(n, 1);
    }

    #[test]
    fn dbi_header_bad_signature() {
        let mut data = vec![0u8; DbiHeader::SIZE];
        // Write a bad signature
        data[0..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        assert!(matches!(DbiHeader::parse(&data), Err(DbiError::BadSignature { .. })));
    }

    #[test]
    fn dbi_header_bad_version() {
        let mut data = vec![0u8; DbiHeader::SIZE];
        data[0..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        data[4..8].copy_from_slice(&99_999_999i32.to_le_bytes());
        assert!(matches!(DbiHeader::parse(&data), Err(DbiError::BadVersion { .. })));
    }

    fn make_dbi_header(mod_info_size: i32, sc_size: i32) -> Vec<u8> {
        let mut data = vec![0u8; DbiHeader::SIZE];
        data[0..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        data[4..8].copy_from_slice(&20_091_201i32.to_le_bytes());
        // age = 1
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        data[24..28].copy_from_slice(&mod_info_size.to_le_bytes());
        data[28..32].copy_from_slice(&sc_size.to_le_bytes());
        data
    }

    #[test]
    fn dbi_reader_empty_streams() {
        let data = make_dbi_header(0, 0);
        let reader = DbiReader::parse(&data).unwrap();
        assert_eq!(reader.modules.len(), 0);
        assert_eq!(reader.section_contributions.len(), 0);
        assert_eq!(reader.header.age, 1);
    }

    #[test]
    fn dbi_reader_summary_format() {
        let data = make_dbi_header(0, 0);
        let reader = DbiReader::parse(&data).unwrap();
        let s = reader.summary();
        assert!(s.contains("version=20091201"));
        assert!(s.contains("age=1"));
        assert!(s.contains("modules=0"));
    }

    #[test]
    fn mod_info_flags() {
        // Craft a minimal ModInfo fixed portion with sc + variable strings
        let mut data = vec![0u8; ModInfo::FIXED_SIZE + 16];
        // section_contribution at offset 4
        // flags: written_since_open | ec_enabled => 0x0003
        let flags_offset = 4 + SectionContrib::SIZE;
        data[flags_offset..flags_offset + 2].copy_from_slice(&0x0003u16.to_le_bytes());
        // module_name = "foo" at str_start
        let str_start = flags_offset + 32;
        data[str_start..str_start + 4].copy_from_slice(b"foo\0");
        data[str_start + 4..str_start + 5].copy_from_slice(b"\0");

        let (mi, _) = ModInfo::parse(&data, 0).unwrap();
        assert!(mi.written_since_open());
        assert!(mi.ec_enabled());
        assert_eq!(mi.module_name, "foo");
        assert_eq!(mi.obj_file_name, "");
    }

    #[test]
    fn contributions_filter_by_section() {
        let data = make_dbi_header(0, 0);
        let mut reader = DbiReader::parse(&data).unwrap();
        reader.section_contributions.push(SectionContrib { section: 1, offset: 0x100, size: 0x80, characteristics: 0x20, ..Default::default() });
        reader.section_contributions.push(SectionContrib { section: 2, offset: 0x200, size: 0x40, characteristics: 0x40, ..Default::default() });
        reader.section_contributions.push(SectionContrib { section: 1, offset: 0x300, size: 0x60, characteristics: 0x20, ..Default::default() });

        let in_sec1 = reader.contributions_containing_offset(1, 0x150);
        assert_eq!(in_sec1.len(), 1);
        assert_eq!(in_sec1[0].offset, 0x100);
    }

    #[test]
    fn total_code_size_sums_correctly() {
        let data = make_dbi_header(0, 0);
        let mut reader = DbiReader::parse(&data).unwrap();
        reader.section_contributions.push(SectionContrib { section: 1, offset: 0, size: 0x400, characteristics: 0x6000_0020, ..Default::default() });
        reader.section_contributions.push(SectionContrib { section: 2, offset: 0, size: 0x200, characteristics: 0x4000_0040, ..Default::default() });
        assert_eq!(reader.total_code_size(), 0x400);
        assert_eq!(reader.total_data_size(), 0x200);
    }
}
