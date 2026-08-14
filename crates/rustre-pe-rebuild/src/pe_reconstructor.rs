//! PE reconstructor — find PE headers in a raw memory dump, rebuild the
//! section table, fix up the import table and data directory entries, and
//! recalculate the PE checksum.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconstructError {
    NoPeSignatureFound,
    TruncatedDosHeader,
    TruncatedPeHeader,
    TruncatedOptionalHeader,
    InvalidMachine(u16),
    InvalidSectionTable(String),
    NoSections,
    ImportDirectoryUnresolvable(String),
    ChecksumOverflow,
    OutputTooSmall { needed: usize, available: usize },
    Custom(String),
}

impl std::fmt::Display for ReconstructError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPeSignatureFound => write!(f, "no PE signature found in dump"),
            Self::TruncatedDosHeader => write!(f, "DOS header is truncated"),
            Self::TruncatedPeHeader => write!(f, "PE header is truncated"),
            Self::TruncatedOptionalHeader => write!(f, "Optional header is truncated"),
            Self::InvalidMachine(m) => write!(f, "unsupported machine type {m:#06x}"),
            Self::InvalidSectionTable(e) => write!(f, "invalid section table: {e}"),
            Self::NoSections => write!(f, "no sections found"),
            Self::ImportDirectoryUnresolvable(e) => write!(f, "import directory: {e}"),
            Self::ChecksumOverflow => write!(f, "checksum computation overflowed"),
            Self::OutputTooSmall { needed, available } =>
                write!(f, "output buffer too small: need {needed}, have {available}"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for ReconstructError {}

pub type Result<T> = std::result::Result<T, ReconstructError>;

// ---------------------------------------------------------------------------
// PE constants
// ---------------------------------------------------------------------------

const DOS_MAGIC: u16 = 0x5A4D;         // "MZ"
const PE_SIGNATURE: u32 = 0x0000_4550;  // "PE\0\0"
const MACHINE_I386: u16 = 0x014C;
const MACHINE_AMD64: u16 = 0x8664;
const MACHINE_ARM: u16 = 0x01C0;
const MACHINE_ARM64: u16 = 0xAA64;
const OPT_HDR_MAGIC_PE32: u16 = 0x010B;
const OPT_HDR_MAGIC_PE32PLUS: u16 = 0x020B;

const SECTION_ENTRY_SIZE: usize = 40;
const DOS_HEADER_SIZE: usize = 64;
const PE_SIGNATURE_SIZE: usize = 4;
const COFF_HEADER_SIZE: usize = 20;
const OPT_HDR_SIZE_PE32: usize = 96;
const OPT_HDR_SIZE_PE32PLUS: usize = 112;
const NUM_DATA_DIRS: usize = 16;

// Section characteristics.
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// ---------------------------------------------------------------------------
// Raw helpers
// ---------------------------------------------------------------------------

fn read_u8(data: &[u8], off: usize) -> Option<u8> {
    data.get(off).copied()
}
fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off+2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off+4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off+8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}
fn write_u16_le(data: &mut [u8], off: usize, v: u16) {
    if off + 2 <= data.len() {
        data[off..off+2].copy_from_slice(&v.to_le_bytes());
    }
}
fn write_u32_le(data: &mut [u8], off: usize, v: u32) {
    if off + 4 <= data.len() {
        data[off..off+4].copy_from_slice(&v.to_le_bytes());
    }
}

// Null-terminated ASCII/UTF-8 from a fixed-size array.
fn read_cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// DOS header
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct DosHeader {
    e_magic: u16,
    e_lfanew: u32,
}

impl DosHeader {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < DOS_HEADER_SIZE { return Err(ReconstructError::TruncatedDosHeader); }
        let e_magic = read_u16_le(data, 0).unwrap();
        if e_magic != DOS_MAGIC { return Err(ReconstructError::TruncatedDosHeader); }
        let e_lfanew = read_u32_le(data, 0x3C).unwrap();
        Ok(Self { e_magic, e_lfanew })
    }
}

// ---------------------------------------------------------------------------
// COFF file header
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CoffHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
    /// Offset of COFF header within the dump buffer.
    offset: usize,
}

impl CoffHeader {
    fn parse(data: &[u8], offset: usize) -> Result<Self> {
        if data.len() < offset + COFF_HEADER_SIZE {
            return Err(ReconstructError::TruncatedPeHeader);
        }
        let base = offset;
        Ok(Self {
            machine: read_u16_le(data, base).unwrap(),
            number_of_sections: read_u16_le(data, base + 2).unwrap(),
            time_date_stamp: read_u32_le(data, base + 4).unwrap(),
            pointer_to_symbol_table: read_u32_le(data, base + 8).unwrap(),
            number_of_symbols: read_u32_le(data, base + 12).unwrap(),
            size_of_optional_header: read_u16_le(data, base + 16).unwrap(),
            characteristics: read_u16_le(data, base + 18).unwrap(),
            offset,
        })
    }
}

// ---------------------------------------------------------------------------
// Optional header (PE32 and PE32+)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Architecture {
    X86,
    X64,
    Arm32,
    Arm64,
}

#[derive(Debug, Clone)]
struct OptionalHeader {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    number_of_rva_and_sizes: u32,
    data_directories: Vec<(u32, u32)>, // (rva, size)
    /// Offset of the `OptionalHeader` within the dump buffer.
    offset: usize,
    is_pe32plus: bool,
}

impl OptionalHeader {
    fn parse(data: &[u8], offset: usize) -> Result<Self> {
        if data.len() < offset + 2 { return Err(ReconstructError::TruncatedOptionalHeader); }
        let magic = read_u16_le(data, offset).unwrap();
        let is_pe32plus = match magic {
            OPT_HDR_MAGIC_PE32 => false,
            OPT_HDR_MAGIC_PE32PLUS => true,
            _ => return Err(ReconstructError::TruncatedOptionalHeader),
        };

        let base_size = if is_pe32plus { OPT_HDR_SIZE_PE32PLUS } else { OPT_HDR_SIZE_PE32 };
        if data.len() < offset + base_size { return Err(ReconstructError::TruncatedOptionalHeader); }

        let o = offset;
        let major_linker_version = read_u8(data, o + 2).unwrap();
        let minor_linker_version = read_u8(data, o + 3).unwrap();
        let size_of_code = read_u32_le(data, o + 4).unwrap();
        let size_of_initialized_data = read_u32_le(data, o + 8).unwrap();
        let size_of_uninitialized_data = read_u32_le(data, o + 12).unwrap();
        let address_of_entry_point = read_u32_le(data, o + 16).unwrap();
        let base_of_code = read_u32_le(data, o + 20).unwrap();

        let (image_base, dd_offset) = if is_pe32plus {
            (read_u64_le(data, o + 24).unwrap_or(0), o + 24)
        } else {
            (u64::from(read_u32_le(data, o + 28).unwrap_or(0)), o + 28)
        };

        // Offsets after image_base differ.
        let (sect_align_off, file_align_off, szimg_off, szhdr_off, checksum_off, subsys_off, dllchars_off, nrvas_off, dd_off) =
            if is_pe32plus {
                (o+32, o+36, o+56, o+60, o+64, o+68, o+70, o+108, o+112)
            } else {
                (o+32, o+36, o+52, o+56, o+60, o+64, o+66, o+92, o+96)
            };
        // `dd_offset` marks where the ImageBase field starts; the data
        // directory must sit a fixed distance further along. Cross-check both
        // computations to catch off-by-one drift between code paths.
        let expected_dd_off = dd_offset + if is_pe32plus { 88 } else { 68 };
        debug_assert!(
            dd_off == expected_dd_off,
            "OptionalHeader layout mismatch (PE32+={is_pe32plus}): dd_off={dd_off} expected={expected_dd_off}"
        );

        let section_alignment = read_u32_le(data, sect_align_off).unwrap_or(0x1000);
        let file_alignment = read_u32_le(data, file_align_off).unwrap_or(0x200);
        let major_os_version = read_u16_le(data, o+40).unwrap_or(0);
        let minor_os_version = read_u16_le(data, o+42).unwrap_or(0);
        let major_image_version = read_u16_le(data, o+44).unwrap_or(0);
        let minor_image_version = read_u16_le(data, o+46).unwrap_or(0);
        let major_subsystem_version = read_u16_le(data, o+48).unwrap_or(4);
        let minor_subsystem_version = read_u16_le(data, o+50).unwrap_or(0);
        let size_of_image = read_u32_le(data, szimg_off).unwrap_or(0);
        let size_of_headers = read_u32_le(data, szhdr_off).unwrap_or(0);
        let checksum = read_u32_le(data, checksum_off).unwrap_or(0);
        let subsystem = read_u16_le(data, subsys_off).unwrap_or(2);
        let dll_characteristics = read_u16_le(data, dllchars_off).unwrap_or(0);
        let number_of_rva_and_sizes = read_u32_le(data, nrvas_off).unwrap_or(16).min(u32::try_from(NUM_DATA_DIRS).unwrap_or(u32::MAX));

        let mut data_directories = Vec::with_capacity(number_of_rva_and_sizes as usize);
        for i in 0..number_of_rva_and_sizes as usize {
            let base = dd_off + i * 8;
            let rva = read_u32_le(data, base).unwrap_or(0);
            let size = read_u32_le(data, base + 4).unwrap_or(0);
            data_directories.push((rva, size));
        }
        while data_directories.len() < NUM_DATA_DIRS {
            data_directories.push((0, 0));
        }

        Ok(Self {
            magic,
            major_linker_version,
            minor_linker_version,
            size_of_code,
            size_of_initialized_data,
            size_of_uninitialized_data,
            address_of_entry_point,
            base_of_code,
            image_base,
            section_alignment,
            file_alignment,
            major_os_version,
            minor_os_version,
            major_image_version,
            minor_image_version,
            major_subsystem_version,
            minor_subsystem_version,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            dll_characteristics,
            number_of_rva_and_sizes,
            data_directories,
            offset,
            is_pe32plus,
        })
    }

    const fn arch(machine: u16) -> Result<Architecture> {
        match machine {
            MACHINE_I386 => Ok(Architecture::X86),
            MACHINE_AMD64 => Ok(Architecture::X64),
            MACHINE_ARM => Ok(Architecture::Arm32),
            MACHINE_ARM64 => Ok(Architecture::Arm64),
            other => Err(ReconstructError::InvalidMachine(other)),
        }
    }
}

// ---------------------------------------------------------------------------
// Section header
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub relocations_offset: u32,
    pub linenumbers_offset: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    fn parse(data: &[u8], offset: usize) -> Option<Self> {
        if data.len() < offset + SECTION_ENTRY_SIZE { return None; }
        let o = offset;
        let name = read_cstr(&data[o..o+8]);
        let virtual_size = read_u32_le(data, o + 8)?;
        let virtual_address = read_u32_le(data, o + 12)?;
        let raw_size = read_u32_le(data, o + 16)?;
        let raw_offset = read_u32_le(data, o + 20)?;
        let relocations_offset = read_u32_le(data, o + 24)?;
        let linenumbers_offset = read_u32_le(data, o + 28)?;
        let number_of_relocations = read_u16_le(data, o + 32)?;
        let number_of_linenumbers = read_u16_le(data, o + 34)?;
        let characteristics = read_u32_le(data, o + 36)?;
        Some(Self {
            name, virtual_size, virtual_address, raw_size, raw_offset,
            relocations_offset, linenumbers_offset, number_of_relocations,
            number_of_linenumbers, characteristics,
        })
    }

    #[must_use]
    pub const fn is_executable(&self) -> bool { self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 }
    #[must_use]
    pub const fn is_writable(&self) -> bool { self.characteristics & IMAGE_SCN_MEM_WRITE != 0 }
    #[must_use]
    pub const fn is_code(&self) -> bool { self.characteristics & IMAGE_SCN_CNT_CODE != 0 }

    /// Map a RVA to a file offset using this section's mapping.
    #[must_use]
    pub const fn rva_to_file_off(&self, rva: u32) -> Option<usize> {
        if rva >= self.virtual_address && rva < self.virtual_address + self.virtual_size {
            let delta = rva - self.virtual_address;
            if delta < self.raw_size {
                return Some((self.raw_offset + delta) as usize);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Import descriptor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    pub dll_name: String,
    pub functions: Vec<ImportFunction>,
    pub iat_rva: u32,
    pub int_rva: u32,
    pub first_thunk: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportFunction {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
    pub iat_offset: u32,
}

// ---------------------------------------------------------------------------
// Parsed PE (intermediate representation)
// ---------------------------------------------------------------------------

struct ParsedPe<'a> {
    data: &'a [u8],
    dos: DosHeader,
    coff: CoffHeader,
    opt: OptionalHeader,
    sections: Vec<SectionHeader>,
    pe_offset: usize,
}

impl ParsedPe<'_> {
    const fn sections_offset(&self) -> usize {
        self.pe_offset + PE_SIGNATURE_SIZE + COFF_HEADER_SIZE + self.coff.size_of_optional_header as usize
    }

    /// File offset of the PE signature, derived from the DOS header. Equal to
    /// `pe_offset + e_lfanew`. Used as a sanity check when validating a dump.
    const fn pe_signature_offset(&self) -> usize {
        self.pe_offset + self.dos.e_lfanew as usize
    }

    fn rva_to_file_off(&self, rva: u32) -> Option<usize> {
        for sec in &self.sections {
            if let Some(off) = sec.rva_to_file_off(rva) {
                return Some(off);
            }
        }
        None
    }

    fn read_cstr_at_rva(&self, rva: u32) -> Option<String> {
        let off = self.rva_to_file_off(rva)?;
        let end = self.data[off..].iter().position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&self.data[off..off+end]).into_owned())
    }

    fn parse_import_table(&self) -> Vec<ImportEntry> {
        let (idt_rva, idt_size) = self.opt.data_directories.get(1).copied().unwrap_or((0, 0));
        if idt_rva == 0 || idt_size == 0 { return vec![]; }

        let mut entries = Vec::new();
        let Some(mut desc_off) = self.rva_to_file_off(idt_rva) else { return vec![]; };

        loop {
            if desc_off + 20 > self.data.len() { break; }
            let orig_first_thunk = read_u32_le(self.data, desc_off).unwrap_or(0);
            let name_rva = read_u32_le(self.data, desc_off + 12).unwrap_or(0);
            let first_thunk = read_u32_le(self.data, desc_off + 16).unwrap_or(0);

            if orig_first_thunk == 0 && name_rva == 0 && first_thunk == 0 { break; }

            let dll_name = self.read_cstr_at_rva(name_rva).unwrap_or_default();
            let import_name_table_rva = if orig_first_thunk != 0 { orig_first_thunk } else { first_thunk };
            let iat_base_rva = first_thunk;

            let mut functions = Vec::new();
            let is_64 = self.opt.is_pe32plus;
            let thunk_size = if is_64 { 8usize } else { 4usize };
            let ordinal_flag: u64 = if is_64 { 0x8000_0000_0000_0000 } else { 0x8000_0000 };

            if let Some(mut int_off) = self.rva_to_file_off(import_name_table_rva) {
                let mut iat_off = self.rva_to_file_off(iat_base_rva).unwrap_or(usize::MAX);
                let mut thunk_idx = 0u32;
                loop {
                    // Bail if either INT or IAT walks past the buffer; without
                    // checking iat_off, a corrupt IAT RVA would silently emit
                    // junk iat_offset values.
                    if int_off + thunk_size > self.data.len()
                        || iat_off.saturating_add(thunk_size) > self.data.len()
                    { break; }
                    let thunk_val: u64 = if is_64 {
                        read_u64_le(self.data, int_off).unwrap_or(0)
                    } else {
                        u64::from(read_u32_le(self.data, int_off).unwrap_or(0))
                    };
                    if thunk_val == 0 { break; }

                    let thunk_off = iat_base_rva + thunk_idx * u32::try_from(thunk_size).unwrap_or(u32::MAX);
                    let func = if thunk_val & ordinal_flag != 0 {
                        ImportFunction {
                            name: None,
                            ordinal: Some(u16::try_from(thunk_val & 0xFFFF).unwrap_or(u16::MAX)),
                            hint: None,
                            iat_offset: thunk_off,
                        }
                    } else {
                        let hint_name_rva = u32::try_from(thunk_val & 0x7FFF_FFFF).unwrap_or(u32::MAX);
                        let (hint, func_name) = self.rva_to_file_off(hint_name_rva).map_or(
                            (None, None),
                            |hn_off| {
                                let h = read_u16_le(self.data, hn_off);
                                let fn_name = read_cstr(&self.data[hn_off+2..]);
                                (h, Some(fn_name))
                            },
                        );
                        ImportFunction {
                            name: func_name,
                            ordinal: None,
                            hint,
                            iat_offset: thunk_off,
                        }
                    };
                    functions.push(func);
                    int_off += thunk_size;
                    iat_off += thunk_size;
                    thunk_idx += 1;
                }
            }

            entries.push(ImportEntry {
                dll_name,
                functions,
                iat_rva: iat_base_rva,
                int_rva: import_name_table_rva,
                first_thunk,
            });
            desc_off += 20;
        }
        entries
    }
}

// ---------------------------------------------------------------------------
// PE search heuristic: scan the dump for likely PE headers
// ---------------------------------------------------------------------------

/// Find all potential PE header offsets in a memory dump.
/// Returns a sorted list of candidate offsets.
#[must_use]
pub fn find_pe_candidates(dump: &[u8]) -> Vec<usize> {
    let mut candidates = Vec::new();
    let mut i = 0;
    while i + DOS_HEADER_SIZE <= dump.len() {
        // Look for MZ signature.
        if dump[i] == b'M'
            && dump[i+1] == b'Z'
            && let Some(e_lfanew) = read_u32_le(dump, i + 0x3C)
        {
            let pe_off = i + e_lfanew as usize;
            if pe_off + 4 <= dump.len()
                && read_u32_le(dump, pe_off).is_some_and(|sig| sig == PE_SIGNATURE)
            {
                candidates.push(i);
            }
        }
        // Advance by 4-byte alignment for speed.
        i += 4;
    }
    candidates
}

// ---------------------------------------------------------------------------
// Reconstruction configuration
// ---------------------------------------------------------------------------

/// Bitflags for `ReconstructConfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReconstructFlags(pub u8);

impl ReconstructFlags {
    pub const ZERO_CHECKSUM:        u8 = 0x01;
    pub const RECALCULATE_CHECKSUM: u8 = 0x02;
    pub const STRIP_BASE_RELOCS:    u8 = 0x04;
    pub const FIX_SIZE_OF_IMAGE:    u8 = 0x08;
    pub const TRIM_SECTIONS:        u8 = 0x10;
    pub const ZERO_BOUND_IMPORTS:   u8 = 0x20;

    #[must_use] pub const fn zero_checksum(self) -> bool        { self.0 & Self::ZERO_CHECKSUM != 0 }
    #[must_use] pub const fn recalculate_checksum(self) -> bool { self.0 & Self::RECALCULATE_CHECKSUM != 0 }
    #[must_use] pub const fn strip_base_relocs(self) -> bool    { self.0 & Self::STRIP_BASE_RELOCS != 0 }
    #[must_use] pub const fn fix_size_of_image(self) -> bool    { self.0 & Self::FIX_SIZE_OF_IMAGE != 0 }
    #[must_use] pub const fn trim_sections(self) -> bool        { self.0 & Self::TRIM_SECTIONS != 0 }
    #[must_use] pub const fn zero_bound_imports(self) -> bool   { self.0 & Self::ZERO_BOUND_IMPORTS != 0 }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructConfig {
    pub flags: ReconstructFlags,
    /// Override for the OEP (entry point RVA). `None` = keep original.
    pub oep_override: Option<u32>,
    /// Candidate PE offset to use; if `None`, use the first found.
    pub force_pe_offset: Option<usize>,
}

impl Default for ReconstructConfig {
    fn default() -> Self {
        Self {
            flags: ReconstructFlags(
                ReconstructFlags::RECALCULATE_CHECKSUM
                | ReconstructFlags::FIX_SIZE_OF_IMAGE
                | ReconstructFlags::TRIM_SECTIONS
                | ReconstructFlags::ZERO_BOUND_IMPORTS,
            ),
            oep_override: None,
            force_pe_offset: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Reconstruction statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ReconstructStats {
    pub pe_offset_used: usize,
    pub sections_found: usize,
    pub sections_with_data: usize,
    pub import_entries: usize,
    pub import_functions: usize,
    pub checksum_recalculated: bool,
    pub oep: u32,
    pub architecture: String,
    pub image_base: u64,
    pub size_of_image: u32,
}

// ---------------------------------------------------------------------------
// PE checksum calculation
// ---------------------------------------------------------------------------

/// Recalculate the PE checksum for the given buffer.
/// The checksum field itself (at `checksum_offset`) must be zeroed before calling.
///
/// # Panics
/// Panics if `data` is non-empty but `data.last()` returns `None` (impossible).
#[must_use]
pub fn calculate_pe_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut checksum: u64 = 0;
    let mut i = 0;
    while i + 2 <= data.len() {
        let word = if i == checksum_offset || i == checksum_offset + 2 {
            0u16
        } else {
            u16::from_le_bytes([data[i], data[i+1]])
        };
        checksum += u64::from(word);
        if checksum > 0xFFFF_FFFF {
            checksum = (checksum & 0xFFFF_FFFF) + (checksum >> 32);
        }
        i += 2;
    }
    // Handle trailing odd byte.
    if !data.len().is_multiple_of(2) {
        checksum += u64::from(*data.last().unwrap());
    }
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    u32::try_from(checksum).unwrap_or(u32::MAX) + u32::try_from(data.len()).unwrap_or(u32::MAX)
}

// ---------------------------------------------------------------------------
// Core reconstructor
// ---------------------------------------------------------------------------

pub struct PeReconstructor {
    config: ReconstructConfig,
}

impl PeReconstructor {
    #[must_use]
    pub const fn new(config: ReconstructConfig) -> Self { Self { config } }
    #[must_use]
    pub fn with_defaults() -> Self { Self::new(ReconstructConfig::default()) }

    /// Reconstruct a PE file from a raw memory dump.
    ///
    /// Returns the rebuilt PE bytes and reconstruction statistics.
    ///
    /// # Errors
    /// Returns an error if no PE signature is found, the header is truncated,
    /// or any other structural problem prevents reconstruction.
    pub fn reconstruct(&self, dump: &[u8]) -> Result<(Vec<u8>, ReconstructStats)> {
        // Find PE offset.
        let pe_base = if let Some(forced) = self.config.force_pe_offset {
            forced
        } else {
            let candidates = find_pe_candidates(dump);
            *candidates.first().ok_or(ReconstructError::NoPeSignatureFound)?
        };

        let dos = DosHeader::parse(&dump[pe_base..])?;
        let pe_sig_off = pe_base + dos.e_lfanew as usize;
        let coff_off = pe_sig_off + PE_SIGNATURE_SIZE;
        let coff = CoffHeader::parse(dump, coff_off)?;
        let opt_off = coff_off + COFF_HEADER_SIZE;
        let opt = OptionalHeader::parse(dump, opt_off)?;

        let arch = OptionalHeader::arch(coff.machine).map_or_else(|_| "Unknown".into(), |a| format!("{a:?}"));

        // Parse section headers.
        let sections_off = opt_off + coff.size_of_optional_header as usize;
        let mut sections = Vec::with_capacity(coff.number_of_sections as usize);
        for i in 0..coff.number_of_sections as usize {
            let sec_off = sections_off + i * SECTION_ENTRY_SIZE;
            let sec = SectionHeader::parse(dump, sec_off)
                .ok_or_else(|| ReconstructError::InvalidSectionTable(
                    format!("section {i} at offset {sec_off:#x} truncated")))?;
            sections.push(sec);
        }

        if sections.is_empty() { return Err(ReconstructError::NoSections); }

        let parsed = ParsedPe { data: dump, dos, coff, opt, sections: sections.clone(), pe_offset: pe_base };

        // Parse import table for statistics.
        let imports = parsed.parse_import_table();
        let import_entries = imports.len();
        let import_functions: usize = imports.iter().map(|e| e.functions.len()).sum();

        // Build output buffer.
        // Determine output size: headers + all section data.
        let headers_size = Self::align_up(
            sections_off + sections.len() * SECTION_ENTRY_SIZE - pe_base,
            parsed.opt.file_alignment as usize,
        );

        let size_of_image = if self.config.flags.fix_size_of_image() {
            Self::compute_size_of_image(&sections, parsed.opt.section_alignment)
        } else {
            parsed.opt.size_of_image
        };

        // Use section alignment for virtual layout but file_alignment for raw.
        let mut out = vec![0u8; size_of_image as usize];
        if out.len() < dump.len().min(size_of_image as usize) {
            out.resize(dump.len(), 0);
        }

        // Copy the header region from dump.
        // IMPORTANT: `pe_base` must be 0 for a standalone PE output.  When the
        // caller passes a non-zero `pe_base` (e.g. to locate an embedded PE inside
        // a multi-PE dump), the DOS stub bytes before `pe_base` are intentionally
        // omitted from the output, which means `e_lfanew` in the output must be
        // adjusted by the caller to account for this truncation.
        let hdr_end = pe_base + headers_size;
        let copy_end = hdr_end.min(dump.len()).min(out.len());
        // `out` is sized from SizeOfImage, which comes from the dump when
        // FIX_SIZE_OF_IMAGE is off, so `copy_end` can be clamped BELOW `pe_base`
        // for an embedded PE. Then `copy_end - pe_base` underflows and
        // `dump[pe_base..copy_end]` starts after it ends — a panic, not an error.
        if copy_end > pe_base {
            out[..copy_end - pe_base].copy_from_slice(&dump[pe_base..copy_end]);
        }

        // Copy each section's raw data.
        let mut sections_with_data = 0usize;
        for sec in &sections {
            let src_off = sec.raw_offset as usize;
            let src_size = sec.raw_size as usize;
            let dst_off = sec.virtual_address as usize;
            let copy_len = src_size
                .min(sec.virtual_size as usize)
                .min(if src_off < dump.len() { dump.len() - src_off } else { 0 })
                .min(if dst_off < out.len() { out.len() - dst_off } else { 0 });
            if copy_len > 0 && src_off < dump.len() {
                out[dst_off..dst_off + copy_len].copy_from_slice(&dump[src_off..src_off + copy_len]);
                sections_with_data += 1;
            }
        }

        let opt = &parsed.opt;
        let final_oep = self.config.oep_override.unwrap_or(opt.address_of_entry_point);
        let checksum_recalculated = self.apply_output_patches(&mut out, opt, size_of_image);

        let stats = ReconstructStats {
            pe_offset_used: pe_base,
            sections_found: sections.len(),
            sections_with_data,
            import_entries,
            import_functions,
            checksum_recalculated,
            oep: final_oep,
            architecture: arch,
            image_base: opt.image_base,
            size_of_image,
        };

        Ok((out, stats))
    }

    fn apply_output_patches(&self, out: &mut [u8], opt: &OptionalHeader, size_of_image: u32) -> bool {
        // Apply OEP override.
        if let Some(oep_override) = self.config.oep_override {
            let ep_field_off = opt.offset + 16;
            if ep_field_off + 4 <= out.len() {
                write_u32_le(out, ep_field_off, oep_override);
            }
        }

        // Fix SizeOfImage.
        if self.config.flags.fix_size_of_image() {
            let szimg_off = if opt.is_pe32plus { opt.offset + 56 } else { opt.offset + 52 };
            write_u32_le(out, szimg_off, size_of_image);
        }

        let dd_base = if opt.is_pe32plus { opt.offset + 112 } else { opt.offset + 96 };

        // Zero bound imports directory (entry 11).
        if self.config.flags.zero_bound_imports() {
            let bound_off = dd_base + 11 * 8;
            write_u32_le(out, bound_off, 0);
            write_u32_le(out, bound_off + 4, 0);
        }

        // Strip base relocations directory (entry 5) if requested.
        if self.config.flags.strip_base_relocs() {
            let reloc_off = dd_base + 5 * 8;
            write_u32_le(out, reloc_off, 0);
            write_u32_le(out, reloc_off + 4, 0);
        }

        // Recalculate or zero checksum.
        let cs_off = if opt.is_pe32plus { opt.offset + 64 } else { opt.offset + 60 };
        if self.config.flags.recalculate_checksum() {
            write_u32_le(out, cs_off, 0);
            let cs = calculate_pe_checksum(out, cs_off);
            write_u32_le(out, cs_off, cs);
            true
        } else {
            if self.config.flags.zero_checksum() {
                write_u32_le(out, cs_off, 0);
            }
            false
        }
    }

    const fn align_up(v: usize, align: usize) -> usize {
        if align == 0 { return v; }
        v.saturating_add(align - 1) & !(align - 1)
    }

    fn compute_size_of_image(sections: &[SectionHeader], section_alignment: u32) -> u32 {
        let align = section_alignment as usize;
        sections.iter()
            .max_by_key(|s| s.virtual_address + s.virtual_size)
            .map_or(0, |last| {
                let end = last.virtual_address as usize + last.virtual_size as usize;
                u32::try_from(Self::align_up(end, align)).unwrap_or(u32::MAX)
            })
    }
}

// ---------------------------------------------------------------------------
// Header analysis report
// ---------------------------------------------------------------------------

/// Detailed read-only view of a PE's headers.
///
/// Returned by [`PeReconstructor::analyze`] so callers can inspect linker
/// versions, version stamps, subsystem details, and per-section characteristics
/// without re-parsing the bytes themselves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderAnalysis {
    pub pe_offset: usize,
    pub dos_magic: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub coff_characteristics: u16,
    pub coff_header_offset: usize,
    pub opt_magic: u16,
    pub linker_version: (u8, u8),
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub os_version: (u16, u16),
    pub image_version: (u16, u16),
    pub subsystem_version: (u16, u16),
    pub size_of_headers: u32,
    pub original_checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub number_of_rva_and_sizes: u32,
    pub data_directory_byte_offset: usize,
    /// Histogram of section characteristics flags, keyed by the flag bit.
    pub section_flag_histogram: HashMap<u32, usize>,
    /// Page-size constants used for pointer-size-dependent calculations.
    pub pointer_size_bytes: usize,
}

impl PeReconstructor {
    /// Parse and summarise the header structure of `dump` without rebuilding.
    ///
    /// # Errors
    /// Returns an error if the PE header cannot be parsed.
    pub fn analyze(&self, dump: &[u8]) -> Result<HeaderAnalysis> {
        let pe_base = if let Some(forced) = self.config.force_pe_offset {
            forced
        } else {
            let candidates = find_pe_candidates(dump);
            *candidates.first().ok_or(ReconstructError::NoPeSignatureFound)?
        };
        let dos = DosHeader::parse(&dump[pe_base..])?;
        let pe_sig_off = pe_base + dos.e_lfanew as usize;
        let coff_off = pe_sig_off + PE_SIGNATURE_SIZE;
        let coff = CoffHeader::parse(dump, coff_off)?;
        let opt_off = coff_off + COFF_HEADER_SIZE;
        let opt = OptionalHeader::parse(dump, opt_off)?;
        let sections_off = opt_off + coff.size_of_optional_header as usize;

        // Sanity-check the optional header size against the known PE32/PE32+
        // values so callers can flag truncated dumps.
        debug_assert!(
            coff.size_of_optional_header as usize == OPT_HDR_SIZE_PE32
                || coff.size_of_optional_header as usize == OPT_HDR_SIZE_PE32PLUS
                || coff.size_of_optional_header as usize == 0
        );

        // Build the parsed view and use sections_offset() to validate.
        let mut sections = Vec::with_capacity(coff.number_of_sections as usize);
        for i in 0..coff.number_of_sections as usize {
            let sec_off = sections_off + i * SECTION_ENTRY_SIZE;
            if let Some(sec) = SectionHeader::parse(dump, sec_off) {
                sections.push(sec);
            }
        }
        let parsed = ParsedPe {
            data: dump,
            dos: dos.clone(),
            coff: coff.clone(),
            opt: opt.clone(),
            sections: sections.clone(),
            pe_offset: pe_base,
        };
        debug_assert_eq!(parsed.sections_offset(), sections_off);
        debug_assert_eq!(parsed.pe_signature_offset(), pe_sig_off);

        // Section flag histogram: split each section's characteristics into
        // its component bits (CODE / INITIALIZED_DATA / etc.) and tally them.
        let interesting: [u32; 6] = [
            IMAGE_SCN_CNT_CODE,
            IMAGE_SCN_CNT_INITIALIZED_DATA,
            IMAGE_SCN_CNT_UNINITIALIZED_DATA,
            IMAGE_SCN_MEM_EXECUTE,
            IMAGE_SCN_MEM_READ,
            IMAGE_SCN_MEM_WRITE,
        ];
        let mut section_flag_histogram: HashMap<u32, usize> = HashMap::new();
        for sec in &sections {
            for &bit in &interesting {
                if sec.characteristics & bit != 0 {
                    *section_flag_histogram.entry(bit).or_insert(0) += 1;
                }
            }
        }

        let pointer_size_bytes = if opt.is_pe32plus { 8usize } else { 4usize };
        let dd_byte_offset = if opt.is_pe32plus { opt.offset + 112 } else { opt.offset + 96 };

        Ok(HeaderAnalysis {
            pe_offset: pe_base,
            dos_magic: dos.e_magic,
            time_date_stamp: coff.time_date_stamp,
            pointer_to_symbol_table: coff.pointer_to_symbol_table,
            number_of_symbols: coff.number_of_symbols,
            coff_characteristics: coff.characteristics,
            coff_header_offset: coff.offset,
            opt_magic: opt.magic,
            linker_version: (opt.major_linker_version, opt.minor_linker_version),
            size_of_code: opt.size_of_code,
            size_of_initialized_data: opt.size_of_initialized_data,
            size_of_uninitialized_data: opt.size_of_uninitialized_data,
            base_of_code: opt.base_of_code,
            image_base: opt.image_base,
            os_version: (opt.major_os_version, opt.minor_os_version),
            image_version: (opt.major_image_version, opt.minor_image_version),
            subsystem_version: (opt.major_subsystem_version, opt.minor_subsystem_version),
            size_of_headers: opt.size_of_headers,
            original_checksum: opt.checksum,
            subsystem: opt.subsystem,
            dll_characteristics: opt.dll_characteristics,
            number_of_rva_and_sizes: opt.number_of_rva_and_sizes,
            data_directory_byte_offset: dd_byte_offset,
            section_flag_histogram,
            pointer_size_bytes,
        })
    }
}

/// Write a 16-bit unsigned value to `data` at `off` in little-endian order.
///
/// Re-exported for callers that need to surgically patch a 16-bit field
/// (e.g. `OptionalHeader.MajorImageVersion`) without rebuilding the whole file.
pub fn patch_u16_le(data: &mut [u8], off: usize, v: u16) {
    write_u16_le(data, off, v);
}

// ---------------------------------------------------------------------------
// Convenience: parse import table from a known-good PE buffer.
// ---------------------------------------------------------------------------

/// # Errors
/// Returns an error if the PE header cannot be parsed.
pub fn parse_imports(pe_data: &[u8]) -> Result<Vec<ImportEntry>> {
    if pe_data.len() < DOS_HEADER_SIZE { return Err(ReconstructError::TruncatedDosHeader); }
    let dos = DosHeader::parse(pe_data)?;
    let pe_sig_off = dos.e_lfanew as usize;
    let coff_off = pe_sig_off + PE_SIGNATURE_SIZE;
    let coff = CoffHeader::parse(pe_data, coff_off)?;
    let opt_off = coff_off + COFF_HEADER_SIZE;
    let opt = OptionalHeader::parse(pe_data, opt_off)?;
    let sections_off = opt_off + coff.size_of_optional_header as usize;
    let mut sections = Vec::new();
    for i in 0..coff.number_of_sections as usize {
        let sec_off = sections_off + i * SECTION_ENTRY_SIZE;
        if let Some(sec) = SectionHeader::parse(pe_data, sec_off) {
            sections.push(sec);
        }
    }
    let parsed = ParsedPe { data: pe_data, dos, coff, opt, sections, pe_offset: 0 };
    Ok(parsed.parse_import_table())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe() -> Vec<u8> {
        // Build a minimal valid PE32 stub for testing.
        let mut data = vec![0u8; 0x400];
        // DOS header.
        data[0] = b'M'; data[1] = b'Z';
        write_u32_le(&mut data, 0x3C, 0x40); // e_lfanew = 0x40
        // PE signature at 0x40.
        write_u32_le(&mut data, 0x40, PE_SIGNATURE);
        // COFF header at 0x44.
        write_u16_le(&mut data, 0x44, MACHINE_I386); // machine
        write_u16_le(&mut data, 0x46, 1);            // 1 section
        write_u32_le(&mut data, 0x48, 0);            // timestamp
        write_u32_le(&mut data, 0x4C, 0);            // symbol table
        write_u32_le(&mut data, 0x50, 0);            // symbol count
        write_u16_le(&mut data, 0x54, 0x60);         // size of opt header (96)
        write_u16_le(&mut data, 0x56, 0x0102);       // characteristics
        // Optional header at 0x58.
        let oh = 0x58usize;
        write_u16_le(&mut data, oh, OPT_HDR_MAGIC_PE32);     // magic
        write_u32_le(&mut data, oh + 4, 0x100);              // SizeOfCode
        write_u32_le(&mut data, oh + 16, 0x1000);            // AddressOfEntryPoint
        write_u32_le(&mut data, oh + 20, 0x1000);            // BaseOfCode
        write_u32_le(&mut data, oh + 28, 0x0040_0000);       // ImageBase
        write_u32_le(&mut data, oh + 32, 0x1000);            // SectionAlignment
        write_u32_le(&mut data, oh + 36, 0x200);             // FileAlignment
        write_u16_le(&mut data, oh + 48, 4);                 // MajorSubsystemVersion
        write_u32_le(&mut data, oh + 52, 0x2000);            // SizeOfImage
        write_u32_le(&mut data, oh + 56, 0x200);             // SizeOfHeaders
        write_u16_le(&mut data, oh + 64, 2);                 // Subsystem (GUI)
        write_u32_le(&mut data, oh + 92, 0);                 // NumberOfRvaAndSizes = 0
        // Section header at 0x58 + 0x60 = 0xB8.
        let sec = 0xB8usize;
        data[sec..sec+5].copy_from_slice(b".text");
        write_u32_le(&mut data, sec + 8, 0x100);    // VirtualSize
        write_u32_le(&mut data, sec + 12, 0x1000);  // VirtualAddress
        write_u32_le(&mut data, sec + 16, 0x200);   // SizeOfRawData
        write_u32_le(&mut data, sec + 20, 0x200);   // PointerToRawData
        write_u32_le(&mut data, sec + 36,
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
        data
    }

    #[test]
    fn test_find_pe_candidates() {
        let pe = minimal_pe();
        let candidates = find_pe_candidates(&pe);
        assert!(!candidates.is_empty(), "should find at least one PE candidate");
        assert_eq!(candidates[0], 0);
    }

    #[test]
    fn test_reconstruct_minimal() {
        let pe = minimal_pe();
        let reconstructor = PeReconstructor::with_defaults();
        let result = reconstructor.reconstruct(&pe);
        assert!(result.is_ok(), "reconstruction failed: {:?}", result.err());
        let (out, stats) = result.unwrap();
        assert_eq!(stats.sections_found, 1);
        assert_eq!(stats.oep, 0x1000);
        // Output must start with MZ.
        assert_eq!(&out[..2], b"MZ");
    }

    #[test]
    fn test_checksum_calculation() {
        let mut buf = vec![0u8; 0x200];
        buf[0] = b'M'; buf[1] = b'Z';
        let cs = calculate_pe_checksum(&buf, 0x58);
        // Just verify it doesn't panic and returns something.
        let _ = cs;
    }

    #[test]
    fn test_align_up() {
        assert_eq!(PeReconstructor::align_up(0x1001, 0x1000), 0x2000);
        assert_eq!(PeReconstructor::align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(PeReconstructor::align_up(0, 0x200), 0);
    }

    #[test]
    fn test_embedded_pe_with_small_size_of_image_does_not_panic() {
        // An embedded PE at a non-zero offset whose SizeOfImage is SMALLER than
        // that offset. `out` is sized from SizeOfImage, so the header-copy end got
        // clamped below `pe_base`: `copy_end - pe_base` underflowed and the source
        // slice started after it ended.
        let mut pe = minimal_pe();
        write_u32_le(&mut pe, 0x58 + 52, 0x100); // SizeOfImage, well below pe_base
        let mut dump = vec![0u8; 0x1000];
        dump.extend_from_slice(&pe);

        // FIX_SIZE_OF_IMAGE off, so the dump's own SizeOfImage is the one used.
        let cfg = ReconstructConfig {
            flags: ReconstructFlags(0),
            oep_override: None,
            force_pe_offset: Some(0x1000),
        };
        let r = PeReconstructor::new(cfg).reconstruct(&dump);
        // Either outcome is acceptable — panicking is not.
        assert!(r.is_ok() || r.is_err());

        // A sane SizeOfImage still reconstructs and copies the headers.
        let cfg = ReconstructConfig { force_pe_offset: Some(0x1000), ..Default::default() };
        let (out, _) = PeReconstructor::new(cfg).reconstruct(&dump).unwrap();
        assert_eq!(&out[..2], b"MZ");
    }
}
