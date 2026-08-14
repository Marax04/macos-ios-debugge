//! PS2 ELF Loader — Sony `PlayStation` 2 MIPS `R5900` executable format.
//!
//! Parses ELF binaries targeting the PS2 Emotion Engine (MIPS R5900),
//! handles SCE-specific section types in the 0x70000000 range,
//! parses the `.sce.moduleinfo` section for module metadata,
//! computes MIPS GP-relative addressing, and processes MIPS HI16/LO16
//! relocation pairs as they appear in PS2 executables.

use std::collections::HashMap;
use std::fmt;

// ─── Constants ────────────────────────────────────────────────────────────────

/// ELF magic bytes.
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// `EM_MIPS` machine type value in the ELF header.
pub const EM_MIPS: u16 = 8;

/// ELF class: 32-bit.
pub const ELFCLASS32: u8 = 1;

/// ELF data encoding: little-endian.
pub const ELFDATA2LSB: u8 = 1;

/// Size of the ELF32 file header in bytes.
pub const ELF32_HEADER_SIZE: usize = 52;

/// Size of an ELF32 program header entry.
pub const ELF32_PHDR_SIZE: usize = 32;

/// Size of an ELF32 section header entry.
pub const ELF32_SHDR_SIZE: usize = 40;

/// `PT_LOAD` segment type.
pub const PT_LOAD: u32 = 1;

/// `SHT_NULL` section type.
pub const SHT_NULL: u32 = 0;

/// `SHT_PROGBITS` section type.
pub const SHT_PROGBITS: u32 = 1;

/// `SHT_SYMTAB` section type.
pub const SHT_SYMTAB: u32 = 2;

/// `SHT_STRTAB` section type.
pub const SHT_STRTAB: u32 = 3;

/// `SHT_RELA` section type.
pub const SHT_RELA: u32 = 4;

/// `SHT_REL` section type.
pub const SHT_REL: u32 = 9;

/// Base of the SCE-specific section type range.
pub const SCE_SECTION_BASE: u32 = 0x7000_0000;

/// `SCE_IOP_RELOC` section type.
pub const SHT_SCE_IOP_RELOC: u32 = 0x7000_0080;

/// `SCE_PS2_RELOC` section type.
pub const SHT_SCE_PS2_RELOC: u32 = 0x6000_0000;

/// `SCE_MODULEINFO` section name.
pub const SCE_MODULEINFO_NAME: &str = ".sce.moduleinfo";

/// MIPS HI16 relocation type.
pub const R_MIPS_HI16: u8 = 5;

/// MIPS LO16 relocation type.
pub const R_MIPS_LO16: u8 = 6;

/// MIPS26 relocation type (jump).
pub const R_MIPS_26: u8 = 4;

/// MIPS32 relocation type.
pub const R_MIPS_32: u8 = 2;

/// Size of the PS2 `SCE_MODULEINFO` structure in bytes.
pub const MODULEINFO_SIZE: usize = 256;

// ─── SceSectionType ───────────────────────────────────────────────────────────

/// Categorises a PS2 ELF section type, distinguishing standard from SCE-specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SceSectionType {
    /// Standard ELF null section (`SHT_NULL` = 0).
    Null,
    /// Standard program-bits section.
    ProgBits,
    /// Symbol table section.
    SymTab,
    /// String table section.
    StrTab,
    /// Standard RELA relocation section.
    Rela,
    /// Standard REL relocation section.
    Rel,
    /// SCE IOP relocation section (0x70000080).
    SceIopReloc,
    /// SCE PS2 relocation section (0x60000000).
    ScePs2Reloc,
    /// Any other SCE section in the 0x70000000 range.
    SceOther(u32),
    /// Any unrecognised type.
    Unknown(u32),
}

impl SceSectionType {
    /// Classify a raw section type value.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        match raw {
            SHT_NULL => Self::Null,
            SHT_PROGBITS => Self::ProgBits,
            SHT_SYMTAB => Self::SymTab,
            SHT_STRTAB => Self::StrTab,
            SHT_RELA => Self::Rela,
            SHT_REL => Self::Rel,
            SHT_SCE_IOP_RELOC => Self::SceIopReloc,
            SHT_SCE_PS2_RELOC => Self::ScePs2Reloc,
            v if v >= SCE_SECTION_BASE => Self::SceOther(v),
            v => Self::Unknown(v),
        }
    }

    /// Returns `true` for any SCE-proprietary section type.
    #[must_use]
    pub const fn is_sce(&self) -> bool {
        matches!(
            self,
            Self::SceIopReloc | Self::ScePs2Reloc | Self::SceOther(_)
        )
    }

    /// Returns `true` for any relocation section (standard or SCE).
    #[must_use]
    pub const fn is_reloc(&self) -> bool {
        matches!(
            self,
            Self::Rela | Self::Rel | Self::SceIopReloc | Self::ScePs2Reloc
        )
    }
}

impl fmt::Display for SceSectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "SHT_NULL"),
            Self::ProgBits => write!(f, "SHT_PROGBITS"),
            Self::SymTab => write!(f, "SHT_SYMTAB"),
            Self::StrTab => write!(f, "SHT_STRTAB"),
            Self::Rela => write!(f, "SHT_RELA"),
            Self::Rel => write!(f, "SHT_REL"),
            Self::SceIopReloc => write!(f, "SHT_SCE_IOP_RELOC"),
            Self::ScePs2Reloc => write!(f, "SHT_SCE_PS2_RELOC"),
            Self::SceOther(v) => write!(f, "SCE_{v:#010x}"),
            Self::Unknown(v) => write!(f, "UNKNOWN({v:#010x})"),
        }
    }
}

// ─── Ps2ElfHeader ─────────────────────────────────────────────────────────────

/// Parsed ELF32 file header for a PS2 binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ps2ElfHeader {
    /// `EI_CLASS`: must be `ELFCLASS32` (1).
    pub ei_class: u8,
    /// `EI_DATA`: must be `ELFDATA2LSB` (1) for PS2.
    pub ei_data: u8,
    /// `EI_VERSION`: must be 1.
    pub ei_version: u8,
    /// `EI_OSABI`: typically 0 for PS2.
    pub ei_osabi: u8,
    /// `e_type`: `ET_EXEC` (2) or `ET_SCE_EXEC` (0xFF01) for PS2.
    pub e_type: u16,
    /// `e_machine`: must be `EM_MIPS` (8).
    pub e_machine: u16,
    /// `e_entry`: virtual address of the entry point.
    pub e_entry: u32,
    /// `e_phoff`: file offset to the first program header.
    pub e_phoff: u32,
    /// `e_shoff`: file offset to the first section header.
    pub e_shoff: u32,
    /// `e_flags`: MIPS-specific flags.
    pub e_flags: u32,
    /// `e_phentsize`: size of one program header entry.
    pub e_phentsize: u16,
    /// `e_phnum`: number of program headers.
    pub e_phnum: u16,
    /// `e_shentsize`: size of one section header entry.
    pub e_shentsize: u16,
    /// `e_shnum`: number of section headers.
    pub e_shnum: u16,
    /// `e_shstrndx`: index of the section name string table.
    pub e_shstrndx: u16,
}

impl Ps2ElfHeader {
    /// Parse a 52-byte ELF32 file header from `data`.
    ///
    /// # Errors
    /// Returns a description string if the data is too short, magic is wrong,
    /// class/data/machine fields are invalid for PS2.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < ELF32_HEADER_SIZE {
            return Err(format!(
                "ELF header too short: {} < {ELF32_HEADER_SIZE}",
                data.len()
            ));
        }
        if data[..4] != ELF_MAGIC {
            return Err("invalid ELF magic".to_string());
        }
        let ei_class = data[4];
        if ei_class != ELFCLASS32 {
            return Err(format!("expected ELFCLASS32, got {ei_class}"));
        }
        let ei_data = data[5];
        if ei_data != ELFDATA2LSB {
            return Err(format!("expected little-endian ELF, got {ei_data}"));
        }
        let ei_version = data[6];
        let ei_osabi = data[7];
        let e_type = u16::from_le_bytes([data[16], data[17]]);
        let e_machine = u16::from_le_bytes([data[18], data[19]]);
        if e_machine != EM_MIPS {
            return Err(format!(
                "expected EM_MIPS ({EM_MIPS}), got {e_machine}"
            ));
        }
        let e_entry = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        let e_phoff = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
        let shdr_offset = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        let e_flags = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
        let e_phentsize = u16::from_le_bytes([data[42], data[43]]);
        let e_phnum = u16::from_le_bytes([data[44], data[45]]);
        let shdr_entry_size = u16::from_le_bytes([data[46], data[47]]);
        let shdr_count = u16::from_le_bytes([data[48], data[49]]);
        let e_shstrndx = u16::from_le_bytes([data[50], data[51]]);

        Ok(Self {
            ei_class,
            ei_data,
            ei_version,
            ei_osabi,
            e_type,
            e_machine,
            e_entry,
            e_phoff,
            e_shoff: shdr_offset,
            e_flags,
            e_phentsize,
            e_phnum,
            e_shentsize: shdr_entry_size,
            e_shnum: shdr_count,
            e_shstrndx,
        })
    }

    /// Returns `true` if this looks like a PS2 executable.
    #[must_use]
    pub const fn is_ps2_exec(&self) -> bool {
        self.e_machine == EM_MIPS
            && (self.e_type == 2 /* ET_EXEC */ || self.e_type == 0xFF01 /* ET_SCE_EXEC */)
    }

    /// Decode the MIPS ABI flags from `e_flags`.
    #[must_use]
    pub const fn mips_abi(&self) -> &'static str {
        match (self.e_flags >> 28) & 0xF {
            0 => "MIPS32 O32",
            1 => "MIPS32 O64",
            2 => "MIPS32 EABI32",
            3 => "MIPS64 EABI64",
            _ => "unknown ABI",
        }
    }
}

impl fmt::Display for Ps2ElfHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PS2 ELF entry={:#010x} phnum={} shnum={} flags={:#010x} abi={}",
            self.e_entry, self.e_phnum, self.e_shnum, self.e_flags, self.mips_abi()
        )
    }
}

// ─── ELF32 program header ─────────────────────────────────────────────────────

/// Parsed ELF32 program header (Phdr).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ps2ProgramHeader {
    /// `p_type`: segment type.
    pub p_type: u32,
    /// `p_offset`: file offset of segment data.
    pub p_offset: u32,
    /// `p_vaddr`: virtual address of segment.
    pub p_vaddr: u32,
    /// `p_paddr`: physical address (often same as vaddr on PS2).
    pub p_paddr: u32,
    /// `p_filesz`: size of segment in file.
    pub p_filesz: u32,
    /// `p_memsz`: size of segment in memory.
    pub p_memsz: u32,
    /// `p_flags`: segment flags (`PF_R`/W/X).
    pub p_flags: u32,
    /// `p_align`: alignment.
    pub p_align: u32,
}

impl Ps2ProgramHeader {
    /// Parse one 32-byte Phdr from `data` at `offset`.
    ///
    /// # Errors
    /// Returns an error string if data is too short.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + ELF32_PHDR_SIZE > data.len() {
            return Err(format!(
                "Phdr at {offset} extends past end of file ({} bytes)",
                data.len()
            ));
        }
        let d = &data[offset..];
        Ok(Self {
            p_type:   u32::from_le_bytes([d[0],  d[1],  d[2],  d[3]]),
            p_offset: u32::from_le_bytes([d[4],  d[5],  d[6],  d[7]]),
            p_vaddr:  u32::from_le_bytes([d[8],  d[9],  d[10], d[11]]),
            p_paddr:  u32::from_le_bytes([d[12], d[13], d[14], d[15]]),
            p_filesz: u32::from_le_bytes([d[16], d[17], d[18], d[19]]),
            p_memsz:  u32::from_le_bytes([d[20], d[21], d[22], d[23]]),
            p_flags:  u32::from_le_bytes([d[24], d[25], d[26], d[27]]),
            p_align:  u32::from_le_bytes([d[28], d[29], d[30], d[31]]),
        })
    }

    /// Returns `true` if this is a `PT_LOAD` segment.
    #[must_use]
    pub const fn is_load(&self) -> bool {
        self.p_type == PT_LOAD
    }

    /// Returns `true` if the segment is executable.
    #[must_use]
    pub const fn is_exec(&self) -> bool {
        self.p_flags & 1 != 0
    }

    /// Returns `true` if the segment is writable.
    #[must_use]
    pub const fn is_write(&self) -> bool {
        self.p_flags & 2 != 0
    }

    /// Returns `true` if the segment is readable.
    #[must_use]
    pub const fn is_read(&self) -> bool {
        self.p_flags & 4 != 0
    }
}

// ─── ELF32 section header ─────────────────────────────────────────────────────

/// Parsed ELF32 section header (Shdr).
#[derive(Debug, Clone)]
pub struct Ps2SectionHeader {
    /// `sh_name`: offset into the section name string table.
    pub sh_name: u32,
    /// `sh_type`: raw section type.
    pub sh_type: u32,
    /// `sh_flags`: section flags.
    pub sh_flags: u32,
    /// `sh_addr`: virtual address of section in memory.
    pub sh_addr: u32,
    /// `sh_offset`: file offset of section data.
    pub sh_offset: u32,
    /// `sh_size`: size of section in file.
    pub sh_size: u32,
    /// `sh_link`: linked section index.
    pub sh_link: u32,
    /// `sh_info`: extra information.
    pub sh_info: u32,
    /// `sh_addralign`: alignment requirement.
    pub sh_addralign: u32,
    /// `sh_entsize`: size of each entry (for table sections).
    pub sh_entsize: u32,
    /// Resolved section name (filled in after parsing the shstrtab).
    pub name: String,
}

impl Ps2SectionHeader {
    /// Parse one 40-byte Shdr from `data` at `offset`.
    ///
    /// # Errors
    /// Returns an error string if data is too short.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + ELF32_SHDR_SIZE > data.len() {
            return Err(format!(
                "Shdr at {offset} extends past end of file"
            ));
        }
        let d = &data[offset..];
        Ok(Self {
            sh_name:      u32::from_le_bytes([d[0],  d[1],  d[2],  d[3]]),
            sh_type:      u32::from_le_bytes([d[4],  d[5],  d[6],  d[7]]),
            sh_flags:     u32::from_le_bytes([d[8],  d[9],  d[10], d[11]]),
            sh_addr:      u32::from_le_bytes([d[12], d[13], d[14], d[15]]),
            sh_offset:    u32::from_le_bytes([d[16], d[17], d[18], d[19]]),
            sh_size:      u32::from_le_bytes([d[20], d[21], d[22], d[23]]),
            sh_link:      u32::from_le_bytes([d[24], d[25], d[26], d[27]]),
            sh_info:      u32::from_le_bytes([d[28], d[29], d[30], d[31]]),
            sh_addralign: u32::from_le_bytes([d[32], d[33], d[34], d[35]]),
            sh_entsize:   u32::from_le_bytes([d[36], d[37], d[38], d[39]]),
            name: String::new(),
        })
    }

    /// Return the classified section type.
    #[must_use]
    pub const fn section_type(&self) -> SceSectionType {
        SceSectionType::from_raw(self.sh_type)
    }
}

// ─── ModuleInfo ───────────────────────────────────────────────────────────────

/// PS2 SCE module information parsed from `.sce.moduleinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    /// Module attribute flags.
    pub attributes: u16,
    /// Module version (major, minor).
    pub version: [u8; 2],
    /// Module name (ASCII, null-terminated, up to 28 bytes).
    pub name: String,
    /// GP register value for this module.
    pub gp_value: u32,
    /// Export table offset.
    pub export_offset: u32,
    /// End of export table offset.
    pub export_end: u32,
    /// Import table offset.
    pub import_offset: u32,
    /// End of import table offset.
    pub import_end: u32,
}

impl ModuleInfo {
    /// Parse a `ModuleInfo` from the `.sce.moduleinfo` section data.
    ///
    /// # Errors
    /// Returns an error string if the section data is too short.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 48 {
            return Err(format!(
                "moduleinfo section too short: {} < 48",
                data.len()
            ));
        }
        let attributes = u16::from_le_bytes([data[0], data[1]]);
        let version = [data[2], data[3]];
        // Name is 28 bytes at offset 4.
        let name_raw = &data[4..32];
        let nul = name_raw.iter().position(|&b| b == 0).unwrap_or(28);
        let name = String::from_utf8_lossy(&name_raw[..nul]).to_string();
        let gp_value = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        let export_offset = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
        let export_end = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);
        let import_offset = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
        let import_end = if data.len() >= 52 {
            u32::from_le_bytes([data[48], data[49], data[50], data[51]])
        } else {
            import_offset
        };
        Ok(Self {
            attributes,
            version,
            name,
            gp_value,
            export_offset,
            export_end,
            import_offset,
            import_end,
        })
    }

    /// Module version as "major.minor" string.
    #[must_use]
    pub fn version_str(&self) -> String {
        format!("{}.{:02}", self.version[1], self.version[0])
    }

    /// Number of export table entries (each entry is 4 bytes).
    #[must_use]
    pub const fn export_count(&self) -> usize {
        self.export_end.saturating_sub(self.export_offset) as usize / 4
    }

    /// Number of import table entries (each entry is 4 bytes).
    #[must_use]
    pub const fn import_count(&self) -> usize {
        self.import_end.saturating_sub(self.import_offset) as usize / 4
    }
}

impl fmt::Display for ModuleInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SCE Module \"{}\" v{} gp={:#010x} exports={} imports={}",
            self.name,
            self.version_str(),
            self.gp_value,
            self.export_count(),
            self.import_count(),
        )
    }
}

// ─── MipsReloc ────────────────────────────────────────────────────────────────

/// A single MIPS relocation entry as found in PS2 ELF REL sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MipsReloc {
    /// Offset in the section or file to patch.
    pub r_offset: u32,
    /// Symbol index (upper 24 bits of `r_info`).
    pub sym_index: u32,
    /// Relocation type (lower 8 bits of `r_info`).
    pub r_type: u8,
    /// Addend for RELA relocations (0 for REL).
    pub r_addend: i32,
}

impl MipsReloc {
    /// Parse a 8-byte REL entry from `data` at `offset`.
    ///
    /// # Errors
    /// Returns an error string if out of bounds.
    pub fn parse_rel(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 8 > data.len() {
            return Err(format!("REL entry at {offset} out of bounds"));
        }
        let r_offset = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
        let r_info   = u32::from_le_bytes([data[offset+4], data[offset+5], data[offset+6], data[offset+7]]);
        let sym_index = r_info >> 8;
        let r_type = (r_info & 0xFF) as u8;
        Ok(Self { r_offset, sym_index, r_type, r_addend: 0 })
    }

    /// Parse a 12-byte RELA entry from `data` at `offset`.
    ///
    /// # Errors
    /// Returns an error string if out of bounds.
    pub fn parse_rela(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 12 > data.len() {
            return Err(format!("RELA entry at {offset} out of bounds"));
        }
        let r_offset = u32::from_le_bytes([data[offset],   data[offset+1], data[offset+2], data[offset+3]]);
        let r_info   = u32::from_le_bytes([data[offset+4], data[offset+5], data[offset+6], data[offset+7]]);
        let r_addend = i32::from_le_bytes([data[offset+8], data[offset+9], data[offset+10], data[offset+11]]);
        let sym_index = r_info >> 8;
        let r_type = (r_info & 0xFF) as u8;
        Ok(Self { r_offset, sym_index, r_type, r_addend })
    }

    /// Return a human-readable relocation type name.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self.r_type {
            0 => "R_MIPS_NONE",
            1 => "R_MIPS_16",
            2 => "R_MIPS_32",
            3 => "R_MIPS_REL32",
            4 => "R_MIPS_26",
            5 => "R_MIPS_HI16",
            6 => "R_MIPS_LO16",
            7 => "R_MIPS_GPREL16",
            8 => "R_MIPS_LITERAL",
            9 => "R_MIPS_GOT16",
            10 => "R_MIPS_PC16",
            11 => "R_MIPS_CALL16",
            12 => "R_MIPS_GPREL32",
            _ => "R_MIPS_UNKNOWN",
        }
    }
}

// ─── MipsHiLoRelocPair ────────────────────────────────────────────────────────

/// Holds a pending HI16 relocation waiting for its matching LO16.
#[derive(Debug, Clone)]
struct PendingHi16 {
    /// File/section offset of the HI16 instruction.
    offset: u32,
    /// Symbol value associated with this HI16.
    sym_value: u32,
}

/// Apply MIPS HI16/LO16 relocation pairs to a mutable byte buffer.
///
/// MIPS HI16/LO16 pairs encode a 32-bit address split across two instructions:
/// - HI16: upper 16 bits of the address (with carry from LO16 sign extension).
/// - LO16: lower 16 bits of the address (sign-extended by the CPU).
///
/// Returns the number of relocation pairs processed.
#[must_use]
pub fn apply_mips_hi16_lo16_relocs<S: std::hash::BuildHasher>(
    section_data: &mut [u8],
    relocs: &[MipsReloc],
    sym_values: &HashMap<u32, u32, S>,
) -> usize {
    let mut pending_hi16: Vec<PendingHi16> = Vec::new();
    let mut pairs_applied = 0usize;

    for reloc in relocs {
        let off = reloc.r_offset as usize;
        let sym_val = sym_values.get(&reloc.sym_index).copied().unwrap_or(0);

        match reloc.r_type {
            R_MIPS_HI16 => {
                pending_hi16.push(PendingHi16 {
                    offset: reloc.r_offset,
                    sym_value: sym_val,
                });
            }
            R_MIPS_LO16 => {
                // Read the LO16 immediate from the instruction.
                if off + 4 > section_data.len() {
                    pending_hi16.clear();
                    continue;
                }
                let lo_instr = u32::from_le_bytes([
                    section_data[off],
                    section_data[off + 1],
                    section_data[off + 2],
                    section_data[off + 3],
                ]);
                let lo_imm = (lo_instr & 0xFFFF) as i16;

                // The full 32-bit address: sym_val + lo_imm (sign-extended).
                let full_addr = sym_val.wrapping_add(reloc.r_addend.cast_unsigned());
                let lo16 = full_addr & 0xFFFF;

                // Apply the LO16 patch.
                let patched_lo = (lo_instr & 0xFFFF_0000) | lo16;
                let bytes = patched_lo.to_le_bytes();
                section_data[off..off + 4].copy_from_slice(&bytes);

                // Now patch all pending HI16 instructions.
                for hi in std::mem::take(&mut pending_hi16) {
                    let hi_off = hi.offset as usize;
                    if hi_off + 4 > section_data.len() {
                        continue;
                    }
                    let hi_instr = u32::from_le_bytes([
                        section_data[hi_off],
                        section_data[hi_off + 1],
                        section_data[hi_off + 2],
                        section_data[hi_off + 3],
                    ]);
                    // Compute HI16 using the HI16's own symbol value (the
                    // HI16 and LO16 may reference distinct symbols when
                    // emitted by the assembler in unusual orderings).
                    let hi_full = hi.sym_value.wrapping_add(reloc.r_addend.cast_unsigned());
                    let combined = if hi.sym_value == sym_val {
                        full_addr
                    } else {
                        hi_full
                    };
                    let adjusted = combined.wrapping_add(u32::from(lo_imm < 0));
                    let hi16 = (adjusted >> 16) & 0xFFFF;
                    let patched_hi = (hi_instr & 0xFFFF_0000) | hi16;
                    let hbytes = patched_hi.to_le_bytes();
                    section_data[hi_off..hi_off + 4].copy_from_slice(&hbytes);
                    pairs_applied += 1;
                }
            }
            _ => {
                // Non-HI/LO relocation; discard pending HI16 accumulation.
                // A production loader would handle other types here.
                if !pending_hi16.is_empty() {
                    pending_hi16.clear();
                }
            }
        }
    }

    pairs_applied
}

// ─── GpAddressing ─────────────────────────────────────────────────────────────

/// Computes MIPS GP-relative (small data) addresses.
///
/// The PS2 Emotion Engine uses a global pointer (GP) register to access small
/// data within a ±32KB window.  Given the GP base and a signed 16-bit offset,
/// this returns the effective virtual address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpAddressing {
    /// The value of the GP register (base address of the .sdata/.sbss area).
    pub gp_base: u32,
}

impl GpAddressing {
    /// Create a new GP addressing helper.
    #[must_use]
    pub const fn new(gp_base: u32) -> Self {
        Self { gp_base }
    }

    /// Compute the effective address for a GP-relative access.
    ///
    /// `offset` is the signed 16-bit immediate from the instruction.
    #[must_use]
    pub const fn effective_address(&self, offset: i16) -> u32 {
        self.gp_base.wrapping_add((offset as i32).cast_unsigned())
    }

    /// Returns `true` if `addr` is within the GP-accessible window (±32 KB).
    #[must_use]
    pub const fn in_gp_window(&self, addr: u32) -> bool {
        let lo = self.gp_base.wrapping_sub(0x8000);
        let hi = self.gp_base.wrapping_add(0x7FFF);
        if lo <= hi {
            addr >= lo && addr <= hi
        } else {
            // Wraps around 0 — two disjoint ranges.
            addr >= lo || addr <= hi
        }
    }

    /// Compute the GP-relative offset for a given virtual address.
    ///
    /// Returns `None` if the address is outside the ±32 KB window.
    #[must_use]
    pub fn gp_offset_of(&self, addr: u32) -> Option<i16> {
        let diff = addr.wrapping_sub(self.gp_base).cast_signed();
        if (-0x8000..=0x7FFF).contains(&diff) {
            Some(i16::try_from(diff).unwrap_or(i16::MAX))
        } else {
            None
        }
    }
}

// ─── Ps2Symbol ────────────────────────────────────────────────────────────────

/// A symbol extracted from the PS2 ELF symbol table or module info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ps2Symbol {
    /// Symbol name.
    pub name: String,
    /// Virtual address (`st_value` from the ELF symtab or derived from exports).
    pub address: u32,
    /// Symbol size in bytes (0 if unknown).
    pub size: u32,
    /// Symbol type: `STT_FUNC` (2), `STT_OBJECT` (1), etc.
    pub sym_type: u8,
    /// Symbol binding: `STB_LOCAL` (0), `STB_GLOBAL` (1), `STB_WEAK` (2).
    pub binding: u8,
    /// Section index the symbol resides in.
    pub shndx: u16,
    /// Source of the symbol.
    pub source: Ps2SymbolSource,
}

/// The origin of a PS2 symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ps2SymbolSource {
    /// From the standard ELF `.symtab` section.
    ElfSymtab,
    /// From the SCE module export table.
    ModuleExport,
    /// Derived from module entry point.
    ModuleEntry,
}

impl Ps2Symbol {
    /// Returns `true` if this symbol represents a function.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        self.sym_type == 2
    }

    /// Returns `true` if this is a global or weak symbol.
    #[must_use]
    pub const fn is_global(&self) -> bool {
        self.binding == 1 || self.binding == 2
    }
}

// ─── Ps2Loader ────────────────────────────────────────────────────────────────

/// The primary PS2 ELF loader.
///
/// Parses the ELF structure, extracts load segments, resolves section names,
/// parses `.sce.moduleinfo`, builds a symbol table, and resolves GP addressing.
#[derive(Debug)]
pub struct Ps2Loader {
    /// Parsed ELF file header.
    pub header: Ps2ElfHeader,
    /// All parsed program headers.
    pub phdrs: Vec<Ps2ProgramHeader>,
    /// All parsed section headers (with resolved names).
    pub shdrs: Vec<Ps2SectionHeader>,
    /// Module info, if the `.sce.moduleinfo` section was present.
    pub module_info: Option<ModuleInfo>,
    /// GP addressing helper derived from module info or `.reginfo` section.
    pub gp: GpAddressing,
    /// Symbol table built from the ELF symtab and module exports.
    pub symbols: Vec<Ps2Symbol>,
    /// All relocation entries collected from REL/RELA sections.
    pub relocs: Vec<MipsReloc>,
    /// Load segments: (`vaddr`, `file_offset`, `size`) for each `PT_LOAD`.
    pub load_segments: Vec<(u32, u32, u32)>,
}

impl Ps2Loader {
    /// Load and parse a PS2 ELF binary from `data`.
    ///
    /// # Errors
    /// Returns a string describing the parse error on failure.
    pub fn load(data: &[u8]) -> Result<Self, String> {
        let header = Ps2ElfHeader::parse(data)?;

        // Parse all program headers.
        let mut phdrs = Vec::with_capacity(header.e_phnum as usize);
        for i in 0..header.e_phnum as usize {
            let off = header.e_phoff as usize + i * header.e_phentsize as usize;
            phdrs.push(Ps2ProgramHeader::parse(data, off)?);
        }

        // Collect PT_LOAD segments.
        let load_segments: Vec<(u32, u32, u32)> = phdrs
            .iter()
            .filter(|p| p.is_load() && p.p_filesz > 0)
            .map(|p| (p.p_vaddr, p.p_offset, p.p_filesz))
            .collect();

        // Parse all section headers.
        let mut raw_shdrs: Vec<Ps2SectionHeader> = Vec::with_capacity(header.e_shnum as usize);
        for i in 0..header.e_shnum as usize {
            let off = header.e_shoff as usize + i * header.e_shentsize as usize;
            raw_shdrs.push(Ps2SectionHeader::parse(data, off)?);
        }

        // Resolve section names from shstrtab.
        if (header.e_shstrndx as usize) < raw_shdrs.len() {
            let strtab_shdr = &raw_shdrs[header.e_shstrndx as usize];
            let strtab_off = strtab_shdr.sh_offset as usize;
            let strtab_size = strtab_shdr.sh_size as usize;
            if strtab_off + strtab_size <= data.len() {
                let strtab = &data[strtab_off..strtab_off + strtab_size];
                for shdr in &mut raw_shdrs {
                    let name_off = shdr.sh_name as usize;
                    if name_off < strtab.len() {
                        let end = strtab[name_off..]
                            .iter()
                            .position(|&b| b == 0)
                            .map_or(strtab.len() - name_off, |p| p);
                        shdr.name = String::from_utf8_lossy(
                            &strtab[name_off..name_off + end],
                        )
                        .to_string();
                    }
                }
            }
        }

        // Parse module info.
        let module_info = raw_shdrs
            .iter()
            .find(|s| s.name == SCE_MODULEINFO_NAME)
            .and_then(|s| {
                let off = s.sh_offset as usize;
                let sz = s.sh_size as usize;
                if off + sz <= data.len() {
                    ModuleInfo::parse(&data[off..off + sz]).ok()
                } else {
                    None
                }
            });

        // Determine GP base.
        let gp_base = module_info.as_ref().map_or(0, |mi| mi.gp_value);
        let gp = GpAddressing::new(gp_base);

        // Parse symbol table.
        let mut symbols = Vec::new();
        let strtab_data = find_strtab(data, &raw_shdrs, ".strtab");
        for shdr in &raw_shdrs {
            if shdr.sh_type == SHT_SYMTAB && shdr.sh_entsize >= 16 {
                let off = shdr.sh_offset as usize;
                let sz = shdr.sh_size as usize;
                if off + sz > data.len() {
                    continue;
                }
                let sym_data = &data[off..off + sz];
                let count = sz / shdr.sh_entsize as usize;
                for i in 0..count {
                    let s_off = i * shdr.sh_entsize as usize;
                    if s_off + 16 > sym_data.len() {
                        break;
                    }
                    let sd = &sym_data[s_off..];
                    let st_name   = u32::from_le_bytes([sd[0],  sd[1],  sd[2],  sd[3]]);
                    let st_value  = u32::from_le_bytes([sd[4],  sd[5],  sd[6],  sd[7]]);
                    let st_size   = u32::from_le_bytes([sd[8],  sd[9],  sd[10], sd[11]]);
                    let st_info   = sd[12];
                    let st_shndx  = u16::from_le_bytes([sd[14], sd[15]]);
                    let name = resolve_strtab_name(strtab_data, st_name as usize);
                    symbols.push(Ps2Symbol {
                        name,
                        address: st_value,
                        size: st_size,
                        sym_type: st_info & 0xF,
                        binding: st_info >> 4,
                        shndx: st_shndx,
                        source: Ps2SymbolSource::ElfSymtab,
                    });
                }
            }
        }

        // Add module entry point as a synthetic symbol.
        if let Some(ref mi) = module_info {
            symbols.push(Ps2Symbol {
                name: format!("{}_start", mi.name),
                address: header.e_entry,
                size: 0,
                sym_type: 2,
                binding: 1,
                shndx: 0,
                source: Ps2SymbolSource::ModuleEntry,
            });
        }

        // Collect all REL relocations.
        let mut relocs = Vec::new();
        for shdr in &raw_shdrs {
            if shdr.sh_type == SHT_REL && shdr.sh_entsize == 8 {
                let off = shdr.sh_offset as usize;
                let sz = shdr.sh_size as usize;
                if off + sz > data.len() {
                    continue;
                }
                let count = sz / 8;
                for i in 0..count {
                    if let Ok(r) = MipsReloc::parse_rel(data, off + i * 8) {
                        relocs.push(r);
                    }
                }
            }
        }

        Ok(Self {
            header,
            phdrs,
            shdrs: raw_shdrs,
            module_info,
            gp,
            symbols,
            relocs,
            load_segments,
        })
    }

    /// Return all function symbols sorted by address.
    #[must_use]
    pub fn functions(&self) -> Vec<&Ps2Symbol> {
        let mut fns: Vec<&Ps2Symbol> = self.symbols.iter().filter(|s| s.is_function()).collect();
        fns.sort_by_key(|s| s.address);
        fns
    }

    /// Find a symbol by name.
    #[must_use]
    pub fn symbol_by_name(&self, name: &str) -> Option<&Ps2Symbol> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /// Return the entry point address.
    #[must_use]
    pub const fn entry_point(&self) -> u32 {
        self.header.e_entry
    }

    /// Summary string for the loaded binary.
    #[must_use]
    pub fn summary(&self) -> String {
        let mod_name = self
            .module_info
            .as_ref()
            .map_or("(no module info)", |m| &m.name);
        format!(
            "PS2 ELF \"{}\" entry={:#010x} segs={} syms={} relocs={}",
            mod_name,
            self.header.e_entry,
            self.load_segments.len(),
            self.symbols.len(),
            self.relocs.len(),
        )
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Locate the `.strtab` section data (or empty if not found).
fn find_strtab<'a>(data: &'a [u8], shdrs: &[Ps2SectionHeader], name: &str) -> &'a [u8] {
    for shdr in shdrs {
        if shdr.name == name {
            let off = shdr.sh_offset as usize;
            let sz = shdr.sh_size as usize;
            if off + sz <= data.len() {
                return &data[off..off + sz];
            }
        }
    }
    &[]
}

/// Look up a null-terminated string in a string table at `offset`.
fn resolve_strtab_name(strtab: &[u8], offset: usize) -> String {
    if offset >= strtab.len() {
        return String::new();
    }
    let end = strtab[offset..]
        .iter()
        .position(|&b| b == 0)
        .map_or(strtab.len() - offset, |p| p);
    String::from_utf8_lossy(&strtab[offset..offset + end]).to_string()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_elf_header(entry: u32, phnum: u16, shnum: u16, shstrndx: u16) -> Vec<u8> {
        let mut h = vec![0u8; ELF32_HEADER_SIZE];
        h[0..4].copy_from_slice(&ELF_MAGIC);
        h[4] = ELFCLASS32;
        h[5] = ELFDATA2LSB;
        h[6] = 1; // EI_VERSION
        h[7] = 0; // ELFOSABI_NONE
        h[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        h[18..20].copy_from_slice(&EM_MIPS.to_le_bytes());
        h[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        h[24..28].copy_from_slice(&entry.to_le_bytes());
        h[40..42].copy_from_slice(&u16::try_from(ELF32_HEADER_SIZE).unwrap_or(u16::MAX).to_le_bytes()); // e_ehsize
        h[42..44].copy_from_slice(&u16::try_from(ELF32_PHDR_SIZE).unwrap_or(u16::MAX).to_le_bytes()); // e_phentsize
        h[44..46].copy_from_slice(&phnum.to_le_bytes());
        h[46..48].copy_from_slice(&u16::try_from(ELF32_SHDR_SIZE).unwrap_or(u16::MAX).to_le_bytes()); // e_shentsize
        h[48..50].copy_from_slice(&shnum.to_le_bytes());
        h[50..52].copy_from_slice(&shstrndx.to_le_bytes());
        h
    }

    #[test]
    fn test_elf_header_parse() {
        let h = make_elf_header(0x1000_0000, 0, 0, 0);
        let hdr = Ps2ElfHeader::parse(&h).unwrap();
        assert_eq!(hdr.e_entry, 0x1000_0000);
        assert_eq!(hdr.e_machine, EM_MIPS);
        assert!(hdr.is_ps2_exec());
    }

    #[test]
    fn test_elf_header_wrong_magic() {
        let mut h = make_elf_header(0, 0, 0, 0);
        h[0] = 0xFF;
        assert!(Ps2ElfHeader::parse(&h).is_err());
    }

    #[test]
    fn test_sce_section_type_classification() {
        assert!(SceSectionType::from_raw(SHT_SCE_IOP_RELOC).is_sce());
        assert!(SceSectionType::from_raw(SHT_SCE_PS2_RELOC).is_sce());
        assert!(SceSectionType::from_raw(0x7000_1234).is_sce());
        assert!(!SceSectionType::from_raw(SHT_PROGBITS).is_sce());
        assert!(SceSectionType::from_raw(SHT_REL).is_reloc());
    }

    #[test]
    fn test_module_info_parse() {
        let mut mi_data = vec![0u8; 52];
        mi_data[0..2].copy_from_slice(&0x0001u16.to_le_bytes()); // attributes
        mi_data[2] = 0x10; // version minor
        mi_data[3] = 0x01; // version major
        let name = b"TestModule";
        mi_data[4..4 + name.len()].copy_from_slice(name);
        mi_data[32..36].copy_from_slice(&0xBEEF_0000u32.to_le_bytes()); // gp_value
        mi_data[36..40].copy_from_slice(&0x100u32.to_le_bytes()); // export_offset
        mi_data[40..44].copy_from_slice(&0x120u32.to_le_bytes()); // export_end
        mi_data[44..48].copy_from_slice(&0x200u32.to_le_bytes()); // import_offset
        mi_data[48..52].copy_from_slice(&0x240u32.to_le_bytes()); // import_end

        let mi = ModuleInfo::parse(&mi_data).unwrap();
        assert_eq!(mi.name, "TestModule");
        assert_eq!(mi.gp_value, 0xBEEF_0000);
        assert_eq!(mi.export_count(), 8); // (0x120 - 0x100) / 4
        assert_eq!(mi.version_str(), "1.16");
    }

    #[test]
    fn test_gp_addressing() {
        let gp = GpAddressing::new(0x8000_0000);
        assert_eq!(gp.effective_address(0x100), 0x8000_0100);
        assert_eq!(gp.effective_address(-0x100i16), 0x7FFF_FF00);
        assert!(gp.in_gp_window(0x8000_0010));
        assert!(!gp.in_gp_window(0x7000_0000));
        assert_eq!(gp.gp_offset_of(0x8000_0010), Some(0x10));
        assert!(gp.gp_offset_of(0x7000_0000).is_none());
    }

    #[test]
    fn test_mips_reloc_parse_rel() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&0x1000u32.to_le_bytes()); // r_offset
        // r_info: sym=5, type=R_MIPS_HI16(5)
        let r_info: u32 = (5 << 8) | 5;
        data[4..8].copy_from_slice(&r_info.to_le_bytes());
        let r = MipsReloc::parse_rel(&data, 0).unwrap();
        assert_eq!(r.r_offset, 0x1000);
        assert_eq!(r.sym_index, 5);
        assert_eq!(r.r_type, R_MIPS_HI16);
        assert_eq!(r.type_name(), "R_MIPS_HI16");
    }

    #[test]
    fn test_apply_hi16_lo16_relocs() {
        // Build a fake code section with HI16 and LO16 instructions.
        // lui  $v0, 0x0000  → 0x3C020000 (opcode 0x0F, rd=2, imm=0)
        // addiu $v0, $v0, 0x0  → 0x24420000
        let mut section = vec![0u8; 8];
        section[0..4].copy_from_slice(&0x3C02_0000u32.to_le_bytes()); // HI16 instr
        section[4..8].copy_from_slice(&0x2442_0000u32.to_le_bytes()); // LO16 instr

        let hi_reloc = MipsReloc { r_offset: 0, sym_index: 1, r_type: R_MIPS_HI16, r_addend: 0 };
        let lo_reloc = MipsReloc { r_offset: 4, sym_index: 1, r_type: R_MIPS_LO16, r_addend: 0 };

        let mut syms = HashMap::new();
        syms.insert(1u32, 0x1234_5678u32);

        let pairs = apply_mips_hi16_lo16_relocs(&mut section, &[hi_reloc, lo_reloc], &syms);
        assert_eq!(pairs, 1);
        // LO16 should be 0x5678, HI16 adjusted for sign extension of 0x5678 (positive) → 0x1234.
        let lo_instr = u32::from_le_bytes([section[4], section[5], section[6], section[7]]);
        assert_eq!(lo_instr & 0xFFFF, 0x5678);
        let hi_instr = u32::from_le_bytes([section[0], section[1], section[2], section[3]]);
        assert_eq!(hi_instr & 0xFFFF, 0x1234);
    }
}
