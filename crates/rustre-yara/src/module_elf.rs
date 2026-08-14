//! YARA ELF module — exposes ELF header, section, and segment metadata as
//! YARA-queryable fields.
//!
//! Mirrors the behaviour of the official libyara `elf` module:
//! `elf.type`, `elf.machine`, `elf.entry_point`, `elf.number_of_sections`,
//! `elf.number_of_segments`, `elf.sections[n].{name,type,address,size,offset,flags}`,
//! `elf.segments[n].{type,flags,offset,virtual_address,physical_address,file_size,memory_size,alignment}`.

use std::collections::HashMap;

// ── ELF constants ─────────────────────────────────────────────────────────────

/// ELF file type (`e_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfType {
    None,
    Rel,
    Exec,
    Dyn,
    Core,
    Unknown(u16),
}

impl ElfType {
    #[must_use] 
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Rel,
            2 => Self::Exec,
            3 => Self::Dyn,
            4 => Self::Core,
            n => Self::Unknown(n),
        }
    }

    #[must_use] 
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::None => 0,
            Self::Rel => 1,
            Self::Exec => 2,
            Self::Dyn => 3,
            Self::Core => 4,
            Self::Unknown(n) => n,
        }
    }
}

/// ELF machine type (`e_machine`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfMachine {
    None,
    M32,
    Sparc,
    I386,
    M68K,
    Mips,
    PowerPc,
    S390,
    Arm,
    SuperH,
    Ia64,
    X86_64,
    Aarch64,
    RiscV,
    Unknown(u16),
}

impl ElfMachine {
    #[must_use] 
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0 => Self::None,
            1 => Self::M32,
            2 => Self::Sparc,
            3 => Self::I386,
            4 => Self::M68K,
            8 => Self::Mips,
            20 => Self::PowerPc,
            22 => Self::S390,
            40 => Self::Arm,
            42 => Self::SuperH,
            50 => Self::Ia64,
            62 => Self::X86_64,
            183 => Self::Aarch64,
            243 => Self::RiscV,
            n => Self::Unknown(n),
        }
    }

    #[must_use] 
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::None => 0,
            Self::M32 => 1,
            Self::Sparc => 2,
            Self::I386 => 3,
            Self::M68K => 4,
            Self::Mips => 8,
            Self::PowerPc => 20,
            Self::S390 => 22,
            Self::Arm => 40,
            Self::SuperH => 42,
            Self::Ia64 => 50,
            Self::X86_64 => 62,
            Self::Aarch64 => 183,
            Self::RiscV => 243,
            Self::Unknown(n) => n,
        }
    }
}

// ── Section ───────────────────────────────────────────────────────────────────

/// Section header flags.
pub mod sh_flags {
    pub const WRITE: u64 = 0x1;
    pub const ALLOC: u64 = 0x2;
    pub const EXECINSTR: u64 = 0x4;
    pub const MERGE: u64 = 0x10;
    pub const STRINGS: u64 = 0x20;
    pub const INFO_LINK: u64 = 0x40;
    pub const LINK_ORDER: u64 = 0x80;
    pub const TLS: u64 = 0x400;
}

/// Section header type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionType {
    Null,
    ProgBits,
    SymTab,
    StrTab,
    Rela,
    Hash,
    Dynamic,
    Note,
    NoBits,
    Rel,
    DynSym,
    Unknown(u32),
}

impl SectionType {
    #[must_use] 
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Null,
            1 => Self::ProgBits,
            2 => Self::SymTab,
            3 => Self::StrTab,
            4 => Self::Rela,
            5 => Self::Hash,
            6 => Self::Dynamic,
            7 => Self::Note,
            8 => Self::NoBits,
            9 => Self::Rel,
            11 => Self::DynSym,
            n => Self::Unknown(n),
        }
    }

    #[must_use] 
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Null => 0,
            Self::ProgBits => 1,
            Self::SymTab => 2,
            Self::StrTab => 3,
            Self::Rela => 4,
            Self::Hash => 5,
            Self::Dynamic => 6,
            Self::Note => 7,
            Self::NoBits => 8,
            Self::Rel => 9,
            Self::DynSym => 11,
            Self::Unknown(n) => n,
        }
    }
}

/// One parsed ELF section.
#[derive(Debug, Clone)]
pub struct ElfSection {
    /// Section name (may be empty if `.shstrtab` is missing).
    pub name: String,
    pub section_type: SectionType,
    pub flags: u64,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub align: u64,
    pub entry_size: u64,
}

// ── Segment ───────────────────────────────────────────────────────────────────

/// Program header type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SegmentType {
    Null,
    Load,
    Dynamic,
    Interp,
    Note,
    Shlib,
    Phdr,
    Tls,
    GnuStack,
    GnuRelRo,
    Unknown(u32),
}

impl SegmentType {
    #[must_use] 
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Null,
            1 => Self::Load,
            2 => Self::Dynamic,
            3 => Self::Interp,
            4 => Self::Note,
            5 => Self::Shlib,
            6 => Self::Phdr,
            7 => Self::Tls,
            0x6474_E551 => Self::GnuStack,
            0x6474_E552 => Self::GnuRelRo,
            n => Self::Unknown(n),
        }
    }
}

/// Program header flags.
pub mod ph_flags {
    pub const EXECUTE: u32 = 0x1;
    pub const WRITE: u32 = 0x2;
    pub const READ: u32 = 0x4;
}

/// One parsed ELF segment (program header entry).
#[derive(Debug, Clone)]
pub struct ElfSegment {
    pub segment_type: SegmentType,
    pub flags: u32,
    pub offset: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub alignment: u64,
}

// ── Parse error ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfModuleError {
    TooShort,
    BadMagic,
    UnsupportedClass(u8),
    UnsupportedEncoding(u8),
    Truncated(&'static str),
}

impl std::fmt::Display for ElfModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "data too short to be ELF"),
            Self::BadMagic => write!(f, "ELF magic mismatch"),
            Self::UnsupportedClass(c) => write!(f, "unsupported ELF class {c}"),
            Self::UnsupportedEncoding(e) => write!(f, "unsupported ELF data encoding {e}"),
            Self::Truncated(s) => write!(f, "truncated ELF: {s}"),
        }
    }
}

impl std::error::Error for ElfModuleError {}

pub type ElfResult<T> = Result<T, ElfModuleError>;

// ── YARA ELF module ───────────────────────────────────────────────────────────

/// Parsed ELF metadata exposed to YARA rules.
#[derive(Debug, Clone)]
pub struct YaraModuleElf {
    pub elf_type: ElfType,
    pub machine: ElfMachine,
    pub entry_point: u64,
    pub number_of_sections: u32,
    pub number_of_segments: u32,
    pub sections: Vec<ElfSection>,
    pub segments: Vec<ElfSegment>,
    /// True for 64-bit ELFs, false for 32-bit.
    pub is_64bit: bool,
    /// True for little-endian, false for big-endian.
    pub is_little_endian: bool,
}

impl YaraModuleElf {
    /// Parse `data` as an ELF binary and return the module view.
    ///
    /// # Errors
    ///
    /// Returns [`ElfModuleError`] if the binary is malformed.
    pub fn parse(data: &[u8]) -> ElfResult<Self> {
        if data.len() < 16 {
            return Err(ElfModuleError::TooShort);
        }
        if &data[0..4] != b"\x7fELF" {
            return Err(ElfModuleError::BadMagic);
        }
        let class = data[4];
        let encoding = data[5];

        match class {
            1 => Self::parse_elf32(data, encoding),
            2 => Self::parse_elf64(data, encoding),
            c => Err(ElfModuleError::UnsupportedClass(c)),
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn read_u16(data: &[u8], off: usize, le: bool) -> ElfResult<u16> {
        if off + 2 > data.len() {
            return Err(ElfModuleError::Truncated("u16 read"));
        }
        let b = &data[off..off + 2];
        Ok(if le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    }

    fn read_u32(data: &[u8], off: usize, le: bool) -> ElfResult<u32> {
        if off + 4 > data.len() {
            return Err(ElfModuleError::Truncated("u32 read"));
        }
        let b = &data[off..off + 4];
        Ok(if le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    }

    fn read_u64(data: &[u8], off: usize, le: bool) -> ElfResult<u64> {
        if off + 8 > data.len() {
            return Err(ElfModuleError::Truncated("u64 read"));
        }
        let b = &data[off..off + 8];
        Ok(if le {
            u64::from_le_bytes(b.try_into().unwrap())
        } else {
            u64::from_be_bytes(b.try_into().unwrap())
        })
    }

    fn read_cstr(data: &[u8], off: usize) -> String {
        if off >= data.len() {
            return String::new();
        }
        let end = data[off..]
            .iter()
            .position(|&b| b == 0)
            .map_or(data.len(), |i| off + i);
        String::from_utf8_lossy(&data[off..end]).into_owned()
    }

    // ── 32-bit parser ─────────────────────────────────────────────────────────

    fn parse_elf32(data: &[u8], encoding: u8) -> ElfResult<Self> {
        if data.len() < 52 {
            return Err(ElfModuleError::Truncated("elf32 header"));
        }
        let le = match encoding {
            1 => true,
            2 => false,
            e => return Err(ElfModuleError::UnsupportedEncoding(e)),
        };

        let elf_type = ElfType::from_u16(Self::read_u16(data, 16, le)?);
        let machine = ElfMachine::from_u16(Self::read_u16(data, 18, le)?);
        let entry = u64::from(Self::read_u32(data, 24, le)?);
        let phoff = Self::read_u32(data, 28, le)? as usize;
        let shoff = Self::read_u32(data, 32, le)? as usize;
        let phentsize = Self::read_u16(data, 42, le)? as usize;
        let phnum = Self::read_u16(data, 44, le)? as usize;
        let shentsize = Self::read_u16(data, 46, le)? as usize;
        let shnum = Self::read_u16(data, 48, le)? as usize;
        let shstrndx = Self::read_u16(data, 50, le)? as usize;

        // Parse section headers
        let shstrtab_off = if shstrndx < shnum && shoff != 0 && shentsize >= 40 {
            let sh = shstrndx
                .checked_mul(shentsize)
                .and_then(|off| shoff.checked_add(off));
            match sh {
                Some(sh) if sh.checked_add(40).is_some_and(|end| end <= data.len()) => {
                    Self::read_u32(data, sh + 16, le)? as usize
                }
                _ => 0,
            }
        } else {
            0
        };

        let mut sections = Vec::with_capacity(shnum);
        for i in 0..shnum {
            let Some(sh) = i.checked_mul(shentsize).and_then(|off| shoff.checked_add(off)) else { break };
            if sh.checked_add(40).is_none_or(|end| end > data.len()) {
                break;
            }
            let name_idx = Self::read_u32(data, sh, le)? as usize;
            let name = if shstrtab_off > 0 {
                match shstrtab_off.checked_add(name_idx) {
                    Some(addr) if addr < data.len() => Self::read_cstr(data, addr),
                    _ => String::new(),
                }
            } else {
                String::new()
            };
            sections.push(ElfSection {
                name,
                section_type: SectionType::from_u32(Self::read_u32(data, sh + 4, le)?),
                flags: u64::from(Self::read_u32(data, sh + 8, le)?),
                address: u64::from(Self::read_u32(data, sh + 12, le)?),
                offset: u64::from(Self::read_u32(data, sh + 16, le)?),
                size: u64::from(Self::read_u32(data, sh + 20, le)?),
                link: Self::read_u32(data, sh + 24, le)?,
                info: Self::read_u32(data, sh + 28, le)?,
                align: u64::from(Self::read_u32(data, sh + 32, le)?),
                entry_size: u64::from(Self::read_u32(data, sh + 36, le)?),
            });
        }

        // Parse program headers
        let mut segments = Vec::with_capacity(phnum);
        for i in 0..phnum {
            let Some(ph) = i.checked_mul(phentsize).and_then(|off| phoff.checked_add(off)) else { break };
            if ph + 32 > data.len() {
                break;
            }
            segments.push(ElfSegment {
                segment_type: SegmentType::from_u32(Self::read_u32(data, ph, le)?),
                offset: u64::from(Self::read_u32(data, ph + 4, le)?),
                virtual_address: u64::from(Self::read_u32(data, ph + 8, le)?),
                physical_address: u64::from(Self::read_u32(data, ph + 12, le)?),
                file_size: u64::from(Self::read_u32(data, ph + 16, le)?),
                memory_size: u64::from(Self::read_u32(data, ph + 20, le)?),
                flags: Self::read_u32(data, ph + 24, le)?,
                alignment: u64::from(Self::read_u32(data, ph + 28, le)?),
            });
        }

        Ok(Self {
            elf_type,
            machine,
            entry_point: entry,
            number_of_sections: u32::try_from(shnum).unwrap_or(u32::MAX),
            number_of_segments: u32::try_from(phnum).unwrap_or(u32::MAX),
            sections,
            segments,
            is_64bit: false,
            is_little_endian: le,
        })
    }

    // ── 64-bit parser ─────────────────────────────────────────────────────────

    fn parse_elf64(data: &[u8], encoding: u8) -> ElfResult<Self> {
        if data.len() < 64 {
            return Err(ElfModuleError::Truncated("elf64 header"));
        }
        let le = match encoding {
            1 => true,
            2 => false,
            e => return Err(ElfModuleError::UnsupportedEncoding(e)),
        };

        let elf_type = ElfType::from_u16(Self::read_u16(data, 16, le)?);
        let machine = ElfMachine::from_u16(Self::read_u16(data, 18, le)?);
        let entry = Self::read_u64(data, 24, le)?;
        let phoff = usize::try_from(Self::read_u64(data, 32, le)?).unwrap_or(0);
        let shoff = usize::try_from(Self::read_u64(data, 40, le)?).unwrap_or(0);
        let phentsize = Self::read_u16(data, 54, le)? as usize;
        let phnum = Self::read_u16(data, 56, le)? as usize;
        let shentsize = Self::read_u16(data, 58, le)? as usize;
        let shnum = Self::read_u16(data, 60, le)? as usize;
        let shstrndx = Self::read_u16(data, 62, le)? as usize;

        let shstrtab_off = if shstrndx < shnum && shoff != 0 && shentsize >= 64 {
            let sh = shstrndx
                .checked_mul(shentsize)
                .and_then(|off| shoff.checked_add(off)).unwrap_or_default();
            if sh != 0 && sh + 64 <= data.len() {
                usize::try_from(Self::read_u64(data, sh + 24, le)?).unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        };

        let mut sections = Vec::with_capacity(shnum);
        for i in 0..shnum {
            let Some(sh) = i.checked_mul(shentsize).and_then(|off| shoff.checked_add(off)) else { break };
            if sh + 64 > data.len() {
                break;
            }
            let name_idx = Self::read_u32(data, sh, le)? as usize;
            let name = if shstrtab_off > 0 {
                match shstrtab_off.checked_add(name_idx) {
                    Some(addr) if addr < data.len() => Self::read_cstr(data, addr),
                    _ => String::new(),
                }
            } else {
                String::new()
            };
            sections.push(ElfSection {
                name,
                section_type: SectionType::from_u32(Self::read_u32(data, sh + 4, le)?),
                flags: Self::read_u64(data, sh + 8, le)?,
                address: Self::read_u64(data, sh + 16, le)?,
                offset: Self::read_u64(data, sh + 24, le)?,
                size: Self::read_u64(data, sh + 32, le)?,
                link: Self::read_u32(data, sh + 40, le)?,
                info: Self::read_u32(data, sh + 44, le)?,
                align: Self::read_u64(data, sh + 48, le)?,
                entry_size: Self::read_u64(data, sh + 56, le)?,
            });
        }

        let mut segments = Vec::with_capacity(phnum);
        for i in 0..phnum {
            let Some(ph) = i.checked_mul(phentsize).and_then(|off| phoff.checked_add(off)) else { break };
            if ph + 56 > data.len() {
                break;
            }
            segments.push(ElfSegment {
                segment_type: SegmentType::from_u32(Self::read_u32(data, ph, le)?),
                flags: Self::read_u32(data, ph + 4, le)?,
                offset: Self::read_u64(data, ph + 8, le)?,
                virtual_address: Self::read_u64(data, ph + 16, le)?,
                physical_address: Self::read_u64(data, ph + 24, le)?,
                file_size: Self::read_u64(data, ph + 32, le)?,
                memory_size: Self::read_u64(data, ph + 40, le)?,
                alignment: Self::read_u64(data, ph + 48, le)?,
            });
        }

        Ok(Self {
            elf_type,
            machine,
            entry_point: entry,
            number_of_sections: u32::try_from(shnum).unwrap_or(u32::MAX),
            number_of_segments: u32::try_from(phnum).unwrap_or(u32::MAX),
            sections,
            segments,
            is_64bit: true,
            is_little_endian: le,
        })
    }

    // ── Query helpers (mirror libyara elf module API) ─────────────────────────

    /// Find a section by name.
    #[must_use] 
    pub fn section_by_name(&self, name: &str) -> Option<&ElfSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Find all sections with a given type.
    #[must_use] 
    pub fn sections_of_type(&self, t: SectionType) -> Vec<&ElfSection> {
        self.sections
            .iter()
            .filter(|s| s.section_type == t)
            .collect()
    }

    /// Find all LOAD segments.
    #[must_use] 
    pub fn load_segments(&self) -> Vec<&ElfSegment> {
        self.segments
            .iter()
            .filter(|s| s.segment_type == SegmentType::Load)
            .collect()
    }

    /// Check whether the binary has a `.dynamic` section.
    #[must_use] 
    pub fn is_dynamically_linked(&self) -> bool {
        self.sections.iter().any(|s| s.name == ".dynamic")
            || self
                .segments
                .iter()
                .any(|s| s.segment_type == SegmentType::Dynamic)
    }

    /// Collect section names into a `HashMap<name, index>`.
    #[must_use] 
    pub fn section_name_index(&self) -> HashMap<&str, usize> {
        self.sections
            .iter()
            .enumerate()
            .map(|(i, s)| (s.name.as_str(), i))
            .collect()
    }
}

// ── Minimal ELF builder for tests ────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ELF32 LE executable with no sections and no segments.
    fn minimal_elf32() -> Vec<u8> {
        let mut e = vec![0u8; 52];
        e[0..4].copy_from_slice(b"\x7fELF");
        e[4] = 1; // ELFCLASS32
        e[5] = 1; // ELFDATA2LSB
        e[6] = 1; // EV_CURRENT
        // e_type = ET_EXEC
        e[16] = 2;
        e[17] = 0;
        // e_machine = EM_386
        e[18] = 3;
        e[19] = 0;
        // e_version = 1
        e[20] = 1;
        // e_entry = 0x08048000
        e[24..28].copy_from_slice(&0x0804_8000u32.to_le_bytes());
        // e_ehsize = 52
        e[40..42].copy_from_slice(&52u16.to_le_bytes());
        e
    }

    /// Build a minimal ELF64 LE executable.
    fn minimal_elf64() -> Vec<u8> {
        let mut e = vec![0u8; 64];
        e[0..4].copy_from_slice(b"\x7fELF");
        e[4] = 2; // ELFCLASS64
        e[5] = 1; // ELFDATA2LSB
        e[6] = 1;
        e[16] = 2;
        e[17] = 0; // ET_EXEC
        e[18] = 62;
        e[19] = 0; // EM_X86_64
        e[20] = 1;
        // e_entry = 0x400000
        e[24..32].copy_from_slice(&0x0000_0000_0040_0000u64.to_le_bytes());
        e[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        e
    }

    #[test]
    fn test_bad_magic() {
        let data = b"NOTELF\0\0\0\0\0\0\0\0\0\0";
        assert!(matches!(YaraModuleElf::parse(data), Err(ElfModuleError::BadMagic)));
    }

    #[test]
    fn test_too_short() {
        assert!(matches!(
            YaraModuleElf::parse(b"\x7fELF"),
            Err(ElfModuleError::TooShort)
        ));
    }

    #[test]
    fn test_unsupported_class() {
        let mut d = minimal_elf32();
        d[4] = 5; // unknown class
        assert!(matches!(
            YaraModuleElf::parse(&d),
            Err(ElfModuleError::UnsupportedClass(5))
        ));
    }

    #[test]
    fn test_elf32_parse_type() {
        let m = YaraModuleElf::parse(&minimal_elf32()).unwrap();
        assert_eq!(m.elf_type, ElfType::Exec);
        assert!(!m.is_64bit);
    }

    #[test]
    fn test_elf32_parse_machine() {
        let m = YaraModuleElf::parse(&minimal_elf32()).unwrap();
        assert_eq!(m.machine, ElfMachine::I386);
    }

    #[test]
    fn test_elf32_entry_point() {
        let m = YaraModuleElf::parse(&minimal_elf32()).unwrap();
        assert_eq!(m.entry_point, 0x0804_8000);
    }

    #[test]
    fn test_elf64_parse() {
        let m = YaraModuleElf::parse(&minimal_elf64()).unwrap();
        assert_eq!(m.machine, ElfMachine::X86_64);
        assert!(m.is_64bit);
        assert_eq!(m.entry_point, 0x40_0000);
    }

    #[test]
    fn test_elf64_is_little_endian() {
        let m = YaraModuleElf::parse(&minimal_elf64()).unwrap();
        assert!(m.is_little_endian);
    }

    #[test]
    fn test_number_of_sections_zero() {
        let m = YaraModuleElf::parse(&minimal_elf32()).unwrap();
        assert_eq!(m.number_of_sections, 0);
    }

    #[test]
    fn test_number_of_segments_zero() {
        let m = YaraModuleElf::parse(&minimal_elf32()).unwrap();
        assert_eq!(m.number_of_segments, 0);
    }

    #[test]
    fn test_elf_type_roundtrip() {
        for t in [
            ElfType::None,
            ElfType::Rel,
            ElfType::Exec,
            ElfType::Dyn,
            ElfType::Core,
            ElfType::Unknown(0xFFFF),
        ] {
            assert_eq!(ElfType::from_u16(t.as_u16()), t);
        }
    }

    #[test]
    fn test_elf_machine_roundtrip() {
        for m in [
            ElfMachine::I386,
            ElfMachine::X86_64,
            ElfMachine::Aarch64,
            ElfMachine::RiscV,
        ] {
            assert_eq!(ElfMachine::from_u16(m.as_u16()), m);
        }
    }

    #[test]
    fn test_section_type_roundtrip() {
        for t in [
            SectionType::ProgBits,
            SectionType::StrTab,
            SectionType::Dynamic,
        ] {
            assert_eq!(SectionType::from_u32(t.as_u32()), t);
        }
    }

    #[test]
    fn test_section_by_name_not_found() {
        let m = YaraModuleElf::parse(&minimal_elf64()).unwrap();
        assert!(m.section_by_name(".text").is_none());
    }

    #[test]
    fn test_load_segments_empty() {
        let m = YaraModuleElf::parse(&minimal_elf64()).unwrap();
        assert!(m.load_segments().is_empty());
    }

    #[test]
    fn test_is_dynamically_linked_false() {
        let m = YaraModuleElf::parse(&minimal_elf64()).unwrap();
        assert!(!m.is_dynamically_linked());
    }

    #[test]
    fn test_sections_of_type_empty() {
        let m = YaraModuleElf::parse(&minimal_elf64()).unwrap();
        assert!(m.sections_of_type(SectionType::ProgBits).is_empty());
    }

    #[test]
    fn test_segment_type_from_u32_gnu_stack() {
        assert_eq!(SegmentType::from_u32(0x6474_E551), SegmentType::GnuStack);
    }

    #[test]
    fn test_big_endian_elf32() {
        let mut e = minimal_elf32();
        e[5] = 2; // ELFDATA2MSB
        // Fix entry point to big-endian
        e[24..28].copy_from_slice(&0x0804_8000u32.to_be_bytes());
        let m = YaraModuleElf::parse(&e).unwrap();
        assert!(!m.is_little_endian);
        assert_eq!(m.entry_point, 0x0804_8000);
    }
}
