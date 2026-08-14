//! ELF section header (Shdr) parsing — all SHT_* and SHF_* constants.

// ---------------------------------------------------------------------------
// SHT_* section type constants
// ---------------------------------------------------------------------------

pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_SHLIB: u32 = 10;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;
pub const SHT_PREINIT_ARRAY: u32 = 16;
pub const SHT_GROUP: u32 = 17;
pub const SHT_SYMTAB_SHNDX: u32 = 18;
pub const SHT_RELR: u32 = 19;
pub const SHT_LOOS: u32 = 0x6000_0000;
pub const SHT_GNU_ATTRIBUTES: u32 = 0x6FFF_FFF5;
pub const SHT_GNU_HASH: u32 = 0x6FFF_FFF6;
pub const SHT_GNU_LIBLIST: u32 = 0x6FFF_FFF7;
pub const SHT_CHECKSUM: u32 = 0x6FFF_FFF8;
pub const SHT_GNU_VERDEF: u32 = 0x6FFF_FFFD;
pub const SHT_GNU_VERNEED: u32 = 0x6FFF_FFFE;
pub const SHT_GNU_VERSYM: u32 = 0x6FFF_FFFF;
pub const SHT_HIOS: u32 = 0x6FFF_FFFF;
pub const SHT_LOPROC: u32 = 0x7000_0000;
pub const SHT_ARM_EXIDX: u32 = 0x7000_0001;
pub const SHT_ARM_PREEMPTMAP: u32 = 0x7000_0002;
pub const SHT_ARM_ATTRIBUTES: u32 = 0x7000_0003;
pub const SHT_ARM_DEBUGOVERLAY: u32 = 0x7000_0004;
pub const SHT_ARM_OVERLAYSECTION: u32 = 0x7000_0005;
pub const SHT_MIPS_REGINFO: u32 = 0x7000_0006;
pub const SHT_MIPS_OPTIONS: u32 = 0x7000_000D;
pub const SHT_MIPS_ABIFLAGS: u32 = 0x7000_002A;
pub const SHT_X86_64_UNWIND: u32 = 0x7000_0001;
pub const SHT_HIPROC: u32 = 0x7FFF_FFFF;
pub const SHT_LOUSER: u32 = 0x8000_0000;
pub const SHT_HIUSER: u32 = 0xFFFF_FFFF;

/// Human-readable section type name.
#[must_use]
pub fn section_type_name(t: u32) -> &'static str {
    match t {
        SHT_NULL => "SHT_NULL",
        SHT_PROGBITS => "SHT_PROGBITS",
        SHT_SYMTAB => "SHT_SYMTAB",
        SHT_STRTAB => "SHT_STRTAB",
        SHT_RELA => "SHT_RELA",
        SHT_HASH => "SHT_HASH",
        SHT_DYNAMIC => "SHT_DYNAMIC",
        SHT_NOTE => "SHT_NOTE",
        SHT_NOBITS => "SHT_NOBITS",
        SHT_REL => "SHT_REL",
        SHT_SHLIB => "SHT_SHLIB",
        SHT_DYNSYM => "SHT_DYNSYM",
        SHT_INIT_ARRAY => "SHT_INIT_ARRAY",
        SHT_FINI_ARRAY => "SHT_FINI_ARRAY",
        SHT_PREINIT_ARRAY => "SHT_PREINIT_ARRAY",
        SHT_GROUP => "SHT_GROUP",
        SHT_SYMTAB_SHNDX => "SHT_SYMTAB_SHNDX",
        SHT_RELR => "SHT_RELR",
        SHT_GNU_HASH => "SHT_GNU_HASH",
        SHT_GNU_VERDEF => "SHT_GNU_VERDEF",
        SHT_GNU_VERNEED => "SHT_GNU_VERNEED",
        SHT_GNU_VERSYM => "SHT_GNU_VERSYM",
        SHT_ARM_EXIDX => "SHT_ARM_EXIDX",
        SHT_ARM_ATTRIBUTES => "SHT_ARM_ATTRIBUTES",
        SHT_MIPS_REGINFO => "SHT_MIPS_REGINFO",
        SHT_MIPS_OPTIONS => "SHT_MIPS_OPTIONS",
        _ if (SHT_LOPROC..=SHT_HIPROC).contains(&t) => "SHT_LOPROC..HIPROC (arch-specific)",
        _ if (SHT_LOOS..=SHT_HIOS).contains(&t) => "SHT_LOOS..HIOS (OS-specific)",
        _ if t >= SHT_LOUSER => "SHT_LOUSER..HIUSER (application)",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// SHF_* section flag constants
// ---------------------------------------------------------------------------

pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_MERGE: u64 = 0x10;
pub const SHF_STRINGS: u64 = 0x20;
pub const SHF_INFO_LINK: u64 = 0x40;
pub const SHF_LINK_ORDER: u64 = 0x80;
pub const SHF_OS_NONCONFORMING: u64 = 0x100;
pub const SHF_GROUP: u64 = 0x200;
pub const SHF_TLS: u64 = 0x400;
pub const SHF_COMPRESSED: u64 = 0x800;
pub const SHF_GNU_RETAIN: u64 = 0x0020_0000;
pub const SHF_EXCLUDE: u64 = 0x8000_0000;
pub const SHF_MASKOS: u64 = 0x0FF0_0000;
pub const SHF_MASKPROC: u64 = 0xF000_0000;
pub const SHF_ARM_ENTRYSECT: u64 = 0x1000_0000;
pub const SHF_ARM_COMDEF: u64 = 0x8000_0000;
pub const SHF_MIPS_GPREL: u64 = 0x1000_0000;
pub const SHF_MIPS_MERGE: u64 = 0x2000_0000;
pub const SHF_MIPS_ADDR: u64 = 0x4000_0000;
pub const SHF_MIPS_STRINGS: u64 = 0x8000_0000;

/// Format SHF_* flags as a human-readable string.
#[must_use]
pub fn format_section_flags(flags: u64) -> String {
    let mut s = String::new();
    if flags & SHF_WRITE != 0 {
        s.push('W');
    }
    if flags & SHF_ALLOC != 0 {
        s.push('A');
    }
    if flags & SHF_EXECINSTR != 0 {
        s.push('X');
    }
    if flags & SHF_MERGE != 0 {
        s.push('M');
    }
    if flags & SHF_STRINGS != 0 {
        s.push('S');
    }
    if flags & SHF_INFO_LINK != 0 {
        s.push('I');
    }
    if flags & SHF_LINK_ORDER != 0 {
        s.push('L');
    }
    if flags & SHF_OS_NONCONFORMING != 0 {
        s.push('O');
    }
    if flags & SHF_GROUP != 0 {
        s.push('G');
    }
    if flags & SHF_TLS != 0 {
        s.push('T');
    }
    if flags & SHF_COMPRESSED != 0 {
        s.push('C');
    }
    if s.is_empty() {
        s.push_str("(none)");
    }
    s
}

// ---------------------------------------------------------------------------
// Special section indices
// ---------------------------------------------------------------------------

pub const SHN_UNDEF: u16 = 0;
pub const SHN_LORESERVE: u16 = 0xFF00;
pub const SHN_LOPROC: u16 = 0xFF00;
pub const SHN_BEFORE: u16 = 0xFF00;
pub const SHN_AFTER: u16 = 0xFF01;
pub const SHN_HIPROC: u16 = 0xFF1F;
pub const SHN_LOOS: u16 = 0xFF20;
pub const SHN_HIOS: u16 = 0xFF3F;
pub const SHN_ABS: u16 = 0xFFF1;
pub const SHN_COMMON: u16 = 0xFFF2;
pub const SHN_XINDEX: u16 = 0xFFFF;
pub const SHN_HIRESERVE: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// Raw Shdr32 / Shdr64
// ---------------------------------------------------------------------------

/// Raw 32-bit ELF section header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shdr32 {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u32,
    pub sh_addr: u32,
    pub sh_offset: u32,
    pub sh_size: u32,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u32,
    pub sh_entsize: u32,
}

impl Shdr32 {
    pub const SIZE: usize = 40;

    /// # Errors
    /// Returns an error string if the data is too short at the given offset.
    pub fn parse(data: &[u8], offset: usize, le: bool) -> Result<Self, String> {
        if offset + Self::SIZE > data.len() {
            return Err(format!("Shdr32 truncated at {offset:#x}"));
        }
        let r32 = |off: usize| -> u32 {
            let b: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0; 4]);
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let b = offset;
        Ok(Self {
            sh_name: r32(b),
            sh_type: r32(b + 4),
            sh_flags: r32(b + 8),
            sh_addr: r32(b + 12),
            sh_offset: r32(b + 16),
            sh_size: r32(b + 20),
            sh_link: r32(b + 24),
            sh_info: r32(b + 28),
            sh_addralign: r32(b + 32),
            sh_entsize: r32(b + 36),
        })
    }

    #[must_use] 
    pub fn parse_all(
        data: &[u8],
        e_shoff: u32,
        e_shentsize: u16,
        e_shnum: u16,
        le: bool,
    ) -> Vec<Self> {
        let step = e_shentsize as usize;
        let base = e_shoff as usize;
        (0..e_shnum as usize)
            .filter_map(|i| {
                let off = i.checked_mul(step).and_then(|d| base.checked_add(d))?;
                Self::parse(data, off, le).ok()
            })
            .collect()
    }
}

/// Raw 64-bit ELF section header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shdr64 {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

impl Shdr64 {
    pub const SIZE: usize = 64;

    /// # Errors
    /// Returns an error string if the data is too short at the given offset.
    pub fn parse(data: &[u8], offset: usize, le: bool) -> Result<Self, String> {
        if offset + Self::SIZE > data.len() {
            return Err(format!("Shdr64 truncated at {offset:#x}"));
        }
        let r32 = |off: usize| -> u32 {
            let b: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0; 4]);
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let r64 = |off: usize| -> u64 {
            let b: [u8; 8] = data[off..off + 8].try_into().unwrap_or([0; 8]);
            if le {
                u64::from_le_bytes(b)
            } else {
                u64::from_be_bytes(b)
            }
        };
        let b = offset;
        Ok(Self {
            sh_name: r32(b),
            sh_type: r32(b + 4),
            sh_flags: r64(b + 8),
            sh_addr: r64(b + 16),
            sh_offset: r64(b + 24),
            sh_size: r64(b + 32),
            sh_link: r32(b + 40),
            sh_info: r32(b + 44),
            sh_addralign: r64(b + 48),
            sh_entsize: r64(b + 56),
        })
    }

    #[must_use] 
    pub fn parse_all(
        data: &[u8],
        e_shoff: u64,
        e_shentsize: u16,
        e_shnum: u16,
        le: bool,
    ) -> Vec<Self> {
        let step = e_shentsize as usize;
        let Ok(base) = usize::try_from(e_shoff) else { return Vec::new() };
        (0..e_shnum as usize)
            .filter_map(|i| {
                let off = i.checked_mul(step).and_then(|d| base.checked_add(d))?;
                Self::parse(data, off, le).ok()
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// String table lookup
// ---------------------------------------------------------------------------

/// Look up a null-terminated string at `offset` in a string table blob.
#[must_use]
pub fn strtab_get(strtab: &[u8], offset: usize) -> &str {
    if offset >= strtab.len() {
        return "";
    }
    let slice = &strtab[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    std::str::from_utf8(&slice[..end]).unwrap_or("")
}

/// Extract the section name string table from ELF data.
///
/// `shstrndx` is the section header index of the name string table.
#[must_use] 
pub fn get_section_name_table<'a>(data: &'a [u8], shdrs32: &[Shdr32], shstrndx: u16) -> &'a [u8] {
    let idx = shstrndx as usize;
    if idx >= shdrs32.len() {
        return &[];
    }
    let sh = &shdrs32[idx];
    let off = usize::try_from(sh.sh_offset).unwrap_or(usize::MAX);
    let sz = usize::try_from(sh.sh_size).unwrap_or(usize::MAX);
    match off.checked_add(sz) {
        Some(end) if end <= data.len() => &data[off..end],
        _ => &[],
    }
}

/// Extract the section name string table from 64-bit ELF data.
#[must_use] 
pub fn get_section_name_table64<'a>(data: &'a [u8], shdrs64: &[Shdr64], shstrndx: u16) -> &'a [u8] {
    let idx = shstrndx as usize;
    if idx >= shdrs64.len() {
        return &[];
    }
    let sh = &shdrs64[idx];
    let off = usize::try_from(sh.sh_offset).unwrap_or(usize::MAX);
    let sz = usize::try_from(sh.sh_size).unwrap_or(usize::MAX);
    if off + sz <= data.len() {
        &data[off..off + sz]
    } else {
        &[]
    }
}

// ---------------------------------------------------------------------------
// High-level ELF section
// ---------------------------------------------------------------------------

/// Normalized ELF section with resolved name.
#[derive(Debug, Clone)]
pub struct ElfSection {
    /// Resolved section name (from shstrtab).
    pub name: String,
    /// `sh_type` (SHT_*).
    pub section_type: u32,
    /// `sh_flags` (SHF_*).
    pub flags: u64,
    /// `sh_addr` — virtual address.
    pub addr: u64,
    /// `sh_offset` — file offset.
    pub offset: u64,
    /// `sh_size` — size in bytes.
    pub size: u64,
    /// `sh_link` — section link index.
    pub link: u32,
    /// `sh_info` — extra info.
    pub info: u32,
    /// `sh_addralign` — alignment.
    pub addralign: u64,
    /// `sh_entsize` — entry size (for tables).
    pub entsize: u64,
}

impl ElfSection {
    #[must_use]
    pub const fn from_shdr32(sh: &Shdr32, name: String) -> Self {
        Self {
            name,
            section_type: sh.sh_type,
            flags: sh.sh_flags as u64,
            addr: sh.sh_addr as u64,
            offset: sh.sh_offset as u64,
            size: sh.sh_size as u64,
            link: sh.sh_link,
            info: sh.sh_info,
            addralign: sh.sh_addralign as u64,
            entsize: sh.sh_entsize as u64,
        }
    }

    #[must_use]
    pub const fn from_shdr64(sh: &Shdr64, name: String) -> Self {
        Self {
            name,
            section_type: sh.sh_type,
            flags: sh.sh_flags,
            addr: sh.sh_addr,
            offset: sh.sh_offset,
            size: sh.sh_size,
            link: sh.sh_link,
            info: sh.sh_info,
            addralign: sh.sh_addralign,
            entsize: sh.sh_entsize,
        }
    }

    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.flags & SHF_EXECINSTR != 0
    }
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.flags & SHF_WRITE != 0
    }
    #[must_use]
    pub const fn is_allocated(&self) -> bool {
        self.flags & SHF_ALLOC != 0
    }
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        self.flags & SHF_TLS != 0
    }
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.flags & SHF_COMPRESSED != 0
    }
    #[must_use]
    pub const fn is_bss(&self) -> bool {
        self.section_type == SHT_NOBITS
    }

    /// Returns the end virtual address of the section.
    ///
    /// A section with `sh_addr == 0` is not assigned a virtual memory location
    /// (e.g. non-`SHF_ALLOC` sections or sections in relocatable objects), so it
    /// has no meaningful end address and this returns 0.
    #[must_use]
    pub const fn addr_end(&self) -> u64 {
        if self.addr == 0 {
            0
        } else {
            self.addr.saturating_add(self.size)
        }
    }

    /// Type name string.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        section_type_name(self.section_type)
    }
}

/// Build a list of high-level sections from raw 32-bit shdrs and name table.
#[must_use] 
pub fn build_sections32(shdrs: &[Shdr32], strtab: &[u8]) -> Vec<ElfSection> {
    shdrs
        .iter()
        .map(|sh| {
            let name = strtab_get(strtab, sh.sh_name as usize).to_string();
            ElfSection::from_shdr32(sh, name)
        })
        .collect()
}

/// Build a list of high-level sections from raw 64-bit shdrs and name table.
#[must_use] 
pub fn build_sections64(shdrs: &[Shdr64], strtab: &[u8]) -> Vec<ElfSection> {
    shdrs
        .iter()
        .map(|sh| {
            let name = strtab_get(strtab, sh.sh_name as usize).to_string();
            ElfSection::from_shdr64(sh, name)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_shdr32(
        sh_type: u32,
        sh_flags: u32,
        sh_offset: u32,
        sh_size: u32,
        sh_name: u32,
    ) -> Vec<u8> {
        let mut b = vec![0u8; 40];
        b[0..4].copy_from_slice(&sh_name.to_le_bytes());
        b[4..8].copy_from_slice(&sh_type.to_le_bytes());
        b[8..12].copy_from_slice(&sh_flags.to_le_bytes());
        b[12..16].copy_from_slice(&0u32.to_le_bytes()); // addr
        b[16..20].copy_from_slice(&sh_offset.to_le_bytes());
        b[20..24].copy_from_slice(&sh_size.to_le_bytes());
        b
    }

    fn make_shdr64(
        sh_type: u32,
        sh_flags: u64,
        sh_offset: u64,
        sh_size: u64,
        sh_name: u32,
    ) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[0..4].copy_from_slice(&sh_name.to_le_bytes());
        b[4..8].copy_from_slice(&sh_type.to_le_bytes());
        b[8..16].copy_from_slice(&sh_flags.to_le_bytes());
        b[16..24].copy_from_slice(&0u64.to_le_bytes()); // addr
        b[24..32].copy_from_slice(&sh_offset.to_le_bytes());
        b[32..40].copy_from_slice(&sh_size.to_le_bytes());
        b
    }

    #[test]
    fn test_parse_shdr32() {
        let b = make_shdr32(
            SHT_PROGBITS,
            (SHF_ALLOC | SHF_EXECINSTR) as u32,
            0x1000,
            0x500,
            1,
        );
        let sh = Shdr32::parse(&b, 0, true).unwrap();
        assert_eq!(sh.sh_type, SHT_PROGBITS);
        assert_eq!(sh.sh_flags & SHF_EXECINSTR as u32, SHF_EXECINSTR as u32);
    }

    #[test]
    fn test_parse_shdr64() {
        let b = make_shdr64(SHT_DYNSYM, SHF_ALLOC, 0x2000, 0x100, 5);
        let sh = Shdr64::parse(&b, 0, true).unwrap();
        assert_eq!(sh.sh_type, SHT_DYNSYM);
        assert_eq!(sh.sh_size, 0x100);
    }

    #[test]
    fn test_section_type_name() {
        assert_eq!(section_type_name(SHT_PROGBITS), "SHT_PROGBITS");
        assert_eq!(section_type_name(SHT_DYNSYM), "SHT_DYNSYM");
        assert_eq!(section_type_name(SHT_GNU_HASH), "SHT_GNU_HASH");
        assert_eq!(section_type_name(SHT_ARM_EXIDX), "SHT_ARM_EXIDX");
        assert_eq!(
            section_type_name(0x7F00_0099),
            "SHT_LOPROC..HIPROC (arch-specific)"
        );
    }

    #[test]
    fn test_format_section_flags() {
        let f = format_section_flags(SHF_ALLOC | SHF_EXECINSTR);
        assert!(f.contains('A'));
        assert!(f.contains('X'));
        assert!(!f.contains('W'));
    }

    #[test]
    fn test_format_section_flags_empty() {
        let f = format_section_flags(0);
        assert_eq!(f, "(none)");
    }

    #[test]
    fn test_strtab_get() {
        let strtab = b"\0.text\0.data\0";
        assert_eq!(strtab_get(strtab, 1), ".text");
        assert_eq!(strtab_get(strtab, 7), ".data");
        assert_eq!(strtab_get(strtab, 0), "");
        assert_eq!(strtab_get(strtab, 999), "");
    }

    #[test]
    fn test_elf_section_from_shdr32() {
        let b = make_shdr32(
            SHT_PROGBITS,
            (SHF_ALLOC | SHF_EXECINSTR) as u32,
            0x1000,
            0x500,
            1,
        );
        let sh = Shdr32::parse(&b, 0, true).unwrap();
        let sec = ElfSection::from_shdr32(&sh, ".text".into());
        assert_eq!(sec.name, ".text");
        assert!(sec.is_executable());
        assert!(sec.is_allocated());
        assert!(!sec.is_writable());
        assert!(!sec.is_bss());
        assert_eq!(sec.addr_end(), 0);
    }

    #[test]
    fn test_elf_section_bss() {
        let b = make_shdr32(SHT_NOBITS, (SHF_ALLOC | SHF_WRITE) as u32, 0, 0x200, 1);
        let sh = Shdr32::parse(&b, 0, true).unwrap();
        let sec = ElfSection::from_shdr32(&sh, ".bss".into());
        assert!(sec.is_bss());
        assert!(sec.is_writable());
    }

    #[test]
    fn test_build_sections32() {
        let strtab = b"\0.text\0.bss\0";
        let b1 = make_shdr32(
            SHT_PROGBITS,
            (SHF_ALLOC | SHF_EXECINSTR) as u32,
            0x1000,
            0x200,
            1,
        );
        let b2 = make_shdr32(SHT_NOBITS, (SHF_ALLOC | SHF_WRITE) as u32, 0, 0x100, 7);
        let sh1 = Shdr32::parse(&b1, 0, true).unwrap();
        let sh2 = Shdr32::parse(&b2, 0, true).unwrap();
        let sections = build_sections32(&[sh1, sh2], strtab);
        assert_eq!(sections[0].name, ".text");
        assert_eq!(sections[1].name, ".bss");
    }

    #[test]
    fn test_shdr32_truncated() {
        assert!(Shdr32::parse(&[0u8; 10], 0, true).is_err());
    }

    #[test]
    fn test_shdr64_truncated() {
        assert!(Shdr64::parse(&[0u8; 10], 0, true).is_err());
    }

    #[test]
    fn test_elf_section_tls() {
        let b = make_shdr64(SHT_PROGBITS, SHF_ALLOC | SHF_TLS, 0x3000, 0x10, 1);
        let sh = Shdr64::parse(&b, 0, true).unwrap();
        let sec = ElfSection::from_shdr64(&sh, ".tdata".into());
        assert!(sec.is_tls());
    }
}
