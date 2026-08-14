//! YARA ELF module implementation.
//!
//! Parses ELF32 and ELF64 binaries and exposes their structure to YARA
//! condition expressions.  Provides the same interface as the official
//! libyara `elf` module.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// ELF constants
// ---------------------------------------------------------------------------

const ELFMAG: &[u8; 4] = b"\x7FELF";
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1; // little-endian
const ELFDATA2MSB: u8 = 2; // big-endian

// ELF section types
const SHT_NULL:     u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB:   u32 = 2;
const SHT_STRTAB:   u32 = 3;
const SHT_DYNAMIC:  u32 = 6;
const SHT_DYNSYM:   u32 = 11;

// ELF segment types
const PT_LOAD:    u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP:  u32 = 3;

// ELF dynamic tags
const DT_NULL:    i64 = 0;
const DT_NEEDED:  i64 = 1;
const DT_STRTAB:  i64 = 5;
const DT_SYMTAB:  i64 = 6;
const DT_STRSZ:   i64 = 10;
const DT_SONAME:  i64 = 14;
const DT_RPATH:   i64 = 15;

// Symbol types
const STT_NOTYPE:  u8 = 0;
const STT_OBJECT:  u8 = 1;
const STT_FUNC:    u8 = 2;
const STT_SECTION: u8 = 3;
const STT_FILE:    u8 = 4;

// Symbol binding
const STB_LOCAL:  u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK:   u8 = 2;

// Symbol visibility
const STV_DEFAULT:   u8 = 0;
const STV_INTERNAL:  u8 = 1;
const STV_HIDDEN:    u8 = 2;
const STV_PROTECTED: u8 = 3;

// ---------------------------------------------------------------------------
// Section info
// ---------------------------------------------------------------------------

/// Parsed ELF section header.
#[derive(Debug, Clone)]
pub struct ElfSectionInfo {
    pub name: String,
    pub type_: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
}

// ---------------------------------------------------------------------------
// Segment info
// ---------------------------------------------------------------------------

/// Parsed ELF program header (segment).
#[derive(Debug, Clone)]
pub struct ElfSegmentInfo {
    pub type_: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

// ---------------------------------------------------------------------------
// Symbol info
// ---------------------------------------------------------------------------

/// Parsed ELF symbol table entry.
#[derive(Debug, Clone)]
pub struct ElfSymbolInfo {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub type_: u8,
    pub binding: u8,
    pub visibility: u8,
    pub shndx: u16,
}

impl ElfSymbolInfo {
    #[must_use] 
    pub const fn is_global(&self) -> bool { self.binding == STB_GLOBAL }
    #[must_use] 
    pub const fn is_function(&self) -> bool { self.type_ == STT_FUNC }
    #[must_use] 
    pub const fn is_object(&self) -> bool { self.type_ == STT_OBJECT }
    #[must_use] 
    pub const fn is_weak(&self) -> bool { self.binding == STB_WEAK }
    #[must_use] 
    pub const fn is_local(&self) -> bool { self.binding == STB_LOCAL }
}

// ---------------------------------------------------------------------------
// Dynamic entry
// ---------------------------------------------------------------------------

/// One entry from the `.dynamic` section.
#[derive(Debug, Clone)]
pub struct ElfDynEntry {
    pub tag: i64,
    pub value: u64,
}

// ---------------------------------------------------------------------------
// Module data
// ---------------------------------------------------------------------------

/// All data extracted from an ELF binary, mirrors the libyara `elf` module.
#[derive(Debug, Clone, Default)]
pub struct ElfModuleData {
    /// `e_machine` field value.
    pub machine: u16,
    /// `e_type` field value.
    pub type_: u16,
    /// Entry point virtual address.
    pub entry_point: u64,
    /// ELF class: 32 or 64.
    pub class: u8,
    /// Data encoding: 1=LSB, 2=MSB.
    pub data: u8,
    /// `e_flags`
    pub flags: u32,
    pub sections: Vec<ElfSectionInfo>,
    pub segments: Vec<ElfSegmentInfo>,
    pub symbols: Vec<ElfSymbolInfo>,
    pub dynamic: Vec<ElfDynEntry>,
    /// `DT_NEEDED` entries resolved to library names.
    pub imports: Vec<String>,
    /// Exported function names from dynsym.
    pub exports: Vec<String>,
}

// ---------------------------------------------------------------------------
// Parse errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfParseError {
    TooSmall,
    BadMagic,
    UnknownClass(u8),
    UnknownEncoding(u8),
    SectionTableOutOfBounds,
    ProgramTableOutOfBounds,
    StringTableOutOfBounds,
    SymbolTableMalformed,
    DynamicSectionMalformed,
    Custom(String),
}

impl std::fmt::Display for ElfParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooSmall => write!(f, "buffer too small"),
            Self::BadMagic => write!(f, "bad ELF magic"),
            Self::UnknownClass(c) => write!(f, "unknown ELF class: {c}"),
            Self::UnknownEncoding(e) => write!(f, "unknown ELF encoding: {e}"),
            Self::SectionTableOutOfBounds => write!(f, "section header table out of bounds"),
            Self::ProgramTableOutOfBounds => write!(f, "program header table out of bounds"),
            Self::StringTableOutOfBounds => write!(f, "string table out of bounds"),
            Self::SymbolTableMalformed => write!(f, "symbol table malformed"),
            Self::DynamicSectionMalformed => write!(f, "dynamic section malformed"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}
impl std::error::Error for ElfParseError {}

// ---------------------------------------------------------------------------
// Reader helper
// ---------------------------------------------------------------------------

struct Cursor<'a> {
    data: &'a [u8],
    le: bool,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8], le: bool) -> Self { Self { data, le } }

    fn u8_at(&self, off: usize) -> Option<u8> { self.data.get(off).copied() }

    fn u16_at(&self, off: usize) -> Option<u16> {
        let b = self.data.get(off..off + 2)?;
        if self.le { Some(u16::from_le_bytes(b.try_into().unwrap())) }
        else       { Some(u16::from_be_bytes(b.try_into().unwrap())) }
    }

    fn u32_at(&self, off: usize) -> Option<u32> {
        let b = self.data.get(off..off + 4)?;
        if self.le { Some(u32::from_le_bytes(b.try_into().unwrap())) }
        else       { Some(u32::from_be_bytes(b.try_into().unwrap())) }
    }

    fn u64_at(&self, off: usize) -> Option<u64> {
        let b = self.data.get(off..off + 8)?;
        if self.le { Some(u64::from_le_bytes(b.try_into().unwrap())) }
        else       { Some(u64::from_be_bytes(b.try_into().unwrap())) }
    }

    fn i64_at(&self, off: usize) -> Option<i64> {
        Some(self.u64_at(off)?.cast_signed())
    }

    fn str_at(&self, off: usize) -> String {
        let start = off.min(self.data.len());
        let slice = &self.data[start..];
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        String::from_utf8_lossy(&slice[..end]).into_owned()
    }
}

// ---------------------------------------------------------------------------
// ELF32 parser
// ---------------------------------------------------------------------------

/// Parse an ELF32 binary.
///
/// # Errors
///
/// Returns [`ElfParseError`] if the binary is malformed or too small.
pub fn parse_elf32(data: &[u8]) -> Result<ElfModuleData, ElfParseError> {
    if data.len() < 52 { return Err(ElfParseError::TooSmall); }
    if &data[0..4] != ELFMAG { return Err(ElfParseError::BadMagic); }
    let class = data[4];
    if class != ELFCLASS32 { return Err(ElfParseError::UnknownClass(class)); }
    let encoding = data[5];
    if encoding != ELFDATA2LSB && encoding != ELFDATA2MSB {
        return Err(ElfParseError::UnknownEncoding(encoding));
    }
    let le = encoding == ELFDATA2LSB;
    let c = Cursor::new(data, le);
    let type_    = c.u16_at(16).unwrap_or(0);
    let machine  = c.u16_at(18).unwrap_or(0);
    let entry    = u64::from(c.u32_at(24).unwrap_or(0));
    let phoff    = c.u32_at(28).unwrap_or(0) as usize;
    let shoff    = c.u32_at(32).unwrap_or(0) as usize;
    let flags    = c.u32_at(36).unwrap_or(0);
    let phentsize = c.u16_at(42).unwrap_or(32) as usize;
    let phnum    = c.u16_at(44).unwrap_or(0) as usize;
    let shentsize = c.u16_at(46).unwrap_or(40) as usize;
    let shnum    = c.u16_at(48).unwrap_or(0) as usize;
    let shstrndx = c.u16_at(50).unwrap_or(0) as usize;
    if shoff > 0 && shoff + shnum * shentsize > data.len() {
        return Err(ElfParseError::SectionTableOutOfBounds);
    }
    let (sections, so) = parse_elf32_sections(&c, data, le, shoff, shnum, shentsize, shstrndx);
    if phoff > 0 && phoff + phnum * phentsize > data.len() {
        return Err(ElfParseError::ProgramTableOutOfBounds);
    }
    let mut segments = Vec::with_capacity(phnum);
    for i in 0..phnum {
        let base = phoff + i * phentsize;
        if base + phentsize > data.len() { break; }
        segments.push(ElfSegmentInfo {
            type_: c.u32_at(base).unwrap_or(0),
            flags: c.u32_at(base + 24).unwrap_or(0),
            offset: u64::from(c.u32_at(base + 4).unwrap_or(0)),
            vaddr:  u64::from(c.u32_at(base + 8).unwrap_or(0)),
            paddr:  u64::from(c.u32_at(base + 12).unwrap_or(0)),
            filesz: u64::from(c.u32_at(base + 16).unwrap_or(0)),
            memsz:  u64::from(c.u32_at(base + 20).unwrap_or(0)),
            align:  u64::from(c.u32_at(base + 28).unwrap_or(0)),
        });
    }
    let strtab = safe_slice(data, so[0], so[1]);
    let dynstr = safe_slice(data, so[6], so[7]);
    let symbols = parse_symbols32(&c, strtab, so[2], so[3]);
    let dyn_symbols = parse_symbols32(&c, dynstr, so[4], so[5]);
    let exports: Vec<String> = dyn_symbols.iter()
        .filter(|s| s.is_global() && s.is_function() && !s.name.is_empty())
        .map(|s| s.name.clone()).collect();
    let mut all_symbols = symbols;
    all_symbols.extend(dyn_symbols);
    let dynamic = parse_dynamic32(&c, so[8], so[9]);
    let imports = resolve_needed(&dynamic, dynstr);
    Ok(ElfModuleData {
        machine, type_, entry_point: entry, class, data: encoding, flags,
        sections, segments, symbols: all_symbols, dynamic, imports, exports,
    })
}

fn safe_slice(data: &[u8], offset: usize, size: usize) -> &[u8] {
    if offset.saturating_add(size) <= data.len() { &data[offset..offset + size] }
    else { &data[0..0] }
}

/// Returns (sections, \[`strtab_off`, `strtab_sz`, `symtab_off`, `symtab_sz`, `dynsym_off`, `dynsym_sz`, `dynstr_off`, `dynstr_sz`, `dyn_off`, `dyn_sz`\])
fn parse_elf32_sections(
    c: &Cursor<'_>, data: &[u8], le: bool,
    shoff: usize, shnum: usize, shentsize: usize, shstrndx: usize,
) -> (Vec<ElfSectionInfo>, [usize; 10]) {
    let shstr = if shoff > 0 && shstrndx < shnum {
        let shstrtab_hdr = shoff + shstrndx * shentsize;
        let str_off = c.u32_at(shstrtab_hdr + 16).unwrap_or(0) as usize;
        let str_sz  = c.u32_at(shstrtab_hdr + 20).unwrap_or(0) as usize;
        safe_slice(data, str_off, str_sz)
    } else { &data[0..0] };
    let shstr_cursor = Cursor::new(shstr, le);
    let mut sections = Vec::with_capacity(shnum);
    let mut offsets = [0usize; 10];
    for i in 0..shnum {
        let base = shoff + i * shentsize;
        if base + shentsize > data.len() { break; }
        let name_idx = c.u32_at(base).unwrap_or(0) as usize;
        let type_    = c.u32_at(base + 4).unwrap_or(0);
        let flags    = u64::from(c.u32_at(base + 8).unwrap_or(0));
        let addr     = u64::from(c.u32_at(base + 12).unwrap_or(0));
        let offset   = u64::from(c.u32_at(base + 16).unwrap_or(0));
        let size     = u64::from(c.u32_at(base + 20).unwrap_or(0));
        let link     = c.u32_at(base + 24).unwrap_or(0);
        let info     = c.u32_at(base + 28).unwrap_or(0);
        let addralign = u64::from(c.u32_at(base + 32).unwrap_or(0));
        let entsize  = u64::from(c.u32_at(base + 36).unwrap_or(0));
        let name     = shstr_cursor.str_at(name_idx);
        match type_ {
            SHT_STRTAB if name == ".strtab" => { offsets[0] = usize::try_from(offset).unwrap_or(0); offsets[1] = usize::try_from(size).unwrap_or(0); }
            SHT_STRTAB if name == ".dynstr" => { offsets[6] = usize::try_from(offset).unwrap_or(0); offsets[7] = usize::try_from(size).unwrap_or(0); }
            SHT_SYMTAB => { offsets[2] = usize::try_from(offset).unwrap_or(0); offsets[3] = usize::try_from(size).unwrap_or(0); }
            SHT_DYNSYM => { offsets[4] = usize::try_from(offset).unwrap_or(0); offsets[5] = usize::try_from(size).unwrap_or(0); }
            SHT_DYNAMIC => { offsets[8] = usize::try_from(offset).unwrap_or(0); offsets[9] = usize::try_from(size).unwrap_or(0); }
            _ => {}
        }
        sections.push(ElfSectionInfo { name, type_, flags, addr, offset, size, link, info, addralign, entsize });
    }
    (sections, offsets)
}

fn parse_symbols32(c: &Cursor<'_>, strtab: &[u8], offset: usize, size: usize) -> Vec<ElfSymbolInfo> {
    let entry_size = 16usize;
    if size == 0 || offset == 0 { return vec![]; }
    let n = size / entry_size;
    let mut syms = Vec::with_capacity(n);
    let sc = Cursor::new(strtab, c.le);
    for i in 0..n {
        let base = offset + i * entry_size;
        if base + entry_size > c.data.len() { break; }
        let name_idx = c.u32_at(base).unwrap_or(0) as usize;
        let value    = u64::from(c.u32_at(base + 4).unwrap_or(0));
        let size_    = u64::from(c.u32_at(base + 8).unwrap_or(0));
        let info     = c.u8_at(base + 12).unwrap_or(0);
        let other    = c.u8_at(base + 13).unwrap_or(0);
        let shndx    = c.u16_at(base + 14).unwrap_or(0);
        syms.push(ElfSymbolInfo {
            name: sc.str_at(name_idx),
            value, size: size_,
            type_: info & 0xF,
            binding: info >> 4,
            visibility: other & 3,
            shndx,
        });
    }
    syms
}

fn parse_dynamic32(c: &Cursor<'_>, offset: usize, size: usize) -> Vec<ElfDynEntry> {
    let entry_size = 8usize;
    if size == 0 || offset == 0 { return vec![]; }
    let n = size / entry_size;
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let base = offset + i * entry_size;
        if base + entry_size > c.data.len() { break; }
        let tag = i64::from(c.u32_at(base).unwrap_or(0));
        let val = u64::from(c.u32_at(base + 4).unwrap_or(0));
        entries.push(ElfDynEntry { tag, value: val });
        if tag == DT_NULL { break; }
    }
    entries
}

// ---------------------------------------------------------------------------
// ELF64 parser
// ---------------------------------------------------------------------------

/// Parse an ELF64 binary.
///
/// # Errors
///
/// Returns [`ElfParseError`] if the binary is malformed or too small.
pub fn parse_elf64(data: &[u8]) -> Result<ElfModuleData, ElfParseError> {
    if data.len() < 64 { return Err(ElfParseError::TooSmall); }
    if &data[0..4] != ELFMAG { return Err(ElfParseError::BadMagic); }
    let class = data[4];
    if class != ELFCLASS64 { return Err(ElfParseError::UnknownClass(class)); }
    let encoding = data[5];
    if encoding != ELFDATA2LSB && encoding != ELFDATA2MSB {
        return Err(ElfParseError::UnknownEncoding(encoding));
    }
    let le = encoding == ELFDATA2LSB;
    let c = Cursor::new(data, le);
    let type_     = c.u16_at(16).unwrap_or(0);
    let machine   = c.u16_at(18).unwrap_or(0);
    let entry     = c.u64_at(24).unwrap_or(0);
    let phoff     = usize::try_from(c.u64_at(32).unwrap_or(0)).unwrap_or(0);
    let shoff     = usize::try_from(c.u64_at(40).unwrap_or(0)).unwrap_or(0);
    let flags     = c.u32_at(48).unwrap_or(0);
    let phentsize = c.u16_at(54).unwrap_or(56) as usize;
    let phnum     = c.u16_at(56).unwrap_or(0) as usize;
    let shentsize = c.u16_at(58).unwrap_or(64) as usize;
    let shnum     = c.u16_at(60).unwrap_or(0) as usize;
    let shstrndx  = c.u16_at(62).unwrap_or(0) as usize;
    if shoff > 0 && shoff + shnum * shentsize > data.len() {
        return Err(ElfParseError::SectionTableOutOfBounds);
    }
    let (sections, so) = parse_elf64_sections(&c, data, le, shoff, shnum, shentsize, shstrndx);
    if phoff > 0 && phoff + phnum * phentsize > data.len() {
        return Err(ElfParseError::ProgramTableOutOfBounds);
    }
    let mut segments = Vec::with_capacity(phnum);
    for i in 0..phnum {
        let base = phoff + i * phentsize;
        if base + phentsize > data.len() { break; }
        segments.push(ElfSegmentInfo {
            type_:  c.u32_at(base).unwrap_or(0),
            flags:  c.u32_at(base + 4).unwrap_or(0),
            offset: c.u64_at(base + 8).unwrap_or(0),
            vaddr:  c.u64_at(base + 16).unwrap_or(0),
            paddr:  c.u64_at(base + 24).unwrap_or(0),
            filesz: c.u64_at(base + 32).unwrap_or(0),
            memsz:  c.u64_at(base + 40).unwrap_or(0),
            align:  c.u64_at(base + 48).unwrap_or(0),
        });
    }
    let strtab = safe_slice(data, so[0], so[1]);
    let dynstr = safe_slice(data, so[6], so[7]);
    let symbols = parse_symbols64(&c, strtab, so[2], so[3]);
    let dyn_symbols = parse_symbols64(&c, dynstr, so[4], so[5]);
    let exports: Vec<String> = dyn_symbols.iter()
        .filter(|s| s.is_global() && s.is_function() && !s.name.is_empty())
        .map(|s| s.name.clone()).collect();
    let mut all_symbols = symbols;
    all_symbols.extend(dyn_symbols);
    let dynamic = parse_dynamic64(&c, so[8], so[9]);
    let imports = resolve_needed(&dynamic, dynstr);
    Ok(ElfModuleData {
        machine, type_, entry_point: entry, class, data: encoding, flags,
        sections, segments, symbols: all_symbols, dynamic, imports, exports,
    })
}

fn parse_elf64_sections(
    c: &Cursor<'_>, data: &[u8], le: bool,
    shoff: usize, shnum: usize, shentsize: usize, shstrndx: usize,
) -> (Vec<ElfSectionInfo>, [usize; 10]) {
    let shstr = if shoff > 0 && shstrndx < shnum {
        let shstrtab_hdr = shoff + shstrndx * shentsize;
        let str_off = usize::try_from(c.u64_at(shstrtab_hdr + 24).unwrap_or(0)).unwrap_or(0);
        let str_sz  = usize::try_from(c.u64_at(shstrtab_hdr + 32).unwrap_or(0)).unwrap_or(0);
        safe_slice(data, str_off, str_sz)
    } else { &data[0..0] };
    let shstr_cursor = Cursor::new(shstr, le);
    let mut sections = Vec::with_capacity(shnum);
    let mut offsets = [0usize; 10];
    for i in 0..shnum {
        let base = shoff + i * shentsize;
        if base + shentsize > data.len() { break; }
        let name_idx  = c.u32_at(base).unwrap_or(0) as usize;
        let type_     = c.u32_at(base + 4).unwrap_or(0);
        let flags     = c.u64_at(base + 8).unwrap_or(0);
        let addr      = c.u64_at(base + 16).unwrap_or(0);
        let offset    = c.u64_at(base + 24).unwrap_or(0);
        let size      = c.u64_at(base + 32).unwrap_or(0);
        let link      = c.u32_at(base + 40).unwrap_or(0);
        let info      = c.u32_at(base + 44).unwrap_or(0);
        let addralign = c.u64_at(base + 48).unwrap_or(0);
        let entsize   = c.u64_at(base + 56).unwrap_or(0);
        let name      = shstr_cursor.str_at(name_idx);
        match type_ {
            SHT_STRTAB if name == ".strtab" => { offsets[0] = usize::try_from(offset).unwrap_or(0); offsets[1] = usize::try_from(size).unwrap_or(0); }
            SHT_STRTAB if name == ".dynstr" => { offsets[6] = usize::try_from(offset).unwrap_or(0); offsets[7] = usize::try_from(size).unwrap_or(0); }
            SHT_SYMTAB => { offsets[2] = usize::try_from(offset).unwrap_or(0); offsets[3] = usize::try_from(size).unwrap_or(0); }
            SHT_DYNSYM => { offsets[4] = usize::try_from(offset).unwrap_or(0); offsets[5] = usize::try_from(size).unwrap_or(0); }
            SHT_DYNAMIC => { offsets[8] = usize::try_from(offset).unwrap_or(0); offsets[9] = usize::try_from(size).unwrap_or(0); }
            _ => {}
        }
        sections.push(ElfSectionInfo { name, type_, flags, addr, offset, size, link, info, addralign, entsize });
    }
    (sections, offsets)
}

fn parse_symbols64(c: &Cursor<'_>, strtab: &[u8], offset: usize, size: usize) -> Vec<ElfSymbolInfo> {
    let entry_size = 24usize;
    if size == 0 || offset == 0 { return vec![]; }
    let n = size / entry_size;
    let mut syms = Vec::with_capacity(n);
    let sc = Cursor::new(strtab, c.le);
    for i in 0..n {
        let base = offset + i * entry_size;
        if base + entry_size > c.data.len() { break; }
        let name_idx = c.u32_at(base).unwrap_or(0) as usize;
        let info     = c.u8_at(base + 4).unwrap_or(0);
        let other    = c.u8_at(base + 5).unwrap_or(0);
        let shndx    = c.u16_at(base + 6).unwrap_or(0);
        let value    = c.u64_at(base + 8).unwrap_or(0);
        let size_    = c.u64_at(base + 16).unwrap_or(0);
        syms.push(ElfSymbolInfo {
            name: sc.str_at(name_idx),
            value, size: size_,
            type_: info & 0xF,
            binding: info >> 4,
            visibility: other & 3,
            shndx,
        });
    }
    syms
}

fn parse_dynamic64(c: &Cursor<'_>, offset: usize, size: usize) -> Vec<ElfDynEntry> {
    let entry_size = 16usize;
    if size == 0 || offset == 0 { return vec![]; }
    let n = size / entry_size;
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let base = offset + i * entry_size;
        if base + entry_size > c.data.len() { break; }
        let tag = c.i64_at(base).unwrap_or(0);
        let val = c.u64_at(base + 8).unwrap_or(0);
        entries.push(ElfDynEntry { tag, value: val });
        if tag == DT_NULL { break; }
    }
    entries
}

fn resolve_needed(dynamic: &[ElfDynEntry], dynstr: &[u8]) -> Vec<String> {
    let sc = Cursor::new(dynstr, true);
    dynamic.iter()
        .filter(|e| e.tag == DT_NEEDED)
        .map(|e| sc.str_at(usize::try_from(e.value).unwrap_or(0)))
        .collect()
}

// ---------------------------------------------------------------------------
// YARA ELF module
// ---------------------------------------------------------------------------

/// The YARA ELF module wrapper.
pub struct YaraElfModule {
    data: Option<ElfModuleData>,
}

impl YaraElfModule {
    #[must_use] 
    pub const fn new() -> Self { Self { data: None } }

    /// Parse bytes as either ELF32 or ELF64 and store the result.
    ///
    /// # Errors
    ///
    /// Returns [`ElfParseError`] if the binary cannot be parsed.
    pub fn load(&mut self, bytes: &[u8]) -> Result<(), ElfParseError> {
        if bytes.len() < 5 { return Err(ElfParseError::TooSmall); }
        if &bytes[0..4] != ELFMAG { return Err(ElfParseError::BadMagic); }
        let class = bytes[4];
        let parsed = match class {
            ELFCLASS32 => parse_elf32(bytes)?,
            ELFCLASS64 => parse_elf64(bytes)?,
            other => return Err(ElfParseError::UnknownClass(other)),
        };
        self.data = Some(parsed);
        Ok(())
    }

    const fn elf(&self) -> Option<&ElfModuleData> { self.data.as_ref() }

    /// Number of sections in the ELF.
    #[must_use] 
    pub fn number_of_sections(&self) -> u64 {
        self.elf().map_or(0, |e| e.sections.len() as u64)
    }

    /// True if a section with the given name exists.
    #[must_use] 
    pub fn has_section(&self, name: &str) -> bool {
        self.elf().is_some_and(|e| e.sections.iter().any(|s| s.name == name))
    }

    /// Zero-based index of the first section with the given name.
    #[must_use] 
    pub fn section_index(&self, name: &str) -> Option<u64> {
        self.elf().and_then(|e| {
            e.sections.iter().position(|s| s.name == name).map(|i| i as u64)
        })
    }

    /// Number of segments.
    #[must_use] 
    pub fn number_of_segments(&self) -> u64 {
        self.elf().map_or(0, |e| e.segments.len() as u64)
    }

    /// List of shared library names from `DT_NEEDED`.
    pub fn import_libraries(&self) -> Vec<String> {
        self.elf().map_or_else(Vec::new, |e| e.imports.clone())
    }

    /// Symbol type (STT_*) for the named symbol, if present.
    #[must_use] 
    pub fn symbol_type(&self, name: &str) -> Option<u64> {
        self.elf().and_then(|e| {
            e.symbols.iter()
                .find(|s| s.name == name)
                .map(|s| u64::from(s.type_))
        })
    }

    /// Entry point virtual address.
    #[must_use] 
    pub fn entry_point(&self) -> u64 {
        self.elf().map_or(0, |e| e.entry_point)
    }

    /// Machine type (`e_machine`).
    #[must_use] 
    pub fn machine(&self) -> u16 {
        self.elf().map_or(0, |e| e.machine)
    }

    /// ELF type (`e_type`).
    #[must_use] 
    pub fn elf_type(&self) -> u16 {
        self.elf().map_or(0, |e| e.type_)
    }

    /// All exported symbol names.
    pub fn exports(&self) -> Vec<String> {
        self.elf().map_or_else(Vec::new, |e| e.exports.clone())
    }

    /// Human-readable name for a section type (`SHT_*`).
    #[must_use] 
    pub const fn section_type_name(t: u32) -> &'static str {
        match t {
            SHT_NULL => "NULL",
            SHT_PROGBITS => "PROGBITS",
            SHT_SYMTAB => "SYMTAB",
            SHT_STRTAB => "STRTAB",
            SHT_DYNAMIC => "DYNAMIC",
            SHT_DYNSYM => "DYNSYM",
            _ => "OTHER",
        }
    }

    /// Human-readable name for a segment type (`PT_*`).
    #[must_use] 
    pub const fn segment_type_name(t: u32) -> &'static str {
        match t {
            PT_LOAD => "LOAD",
            PT_DYNAMIC => "DYNAMIC",
            PT_INTERP => "INTERP",
            _ => "OTHER",
        }
    }

    /// Human-readable name for a dynamic tag (`DT_*`).
    #[must_use] 
    pub const fn dynamic_tag_name(t: i64) -> &'static str {
        match t {
            DT_NULL => "NULL",
            DT_NEEDED => "NEEDED",
            DT_STRTAB => "STRTAB",
            DT_SYMTAB => "SYMTAB",
            DT_STRSZ => "STRSZ",
            DT_SONAME => "SONAME",
            DT_RPATH => "RPATH",
            _ => "OTHER",
        }
    }

    /// Human-readable name for a symbol type (`STT_*`).
    #[must_use] 
    pub const fn symbol_type_name(t: u8) -> &'static str {
        match t {
            STT_NOTYPE => "NOTYPE",
            STT_OBJECT => "OBJECT",
            STT_FUNC => "FUNC",
            STT_SECTION => "SECTION",
            STT_FILE => "FILE",
            _ => "OTHER",
        }
    }

    /// Human-readable name for a symbol binding (`STB_*`).
    #[must_use] 
    pub const fn symbol_binding_name(b: u8) -> &'static str {
        match b {
            STB_LOCAL => "LOCAL",
            STB_GLOBAL => "GLOBAL",
            STB_WEAK => "WEAK",
            _ => "OTHER",
        }
    }

    /// Human-readable name for a symbol visibility (`STV_*`).
    #[must_use] 
    pub const fn symbol_visibility_name(v: u8) -> &'static str {
        match v {
            STV_DEFAULT => "DEFAULT",
            STV_INTERNAL => "INTERNAL",
            STV_HIDDEN => "HIDDEN",
            STV_PROTECTED => "PROTECTED",
            _ => "OTHER",
        }
    }

    /// Build a histogram of section types present in the loaded ELF, keyed
    /// by their human-readable name (`SHT_*`).
    #[must_use] 
    pub fn section_type_histogram(&self) -> HashMap<&'static str, u64> {
        let mut hist: HashMap<&'static str, u64> = HashMap::new();
        if let Some(e) = self.elf() {
            for s in &e.sections {
                *hist.entry(Self::section_type_name(s.type_)).or_insert(0) += 1;
            }
        }
        hist
    }

    /// Build a histogram of segment types in the loaded ELF.
    #[must_use] 
    pub fn segment_type_histogram(&self) -> HashMap<&'static str, u64> {
        let mut hist: HashMap<&'static str, u64> = HashMap::new();
        if let Some(e) = self.elf() {
            for s in &e.segments {
                *hist.entry(Self::segment_type_name(s.type_)).or_insert(0) += 1;
            }
        }
        hist
    }
}

impl Default for YaraElfModule {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal ELF64 LE binary with no sections, no program headers.
    fn minimal_elf64() -> Vec<u8> {
        let mut e = vec![0u8; 64];
        e[0..4].copy_from_slice(ELFMAG);
        e[4] = ELFCLASS64;
        e[5] = ELFDATA2LSB;
        e[6] = 1; // EV_CURRENT
        // e_type = ET_EXEC = 2
        e[16..18].copy_from_slice(&2u16.to_le_bytes());
        // e_machine = EM_X86_64 = 62
        e[18..20].copy_from_slice(&62u16.to_le_bytes());
        // e_version = 1
        e[20..24].copy_from_slice(&1u32.to_le_bytes());
        // entry = 0x401000
        e[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        // shentsize = 64
        e[58..60].copy_from_slice(&64u16.to_le_bytes());
        e
    }

    fn minimal_elf32() -> Vec<u8> {
        let mut e = vec![0u8; 52];
        e[0..4].copy_from_slice(ELFMAG);
        e[4] = ELFCLASS32;
        e[5] = ELFDATA2LSB;
        e[6] = 1;
        e[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        e[18..20].copy_from_slice(&3u16.to_le_bytes()); // EM_386
        e[24..28].copy_from_slice(&0x08048000u32.to_le_bytes()); // entry
        e[46..48].copy_from_slice(&40u16.to_le_bytes()); // shentsize
        e
    }

    #[test]
    fn test_parse_elf64_minimal() {
        let data = minimal_elf64();
        let elf = parse_elf64(&data).unwrap();
        assert_eq!(elf.machine, 62);
        assert_eq!(elf.entry_point, 0x401000);
        assert_eq!(elf.class, ELFCLASS64);
    }

    #[test]
    fn test_parse_elf32_minimal() {
        let data = minimal_elf32();
        let elf = parse_elf32(&data).unwrap();
        assert_eq!(elf.machine, 3);
        assert_eq!(elf.entry_point, 0x08048000);
        assert_eq!(elf.class, ELFCLASS32);
    }

    #[test]
    fn test_bad_magic() {
        let mut data = minimal_elf64();
        data[0] = 0xFF;
        assert!(matches!(parse_elf64(&data), Err(ElfParseError::BadMagic)));
    }

    #[test]
    fn test_wrong_class_64() {
        let mut data = minimal_elf64();
        data[4] = ELFCLASS32; // wrong class for parse_elf64
        assert!(matches!(parse_elf64(&data), Err(ElfParseError::UnknownClass(_))));
    }

    #[test]
    fn test_module_load_64() {
        let data = minimal_elf64();
        let mut module = YaraElfModule::new();
        module.load(&data).unwrap();
        assert_eq!(module.machine(), 62);
        assert_eq!(module.entry_point(), 0x401000);
    }

    #[test]
    fn test_module_load_32() {
        let data = minimal_elf32();
        let mut module = YaraElfModule::new();
        module.load(&data).unwrap();
        assert_eq!(module.machine(), 3);
    }

    #[test]
    fn test_number_of_sections_zero() {
        let data = minimal_elf64();
        let mut module = YaraElfModule::new();
        module.load(&data).unwrap();
        assert_eq!(module.number_of_sections(), 0);
    }

    #[test]
    fn test_has_section_false_when_empty() {
        let data = minimal_elf64();
        let mut module = YaraElfModule::new();
        module.load(&data).unwrap();
        assert!(!module.has_section(".text"));
    }

    #[test]
    fn test_section_index_none_when_empty() {
        let data = minimal_elf64();
        let mut module = YaraElfModule::new();
        module.load(&data).unwrap();
        assert!(module.section_index(".text").is_none());
    }

    #[test]
    fn test_import_libraries_empty() {
        let data = minimal_elf64();
        let mut module = YaraElfModule::new();
        module.load(&data).unwrap();
        assert!(module.import_libraries().is_empty());
    }

    #[test]
    fn test_symbol_type_none_when_no_symbols() {
        let data = minimal_elf64();
        let mut module = YaraElfModule::new();
        module.load(&data).unwrap();
        assert!(module.symbol_type("main").is_none());
    }

    #[test]
    fn test_exports_empty() {
        let data = minimal_elf64();
        let mut module = YaraElfModule::new();
        module.load(&data).unwrap();
        assert!(module.exports().is_empty());
    }

    #[test]
    fn test_elf_type() {
        let data = minimal_elf64();
        let mut module = YaraElfModule::new();
        module.load(&data).unwrap();
        assert_eq!(module.elf_type(), 2); // ET_EXEC
    }

    #[test]
    fn test_symbol_is_global() {
        let sym = ElfSymbolInfo {
            name: "foo".into(), value: 0, size: 0,
            type_: STT_FUNC, binding: STB_GLOBAL, visibility: STV_DEFAULT, shndx: 1,
        };
        assert!(sym.is_global());
        assert!(sym.is_function());
        assert!(!sym.is_weak());
    }

    #[test]
    fn test_symbol_is_local() {
        let sym = ElfSymbolInfo {
            name: "bar".into(), value: 0, size: 0,
            type_: STT_OBJECT, binding: STB_LOCAL, visibility: STV_HIDDEN, shndx: 2,
        };
        assert!(sym.is_local());
        assert!(sym.is_object());
    }

    #[test]
    fn test_hex_token_parse_simple_from_elf_path() {
        // Sanity: parse ELF64 too small
        assert!(matches!(parse_elf64(&[0u8; 10]), Err(ElfParseError::TooSmall)));
    }

    #[test]
    fn test_number_of_segments_zero() {
        let data = minimal_elf64();
        let mut module = YaraElfModule::new();
        module.load(&data).unwrap();
        assert_eq!(module.number_of_segments(), 0);
    }
}
