//! `elf_provider.rs` — ELF symbol table provider.
//!
//! Parses `.symtab` and `.dynsym` sections of ELF32/ELF64 binaries to produce
//! [`Symbol`] records.
//!
//! Implements:
//! - `ELF32_Sym` / `ELF64_Sym` struct parsing (from raw section data)
//! - `st_info` decoding for binding (`LOCAL/GLOBAL/WEAK/GNU_UNIQUE`) and type
//!   (NOTYPE/OBJECT/FUNC/SECTION/FILE/COMMON/TLS/IFUNC)
//! - `st_other` decoding for visibility (DEFAULT/INTERNAL/HIDDEN/PROTECTED)
//! - Section-relative address resolution using a section header table
//! - ELF REL/RELA relocation processing to resolve imported symbol addresses
//!   (stubs; real GOT/PLT resolution requires virtual-address layout)

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    LegacySymbolSource, SourceLocation, SymKind, Symbol, SymbolBinding, SymbolProvider,
    SymbolVisibility,
};

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors raised while parsing an ELF object's symbol tables.
#[derive(Debug, Error)]
pub enum ElfError {
    /// The file did not begin with the ELF magic (`\x7fELF`).
    #[error("invalid ELF magic")]
    InvalidMagic,
    /// The `EI_CLASS` byte was neither 32- nor 64-bit.
    #[error("unsupported ELF class: {0}")]
    UnsupportedClass(u8),
    /// The `EI_DATA` byte specified an unsupported endianness.
    #[error("unsupported ELF data encoding: {0}")]
    UnsupportedEncoding(u8),
    /// A required section was not present.
    #[error("section not found: {0}")]
    SectionNotFound(String),
    /// A symbol table ended before a full entry could be read.
    #[error("symbol table truncated at offset {0}")]
    Truncated(usize),
    /// An I/O error occurred while reading the object.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A `st_name` offset fell outside the string table.
    #[error("string table error: offset {0} out of bounds")]
    StringTableOob(usize),
    /// Any other error, carrying a message.
    #[error("{0}")]
    Other(String),
}

/// Convenience result alias for ELF operations.
pub type Result<T> = std::result::Result<T, ElfError>;

// ── ELF constants ─────────────────────────────────────────────────────────────

/// The four-byte ELF identification magic (`EI_MAG0..3`).
pub const ELFMAG: &[u8] = b"\x7fELF";
/// `ELFCLASS32` — 32-bit objects (`EI_CLASS`).
pub const ELFCLASS32: u8 = 1;
/// `ELFCLASS64` — 64-bit objects (`EI_CLASS`).
pub const ELFCLASS64: u8 = 2;
/// `ELFDATA2LSB` — two's-complement little-endian (`EI_DATA`).
pub const ELFDATA2LSB: u8 = 1; // Little-endian
/// `ELFDATA2MSB` — two's-complement big-endian (`EI_DATA`).
pub const ELFDATA2MSB: u8 = 2; // Big-endian

// st_bind values (upper nibble of st_info)
/// `STB_LOCAL` — local binding (not visible outside the object).
pub const STB_LOCAL: u8 = 0;
/// `STB_GLOBAL` — global binding (visible to all combined objects).
pub const STB_GLOBAL: u8 = 1;
/// `STB_WEAK` — weak binding (overridable by a strong definition).
pub const STB_WEAK: u8 = 2;
/// `STB_GNU_UNIQUE` — GNU unique global binding.
pub const STB_GNU_UNIQUE: u8 = 10;

// st_type values (lower nibble of st_info)
/// `STT_NOTYPE` — symbol type unspecified.
pub const STT_NOTYPE: u8 = 0;
/// `STT_OBJECT` — a data object (variable, array).
pub const STT_OBJECT: u8 = 1;
/// `STT_FUNC` — a function or executable code.
pub const STT_FUNC: u8 = 2;
/// `STT_SECTION` — a section symbol.
pub const STT_SECTION: u8 = 3;
/// `STT_FILE` — a source-file name symbol.
pub const STT_FILE: u8 = 4;
/// `STT_COMMON` — an uninitialised common block.
pub const STT_COMMON: u8 = 5;
/// `STT_TLS` — a thread-local storage object.
pub const STT_TLS: u8 = 6;
/// `STT_GNU_IFUNC` — a GNU indirect function (resolver).
pub const STT_GNU_IFUNC: u8 = 10;

// st_visibility values (lower 2 bits of st_other)
/// `STV_DEFAULT` — visibility as specified by the symbol's binding.
pub const STV_DEFAULT: u8 = 0;
/// `STV_INTERNAL` — processor-specific hidden visibility.
pub const STV_INTERNAL: u8 = 1;
/// `STV_HIDDEN` — not visible to other components.
pub const STV_HIDDEN: u8 = 2;
/// `STV_PROTECTED` — visible but not preemptable.
pub const STV_PROTECTED: u8 = 3;

// Special section indices
/// `SHN_UNDEF` — the undefined / external section index.
pub const SHN_UNDEF: u16 = 0;
/// `SHN_ABS` — the symbol holds an absolute, non-relocatable value.
pub const SHN_ABS: u16 = 0xfff1;
/// `SHN_COMMON` — the symbol is an unallocated common block.
pub const SHN_COMMON: u16 = 0xfff2;

// Relocation types (x86_64)
/// `R_X86_64_NONE` — no relocation.
pub const R_X86_64_NONE: u32 = 0;
/// `R_X86_64_64` — a direct 64-bit absolute relocation (`S + A`).
pub const R_X86_64_64: u32 = 1;
/// `R_X86_64_PC32` — a 32-bit PC-relative relocation (`S + A - P`).
pub const R_X86_64_PC32: u32 = 2;
/// `R_X86_64_GLOB_DAT` — set a GOT entry to a symbol's address.
pub const R_X86_64_GLOB_DAT: u32 = 6;
/// `R_X86_64_JUMP_SLOT` — set a PLT GOT entry to a symbol's address.
pub const R_X86_64_JUMP_SLOT: u32 = 7;

// ── ElfIdent ──────────────────────────────────────────────────────────────────

/// The identification fields decoded from an ELF header's `e_ident` array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElfIdent {
    /// `EI_CLASS` — `ELFCLASS32` or `ELFCLASS64`.
    pub class: u8,
    /// `EI_DATA` — byte order (`ELFDATA2LSB`/`ELFDATA2MSB`).
    pub data: u8,
    /// `EI_VERSION` — the ELF header version (currently 1).
    pub version: u8,
    /// `EI_OSABI` — the target operating-system/ABI identifier.
    pub os_abi: u8,
}

impl ElfIdent {
    /// Parse the 16-byte `e_ident`, returning `None` if it is too short or the
    /// magic does not match.
    #[must_use]
    pub fn parse(e_ident: &[u8]) -> Option<Self> {
        if e_ident.len() < 16 {
            return None;
        }
        if &e_ident[0..4] != ELFMAG {
            return None;
        }
        Some(Self {
            class: e_ident[4],
            data: e_ident[5],
            version: e_ident[6],
            os_abi: e_ident[7],
        })
    }

    /// Whether the object is 64-bit (`ELFCLASS64`).
    #[must_use]
    pub const fn is_64bit(&self) -> bool {
        self.class == ELFCLASS64
    }
    /// Whether the object is little-endian (`ELFDATA2LSB`).
    #[must_use]
    pub const fn is_little_endian(&self) -> bool {
        self.data == ELFDATA2LSB
    }
}

// ── ElfSym ────────────────────────────────────────────────────────────────────

/// A parsed ELF symbol table entry (common representation for 32 and 64 bit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfSym {
    /// Index into the string table.
    pub st_name: u32,
    /// Symbol value (address for defined symbols).
    pub st_value: u64,
    /// Symbol size in bytes.
    pub st_size: u64,
    /// `st_bind` in upper nibble, `st_type` in lower nibble.
    pub st_info: u8,
    /// Visibility encoding.
    pub st_other: u8,
    /// Section index.
    pub st_shndx: u16,
    /// Resolved name (populated after string table lookup).
    pub name: String,
}

impl ElfSym {
    /// Extract binding from `st_info`.
    #[must_use]
    pub const fn binding(&self) -> u8 {
        self.st_info >> 4
    }
    /// Extract type from `st_info`.
    #[must_use]
    pub const fn sym_type(&self) -> u8 {
        self.st_info & 0x0f
    }
    /// Extract visibility from `st_other`.
    #[must_use]
    pub const fn visibility(&self) -> u8 {
        self.st_other & 0x3
    }

    /// The binding mapped to the crate's [`SymbolBinding`].
    #[must_use]
    pub const fn sym_binding(&self) -> SymbolBinding {
        match self.binding() {
            STB_GLOBAL => SymbolBinding::Global,
            STB_WEAK => SymbolBinding::Weak,
            STB_GNU_UNIQUE => SymbolBinding::GnuUnique,
            // STB_LOCAL and any unknown binding fall through to Local.
            _ => SymbolBinding::Local,
        }
    }

    /// The visibility mapped to the crate's [`SymbolVisibility`].
    #[must_use]
    pub const fn sym_visibility(&self) -> SymbolVisibility {
        match self.visibility() {
            STV_INTERNAL => SymbolVisibility::Internal,
            STV_HIDDEN => SymbolVisibility::Hidden,
            STV_PROTECTED => SymbolVisibility::Protected,
            // STV_DEFAULT and any unknown visibility fall through to Default.
            _ => SymbolVisibility::Default,
        }
    }

    /// The symbol type mapped to the crate's [`SymKind`].
    #[must_use]
    pub const fn sym_kind(&self) -> SymKind {
        match self.sym_type() {
            STT_FUNC => SymKind::Function,
            // An IFUNC's address holds a *resolver* that returns the real
            // implementation, so callers must be able to tell it apart from an
            // ordinary function. `Symbol::is_function` already covers IFunc.
            STT_GNU_IFUNC => SymKind::IFunc,
            STT_OBJECT => SymKind::Data,
            STT_SECTION => SymKind::Section,
            STT_FILE => SymKind::File,
            STT_COMMON => SymKind::Common,
            STT_TLS => SymKind::TLS,
            _ => SymKind::Unknown,
        }
    }

    /// Whether the symbol is undefined (`st_shndx == SHN_UNDEF`).
    #[must_use]
    pub const fn is_undefined(&self) -> bool {
        self.st_shndx == SHN_UNDEF
    }
    /// Whether the symbol holds an absolute value (`st_shndx == SHN_ABS`).
    #[must_use]
    pub const fn is_absolute(&self) -> bool {
        self.st_shndx == SHN_ABS
    }
    /// Whether the symbol is a common block (`st_shndx == SHN_COMMON`).
    #[must_use]
    pub const fn is_common(&self) -> bool {
        self.st_shndx == SHN_COMMON
    }
    /// Whether the symbol is defined (not `SHN_UNDEF`).
    #[must_use]
    pub const fn is_defined(&self) -> bool {
        !self.is_undefined()
    }
    /// Whether the symbol has local binding (`STB_LOCAL`).
    #[must_use]
    pub const fn is_local(&self) -> bool {
        self.binding() == STB_LOCAL
    }

    /// Convert to the crate's [`Symbol`].
    #[must_use]
    pub fn to_symbol(&self) -> Symbol {
        let mut sym = Symbol::new(self.name.clone(), self.st_value, self.sym_kind());
        sym.size = if self.st_size > 0 {
            Some(self.st_size)
        } else {
            None
        };
        sym.binding = self.sym_binding();
        sym.visibility = self.sym_visibility();
        // SHN_UNDEF (0) and the reserved range 0xff00..=0xffff (SHN_ABS,
        // SHN_COMMON, SHN_XINDEX, …) are markers, not indices into the section
        // header table. Storing them verbatim made `section_index(0)` match
        // every undefined symbol and gave `SectionSymbols` phantom buckets.
        // The undefined/absolute/common distinction is carried by
        // `source`/`kind` instead.
        sym.section_index = if self.st_shndx == SHN_UNDEF || self.st_shndx >= 0xff00 {
            None
        } else {
            Some(self.st_shndx)
        };
        sym.source = if self.is_undefined() {
            LegacySymbolSource::Import
        } else {
            LegacySymbolSource::Debug
        };
        sym
    }
}

// ── ElfSym32 / ElfSym64 ───────────────────────────────────────────────────────

/// Raw ELF32 symbol table entry (24 bytes).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ElfSym32Raw {
    /// `st_name` — string-table offset of the symbol's name.
    pub st_name: u32,
    /// `st_value` — the symbol's value (address for defined symbols).
    pub st_value: u32,
    /// `st_size` — the symbol's size in bytes.
    pub st_size: u32,
    /// `st_info` — binding (upper nibble) and type (lower nibble).
    pub st_info: u8,
    /// `st_other` — visibility (lower 2 bits).
    pub st_other: u8,
    /// `st_shndx` — the section header index the symbol belongs to.
    pub st_shndx: u16,
}

/// Raw ELF64 symbol table entry (24 bytes).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ElfSym64Raw {
    /// `st_name` — string-table offset of the symbol's name.
    pub st_name: u32,
    /// `st_info` — binding (upper nibble) and type (lower nibble).
    pub st_info: u8,
    /// `st_other` — visibility (lower 2 bits).
    pub st_other: u8,
    /// `st_shndx` — the section header index the symbol belongs to.
    pub st_shndx: u16,
    /// `st_value` — the symbol's value (address for defined symbols).
    pub st_value: u64,
    /// `st_size` — the symbol's size in bytes.
    pub st_size: u64,
}

/// Size in bytes of one ELF32 symbol table entry.
pub const ELF32_SYM_SIZE: usize = 16;
/// Size in bytes of one ELF64 symbol table entry.
pub const ELF64_SYM_SIZE: usize = 24;

// ── ElfSectionInfo ────────────────────────────────────────────────────────────

/// Section header info needed for address resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfSectionInfo {
    /// The section header index.
    pub index: u16,
    /// The section name (from the section-header string table).
    pub name: String,
    /// `sh_addr` — the section's virtual address when loaded (0 if not allocated).
    pub addr: u64,
    /// `sh_offset` — the section's byte offset within the file.
    pub offset: u64,
    /// `sh_size` — the section's size in bytes.
    pub size: u64,
    /// `sh_flags` — the section attribute flags.
    pub flags: u64,
}

impl ElfSectionInfo {
    /// Construct section info from its header fields.
    pub fn new(
        index: u16,
        name: impl Into<String>,
        addr: u64,
        offset: u64,
        size: u64,
        flags: u64,
    ) -> Self {
        Self {
            index,
            name: name.into(),
            addr,
            offset,
            size,
            flags,
        }
    }

    /// Whether file offset `off` falls within this section's byte range.
    #[must_use]
    pub const fn contains_offset(&self, off: u64) -> bool {
        let Some(end) = self.offset.checked_add(self.size) else {
            return false;
        };
        off >= self.offset && off < end
    }

    /// Convert a file offset to a virtual address using this section's info.
    #[must_use]
    pub const fn offset_to_va(&self, file_offset: u64) -> Option<u64> {
        if self.contains_offset(file_offset) {
            // file_offset >= self.offset is guaranteed by contains_offset
            let delta = file_offset - self.offset;
            self.addr.checked_add(delta)
        } else {
            None
        }
    }
}

// ── ElfRelocation ─────────────────────────────────────────────────────────────

/// A parsed ELF relocation entry (REL or RELA).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfRelocation {
    /// Virtual address of the location to be relocated.
    pub r_offset: u64,
    /// Symbol table index (upper 32 bits of `r_info` for ELF64).
    pub r_sym: u32,
    /// Relocation type (lower 32 bits of `r_info` for ELF64).
    pub r_type: u32,
    /// Addend (RELA only; zero for REL).
    pub r_addend: i64,
    /// True if this is a RELA entry (has explicit addend).
    pub is_rela: bool,
}

impl ElfRelocation {
    /// Build a REL entry (no explicit addend) by splitting `r_info` into
    /// symbol index and type.
    #[must_use]
    pub const fn new_rel(r_offset: u64, r_info: u64) -> Self {
        Self {
            r_offset,
            r_sym: (r_info >> 32) as u32,
            r_type: (r_info & 0xffff_ffff) as u32,
            r_addend: 0,
            is_rela: false,
        }
    }

    /// Build a RELA entry (with explicit `r_addend`).
    #[must_use]
    pub const fn new_rela(r_offset: u64, r_info: u64, r_addend: i64) -> Self {
        let mut r = Self::new_rel(r_offset, r_info);
        r.r_addend = r_addend;
        r.is_rela = true;
        r
    }
}

/// Parse a `.rel` section (no addend, ELF64: 16 bytes/entry).
///
/// # Panics
///
/// Panics only if internal `try_into` conversions of 8-byte slices fail, which is impossible by construction.
#[must_use]
pub fn parse_rel64(data: &[u8]) -> Vec<ElfRelocation> {
    let mut relocs = Vec::new();
    let mut cursor = 0;
    while cursor + 16 <= data.len() {
        let r_offset = u64::from_le_bytes(data[cursor..cursor + 8].try_into().unwrap());
        let r_info = u64::from_le_bytes(data[cursor + 8..cursor + 16].try_into().unwrap());
        relocs.push(ElfRelocation::new_rel(r_offset, r_info));
        cursor += 16;
    }
    relocs
}

/// Parse a `.rela` section (with addend, ELF64: 24 bytes/entry).
///
/// # Panics
///
/// Panics only if internal `try_into` conversions of 8-byte slices fail, which is impossible by construction.
#[must_use]
pub fn parse_rela64(data: &[u8]) -> Vec<ElfRelocation> {
    let mut relocs = Vec::new();
    let mut cursor = 0;
    while cursor + 24 <= data.len() {
        let r_offset = u64::from_le_bytes(data[cursor..cursor + 8].try_into().unwrap());
        let r_info = u64::from_le_bytes(data[cursor + 8..cursor + 16].try_into().unwrap());
        let r_addend = i64::from_le_bytes(data[cursor + 16..cursor + 24].try_into().unwrap());
        relocs.push(ElfRelocation::new_rela(r_offset, r_info, r_addend));
        cursor += 24;
    }
    relocs
}

// ── SymtabParser ─────────────────────────────────────────────────────────────

/// Parses a raw `.symtab` or `.dynsym` section together with its string table.
pub struct SymtabParser<'a> {
    symtab: &'a [u8],
    strtab: &'a [u8],
    is_64bit: bool,
    is_little_endian: bool,
}

impl<'a> SymtabParser<'a> {
    /// Create a parser over a symbol table and its associated string table,
    /// specifying the object's class (`is_64bit`) and byte order.
    #[must_use]
    pub const fn new(
        symtab: &'a [u8],
        strtab: &'a [u8],
        is_64bit: bool,
        is_little_endian: bool,
    ) -> Self {
        Self {
            symtab,
            strtab,
            is_64bit,
            is_little_endian,
        }
    }

    fn read_u16(&self, data: &[u8], off: usize) -> Option<u16> {
        let bytes = data.get(off..off + 2)?;
        let b = [bytes[0], bytes[1]];
        Some(if self.is_little_endian {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }

    fn read_u32(&self, data: &[u8], off: usize) -> Option<u32> {
        let b: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
        Some(if self.is_little_endian {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    fn read_u64(&self, data: &[u8], off: usize) -> Option<u64> {
        let b: [u8; 8] = data.get(off..off + 8)?.try_into().ok()?;
        Some(if self.is_little_endian {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }

    fn read_name(&self, offset: u32) -> String {
        let off = offset as usize;
        if off >= self.strtab.len() {
            return format!("<oob:{off:#x}>");
        }
        let end = self.strtab[off..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.strtab.len() - off);
        String::from_utf8_lossy(&self.strtab[off..off + end]).into_owned()
    }

    /// Parse all symbol table entries.
    ///
    /// # Errors
    ///
    /// Returns `ElfError::Truncated` if the table size is not a multiple of the entry size.
    pub fn parse(&self) -> Result<Vec<ElfSym>> {
        let entry_size = if self.is_64bit {
            ELF64_SYM_SIZE
        } else {
            ELF32_SYM_SIZE
        };
        if !self.symtab.len().is_multiple_of(entry_size) {
            return Err(ElfError::Truncated(self.symtab.len()));
        }
        let count = self.symtab.len() / entry_size;
        let mut syms = Vec::with_capacity(count);
        for i in 0..count {
            let off = i * entry_size;
            let raw = &self.symtab[off..off + entry_size];
            // Shared prefix: st_name is at offset 0 in both ELF32 and ELF64 layouts.
            let Some(st_name) = self.read_u32(raw, 0) else { continue };
            let sym = if self.is_64bit {
                let st_info = raw[4];
                let st_other = raw[5];
                let Some(st_shndx) = self.read_u16(raw, 6) else { continue };
                let Some(st_value) = self.read_u64(raw, 8) else { continue };
                let Some(st_size) = self.read_u64(raw, 16) else { continue };
                let name = self.read_name(st_name);
                ElfSym {
                    st_name,
                    st_value,
                    st_size,
                    st_info,
                    st_other,
                    st_shndx,
                    name,
                }
            } else {
                let Some(st_value_raw) = self.read_u32(raw, 4) else { continue };
                let st_value = u64::from(st_value_raw);
                let Some(st_size_raw) = self.read_u32(raw, 8) else { continue };
                let st_size = u64::from(st_size_raw);
                let st_info = raw[12];
                let st_other = raw[13];
                let Some(st_shndx) = self.read_u16(raw, 14) else { continue };
                let name = self.read_name(st_name);
                ElfSym {
                    st_name,
                    st_value,
                    st_size,
                    st_info,
                    st_other,
                    st_shndx,
                    name,
                }
            };
            syms.push(sym);
        }
        Ok(syms)
    }
}

// ── ElfSymbolProvider ─────────────────────────────────────────────────────────

/// Implements [`SymbolProvider`] by parsing ELF symbol tables.
#[derive(Debug)]
pub struct ElfSymbolProvider {
    name: String,
    symbols: Vec<Symbol>,
    relocations: Vec<ElfRelocation>,
    sections: Vec<ElfSectionInfo>,
    /// `name → index into symbols` (first occurrence wins).
    by_name: HashMap<String, usize>,
    /// `(address, index into symbols)` sorted ascending, for O(log n) lookups.
    addr_sorted: Vec<(u64, usize)>,
}

impl ElfSymbolProvider {
    /// Create an empty provider identified by `name`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            symbols: Vec::new(),
            relocations: Vec::new(),
            sections: Vec::new(),
            by_name: HashMap::new(),
            addr_sorted: Vec::new(),
        }
    }

    /// Build a provider from pre-parsed `ElfSym` records.
    ///
    /// Bulk path: pushes every symbol and builds the indices once, rather than
    /// inserting into the sorted address vector per symbol (which is O(n) per
    /// insert, i.e. O(n^2) over a large `.symtab`).
    pub fn from_elf_syms(name: impl Into<String>, syms: Vec<ElfSym>) -> Self {
        let mut p = Self::new(name);
        p.symbols = syms.into_iter().map(|s| s.to_symbol()).collect();
        p.rebuild_index();
        p
    }

    /// Rebuild `by_name` / `addr_sorted` from `symbols` in one pass.
    ///
    /// Preserves the incremental semantics of [`Self::add_symbol`]: the first
    /// occurrence of a name wins, and the address index is sorted on the
    /// `(address, index)` tuple.
    pub fn rebuild_index(&mut self) {
        self.by_name.clear();
        self.addr_sorted.clear();
        self.addr_sorted.reserve(self.symbols.len());
        for (idx, s) in self.symbols.iter().enumerate() {
            self.by_name.entry(s.name.clone()).or_insert(idx);
            self.addr_sorted.push((s.address, idx));
        }
        self.addr_sorted.sort_unstable();
    }

    /// Parse from raw `.symtab` + `.strtab` bytes.
    ///
    /// # Errors
    ///
    /// Propagates `ElfError::Truncated` from the underlying `SymtabParser` if the table is malformed.
    pub fn parse_symtab(
        name: impl Into<String>,
        symtab: &[u8],
        strtab: &[u8],
        is_64bit: bool,
        is_little_endian: bool,
    ) -> Result<Self> {
        let parser = SymtabParser::new(symtab, strtab, is_64bit, is_little_endian);
        let syms = parser.parse()?;
        Ok(Self::from_elf_syms(name, syms))
    }

    /// Parse from a complete ELF file bytes (stub: detects header, finds sections).
    ///
    /// # Errors
    ///
    /// Returns `ElfError::InvalidMagic`, `ElfError::UnsupportedClass`, or `ElfError::UnsupportedEncoding`
    /// if the file does not begin with a recognised ELF header.
    pub fn parse_elf(name: impl Into<String>, data: &[u8]) -> Result<Self> {
        if data.len() < 16 {
            return Err(ElfError::InvalidMagic);
        }
        let ident = ElfIdent::parse(data).ok_or(ElfError::InvalidMagic)?;
        if ident.class != ELFCLASS32 && ident.class != ELFCLASS64 {
            return Err(ElfError::UnsupportedClass(ident.class));
        }
        if ident.data != ELFDATA2LSB && ident.data != ELFDATA2MSB {
            return Err(ElfError::UnsupportedEncoding(ident.data));
        }
        // Real parsing would extract section headers and find .symtab/.dynsym.
        // This stub returns an empty provider to avoid a full ELF parser dep.
        Ok(Self::new(name))
    }

    /// Apply relocations: for each `JUMP_SLOT` / `GLOB_DAT` relocation, try to
    /// mark the target symbol's GOT/PLT address.
    pub fn apply_relocations(&mut self, relocs: Vec<ElfRelocation>) {
        // Stub: just store them for inspection.
        self.relocations = relocs;
    }

    /// Resolve section-relative addresses for symbols whose `st_shndx` is a
    /// normal section index.
    pub fn resolve_section_addresses(&mut self, sections: &[ElfSectionInfo]) {
        self.sections = sections.to_vec();
        // For each symbol that has an address in a known section, we could
        // verify / re-compute the VA.  Stub: store sections only.
    }

    /// Append a symbol and incrementally update the name/address indexes.
    pub fn add_symbol(&mut self, sym: Symbol) {
        self.symbols.push(sym);
        let idx = self.symbols.len() - 1;
        let s = &self.symbols[idx];
        self.by_name.entry(s.name.clone()).or_insert(idx);
        let key = (s.address, idx);
        let pos = self.addr_sorted.partition_point(|&e| e <= key);
        self.addr_sorted.insert(pos, key);
    }
    /// Number of symbols held.
    #[must_use]
    pub const fn symbol_count(&self) -> usize {
        self.symbols.len()
    }
    /// Number of stored relocations.
    #[must_use]
    pub const fn relocation_count(&self) -> usize {
        self.relocations.len()
    }
    /// The stored relocations.
    #[must_use]
    pub fn relocations(&self) -> &[ElfRelocation] {
        &self.relocations
    }
    /// The stored section descriptors.
    #[must_use]
    pub fn sections(&self) -> &[ElfSectionInfo] {
        &self.sections
    }

    /// Build a `name → address` index over every symbol currently held by the
    /// provider.  When multiple symbols share a name the *first* address is
    /// retained, mirroring linker behaviour.
    #[must_use]
    pub fn name_index(&self) -> HashMap<String, u64> {
        let mut m: HashMap<String, u64> = HashMap::with_capacity(self.symbols.len());
        for s in &self.symbols {
            m.entry(s.name.clone()).or_insert(s.address);
        }
        m
    }

    /// Return all undefined (imported) symbols.
    #[must_use]
    pub fn imports(&self) -> Vec<&Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.source == LegacySymbolSource::Import)
            .collect()
    }

    /// Return all defined (local+global) symbols.
    #[must_use]
    pub fn defined_symbols(&self) -> Vec<&Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.source != LegacySymbolSource::Import)
            .collect()
    }
}

impl SymbolProvider for ElfSymbolProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn lookup_name(&self, name: &str) -> Option<Symbol> {
        self.by_name.get(name).map(|&i| self.symbols[i].clone())
    }

    fn lookup_address(&self, addr: u64) -> Option<Symbol> {
        let start = self.addr_sorted.partition_point(|&(a, _)| a < addr);
        let &(a, i) = self.addr_sorted.get(start)?;
        (a == addr).then(|| self.symbols[i].clone())
    }

    fn lookup_nearest(&self, addr: u64) -> Option<Symbol> {
        let ub = self.addr_sorted.partition_point(|&(a, _)| a <= addr);
        let &(best, _) = self.addr_sorted[..ub].last()?;
        // Address 0 marks undefined/absent symbols — never "nearest".
        if best == 0 {
            return None;
        }
        let start = self.addr_sorted[..ub].partition_point(|&(a, _)| a < best);
        Some(self.symbols[self.addr_sorted[start].1].clone())
    }

    fn all_symbols(&self) -> Vec<Symbol> {
        self.symbols.clone()
    }

    fn all_functions(&self) -> Vec<Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.kind == SymKind::Function)
            .cloned()
            .collect()
    }

    fn source_line_for_address(&self, _addr: u64) -> Option<SourceLocation> {
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_indexed_lookups() {
        let mut p = ElfSymbolProvider::new("t");
        p.add_symbol(Symbol::new("und".to_string(), 0, SymKind::Function));
        p.add_symbol(Symbol::new("f1".to_string(), 0x1000, SymKind::Function));
        p.add_symbol(Symbol::new("f2".to_string(), 0x2000, SymKind::Function));
        assert_eq!(p.lookup_name("f1").unwrap().address, 0x1000);
        assert!(p.lookup_name("nope").is_none());
        assert_eq!(p.lookup_address(0x2000).unwrap().name, "f2");
        assert!(p.lookup_address(0x1500).is_none());
        assert_eq!(p.lookup_nearest(0x1fff).unwrap().name, "f1");
        // Address-0 (undefined) symbols are never "nearest".
        assert!(p.lookup_nearest(0xfff).is_none());
    }

    // ── ElfIdent ──────────────────────────────────────────────────────────────

    #[test]
    fn elf_ident_valid() {
        let mut e_ident = [0u8; 16];
        e_ident[0..4].copy_from_slice(ELFMAG);
        e_ident[4] = ELFCLASS64;
        e_ident[5] = ELFDATA2LSB;
        let id = ElfIdent::parse(&e_ident).unwrap();
        assert!(id.is_64bit());
        assert!(id.is_little_endian());
    }
    #[test]
    fn elf_ident_32bit_be() {
        let mut e_ident = [0u8; 16];
        e_ident[0..4].copy_from_slice(ELFMAG);
        e_ident[4] = ELFCLASS32;
        e_ident[5] = ELFDATA2MSB;
        let id = ElfIdent::parse(&e_ident).unwrap();
        assert!(!id.is_64bit());
        assert!(!id.is_little_endian());
    }
    #[test]
    fn elf_ident_invalid_magic() {
        let e_ident = [0u8; 16];
        assert!(ElfIdent::parse(&e_ident).is_none());
    }
    #[test]
    fn elf_ident_too_short() {
        assert!(ElfIdent::parse(b"ELF").is_none());
    }

    // ── ElfSym ────────────────────────────────────────────────────────────────

    fn make_sym(name: &str, value: u64, info: u8, shndx: u16) -> ElfSym {
        ElfSym {
            st_name: 0,
            st_value: value,
            st_size: 0,
            st_info: info,
            st_other: 0,
            st_shndx: shndx,
            name: name.to_string(),
        }
    }

    #[test]
    fn sym_binding_global() {
        let s = make_sym("f", 0x100, (STB_GLOBAL << 4) | STT_FUNC, 1);
        assert_eq!(s.sym_binding(), SymbolBinding::Global);
    }
    #[test]
    fn sym_binding_local() {
        let s = make_sym("f", 0x100, (STB_LOCAL << 4) | STT_FUNC, 1);
        assert_eq!(s.sym_binding(), SymbolBinding::Local);
    }
    #[test]
    fn sym_binding_weak() {
        let s = make_sym("f", 0x100, (STB_WEAK << 4) | STT_FUNC, 1);
        assert_eq!(s.sym_binding(), SymbolBinding::Weak);
    }
    #[test]
    fn sym_type_func() {
        let s = make_sym("f", 0, (STB_GLOBAL << 4) | STT_FUNC, 1);
        assert_eq!(s.sym_kind(), SymKind::Function);
    }
    #[test]
    fn sym_type_object() {
        let s = make_sym("d", 0, (STB_GLOBAL << 4) | STT_OBJECT, 1);
        assert_eq!(s.sym_kind(), SymKind::Data);
    }
    #[test]
    fn sym_type_tls() {
        let s = make_sym("t", 0, STT_TLS, 1);
        assert_eq!(s.sym_kind(), SymKind::TLS);
    }
    #[test]
    fn sym_type_common() {
        let s = make_sym("c", 0, STT_COMMON, SHN_COMMON);
        assert_eq!(s.sym_kind(), SymKind::Common);
    }
    #[test]
    fn sym_type_section() {
        let s = make_sym("", 0, STT_SECTION, 1);
        assert_eq!(s.sym_kind(), SymKind::Section);
    }
    #[test]
    fn sym_visibility_default() {
        let s = make_sym("f", 0, 0, 0);
        assert_eq!(s.sym_visibility(), SymbolVisibility::Default);
    }
    #[test]
    fn sym_visibility_hidden() {
        let mut s = make_sym("f", 0, 0, 0);
        s.st_other = STV_HIDDEN;
        assert_eq!(s.sym_visibility(), SymbolVisibility::Hidden);
    }
    #[test]
    fn sym_visibility_protected() {
        let mut s = make_sym("f", 0, 0, 0);
        s.st_other = STV_PROTECTED;
        assert_eq!(s.sym_visibility(), SymbolVisibility::Protected);
    }
    #[test]
    fn sym_is_undefined() {
        assert!(make_sym("x", 0, 0, SHN_UNDEF).is_undefined());
    }
    #[test]
    fn sym_is_defined() {
        assert!(make_sym("x", 0x100, (STB_GLOBAL << 4) | STT_FUNC, 1).is_defined());
    }
    #[test]
    fn sym_is_absolute() {
        assert!(make_sym("x", 0x1000, 0, SHN_ABS).is_absolute());
    }
    #[test]
    fn sym_to_symbol() {
        let s = make_sym("main", 0x0040_1000, (STB_GLOBAL << 4) | STT_FUNC, 1);
        let sym = s.to_symbol();
        assert_eq!(sym.name, "main");
        assert_eq!(sym.address, 0x0040_1000);
        assert_eq!(sym.kind, SymKind::Function);
    }
    #[test]
    fn sym_to_symbol_import() {
        let s = make_sym("printf", 0, (STB_GLOBAL << 4) | STT_FUNC, SHN_UNDEF);
        let sym = s.to_symbol();
        assert_eq!(sym.source, LegacySymbolSource::Import);
    }

    #[test]
    fn sym_to_symbol_keeps_real_section_index() {
        let s = make_sym("main", 0x0040_1000, (STB_GLOBAL << 4) | STT_FUNC, 3);
        assert_eq!(s.to_symbol().section_index, Some(3));
    }

    #[test]
    fn sym_to_symbol_drops_reserved_section_indices() {
        // SHN_UNDEF/SHN_ABS/SHN_COMMON are markers, not section-table indices:
        // storing them made `section_index(0)` match every undefined symbol and
        // gave SectionSymbols phantom buckets for 0/0xfff1/0xfff2.
        for shndx in [SHN_UNDEF, SHN_ABS, SHN_COMMON, 0xffff] {
            let s = make_sym("x", 0, (STB_GLOBAL << 4) | STT_FUNC, shndx);
            assert_eq!(
                s.to_symbol().section_index,
                None,
                "shndx {shndx:#x} should not be reported as a section index"
            );
        }
    }

    // ── SymtabParser ──────────────────────────────────────────────────────────

    fn make_elf64_sym_bytes(
        name_off: u32,
        info: u8,
        other: u8,
        shndx: u16,
        value: u64,
        size: u64,
    ) -> Vec<u8> {
        let mut b = Vec::with_capacity(24);
        b.extend_from_slice(&name_off.to_le_bytes());
        b.push(info);
        b.push(other);
        b.extend_from_slice(&shndx.to_le_bytes());
        b.extend_from_slice(&value.to_le_bytes());
        b.extend_from_slice(&size.to_le_bytes());
        b
    }

    #[test]
    fn symtab_parse_elf64_single() {
        let symtab = make_elf64_sym_bytes(0, (STB_GLOBAL << 4) | STT_FUNC, 0, 1, 0x1000, 0x100);
        let strtab = b"main\0";
        let p = SymtabParser::new(&symtab, strtab, true, true);
        let syms = p.parse().unwrap();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "main");
        assert_eq!(syms[0].st_value, 0x1000);
    }
    #[test]
    fn symtab_parse_elf64_multiple() {
        let strtab = b"\0main\0printf\0";
        let mut symtab = make_elf64_sym_bytes(0, STT_NOTYPE, 0, SHN_UNDEF, 0, 0); // null entry
        symtab.extend(make_elf64_sym_bytes(
            1,
            (STB_GLOBAL << 4) | STT_FUNC,
            0,
            1,
            0x1000,
            0x40,
        )); // main
        symtab.extend(make_elf64_sym_bytes(
            6,
            (STB_GLOBAL << 4) | STT_FUNC,
            0,
            SHN_UNDEF,
            0,
            0,
        )); // printf
        let p = SymtabParser::new(&symtab, strtab, true, true);
        let syms = p.parse().unwrap();
        assert_eq!(syms.len(), 3);
        assert_eq!(syms[1].name, "main");
        assert_eq!(syms[2].name, "printf");
    }
    #[test]
    fn symtab_parse_empty() {
        let p = SymtabParser::new(&[], b"\0", true, true);
        assert!(p.parse().unwrap().is_empty());
    }
    #[test]
    fn symtab_parse_truncated() {
        let symtab = vec![0u8; 23]; // not a multiple of 24
        let p = SymtabParser::new(&symtab, b"", true, true);
        assert!(p.parse().is_err());
    }

    // ── ElfSectionInfo ────────────────────────────────────────────────────────

    #[test]
    fn section_contains_offset() {
        let s = ElfSectionInfo::new(1, ".text", 0x1000, 0x100, 0x200, 6);
        assert!(s.contains_offset(0x100));
        assert!(!s.contains_offset(0x400));
    }
    #[test]
    fn section_offset_to_va() {
        let s = ElfSectionInfo::new(1, ".text", 0x0040_1000, 0x100, 0x200, 6);
        assert_eq!(s.offset_to_va(0x150), Some(0x0040_1050));
        assert!(s.offset_to_va(0x400).is_none());
    }

    // ── ElfRelocation ─────────────────────────────────────────────────────────

    #[test]
    fn reloc_new_rel() {
        let r = ElfRelocation::new_rel(0x2000, (5u64 << 32) | u64::from(R_X86_64_JUMP_SLOT));
        assert_eq!(r.r_offset, 0x2000);
        assert_eq!(r.r_sym, 5);
        assert_eq!(r.r_type, R_X86_64_JUMP_SLOT);
        assert_eq!(r.r_addend, 0);
        assert!(!r.is_rela);
    }
    #[test]
    fn reloc_new_rela() {
        let r = ElfRelocation::new_rela(0x3000, (1u64 << 32) | u64::from(R_X86_64_GLOB_DAT), -4);
        assert_eq!(r.r_addend, -4);
        assert!(r.is_rela);
    }
    #[test]
    fn parse_rel64_empty() {
        assert!(parse_rel64(&[]).is_empty());
    }
    #[test]
    fn parse_rel64_single() {
        let mut data = vec![0u8; 16];
        data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        data[8..16].copy_from_slice(&((2u64 << 32) | u64::from(R_X86_64_JUMP_SLOT)).to_le_bytes());
        let relocs = parse_rel64(&data);
        assert_eq!(relocs.len(), 1);
        assert_eq!(relocs[0].r_offset, 0x1000);
        assert_eq!(relocs[0].r_sym, 2);
    }
    #[test]
    fn parse_rela64_single() {
        let mut data = vec![0u8; 24];
        data[0..8].copy_from_slice(&0x2000u64.to_le_bytes());
        data[8..16].copy_from_slice(&((3u64 << 32) | u64::from(R_X86_64_64)).to_le_bytes());
        data[16..24].copy_from_slice(&(-8i64).to_le_bytes());
        let relocs = parse_rela64(&data);
        assert_eq!(relocs.len(), 1);
        assert!(relocs[0].is_rela);
        assert_eq!(relocs[0].r_addend, -8);
    }

    // ── ElfSymbolProvider ─────────────────────────────────────────────────────

    #[test]
    fn provider_new_empty() {
        let p = ElfSymbolProvider::new("libc.so.6");
        assert_eq!(p.symbol_count(), 0);
    }
    #[test]
    fn provider_from_elf_syms() {
        let syms = vec![
            make_sym("main", 0x1000, (STB_GLOBAL << 4) | STT_FUNC, 1),
            make_sym("printf", 0, (STB_GLOBAL << 4) | STT_FUNC, SHN_UNDEF),
        ];
        let p = ElfSymbolProvider::from_elf_syms("test", syms);
        assert_eq!(p.symbol_count(), 2);
        assert_eq!(p.imports().len(), 1);
        assert_eq!(p.defined_symbols().len(), 1);
    }
    #[test]
    fn provider_lookup_name() {
        let p = ElfSymbolProvider::from_elf_syms(
            "t",
            vec![make_sym("foo", 0x100, (STB_GLOBAL << 4) | STT_FUNC, 1)],
        );
        assert!(p.lookup_name("foo").is_some());
        assert!(p.lookup_name("bar").is_none());
    }
    #[test]
    fn provider_lookup_address() {
        let p = ElfSymbolProvider::from_elf_syms(
            "t",
            vec![make_sym("f", 0x400, (STB_GLOBAL << 4) | STT_FUNC, 1)],
        );
        assert!(p.lookup_address(0x400).is_some());
        assert!(p.lookup_address(0x401).is_none());
    }
    #[test]
    fn provider_lookup_nearest() {
        let syms = vec![
            make_sym("a", 0x1000, (STB_GLOBAL << 4) | STT_FUNC, 1),
            make_sym("b", 0x3000, (STB_GLOBAL << 4) | STT_FUNC, 1),
        ];
        let p = ElfSymbolProvider::from_elf_syms("t", syms);
        assert_eq!(p.lookup_nearest(0x2000).unwrap().name, "a");
    }
    #[test]
    fn provider_all_functions() {
        let syms = vec![
            make_sym("f", 0x100, (STB_GLOBAL << 4) | STT_FUNC, 1),
            make_sym("d", 0x200, (STB_GLOBAL << 4) | STT_OBJECT, 1),
        ];
        let p = ElfSymbolProvider::from_elf_syms("t", syms);
        assert_eq!(p.all_functions().len(), 1);
    }
    #[test]
    fn provider_apply_relocations() {
        let mut p = ElfSymbolProvider::new("t");
        p.apply_relocations(vec![ElfRelocation::new_rel(
            0x3000,
            (1u64 << 32) | u64::from(R_X86_64_JUMP_SLOT),
        )]);
        assert_eq!(p.relocation_count(), 1);
    }
    #[test]
    fn provider_resolve_sections() {
        let mut p = ElfSymbolProvider::new("t");
        let sections = vec![ElfSectionInfo::new(1, ".text", 0x1000, 0x100, 0x200, 6)];
        p.resolve_section_addresses(&sections);
        assert_eq!(p.sections().len(), 1);
    }
    #[test]
    fn provider_source_line_none() {
        let p = ElfSymbolProvider::new("t");
        assert!(p.source_line_for_address(0).is_none());
    }
    #[test]
    fn provider_name() {
        let p = ElfSymbolProvider::new("libssl.so.3");
        assert_eq!(p.name(), "libssl.so.3");
    }
    #[test]
    fn provider_parse_elf_invalid() {
        assert!(ElfSymbolProvider::parse_elf("t", b"hello").is_err());
    }
    #[test]
    fn provider_parse_elf_valid_magic() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(ELFMAG);
        data[4] = ELFCLASS64;
        data[5] = ELFDATA2LSB;
        let p = ElfSymbolProvider::parse_elf("t", &data).unwrap();
        // Stub returns empty provider
        assert_eq!(p.symbol_count(), 0);
    }

    // -- Regression: IFUNC kind, and batch index construction ----------------

    fn mk_sym(name: &str, addr: u64, ty: u8) -> ElfSym {
        ElfSym {
            st_name: 0,
            st_value: addr,
            st_size: 0,
            st_info: ty,
            st_other: 0,
            st_shndx: 1,
            name: name.to_string(),
        }
    }

    #[test]
    fn gnu_ifunc_maps_to_ifunc_kind() {
        assert_eq!(mk_sym("memcpy", 0x10, STT_GNU_IFUNC).sym_kind(), SymKind::IFunc);
        // Ordinary functions are unaffected.
        assert_eq!(mk_sym("puts", 0x20, STT_FUNC).sym_kind(), SymKind::Function);
        // `is_function` still covers IFUNC.
        assert!(mk_sym("memcpy", 0x10, STT_GNU_IFUNC).to_symbol().is_function());
    }

    #[test]
    fn from_elf_syms_batch_index_matches_incremental() {
        // Duplicate name: first occurrence must win, as with add_symbol.
        let syms = vec![
            mk_sym("b", 0x200, STT_FUNC),
            mk_sym("a", 0x100, STT_FUNC),
            mk_sym("b", 0x300, STT_FUNC),
        ];

        let batch = ElfSymbolProvider::from_elf_syms("t", syms.clone());
        let mut incremental = ElfSymbolProvider::new("t");
        for s in &syms {
            incremental.add_symbol(s.to_symbol());
        }

        assert_eq!(batch.symbol_count(), 3);
        assert_eq!(batch.lookup_name("b").unwrap().address, 0x200);
        assert_eq!(batch.lookup_name("a").unwrap().address, 0x100);
        assert_eq!(batch.lookup_address(0x300).unwrap().name, "b");
        assert_eq!(
            batch.lookup_nearest(0x250).unwrap().name,
            incremental.lookup_nearest(0x250).unwrap().name
        );
    }

}
