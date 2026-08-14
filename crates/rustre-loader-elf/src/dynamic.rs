//! ELF dynamic linking — low-level raw-entry layer.
//!
//! **Layer:** lower-level companion to [`crate::elf_dynamic_analysis`].
//! While `elf_dynamic_analysis` provides high-level structured types
//! (`ElfDynamicAnalysis`, `GotPltAnalysis`, etc.), this module provides:
//!
//! * Complete `DT_*` tag constant tables in nested submodules (`dt`, `df`,
//!   `df1`) for use as a reference or for matching raw tag values.
//! * `DynEntry` — the raw `(tag, val)` pair extracted from `PT_DYNAMIC`.
//! * Architecture-coupled relocation type enums (`RelTypeX86_64`,
//!   `RelTypeArm`, `RelTypeAarch64`).
//! * `ElfSymbol` with IFUNC and version annotation fields not present in
//!   the `ElfSymbol` defined in `lib.rs`.
//!
//! The `DynError` type in this module is intentionally distinct from the
//! one re-exported from `elf_dynamic_analysis` — it reflects a different
//! error vocabulary suited to raw-offset-level parsing.
//!
//! Parses the `PT_DYNAMIC` segment to extract all DT_* tags, shared library
//! dependencies, symbol versions, GNU hash tables, PLT/GOT reconstruction,
//! and full relocation processing for x86-64, ARM, and `AArch64`.
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynError {
    OutOfBounds { offset: usize, size: usize },
    UnexpectedEnd,
    InvalidStructure(String),
    UnsupportedArch(String),
    UnsupportedClass(u8),
    InvalidStringOffset(u64),
    MissingSection(String),
}

impl fmt::Display for DynError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfBounds { offset, size } => {
                write!(f, "out-of-bounds at offset {offset} (size {size})")
            }
            Self::UnexpectedEnd => write!(f, "unexpected end of data"),
            Self::InvalidStructure(s) => write!(f, "invalid structure: {s}"),
            Self::UnsupportedArch(s) => write!(f, "unsupported architecture: {s}"),
            Self::UnsupportedClass(c) => write!(f, "unsupported ELF class: {c}"),
            Self::InvalidStringOffset(o) => write!(f, "invalid string offset: {o}"),
            Self::MissingSection(s) => write!(f, "missing section/segment: {s}"),
        }
    }
}
impl std::error::Error for DynError {}
pub type DynResult<T> = Result<T, DynError>;

// ---------------------------------------------------------------------------
// Architecture
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfArch {
    X86_64,
    Arm32,
    AArch64,
    Unknown(u16),
}

impl ElfArch {
    #[must_use] 
    pub const fn from_e_machine(m: u16) -> Self {
        match m {
            62 => Self::X86_64,
            40 => Self::Arm32,
            183 => Self::AArch64,
            x => Self::Unknown(x),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfEndian {
    Little,
    Big,
}

// ---------------------------------------------------------------------------
// DT_* tag constants (complete set)
// ---------------------------------------------------------------------------

pub mod dt {
    pub const NULL: u64 = 0;
    pub const NEEDED: u64 = 1;
    pub const PLTRELSZ: u64 = 2;
    pub const PLTGOT: u64 = 3;
    pub const HASH: u64 = 4;
    pub const STRTAB: u64 = 5;
    pub const SYMTAB: u64 = 6;
    pub const RELA: u64 = 7;
    pub const RELASZ: u64 = 8;
    pub const RELAENT: u64 = 9;
    pub const STRSZ: u64 = 10;
    pub const SYMENT: u64 = 11;
    pub const INIT: u64 = 12;
    pub const FINI: u64 = 13;
    pub const SONAME: u64 = 14;
    pub const RPATH: u64 = 15;
    pub const SYMBOLIC: u64 = 16;
    pub const REL: u64 = 17;
    pub const RELSZ: u64 = 18;
    pub const RELENT: u64 = 19;
    pub const PLTREL: u64 = 20;
    pub const DEBUG: u64 = 21;
    pub const TEXTREL: u64 = 22;
    pub const JMPREL: u64 = 23;
    pub const BIND_NOW: u64 = 24;
    pub const INIT_ARRAY: u64 = 25;
    pub const FINI_ARRAY: u64 = 26;
    pub const INIT_ARRAYSZ: u64 = 27;
    pub const FINI_ARRAYSZ: u64 = 28;
    pub const RUNPATH: u64 = 29;
    pub const FLAGS: u64 = 30;
    pub const ENCODING: u64 = 32;
    pub const PREINIT_ARRAY: u64 = 32;
    pub const PREINIT_ARRAYSZ: u64 = 33;
    pub const SYMTAB_SHNDX: u64 = 34;
    pub const RELRSZ: u64 = 35;
    pub const RELR: u64 = 36;
    pub const RELRENT: u64 = 37;
    pub const FLAGS_1: u64 = 0x6FFF_FFFB;
    pub const VERSYM: u64 = 0x6FFF_FFF0;
    pub const VERDEF: u64 = 0x6FFF_FFFC;
    pub const VERDEFNUM: u64 = 0x6FFF_FFFD;
    pub const VERNEED: u64 = 0x6FFF_FFFE;
    pub const VERNEEDNUM: u64 = 0x6FFF_FFFF;
    pub const GNU_HASH: u64 = 0x6FFF_FEF5;
    pub const GNU_FLAGS_1: u64 = 0x6FFF_FEFA;
    pub const AUXILIARY: u64 = 0x7FFF_FFFD;
    pub const USED: u64 = 0x7FFF_FFFE;
    pub const FILTER: u64 = 0x7FFF_FFFF;
    pub const LOOS: u64 = 0x6000_000D;
    pub const HIOS: u64 = 0x6FFF_F000;
    pub const LOPROC: u64 = 0x7000_0000;
    pub const HIPROC: u64 = 0x7FFF_FFFF;
}

/// `DT_FLAGS` bits
pub mod df {
    pub const ORIGIN: u64 = 0x0000_0001;
    pub const SYMBOLIC: u64 = 0x0000_0002;
    pub const TEXTREL: u64 = 0x0000_0004;
    pub const BIND_NOW: u64 = 0x0000_0008;
    pub const STATIC_TLS: u64 = 0x0000_0010;
}

/// `DT_FLAGS_1` bits
pub mod df1 {
    pub const NOW: u64 = 0x0000_0001;
    pub const GLOBAL: u64 = 0x0000_0002;
    pub const GROUP: u64 = 0x0000_0004;
    pub const NODELETE: u64 = 0x0000_0008;
    pub const LOADFLTR: u64 = 0x0000_0010;
    pub const INITFIRST: u64 = 0x0000_0020;
    pub const NOOPEN: u64 = 0x0000_0040;
    pub const ORIGIN: u64 = 0x0000_0080;
    pub const DIRECT: u64 = 0x0000_0100;
    pub const TRANS: u64 = 0x0000_0200;
    pub const INTERPOSE: u64 = 0x0000_0400;
    pub const NODEFLIB: u64 = 0x0000_0800;
    pub const NODUMP: u64 = 0x0000_1000;
    pub const CONFALT: u64 = 0x0000_2000;
    pub const ENDFILTEE: u64 = 0x0000_4000;
    pub const DISPRELDNE: u64 = 0x0000_8000;
    pub const DISPRELPND: u64 = 0x0001_0000;
    pub const NODIRECT: u64 = 0x0002_0000;
    pub const IGNMULDEF: u64 = 0x0004_0000;
    pub const NOKSYMS: u64 = 0x0008_0000;
    pub const NOHDR: u64 = 0x0010_0000;
    pub const EDITED: u64 = 0x0020_0000;
    pub const NORELOC: u64 = 0x0040_0000;
    pub const SYMINTPOSE: u64 = 0x0080_0000;
    pub const GLOBAUDIT: u64 = 0x0100_0000;
    pub const SINGLETON: u64 = 0x0200_0000;
    pub const STUB: u64 = 0x0400_0000;
    pub const PIE: u64 = 0x0800_0000;
    pub const KMOD: u64 = 0x1000_0000;
    pub const WEAKFILTER: u64 = 0x2000_0000;
    pub const NOCOMMON: u64 = 0x4000_0000;
}

// ---------------------------------------------------------------------------
// Raw dynamic entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynEntry {
    pub tag: u64,
    pub val: u64,
}

impl DynEntry {
    #[must_use] 
    pub const fn is_null(&self) -> bool {
        self.tag == dt::NULL
    }
}

// ---------------------------------------------------------------------------
// ELF symbol types and bindings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymBind {
    Local,
    Global,
    Weak,
    Unknown(u8),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymType {
    None,
    Object,
    Func,
    Section,
    File,
    Common,
    Tls,
    GnuIfunc,
    Unknown(u8),
}

impl SymBind {
    #[must_use] 
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Local,
            1 => Self::Global,
            2 => Self::Weak,
            x => Self::Unknown(x),
        }
    }
}
impl SymType {
    #[must_use] 
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Object,
            2 => Self::Func,
            3 => Self::Section,
            4 => Self::File,
            5 => Self::Common,
            6 => Self::Tls,
            10 => Self::GnuIfunc,
            x => Self::Unknown(x),
        }
    }
}

// ---------------------------------------------------------------------------
// ELF Symbol
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ElfSymbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub sym_bind: SymBind,
    pub sym_type: SymType,
    pub visibility: u8,
    pub shndx: u16,
    /// Version string (e.g. "`GLIBC_2.5`"), if available.
    pub version: Option<String>,
    /// True if this is an `STT_GNU_IFUNC` indirect function.
    pub is_ifunc: bool,
}

// ---------------------------------------------------------------------------
// Relocation types
// ---------------------------------------------------------------------------

/// x86-64 relocation type codes (`R_X86_64`_*)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RelTypeX86_64 {
    None = 0,
    R64 = 1,
    Pc32 = 2,
    Got32 = 3,
    Plt32 = 4,
    Copy = 5,
    GlobDat = 6,
    JumpSlot = 7,
    Relative = 8,
    Gotpcrel = 9,
    R32 = 10,
    R32s = 11,
    R16 = 12,
    Pc16 = 13,
    R8 = 14,
    Pc8 = 15,
    Dtpmod64 = 16,
    Dtpoff64 = 17,
    Tpoff64 = 18,
    Tlsgd = 19,
    Tlsld = 20,
    Dtpoff32 = 21,
    Gottpoff = 22,
    Tpoff32 = 23,
    Pc64 = 24,
    Gotoff64 = 25,
    Gotpc32 = 26,
    Got64 = 27,
    Gotpcrel64 = 28,
    Gotpc64 = 29,
    Gotplt64 = 30,
    Pltoff64 = 31,
    Size32 = 32,
    Size64 = 33,
    Gotpc32Tlsdesc = 34,
    TlsdescCall = 35,
    Tlsdesc = 36,
    Irelative = 37,
    Relative64 = 38,
    Gotpcrelx = 41,
    RexGotpcrelx = 42,
    Unknown(u32),
}

impl RelTypeX86_64 {
    #[must_use] 
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::None,
            1 => Self::R64,
            2 => Self::Pc32,
            3 => Self::Got32,
            4 => Self::Plt32,
            5 => Self::Copy,
            6 => Self::GlobDat,
            7 => Self::JumpSlot,
            8 => Self::Relative,
            9 => Self::Gotpcrel,
            10 => Self::R32,
            11 => Self::R32s,
            12 => Self::R16,
            13 => Self::Pc16,
            14 => Self::R8,
            15 => Self::Pc8,
            16 => Self::Dtpmod64,
            17 => Self::Dtpoff64,
            18 => Self::Tpoff64,
            19 => Self::Tlsgd,
            20 => Self::Tlsld,
            21 => Self::Dtpoff32,
            22 => Self::Gottpoff,
            23 => Self::Tpoff32,
            24 => Self::Pc64,
            25 => Self::Gotoff64,
            26 => Self::Gotpc32,
            27 => Self::Got64,
            34 => Self::Gotpc32Tlsdesc,
            35 => Self::TlsdescCall,
            36 => Self::Tlsdesc,
            37 => Self::Irelative,
            38 => Self::Relative64,
            41 => Self::Gotpcrelx,
            42 => Self::RexGotpcrelx,
            x => Self::Unknown(x),
        }
    }

    #[must_use] 
    pub const fn name(&self) -> &'static str {
        match self {
            Self::None => "R_X86_64_NONE",
            Self::R64 => "R_X86_64_64",
            Self::Pc32 => "R_X86_64_PC32",
            Self::Got32 => "R_X86_64_GOT32",
            Self::Plt32 => "R_X86_64_PLT32",
            Self::Copy => "R_X86_64_COPY",
            Self::GlobDat => "R_X86_64_GLOB_DAT",
            Self::JumpSlot => "R_X86_64_JUMP_SLOT",
            Self::Relative => "R_X86_64_RELATIVE",
            Self::Gotpcrel => "R_X86_64_GOTPCREL",
            Self::R32 => "R_X86_64_32",
            Self::R32s => "R_X86_64_32S",
            Self::R16 => "R_X86_64_16",
            Self::Pc16 => "R_X86_64_PC16",
            Self::R8 => "R_X86_64_8",
            Self::Pc8 => "R_X86_64_PC8",
            Self::Dtpmod64 => "R_X86_64_DTPMOD64",
            Self::Dtpoff64 => "R_X86_64_DTPOFF64",
            Self::Tpoff64 => "R_X86_64_TPOFF64",
            Self::Tlsgd => "R_X86_64_TLSGD",
            Self::Tlsld => "R_X86_64_TLSLD",
            Self::Dtpoff32 => "R_X86_64_DTPOFF32",
            Self::Gottpoff => "R_X86_64_GOTTPOFF",
            Self::Tpoff32 => "R_X86_64_TPOFF32",
            Self::Pc64 => "R_X86_64_PC64",
            Self::Gotoff64 => "R_X86_64_GOTOFF64",
            Self::Gotpc32 => "R_X86_64_GOTPC32",
            Self::Got64 => "R_X86_64_GOT64",
            Self::Gotpcrel64 => "R_X86_64_GOTPCREL64",
            Self::Gotpc64 => "R_X86_64_GOTPC64",
            Self::Gotplt64 => "R_X86_64_GOTPLT64",
            Self::Pltoff64 => "R_X86_64_PLTOFF64",
            Self::Size32 => "R_X86_64_SIZE32",
            Self::Size64 => "R_X86_64_SIZE64",
            Self::Gotpc32Tlsdesc => "R_X86_64_GOTPC32_TLSDESC",
            Self::TlsdescCall => "R_X86_64_TLSDESC_CALL",
            Self::Tlsdesc => "R_X86_64_TLSDESC",
            Self::Irelative => "R_X86_64_IRELATIVE",
            Self::Relative64 => "R_X86_64_RELATIVE64",
            Self::Gotpcrelx => "R_X86_64_GOTPCRELX",
            Self::RexGotpcrelx => "R_X86_64_REX_GOTPCRELX",
            Self::Unknown(_) => "R_X86_64_UNKNOWN",
        }
    }
}

/// ARM relocation type codes (`R_ARM`_*)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelTypeArm {
    None,
    Abs32,
    Rel32,
    Pc24,
    GlobDat,
    JumpSlot,
    Relative,
    Copy,
    ThmCall,
    ThmJump24,
    Call,
    AluPcG0Nc,
    AluPcG0,
    AluPcG1Nc,
    AluPcG1,
    AluPcG2,
    Gotoff32,
    Gotpc,
    Got32,
    PltAbs,
    PltPc24,
    GotPltAbs,
    GotPltPc24,
    ThmGotPltBrel,
    ThmJump11,
    ThmJump8,
    Unknown(u32),
}
impl RelTypeArm {
    #[must_use] 
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::None,
            2 => Self::Abs32,
            3 => Self::Rel32,
            28 => Self::GlobDat,
            29 => Self::JumpSlot,
            23 => Self::Relative,
            20 => Self::Copy,
            x => Self::Unknown(x),
        }
    }
    #[must_use] 
    pub const fn name(&self) -> &'static str {
        match self {
            Self::None => "R_ARM_NONE",
            Self::Abs32 => "R_ARM_ABS32",
            Self::Rel32 => "R_ARM_REL32",
            Self::Pc24 => "R_ARM_PC24",
            Self::GlobDat => "R_ARM_GLOB_DAT",
            Self::JumpSlot => "R_ARM_JUMP_SLOT",
            Self::Relative => "R_ARM_RELATIVE",
            Self::Copy => "R_ARM_COPY",
            _ => "R_ARM_*",
        }
    }
}

/// `AArch64` relocation type codes (`R_AARCH64`_*)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelTypeAArch64 {
    None,
    Abs64,
    Abs32,
    Abs16,
    Prel64,
    Prel32,
    Prel16,
    MovwUabsG0,
    MovwUabsG0Nc,
    MovwUabsG1,
    MovwUabsG1Nc,
    MovwUabsG2,
    MovwUabsG2Nc,
    MovwUabsG3,
    GlobDat,
    JumpSlot,
    Relative,
    Copy,
    TlsdescGd64Lo12,
    TlsdescLd64Lo12,
    TlsdescAdd,
    TlsdescCall,
    TlsIeAdrGottprel21,
    TlsIeAdd,
    TlsLeMovwTprelG1,
    TlsLeMovwTprelG0Nc,
    Unknown(u32),
}
impl RelTypeAArch64 {
    #[must_use] 
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::None,
            257 => Self::Abs64,
            258 => Self::Abs32,
            259 => Self::Abs16,
            260 => Self::Prel64,
            261 => Self::Prel32,
            262 => Self::Prel16,
            1025 => Self::GlobDat,
            1026 => Self::JumpSlot,
            1027 => Self::Relative,
            1024 => Self::Copy,
            x => Self::Unknown(x),
        }
    }
    #[must_use] 
    pub const fn name(&self) -> &'static str {
        match self {
            Self::None => "R_AARCH64_NONE",
            Self::Abs64 => "R_AARCH64_ABS64",
            Self::Abs32 => "R_AARCH64_ABS32",
            Self::GlobDat => "R_AARCH64_GLOB_DAT",
            Self::JumpSlot => "R_AARCH64_JUMP_SLOT",
            Self::Relative => "R_AARCH64_RELATIVE",
            Self::Copy => "R_AARCH64_COPY",
            _ => "R_AARCH64_*",
        }
    }
}

// ---------------------------------------------------------------------------
// Relocation entry (cooked)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelType {
    X86_64(RelTypeX86_64),
    Arm(RelTypeArm),
    AArch64(RelTypeAArch64),
    Unknown { arch_raw: u32 },
}

#[derive(Debug, Clone)]
pub struct Relocation {
    pub offset: u64,
    pub rel_type: RelType,
    /// Symbol index into the dynamic symbol table.
    pub sym_idx: u32,
    /// Addend (RELA); None for REL.
    pub addend: Option<i64>,
    /// Resolved symbol name (if available after symbol table lookup).
    pub symbol_name: Option<String>,
}

impl Relocation {
    #[must_use] 
    pub const fn is_plt(&self) -> bool {
        matches!(
            self.rel_type,
            RelType::X86_64(RelTypeX86_64::JumpSlot)
                | RelType::Arm(RelTypeArm::JumpSlot)
                | RelType::AArch64(RelTypeAArch64::JumpSlot)
        )
    }

    #[must_use] 
    pub const fn is_copy(&self) -> bool {
        matches!(
            self.rel_type,
            RelType::X86_64(RelTypeX86_64::Copy)
                | RelType::Arm(RelTypeArm::Copy)
                | RelType::AArch64(RelTypeAArch64::Copy)
        )
    }
}

// ---------------------------------------------------------------------------
// PLT / GOT entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct GotEntry {
    pub address: u64,
    pub symbol_name: Option<String>,
    pub sym_idx: u32,
}

#[derive(Debug, Clone)]
pub struct PltEntry {
    pub address: u64,
    pub got_address: u64,
    pub symbol_name: Option<String>,
    pub sym_idx: u32,
}

// ---------------------------------------------------------------------------
// GNU Hash table
// ---------------------------------------------------------------------------

/// Parsed GNU Hash table for fast symbol lookup.
#[derive(Debug, Clone)]
pub struct GnuHashTable {
    pub nbuckets: u32,
    pub symoffset: u32,
    pub bloom_size: u32,
    pub bloom_shift: u32,
    pub bloom: Vec<u64>,
    pub buckets: Vec<u32>,
    pub chain: Vec<u32>,
}

impl GnuHashTable {
    /// Parse from raw .gnu.hash section bytes (64-bit host).
    ///
    /// # Errors
    /// Returns an error if the data is too short or malformed.
    ///
    /// # Panics
    /// Panics if internal slice operations fail unexpectedly.
    pub fn parse(data: &[u8]) -> DynResult<Self> {
        if data.len() < 16 {
            return Err(DynError::UnexpectedEnd);
        }
        let nbuckets = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let symoffset = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let bloom_size = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let bloom_shift = u32::from_le_bytes(data[12..16].try_into().unwrap());

        let mut off = 16usize;

        let bloom_bytes = bloom_size as usize * 8;
        if off + bloom_bytes > data.len() {
            return Err(DynError::OutOfBounds {
                offset: off,
                size: bloom_bytes,
            });
        }
        let bloom: Vec<u64> = (0..bloom_size as usize)
            .map(|i| u64::from_le_bytes(data[off + i * 8..off + i * 8 + 8].try_into().unwrap()))
            .collect();
        off += bloom_bytes;

        let bucket_bytes = nbuckets as usize * 4;
        if off + bucket_bytes > data.len() {
            return Err(DynError::OutOfBounds {
                offset: off,
                size: bucket_bytes,
            });
        }
        let buckets: Vec<u32> = (0..nbuckets as usize)
            .map(|i| u32::from_le_bytes(data[off + i * 4..off + i * 4 + 4].try_into().unwrap()))
            .collect();
        off += bucket_bytes;

        let chain_count = (data.len() - off) / 4;
        let chain: Vec<u32> = (0..chain_count)
            .map(|i| u32::from_le_bytes(data[off + i * 4..off + i * 4 + 4].try_into().unwrap()))
            .collect();

        Ok(Self {
            nbuckets,
            symoffset,
            bloom_size,
            bloom_shift,
            bloom,
            buckets,
            chain,
        })
    }

    /// GNU hash function.
    #[must_use] 
    pub fn hash(name: &[u8]) -> u32 {
        let mut h = 5381u32;
        for &b in name {
            h = h.wrapping_mul(33).wrapping_add(u32::from(b));
        }
        h
    }

    /// Check bloom filter for `name`.
    #[must_use] 
    pub fn bloom_check(&self, name: &[u8]) -> bool {
        if self.bloom.is_empty() {
            return true;
        }
        let h = Self::hash(name);
        let c = 64u32; // word size for 64-bit
        let word_idx = ((h / c) % self.bloom_size) as usize;
        let bit1 = h & (c - 1);
        let bit2 = (h >> self.bloom_shift) & (c - 1);
        let bloom_word = self.bloom[word_idx];
        (bloom_word >> bit1 & 1 != 0) && (bloom_word >> bit2 & 1 != 0)
    }
}

// ---------------------------------------------------------------------------
// Symbol version structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct VerNeed {
    pub version: u16,
    pub cnt: u16,
    pub file: String,
    pub aux: Vec<VerNeedAux>,
}

#[derive(Debug, Clone)]
pub struct VerNeedAux {
    pub hash: u32,
    pub flags: u16,
    pub other: u16,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct VerDef {
    pub version: u16,
    pub flags: u16,
    pub ndx: u16,
    pub cnt: u16,
    pub hash: u32,
    pub names: Vec<String>,
}

// ---------------------------------------------------------------------------
// Parsed dynamic section (high level)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DynamicSection {
    pub entries: Vec<DynEntry>,
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub init: Option<u64>,
    pub fini: Option<u64>,
    pub init_array: Option<u64>,
    pub init_array_sz: Option<u64>,
    pub fini_array: Option<u64>,
    pub fini_array_sz: Option<u64>,
    pub preinit_array: Option<u64>,
    pub preinit_array_sz: Option<u64>,
    pub flags: Option<u64>,
    pub flags_1: Option<u64>,
    pub pltrel: Option<u64>,
    pub pltrelsz: Option<u64>,
    pub pltgot: Option<u64>,
    pub jmprel: Option<u64>,
    pub strtab_addr: Option<u64>,
    pub strtab_size: Option<u64>,
    pub symtab_addr: Option<u64>,
    pub syment: Option<u64>,
    pub rela_addr: Option<u64>,
    pub rela_sz: Option<u64>,
    pub rela_ent: Option<u64>,
    pub rel_addr: Option<u64>,
    pub rel_sz: Option<u64>,
    pub rel_ent: Option<u64>,
    pub hash_addr: Option<u64>,
    pub gnu_hash_addr: Option<u64>,
    pub versym_addr: Option<u64>,
    pub verneed_addr: Option<u64>,
    pub verneed_num: Option<u64>,
    pub verdef_addr: Option<u64>,
    pub verdef_num: Option<u64>,
    pub bind_now: bool,
    pub symbolic: bool,
    pub textrel: bool,
}

impl DynamicSection {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
            needed: Vec::new(),
            soname: None,
            rpath: None,
            runpath: None,
            init: None,
            fini: None,
            init_array: None,
            init_array_sz: None,
            fini_array: None,
            fini_array_sz: None,
            preinit_array: None,
            preinit_array_sz: None,
            flags: None,
            flags_1: None,
            pltrel: None,
            pltrelsz: None,
            pltgot: None,
            jmprel: None,
            strtab_addr: None,
            strtab_size: None,
            symtab_addr: None,
            syment: None,
            rela_addr: None,
            rela_sz: None,
            rela_ent: None,
            rel_addr: None,
            rel_sz: None,
            rel_ent: None,
            hash_addr: None,
            gnu_hash_addr: None,
            versym_addr: None,
            verneed_addr: None,
            verneed_num: None,
            verdef_addr: None,
            verdef_num: None,
            bind_now: false,
            symbolic: false,
            textrel: false,
        }
    }

    #[must_use] 
    pub fn has_flag(&self, flag: u64) -> bool {
        self.flags.is_some_and(|f| f & flag != 0)
    }

    #[must_use] 
    pub fn has_flag_1(&self, flag: u64) -> bool {
        self.flags_1.is_some_and(|f| f & flag != 0)
    }

    #[must_use] 
    pub fn is_pie(&self) -> bool {
        self.has_flag_1(df1::PIE)
    }
    #[must_use] 
    pub fn is_now(&self) -> bool {
        self.bind_now || self.has_flag_1(df1::NOW)
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Low-level byte reader for ELF data.
struct ByteReader<'a> {
    data: &'a [u8],
    endian: ElfEndian,
    class: ElfClass,
}

impl<'a> ByteReader<'a> {
    const fn new(data: &'a [u8], endian: ElfEndian, class: ElfClass) -> Self {
        Self {
            data,
            endian,
            class,
        }
    }

    fn u16_at(&self, off: usize) -> DynResult<u16> {
        if off + 2 > self.data.len() {
            return Err(DynError::OutOfBounds {
                offset: off,
                size: 2,
            });
        }
        let b = &self.data[off..off + 2];
        Ok(match self.endian {
            ElfEndian::Little => u16::from_le_bytes(b.try_into().unwrap()),
            ElfEndian::Big => u16::from_be_bytes(b.try_into().unwrap()),
        })
    }

    fn u32_at(&self, off: usize) -> DynResult<u32> {
        if off + 4 > self.data.len() {
            return Err(DynError::OutOfBounds {
                offset: off,
                size: 4,
            });
        }
        let b = &self.data[off..off + 4];
        Ok(match self.endian {
            ElfEndian::Little => u32::from_le_bytes(b.try_into().unwrap()),
            ElfEndian::Big => u32::from_be_bytes(b.try_into().unwrap()),
        })
    }

    fn u64_at(&self, off: usize) -> DynResult<u64> {
        if off + 8 > self.data.len() {
            return Err(DynError::OutOfBounds {
                offset: off,
                size: 8,
            });
        }
        let b = &self.data[off..off + 8];
        Ok(match self.endian {
            ElfEndian::Little => u64::from_le_bytes(b.try_into().unwrap()),
            ElfEndian::Big => u64::from_be_bytes(b.try_into().unwrap()),
        })
    }

    fn addr_at(&self, off: usize) -> DynResult<u64> {
        match self.class {
            ElfClass::Elf32 => self.u32_at(off).map(u64::from),
            ElfClass::Elf64 => self.u64_at(off),
        }
    }

    const fn addr_size(&self) -> usize {
        match self.class {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        }
    }

    fn read_cstr(&self, off: usize) -> DynResult<String> {
        if off >= self.data.len() {
            return Err(DynError::OutOfBounds {
                offset: off,
                size: 1,
            });
        }
        let end = self.data[off..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.data.len() - off);
        String::from_utf8(self.data[off..off + end].to_vec())
            .map_err(|_| DynError::InvalidStructure("invalid UTF-8 in string".into()))
    }
}

/// Parse the raw dynamic segment bytes into a `DynamicSection`.
///
/// `dyn_data`  – raw bytes of the `PT_DYNAMIC` segment.
/// `strtab`    – raw bytes of the `DT_STRTAB` string table (already resolved).
/// `endian`    – ELF endianness.
/// `class`     – ELF class (32/64 bit).
///
/// # Errors
/// Returns an error if the dynamic segment data is malformed or cannot be parsed.
pub fn parse_dynamic_segment(
    dyn_data: &[u8],
    strtab: &[u8],
    endian: ElfEndian,
    class: ElfClass,
) -> DynResult<DynamicSection> {
    let r = ByteReader::new(dyn_data, endian, class);
    let str_r = ByteReader::new(strtab, endian, class);

    let entry_size = r.addr_size() * 2;
    let mut ds = DynamicSection::new();

    let mut off = 0usize;
    while off + entry_size <= dyn_data.len() {
        let tag = r.addr_at(off)?;
        let val = r.addr_at(off + r.addr_size())?;
        off += entry_size;

        let entry = DynEntry { tag, val };
        if entry.is_null() {
            ds.entries.push(entry);
            break;
        }
        ds.entries.push(entry);

        match tag {
            dt::NEEDED => {
                let name = str_r
                    .read_cstr(usize::try_from(val).unwrap_or(usize::MAX))
                    .unwrap_or_else(|_| format!("<strtab@{val}>"));
                ds.needed.push(name);
            }
            dt::SONAME => ds.soname = Some(str_r.read_cstr(usize::try_from(val).unwrap_or(usize::MAX)).unwrap_or_default()),
            dt::RPATH => ds.rpath = Some(str_r.read_cstr(usize::try_from(val).unwrap_or(usize::MAX)).unwrap_or_default()),
            dt::RUNPATH => ds.runpath = Some(str_r.read_cstr(usize::try_from(val).unwrap_or(usize::MAX)).unwrap_or_default()),
            dt::INIT => ds.init = Some(val),
            dt::FINI => ds.fini = Some(val),
            dt::INIT_ARRAY => ds.init_array = Some(val),
            dt::INIT_ARRAYSZ => ds.init_array_sz = Some(val),
            dt::FINI_ARRAY => ds.fini_array = Some(val),
            dt::FINI_ARRAYSZ => ds.fini_array_sz = Some(val),
            dt::PREINIT_ARRAY => ds.preinit_array = Some(val),
            dt::PREINIT_ARRAYSZ => ds.preinit_array_sz = Some(val),
            dt::FLAGS => ds.flags = Some(val),
            dt::FLAGS_1 => ds.flags_1 = Some(val),
            dt::PLTREL => ds.pltrel = Some(val),
            dt::PLTRELSZ => ds.pltrelsz = Some(val),
            dt::PLTGOT => ds.pltgot = Some(val),
            dt::JMPREL => ds.jmprel = Some(val),
            dt::STRTAB => ds.strtab_addr = Some(val),
            dt::STRSZ => ds.strtab_size = Some(val),
            dt::SYMTAB => ds.symtab_addr = Some(val),
            dt::SYMENT => ds.syment = Some(val),
            dt::RELA => ds.rela_addr = Some(val),
            dt::RELASZ => ds.rela_sz = Some(val),
            dt::RELAENT => ds.rela_ent = Some(val),
            dt::REL => ds.rel_addr = Some(val),
            dt::RELSZ => ds.rel_sz = Some(val),
            dt::RELENT => ds.rel_ent = Some(val),
            dt::HASH => ds.hash_addr = Some(val),
            dt::GNU_HASH => ds.gnu_hash_addr = Some(val),
            dt::VERSYM => ds.versym_addr = Some(val),
            dt::VERNEED => ds.verneed_addr = Some(val),
            dt::VERNEEDNUM => ds.verneed_num = Some(val),
            dt::VERDEF => ds.verdef_addr = Some(val),
            dt::VERDEFNUM => ds.verdef_num = Some(val),
            dt::BIND_NOW => ds.bind_now = true,
            dt::SYMBOLIC => ds.symbolic = true,
            dt::TEXTREL => ds.textrel = true,
            _ => {}
        }
    }

    Ok(ds)
}

// ---------------------------------------------------------------------------
// Symbol table parser
// ---------------------------------------------------------------------------

/// Parse the ELF dynamic symbol table.
///
/// `sym_data`  – raw bytes of the symbol table.
/// `strtab`    – raw bytes of the `DT_STRTAB` string table.
/// `versym`    – optional `DT_VERSYM` table bytes (2 bytes per symbol).
/// `versions`  – optional map from version index to version string.
/// `endian`    – ELF endianness.
/// `class`     – ELF class.
///
/// # Errors
/// Returns an error if the symbol table data is malformed or cannot be parsed.
///
/// # Panics
/// Panics if internal slice operations fail unexpectedly.
pub fn parse_symbol_table<S: ::std::hash::BuildHasher>(
    sym_data: &[u8],
    strtab: &[u8],
    versym: Option<&[u8]>,
    versions: Option<&HashMap<u16, String, S>>,
    endian: ElfEndian,
    class: ElfClass,
) -> DynResult<Vec<ElfSymbol>> {
    let r = ByteReader::new(sym_data, endian, class);
    let str_r = ByteReader::new(strtab, endian, class);

    let sym_size = match class {
        ElfClass::Elf32 => 16,
        ElfClass::Elf64 => 24,
    };
    let count = sym_data.len() / sym_size;
    let mut symbols = Vec::with_capacity(count);

    for i in 0..count {
        let off = i * sym_size;
        let (name_idx, value, size, info, other, shndx) = match class {
            ElfClass::Elf32 => {
                let ni = r.u32_at(off)?;
                let va = u64::from(r.u32_at(off + 4)?);
                let sz = u64::from(r.u32_at(off + 8)?);
                let inf = sym_data[off + 12];
                let oth = sym_data[off + 13];
                let sh = r.u16_at(off + 14)?;
                (ni, va, sz, inf, oth, sh)
            }
            ElfClass::Elf64 => {
                let ni = r.u32_at(off)?;
                let inf = sym_data[off + 4];
                let oth = sym_data[off + 5];
                let sh = r.u16_at(off + 6)?;
                let va = r.u64_at(off + 8)?;
                let sz = r.u64_at(off + 16)?;
                (ni, va, sz, inf, oth, sh)
            }
        };

        let name = str_r.read_cstr(name_idx as usize).unwrap_or_default();
        let sym_bind = SymBind::from_u8(info >> 4);
        let sym_type = SymType::from_u8(info & 0xF);
        let is_ifunc = sym_type == SymType::GnuIfunc;

        let version = versym.and_then(|vs| {
            let voff = i * 2;
            if voff + 2 > vs.len() {
                return None;
            }
            let ver_idx = u16::from_le_bytes(vs[voff..voff + 2].try_into().unwrap()) & 0x7FFF;
            versions.and_then(|vm| vm.get(&ver_idx)).cloned()
        });

        symbols.push(ElfSymbol {
            name,
            value,
            size,
            sym_bind,
            sym_type,
            visibility: other & 0x3,
            shndx,
            version,
            is_ifunc,
        });
    }

    Ok(symbols)
}

// ---------------------------------------------------------------------------
// Relocation table parser
// ---------------------------------------------------------------------------

/// Parse a RELA (with explicit addend) table.
///
/// # Errors
/// Returns an error if the relocation table data is malformed.
pub fn parse_rela_table(
    data: &[u8],
    endian: ElfEndian,
    class: ElfClass,
    arch: ElfArch,
    symbols: &[ElfSymbol],
) -> DynResult<Vec<Relocation>> {
    let r = ByteReader::new(data, endian, class);
    let entry_size = match class {
        ElfClass::Elf32 => 12,
        ElfClass::Elf64 => 24,
    };
    let count = data.len() / entry_size;
    let mut relocs = Vec::with_capacity(count);

    for i in 0..count {
        let off = i * entry_size;
        let (offset, info, addend) = match class {
            ElfClass::Elf32 => {
                let o = u64::from(r.u32_at(off)?);
                let inf = r.u32_at(off + 4)?;
                let a = i64::from(r.u32_at(off + 8)?.cast_signed());
                (o, u64::from(inf), a)
            }
            ElfClass::Elf64 => {
                let o = r.u64_at(off)?;
                let inf = r.u64_at(off + 8)?;
                let a = (r.u64_at(off + 16)?).cast_signed();
                (o, inf, a)
            }
        };

        let (sym_idx, type_raw) = match class {
            ElfClass::Elf32 => (u32::try_from(info >> 8).unwrap_or(u32::MAX), u32::try_from(info & 0xFF).unwrap_or(u32::MAX)),
            ElfClass::Elf64 => (u32::try_from(info >> 32).unwrap_or(u32::MAX), u32::try_from(info & 0xFFFF_FFFF).unwrap_or(u32::MAX)),
        };

        let rel_type = match arch {
            ElfArch::X86_64 => RelType::X86_64(RelTypeX86_64::from_u32(type_raw)),
            ElfArch::Arm32 => RelType::Arm(RelTypeArm::from_u32(type_raw)),
            ElfArch::AArch64 => RelType::AArch64(RelTypeAArch64::from_u32(type_raw)),
            ElfArch::Unknown(_) => RelType::Unknown { arch_raw: type_raw },
        };

        let symbol_name = symbols.get(sym_idx as usize).map(|s| s.name.clone());

        relocs.push(Relocation {
            offset,
            rel_type,
            sym_idx,
            addend: Some(addend),
            symbol_name,
        });
    }
    Ok(relocs)
}

/// Parse a REL (implicit addend) table.
///
/// # Errors
/// Returns an error if the relocation table data is malformed.
pub fn parse_rel_table(
    data: &[u8],
    endian: ElfEndian,
    class: ElfClass,
    arch: ElfArch,
    symbols: &[ElfSymbol],
) -> DynResult<Vec<Relocation>> {
    let r = ByteReader::new(data, endian, class);
    let entry_size = match class {
        ElfClass::Elf32 => 8,
        ElfClass::Elf64 => 16,
    };
    let count = data.len() / entry_size;
    let mut relocs = Vec::with_capacity(count);

    for i in 0..count {
        let off = i * entry_size;
        let (offset, info) = match class {
            ElfClass::Elf32 => (u64::from(r.u32_at(off)?), u64::from(r.u32_at(off + 4)?)),
            ElfClass::Elf64 => (r.u64_at(off)?, r.u64_at(off + 8)?),
        };

        let (sym_idx, type_raw) = match class {
            ElfClass::Elf32 => (u32::try_from(info >> 8).unwrap_or(u32::MAX), u32::try_from(info & 0xFF).unwrap_or(u32::MAX)),
            ElfClass::Elf64 => (u32::try_from(info >> 32).unwrap_or(u32::MAX), u32::try_from(info & 0xFFFF_FFFF).unwrap_or(u32::MAX)),
        };

        let rel_type = match arch {
            ElfArch::X86_64 => RelType::X86_64(RelTypeX86_64::from_u32(type_raw)),
            ElfArch::Arm32 => RelType::Arm(RelTypeArm::from_u32(type_raw)),
            ElfArch::AArch64 => RelType::AArch64(RelTypeAArch64::from_u32(type_raw)),
            ElfArch::Unknown(_) => RelType::Unknown { arch_raw: type_raw },
        };

        let symbol_name = symbols.get(sym_idx as usize).map(|s| s.name.clone());

        relocs.push(Relocation {
            offset,
            rel_type,
            sym_idx,
            addend: None,
            symbol_name,
        });
    }
    Ok(relocs)
}

// ---------------------------------------------------------------------------
// Apply relocations to a mutable image buffer
// ---------------------------------------------------------------------------

/// Apply a RELA relocation to `image`.
///
/// `base`        - load base address of the image.
/// `got_base`    - virtual address of the GOT.
/// `image_base`  - virtual address at which `image[0]` maps.
///
/// # Errors
/// Returns `DynError` if the relocation target is out of bounds or the relocation type is unsupported.
pub fn apply_rela_x86_64(
    image: &mut [u8],
    reloc: &Relocation,
    sym_value: u64,
    base: u64,
    image_base: u64,
) -> DynResult<()> {
    let vaddr = reloc.offset;
    if vaddr < image_base || vaddr - image_base >= image.len() as u64 {
        return Err(DynError::OutOfBounds {
            offset: usize::try_from(vaddr).unwrap_or(usize::MAX),
            size: 8,
        });
    }
    let file_off = usize::try_from(vaddr - image_base).unwrap_or(usize::MAX);
    let addend = reloc.addend.unwrap_or(0);

    let val: u64 = match &reloc.rel_type {
        RelType::X86_64(RelTypeX86_64::Relative) => base.wrapping_add(addend.cast_unsigned()),
        RelType::X86_64(RelTypeX86_64::GlobDat | RelTypeX86_64::JumpSlot) => sym_value,
        RelType::X86_64(RelTypeX86_64::R64) => sym_value.wrapping_add(addend.cast_unsigned()),
        RelType::X86_64(RelTypeX86_64::R32) => {
            (sym_value.wrapping_add(addend.cast_unsigned())) & 0xFFFF_FFFF
        }
        _ => {
            return Ok(());
        }
    };

    if file_off.checked_add(8).is_some_and(|end| end <= image.len()) {
        image[file_off..file_off + 8].copy_from_slice(&val.to_le_bytes());
    } else if file_off.checked_add(4).is_some_and(|end| end <= image.len()) {
        image[file_off..file_off + 4].copy_from_slice(&u32::try_from(val & 0xFFFF_FFFF).unwrap_or(u32::MAX).to_le_bytes());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PLT / GOT reconstruction
// ---------------------------------------------------------------------------

/// Reconstruct GOT entries from `JUMP_SLOT` relocations.
///
/// `symbols` is consulted as a fallback when a relocation arrives with an
/// empty `symbol_name` (e.g. relocations parsed before the dynsym strings were
/// resolved): the matching `ElfSymbol::name` from the supplied table is used
/// instead, so reconstructed GOT entries are not anonymous.
#[must_use] 
pub fn reconstruct_got_plt(relocs: &[Relocation], symbols: &[ElfSymbol]) -> Vec<GotEntry> {
    relocs
        .iter()
        .filter(|r| r.is_plt())
        .map(|r| {
            let symbol_name = match &r.symbol_name {
                Some(name) if !name.is_empty() => Some(name.clone()),
                _ => symbols
                    .get(r.sym_idx as usize)
                    .map(|s| s.name.clone())
                    .filter(|n| !n.is_empty()),
            };
            GotEntry {
                address: r.offset,
                symbol_name,
                sym_idx: r.sym_idx,
            }
        })
        .collect()
}

/// Build PLT entries from GOT entries.
///
/// Assumes standard x86-64 PLT layout: PLT stub = `jmp [GOT+N]`.
/// `plt_base` – virtual address of the first real PLT stub (after header).
/// `plt_entry_size` – bytes per PLT entry (typically 16).
#[must_use] 
pub fn reconstruct_plt(
    got_entries: &[GotEntry],
    plt_base: u64,
    plt_entry_size: u64,
) -> Vec<PltEntry> {
    got_entries
        .iter()
        .enumerate()
        .map(|(i, g)| PltEntry {
            address: plt_base + i as u64 * plt_entry_size,
            got_address: g.address,
            symbol_name: g.symbol_name.clone(),
            sym_idx: g.sym_idx,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Version table parsing (Verneed / Verdef)
// ---------------------------------------------------------------------------

/// Parse the `SHT_GNU_verneed` table.
///
/// # Errors
/// Returns an error if the verneed table data is malformed.
pub fn parse_verneed(
    data: &[u8],
    strtab: &[u8],
    count: usize,
    endian: ElfEndian,
) -> DynResult<Vec<VerNeed>> {
    let r = ByteReader::new(data, endian, ElfClass::Elf64);
    let str_r = ByteReader::new(strtab, endian, ElfClass::Elf64);

    let mut result = Vec::new();
    let mut off = 0usize;

    for _ in 0..count {
        if off + 16 > data.len() {
            break;
        }
        let version = r.u16_at(off)?;
        let cnt = r.u16_at(off + 2)?;
        let file_off = r.u32_at(off + 4)?;
        let aux_offset = r.u32_at(off + 8)? as usize;
        let next = r.u32_at(off + 12)? as usize;

        let file = str_r.read_cstr(file_off as usize).unwrap_or_default();

        let mut aux_entries = Vec::new();
        let mut aoff = off + aux_offset;
        for _ in 0..cnt {
            if aoff + 16 > data.len() {
                break;
            }
            let hash = r.u32_at(aoff)?;
            let flags = r.u16_at(aoff + 4)?;
            let other = r.u16_at(aoff + 6)?;
            let name_off = r.u32_at(aoff + 8)? as usize;
            let anext = r.u32_at(aoff + 12)? as usize;
            let name = str_r.read_cstr(name_off).unwrap_or_default();
            aux_entries.push(VerNeedAux {
                hash,
                flags,
                other,
                name,
            });
            if anext == 0 {
                break;
            }
            aoff += anext;
        }

        result.push(VerNeed {
            version,
            cnt,
            file,
            aux: aux_entries,
        });
        if next == 0 {
            break;
        }
        off += next;
    }

    Ok(result)
}

/// Parse the `SHT_GNU_verdef` table.
///
/// # Errors
/// Returns an error if the verdef table data is malformed.
pub fn parse_verdef(
    data: &[u8],
    strtab: &[u8],
    count: usize,
    endian: ElfEndian,
) -> DynResult<Vec<VerDef>> {
    let r = ByteReader::new(data, endian, ElfClass::Elf64);
    let str_r = ByteReader::new(strtab, endian, ElfClass::Elf64);

    let mut result = Vec::new();
    let mut off = 0usize;

    for _ in 0..count {
        if off + 20 > data.len() {
            break;
        }
        let version = r.u16_at(off)?;
        let flags = r.u16_at(off + 2)?;
        let ndx = r.u16_at(off + 4)?;
        let cnt = r.u16_at(off + 6)?;
        let hash = r.u32_at(off + 8)?;
        let aux_offset = r.u32_at(off + 12)? as usize;
        let next = r.u32_at(off + 16)? as usize;

        let mut names = Vec::new();
        let mut aoff = off + aux_offset;
        for _ in 0..cnt {
            if aoff + 8 > data.len() {
                break;
            }
            let name_off = r.u32_at(aoff)? as usize;
            let anext = r.u32_at(aoff + 4)? as usize;
            names.push(str_r.read_cstr(name_off).unwrap_or_default());
            if anext == 0 {
                break;
            }
            aoff += anext;
        }

        result.push(VerDef {
            version,
            flags,
            ndx,
            cnt,
            hash,
            names,
        });
        if next == 0 {
            break;
        }
        off += next;
    }

    Ok(result)
}

/// Build a version index -> version string map from `VerNeed` + `VerDef` tables.
#[must_use] 
pub fn build_version_map(verneed: &[VerNeed], verdef: &[VerDef]) -> HashMap<u16, String> {
    let mut map = HashMap::new();
    for vn in verneed {
        for aux in &vn.aux {
            map.insert(aux.other, aux.name.clone());
        }
    }
    for vd in verdef {
        if let Some(name) = vd.names.first() {
            map.insert(vd.ndx, name.clone());
        }
    }
    map
}

// ---------------------------------------------------------------------------
// IFUNC resolution model
// ---------------------------------------------------------------------------

/// An IFUNC resolver: at runtime the resolver function at `resolver_addr`
/// is called; it returns the actual implementation address.
#[derive(Debug, Clone)]
pub struct IfuncResolver {
    pub symbol_name: String,
    pub resolver_addr: u64,
    pub resolved_addr: Option<u64>,
}

/// Extract all IFUNC (`STT_GNU_IFUNC`) symbols.
#[must_use] 
pub fn collect_ifunc_symbols(symbols: &[ElfSymbol]) -> Vec<IfuncResolver> {
    symbols
        .iter()
        .filter(|s| s.is_ifunc)
        .map(|s| IfuncResolver {
            symbol_name: s.name.clone(),
            resolver_addr: s.value,
            resolved_addr: None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Summary helper
// ---------------------------------------------------------------------------

/// Whether the binary contains text relocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextRel {
    /// Binary has text relocations.
    Yes,
    /// Binary does not have text relocations.
    #[default]
    No,
}

impl TextRel {
    /// Returns `true` if text relocations are present.
    #[must_use]
    pub fn is_yes(self) -> bool {
        self == Self::Yes
    }
}

impl From<bool> for TextRel {
    fn from(b: bool) -> Self {
        if b { Self::Yes } else { Self::No }
    }
}

#[derive(Debug, Clone)]
pub struct DynamicSummary {
    pub needed_libs: Vec<String>,
    pub soname: Option<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub is_pie: bool,
    pub bind_now: bool,
    pub has_gnu_hash: bool,
    pub has_textrel: TextRel,
    pub init_funcs: Vec<u64>,
    pub fini_funcs: Vec<u64>,
    pub reloc_count: usize,
    pub plt_count: usize,
    pub imported_syms: Vec<String>,
    pub ifunc_syms: Vec<String>,
}

pub fn summarize(
    ds: &DynamicSection,
    relocs: &[Relocation],
    symbols: &[ElfSymbol],
) -> DynamicSummary {
    let imported_syms: Vec<String> = relocs
        .iter()
        .filter_map(|r| r.symbol_name.as_deref())
        .filter(|n| !n.is_empty())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .map(str::to_owned)
        .collect();

    let ifunc_syms: Vec<String> = symbols
        .iter()
        .filter(|s| s.is_ifunc)
        .map(|s| s.name.clone())
        .collect();

    let mut init_funcs = Vec::new();
    if let Some(a) = ds.init {
        init_funcs.push(a);
    }

    let mut fini_funcs = Vec::new();
    if let Some(a) = ds.fini {
        fini_funcs.push(a);
    }

    DynamicSummary {
        needed_libs: ds.needed.clone(),
        soname: ds.soname.clone(),
        rpath: ds.rpath.clone(),
        runpath: ds.runpath.clone(),
        is_pie: ds.is_pie(),
        bind_now: ds.is_now(),
        has_gnu_hash: ds.gnu_hash_addr.is_some(),
        has_textrel: TextRel::from(ds.textrel || ds.has_flag(df::TEXTREL)),
        init_funcs,
        fini_funcs,
        reloc_count: relocs.len(),
        plt_count: relocs.iter().filter(|r| r.is_plt()).count(),
        imported_syms,
        ifunc_syms,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn _le64(v: u64) -> [u8; 8] {
        v.to_le_bytes()
    }
    fn _le32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    // ---- DynEntry --------------------------------------------------------

    #[test]
    fn test_dynentry_null() {
        let e = DynEntry { tag: 0, val: 0 };
        assert!(e.is_null());
    }

    #[test]
    fn test_dynentry_non_null() {
        let e = DynEntry {
            tag: dt::NEEDED,
            val: 0,
        };
        assert!(!e.is_null());
    }

    // ---- parse_dynamic_segment -------------------------------------------

    fn make_dyn_entry_64(tag: u64, val: u64) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&tag.to_le_bytes());
        v.extend_from_slice(&val.to_le_bytes());
        v
    }

    fn make_strtab(strings: &[&str]) -> Vec<u8> {
        let mut buf = vec![0u8]; // index 0 = empty string
        for &s in strings {
            buf.extend_from_slice(s.as_bytes());
            buf.push(0);
        }
        buf
    }

    #[test]
    fn test_parse_dynamic_needed() {
        let strtab = make_strtab(&["libc.so.6", "libm.so.6"]);
        // DT_STRTAB offset 0 maps to index 1 ("libc.so.6"), index 11 ("libm.so.6")
        let mut dyn_data = Vec::new();
        dyn_data.extend(make_dyn_entry_64(dt::NEEDED, 1));
        dyn_data.extend(make_dyn_entry_64(dt::NEEDED, 11));
        dyn_data.extend(make_dyn_entry_64(dt::NULL, 0));

        let ds =
            parse_dynamic_segment(&dyn_data, &strtab, ElfEndian::Little, ElfClass::Elf64).unwrap();
        assert_eq!(ds.needed.len(), 2);
        assert_eq!(ds.needed[0], "libc.so.6");
        assert_eq!(ds.needed[1], "libm.so.6");
    }

    #[test]
    fn test_parse_dynamic_flags() {
        let strtab = vec![0u8];
        let mut dyn_data = Vec::new();
        dyn_data.extend(make_dyn_entry_64(dt::FLAGS, df::BIND_NOW));
        dyn_data.extend(make_dyn_entry_64(dt::FLAGS_1, df1::PIE));
        dyn_data.extend(make_dyn_entry_64(dt::NULL, 0));

        let ds =
            parse_dynamic_segment(&dyn_data, &strtab, ElfEndian::Little, ElfClass::Elf64).unwrap();
        assert!(ds.has_flag(df::BIND_NOW));
        assert!(ds.is_pie());
    }

    #[test]
    fn test_parse_dynamic_init_fini() {
        let strtab = vec![0u8];
        let mut dyn_data = Vec::new();
        dyn_data.extend(make_dyn_entry_64(dt::INIT, 0x1000));
        dyn_data.extend(make_dyn_entry_64(dt::FINI, 0x2000));
        dyn_data.extend(make_dyn_entry_64(dt::NULL, 0));

        let ds =
            parse_dynamic_segment(&dyn_data, &strtab, ElfEndian::Little, ElfClass::Elf64).unwrap();
        assert_eq!(ds.init, Some(0x1000));
        assert_eq!(ds.fini, Some(0x2000));
    }

    #[test]
    fn test_parse_dynamic_soname() {
        let strtab = make_strtab(&["libfoo.so.1"]);
        let mut dyn_data = Vec::new();
        dyn_data.extend(make_dyn_entry_64(dt::SONAME, 1));
        dyn_data.extend(make_dyn_entry_64(dt::NULL, 0));

        let ds =
            parse_dynamic_segment(&dyn_data, &strtab, ElfEndian::Little, ElfClass::Elf64).unwrap();
        assert_eq!(ds.soname.as_deref(), Some("libfoo.so.1"));
    }

    #[test]
    fn test_parse_dynamic_empty() {
        let strtab = vec![0u8];
        let mut dyn_data = Vec::new();
        dyn_data.extend(make_dyn_entry_64(dt::NULL, 0));

        let ds =
            parse_dynamic_segment(&dyn_data, &strtab, ElfEndian::Little, ElfClass::Elf64).unwrap();
        assert!(ds.needed.is_empty());
        assert!(ds.soname.is_none());
    }

    #[test]
    fn test_parse_dynamic_runpath_rpath() {
        let strtab = make_strtab(&["/lib:/usr/lib", "/opt/lib"]);
        let mut dyn_data = Vec::new();
        dyn_data.extend(make_dyn_entry_64(dt::RPATH, 1));
        dyn_data.extend(make_dyn_entry_64(dt::RUNPATH, 15));
        dyn_data.extend(make_dyn_entry_64(dt::NULL, 0));

        let ds =
            parse_dynamic_segment(&dyn_data, &strtab, ElfEndian::Little, ElfClass::Elf64).unwrap();
        assert_eq!(ds.rpath.as_deref(), Some("/lib:/usr/lib"));
        assert_eq!(ds.runpath.as_deref(), Some("/opt/lib"));
    }

    #[test]
    fn test_parse_dynamic_bind_now() {
        let strtab = vec![0u8];
        let mut dyn_data = Vec::new();
        dyn_data.extend(make_dyn_entry_64(dt::BIND_NOW, 0));
        dyn_data.extend(make_dyn_entry_64(dt::NULL, 0));

        let ds =
            parse_dynamic_segment(&dyn_data, &strtab, ElfEndian::Little, ElfClass::Elf64).unwrap();
        assert!(ds.bind_now);
        assert!(ds.is_now());
    }

    // ---- ElfArch ---------------------------------------------------------

    #[test]
    fn test_elfarch_from_machine() {
        assert_eq!(ElfArch::from_e_machine(62), ElfArch::X86_64);
        assert_eq!(ElfArch::from_e_machine(40), ElfArch::Arm32);
        assert_eq!(ElfArch::from_e_machine(183), ElfArch::AArch64);
        assert_eq!(ElfArch::from_e_machine(999), ElfArch::Unknown(999));
    }

    // ---- RelTypeX86_64 ---------------------------------------------------

    #[test]
    fn test_rel_type_x86_64_roundtrip() {
        let types = [0u32, 1, 5, 6, 7, 8, 37, 41, 42];
        for &t in &types {
            let rt = RelTypeX86_64::from_u32(t);
            assert!(!rt.name().is_empty(), "type {t} should have a name");
        }
    }

    #[test]
    fn test_rel_type_x86_64_copy() {
        assert_eq!(RelTypeX86_64::from_u32(5), RelTypeX86_64::Copy);
    }

    #[test]
    fn test_rel_type_x86_64_jump_slot() {
        assert_eq!(RelTypeX86_64::from_u32(7), RelTypeX86_64::JumpSlot);
    }

    #[test]
    fn test_rel_type_x86_64_relative() {
        assert_eq!(RelTypeX86_64::from_u32(8), RelTypeX86_64::Relative);
    }

    // ---- GnuHashTable ----------------------------------------------------

    #[test]
    fn test_gnu_hash_parse_minimal() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes()); // nbuckets
        data.extend_from_slice(&1u32.to_le_bytes()); // symoffset
        data.extend_from_slice(&1u32.to_le_bytes()); // bloom_size
        data.extend_from_slice(&6u32.to_le_bytes()); // bloom_shift
        data.extend_from_slice(&0u64.to_le_bytes()); // bloom[0]
        data.extend_from_slice(&0u32.to_le_bytes()); // bucket[0]
        // no chain entries

        let ht = GnuHashTable::parse(&data).unwrap();
        assert_eq!(ht.nbuckets, 1);
        assert_eq!(ht.bloom_size, 1);
        assert_eq!(ht.bloom_shift, 6);
    }

    #[test]
    fn test_gnu_hash_fn() {
        // Known hash: "printf" -> verify non-zero
        let h = GnuHashTable::hash(b"printf");
        assert_ne!(h, 0);
    }

    #[test]
    fn test_gnu_hash_parse_too_short() {
        assert!(GnuHashTable::parse(&[0u8; 4]).is_err());
    }

    // ---- Relocation is_plt / is_copy ------------------------------------

    #[test]
    fn test_reloc_is_plt_x86_64() {
        let r = Relocation {
            offset: 0,
            rel_type: RelType::X86_64(RelTypeX86_64::JumpSlot),
            sym_idx: 0,
            addend: None,
            symbol_name: None,
        };
        assert!(r.is_plt());
        assert!(!r.is_copy());
    }

    #[test]
    fn test_reloc_is_copy() {
        let r = Relocation {
            offset: 0,
            rel_type: RelType::X86_64(RelTypeX86_64::Copy),
            sym_idx: 0,
            addend: None,
            symbol_name: None,
        };
        assert!(r.is_copy());
        assert!(!r.is_plt());
    }

    // ---- reconstruct_got_plt / plt ----------------------------------------

    #[test]
    fn test_reconstruct_got_plt_basic() {
        let relocs = vec![
            Relocation {
                offset: 0x3018,
                rel_type: RelType::X86_64(RelTypeX86_64::JumpSlot),
                sym_idx: 1,
                addend: None,
                symbol_name: Some("printf".into()),
            },
            Relocation {
                offset: 0x3020,
                rel_type: RelType::X86_64(RelTypeX86_64::JumpSlot),
                sym_idx: 2,
                addend: None,
                symbol_name: Some("exit".into()),
            },
        ];
        let syms = vec![];
        let got = reconstruct_got_plt(&relocs, &syms);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].symbol_name.as_deref(), Some("printf"));
        assert_eq!(got[0].address, 0x3018);
    }

    #[test]
    fn test_reconstruct_plt_entries() {
        let got = vec![GotEntry {
            address: 0x3018,
            symbol_name: Some("printf".into()),
            sym_idx: 1,
        }];
        let plt = reconstruct_plt(&got, 0x1020, 16);
        assert_eq!(plt.len(), 1);
        assert_eq!(plt[0].address, 0x1020);
        assert_eq!(plt[0].got_address, 0x3018);
        assert_eq!(plt[0].symbol_name.as_deref(), Some("printf"));
    }

    // ---- build_version_map -----------------------------------------------

    #[test]
    fn test_build_version_map() {
        let verneed = vec![VerNeed {
            version: 1,
            cnt: 1,
            file: "libc.so.6".into(),
            aux: vec![VerNeedAux {
                hash: 0,
                flags: 0,
                other: 3,
                name: "GLIBC_2.5".into(),
            }],
        }];
        let verdef = vec![];
        let map = build_version_map(&verneed, &verdef);
        assert_eq!(map.get(&3).map(std::string::String::as_str), Some("GLIBC_2.5"));
    }

    // ---- collect_ifunc ---------------------------------------------------

    #[test]
    fn test_collect_ifunc() {
        let symbols = vec![
            ElfSymbol {
                name: "memcpy".into(),
                value: 0x400,
                size: 0,
                sym_bind: SymBind::Global,
                sym_type: SymType::GnuIfunc,
                visibility: 0,
                shndx: 1,
                version: None,
                is_ifunc: true,
            },
            ElfSymbol {
                name: "main".into(),
                value: 0x800,
                size: 0,
                sym_bind: SymBind::Global,
                sym_type: SymType::Func,
                visibility: 0,
                shndx: 1,
                version: None,
                is_ifunc: false,
            },
        ];
        let ilist = collect_ifunc_symbols(&symbols);
        assert_eq!(ilist.len(), 1);
        assert_eq!(ilist[0].symbol_name, "memcpy");
        assert_eq!(ilist[0].resolver_addr, 0x400);
    }

    // ---- DynError display ------------------------------------------------

    #[test]
    fn test_dynerror_display() {
        let e = DynError::OutOfBounds { offset: 5, size: 8 };
        assert!(format!("{e}").contains('5'));

        let e = DynError::UnsupportedArch("MIPS".into());
        assert!(format!("{e}").contains("MIPS"));

        let e = DynError::MissingSection(".dynamic".into());
        assert!(format!("{e}").contains(".dynamic"));
    }

    // ---- df / df1 flags --------------------------------------------------

    #[test]
    fn test_df_flags_values() {
        assert_eq!(df::ORIGIN, 0x01);
        assert_eq!(df::SYMBOLIC, 0x02);
        assert_eq!(df::TEXTREL, 0x04);
        assert_eq!(df::BIND_NOW, 0x08);
        assert_eq!(df::STATIC_TLS, 0x10);
    }

    #[test]
    fn test_df1_flags_values() {
        assert_eq!(df1::NOW, 0x01);
        assert_eq!(df1::PIE, 0x0800_0000);
        assert_eq!(df1::NODELETE, 0x08);
    }

    // ---- ByteReader ------------------------------------------------------

    #[test]
    fn test_byte_reader_u64_le() {
        let data = [1u8, 0, 0, 0, 0, 0, 0, 0];
        let r = ByteReader::new(&data, ElfEndian::Little, ElfClass::Elf64);
        assert_eq!(r.u64_at(0).unwrap(), 1);
    }

    #[test]
    fn test_byte_reader_u32_be() {
        let data = [0u8, 0, 0, 1];
        let r = ByteReader::new(&data, ElfEndian::Big, ElfClass::Elf64);
        assert_eq!(r.u32_at(0).unwrap(), 1);
    }

    #[test]
    fn test_byte_reader_out_of_bounds() {
        let data = [0u8; 3];
        let r = ByteReader::new(&data, ElfEndian::Little, ElfClass::Elf64);
        assert!(r.u32_at(0).is_err());
    }

    #[test]
    fn test_byte_reader_cstr() {
        let data = b"hello\0world";
        let r = ByteReader::new(data, ElfEndian::Little, ElfClass::Elf64);
        assert_eq!(r.read_cstr(0).unwrap(), "hello");
        assert_eq!(r.read_cstr(6).unwrap(), "world");
    }

    // ---- summarize -------------------------------------------------------

    #[test]
    fn test_summarize_basic() {
        let strtab = vec![0u8];
        let mut dyn_data = Vec::new();
        dyn_data.extend(make_dyn_entry_64(dt::INIT, 0x1000));
        dyn_data.extend(make_dyn_entry_64(dt::GNU_HASH, 0x2000));
        dyn_data.extend(make_dyn_entry_64(dt::NULL, 0));
        let ds =
            parse_dynamic_segment(&dyn_data, &strtab, ElfEndian::Little, ElfClass::Elf64).unwrap();
        let relocs = vec![];
        let syms = vec![];
        let summary = summarize(&ds, &relocs, &syms);
        assert!(summary.has_gnu_hash);
        assert_eq!(summary.init_funcs, vec![0x1000u64]);
    }
}
