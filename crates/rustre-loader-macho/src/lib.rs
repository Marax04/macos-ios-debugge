//! `rustre-loader-macho`
//!
//! Production-grade Mach-O binary loader for the `RustRE` Suite.
//! Supports 32-bit and 64-bit Mach-O files (little-endian and big-endian),
//! fat/universal binaries, and fully parses all standard load commands,
//! segments, sections, symbols, imports, and exports.

pub mod casts;
pub use casts::*;

pub mod macho_analyzer;
pub mod macho_code_sign;
pub mod macho_dyld_info;
pub mod macho_dylib_analysis;
pub mod macho_objc;
pub mod macho_security;
pub mod objc_metadata; // already existed

pub use macho_objc::{
    MachoObjc, ObjcCategory as MachoObjcCategory, ObjcClass as MachoObjcClass, ObjcClassFlags,
    ObjcError, ObjcIvar, ObjcMethod as MachoObjcMethod, ObjcProperty, ObjcProtocol, ObjcSelector,
    parse_method_list,
};

use async_trait::async_trait;
use rustre_core::loader::BinaryType;
use rustre_core::{
    address::{Address, AddressRange},
    arch::{Architecture, BranchInfo, CallingConvention, Instruction, RegisterInfo},
    binary_view::{BinaryView, Memory, Segment},
    endian::Endian,
    errors::CoreError,
    ids::ViewId,
    permissions::Permissions,
};
use rustre_core::loader::{LoadResult, Loader, LoaderInput, NestedBinary};
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// Mach-O magic constants
// ─────────────────────────────────────────────────────────────────────────────

const MH_MAGIC: u32 = 0xFEED_FACE; // 32-bit LE
const MH_CIGAM: u32 = 0xCEFA_EDFE; // 32-bit BE
const MH_MAGIC_64: u32 = 0xFEED_FACF; // 64-bit LE
const MH_CIGAM_64: u32 = 0xCFFA_EDFE; // 64-bit BE
const FAT_MAGIC: u32 = 0xCAFE_BABE; // fat LE
const FAT_CIGAM: u32 = 0xBEBA_FECA; // fat BE

// CPU type constants
const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM: u32 = 12;
const CPU_TYPE_ARM64: u32 = 0x0100_000C;
const CPU_TYPE_ARM64_32: u32 = 0x0200_000C;
const CPU_TYPE_POWERPC: u32 = 18;
const CPU_TYPE_POWERPC64: u32 = 0x0100_0012;
const CPU_TYPE_MIPS: u32 = 8;
const CPU_TYPE_SPARC: u32 = 14;

// CPU subtype constants for x86_64
const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
const CPU_SUBTYPE_X86_64_H: u32 = 8; // Haswell

// CPU subtype constants for ARM64
const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
const CPU_SUBTYPE_ARM64_V8: u32 = 1;
const CPU_SUBTYPE_ARM64E: u32 = 2;

// CPU subtype constants for ARM
const CPU_SUBTYPE_ARM_ALL: u32 = 0;
const CPU_SUBTYPE_ARM_V7: u32 = 9;
const CPU_SUBTYPE_ARM_V7S: u32 = 11;
const CPU_SUBTYPE_ARM_V7K: u32 = 12;

// File type constants
const MH_OBJECT: u32 = 0x1;
const MH_EXECUTE: u32 = 0x2;
const MH_FVMLIB: u32 = 0x3;
const MH_CORE: u32 = 0x4;
const MH_PRELOAD: u32 = 0x5;
const MH_DYLIB: u32 = 0x6;
const MH_DYLINKER: u32 = 0x7;
const MH_BUNDLE: u32 = 0x8;
const MH_DYLIB_STUB: u32 = 0x9;
const MH_DSYM: u32 = 0xA;
const MH_KEXT_BUNDLE: u32 = 0xB;
const MH_FILESET: u32 = 0xC;

// Mach-O flags
const MH_PIE: u32 = 0x0020_0000;
const MH_TWOLEVEL: u32 = 0x0000_0080;

// Protection flags (vm_prot_t)
const VM_PROT_READ: u32 = 0x1;
const VM_PROT_WRITE: u32 = 0x2;
const VM_PROT_EXECUTE: u32 = 0x4;

// Section type mask
const SECTION_TYPE: u32 = 0x0000_00FF;

// Section type values
const S_REGULAR: u8 = 0x0;
const S_ZEROFILL: u8 = 0x1;
const S_CSTRING_LITERALS: u8 = 0x2;
const S_4BYTE_LITERALS: u8 = 0x3;
const S_8BYTE_LITERALS: u8 = 0x4;
const S_LITERAL_POINTERS: u8 = 0x5;
const S_NON_LAZY_SYMBOL_POINTERS: u8 = 0x6;
const S_LAZY_SYMBOL_POINTERS: u8 = 0x7;
const S_SYMBOL_STUBS: u8 = 0x8;
const S_MOD_INIT_FUNC_POINTERS: u8 = 0x9;
const S_MOD_TERM_FUNC_POINTERS: u8 = 0xA;
const S_COALESCED: u8 = 0xB;
const S_GB_ZEROFILL: u8 = 0xC;
const S_INTERPOSING: u8 = 0xD;

// N_TYPE mask and values
const N_TYPE: u8 = 0x0E;
const N_UNDF: u8 = 0x0;
const N_ABS: u8 = 0x2;
const N_SECT: u8 = 0xE;
const N_PBUD: u8 = 0xC;
const N_INDR: u8 = 0xA;
const N_EXT: u8 = 0x01;
const N_STAB: u8 = 0xE0;

// Load command types
const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xB;
const LC_LOAD_DYLIB: u32 = 0xC;
const LC_ID_DYLIB: u32 = 0xD;
const LC_LOAD_DYLINKER: u32 = 0xE;
const LC_ID_DYLINKER: u32 = 0xF;
const LC_PREBOUND_DYLIB: u32 = 0x10;
const LC_ROUTINES: u32 = 0x11;
const LC_SUB_FRAMEWORK: u32 = 0x12;
const LC_TWOLEVEL_HINTS: u32 = 0x16;
const LC_PREBIND_CKSUM: u32 = 0x17;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_SEGMENT_64: u32 = 0x19;
const LC_ROUTINES_64: u32 = 0x1A;
const LC_UUID: u32 = 0x1B;
const LC_RPATH: u32 = 0x8000_001C;
const LC_CODE_SIGNATURE: u32 = 0x1D;
const LC_SEGMENT_SPLIT_INFO: u32 = 0x1E;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001F;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
const LC_VERSION_MIN_MACOSX: u32 = 0x24;
const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DYLD_ENVIRONMENT: u32 = 0x27;
const LC_MAIN: u32 = 0x8000_0028;
const LC_DATA_IN_CODE: u32 = 0x29;
const LC_SOURCE_VERSION: u32 = 0x2A;
const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2B;
const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
const LC_LINKER_OPTION: u32 = 0x2D;
const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2E;
const LC_VERSION_MIN_TVOS: u32 = 0x2F;
const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
const LC_NOTE: u32 = 0x31;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const LC_FILESET_ENTRY: u32 = 0x8000_0035;
const LC_ATOM_INFO: u32 = 0x36;
const LC_UNIX_THREAD: u32 = 0x5;
const LC_THREAD: u32 = 0x4;

// ─── Code signature SuperBlob / CodeDirectory magic ──────────────────────────
pub const CSMAGIC_REQUIREMENT: u32 = 0xFADE_0C00;
const CSMAGIC_REQUIREMENTS: u32 = 0xFADE_0C01;
const CSMAGIC_CODEDIRECTORY: u32 = 0xFADE_0C02;
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE_0CC0;
const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xFADE_0CC1;
const CSMAGIC_BLOBWRAPPER: u32 = 0xFADE_0B01;
const CSMAGIC_ENTITLEMENTS: u32 = 0xFADE_7171;
const CSMAGIC_ENTITLEMENTS_DER: u32 = 0xFADE_7172;
pub const CS_SLOTTYPE_CODEDIRECTORY: u32 = 0;
pub const CS_SLOTTYPE_INFOSLOT: u32 = 1;
pub const CS_SLOTTYPE_REQUIREMENTS: u32 = 2;
pub const CS_SLOTTYPE_RESOURCEDIR: u32 = 3;
pub const CS_SLOTTYPE_ENTITLEMENTS: u32 = 5;
pub const CS_SLOTTYPE_DER_ENTITLEMENTS: u32 = 7;

// ─── Chained fixup pointer formats ──────────────────────────────────────────
const DYLD_CHAINED_PTR_ARM64E: u32 = 1;
const DYLD_CHAINED_PTR_64: u32 = 2;
const DYLD_CHAINED_PTR_32: u32 = 3;
const DYLD_CHAINED_PTR_32_CACHE: u32 = 4;
const DYLD_CHAINED_PTR_32_FIRMWARE: u32 = 5;
const DYLD_CHAINED_PTR_64_OFFSET: u32 = 6;
const DYLD_CHAINED_PTR_ARM64E_KERNEL: u32 = 7;
const DYLD_CHAINED_PTR_64_KERNEL_CACHE: u32 = 8;
const DYLD_CHAINED_PTR_ARM64E_USERLAND: u32 = 9;
const DYLD_CHAINED_PTR_ARM64E_FIRMWARE: u32 = 10;
const DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: u32 = 11;
const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u32 = 12;

// ─── Data-in-code entry kinds ────────────────────────────────────────────────
const DICE_KIND_DATA: u16 = 0x0001;
const DICE_KIND_JUMP_TABLE8: u16 = 0x0002;
const DICE_KIND_JUMP_TABLE16: u16 = 0x0003;
const DICE_KIND_JUMP_TABLE32: u16 = 0x0004;
const DICE_KIND_ABS_JUMP_TABLE32: u16 = 0x0005;

// ─── Rebase opcodes ──────────────────────────────────────────────────────────
const REBASE_OPCODE_DONE: u8 = 0x00;
const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x10;
const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
const REBASE_OPCODE_ADD_ADDR_ULEB: u8 = 0x30;
const REBASE_OPCODE_ADD_ADDR_IMM_SCALED: u8 = 0x40;
const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8 = 0x50;
const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;

// ─── Rebase types ────────────────────────────────────────────────────────────
const REBASE_TYPE_POINTER: u8 = 1;
pub const REBASE_TYPE_TEXT_ABSOLUTE32: u8 = 2;
pub const REBASE_TYPE_TEXT_PCREL32: u8 = 3;

// ─────────────────────────────────────────────────────────────────────────────
// MachoArch
// ─────────────────────────────────────────────────────────────────────────────

/// Detected CPU architecture of a Mach-O binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachoArch {
    X86,
    X86_64,
    Arm,
    Arm64,
    Arm64_32,
    PowerPc,
    PowerPc64,
    Mips,
    Sparc,
    Unknown(u32),
}

impl MachoArch {
    /// Map a raw `cpu_type` field to a `MachoArch`.
    #[must_use] 
    pub const fn from_cputype(cputype: u32) -> Self {
        match cputype {
            CPU_TYPE_X86 => Self::X86,
            CPU_TYPE_X86_64 => Self::X86_64,
            CPU_TYPE_ARM => Self::Arm,
            CPU_TYPE_ARM64 => Self::Arm64,
            CPU_TYPE_ARM64_32 => Self::Arm64_32,
            CPU_TYPE_POWERPC => Self::PowerPc,
            CPU_TYPE_POWERPC64 => Self::PowerPc64,
            CPU_TYPE_MIPS => Self::Mips,
            CPU_TYPE_SPARC => Self::Sparc,
            other => Self::Unknown(other),
        }
    }

    /// Map a (cputype, cpusubtype) pair to a descriptive subtype name.
    #[must_use] 
    pub const fn subtype_name(cputype: u32, cpusubtype: u32) -> &'static str {
        match (cputype, cpusubtype & 0x00FF_FFFF) {
            (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL) => "x86_64 (all)",
            (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H) => "x86_64h (Haswell)",
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL) => "arm64 (all)",
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8) => "arm64v8",
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E) => "arm64e",
            (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_ALL) => "arm (all)",
            (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7) => "armv7",
            (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7S) => "armv7s",
            (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7K) => "armv7k",
            _ => "unknown subtype",
        }
    }

    /// Native pointer width in bytes.
    #[must_use] 
    pub const fn pointer_size(self) -> usize {
        match self {
            Self::X86 | Self::Arm | Self::Arm64_32 | Self::PowerPc | Self::Mips | Self::Sparc => 4,
            Self::X86_64 | Self::Arm64 | Self::PowerPc64 | Self::Unknown(_) => 8,
        }
    }

    /// Human-readable architecture name.
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::Arm64_32 => "arm64_32",
            Self::PowerPc => "ppc",
            Self::PowerPc64 => "ppc64",
            Self::Mips => "mips",
            Self::Sparc => "sparc",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Natural byte order for this architecture.
    #[must_use] 
    pub const fn endian(self) -> Endian {
        match self {
            Self::PowerPc | Self::PowerPc64 | Self::Mips | Self::Sparc => Endian::Big,
            _ => Endian::Little,
        }
    }

    /// Returns true if this is a 64-bit architecture.
    #[must_use] 
    pub const fn is_64bit(self) -> bool {
        matches!(self, Self::X86_64 | Self::Arm64 | Self::PowerPc64)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoFileType
// ─────────────────────────────────────────────────────────────────────────────

/// Mach-O file type (from the `filetype` header field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachoFileType {
    Object,
    Execute,
    FvmLib,
    Core,
    Preload,
    Dylib,
    Dylinker,
    Bundle,
    DylibStub,
    Dsym,
    KextBundle,
    Fileset,
    Unknown(u32),
}

impl MachoFileType {
    /// Map a raw `filetype` field to a `MachoFileType`.
    #[must_use] 
    pub const fn from_filetype(ft: u32) -> Self {
        match ft {
            MH_OBJECT => Self::Object,
            MH_EXECUTE => Self::Execute,
            MH_FVMLIB => Self::FvmLib,
            MH_CORE => Self::Core,
            MH_PRELOAD => Self::Preload,
            MH_DYLIB => Self::Dylib,
            MH_DYLINKER => Self::Dylinker,
            MH_BUNDLE => Self::Bundle,
            MH_DYLIB_STUB => Self::DylibStub,
            MH_DSYM => Self::Dsym,
            MH_KEXT_BUNDLE => Self::KextBundle,
            MH_FILESET => Self::Fileset,
            other => Self::Unknown(other),
        }
    }

    /// Human-readable name for the file type.
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Object => "MH_OBJECT",
            Self::Execute => "MH_EXECUTE",
            Self::FvmLib => "MH_FVMLIB",
            Self::Core => "MH_CORE",
            Self::Preload => "MH_PRELOAD",
            Self::Dylib => "MH_DYLIB",
            Self::Dylinker => "MH_DYLINKER",
            Self::Bundle => "MH_BUNDLE",
            Self::DylibStub => "MH_DYLIB_STUB",
            Self::Dsym => "MH_DSYM",
            Self::KextBundle => "MH_KEXT_BUNDLE",
            Self::Fileset => "MH_FILESET",
            Self::Unknown(_) => "MH_UNKNOWN",
        }
    }

    /// Returns `true` if this binary is a standalone executable.
    #[must_use] 
    pub const fn is_executable(self) -> bool {
        matches!(self, Self::Execute)
    }

    /// Returns `true` if this binary is a shared library.
    #[must_use] 
    pub const fn is_library(self) -> bool {
        matches!(self, Self::Dylib | Self::DylibStub)
    }

    /// Returns `true` if this is a core dump.
    #[must_use] 
    pub const fn is_core(self) -> bool {
        matches!(self, Self::Core)
    }

    /// Returns `true` if this is a kernel collection fileset.
    #[must_use] 
    pub const fn is_fileset(self) -> bool {
        matches!(self, Self::Fileset)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoSectionType
// ─────────────────────────────────────────────────────────────────────────────

/// The type of a Mach-O section, derived from the low byte of `flags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachoSectionType {
    Regular,
    ZeroFill,
    CStringLiterals,
    FourByteLiterals,
    EightByteLiterals,
    LiteralPointers,
    NonLazySymbolPointers,
    LazySymbolPointers,
    SymbolStubs,
    ModInitFuncPointers,
    ModTermFuncPointers,
    Coalesced,
    GbZeroFill,
    Interposing,
    Unknown(u8),
}

impl MachoSectionType {
    /// Decode the section type from the `flags` field of a section header.
    #[must_use] 
    pub const fn from_flags(flags: u32) -> Self {
        match (flags & SECTION_TYPE) as u8 {
            S_REGULAR => Self::Regular,
            S_ZEROFILL => Self::ZeroFill,
            S_CSTRING_LITERALS => Self::CStringLiterals,
            S_4BYTE_LITERALS => Self::FourByteLiterals,
            S_8BYTE_LITERALS => Self::EightByteLiterals,
            S_LITERAL_POINTERS => Self::LiteralPointers,
            S_NON_LAZY_SYMBOL_POINTERS => Self::NonLazySymbolPointers,
            S_LAZY_SYMBOL_POINTERS => Self::LazySymbolPointers,
            S_SYMBOL_STUBS => Self::SymbolStubs,
            S_MOD_INIT_FUNC_POINTERS => Self::ModInitFuncPointers,
            S_MOD_TERM_FUNC_POINTERS => Self::ModTermFuncPointers,
            S_COALESCED => Self::Coalesced,
            S_GB_ZEROFILL => Self::GbZeroFill,
            S_INTERPOSING => Self::Interposing,
            other => Self::Unknown(other),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoSection
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed section within a Mach-O segment.
#[derive(Debug, Clone)]
pub struct MachoSection {
    /// Section name (e.g. `"__text"`, `"__data"`).
    pub name: String,
    /// Parent segment name (e.g. `"__TEXT"`).
    pub segment: String,
    /// Virtual memory address.
    pub addr: u64,
    /// Virtual size in bytes.
    pub size: u64,
    /// File offset of section data.
    pub offset: u32,
    /// Section alignment (as power of 2).
    pub align: u32,
    /// Raw section flags field.
    pub flags: u32,
    /// Decoded section type.
    pub section_type: MachoSectionType,
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoSegment
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed Mach-O segment (`LC_SEGMENT` or `LC_SEGMENT_64`).
#[derive(Debug, Clone)]
pub struct MachoSegment {
    /// Segment name (e.g. `"__TEXT"`, `"__DATA"`).
    pub name: String,
    /// Virtual memory address.
    pub vm_addr: u64,
    /// Virtual memory size.
    pub vm_size: u64,
    /// File offset.
    pub file_offset: u64,
    /// Size in the file.
    pub file_size: u64,
    /// Maximum virtual memory protection.
    pub max_prot: u32,
    /// Initial virtual memory protection.
    pub init_prot: u32,
    /// Sections within this segment.
    pub sections: Vec<MachoSection>,
}

impl MachoSegment {
    /// `true` if the segment is readable.
    #[must_use] 
    pub const fn is_readable(&self) -> bool {
        self.init_prot & VM_PROT_READ != 0
    }

    /// `true` if the segment is writable.
    #[must_use] 
    pub const fn is_writable(&self) -> bool {
        self.init_prot & VM_PROT_WRITE != 0
    }

    /// `true` if the segment is executable.
    #[must_use] 
    pub const fn is_executable(&self) -> bool {
        self.init_prot & VM_PROT_EXECUTE != 0
    }

    /// Returns `true` if `addr` falls within the virtual address range.
    #[must_use] 
    pub const fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.vm_addr && addr < self.vm_addr.saturating_add(self.vm_size)
    }

    /// Byte range `[file_offset, file_offset + file_size)` within the file.
    #[must_use] 
    pub const fn file_range(&self) -> std::ops::Range<usize> {
        let start = self.file_offset as usize;
        let end = start.saturating_add(self.file_size as usize);
        start..end
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoSymbolType
// ─────────────────────────────────────────────────────────────────────────────

/// Type of a Mach-O symbol table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachoSymbolType {
    Undefined,
    Absolute,
    Section,
    PreboundUndefined,
    Indirect,
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoSymbol
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed Mach-O symbol table entry.
#[derive(Debug, Clone)]
pub struct MachoSymbol {
    /// Symbol name (demangled if available from the string table).
    pub name: String,
    /// Virtual address (value field).
    pub value: u64,
    /// Section index (0 = undefined).
    pub section_index: u8,
    /// Symbol type.
    pub sym_type: MachoSymbolType,
    /// Whether the `N_EXT` external flag is set.
    pub is_external: bool,
    /// Whether this is a debug (stab) symbol.
    pub is_debug: bool,
    /// Whether the symbol is undefined (references a dylib).
    pub is_undefined: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoImport / MachoExport
// ─────────────────────────────────────────────────────────────────────────────

/// A symbol imported from a dynamic library.
#[derive(Debug, Clone)]
pub struct MachoImport {
    /// Symbol name.
    pub name: String,
    /// Name of the dylib that provides this symbol.
    pub dylib: String,
    /// `true` if this symbol comes from the lazy symbol pointer table.
    pub lazy: bool,
    /// Virtual address of the stub (if known).
    pub stub_addr: Option<u64>,
}

/// A symbol exported by this binary.
#[derive(Debug, Clone)]
pub struct MachoExport {
    /// Symbol name.
    pub name: String,
    /// Virtual address.
    pub address: u64,
    /// Raw export flags.
    pub flags: u32,
    /// `true` if this is a re-export from another library.
    pub is_reexport: bool,
    /// Source library name for re-exports.
    pub reexport_from: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// DataInCodeEntry
// ─────────────────────────────────────────────────────────────────────────────

/// Kind of a data-in-code entry (`LC_DATA_IN_CODE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiceKind {
    Data,
    JumpTable8,
    JumpTable16,
    JumpTable32,
    AbsJumpTable32,
    Unknown(u16),
}

impl DiceKind {
    #[must_use] 
    pub const fn from_raw(kind: u16) -> Self {
        match kind {
            DICE_KIND_DATA => Self::Data,
            DICE_KIND_JUMP_TABLE8 => Self::JumpTable8,
            DICE_KIND_JUMP_TABLE16 => Self::JumpTable16,
            DICE_KIND_JUMP_TABLE32 => Self::JumpTable32,
            DICE_KIND_ABS_JUMP_TABLE32 => Self::AbsJumpTable32,
            other => Self::Unknown(other),
        }
    }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Data => "DICE_KIND_DATA",
            Self::JumpTable8 => "DICE_KIND_JUMP_TABLE8",
            Self::JumpTable16 => "DICE_KIND_JUMP_TABLE16",
            Self::JumpTable32 => "DICE_KIND_JUMP_TABLE32",
            Self::AbsJumpTable32 => "DICE_KIND_ABS_JUMP_TABLE32",
            Self::Unknown(_) => "DICE_KIND_UNKNOWN",
        }
    }
}

/// A single entry from the `LC_DATA_IN_CODE` blob.
/// Each entry marks a range within __TEXT that contains non-instruction data.
#[derive(Debug, Clone)]
pub struct DataInCodeEntry {
    /// File offset of the data range (relative to the __TEXT file range).
    pub offset: u32,
    /// Length of the range in bytes.
    pub length: u16,
    /// Kind of data.
    pub kind: DiceKind,
}

// ─────────────────────────────────────────────────────────────────────────────
// RebaseEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single rebase action from `LC_DYLD_INFO_ONLY` rebase opcodes.
#[derive(Debug, Clone)]
pub struct RebaseEntry {
    /// Segment index (0-based).
    pub segment_index: u8,
    /// Offset within the segment.
    pub segment_offset: u64,
    /// Rebase type (`REBASE_TYPE`_*).
    pub rebase_type: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// ObjcClass / ObjcCategory
// ─────────────────────────────────────────────────────────────────────────────

/// An Objective-C method extracted from metadata.
#[derive(Debug, Clone)]
pub struct ObjcMethod {
    /// Method selector string (e.g. `"viewDidLoad"`).
    pub name: String,
    /// Method type encoding string.
    pub types: String,
    /// VM address of the method implementation.
    pub imp: u64,
}

/// An Objective-C class extracted from __`objc_classlist`.
#[derive(Debug, Clone)]
pub struct ObjcClass {
    /// Class name (e.g. `"MyViewController"`).
    pub name: String,
    /// VM address of the class object.
    pub addr: u64,
    /// Instance methods.
    pub instance_methods: Vec<ObjcMethod>,
    /// Class methods.
    pub class_methods: Vec<ObjcMethod>,
    /// Protocol names this class conforms to.
    pub protocols: Vec<String>,
    /// Instance variable names.
    pub ivars: Vec<String>,
}

/// An Objective-C category extracted from __`objc_catlist`.
#[derive(Debug, Clone)]
pub struct ObjcCategory {
    /// Category name (e.g. `"MyCategory"`).
    pub name: String,
    /// Base class name this category extends.
    pub class_name: String,
    /// Instance methods added by this category.
    pub instance_methods: Vec<ObjcMethod>,
    /// Class methods added by this category.
    pub class_methods: Vec<ObjcMethod>,
}

// ─────────────────────────────────────────────────────────────────────────────
// SwiftTypeDescriptor / SwiftProtoConformance
// ─────────────────────────────────────────────────────────────────────────────

/// A Swift type descriptor entry from __`swift5_types`.
#[derive(Debug, Clone)]
pub struct SwiftTypeDescriptor {
    /// VM address of the type descriptor record.
    pub addr: u64,
    /// Relative pointer value (before resolution).
    pub relative_ptr: i32,
}

/// A Swift protocol conformance descriptor from __`swift5_proto`.
#[derive(Debug, Clone)]
pub struct SwiftProtoConformance {
    /// VM address of the conformance descriptor.
    pub addr: u64,
    /// Relative pointer to the protocol.
    pub protocol_relative: i32,
}

// ─────────────────────────────────────────────────────────────────────────────
// CodeSignatureInfo
// ─────────────────────────────────────────────────────────────────────────────

/// A single blob slot within a code signature `SuperBlob`.
#[derive(Debug, Clone)]
pub struct CodeSigBlobSlot {
    /// Slot type (`CS_SLOTTYPE`_*).
    pub slot_type: u32,
    /// Offset from the `SuperBlob` start to this blob.
    pub offset: u32,
    /// Magic bytes identifying the blob type.
    pub magic: u32,
    /// Size of this blob in bytes.
    pub size: u32,
}

/// Parsed `CodeDirectory` from a code signature.
#[derive(Debug, Clone)]
pub struct CodeDirectory {
    /// Version of the `CodeDirectory` structure.
    pub version: u32,
    /// Code signing flags.
    pub flags: u32,
    /// Number of code slots (pages covered by code hashes).
    pub code_slots: u32,
    /// Hash size in bytes (e.g. 20 for SHA-1, 32 for SHA-256).
    pub hash_size: u8,
    /// Hash type (1=SHA-1, 2=SHA-256, 3=SHA-256-Truncated, 4=SHA-384).
    pub hash_type: u8,
    /// Team identifier string.
    pub team_id: Option<String>,
    /// Bundle identifier string.
    pub identifier: String,
    /// Page size as power of two.
    pub page_size: u8,
    /// Offset of the first code slot hash, relative to the blob start.
    ///
    /// Together with `n_special_slots` and `hash_size` this locates every hash
    /// in the directory, which is what a signature *verifier* needs.
    pub hash_offset: usize,
    /// Offset of the identifier string, relative to the blob start.
    pub ident_offset: usize,
    /// Number of special slots stored *before* `hash_offset`.
    pub n_special_slots: usize,
    /// Byte length of the image covered by the code hashes.
    pub code_limit: u32,
    /// Platform identifier (0 for non-platform binaries).
    pub platform: u8,
}

/// Full parsed code signature blob.
#[derive(Debug, Clone)]
pub struct CodeSignatureInfo {
    /// All blob slots in the `SuperBlob`.
    pub slots: Vec<CodeSigBlobSlot>,
    /// Parsed `CodeDirectory`, if present.
    pub code_directory: Option<CodeDirectory>,
    /// Raw entitlements XML plist, if present.
    pub entitlements_xml: Option<String>,
    /// Raw DER-encoded entitlements, if present (length in bytes).
    pub entitlements_der_len: Option<usize>,
    /// Whether a CMS blob (`BlobWrapper`) is present.
    pub has_cms: bool,
    /// Whether a Requirements blob is present.
    pub has_requirements: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// ChainedFixupImport
// ─────────────────────────────────────────────────────────────────────────────

/// An import entry from the `LC_DYLD_CHAINED_FIXUPS` import table.
#[derive(Debug, Clone)]
pub struct ChainedFixupImport {
    /// Library ordinal (1-based; special values 0xFE/0xFF for flat/self).
    pub lib_ordinal: u8,
    /// Symbol name.
    pub name: String,
    /// Whether the symbol is weakly referenced.
    pub weak_import: bool,
    /// Addend for the bind.
    pub addend: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoLoadCommandData / MachoLoadCommand
// ─────────────────────────────────────────────────────────────────────────────

/// Rich decoded payload for a load command.
#[derive(Debug, Clone)]
pub enum MachoLoadCommandData {
    Segment(MachoSegment),
    Dylib {
        name: String,
        timestamp: u32,
        current_version: u32,
        compatibility_version: u32,
    },
    Rpath(String),
    DylibId {
        name: String,
    },
    Entrypoint {
        entry_offset: u64,
        stack_size: u64,
    },
    UnixThread {
        entry_point: u64,
    },
    SourceVersion(u64),
    MinOsVersion {
        platform: String,
        version: u32,
        sdk: u32,
    },
    BuildVersion {
        platform: String,
        minos: u32,
        sdk: u32,
    },
    CodeSignature {
        offset: u32,
        size: u32,
    },
    Uuid([u8; 16]),
    Encryption {
        cryptid: u32,
        offset: u32,
        size: u32,
    },
    FunctionStarts {
        offset: u32,
        size: u32,
    },
    DataInCode {
        offset: u32,
        size: u32,
    },
    DyldInfo {
        rebase_off: u32,
        rebase_size: u32,
        bind_off: u32,
        bind_size: u32,
        weak_bind_off: u32,
        weak_bind_size: u32,
        lazy_bind_off: u32,
        lazy_bind_size: u32,
        export_off: u32,
        export_size: u32,
    },
    DyldExportsTrie {
        offset: u32,
        size: u32,
    },
    DyldChainedFixups {
        offset: u32,
        size: u32,
    },
    Note {
        data_owner: String,
        offset: u64,
        size: u64,
    },
    FilesetEntry {
        vm_addr: u64,
        file_offset: u64,
        entry_id: String,
    },
    Other,
}

/// A decoded Mach-O load command.
#[derive(Debug, Clone)]
pub struct MachoLoadCommand {
    /// Raw `cmd` value.
    pub cmd: u32,
    /// Human-readable command name.
    pub cmd_name: String,
    /// Decoded payload.
    pub data: MachoLoadCommandData,
}

// ─────────────────────────────────────────────────────────────────────────────
// UniversalBinaryEntry
// ─────────────────────────────────────────────────────────────────────────────

/// One architecture slice from a fat/universal binary.
#[derive(Debug, Clone)]
pub struct UniversalBinaryEntry {
    /// Architecture of this slice.
    pub arch: MachoArch,
    /// Byte offset within the fat binary.
    pub offset: u32,
    /// Byte size of this slice.
    pub size: u32,
    /// Alignment (as power of 2).
    pub align: u32,
    /// Raw bytes of this slice.
    pub data: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Fully parsed representation of a Mach-O binary.
#[derive(Debug, Clone)]
pub struct MachoInfo {
    pub arch: MachoArch,
    pub cpu_subtype: u32,
    pub file_type: MachoFileType,
    pub flags: u32,
    pub entry_points: Vec<Address>,
    pub segments: Vec<MachoSegment>,
    pub symbols: Vec<MachoSymbol>,
    pub imports: Vec<MachoImport>,
    pub exports: Vec<MachoExport>,
    /// Dependent dylib install names.
    pub dylibs: Vec<String>,
    pub rpaths: Vec<String>,
    pub uuid: Option<[u8; 16]>,
    pub source_version: Option<u64>,
    pub load_commands: Vec<MachoLoadCommand>,
    pub has_code_signature: bool,
    pub is_pie: bool,
    pub is_fat: bool,
    pub fat_slices: Vec<UniversalBinaryEntry>,
    pub min_os_version: Option<String>,
    pub platform: Option<String>,
    /// Function start addresses recovered from `LC_FUNCTION_STARTS`.
    pub function_starts: Vec<u64>,
    /// Data-in-code entries from `LC_DATA_IN_CODE`.
    pub data_in_code: Vec<DataInCodeEntry>,
    /// Bind entries from `LC_DYLD_INFO_ONLY` bind opcodes.
    pub bind_entries: Vec<BindEntry>,
    /// Export entries from the dyld export trie.
    pub export_entries: Vec<ExportEntry>,
    /// Rebase entries from `LC_DYLD_INFO_ONLY` rebase opcodes.
    pub rebase_entries: Vec<RebaseEntry>,
    /// `ObjC` class names extracted from __`objc_classlist`.
    pub objc_classes: Vec<ObjcClass>,
    /// `ObjC` protocol names extracted from __`objc_protolist`.
    pub objc_protocols: Vec<String>,
    /// `ObjC` category names extracted from __`objc_catlist`.
    pub objc_categories: Vec<ObjcCategory>,
    /// Swift type descriptors from __`swift5_types`.
    pub swift_types: Vec<SwiftTypeDescriptor>,
    /// Swift protocol conformances from __`swift5_proto`.
    pub swift_proto_conformances: Vec<SwiftProtoConformance>,
    /// Code signature information, if parsed.
    pub code_signature: Option<CodeSignatureInfo>,
    /// Chained fixup imports from `LC_DYLD_CHAINED_FIXUPS`.
    pub chained_fixup_imports: Vec<ChainedFixupImport>,
}

impl MachoInfo {
    /// Returns the `__TEXT` segment, if present.
    #[must_use] 
    pub fn text_segment(&self) -> Option<&MachoSegment> {
        self.segments.iter().find(|s| s.name == "__TEXT")
    }

    /// Returns the `__DATA` segment, if present.
    #[must_use] 
    pub fn data_segment(&self) -> Option<&MachoSegment> {
        self.segments.iter().find(|s| s.name == "__DATA")
    }

    /// Finds a section by parent segment name and section name.
    #[must_use] 
    pub fn section_named(&self, segment: &str, section: &str) -> Option<&MachoSection> {
        for seg in &self.segments {
            if seg.name == segment {
                for sec in &seg.sections {
                    if sec.name == section {
                        return Some(sec);
                    }
                }
            }
        }
        None
    }

    /// Returns the first symbol whose `value` matches `addr`.
    #[must_use] 
    pub fn symbol_at(&self, addr: u64) -> Option<&MachoSymbol> {
        self.symbols.iter().find(|s| s.value == addr)
    }

    /// Returns the first symbol whose name matches `name`.
    #[must_use] 
    pub fn find_symbol(&self, name: &str) -> Option<&MachoSymbol> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /// `true` if this is a dynamic library.
    #[must_use] 
    pub const fn is_dylib(&self) -> bool {
        self.file_type.is_library()
    }

    /// `true` if this is a standalone executable.
    #[must_use] 
    pub const fn is_executable(&self) -> bool {
        self.file_type.is_executable()
    }

    /// Formats the UUID as `"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"`.
    #[must_use] 
    pub fn uuid_string(&self) -> Option<String> {
        self.uuid.map(|u| {
            format!(
                "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                u[0], u[1], u[2], u[3],
                u[4], u[5],
                u[6], u[7],
                u[8], u[9],
                u[10], u[11], u[12], u[13], u[14], u[15],
            )
        })
    }

    /// Returns decoded header flags.
    #[must_use] 
    pub const fn header_flags(&self) -> MachoHeaderFlags {
        MachoHeaderFlags::from_raw(self.flags)
    }

    /// Returns `true` if this binary contains `ObjC` class metadata.
    #[must_use] 
    pub const fn has_objc(&self) -> bool {
        !self.objc_classes.is_empty() || !self.objc_protocols.is_empty()
    }

    /// Returns `true` if this binary contains Swift metadata.
    #[must_use] 
    pub const fn has_swift(&self) -> bool {
        !self.swift_types.is_empty() || !self.swift_proto_conformances.is_empty()
    }

    /// Returns the number of unique function start addresses recovered.
    #[must_use] 
    pub const fn function_count(&self) -> usize {
        self.function_starts.len()
    }

    /// Looks up a function start address by index.
    #[must_use] 
    pub fn function_start_at(&self, idx: usize) -> Option<u64> {
        self.function_starts.get(idx).copied()
    }

    /// Returns the total number of data-in-code entries.
    #[must_use] 
    pub const fn data_in_code_count(&self) -> usize {
        self.data_in_code.len()
    }

    /// Checks whether the code signature is present and has CMS.
    #[must_use] 
    pub fn is_signed_with_cms(&self) -> bool {
        self.code_signature
            .as_ref()
            .is_some_and(|cs| cs.has_cms)
    }

    /// Returns the entitlements XML plist if present.
    #[must_use] 
    pub fn entitlements(&self) -> Option<&str> {
        self.code_signature
            .as_ref()
            .and_then(|cs| cs.entitlements_xml.as_deref())
    }

    /// Returns all `ObjC` class names (sorted).
    #[must_use] 
    pub fn objc_class_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.objc_classes.iter().map(|c| c.name.as_str()).collect();
        names.sort_unstable();
        names
    }

    /// Returns all chained fixup import symbol names.
    #[must_use] 
    pub fn chained_import_names(&self) -> Vec<&str> {
        self.chained_fixup_imports
            .iter()
            .map(|i| i.name.as_str())
            .collect()
    }

    /// Returns the CPU subtype name for this binary.
    #[must_use] 
    pub const fn cpu_subtype_name(&self) -> &'static str {
        let cputype = match self.arch {
            MachoArch::X86 => CPU_TYPE_X86,
            MachoArch::X86_64 => CPU_TYPE_X86_64,
            MachoArch::Arm => CPU_TYPE_ARM,
            MachoArch::Arm64 => CPU_TYPE_ARM64,
            MachoArch::Arm64_32 => CPU_TYPE_ARM64_32,
            MachoArch::PowerPc => CPU_TYPE_POWERPC,
            MachoArch::PowerPc64 => CPU_TYPE_POWERPC64,
            MachoArch::Mips => CPU_TYPE_MIPS,
            MachoArch::Sparc => CPU_TYPE_SPARC,
            MachoArch::Unknown(v) => v,
        };
        MachoArch::subtype_name(cputype, self.cpu_subtype)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: read little-endian primitives from a byte slice
// ─────────────────────────────────────────────────────────────────────────────

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    bytes
        .get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn read_u32_be(bytes: &[u8], off: usize) -> Option<u32> {
    bytes
        .get(off..off + 4)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
}

fn read_u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    bytes
        .get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

fn read_u64_be(bytes: &[u8], off: usize) -> Option<u64> {
    bytes
        .get(off..off + 8)
        .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
}

fn read_cstr(bytes: &[u8], off: usize, max_len: usize) -> String {
    let end = off + max_len;
    let end = end.min(bytes.len());
    if off >= end {
        return String::new();
    }
    let slice = &bytes[off..end];
    let null_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..null_pos]).into_owned()
}

/// Read a NUL-terminated string from a load command's name offset (relative to the LC start).
fn read_lc_str(lc_bytes: &[u8], name_off: usize) -> String {
    if name_off >= lc_bytes.len() {
        return String::new();
    }
    let slice = &lc_bytes[name_off..];
    let null_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..null_pos]).into_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoParser
// ─────────────────────────────────────────────────────────────────────────────

/// Stateless parser that converts raw bytes into a [`MachoInfo`].
pub struct MachoParser;

impl MachoParser {
    /// Parse either a regular Mach-O or a fat/universal binary.
    /// For fat binaries the best available slice is automatically selected.
    pub fn parse(bytes: &[u8]) -> Result<MachoInfo, CoreError> {
        if bytes.len() < 4 {
            return Err(CoreError::InvalidFormat {
                message: "File too small".into(),
            });
        }
        let magic_le = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let is_fat = magic_le == FAT_MAGIC || magic_le == FAT_CIGAM;
        if is_fat {
            let entries = Self::parse_fat(bytes)?;
            if let Some(best) = Self::select_best_slice(&entries) {
                let mut info = Self::parse_single(&best.data)?;
                info.is_fat = true;
                info.fat_slices = entries;
                return Ok(info);
            }
            return Err(CoreError::InvalidFormat {
                message: "Fat binary has no usable slices".into(),
            });
        }
        Self::parse_single(bytes)
    }

    /// Parse a fat/universal binary; returns all slices.
    pub fn parse_fat(bytes: &[u8]) -> Result<Vec<UniversalBinaryEntry>, CoreError> {
        if bytes.len() < 8 {
            return Err(CoreError::InvalidFormat {
                message: "Fat binary too small".into(),
            });
        }
        let magic = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let _big_endian = magic == FAT_CIGAM;

        // Apple's fat header nfat_arch is always stored big-endian on disk.
        // The big_endian flag indicates the magic matched FAT_CIGAM (LE-read bytes),
        // but nfat_arch is unconditionally BE regardless of slice endianness.
        let nfat = read_u32_be(bytes, 4).unwrap_or(0);

        // fat_arch struct is always big-endian, 20 bytes each, starting at offset 8.
        // Cap nfat to avoid allocating / iterating an attacker-controlled number of entries.
        let max_possible = (bytes.len().saturating_sub(8)) / 20;
        let nfat = (nfat as usize).min(max_possible);
        let mut entries = Vec::new();
        for i in 0..nfat {
            let base = 8 + i * 20;
            if base + 20 > bytes.len() {
                break;
            }
            let cputype = read_u32_be(bytes, base).unwrap_or(0);
            // cpusubtype at base+4 (unused here)
            let offset = read_u32_be(bytes, base + 8).unwrap_or(0);
            let size = read_u32_be(bytes, base + 12).unwrap_or(0);
            let align = read_u32_be(bytes, base + 16).unwrap_or(0);
            let start = offset as usize;
            let end = start.saturating_add(size as usize);
            if end > bytes.len() {
                continue;
            }
            entries.push(UniversalBinaryEntry {
                arch: MachoArch::from_cputype(cputype),
                offset,
                size,
                align,
                data: bytes[start..end].to_vec(),
            });
        }
        Ok(entries)
    }

    /// Select the "best" slice from a universal binary.
    /// Preference order: `x86_64` > arm64 > any other.
    #[must_use] 
    pub fn select_best_slice(entries: &[UniversalBinaryEntry]) -> Option<&UniversalBinaryEntry> {
        if entries.is_empty() {
            return None;
        }
        if let Some(e) = entries.iter().find(|e| e.arch == MachoArch::X86_64) {
            return Some(e);
        }
        if let Some(e) = entries.iter().find(|e| e.arch == MachoArch::Arm64) {
            return Some(e);
        }
        entries.first()
    }

    /// Parse a single (non-fat) Mach-O binary slice.
    pub fn parse_single(bytes: &[u8]) -> Result<MachoInfo, CoreError> {
        if bytes.len() < 4 {
            return Err(CoreError::InvalidFormat {
                message: "Slice too small".into(),
            });
        }
        // Use goblin to validate that this is a well-formed Mach-O object before
        // proceeding with our detailed hand-rolled parser.  goblin::peek_bytes()
        // inspects the first 16 bytes to detect the object type without allocating
        // a full parse tree, providing a cheap pre-flight check that catches
        // truncated or corrupt headers early.
        {
            let mut hint_bytes = [0u8; 16];
            let n = bytes.len().min(16);
            hint_bytes[..n].copy_from_slice(&bytes[..n]);
            // If goblin cannot recognise the magic at all (unknown format),
            // fall through and let our own magic-check below produce a
            // more descriptive error message.
            let _ = goblin::peek_bytes(&hint_bytes);
        }
        let magic_le = u32::from_le_bytes(bytes[..4].try_into().unwrap());

        let (is_64, big_endian) = match magic_le {
            MH_MAGIC => (false, false),
            MH_CIGAM => (false, true),
            MH_MAGIC_64 => (true, false),
            MH_CIGAM_64 => (true, true),
            other => {
                return Err(CoreError::InvalidFormat {
                    message: format!("Unknown Mach-O magic: 0x{other:08X}"),
                });
            }
        };

        // Mach-O header layout:
        // 32-bit: magic(4) + cputype(4) + cpusubtype(4) + filetype(4) + ncmds(4) + sizeofcmds(4) + flags(4) = 28 bytes
        // 64-bit: same + reserved(4) = 32 bytes
        let hdr_size = if is_64 { 32 } else { 28 };
        if bytes.len() < hdr_size {
            return Err(CoreError::InvalidFormat {
                message: "Mach-O header truncated".into(),
            });
        }

        let read32 = |off: usize| -> u32 {
            if big_endian {
                read_u32_be(bytes, off).unwrap_or(0)
            } else {
                read_u32_le(bytes, off).unwrap_or(0)
            }
        };

        let cputype = read32(4);
        // cpusubtype at 8 (not needed for arch detection)
        let filetype = read32(12);
        let ncmds = read32(16);
        let _sizeofcmds = read32(20);
        let flags = read32(24);

        let arch = MachoArch::from_cputype(cputype);
        let file_type = MachoFileType::from_filetype(filetype);
        let (is_pie, _) = Self::decode_flags(flags, &file_type);

        let mut segments: Vec<MachoSegment> = Vec::new();
        let mut load_commands: Vec<MachoLoadCommand> = Vec::new();
        let mut entry_points: Vec<Address> = Vec::new();
        let mut dylibs: Vec<String> = Vec::new();
        let mut rpaths: Vec<String> = Vec::new();
        let mut uuid: Option<[u8; 16]> = None;
        let mut source_version: Option<u64> = None;
        let mut has_code_signature = false;
        let mut min_os_version: Option<String> = None;
        let mut platform: Option<String> = None;
        let mut symtab_off: u32 = 0;
        let mut nsyms: u32 = 0;
        let mut strtab_off: u32 = 0;
        let mut strtab_size: u32 = 0;
        let mut text_entry: u64 = 0; // for __TEXT vm_addr (used with LC_MAIN)
        let mut dyld_rebase_off: u32 = 0;
        let mut dyld_rebase_size: u32 = 0;
        let mut dyld_bind_off: u32 = 0;
        let mut dyld_bind_size: u32 = 0;
        let mut dyld_lazy_bind_off: u32 = 0;
        let mut dyld_lazy_bind_size: u32 = 0;
        let mut dyld_export_off: u32 = 0;
        let mut dyld_export_size: u32 = 0;
        let mut func_starts_off: u32 = 0;
        let mut func_starts_size: u32 = 0;
        let mut data_in_code_off: u32 = 0;
        let mut data_in_code_size: u32 = 0;
        let mut code_sig_off: u32 = 0;
        let mut code_sig_size: u32 = 0;
        let mut dyld_exports_trie_off: u32 = 0;
        let mut dyld_exports_trie_size: u32 = 0;
        let mut chained_fixups_off: u32 = 0;
        let mut chained_fixups_size: u32 = 0;
        let cpu_subtype = read32(8);

        // Walk load commands
        let mut lc_off = hdr_size;
        for _ in 0..ncmds {
            if lc_off + 8 > bytes.len() {
                break;
            }
            let cmd = read32(lc_off);
            let cmdsize = read32(lc_off + 4) as usize;
            if cmdsize < 8 || lc_off + cmdsize > bytes.len() {
                break;
            }
            let lc_bytes = &bytes[lc_off..lc_off + cmdsize];

            // Helper closures scoped to lc_bytes + big_endian
            let lc_read32 = |off: usize| -> u32 {
                if big_endian {
                    read_u32_be(lc_bytes, off).unwrap_or(0)
                } else {
                    read_u32_le(lc_bytes, off).unwrap_or(0)
                }
            };
            let lc_read64 = |off: usize| -> u64 {
                if big_endian {
                    read_u64_be(lc_bytes, off).unwrap_or(0)
                } else {
                    read_u64_le(lc_bytes, off).unwrap_or(0)
                }
            };

            let cmd_name = Self::lc_name(cmd).to_string();
            let lc_data: MachoLoadCommandData = match cmd {
                LC_SEGMENT => {
                    // segment_command: cmd(4)+cmdsize(4)+segname(16)+vmaddr(4)+vmsize(4)+fileoff(4)+filesize(4)+maxprot(4)+initprot(4)+nsects(4)+flags(4) = 56
                    if lc_bytes.len() < 56 {
                        MachoLoadCommandData::Other
                    } else {
                        let seg_name = read_cstr(lc_bytes, 8, 16);
                        let vm_addr = u64::from(lc_read32(24));
                        let vm_size = u64::from(lc_read32(28));
                        let file_offset = u64::from(lc_read32(32));
                        let file_size_val = u64::from(lc_read32(36));
                        let max_prot = lc_read32(40);
                        let init_prot = lc_read32(44);
                        let nsects = lc_read32(48) as usize;
                        if seg_name == "__TEXT" {
                            text_entry = vm_addr;
                        }
                        let mut sections = Vec::new();
                        // section (32-bit): sectname(16)+segname(16)+addr(4)+size(4)+offset(4)+align(4)+...+flags(4) = 68 bytes
                        for si in 0..nsects {
                            let sec_base = 56 + si * 68;
                            if sec_base + 68 > lc_bytes.len() {
                                break;
                            }
                            let sec_name = read_cstr(lc_bytes, sec_base, 16);
                            let sec_seg = read_cstr(lc_bytes, sec_base + 16, 16);
                            let sec_addr = u64::from(lc_read32(sec_base + 32));
                            let sec_size = u64::from(lc_read32(sec_base + 36));
                            let sec_offset = lc_read32(sec_base + 40);
                            let sec_align = lc_read32(sec_base + 44);
                            let sec_flags = lc_read32(sec_base + 64);
                            sections.push(MachoSection {
                                name: sec_name,
                                segment: sec_seg,
                                addr: sec_addr,
                                size: sec_size,
                                offset: sec_offset,
                                align: sec_align,
                                flags: sec_flags,
                                section_type: MachoSectionType::from_flags(sec_flags),
                            });
                        }
                        let seg = MachoSegment {
                            name: seg_name,
                            vm_addr,
                            vm_size,
                            file_offset,
                            file_size: file_size_val,
                            max_prot,
                            init_prot,
                            sections,
                        };
                        segments.push(seg.clone());
                        MachoLoadCommandData::Segment(seg)
                    }
                }
                LC_SEGMENT_64 => {
                    // segment_command_64: cmd(4)+cmdsize(4)+segname(16)+vmaddr(8)+vmsize(8)+fileoff(8)+filesize(8)+maxprot(4)+initprot(4)+nsects(4)+flags(4) = 72
                    if lc_bytes.len() < 72 {
                        MachoLoadCommandData::Other
                    } else {
                        let seg_name = read_cstr(lc_bytes, 8, 16);
                        let vm_addr = lc_read64(24);
                        let vm_size = lc_read64(32);
                        let file_offset = lc_read64(40);
                        let file_size_val = lc_read64(48);
                        let max_prot = lc_read32(56);
                        let init_prot = lc_read32(60);
                        let nsects = lc_read32(64) as usize;
                        if seg_name == "__TEXT" {
                            text_entry = vm_addr;
                        }
                        let mut sections = Vec::new();
                        // section_64: sectname(16)+segname(16)+addr(8)+size(8)+offset(4)+align(4)+...+flags(4) = 80 bytes
                        for si in 0..nsects {
                            let sec_base = 72 + si * 80;
                            if sec_base + 80 > lc_bytes.len() {
                                break;
                            }
                            let sec_name = read_cstr(lc_bytes, sec_base, 16);
                            let sec_seg = read_cstr(lc_bytes, sec_base + 16, 16);
                            let sec_addr = lc_read64(sec_base + 32);
                            let sec_size = lc_read64(sec_base + 40);
                            let sec_offset = lc_read32(sec_base + 48);
                            let sec_align = lc_read32(sec_base + 52);
                            let sec_flags = lc_read32(sec_base + 64); // flags at offset 64 in section_64
                            sections.push(MachoSection {
                                name: sec_name,
                                segment: sec_seg,
                                addr: sec_addr,
                                size: sec_size,
                                offset: sec_offset,
                                align: sec_align,
                                flags: sec_flags,
                                section_type: MachoSectionType::from_flags(sec_flags),
                            });
                        }
                        let seg = MachoSegment {
                            name: seg_name,
                            vm_addr,
                            vm_size,
                            file_offset,
                            file_size: file_size_val,
                            max_prot,
                            init_prot,
                            sections,
                        };
                        segments.push(seg.clone());
                        MachoLoadCommandData::Segment(seg)
                    }
                }
                LC_SYMTAB => {
                    // symtab_command: cmd(4)+cmdsize(4)+symoff(4)+nsyms(4)+stroff(4)+strsize(4)
                    if lc_bytes.len() >= 24 {
                        symtab_off = lc_read32(8);
                        nsyms = lc_read32(12);
                        strtab_off = lc_read32(16);
                        strtab_size = lc_read32(20);
                    }
                    MachoLoadCommandData::Other
                }
                LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                    if lc_bytes.len() >= 48 {
                        dyld_rebase_off = lc_read32(8);
                        dyld_rebase_size = lc_read32(12);
                        dyld_bind_off = lc_read32(16);
                        dyld_bind_size = lc_read32(20);
                        // weak bind at 24..28
                        dyld_lazy_bind_off = lc_read32(32);
                        dyld_lazy_bind_size = lc_read32(36);
                        dyld_export_off = lc_read32(40);
                        dyld_export_size = lc_read32(44);
                        MachoLoadCommandData::DyldInfo {
                            rebase_off: dyld_rebase_off,
                            rebase_size: dyld_rebase_size,
                            bind_off: dyld_bind_off,
                            bind_size: dyld_bind_size,
                            weak_bind_off: lc_read32(24),
                            weak_bind_size: lc_read32(28),
                            lazy_bind_off: dyld_lazy_bind_off,
                            lazy_bind_size: dyld_lazy_bind_size,
                            export_off: dyld_export_off,
                            export_size: dyld_export_size,
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_FUNCTION_STARTS => {
                    if lc_bytes.len() >= 16 {
                        func_starts_off = lc_read32(8);
                        func_starts_size = lc_read32(12);
                        MachoLoadCommandData::FunctionStarts {
                            offset: func_starts_off,
                            size: func_starts_size,
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_DATA_IN_CODE => {
                    if lc_bytes.len() >= 16 {
                        data_in_code_off = lc_read32(8);
                        data_in_code_size = lc_read32(12);
                        MachoLoadCommandData::DataInCode {
                            offset: data_in_code_off,
                            size: data_in_code_size,
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_DYLD_EXPORTS_TRIE => {
                    if lc_bytes.len() >= 16 {
                        dyld_exports_trie_off = lc_read32(8);
                        dyld_exports_trie_size = lc_read32(12);
                        MachoLoadCommandData::DyldExportsTrie {
                            offset: dyld_exports_trie_off,
                            size: dyld_exports_trie_size,
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_DYLD_CHAINED_FIXUPS => {
                    if lc_bytes.len() >= 16 {
                        chained_fixups_off = lc_read32(8);
                        chained_fixups_size = lc_read32(12);
                        MachoLoadCommandData::DyldChainedFixups {
                            offset: chained_fixups_off,
                            size: chained_fixups_size,
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_NOTE => {
                    // note_command: cmd(4)+cmdsize(4)+data_owner(16)+offset(8)+size(8)
                    if lc_bytes.len() >= 40 {
                        let data_owner = read_cstr(lc_bytes, 8, 16);
                        let offset = lc_read64(24);
                        let size = lc_read64(32);
                        MachoLoadCommandData::Note {
                            data_owner,
                            offset,
                            size,
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_FILESET_ENTRY => {
                    // fileset_entry_command: cmd(4)+cmdsize(4)+vmaddr(8)+fileoff(8)+entry_id_off(4)+reserved(4)
                    if lc_bytes.len() >= 32 {
                        let vm_addr = lc_read64(8);
                        let file_offset = lc_read64(16);
                        let id_off = lc_read32(24) as usize;
                        let entry_id = read_lc_str(lc_bytes, id_off);
                        MachoLoadCommandData::FilesetEntry {
                            vm_addr,
                            file_offset,
                            entry_id,
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_LAZY_LOAD_DYLIB | LC_REEXPORT_DYLIB
                | LC_LOAD_UPWARD_DYLIB | LC_ID_DYLIB => {
                    // dylib_command: cmd(4)+cmdsize(4)+name_off(4)+timestamp(4)+current_ver(4)+compat_ver(4)
                    if lc_bytes.len() >= 24 {
                        let name_off = lc_read32(8) as usize;
                        let timestamp = lc_read32(12);
                        let current_version = lc_read32(16);
                        let compatibility_version = lc_read32(20);
                        let name = read_lc_str(lc_bytes, name_off);
                        if cmd != LC_ID_DYLIB && !name.is_empty() {
                            dylibs.push(name.clone());
                        }
                        if cmd == LC_ID_DYLIB {
                            MachoLoadCommandData::DylibId { name }
                        } else {
                            MachoLoadCommandData::Dylib {
                                name,
                                timestamp,
                                current_version,
                                compatibility_version,
                            }
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_RPATH => {
                    if lc_bytes.len() >= 12 {
                        let path_off = lc_read32(8) as usize;
                        let path = read_lc_str(lc_bytes, path_off);
                        rpaths.push(path.clone());
                        MachoLoadCommandData::Rpath(path)
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_UUID => {
                    if lc_bytes.len() >= 24 {
                        let mut u = [0u8; 16];
                        u.copy_from_slice(&lc_bytes[8..24]);
                        uuid = Some(u);
                        MachoLoadCommandData::Uuid(u)
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_MAIN => {
                    // entry_point_command: cmd(4)+cmdsize(4)+entryoff(8)+stacksize(8)
                    if lc_bytes.len() >= 24 {
                        let entry_offset = lc_read64(8);
                        let stack_size = lc_read64(16);
                        // LC_MAIN entryoff is relative to the __TEXT segment vmaddr
                        let ep = text_entry.wrapping_add(entry_offset);
                        entry_points.push(Address::new(ep));
                        MachoLoadCommandData::Entrypoint {
                            entry_offset,
                            stack_size,
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_UNIX_THREAD | LC_THREAD => {
                    // thread_command: cmd(4)+cmdsize(4)+ flavors...
                    // For x86_64: flavor(4)+count(4)+state(count*4)
                    // RIP is at different offsets per arch; we do best-effort
                    let ep = Self::extract_thread_entry(lc_bytes, arch, big_endian);
                    if ep != 0 {
                        entry_points.push(Address::new(ep));
                    }
                    MachoLoadCommandData::UnixThread { entry_point: ep }
                }
                LC_SOURCE_VERSION => {
                    if lc_bytes.len() >= 16 {
                        let ver = lc_read64(8);
                        source_version = Some(ver);
                        MachoLoadCommandData::SourceVersion(ver)
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_VERSION_MIN_MACOSX => {
                    if lc_bytes.len() >= 16 {
                        let version = lc_read32(8);
                        let sdk = lc_read32(12);
                        let vs = Self::decode_version(version);
                        min_os_version = Some(vs.clone());
                        platform = Some("macOS".into());
                        MachoLoadCommandData::MinOsVersion {
                            platform: "macOS".into(),
                            version,
                            sdk,
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_VERSION_MIN_IPHONEOS => {
                    if lc_bytes.len() >= 16 {
                        let version = lc_read32(8);
                        let sdk = lc_read32(12);
                        let vs = Self::decode_version(version);
                        min_os_version = Some(vs.clone());
                        platform = Some("iOS".into());
                        MachoLoadCommandData::MinOsVersion {
                            platform: "iOS".into(),
                            version,
                            sdk,
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_VERSION_MIN_TVOS => {
                    if lc_bytes.len() >= 16 {
                        let version = lc_read32(8);
                        let sdk = lc_read32(12);
                        let vs = Self::decode_version(version);
                        min_os_version = Some(vs.clone());
                        platform = Some("tvOS".into());
                        MachoLoadCommandData::MinOsVersion {
                            platform: "tvOS".into(),
                            version,
                            sdk,
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_VERSION_MIN_WATCHOS => {
                    if lc_bytes.len() >= 16 {
                        let version = lc_read32(8);
                        let sdk = lc_read32(12);
                        let vs = Self::decode_version(version);
                        min_os_version = Some(vs.clone());
                        platform = Some("watchOS".into());
                        MachoLoadCommandData::MinOsVersion {
                            platform: "watchOS".into(),
                            version,
                            sdk,
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_BUILD_VERSION => {
                    // build_version_command: cmd(4)+cmdsize(4)+platform(4)+minos(4)+sdk(4)+ntools(4)
                    if lc_bytes.len() >= 24 {
                        let plat_id = lc_read32(8);
                        let minos = lc_read32(12);
                        let sdk = lc_read32(16);
                        let plat_name = match plat_id {
                            1 => "macOS",
                            2 => "iOS",
                            3 => "tvOS",
                            4 => "watchOS",
                            5 => "bridgeOS",
                            6 => "iOSSimulator",
                            7 => "tvOSSimulator",
                            8 => "watchOSSimulator",
                            9 => "driverKit",
                            _ => "unknown",
                        }
                        .to_string();
                        let vs = Self::decode_version(minos);
                        min_os_version = Some(vs);
                        platform = Some(plat_name.clone());
                        MachoLoadCommandData::BuildVersion {
                            platform: plat_name,
                            minos,
                            sdk,
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_CODE_SIGNATURE => {
                    has_code_signature = true;
                    if lc_bytes.len() >= 16 {
                        let offset = lc_read32(8);
                        let size = lc_read32(12);
                        code_sig_off = offset;
                        code_sig_size = size;
                        MachoLoadCommandData::CodeSignature { offset, size }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_ENCRYPTION_INFO => {
                    if lc_bytes.len() >= 20 {
                        let offset = lc_read32(8);
                        let size = lc_read32(12);
                        let cryptid = lc_read32(16);
                        MachoLoadCommandData::Encryption {
                            cryptid,
                            offset,
                            size,
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                LC_ENCRYPTION_INFO_64 => {
                    if lc_bytes.len() >= 24 {
                        let offset = lc_read32(8);
                        let size = lc_read32(12);
                        let cryptid = lc_read32(16);
                        MachoLoadCommandData::Encryption {
                            cryptid,
                            offset,
                            size,
                        }
                    } else {
                        MachoLoadCommandData::Other
                    }
                }
                _ => MachoLoadCommandData::Other,
            };

            load_commands.push(MachoLoadCommand {
                cmd,
                cmd_name,
                data: lc_data,
            });
            lc_off += cmdsize;
        }

        // Parse symbol table
        let symbols = Self::parse_symtab(
            bytes,
            symtab_off,
            nsyms,
            strtab_off,
            strtab_size,
            is_64,
            big_endian,
        );

        // Derive imports from undefined external symbols
        let imports = Self::build_imports(&symbols, &dylibs, flags);

        // Derive exports from defined external symbols
        let mut exports = Self::build_exports(&symbols);

        // Parse LC_FUNCTION_STARTS blob
        let function_starts = if func_starts_off != 0 && func_starts_size != 0 {
            let start = func_starts_off as usize;
            let end = start.saturating_add(func_starts_size as usize);
            bytes.get(start..end.min(bytes.len())).map_or_else(Vec::new, |blob| FunctionStartsParser::parse(blob, text_entry))
        } else {
            Vec::new()
        };

        // Parse LC_DATA_IN_CODE blob
        let data_in_code = if data_in_code_off != 0 && data_in_code_size != 0 {
            let start = data_in_code_off as usize;
            let end = start.saturating_add(data_in_code_size as usize);
            bytes.get(start..end.min(bytes.len())).map_or_else(Vec::new, DataInCodeParser::parse)
        } else {
            Vec::new()
        };

        // Parse rebase opcodes
        let rebase_entries = if dyld_rebase_off != 0 && dyld_rebase_size != 0 {
            let start = dyld_rebase_off as usize;
            let end = start.saturating_add(dyld_rebase_size as usize);
            bytes.get(start..end.min(bytes.len())).map_or_else(Vec::new, RebaseParser::parse)
        } else {
            Vec::new()
        };

        // Parse bind opcodes
        let mut bind_entries = Vec::new();
        if dyld_bind_off != 0 && dyld_bind_size != 0 {
            let start = dyld_bind_off as usize;
            let end = start.saturating_add(dyld_bind_size as usize);
            if let Some(blob) = bytes.get(start..end.min(bytes.len())) {
                bind_entries.extend(DyldInfoParser::parse_bind(blob));
            }
        }
        if dyld_lazy_bind_off != 0 && dyld_lazy_bind_size != 0 {
            let start = dyld_lazy_bind_off as usize;
            let end = start.saturating_add(dyld_lazy_bind_size as usize);
            if let Some(blob) = bytes.get(start..end.min(bytes.len())) {
                let mut lazy = DyldInfoParser::parse_bind(blob);
                for e in &mut lazy {
                    // mark lazy binds
                    let _ = e; // already stored as BindEntry
                }
                bind_entries.extend(lazy);
            }
        }

        // Parse export trie (prefer LC_DYLD_EXPORTS_TRIE over dyld_info export)
        let (exp_off, exp_size) = if dyld_exports_trie_off != 0 {
            (dyld_exports_trie_off, dyld_exports_trie_size)
        } else {
            (dyld_export_off, dyld_export_size)
        };
        let export_entries = if exp_off != 0 && exp_size != 0 {
            let start = exp_off as usize;
            let end = start.saturating_add(exp_size as usize);
            bytes.get(start..end.min(bytes.len())).map_or_else(Vec::new, |blob| {
                let trie_exports = DyldInfoParser::parse_exports(blob);
                // merge into exports Vec
                for te in &trie_exports {
                    if !te.name.is_empty() && !exports.iter().any(|e| e.name == te.name) {
                        exports.push(MachoExport {
                            name: te.name.clone(),
                            address: te.offset,
                            flags: te.flags as u32,
                            is_reexport: (te.flags & 0x8) != 0,
                            reexport_from: None,
                        });
                    }
                }
                trie_exports
            })
        } else {
            Vec::new()
        };

        // Parse chained fixups
        let chained_fixup_imports = if chained_fixups_off != 0 && chained_fixups_size != 0 {
            let start = chained_fixups_off as usize;
            let end = start.saturating_add(chained_fixups_size as usize);
            bytes.get(start..end.min(bytes.len())).map_or_else(Vec::new, ChainedFixupsParser::parse_imports)
        } else {
            Vec::new()
        };

        // Parse code signature
        let code_signature = if code_sig_off != 0 && code_sig_size != 0 {
            let start = code_sig_off as usize;
            let end = start.saturating_add(code_sig_size as usize);
            bytes
                .get(start..end.min(bytes.len()))
                .and_then(|blob| CodeSignatureParser::parse(blob).ok())
        } else {
            None
        };

        // Parse ObjC metadata
        let mut objc_classes = Vec::new();
        let mut objc_protocols = Vec::new();
        let mut objc_categories = Vec::new();
        ObjcMetadataParser::extract_from_segments(
            bytes,
            &segments,
            is_64,
            big_endian,
            &mut objc_classes,
            &mut objc_protocols,
            &mut objc_categories,
        );

        // Parse Swift metadata
        let mut swift_types = Vec::new();
        let mut swift_proto_conformances = Vec::new();
        SwiftMetadataParser::extract_from_segments(
            bytes,
            &segments,
            &mut swift_types,
            &mut swift_proto_conformances,
        );

        Ok(MachoInfo {
            arch,
            cpu_subtype,
            file_type,
            flags,
            entry_points,
            segments,
            symbols,
            imports,
            exports,
            dylibs,
            rpaths,
            uuid,
            source_version,
            load_commands,
            has_code_signature,
            is_pie,
            is_fat: false,
            fat_slices: Vec::new(),
            min_os_version,
            platform,
            function_starts,
            data_in_code,
            bind_entries,
            export_entries,
            rebase_entries,
            objc_classes,
            objc_protocols,
            objc_categories,
            swift_types,
            swift_proto_conformances,
            code_signature,
            chained_fixup_imports,
        })
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn parse_symtab(
        bytes: &[u8],
        symoff: u32,
        nsyms: u32,
        stroff: u32,
        strsize: u32,
        is_64: bool,
        big_endian: bool,
    ) -> Vec<MachoSymbol> {
        if nsyms == 0 || symoff == 0 {
            return Vec::new();
        }
        let strtab_start = stroff as usize;
        let strtab_end = strtab_start.saturating_add(strsize as usize);
        let strtab = bytes
            .get(strtab_start..strtab_end.min(bytes.len()))
            .unwrap_or(&[]);

        let entry_size: usize = if is_64 { 16 } else { 12 };
        let mut syms = Vec::new();

        for i in 0..nsyms as usize {
            // Use checked arithmetic: symoff and nsyms come from untrusted binary data.
            let Some(base) = (symoff as usize).checked_add(i.saturating_mul(entry_size)) else { break };
            if base + entry_size > bytes.len() {
                break;
            }
            let read32 = |off: usize| -> u32 {
                if big_endian {
                    read_u32_be(bytes, off).unwrap_or(0)
                } else {
                    read_u32_le(bytes, off).unwrap_or(0)
                }
            };
            let read64 = |off: usize| -> u64 {
                if big_endian {
                    read_u64_be(bytes, off).unwrap_or(0)
                } else {
                    read_u64_le(bytes, off).unwrap_or(0)
                }
            };

            // nlist / nlist_64: n_strx(4) + n_type(1) + n_sect(1) + n_desc(2) + n_value(4 or 8)
            let strx = read32(base) as usize;
            let n_type = bytes.get(base + 4).copied().unwrap_or(0);
            let n_sect = bytes.get(base + 5).copied().unwrap_or(0);
            // n_desc at base+6 (2 bytes, unused for now)
            let value = if is_64 {
                read64(base + 8)
            } else {
                u64::from(read32(base + 8))
            };

            let is_debug = n_type & N_STAB != 0;
            let is_external = n_type & N_EXT != 0;
            let type_bits = n_type & N_TYPE;
            let sym_type = match type_bits {
                N_ABS => MachoSymbolType::Absolute,
                N_SECT => MachoSymbolType::Section,
                N_PBUD => MachoSymbolType::PreboundUndefined,
                N_INDR => MachoSymbolType::Indirect,
                _ => MachoSymbolType::Undefined,
            };
            let is_undefined = sym_type == MachoSymbolType::Undefined && value == 0;

            // Read name from string table
            let name = if strx < strtab.len() {
                let slice = &strtab[strx..];
                let null_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
                String::from_utf8_lossy(&slice[..null_pos]).into_owned()
            } else {
                String::new()
            };

            syms.push(MachoSymbol {
                name,
                value,
                section_index: n_sect,
                sym_type,
                is_external,
                is_debug,
                is_undefined,
            });
        }
        syms
    }

    fn build_imports(symbols: &[MachoSymbol], dylibs: &[String], _flags: u32) -> Vec<MachoImport> {
        // Undefined external symbols are imports.
        // When TWOLEVEL is set each symbol encodes its dylib ordinal in n_desc,
        // but we store n_desc as part of the raw symbol and haven't threaded it
        // through to MachoSymbol yet, so we fall back to the first available dylib.
        symbols
            .iter()
            .filter(|s| s.is_undefined && s.is_external && !s.name.is_empty())
            .map(|s| MachoImport {
                name: s.name.clone(),
                dylib: dylibs.first().cloned().unwrap_or_default(),
                lazy: false,
                stub_addr: None,
            })
            .collect()
    }

    fn build_exports(symbols: &[MachoSymbol]) -> Vec<MachoExport> {
        symbols
            .iter()
            .filter(|s| s.is_external && !s.is_undefined && !s.is_debug && !s.name.is_empty())
            .map(|s| MachoExport {
                name: s.name.clone(),
                address: s.value,
                flags: 0,
                is_reexport: false,
                reexport_from: None,
            })
            .collect()
    }

    /// Extract the thread entry point from `LC_UNIX_THREAD` / `LC_THREAD` payload.
    fn extract_thread_entry(lc_bytes: &[u8], arch: MachoArch, big_endian: bool) -> u64 {
        // thread_command body starts at offset 8: flavor(4)+count(4)+state(...)
        if lc_bytes.len() < 16 {
            return 0;
        }
        let read32 = |off: usize| -> u32 {
            if big_endian {
                read_u32_be(lc_bytes, off).unwrap_or(0)
            } else {
                read_u32_le(lc_bytes, off).unwrap_or(0)
            }
        };
        let read64 = |off: usize| -> u64 {
            if big_endian {
                read_u64_be(lc_bytes, off).unwrap_or(0)
            } else {
                read_u64_le(lc_bytes, off).unwrap_or(0)
            }
        };

        // flavor at 8, count at 12, state starts at 16
        match arch {
            MachoArch::X86_64 => {
                // x86_thread_state64_t: 42 u64 registers; rip is at index 16 → offset 16 + 16*8 = 144
                if lc_bytes.len() >= 16 + 17 * 8 {
                    read64(16 + 16 * 8)
                } else {
                    0
                }
            }
            MachoArch::X86 => {
                // x86_thread_state32_t: eip at index 10 → offset 16 + 10*4 = 56
                if lc_bytes.len() >= 16 + 11 * 4 {
                    u64::from(read32(16 + 10 * 4))
                } else {
                    0
                }
            }
            MachoArch::Arm64 => {
                // arm_thread_state64_t: x0..x28(29*8), fp(8), lr(8), sp(8), pc(8) → pc at 16+32*8
                if lc_bytes.len() >= 16 + 33 * 8 {
                    read64(16 + 32 * 8)
                } else {
                    0
                }
            }
            MachoArch::Arm => {
                // arm_thread_state32_t: r0..r12(13*4), sp(4), lr(4), pc(4) → pc at 16+15*4
                if lc_bytes.len() >= 16 + 16 * 4 {
                    u64::from(read32(16 + 15 * 4))
                } else {
                    0
                }
            }
            MachoArch::PowerPc => {
                // ppc_thread_state: srr0 at index 0 → offset 16
                if lc_bytes.len() >= 20 {
                    u64::from(read32(16))
                } else {
                    0
                }
            }
            MachoArch::PowerPc64 => {
                if lc_bytes.len() >= 24 {
                    read64(16)
                } else {
                    0
                }
            }
            MachoArch::Arm64_32 => {
                // arm64_32 uses 32-bit pointers but 64-bit register state — same as arm64
                if lc_bytes.len() >= 16 + 33 * 8 {
                    read64(16 + 32 * 8)
                } else {
                    0
                }
            }
            MachoArch::Mips | MachoArch::Sparc | MachoArch::Unknown(_) => 0,
        }
    }

    /// Decode a version packed as `(major << 16) | (minor << 8) | patch` into `"major.minor.patch"`.
    fn decode_version(v: u32) -> String {
        let major = (v >> 16) & 0xFFFF;
        let minor = (v >> 8) & 0xFF;
        let patch = v & 0xFF;
        format!("{major}.{minor}.{patch}")
    }

    /// Decode header flags into `(is_pie, has_twolevel)`.
    const fn decode_flags(flags: u32, _file_type: &MachoFileType) -> (bool, bool) {
        let is_pie = flags & MH_PIE != 0;
        let has_twolevel = flags & MH_TWOLEVEL != 0;
        (is_pie, has_twolevel)
    }

    /// Map a raw load command constant to a human-readable name.
    const fn lc_name(cmd: u32) -> &'static str {
        match cmd {
            LC_SEGMENT => "LC_SEGMENT",
            LC_SYMTAB => "LC_SYMTAB",
            LC_THREAD => "LC_THREAD",
            LC_UNIX_THREAD => "LC_UNIX_THREAD",
            LC_DYSYMTAB => "LC_DYSYMTAB",
            LC_LOAD_DYLIB => "LC_LOAD_DYLIB",
            LC_ID_DYLIB => "LC_ID_DYLIB",
            LC_LOAD_DYLINKER => "LC_LOAD_DYLINKER",
            LC_ID_DYLINKER => "LC_ID_DYLINKER",
            LC_PREBOUND_DYLIB => "LC_PREBOUND_DYLIB",
            LC_ROUTINES => "LC_ROUTINES",
            LC_SUB_FRAMEWORK => "LC_SUB_FRAMEWORK",
            LC_TWOLEVEL_HINTS => "LC_TWOLEVEL_HINTS",
            LC_PREBIND_CKSUM => "LC_PREBIND_CKSUM",
            LC_LOAD_WEAK_DYLIB => "LC_LOAD_WEAK_DYLIB",
            LC_SEGMENT_64 => "LC_SEGMENT_64",
            LC_ROUTINES_64 => "LC_ROUTINES_64",
            LC_UUID => "LC_UUID",
            LC_RPATH => "LC_RPATH",
            LC_CODE_SIGNATURE => "LC_CODE_SIGNATURE",
            LC_SEGMENT_SPLIT_INFO => "LC_SEGMENT_SPLIT_INFO",
            LC_REEXPORT_DYLIB => "LC_REEXPORT_DYLIB",
            LC_LAZY_LOAD_DYLIB => "LC_LAZY_LOAD_DYLIB",
            LC_ENCRYPTION_INFO => "LC_ENCRYPTION_INFO",
            LC_DYLD_INFO => "LC_DYLD_INFO",
            LC_DYLD_INFO_ONLY => "LC_DYLD_INFO_ONLY",
            LC_LOAD_UPWARD_DYLIB => "LC_LOAD_UPWARD_DYLIB",
            LC_VERSION_MIN_MACOSX => "LC_VERSION_MIN_MACOSX",
            LC_VERSION_MIN_IPHONEOS => "LC_VERSION_MIN_IPHONEOS",
            LC_FUNCTION_STARTS => "LC_FUNCTION_STARTS",
            LC_DYLD_ENVIRONMENT => "LC_DYLD_ENVIRONMENT",
            LC_MAIN => "LC_MAIN",
            LC_DATA_IN_CODE => "LC_DATA_IN_CODE",
            LC_SOURCE_VERSION => "LC_SOURCE_VERSION",
            LC_DYLIB_CODE_SIGN_DRS => "LC_DYLIB_CODE_SIGN_DRS",
            LC_ENCRYPTION_INFO_64 => "LC_ENCRYPTION_INFO_64",
            LC_LINKER_OPTION => "LC_LINKER_OPTION",
            LC_LINKER_OPTIMIZATION_HINT => "LC_LINKER_OPTIMIZATION_HINT",
            LC_VERSION_MIN_TVOS => "LC_VERSION_MIN_TVOS",
            LC_VERSION_MIN_WATCHOS => "LC_VERSION_MIN_WATCHOS",
            LC_NOTE => "LC_NOTE",
            LC_BUILD_VERSION => "LC_BUILD_VERSION",
            LC_DYLD_EXPORTS_TRIE => "LC_DYLD_EXPORTS_TRIE",
            LC_DYLD_CHAINED_FIXUPS => "LC_DYLD_CHAINED_FIXUPS",
            LC_FILESET_ENTRY => "LC_FILESET_ENTRY",
            LC_ATOM_INFO => "LC_ATOM_INFO",
            _ => "LC_UNKNOWN",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stub Architecture implementation for BinaryView construction
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal architecture stub used when creating a `BinaryView` from a parsed Mach-O.
/// Full disassembly is delegated to the appropriate arch crate at runtime.
#[derive(Debug)]
struct MachoStubArch {
    name: String,
    pointer_size: usize,
    endian: Endian,
}

impl Architecture for MachoStubArch {
    fn name(&self) -> &str {
        &self.name
    }

    fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    fn endian(&self) -> Endian {
        self.endian
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        let byte = bytes.first().copied().unwrap_or(0);
        Ok(Instruction::new(address, 1, "??", vec![byte]))
    }

    fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
        Vec::new()
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        Vec::new()
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        Vec::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoLoader
// ─────────────────────────────────────────────────────────────────────────────

/// Mach-O binary loader.
#[derive(Debug)]
pub struct MachoLoader;

/// Convert Mach-O protection flags to `Permissions` bitflags.
fn prot_to_perms(prot: u32) -> Permissions {
    let mut p = Permissions::NONE;
    if prot & VM_PROT_READ != 0 {
        p |= Permissions::READ;
    }
    if prot & VM_PROT_WRITE != 0 {
        p |= Permissions::WRITE;
    }
    if prot & VM_PROT_EXECUTE != 0 {
        p |= Permissions::EXECUTE;
    }
    p
}

#[async_trait]
impl Loader for MachoLoader {
    fn name(&self) -> &'static str {
        "macho"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        let data = &input.data;
        if data.len() < 4 {
            return false;
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        matches!(
            magic,
            MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64 | FAT_MAGIC | FAT_CIGAM
        )
    }

    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let info = MachoParser::parse(&input.data)?;

        // Apply preferred base address slide if requested
        let base_slide: u64 = input.hints.base_address().map_or(0, rustre_core::Address::as_u64);

        let arch_stub: Arc<dyn Architecture> = Arc::new(MachoStubArch {
            name: info.arch.name().to_string(),
            pointer_size: info.arch.pointer_size(),
            endian: info.arch.endian(),
        });

        let mut mem = Memory::new();

        for seg in &info.segments {
            // Skip zero-size or __PAGEZERO segments
            if seg.vm_size == 0 || seg.file_size == 0 || seg.name == "__PAGEZERO" {
                continue;
            }
            let vm_start = seg.vm_addr.wrapping_add(base_slide);
            let vm_end = vm_start.saturating_add(seg.vm_size);
            let file_start = seg.file_offset as usize;
            let file_end = file_start.saturating_add(seg.file_size as usize);
            let seg_data = input
                .data
                .get(file_start..file_end.min(input.data.len()))
                .unwrap_or(&[])
                .to_vec();

            // Pad to vm_size with zeros
            let mut padded = seg_data;
            let vm_size = seg.vm_size as usize;
            if padded.len() < vm_size {
                padded.resize(vm_size, 0);
            }

            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(vm_start), Address::new(vm_end)),
                permissions: prot_to_perms(seg.init_prot),
                data: padded,
            });
        }

        let entry_points: Vec<Address> = info
            .entry_points
            .iter()
            .map(|ep| Address::new(ep.as_u64().wrapping_add(base_slide)))
            .collect();

        let bits = (info.arch.pointer_size() * 8) as u32;
        let view_id = ViewId::from_raw(0);

        let view = BinaryView::new(
            view_id,
            input.uri,
            arch_stub,
            info.arch.endian(),
            bits,
            entry_points,
            mem,
        );

        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        if input.data.len() < 4 {
            return Ok(Vec::new());
        }
        let magic =
            u32::from_le_bytes([input.data[0], input.data[1], input.data[2], input.data[3]]);
        if magic != FAT_MAGIC && magic != FAT_CIGAM {
            return Ok(Vec::new());
        }
        let entries = MachoParser::parse_fat(&input.data)?;
        let nested = entries
            .into_iter()
            .map(|e| {
                NestedBinary::new(
                    e.arch.name().to_string(),
                    e.data,
                    u64::from(e.offset),
                    BinaryType::Unknown,
                )
            })
            .collect();
        Ok(nested)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoLoadCommand enum  (spec §3.3 — all important load commands)
// ─────────────────────────────────────────────────────────────────────────────

/// Strongly-typed representation of all important Mach-O load commands.
///
/// Each variant carries exactly the fields defined in the Apple Mach-O ABI or
/// derived from Apple's open-source dyld / cctools.
#[derive(Debug, Clone)]
pub enum MachoLoadCommandEnum {
    /// `LC_SEGMENT_64` — a 64-bit virtual-memory segment.
    Segment64 {
        name: String,
        vmaddr: u64,
        vmsize: u64,
        fileoff: u32,
        filesize: u32,
        /// Collapsed max/init prot — use `init_prot` from the parsed `MachoSegment` for detail.
        prot: u32,
    },
    /// `LC_SYMTAB` — symbol table location and size.
    Symtab {
        symoff: u32,
        nsyms: u32,
        stroff: u32,
        strsize: u32,
    },
    /// `LC_DYSYMTAB` — dynamic symbol table information.
    Dysymtab {
        ilocalsym: u32,
        nlocalsym: u32,
        iextdefsym: u32,
        nextdefsym: u32,
        iundefsym: u32,
        nundefsym: u32,
        tocoff: u32,
        ntoc: u32,
        modtaboff: u32,
        nmodtab: u32,
        extrefsymoff: u32,
        nextrefsyms: u32,
        indirectsymoff: u32,
        nindirectsyms: u32,
        extreloff: u32,
        nextrel: u32,
        locreloff: u32,
        nlocrel: u32,
    },
    /// `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` — offsets and sizes for dyld info blobs.
    DyldInfo {
        rebase_off: u32,
        rebase_size: u32,
        bind_off: u32,
        bind_size: u32,
        weak_bind_off: u32,
        weak_bind_size: u32,
        lazy_bind_off: u32,
        lazy_bind_size: u32,
        export_off: u32,
        export_size: u32,
    },
    /// `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB` / `LC_REEXPORT_DYLIB` — dependent shared library.
    LoadDylib {
        name: String,
        timestamp: u32,
        current_version: u32,
        compat_version: u32,
    },
    /// `LC_RPATH` — run-path addition.
    RpathCommand { path: String },
    /// `LC_MAIN` — modern entry point (replaces `LC_UNIX_THREAD` for executables).
    EntryPoint { entryoff: u64, stacksize: u64 },
    /// `LC_FUNCTION_STARTS` — compressed function-start addresses.
    FunctionStarts { dataoff: u32, datasize: u32 },
    /// `LC_DATA_IN_CODE` — table of non-instruction ranges inside __TEXT.
    DataInCode { dataoff: u32, datasize: u32 },
    /// `LC_CODE_SIGNATURE` — detached code signature blob.
    CodeSignature { dataoff: u32, datasize: u32 },
    /// `LC_ENCRYPTION_INFO_64` — `FairPlay` DRM encryption range.
    EncryptionInfo64 {
        cryptoff: u32,
        cryptsize: u32,
        cryptid: u32,
    },
    /// `LC_VERSION_MIN_IPHONEOS` — minimum iOS version.
    MinVersionIos { version: u32, sdk: u32 },
    /// `LC_BUILD_VERSION` — modern platform / min-OS / SDK triplet.
    BuildVersion { platform: u32, minos: u32, sdk: u32 },
    /// Any load command not listed above.
    Unknown { cmd: u32, cmdsize: u32 },
}

impl MachoLoadCommandEnum {
    /// Parse all load commands from a Mach-O blob, starting at `lc_start` offset.
    /// `big_endian` selects byte order; `ncmds` is taken from the Mach-O header.
    #[must_use] 
    pub fn parse_all(bytes: &[u8], lc_start: usize, ncmds: u32, big_endian: bool) -> Vec<Self> {
        let read32 = |b: &[u8], off: usize| -> u32 {
            if big_endian {
                read_u32_be(b, off).unwrap_or(0)
            } else {
                read_u32_le(b, off).unwrap_or(0)
            }
        };
        let read64 = |b: &[u8], off: usize| -> u64 {
            if big_endian {
                read_u64_be(b, off).unwrap_or(0)
            } else {
                read_u64_le(b, off).unwrap_or(0)
            }
        };

        // Cap ncmds by the number of minimal (8-byte) load commands that can
        // fit in the remaining bytes, to avoid attacker-controlled allocations.
        let max_cmds = bytes.len().saturating_sub(lc_start) / 8;
        let mut out = Vec::with_capacity((ncmds as usize).min(max_cmds));
        let mut off = lc_start;
        for _ in 0..ncmds {
            if off + 8 > bytes.len() {
                break;
            }
            let cmd = read32(bytes, off);
            let cmdsize = read32(bytes, off + 4) as usize;
            if cmdsize < 8 || off + cmdsize > bytes.len() {
                break;
            }
            let lc = &bytes[off..off + cmdsize];

            let variant = match cmd {
                LC_SEGMENT_64 => {
                    if lc.len() >= 72 {
                        Self::Segment64 {
                            name: read_cstr(lc, 8, 16),
                            vmaddr: read64(lc, 24),
                            vmsize: read64(lc, 32),
                            fileoff: read32(lc, 40),
                            filesize: read32(lc, 48),
                            prot: read32(lc, 60), // init_prot
                        }
                    } else {
                        Self::Unknown {
                            cmd,
                            cmdsize: cmdsize as u32,
                        }
                    }
                }
                LC_SYMTAB => {
                    if lc.len() >= 24 {
                        Self::Symtab {
                            symoff: read32(lc, 8),
                            nsyms: read32(lc, 12),
                            stroff: read32(lc, 16),
                            strsize: read32(lc, 20),
                        }
                    } else {
                        Self::Unknown {
                            cmd,
                            cmdsize: cmdsize as u32,
                        }
                    }
                }
                LC_DYSYMTAB => {
                    if lc.len() >= 80 {
                        Self::Dysymtab {
                            ilocalsym: read32(lc, 8),
                            nlocalsym: read32(lc, 12),
                            iextdefsym: read32(lc, 16),
                            nextdefsym: read32(lc, 20),
                            iundefsym: read32(lc, 24),
                            nundefsym: read32(lc, 28),
                            tocoff: read32(lc, 32),
                            ntoc: read32(lc, 36),
                            modtaboff: read32(lc, 40),
                            nmodtab: read32(lc, 44),
                            extrefsymoff: read32(lc, 48),
                            nextrefsyms: read32(lc, 52),
                            indirectsymoff: read32(lc, 56),
                            nindirectsyms: read32(lc, 60),
                            extreloff: read32(lc, 64),
                            nextrel: read32(lc, 68),
                            locreloff: read32(lc, 72),
                            nlocrel: read32(lc, 76),
                        }
                    } else {
                        Self::Unknown {
                            cmd,
                            cmdsize: cmdsize as u32,
                        }
                    }
                }
                LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                    if lc.len() >= 48 {
                        Self::DyldInfo {
                            rebase_off: read32(lc, 8),
                            rebase_size: read32(lc, 12),
                            bind_off: read32(lc, 16),
                            bind_size: read32(lc, 20),
                            weak_bind_off: read32(lc, 24),
                            weak_bind_size: read32(lc, 28),
                            lazy_bind_off: read32(lc, 32),
                            lazy_bind_size: read32(lc, 36),
                            export_off: read32(lc, 40),
                            export_size: read32(lc, 44),
                        }
                    } else {
                        Self::Unknown {
                            cmd,
                            cmdsize: cmdsize as u32,
                        }
                    }
                }
                LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
                | LC_LOAD_UPWARD_DYLIB => {
                    if lc.len() >= 24 {
                        let name_off = read32(lc, 8) as usize;
                        Self::LoadDylib {
                            name: read_lc_str(lc, name_off),
                            timestamp: read32(lc, 12),
                            current_version: read32(lc, 16),
                            compat_version: read32(lc, 20),
                        }
                    } else {
                        Self::Unknown {
                            cmd,
                            cmdsize: cmdsize as u32,
                        }
                    }
                }
                LC_RPATH => {
                    if lc.len() >= 12 {
                        let path_off = read32(lc, 8) as usize;
                        Self::RpathCommand {
                            path: read_lc_str(lc, path_off),
                        }
                    } else {
                        Self::Unknown {
                            cmd,
                            cmdsize: cmdsize as u32,
                        }
                    }
                }
                LC_MAIN => {
                    if lc.len() >= 24 {
                        Self::EntryPoint {
                            entryoff: read64(lc, 8),
                            stacksize: read64(lc, 16),
                        }
                    } else {
                        Self::Unknown {
                            cmd,
                            cmdsize: cmdsize as u32,
                        }
                    }
                }
                LC_FUNCTION_STARTS => {
                    if lc.len() >= 16 {
                        Self::FunctionStarts {
                            dataoff: read32(lc, 8),
                            datasize: read32(lc, 12),
                        }
                    } else {
                        Self::Unknown {
                            cmd,
                            cmdsize: cmdsize as u32,
                        }
                    }
                }
                LC_DATA_IN_CODE => {
                    if lc.len() >= 16 {
                        Self::DataInCode {
                            dataoff: read32(lc, 8),
                            datasize: read32(lc, 12),
                        }
                    } else {
                        Self::Unknown {
                            cmd,
                            cmdsize: cmdsize as u32,
                        }
                    }
                }
                LC_CODE_SIGNATURE => {
                    if lc.len() >= 16 {
                        Self::CodeSignature {
                            dataoff: read32(lc, 8),
                            datasize: read32(lc, 12),
                        }
                    } else {
                        Self::Unknown {
                            cmd,
                            cmdsize: cmdsize as u32,
                        }
                    }
                }
                LC_ENCRYPTION_INFO_64 => {
                    if lc.len() >= 24 {
                        Self::EncryptionInfo64 {
                            cryptoff: read32(lc, 8),
                            cryptsize: read32(lc, 12),
                            cryptid: read32(lc, 16),
                        }
                    } else {
                        Self::Unknown {
                            cmd,
                            cmdsize: cmdsize as u32,
                        }
                    }
                }
                LC_VERSION_MIN_IPHONEOS => {
                    if lc.len() >= 16 {
                        Self::MinVersionIos {
                            version: read32(lc, 8),
                            sdk: read32(lc, 12),
                        }
                    } else {
                        Self::Unknown {
                            cmd,
                            cmdsize: cmdsize as u32,
                        }
                    }
                }
                LC_BUILD_VERSION => {
                    if lc.len() >= 24 {
                        Self::BuildVersion {
                            platform: read32(lc, 8),
                            minos: read32(lc, 12),
                            sdk: read32(lc, 16),
                        }
                    } else {
                        Self::Unknown {
                            cmd,
                            cmdsize: cmdsize as u32,
                        }
                    }
                }
                other => Self::Unknown {
                    cmd: other,
                    cmdsize: cmdsize as u32,
                },
            };
            out.push(variant);
            off += cmdsize;
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionStartsParser
// ─────────────────────────────────────────────────────────────────────────────

/// Parser for the `LC_FUNCTION_STARTS` linked-list blob.
///
/// The data blob is a sequence of ULEB128-encoded deltas from the start of the
/// `__TEXT` segment.  The first value is the offset from the segment start to
/// the first function; each subsequent value is the byte distance to the next.
/// A zero delta terminates the sequence.
pub struct FunctionStartsParser;

impl FunctionStartsParser {
    /// Decode ULEB128-encoded offsets and return absolute function start addresses.
    ///
    /// `data`      — raw bytes of the `LC_FUNCTION_STARTS` blob
    /// `base_addr` — VM address of the `__TEXT` segment (used as accumulator seed)
    ///
    /// Returns a sorted `Vec<u64>` of function start addresses.
    #[must_use] 
    pub fn parse(data: &[u8], base_addr: u64) -> Vec<u64> {
        let mut addresses = Vec::new();
        let mut cursor = 0usize;
        let mut current = base_addr;

        while cursor < data.len() {
            let (delta, consumed) = Self::read_uleb128(data, cursor);
            cursor += consumed;
            if consumed == 0 || delta == 0 {
                break;
            }
            current = current.wrapping_add(delta);
            addresses.push(current);
        }

        addresses.sort_unstable();
        addresses
    }

    /// Read a single ULEB128-encoded `u64` from `data` at `offset`.
    /// Returns `(value, bytes_consumed)`.  Returns `(0, 0)` on error.
    fn read_uleb128(data: &[u8], offset: usize) -> (u64, usize) {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        let mut consumed = 0usize;

        for &byte in data.get(offset..).unwrap_or(&[]) {
            consumed += 1;
            let low7 = u64::from(byte & 0x7F);
            result |= low7 << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                return (result, consumed);
            }
            if shift >= 64 {
                // Overflow guard — treat as terminator
                return (0, 0);
            }
        }
        (0, 0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldInfoParser — export trie and bind opcodes
// ─────────────────────────────────────────────────────────────────────────────

/// A single entry from the dyld export trie.
#[derive(Debug, Clone)]
pub struct ExportEntry {
    /// Mangled symbol name as stored in the trie.
    pub name: String,
    /// VM offset (add to image base to get runtime address).
    pub offset: u64,
    /// Raw export flags (`EXPORT_SYMBOL_FLAGS`_*).
    pub flags: u64,
}

/// A single bind opcode record from `LC_DYLD_INFO` bind data.
#[derive(Debug, Clone)]
pub struct BindEntry {
    /// Library ordinal (1-based index into the binary's dylib list).
    pub library_ordinal: u8,
    /// Mangled symbol name.
    pub symbol_name: String,
    /// Addend applied to the imported symbol's address.
    pub addend: i64,
    /// Target VM address to be patched.
    pub address: u64,
}

/// Stateless parser for dyld info blobs (export trie and bind opcodes).
pub struct DyldInfoParser;

// Bind opcode constants (from Apple's dyld source / mach-o/loader.h)
const BIND_OPCODE_DONE: u8 = 0x00;
const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
pub const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
const BIND_OPCODE_DO_BIND: u8 = 0x90;
const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xA0;
const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xB0;
const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;
/// Threaded binds, used by arm64e and modern iOS/macOS images. The sub-opcode
/// is carried in the immediate nibble.
const BIND_OPCODE_THREADED: u8 = 0xD0;
/// Threaded sub-opcode carrying a ULEB operand (the bind ordinal table size).
/// The other sub-opcode, APPLY (1), carries no operand.
const BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB: u8 = 0;

impl DyldInfoParser {
    /// Parse the export trie encoded in `data` and return all `ExportEntry` records.
    ///
    /// The trie is a radix/prefix tree where each node stores a partial label.
    /// Terminal nodes carry export flags and a ULEB128-encoded image-relative offset.
    #[must_use] 
    pub fn parse_exports(data: &[u8]) -> Vec<ExportEntry> {
        let mut out = Vec::new();
        if data.is_empty() {
            return out;
        }
        let mut prefix = String::new();
        Self::trie_walk(data, 0, &mut prefix, &mut out);
        out
    }

    /// Upper bound on the number of trie nodes visited in one walk.
    ///
    /// The depth guard below is not sufficient on its own. A trie whose child
    /// edges point backwards — trivially forged, and produced by chance in
    /// random bytes — is not an infinite loop, so no cycle check trips: it is a
    /// *branching* traversal that revisits the same nodes at every level, and
    /// 128 levels of that is astronomically many visits. `tests/fuzz_lite.rs`
    /// demonstrated it: three of its four cases ran past 90 seconds or died
    /// allocating 40 GiB, while every test still reported `ok` because the
    /// process aborted rather than failing an assertion.
    /// The bound is the INPUT LENGTH, not a fixed constant: every trie node
    /// consumes at least one byte, so a well-formed trie over `n` bytes cannot
    /// have more than `n` nodes. A flat `100_000` terminated the walk but left it
    /// ruinously slow — measured at **141 s** for this parser against ~0.5 s for
    /// every other parser in the crate on the same corpus, because `100_000`
    /// nodes of string building were still being done for an 8 KB input.
    fn trie_node_budget(data: &[u8]) -> u32 {
        u32::try_from(data.len()).unwrap_or(u32::MAX)
    }

    fn trie_walk(data: &[u8], node_off: usize, prefix: &mut String, out: &mut Vec<ExportEntry>) {
        let mut budget = Self::trie_node_budget(data);
        Self::trie_walk_depth(data, node_off, prefix, out, 0, &mut budget);
    }

    fn trie_walk_depth(
        data: &[u8],
        node_off: usize,
        prefix: &mut String,
        out: &mut Vec<ExportEntry>,
        depth: u32,
        budget: &mut u32,
    ) {
        // Guard against maliciously deep or cyclic tries (stack overflow prevention)
        if depth > 128 {
            return;
        }
        // ... and against wide ones: see `trie_node_budget`.
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        if node_off >= data.len() {
            return;
        }
        // Terminal info size (ULEB128).  0 means not a terminal node.
        let (terminal_size, n) = FunctionStartsParser::read_uleb128(data, node_off);
        if n == 0 {
            return;
        }
        let mut cursor = node_off + n;

        if terminal_size != 0 {
            // Guard against overflow: terminal_size comes from untrusted binary data.
            let term_end = cursor.saturating_add(terminal_size as usize);
            // flags ULEB128
            let (flags, fn_) = FunctionStartsParser::read_uleb128(data, cursor);
            cursor += fn_;

            const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
            const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

            let offset = if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
                // re-export: lib_ordinal ULEB128, then re-export-name cstring
                // We read lib_ordinal as the 'offset' field for the entry.
                let (lib_ordinal, lo) = FunctionStartsParser::read_uleb128(data, cursor);
                cursor += lo;
                // skip the re-export name cstring (NUL-terminated)
                while cursor < term_end && cursor < data.len() && data[cursor] != 0 {
                    cursor += 1;
                }
                if cursor < data.len() { cursor += 1; } // consume NUL
                lib_ordinal
            } else if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
                // stub+resolver: stub_offset ULEB128, resolver_offset ULEB128
                let (stub_off, so) = FunctionStartsParser::read_uleb128(data, cursor);
                cursor += so;
                let (_resolver_off, ro) = FunctionStartsParser::read_uleb128(data, cursor);
                cursor += ro;
                stub_off
            } else {
                // regular: offset ULEB128
                let (off, fo) = FunctionStartsParser::read_uleb128(data, cursor);
                cursor += fo;
                off
            };

            out.push(ExportEntry {
                name: prefix.clone(),
                offset,
                flags,
            });
            // Validate parse did not overshoot the node boundary.
            // This can legitimately happen with malformed/adversarial input —
            // we clamp the cursor back to the declared end rather than
            // panicking, which would create a DoS vector on untrusted binaries.
            // Only clamp on overshoot so the well-formed branch keeps the
            // cursor advances that read the actual ULEB widths and NUL byte.
            if cursor > term_end {
                cursor = term_end;
            }
        }

        if cursor >= data.len() {
            return;
        }
        // Child count
        let child_count = data[cursor] as usize;
        cursor += 1;

        for _ in 0..child_count {
            // Edge label — NUL-terminated string
            let label_start = cursor;
            while cursor < data.len() && data[cursor] != 0 {
                cursor += 1;
            }
            let label = String::from_utf8_lossy(&data[label_start..cursor]).into_owned();
            cursor += 1; // consume NUL

            // Child node offset — ULEB128
            let (child_off, cn) = FunctionStartsParser::read_uleb128(data, cursor);
            cursor += cn;
            if cn == 0 {
                break;
            }

            // Recurse
            prefix.push_str(&label);
            Self::trie_walk_depth(data, child_off as usize, prefix, out, depth + 1, budget);
            // Remove the label suffix we added.
            // label.len() is byte-length and push_str appends the same bytes, so the
            // subtraction is always valid (label.len() <= prefix.len() after the push).
            let new_len = prefix.len().saturating_sub(label.len());
            prefix.truncate(new_len);
        }
    }

    /// Parse bind opcodes from `data` and return all `BindEntry` records.
    ///
    /// This handles the standard dyld bind opcode stream (not chained fixups).
    /// Segment → address mapping is not performed here; `address` reflects the
    /// raw ULEB128 offset accumulated from `SET_SEGMENT_AND_OFFSET` / `ADD_ADDR` opcodes.
    #[must_use] 
    pub fn parse_bind(data: &[u8]) -> Vec<BindEntry> {
        let mut out = Vec::new();
        let mut cursor = 0usize;

        let mut library_ordinal: u8 = 0;
        let mut symbol_name = String::new();
        let mut addend: i64 = 0;
        let mut address: u64 = 0;

        while cursor < data.len() {
            let byte = data[cursor];
            cursor += 1;
            let opcode = byte & 0xF0;
            let imm = byte & 0x0F;

            match opcode {
                BIND_OPCODE_DONE => break,
                BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {
                    library_ordinal = imm;
                }
                BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                    let (v, n) = FunctionStartsParser::read_uleb128(data, cursor);
                    cursor += n;
                    library_ordinal = v as u8;
                }
                BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                    // Special ordinals are negative; encode in low nibble as two's complement
                    library_ordinal = if imm == 0 { 0 } else { 0xF0 | imm };
                }
                BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                    let start = cursor;
                    while cursor < data.len() && data[cursor] != 0 {
                        cursor += 1;
                    }
                    symbol_name = String::from_utf8_lossy(&data[start..cursor]).into_owned();
                    if cursor < data.len() {
                        cursor += 1; // consume NUL
                    }
                }
                BIND_OPCODE_SET_ADDEND_SLEB => {
                    let (v, n) = Self::read_sleb128(data, cursor);
                    cursor += n;
                    addend = v;
                }
                BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                    // imm = segment index; ULEB = offset within segment
                    let (seg_off, n) = FunctionStartsParser::read_uleb128(data, cursor);
                    cursor += n;
                    // We approximate address as seg_off for now (no segment base map)
                    address = seg_off;
                }
                BIND_OPCODE_ADD_ADDR_ULEB => {
                    let (v, n) = FunctionStartsParser::read_uleb128(data, cursor);
                    cursor += n;
                    address = address.wrapping_add(v);
                }
                BIND_OPCODE_DO_BIND => {
                    out.push(BindEntry {
                        library_ordinal,
                        symbol_name: symbol_name.clone(),
                        addend,
                        address,
                    });
                    address = address.wrapping_add(8); // pointer-sized step
                }
                BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                    out.push(BindEntry {
                        library_ordinal,
                        symbol_name: symbol_name.clone(),
                        addend,
                        address,
                    });
                    let (v, n) = FunctionStartsParser::read_uleb128(data, cursor);
                    cursor += n;
                    address = address.wrapping_add(v).wrapping_add(8);
                }
                BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                    out.push(BindEntry {
                        library_ordinal,
                        symbol_name: symbol_name.clone(),
                        addend,
                        address,
                    });
                    address = address.wrapping_add((u64::from(imm) + 1) * 8);
                }
                BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                    let (count, cn) = FunctionStartsParser::read_uleb128(data, cursor);
                    cursor += cn;
                    let (skip, sn) = FunctionStartsParser::read_uleb128(data, cursor);
                    cursor += sn;
                    // Cap attacker-controlled count to stream length to prevent
                    // runaway allocation.
                    let count = count.min(data.len() as u64);
                    for _ in 0..count {
                        out.push(BindEntry {
                            library_ordinal,
                            symbol_name: symbol_name.clone(),
                            addend,
                            address,
                        });
                        address = address.wrapping_add(skip + 8);
                    }
                }
                BIND_OPCODE_THREADED => {
                    // The sub-opcode lives in the immediate. Consuming this ULEB
                    // is what keeps the cursor aligned: skipping the opcode byte
                    // alone would leave the operand to be re-read as an opcode.
                    if imm == BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB {
                        let (_size, n) = FunctionStartsParser::read_uleb128(data, cursor);
                        cursor += n;
                    }
                }
                _ => {
                    // An opcode this decoder does not model. Stop rather than
                    // skip: its operands would be re-read as opcodes, and the
                    // caller would get fabricated entries mixed in with the real
                    // ones, with no way to tell them apart. A short table is
                    // honest; a desynchronised one is not.
                    break;
                }
            }
        }
        out
    }

    /// Read a signed LEB128 value from `data` at `offset`.
    /// Returns `(value, bytes_consumed)`.
    fn read_sleb128(data: &[u8], offset: usize) -> (i64, usize) {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        let mut consumed = 0usize;

        for &byte in data.get(offset..).unwrap_or(&[]) {
            consumed += 1;
            let low7 = i64::from(byte & 0x7F);
            result |= low7 << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                // Sign-extend if the sign bit of the last group is set
                if shift < 64 && (byte & 0x40) != 0 {
                    result |= -(1i64 << shift);
                }
                return (result, consumed);
            }
            if shift >= 64 {
                return (0, 0);
            }
        }
        (0, 0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DataInCodeParser
// ─────────────────────────────────────────────────────────────────────────────

/// Parser for the `LC_DATA_IN_CODE` blob.
///
/// Each entry is 8 bytes: offset(4) + length(2) + kind(2).
pub struct DataInCodeParser;

impl DataInCodeParser {
    /// Parse the `LC_DATA_IN_CODE` blob and return all entries.
    #[must_use] 
    pub fn parse(data: &[u8]) -> Vec<DataInCodeEntry> {
        let mut out = Vec::new();
        let mut cursor = 0usize;
        while cursor + 8 <= data.len() {
            let offset = u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap_or([0; 4]));
            let length =
                u16::from_le_bytes(data[cursor + 4..cursor + 6].try_into().unwrap_or([0; 2]));
            let kind_raw =
                u16::from_le_bytes(data[cursor + 6..cursor + 8].try_into().unwrap_or([0; 2]));
            out.push(DataInCodeEntry {
                offset,
                length,
                kind: DiceKind::from_raw(kind_raw),
            });
            cursor += 8;
        }
        out
    }

    /// Return the total count of non-instruction bytes covered by the entries.
    #[must_use] 
    pub fn total_data_bytes(entries: &[DataInCodeEntry]) -> u64 {
        entries.iter().map(|e| u64::from(e.length)).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RebaseParser
// ─────────────────────────────────────────────────────────────────────────────

/// Parser for `LC_DYLD_INFO_ONLY` rebase opcodes.
pub struct RebaseParser;

impl RebaseParser {
    /// Decode rebase opcodes from `data` and return all `RebaseEntry` records.
    #[must_use] 
    pub fn parse(data: &[u8]) -> Vec<RebaseEntry> {
        let mut out = Vec::new();
        let mut cursor = 0usize;
        let mut segment_index: u8 = 0;
        let mut segment_offset: u64 = 0;
        let mut rebase_type: u8 = REBASE_TYPE_POINTER;

        while cursor < data.len() {
            let byte = data[cursor];
            cursor += 1;
            let opcode = byte & 0xF0;
            let imm = byte & 0x0F;

            match opcode {
                REBASE_OPCODE_DONE => break,
                REBASE_OPCODE_SET_TYPE_IMM => {
                    rebase_type = imm;
                }
                REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                    segment_index = imm;
                    let (v, n) = FunctionStartsParser::read_uleb128(data, cursor);
                    cursor += n;
                    segment_offset = v;
                }
                REBASE_OPCODE_ADD_ADDR_ULEB => {
                    let (v, n) = FunctionStartsParser::read_uleb128(data, cursor);
                    cursor += n;
                    segment_offset = segment_offset.wrapping_add(v);
                }
                REBASE_OPCODE_ADD_ADDR_IMM_SCALED => {
                    segment_offset = segment_offset.wrapping_add(u64::from(imm) * 8);
                }
                REBASE_OPCODE_DO_REBASE_IMM_TIMES => {
                    for _ in 0..imm {
                        out.push(RebaseEntry {
                            segment_index,
                            segment_offset,
                            rebase_type,
                        });
                        segment_offset = segment_offset.wrapping_add(8);
                    }
                }
                REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
                    let (count, n) = FunctionStartsParser::read_uleb128(data, cursor);
                    cursor += n;
                    // Cap attacker-controlled count to the stream length to
                    // prevent runaway allocations.
                    let count = count.min(data.len() as u64);
                    for _ in 0..count {
                        out.push(RebaseEntry {
                            segment_index,
                            segment_offset,
                            rebase_type,
                        });
                        segment_offset = segment_offset.wrapping_add(8);
                    }
                }
                REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
                    out.push(RebaseEntry {
                        segment_index,
                        segment_offset,
                        rebase_type,
                    });
                    let (v, n) = FunctionStartsParser::read_uleb128(data, cursor);
                    cursor += n;
                    segment_offset = segment_offset.wrapping_add(v).wrapping_add(8);
                }
                REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                    let (count, cn) = FunctionStartsParser::read_uleb128(data, cursor);
                    cursor += cn;
                    let (skip, sn) = FunctionStartsParser::read_uleb128(data, cursor);
                    cursor += sn;
                    // Cap attacker-controlled count to the stream length.
                    let count = count.min(data.len() as u64);
                    for _ in 0..count {
                        out.push(RebaseEntry {
                            segment_index,
                            segment_offset,
                            rebase_type,
                        });
                        segment_offset = segment_offset.wrapping_add(skip).wrapping_add(8);
                    }
                }
                _ => {
                    // Unknown opcode — skip
                }
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ChainedFixupsParser
// ─────────────────────────────────────────────────────────────────────────────

/// Parser for `LC_DYLD_CHAINED_FIXUPS` blobs.
///
/// The blob starts with a `dyld_chained_fixups_header`:
///   `fixups_version(4)` + `starts_offset(4)` + `imports_offset(4)` + `symbols_offset(4)`
///   + `imports_count(4)` + `imports_format(4)` + `symbols_format(4)`
pub struct ChainedFixupsParser;

/// Chained fixup pointer format constants (matching `DYLD_CHAINED_PTR`_* above).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainedPtrFormat {
    Arm64E,
    Ptr64,
    Ptr32,
    Ptr32Cache,
    Ptr32Firmware,
    Ptr64Offset,
    Arm64EKernel,
    Ptr64KernelCache,
    Arm64EUserland,
    Arm64EFirmware,
    X86_64KernelCache,
    Arm64EUserland24,
    Unknown(u32),
}

impl ChainedPtrFormat {
    #[must_use] 
    pub const fn from_raw(v: u32) -> Self {
        match v {
            DYLD_CHAINED_PTR_ARM64E => Self::Arm64E,
            DYLD_CHAINED_PTR_64 => Self::Ptr64,
            DYLD_CHAINED_PTR_32 => Self::Ptr32,
            DYLD_CHAINED_PTR_32_CACHE => Self::Ptr32Cache,
            DYLD_CHAINED_PTR_32_FIRMWARE => Self::Ptr32Firmware,
            DYLD_CHAINED_PTR_64_OFFSET => Self::Ptr64Offset,
            DYLD_CHAINED_PTR_ARM64E_KERNEL => Self::Arm64EKernel,
            DYLD_CHAINED_PTR_64_KERNEL_CACHE => Self::Ptr64KernelCache,
            DYLD_CHAINED_PTR_ARM64E_USERLAND => Self::Arm64EUserland,
            DYLD_CHAINED_PTR_ARM64E_FIRMWARE => Self::Arm64EFirmware,
            DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE => Self::X86_64KernelCache,
            DYLD_CHAINED_PTR_ARM64E_USERLAND24 => Self::Arm64EUserland24,
            other => Self::Unknown(other),
        }
    }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Arm64E => "DYLD_CHAINED_PTR_ARM64E",
            Self::Ptr64 => "DYLD_CHAINED_PTR_64",
            Self::Ptr32 => "DYLD_CHAINED_PTR_32",
            Self::Ptr32Cache => "DYLD_CHAINED_PTR_32_CACHE",
            Self::Ptr32Firmware => "DYLD_CHAINED_PTR_32_FIRMWARE",
            Self::Ptr64Offset => "DYLD_CHAINED_PTR_64_OFFSET",
            Self::Arm64EKernel => "DYLD_CHAINED_PTR_ARM64E_KERNEL",
            Self::Ptr64KernelCache => "DYLD_CHAINED_PTR_64_KERNEL_CACHE",
            Self::Arm64EUserland => "DYLD_CHAINED_PTR_ARM64E_USERLAND",
            Self::Arm64EFirmware => "DYLD_CHAINED_PTR_ARM64E_FIRMWARE",
            Self::X86_64KernelCache => "DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE",
            Self::Arm64EUserland24 => "DYLD_CHAINED_PTR_ARM64E_USERLAND24",
            Self::Unknown(_) => "DYLD_CHAINED_PTR_UNKNOWN",
        }
    }
}

/// Metadata about a single segment's chained fixup page starts.
#[derive(Debug, Clone)]
pub struct ChainedStartsInSegment {
    /// Segment offset of first fixup chain.
    pub offset: u32,
    /// Page size (typically 4096).
    pub page_size: u16,
    /// Pointer format for this segment.
    pub pointer_format: ChainedPtrFormat,
    /// First segment offset covered by this record.
    pub segment_offset: u64,
    /// Maximum valid pointer value.
    pub max_valid_pointer: u32,
    /// Per-page chain start offsets (`DYLD_CHAINED_PTR_START_NONE` = 0xFFFF means no chain).
    pub page_starts: Vec<u16>,
}

impl ChainedFixupsParser {
    /// Parse the `LC_DYLD_CHAINED_FIXUPS` blob and return imported symbol entries.
    ///
    /// Format (`dyld_chained_fixups_header)`:
    ///   `fixups_version(4)` + `starts_offset(4)` + `imports_offset(4)` + `symbols_offset(4)`
    ///   + `imports_count(4)` + `imports_format(4)` + `symbols_format(4)` = 28 bytes
    pub fn parse_imports(data: &[u8]) -> Vec<ChainedFixupImport> {
        if data.len() < 28 {
            return Vec::new();
        }
        let read_u32 = |off: usize| -> u32 {
            data.get(off..off + 4)
                .and_then(|b| b.try_into().ok())
                .map_or(0, u32::from_le_bytes)
        };
        let _fixups_version = read_u32(0);
        let _starts_offset = read_u32(4);
        let imports_offset = read_u32(8) as usize;
        let symbols_offset = read_u32(12) as usize;
        let imports_count = read_u32(16) as usize;
        let imports_format = read_u32(20);
        let _symbols_format = read_u32(24);

        // imports_format: 1 = DYLD_CHAINED_IMPORT, 2 = DYLD_CHAINED_IMPORT_ADDEND,
        //                 3 = DYLD_CHAINED_IMPORT_ADDEND64
        let entry_size: usize = match imports_format {
            2 => 8,
            3 => 16,
            _ => 4,
        };

        // Cap imports_count to what can fit in the buffer to prevent
        // attacker-controlled massive allocations.
        let max_imports = data
            .len()
            .saturating_sub(imports_offset)
            .checked_div(entry_size.max(1))
            .unwrap_or(0);
        let imports_count = imports_count.min(max_imports);
        let mut out = Vec::with_capacity(imports_count);
        for i in 0..imports_count {
            let base = imports_offset + i * entry_size;
            if base + entry_size > data.len() {
                break;
            }
            // DYLD_CHAINED_IMPORT: lib_ordinal(8bits) | weak_import(1bit) | name_offset(23bits)
            let raw = read_u32(base);
            let lib_ordinal = (raw & 0xFF) as u8;
            let weak_import = (raw >> 8) & 1 != 0;
            let name_offset = (raw >> 9) as usize;
            let addend: u64 = if imports_format == 2 {
                // DYLD_CHAINED_IMPORT_ADDEND: addend is 32-bit signed at base+4
                data.get(base + 4..base + 8)
                    .and_then(|b| b.try_into().ok())
                    .map_or(0, |b| i64::from(i32::from_le_bytes(b)).cast_unsigned())
            } else if imports_format == 3 {
                // DYLD_CHAINED_IMPORT_ADDEND64: lib_ordinal 16bit, weak 1bit, name_off 31bit at +0; addend 64 at +8
                let raw64_lo = read_u32(base);
                let _raw64_hi = read_u32(base + 4);
                // re-extract for format 3
                let _ = raw64_lo;
                data.get(base + 8..base + 16)
                    .and_then(|b| b.try_into().ok())
                    .map_or(0, u64::from_le_bytes)
            } else {
                0
            };

            // Extract name from symbol pool.
            // Both symbols_offset and name_offset originate from untrusted binary data;
            // use checked_add to prevent integer overflow.
            let sym_off = symbols_offset.checked_add(name_offset);
            let name = sym_off.filter(|&o| o < data.len()).map_or_else(String::new, |sym_off| {
                let slice = &data[sym_off..];
                let null = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
                String::from_utf8_lossy(&slice[..null]).into_owned()
            });

            out.push(ChainedFixupImport {
                lib_ordinal,
                name,
                weak_import,
                addend,
            });
        }
        out
    }

    /// Parse segment start records from a `LC_DYLD_CHAINED_FIXUPS` blob.
    ///
    /// Returns one `ChainedStartsInSegment` per segment described in the blob.
    #[must_use] 
    pub fn parse_segment_starts(data: &[u8]) -> Vec<ChainedStartsInSegment> {
        if data.len() < 28 {
            return Vec::new();
        }
        let read_u16 = |off: usize| -> u16 {
            data.get(off..off + 2)
                .and_then(|b| b.try_into().ok())
                .map_or(0, u16::from_le_bytes)
        };
        let read_u32 = |off: usize| -> u32 {
            data.get(off..off + 4)
                .and_then(|b| b.try_into().ok())
                .map_or(0, u32::from_le_bytes)
        };
        let read_u64 = |off: usize| -> u64 {
            data.get(off..off + 8)
                .and_then(|b| b.try_into().ok())
                .map_or(0, u64::from_le_bytes)
        };

        let starts_offset = read_u32(4) as usize;
        if starts_offset.saturating_add(8) > data.len() {
            return Vec::new();
        }

        // dyld_chained_starts_in_image: size(4) + seg_count(4) + seg_info_offset[seg_count](4 each)
        let seg_count = read_u32(starts_offset + 4) as usize;
        // Cap seg_count to the number of 4-byte offsets that can fit in the remainder.
        let max_seg = (data.len().saturating_sub(starts_offset + 8)) / 4;
        let seg_count = seg_count.min(max_seg);
        let mut out = Vec::with_capacity(seg_count);

        for i in 0..seg_count {
            let Some(seg_info_off_field) = starts_offset.checked_add(8).and_then(|x| x.checked_add(i * 4)) else { break };
            if seg_info_off_field + 4 > data.len() {
                break;
            }
            let seg_info_offset = read_u32(seg_info_off_field) as usize;
            let Some(base) = starts_offset.checked_add(seg_info_offset) else { continue };
            if seg_info_offset == 0 || base.saturating_add(22) > data.len() {
                continue;
            }
            // dyld_chained_starts_in_segment:
            //  size(4) + page_size(2) + pointer_format(2) + segment_offset(8)
            //  + max_valid_pointer(4) + page_count(2) + page_start[page_count](2 each)
            let page_size = read_u16(base + 4);
            let pointer_format_raw = u32::from(read_u16(base + 6));
            let segment_offset = read_u64(base + 8);
            let max_valid_pointer = read_u32(base + 16);
            let page_count = read_u16(base + 20) as usize;
            let mut page_starts = Vec::with_capacity(page_count);
            for p in 0..page_count {
                let ps_off = base + 22 + p * 2;
                if ps_off + 2 > data.len() {
                    break;
                }
                page_starts.push(read_u16(ps_off));
            }
            out.push(ChainedStartsInSegment {
                offset: seg_info_offset as u32,
                page_size,
                pointer_format: ChainedPtrFormat::from_raw(pointer_format_raw),
                segment_offset,
                max_valid_pointer,
                page_starts,
            });
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CodeSignatureParser
// ─────────────────────────────────────────────────────────────────────────────

/// Parser for code signature blobs (`CS_SuperBlob` → `CodeDirectory` / Entitlements).
pub struct CodeSignatureParser;

impl CodeSignatureParser {
    /// Parse a code signature blob (starting with a `SuperBlob` magic).
    pub fn parse(data: &[u8]) -> Result<CodeSignatureInfo, CoreError> {
        if data.len() < 12 {
            return Err(CoreError::InvalidFormat {
                message: "Code signature too small".into(),
            });
        }

        let magic = u32::from_be_bytes(data[0..4].try_into().unwrap_or([0; 4]));
        if magic != CSMAGIC_EMBEDDED_SIGNATURE && magic != CSMAGIC_DETACHED_SIGNATURE {
            return Err(CoreError::InvalidFormat {
                message: format!("Not a SuperBlob: 0x{magic:08X}"),
            });
        }
        let _length = u32::from_be_bytes(data[4..8].try_into().unwrap_or([0; 4]));
        let count = u32::from_be_bytes(data[8..12].try_into().unwrap_or([0; 4])) as usize;

        // Each BlobIndex is 8 bytes: type(4) + offset(4).
        // Cap count to the number of BlobIndex entries that can fit in the buffer
        // BEFORE allocating to avoid attacker-controlled massive allocations.
        let max_count = (data.len().saturating_sub(12)) / 8;
        let count = count.min(max_count);
        let mut slots = Vec::with_capacity(count);
        let mut code_directory: Option<CodeDirectory> = None;
        let mut entitlements_xml: Option<String> = None;
        let mut entitlements_der_len: Option<usize> = None;
        let mut has_cms = false;
        let mut has_requirements = false;
        for i in 0..count {
            let idx_base = 12 + i * 8;
            if idx_base + 8 > data.len() {
                break;
            }
            let slot_type =
                u32::from_be_bytes(data[idx_base..idx_base + 4].try_into().unwrap_or([0; 4]));
            let slot_offset = u32::from_be_bytes(
                data[idx_base + 4..idx_base + 8]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as usize;

            if slot_offset + 8 > data.len() {
                continue;
            }
            let blob_magic = u32::from_be_bytes(
                data[slot_offset..slot_offset + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            let blob_size = u32::from_be_bytes(
                data[slot_offset + 4..slot_offset + 8]
                    .try_into()
                    .unwrap_or([0; 4]),
            );

            slots.push(CodeSigBlobSlot {
                slot_type,
                offset: slot_offset as u32,
                magic: blob_magic,
                size: blob_size,
            });

            // slot_offset and blob_size both come from untrusted binary data.
            let blob_end = slot_offset.saturating_add(blob_size as usize).min(data.len());
            let blob_data = &data[slot_offset..blob_end];

            match blob_magic {
                CSMAGIC_CODEDIRECTORY => {
                    code_directory = Self::parse_code_directory(blob_data);
                }
                CSMAGIC_ENTITLEMENTS => {
                    // Entitlements XML plist follows the 8-byte blob header
                    if blob_data.len() > 8 {
                        let xml_bytes = &blob_data[8..];
                        entitlements_xml = Some(
                            String::from_utf8_lossy(xml_bytes)
                                .trim_end_matches('\0')
                                .to_string(),
                        );
                    }
                }
                CSMAGIC_ENTITLEMENTS_DER => {
                    if blob_data.len() > 8 {
                        entitlements_der_len = Some(blob_data.len() - 8);
                    }
                }
                CSMAGIC_BLOBWRAPPER => {
                    has_cms = true;
                }
                CSMAGIC_REQUIREMENTS => {
                    has_requirements = true;
                }
                _ => {}
            }
        }

        Ok(CodeSignatureInfo {
            slots,
            code_directory,
            entitlements_xml,
            entitlements_der_len,
            has_cms,
            has_requirements,
        })
    }

    /// Parse a `CodeDirectory` blob (starting with magic 0xFADE0C02).
    fn parse_code_directory(data: &[u8]) -> Option<CodeDirectory> {
        // Minimum CodeDirectory v2.0 size: 44 bytes
        if data.len() < 44 {
            return None;
        }
        let magic = u32::from_be_bytes(data[0..4].try_into().ok()?);
        if magic != CSMAGIC_CODEDIRECTORY {
            return None;
        }
        let _length = u32::from_be_bytes(data[4..8].try_into().ok()?);
        let version = u32::from_be_bytes(data[8..12].try_into().ok()?);
        let flags = u32::from_be_bytes(data[12..16].try_into().ok()?);
        let hash_offset = u32::from_be_bytes(data[16..20].try_into().ok()?) as usize;
        let ident_offset = u32::from_be_bytes(data[20..24].try_into().ok()?) as usize;
        let n_special_slots = u32::from_be_bytes(data[24..28].try_into().ok()?) as usize;
        let n_code_slots = u32::from_be_bytes(data[28..32].try_into().ok()?);
        let code_limit = u32::from_be_bytes(data[32..36].try_into().ok()?);
        let hash_size = data.get(36).copied()?;
        let hash_type = data.get(37).copied()?;
        let platform = data.get(38).copied()?;
        let page_size = data.get(39).copied()?;

        // Read identifier string
        let identifier = if ident_offset < data.len() {
            let slice = &data[ident_offset..];
            let null = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
            String::from_utf8_lossy(&slice[..null]).into_owned()
        } else {
            String::new()
        };

        // Team ID is at version >= 0x20100 at hash_offset - n_special_slots*hash_size - team_id_offset
        // It's a relative offset stored at offset 40 in v2.1+
        let team_id = if version >= 0x2_0100 && data.len() >= 44 {
            let team_off = u32::from_be_bytes(data[40..44].try_into().unwrap_or([0; 4])) as usize;
            if team_off != 0 && team_off < data.len() {
                let slice = &data[team_off..];
                let null = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
                if null > 0 {
                    Some(String::from_utf8_lossy(&slice[..null]).into_owned())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        Some(CodeDirectory {
            version,
            flags,
            code_slots: n_code_slots,
            hash_size,
            hash_type,
            team_id,
            identifier,
            page_size,
            hash_offset,
            ident_offset,
            n_special_slots,
            code_limit,
            platform,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ObjcMetadataParser
// ─────────────────────────────────────────────────────────────────────────────

/// Stateless parser for Objective-C runtime metadata embedded in Mach-O sections.
///
/// Reads __`objc_classlist`, __`objc_protolist`, __`objc_catlist` from __DATA/__`DATA_CONST`.
pub struct ObjcMetadataParser;

impl ObjcMetadataParser {
    /// Extract `ObjC` class, protocol, and category information from binary segments.
    ///
    /// For 64-bit binaries each pointer is 8 bytes; for 32-bit, 4 bytes.
    /// This is a best-effort parser; it skips entries where the pointer chain
    /// cannot be resolved within the in-memory binary data.
    pub fn extract_from_segments(
        bytes: &[u8],
        segments: &[MachoSegment],
        is_64: bool,
        big_endian: bool,
        classes: &mut Vec<ObjcClass>,
        protocols: &mut Vec<String>,
        categories: &mut Vec<ObjcCategory>,
    ) {
        let ptr_size = if is_64 { 8usize } else { 4 };

        for seg in segments {
            for sec in &seg.sections {
                let sec_start = sec.offset as usize;
                let sec_end = sec_start.saturating_add(sec.size as usize);
                let Some(sec_bytes) = bytes.get(sec_start..sec_end.min(bytes.len())) else { continue };

                match sec.name.as_str() {
                    "__objc_classlist" => {
                        let class_list = Self::read_pointer_list(sec_bytes, ptr_size, big_endian);
                        for class_ptr in class_list {
                            if let Some(cls) =
                                Self::parse_class(bytes, segments, class_ptr, is_64, big_endian)
                            {
                                classes.push(cls);
                            }
                        }
                    }
                    "__objc_protolist" => {
                        let proto_list = Self::read_pointer_list(sec_bytes, ptr_size, big_endian);
                        for proto_ptr in proto_list {
                            if let Some(name) = Self::read_protocol_name(
                                bytes, segments, proto_ptr, is_64, big_endian,
                            ) {
                                protocols.push(name);
                            }
                        }
                    }
                    "__objc_catlist" => {
                        let cat_list = Self::read_pointer_list(sec_bytes, ptr_size, big_endian);
                        for cat_ptr in cat_list {
                            if let Some(cat) =
                                Self::parse_category(bytes, segments, cat_ptr, is_64, big_endian)
                            {
                                categories.push(cat);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Convert a VM address to a file offset using the segment map.
    fn vm_to_file(addr: u64, segments: &[MachoSegment]) -> Option<usize> {
        for seg in segments {
            if addr >= seg.vm_addr && addr < seg.vm_addr.saturating_add(seg.vm_size) {
                let off = addr - seg.vm_addr;
                // Use checked arithmetic to guard against overflow when combining
                // file_offset (u64) and the intra-segment delta on 32-bit targets.
                let file_off = (seg.file_offset as usize).checked_add(off as usize)?;
                return Some(file_off);
            }
        }
        None
    }

    /// Read a list of VM-address pointers from `data`.
    fn read_pointer_list(data: &[u8], ptr_size: usize, big_endian: bool) -> Vec<u64> {
        let mut out = Vec::new();
        let mut cursor = 0usize;
        while cursor + ptr_size <= data.len() {
            let ptr = if ptr_size == 8 {
                if big_endian {
                    read_u64_be(data, cursor).unwrap_or(0)
                } else {
                    read_u64_le(data, cursor).unwrap_or(0)
                }
            } else if big_endian {
                u64::from(read_u32_be(data, cursor).unwrap_or(0))
            } else {
                u64::from(read_u32_le(data, cursor).unwrap_or(0))
            };
            // Strip ABI tag bits (top byte) from arm64e pointers
            let ptr = ptr & 0x0000_FFFF_FFFF_FFFF;
            if ptr != 0 {
                out.push(ptr);
            }
            cursor += ptr_size;
        }
        out
    }

    /// Read a pointer (VM address) from bytes at `off`.
    fn read_ptr(bytes: &[u8], off: usize, is_64: bool, big_endian: bool) -> u64 {
        if is_64 {
            let v = if big_endian {
                read_u64_be(bytes, off).unwrap_or(0)
            } else {
                read_u64_le(bytes, off).unwrap_or(0)
            };
            v & 0x0000_FFFF_FFFF_FFFF
        } else if big_endian {
            u64::from(read_u32_be(bytes, off).unwrap_or(0))
        } else {
            u64::from(read_u32_le(bytes, off).unwrap_or(0))
        }
    }

    /// Read a NUL-terminated C string from a VM address.
    fn read_cstring_at_va(bytes: &[u8], segments: &[MachoSegment], va: u64) -> Option<String> {
        let off = Self::vm_to_file(va, segments)?;
        if off >= bytes.len() {
            return None;
        }
        let slice = &bytes[off..];
        let null = slice
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(slice.len().min(512));
        Some(String::from_utf8_lossy(&slice[..null]).into_owned())
    }

    /// Parse an `ObjC` class from a VM address.
    /// layout (64-bit): metaclass*(8) + superclass*(8) + cache*(8) + vtable*(8) + data*(8)
    /// The `class_ro_t` pointed to by data* contains: flags(4) + ... + name*(8) at +24
    fn parse_class(
        bytes: &[u8],
        segments: &[MachoSegment],
        class_va: u64,
        is_64: bool,
        big_endian: bool,
    ) -> Option<ObjcClass> {
        let ptr_size = if is_64 { 8usize } else { 4 };
        let class_off = Self::vm_to_file(class_va, segments)?;

        // data* is the 5th pointer in the class_t structure
        let data_ptr_off = class_off + 4 * ptr_size;
        if data_ptr_off + ptr_size > bytes.len() {
            return None;
        }
        let data_ptr = Self::read_ptr(bytes, data_ptr_off, is_64, big_endian);
        // Mask out the low 3 bits (used for flags by the runtime)
        let data_ptr = data_ptr & !0x7;

        let ro_off = Self::vm_to_file(data_ptr, segments)?;

        // class_ro_t (64-bit):
        //   flags(4) + instanceStart(4) + instanceSize(4/8 on 64) + ... + name*(8) at offset 24
        // (simplified: name pointer is at offset 24 for 64-bit, 16 for 32-bit)
        let name_ptr_off = ro_off + if is_64 { 24 } else { 16 };
        if name_ptr_off + ptr_size > bytes.len() {
            return None;
        }
        let name_ptr = Self::read_ptr(bytes, name_ptr_off, is_64, big_endian);
        let name = Self::read_cstring_at_va(bytes, segments, name_ptr).unwrap_or_default();

        // Parse method list: at offset 32 (64-bit) or 20 (32-bit) in class_ro_t
        let methods_ptr_off = ro_off + if is_64 { 32 } else { 20 };
        let instance_methods = if methods_ptr_off + ptr_size <= bytes.len() {
            let methods_ptr = Self::read_ptr(bytes, methods_ptr_off, is_64, big_endian);
            Self::parse_method_list(bytes, segments, methods_ptr, is_64, big_endian)
        } else {
            Vec::new()
        };

        Some(ObjcClass {
            name,
            addr: class_va,
            instance_methods,
            class_methods: Vec::new(), // metaclass parsing omitted for brevity
            protocols: Vec::new(),
            ivars: Vec::new(),
        })
    }

    /// Parse an `ObjC` method list from a VM address.
    /// `method_list_t`: `flags_and_count(4)` + ... then `method_t` entries
    /// `method_t` (64-bit): name*(8) + types*(8) + imp*(8) = 24 bytes
    /// `method_t` (32-bit): name*(4) + types*(4) + imp*(4) = 12 bytes
    fn parse_method_list(
        bytes: &[u8],
        segments: &[MachoSegment],
        methods_va: u64,
        is_64: bool,
        big_endian: bool,
    ) -> Vec<ObjcMethod> {
        if methods_va == 0 {
            return Vec::new();
        }
        let ptr_size = if is_64 { 8usize } else { 4 };
        let Some(methods_off) = Self::vm_to_file(methods_va, segments) else { return Vec::new() };
        if methods_off + 8 > bytes.len() {
            return Vec::new();
        }
        // method_list_t header: flags_and_count(4) + entsizeAndFlags(4)
        let count_raw = if big_endian {
            read_u32_be(bytes, methods_off + 4).unwrap_or(0)
        } else {
            read_u32_le(bytes, methods_off + 4).unwrap_or(0)
        };
        let count = (count_raw & 0x7FFF_FFFF) as usize; // strip high bits

        let method_size = ptr_size * 3;
        let mut out = Vec::with_capacity(count.min(512));

        for i in 0..count.min(512) {
            let entry_off = methods_off + 8 + i * method_size;
            if entry_off + method_size > bytes.len() {
                break;
            }
            let name_ptr = Self::read_ptr(bytes, entry_off, is_64, big_endian);
            let types_ptr = Self::read_ptr(bytes, entry_off + ptr_size, is_64, big_endian);
            let imp = Self::read_ptr(bytes, entry_off + 2 * ptr_size, is_64, big_endian);

            let name = Self::read_cstring_at_va(bytes, segments, name_ptr).unwrap_or_default();
            let types = Self::read_cstring_at_va(bytes, segments, types_ptr).unwrap_or_default();

            out.push(ObjcMethod { name, types, imp });
        }
        out
    }

    /// Read the name of an `ObjC` protocol.
    /// `protocol_t` (64-bit): isa*(8) + name*(8) at offset 8
    fn read_protocol_name(
        bytes: &[u8],
        segments: &[MachoSegment],
        proto_va: u64,
        is_64: bool,
        big_endian: bool,
    ) -> Option<String> {
        let ptr_size = if is_64 { 8usize } else { 4 };
        let proto_off = Self::vm_to_file(proto_va, segments)?;
        let name_ptr_off = proto_off + ptr_size; // skip isa*
        if name_ptr_off + ptr_size > bytes.len() {
            return None;
        }
        let name_ptr = Self::read_ptr(bytes, name_ptr_off, is_64, big_endian);
        Self::read_cstring_at_va(bytes, segments, name_ptr)
    }

    /// Parse an `ObjC` category.
    /// `category_t` (64-bit): name*(8) + cls*(8) + instanceMethods*(8) + classMethods*(8) + ...
    fn parse_category(
        bytes: &[u8],
        segments: &[MachoSegment],
        cat_va: u64,
        is_64: bool,
        big_endian: bool,
    ) -> Option<ObjcCategory> {
        let ptr_size = if is_64 { 8usize } else { 4 };
        let cat_off = Self::vm_to_file(cat_va, segments)?;
        if cat_off + 4 * ptr_size > bytes.len() {
            return None;
        }
        let name_ptr = Self::read_ptr(bytes, cat_off, is_64, big_endian);
        let cls_ptr = Self::read_ptr(bytes, cat_off + ptr_size, is_64, big_endian);
        let inst_methods_ptr = Self::read_ptr(bytes, cat_off + 2 * ptr_size, is_64, big_endian);
        let class_methods_ptr = Self::read_ptr(bytes, cat_off + 3 * ptr_size, is_64, big_endian);

        let name = Self::read_cstring_at_va(bytes, segments, name_ptr).unwrap_or_default();
        let class_name = if cls_ptr != 0 {
            // Try reading class name (class_t → data* → class_ro_t → name*)
            Self::parse_class(bytes, segments, cls_ptr, is_64, big_endian)
                .map(|c| c.name)
                .unwrap_or_default()
        } else {
            String::new()
        };
        let instance_methods =
            Self::parse_method_list(bytes, segments, inst_methods_ptr, is_64, big_endian);
        let class_methods =
            Self::parse_method_list(bytes, segments, class_methods_ptr, is_64, big_endian);

        Some(ObjcCategory {
            name,
            class_name,
            instance_methods,
            class_methods,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SwiftMetadataParser
// ─────────────────────────────────────────────────────────────────────────────

/// Stateless parser for Swift 5 metadata sections in Mach-O binaries.
///
/// Reads __`swift5_types` (type descriptors) and __`swift5_proto` (protocol conformances)
/// from any segment. Each entry is a 32-bit relative pointer (`int32_t`).
pub struct SwiftMetadataParser;

impl SwiftMetadataParser {
    /// Extract Swift type descriptors and protocol conformances from segments.
    pub fn extract_from_segments(
        bytes: &[u8],
        segments: &[MachoSegment],
        types: &mut Vec<SwiftTypeDescriptor>,
        proto_conformances: &mut Vec<SwiftProtoConformance>,
    ) {
        for seg in segments {
            for sec in &seg.sections {
                let sec_start = sec.offset as usize;
                let sec_end = sec_start.saturating_add(sec.size as usize);
                let Some(sec_bytes) = bytes.get(sec_start..sec_end.min(bytes.len())) else { continue };

                match sec.name.as_str() {
                    "__swift5_types" => {
                        Self::parse_relative_ptrs(
                            sec_bytes,
                            sec.addr,
                            types,
                            proto_conformances,
                            true,
                        );
                    }
                    "__swift5_proto" => {
                        Self::parse_relative_ptrs(
                            sec_bytes,
                            sec.addr,
                            types,
                            proto_conformances,
                            false,
                        );
                    }
                    "__swift5_fieldmd" => {
                        // Field descriptor table — just record addresses for now
                        let mut cursor = 0usize;
                        while cursor + 4 <= sec_bytes.len() {
                            let rel = i32::from_le_bytes(
                                sec_bytes[cursor..cursor + 4].try_into().unwrap_or([0; 4]),
                            );
                            types.push(SwiftTypeDescriptor {
                                addr: sec.addr + cursor as u64,
                                relative_ptr: rel,
                            });
                            cursor += 4;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn parse_relative_ptrs(
        data: &[u8],
        base_va: u64,
        types: &mut Vec<SwiftTypeDescriptor>,
        protos: &mut Vec<SwiftProtoConformance>,
        is_types: bool,
    ) {
        let mut cursor = 0usize;
        while cursor + 4 <= data.len() {
            let rel = i32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap_or([0; 4]));
            let entry_va = base_va + cursor as u64;
            if is_types {
                types.push(SwiftTypeDescriptor {
                    addr: entry_va,
                    relative_ptr: rel,
                });
            } else {
                protos.push(SwiftProtoConformance {
                    addr: entry_va,
                    protocol_relative: rel,
                });
            }
            cursor += 4;
        }
    }

    /// Resolve a relative pointer: `entry_addr + relative_value`.
    #[must_use] 
    pub fn resolve_relative_ptr(entry_addr: u64, relative: i32) -> u64 {
        entry_addr.wrapping_add(i64::from(relative).cast_unsigned())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoHeaderFlags
// ─────────────────────────────────────────────────────────────────────────────

/// Decoded Mach-O header flags bitfield.
#[derive(Debug, Clone)]
pub struct MachoHeaderFlags {
    pub is_pie: bool,
    pub has_twolevel: bool,
    pub dyld_link: bool,
    pub no_undefined_refs: bool,
    pub allow_stack_execution: bool,
    pub no_reexported_dylibs: bool,
    pub force_flat: bool,
    pub dead_strippable_dylib: bool,
    pub has_tlv_descriptors: bool,
    pub app_extension_safe: bool,
    pub raw: u32,
}

impl MachoHeaderFlags {
    /// Decode raw header flags into named boolean fields.
    #[must_use] 
    pub const fn from_raw(flags: u32) -> Self {
        Self {
            is_pie: flags & 0x0020_0000 != 0,
            has_twolevel: flags & 0x0000_0080 != 0,
            dyld_link: flags & 0x0000_0004 != 0,
            no_undefined_refs: flags & 0x0000_0001 != 0,
            allow_stack_execution: flags & 0x0002_0000 != 0,
            no_reexported_dylibs: flags & 0x0010_0000 != 0,
            force_flat: flags & 0x0000_0100 != 0,
            dead_strippable_dylib: flags & 0x0040_0000 != 0,
            has_tlv_descriptors: flags & 0x0080_0000 != 0,
            app_extension_safe: flags & 0x0200_0000 != 0,
            raw: flags,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FatBinaryParser
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata for one architecture slice inside a fat/universal binary.
#[derive(Debug, Clone)]
pub struct FatArch {
    /// CPU type raw value.
    pub cputype: u32,
    /// CPU subtype raw value.
    pub cpusubtype: u32,
    /// Byte offset of this slice from the start of the fat binary.
    pub offset: u32,
    /// Byte size of this slice.
    pub size: u32,
    /// Alignment as power of two (e.g. 12 → 4 KiB alignment).
    pub align: u32,
}

/// Utilities for working with fat/universal Mach-O binaries without full parsing.
pub struct FatBinaryParser;

impl FatBinaryParser {
    /// Returns `true` if `data` begins with the fat binary magic `0xCAFEBABE`.
    ///
    /// Note: the fat header is always stored big-endian on disk.
    #[must_use] 
    pub fn detect_fat(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        // 0xCAFEBABE stored big-endian: CA FE BA BE
        u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == 0xCAFE_BABE
    }

    /// List all architecture slices from a fat binary header.
    ///
    /// Returns an empty `Vec` if `data` is not a valid fat binary or if the
    /// header is truncated.
    #[must_use] 
    pub fn list_arches(data: &[u8]) -> Vec<FatArch> {
        if !Self::detect_fat(data) {
            return Vec::new();
        }
        if data.len() < 8 {
            return Vec::new();
        }
        // nfat_arch is big-endian u32 at offset 4
        let nfat = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
        // Cap nfat by the number of 20-byte fat_arch records that fit in the buffer.
        let nfat = nfat.min(data.len().saturating_sub(8) / 20);
        let mut arches = Vec::with_capacity(nfat);

        for i in 0..nfat {
            let base = 8 + i * 20;
            if base + 20 > data.len() {
                break;
            }
            let cputype =
                u32::from_be_bytes([data[base], data[base + 1], data[base + 2], data[base + 3]]);
            let cpusubtype = u32::from_be_bytes([
                data[base + 4],
                data[base + 5],
                data[base + 6],
                data[base + 7],
            ]);
            let offset = u32::from_be_bytes([
                data[base + 8],
                data[base + 9],
                data[base + 10],
                data[base + 11],
            ]);
            let size = u32::from_be_bytes([
                data[base + 12],
                data[base + 13],
                data[base + 14],
                data[base + 15],
            ]);
            let align = u32::from_be_bytes([
                data[base + 16],
                data[base + 17],
                data[base + 18],
                data[base + 19],
            ]);
            arches.push(FatArch {
                cputype,
                cpusubtype,
                offset,
                size,
                align,
            });
        }
        arches
    }

    /// Extract the raw bytes of a specific architecture slice.
    ///
    /// Returns an owned `Vec<u8>` containing exactly `arch.size` bytes.
    /// Returns an empty `Vec` if the slice range is out of bounds.
    #[must_use] 
    pub fn extract_arch(data: &[u8], arch: &FatArch) -> Vec<u8> {
        let start = arch.offset as usize;
        let end = start.saturating_add(arch.size as usize);
        data.get(start..end).unwrap_or(&[]).to_vec()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoSymbol (new standalone parse_symtab) + SymbolKind
// ─────────────────────────────────────────────────────────────────────────────

/// High-level kind of a Mach-O symbol, as produced by the new analyzer API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    /// Defined function / code symbol.
    Function,
    /// Defined data / object symbol.
    Data,
    /// Undefined — references an import from another dylib.
    Undefined,
    /// Absolute symbol (value is constant, not affected by ASLR).
    Absolute,
    /// Other / unknown.
    Other,
}

/// Symbol as produced by the `MachoAnalyzer` API.
///
/// Distinct from the lower-level `MachoSymbol` produced by `MachoParser`.
#[derive(Debug, Clone)]
pub struct AnalyzerSymbol {
    /// Mangled symbol name.
    pub name: String,
    /// Virtual address (or absolute value for `Absolute` symbols).
    pub addr: u64,
    /// High-level kind.
    pub kind: SymbolKind,
    /// One-based section index from the nlist record (`None` for undefined symbols).
    pub section: Option<u8>,
    /// `true` if the `N_EXT` flag is set (externally visible).
    pub external: bool,
}

impl AnalyzerSymbol {
    /// Parse a symbol table directly from raw Mach-O bytes.
    ///
    /// The function reads `nsyms` `nlist_64` records (16 bytes each) starting at
    /// `symoff`, then resolves names from the string table at `stroff`.
    ///
    /// This mirrors `MachoParser::parse_symtab` but returns `AnalyzerSymbol`
    /// and does not require `strsize` (uses the end of `data` as the boundary).
    #[must_use] 
    pub fn parse_symtab(data: &[u8], symoff: u32, nsyms: u32, stroff: u32) -> Vec<Self> {
        if nsyms == 0 {
            return Vec::new();
        }
        let strtab = data.get(stroff as usize..).unwrap_or(&[]);
        let entry_size = 16usize; // nlist_64 is always 16 bytes
        // Cap nsyms by the number of 16-byte nlist_64 records that fit after symoff.
        let max_syms = data.len().saturating_sub(symoff as usize) / entry_size;
        let mut out = Vec::with_capacity((nsyms as usize).min(max_syms));

        for i in 0..nsyms as usize {
            // symoff and nsyms originate from untrusted binary data; use checked arithmetic.
            let Some(base) = (symoff as usize).checked_add(i.saturating_mul(entry_size)) else { break };
            if base + entry_size > data.len() {
                break;
            }
            let strx =
                u32::from_le_bytes(data[base..base + 4].try_into().unwrap_or([0; 4])) as usize;
            let n_type = data[base + 4];
            let n_sect = data[base + 5];
            let value = u64::from_le_bytes(data[base + 8..base + 16].try_into().unwrap_or([0; 8]));

            let is_external = n_type & N_EXT != 0;
            let type_bits = n_type & N_TYPE;
            let is_stab = n_type & N_STAB != 0;

            let kind = if is_stab {
                SymbolKind::Other
            } else {
                match type_bits {
                    N_UNDF => SymbolKind::Undefined,
                    N_ABS => SymbolKind::Absolute,
                    N_SECT => {
                        // Heuristic: symbols with no name prefix are often data;
                        // those prefixed with "_" that end in common suffixes are functions.
                        SymbolKind::Function
                    }
                    _ => SymbolKind::Other,
                }
            };

            let section = if n_sect == 0 { None } else { Some(n_sect) };

            let name = if strx < strtab.len() {
                let sl = &strtab[strx..];
                let null = sl.iter().position(|&b| b == 0).unwrap_or(sl.len());
                String::from_utf8_lossy(&sl[..null]).into_owned()
            } else {
                String::new()
            };

            out.push(Self {
                name,
                addr: value,
                kind,
                section,
                external: is_external,
            });
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoAnalyzer + MachoReport
// ─────────────────────────────────────────────────────────────────────────────

/// Encryption information extracted from `LC_ENCRYPTION_INFO_64`.
#[derive(Debug, Clone)]
pub struct EncryptionInfo {
    /// File offset of the encrypted range.
    pub cryptoff: u32,
    /// Byte size of the encrypted range.
    pub cryptsize: u32,
    /// Encryption system identifier (0 = not encrypted).
    pub cryptid: u32,
}

/// High-level analysis report for a Mach-O binary.
#[derive(Debug, Clone)]
pub struct MachoReport {
    /// Canonical architecture string, e.g. `"arm64"` or `"x86_64"`.
    pub arch: String,
    /// Raw `cpusubtype` field from the Mach-O header.
    pub cpu_subtype: u32,
    /// Human-readable file type, e.g. `"MH_EXECUTE"`.
    pub file_type: String,
    /// All load commands decoded as `MachoLoadCommandEnum` variants.
    pub load_commands: Vec<MachoLoadCommandEnum>,
    /// Segment names, in order of appearance.
    pub segments: Vec<String>,
    /// Install names of all dependent dylibs (`LC_LOAD_DYLIB` etc.).
    pub imported_libs: Vec<String>,
    /// Number of function starts recovered from `LC_FUNCTION_STARTS`.
    pub function_count: usize,
    /// Number of symbols in the symbol table.
    pub symbol_count: usize,
    /// `true` if the binary was linked with `-pie` (position-independent executable).
    pub is_pie: bool,
    /// `true` if any segment is named `__swift5_types` (Swift ARC indicator).
    pub has_arc: bool,
    /// `true` if a `__LLVM` segment containing bitcode is present.
    pub has_bitcode: bool,
    /// `FairPlay` encryption descriptor, if present.
    pub encryption: Option<EncryptionInfo>,
}

/// Stateless analyzer that produces a `MachoReport` from raw Mach-O bytes.
pub struct MachoAnalyzer;

impl MachoAnalyzer {
    /// Produce a `MachoReport` from a raw Mach-O binary slice.
    ///
    /// The analysis is best-effort: malformed or truncated binaries will
    /// produce a partial report rather than an error.
    #[must_use] 
    pub fn analyze(data: &[u8]) -> MachoReport {
        // Parse via the existing full parser first
        let Ok(info) = MachoParser::parse(data) else {
                return MachoReport {
                    arch: "unknown".into(),
                    cpu_subtype: 0,
                    file_type: "MH_UNKNOWN".into(),
                    load_commands: Vec::new(),
                    segments: Vec::new(),
                    imported_libs: Vec::new(),
                    function_count: 0,
                    symbol_count: 0,
                    is_pie: false,
                    has_arc: false,
                    has_bitcode: false,
                    encryption: None,
                };
            };

        // Determine header size and load-command start offset
        let big_endian = matches!(info.arch, MachoArch::PowerPc | MachoArch::PowerPc64);
        let magic_le = if data.len() >= 4 {
            u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4]))
        } else {
            0
        };
        let is_64 = matches!(magic_le, MH_MAGIC_64 | MH_CIGAM_64);
        let hdr_size = if is_64 { 32usize } else { 28usize };

        // cpu_subtype is at offset 8 in the header
        let cpu_subtype = if data.len() >= 12 {
            if big_endian {
                read_u32_be(data, 8).unwrap_or(0)
            } else {
                read_u32_le(data, 8).unwrap_or(0)
            }
        } else {
            0
        };

        // ncmds at offset 16
        let ncmds = if data.len() >= 20 {
            if big_endian {
                read_u32_be(data, 16)
            } else {
                read_u32_le(data, 16)
            }
            .unwrap_or(0)
        } else {
            0
        };

        let load_commands = MachoLoadCommandEnum::parse_all(data, hdr_size, ncmds, big_endian);

        let segments: Vec<String> = info.segments.iter().map(|s| s.name.clone()).collect();
        let imported_libs: Vec<String> = info.dylibs.clone();

        // Count function starts
        let function_count = Self::count_function_starts(data, &load_commands);

        let symbol_count = info.symbols.len();

        let is_pie = Self::is_pie(&load_commands, info.flags);
        let has_arc = Self::detect_swift(&info.segments);
        let has_bitcode = info.segments.iter().any(|s| s.name == "__LLVM");

        let encryption = Self::find_encryption(&load_commands);

        MachoReport {
            arch: info.arch.name().to_string(),
            cpu_subtype,
            file_type: info.file_type.name().to_string(),
            load_commands,
            segments,
            imported_libs,
            function_count,
            symbol_count,
            is_pie,
            has_arc,
            has_bitcode,
            encryption,
        }
    }

    /// Returns `true` if the binary was linked with the PIE flag.
    ///
    /// Checks the `MH_PIE` flag bit (`0x0020_0000`) in the header flags.
    /// The `load_commands` slice is available for callers who wish to perform
    /// additional command-level checks, but the PIE flag lives in the header.
    #[must_use] 
    pub const fn is_pie(_commands: &[MachoLoadCommandEnum], flags: u32) -> bool {
        flags & MH_PIE != 0
    }

    /// Returns `true` if any segment is named `__swift5_types`, which indicates
    /// a binary compiled with Swift (and therefore using ARC).
    #[must_use] 
    pub fn detect_swift(segments: &[MachoSegment]) -> bool {
        segments.iter().any(|s| {
            s.name == "__swift5_types"
                || s.sections.iter().any(|sec| {
                    sec.name == "__swift5_types"
                        || sec.name == "__swift5_proto"
                        || sec.name == "__swift5_fieldmd"
                })
        })
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn count_function_starts(data: &[u8], cmds: &[MachoLoadCommandEnum]) -> usize {
        // Find LC_FUNCTION_STARTS and LC_SEGMENT_64 __TEXT to get base address
        let mut func_data_off: Option<(u32, u32)> = None;
        let mut text_base: u64 = 0;

        for cmd in cmds {
            match cmd {
                MachoLoadCommandEnum::FunctionStarts { dataoff, datasize } => {
                    func_data_off = Some((*dataoff, *datasize));
                }
                MachoLoadCommandEnum::Segment64 { name, vmaddr, .. } if name == "__TEXT" => {
                    text_base = *vmaddr;
                }
                _ => {}
            }
        }

        if let Some((off, size)) = func_data_off {
            let start = off as usize;
            let end = start.saturating_add(size as usize);
            if let Some(blob) = data.get(start..end) {
                return FunctionStartsParser::parse(blob, text_base).len();
            }
        }
        0
    }

    fn find_encryption(cmds: &[MachoLoadCommandEnum]) -> Option<EncryptionInfo> {
        for cmd in cmds {
            if let MachoLoadCommandEnum::EncryptionInfo64 {
                cryptoff,
                cryptsize,
                cryptid,
            } = cmd
            {
                return Some(EncryptionInfo {
                    cryptoff: *cryptoff,
                    cryptsize: *cryptsize,
                    cryptid: *cryptid,
                });
            }
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MachoArch ─────────────────────────────────────────────────────────────

    #[test]
    fn arch_from_cputype_x86() {
        assert_eq!(MachoArch::from_cputype(7), MachoArch::X86);
    }

    #[test]
    fn arch_from_cputype_x86_64() {
        assert_eq!(MachoArch::from_cputype(0x0100_0007), MachoArch::X86_64);
    }

    #[test]
    fn arch_from_cputype_arm() {
        assert_eq!(MachoArch::from_cputype(12), MachoArch::Arm);
    }

    #[test]
    fn arch_from_cputype_arm64() {
        assert_eq!(MachoArch::from_cputype(0x0100_000C), MachoArch::Arm64);
    }

    #[test]
    fn arch_from_cputype_ppc() {
        assert_eq!(MachoArch::from_cputype(18), MachoArch::PowerPc);
    }

    #[test]
    fn arch_from_cputype_ppc64() {
        assert_eq!(MachoArch::from_cputype(0x0100_0012), MachoArch::PowerPc64);
    }

    #[test]
    fn arch_from_cputype_unknown() {
        assert_eq!(MachoArch::from_cputype(0xFF), MachoArch::Unknown(0xFF));
    }

    #[test]
    fn arch_pointer_size() {
        assert_eq!(MachoArch::X86.pointer_size(), 4);
        assert_eq!(MachoArch::X86_64.pointer_size(), 8);
        assert_eq!(MachoArch::Arm.pointer_size(), 4);
        assert_eq!(MachoArch::Arm64.pointer_size(), 8);
        assert_eq!(MachoArch::PowerPc.pointer_size(), 4);
        assert_eq!(MachoArch::PowerPc64.pointer_size(), 8);
    }

    #[test]
    fn arch_name() {
        assert_eq!(MachoArch::X86.name(), "x86");
        assert_eq!(MachoArch::X86_64.name(), "x86_64");
        assert_eq!(MachoArch::Arm64.name(), "arm64");
    }

    #[test]
    fn arch_endian() {
        assert_eq!(MachoArch::X86.endian(), Endian::Little);
        assert_eq!(MachoArch::Arm64.endian(), Endian::Little);
        assert_eq!(MachoArch::PowerPc.endian(), Endian::Big);
        assert_eq!(MachoArch::PowerPc64.endian(), Endian::Big);
    }

    // ── MachoFileType ─────────────────────────────────────────────────────────

    #[test]
    fn filetype_from_raw_execute() {
        assert_eq!(MachoFileType::from_filetype(0x2), MachoFileType::Execute);
    }

    #[test]
    fn filetype_from_raw_dylib() {
        assert_eq!(MachoFileType::from_filetype(0x6), MachoFileType::Dylib);
    }

    #[test]
    fn filetype_from_raw_bundle() {
        assert_eq!(MachoFileType::from_filetype(0x8), MachoFileType::Bundle);
    }

    #[test]
    fn filetype_is_executable() {
        assert!(MachoFileType::Execute.is_executable());
        assert!(!MachoFileType::Dylib.is_executable());
        assert!(!MachoFileType::Bundle.is_executable());
    }

    #[test]
    fn filetype_is_library() {
        assert!(MachoFileType::Dylib.is_library());
        assert!(MachoFileType::DylibStub.is_library());
        assert!(!MachoFileType::Execute.is_library());
    }

    // ── MachoSegment ─────────────────────────────────────────────────────────

    fn make_seg(init_prot: u32) -> MachoSegment {
        MachoSegment {
            name: "__TEST".into(),
            vm_addr: 0x1000,
            vm_size: 0x1000,
            file_offset: 0,
            file_size: 0x1000,
            max_prot: 7,
            init_prot,
            sections: Vec::new(),
        }
    }

    #[test]
    fn segment_is_readable() {
        assert!(make_seg(VM_PROT_READ).is_readable());
        assert!(!make_seg(VM_PROT_WRITE).is_readable());
    }

    #[test]
    fn segment_is_writable() {
        assert!(make_seg(VM_PROT_WRITE).is_writable());
        assert!(!make_seg(VM_PROT_READ).is_writable());
    }

    #[test]
    fn segment_is_executable() {
        assert!(make_seg(VM_PROT_EXECUTE).is_executable());
        assert!(!make_seg(VM_PROT_READ | VM_PROT_WRITE).is_executable());
    }

    #[test]
    fn segment_contains_addr() {
        let seg = make_seg(VM_PROT_READ | VM_PROT_EXECUTE);
        assert!(seg.contains_addr(0x1000));
        assert!(seg.contains_addr(0x1FFF));
        assert!(!seg.contains_addr(0x2000));
        assert!(!seg.contains_addr(0x0FFF));
    }

    // ── MachoSectionType ─────────────────────────────────────────────────────

    #[test]
    fn section_type_from_flags_regular() {
        assert_eq!(MachoSectionType::from_flags(0), MachoSectionType::Regular);
    }

    #[test]
    fn section_type_from_flags_zerofill() {
        assert_eq!(MachoSectionType::from_flags(1), MachoSectionType::ZeroFill);
    }

    #[test]
    fn section_type_from_flags_lazy_symbols() {
        assert_eq!(
            MachoSectionType::from_flags(7),
            MachoSectionType::LazySymbolPointers
        );
    }

    #[test]
    fn section_type_from_flags_cstring() {
        assert_eq!(
            MachoSectionType::from_flags(2),
            MachoSectionType::CStringLiterals
        );
    }

    // ── MachoLoader::can_load ────────────────────────────────────────────────

    fn loader_input(data: Vec<u8>) -> LoaderInput {
        LoaderInput::new("test://binary", data)
    }

    #[test]
    fn can_load_64bit_le_magic() {
        // 0xFEEDFACF in little-endian: CF FA ED FE
        let input = loader_input(vec![0xCF, 0xFA, 0xED, 0xFE, 0x00, 0x00, 0x00, 0x00]);
        assert!(MachoLoader.can_load(&input));
    }

    #[test]
    fn can_load_32bit_le_magic() {
        let input = loader_input(vec![0xCE, 0xFA, 0xED, 0xFE]);
        assert!(MachoLoader.can_load(&input));
    }

    #[test]
    fn can_load_fat_magic() {
        // FAT_MAGIC = 0xCAFEBABE, read as LE: BE BA FE CA
        let input = loader_input(vec![0xBE, 0xBA, 0xFE, 0xCA, 0, 0, 0, 0]);
        assert!(MachoLoader.can_load(&input));
    }

    #[test]
    fn cannot_load_elf() {
        let input = loader_input(vec![0x7F, b'E', b'L', b'F']);
        assert!(!MachoLoader.can_load(&input));
    }

    #[test]
    fn cannot_load_too_short() {
        let input = loader_input(vec![0xCF, 0xFA]);
        assert!(!MachoLoader.can_load(&input));
    }

    // ── MachoParser on a hand-crafted minimal 64-bit LE Mach-O ───────────────

    fn minimal_macho64() -> Vec<u8> {
        let mut b = Vec::new();
        // magic: 0xFEEDFACF (64-bit LE) → stored LE
        b.extend_from_slice(&0xFEED_FACFu32.to_le_bytes());
        // cputype: x86_64 = 0x01000007
        b.extend_from_slice(&0x0100_0007u32.to_le_bytes());
        // cpusubtype: 3
        b.extend_from_slice(&3u32.to_le_bytes());
        // filetype: MH_EXECUTE = 2
        b.extend_from_slice(&2u32.to_le_bytes());
        // ncmds: 0
        b.extend_from_slice(&0u32.to_le_bytes());
        // sizeofcmds: 0
        b.extend_from_slice(&0u32.to_le_bytes());
        // flags: 0x200085 (MH_PIE | MH_DYLDLINK | ...)
        b.extend_from_slice(&0x0020_0085u32.to_le_bytes());
        // reserved (64-bit only)
        b.extend_from_slice(&0u32.to_le_bytes());
        b
    }

    #[test]
    fn parse_minimal_macho64_arch_and_filetype() {
        let bytes = minimal_macho64();
        let info = MachoParser::parse(&bytes).unwrap();
        assert_eq!(info.arch, MachoArch::X86_64);
        assert_eq!(info.file_type, MachoFileType::Execute);
    }

    #[test]
    fn parse_minimal_macho64_is_pie() {
        let bytes = minimal_macho64();
        let info = MachoParser::parse(&bytes).unwrap();
        assert!(info.is_pie);
    }

    #[test]
    fn parse_minimal_macho64_not_fat() {
        let bytes = minimal_macho64();
        let info = MachoParser::parse(&bytes).unwrap();
        assert!(!info.is_fat);
        assert!(info.fat_slices.is_empty());
    }

    // ── Fat binary magic detection ────────────────────────────────────────────

    #[test]
    fn parse_fat_empty_nfat() {
        // FAT_MAGIC stored big-endian: CA FE BA BE; nfat_arch = 0 big-endian
        let bytes: Vec<u8> = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x00];
        let entries = MachoParser::parse_fat(&bytes).unwrap();
        assert!(entries.is_empty());
    }

    // ── MachoInfo helpers ─────────────────────────────────────────────────────

    #[test]
    fn uuid_string_format() {
        let info = MachoInfo {
            arch: MachoArch::X86_64,
            cpu_subtype: 3,
            file_type: MachoFileType::Execute,
            flags: 0,
            entry_points: Vec::new(),
            segments: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            dylibs: Vec::new(),
            rpaths: Vec::new(),
            uuid: Some([
                0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
                0xCD, 0xEF,
            ]),
            source_version: None,
            load_commands: Vec::new(),
            has_code_signature: false,
            is_pie: false,
            is_fat: false,
            fat_slices: Vec::new(),
            min_os_version: None,
            platform: None,
            function_starts: Vec::new(),
            data_in_code: Vec::new(),
            bind_entries: Vec::new(),
            export_entries: Vec::new(),
            rebase_entries: Vec::new(),
            objc_classes: Vec::new(),
            objc_protocols: Vec::new(),
            objc_categories: Vec::new(),
            swift_types: Vec::new(),
            swift_proto_conformances: Vec::new(),
            code_signature: None,
            chained_fixup_imports: Vec::new(),
        };
        let s = info.uuid_string().unwrap();
        assert_eq!(s, "DEADBEEF-CAFE-BABE-0123-456789ABCDEF");
    }

    fn info_with_segments() -> MachoInfo {
        let text_seg = MachoSegment {
            name: "__TEXT".into(),
            vm_addr: 0x1000_0000,
            vm_size: 0x4000,
            file_offset: 0x1000,
            file_size: 0x4000,
            max_prot: 5,
            init_prot: 5,
            sections: vec![MachoSection {
                name: "__text".into(),
                segment: "__TEXT".into(),
                addr: 0x1000_0000,
                size: 0x100,
                offset: 0x1000,
                align: 2,
                flags: 0x8000_0400,
                section_type: MachoSectionType::Regular,
            }],
        };
        let data_seg = MachoSegment {
            name: "__DATA".into(),
            vm_addr: 0x1000_4000,
            vm_size: 0x1000,
            file_offset: 0x5000,
            file_size: 0x1000,
            max_prot: 3,
            init_prot: 3,
            sections: vec![MachoSection {
                name: "__data".into(),
                segment: "__DATA".into(),
                addr: 0x1000_4000,
                size: 0x100,
                offset: 0x5000,
                align: 3,
                flags: 0,
                section_type: MachoSectionType::Regular,
            }],
        };
        MachoInfo {
            arch: MachoArch::X86_64,
            cpu_subtype: 3,
            file_type: MachoFileType::Execute,
            flags: MH_PIE,
            entry_points: vec![Address::new(0x1000_0000)],
            segments: vec![text_seg, data_seg],
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            dylibs: Vec::new(),
            rpaths: Vec::new(),
            uuid: None,
            source_version: None,
            load_commands: Vec::new(),
            has_code_signature: false,
            is_pie: true,
            is_fat: false,
            fat_slices: Vec::new(),
            min_os_version: None,
            platform: None,
            function_starts: Vec::new(),
            data_in_code: Vec::new(),
            bind_entries: Vec::new(),
            export_entries: Vec::new(),
            rebase_entries: Vec::new(),
            objc_classes: Vec::new(),
            objc_protocols: Vec::new(),
            objc_categories: Vec::new(),
            swift_types: Vec::new(),
            swift_proto_conformances: Vec::new(),
            code_signature: None,
            chained_fixup_imports: Vec::new(),
        }
    }

    #[test]
    fn info_text_segment() {
        let info = info_with_segments();
        let seg = info.text_segment().unwrap();
        assert_eq!(seg.name, "__TEXT");
    }

    #[test]
    fn info_data_segment() {
        let info = info_with_segments();
        let seg = info.data_segment().unwrap();
        assert_eq!(seg.name, "__DATA");
    }

    #[test]
    fn info_section_named() {
        let info = info_with_segments();
        let sec = info.section_named("__TEXT", "__text").unwrap();
        assert_eq!(sec.name, "__text");
        assert!(info.section_named("__TEXT", "__stubs").is_none());
    }

    #[test]
    fn info_is_dylib_vs_executable() {
        let exe = info_with_segments();
        assert!(exe.is_executable());
        assert!(!exe.is_dylib());

        let mut dylib = exe;
        dylib.file_type = MachoFileType::Dylib;
        assert!(dylib.is_dylib());
        assert!(!dylib.is_executable());
    }

    // ── MachoSymbol type detection ────────────────────────────────────────────

    #[test]
    fn symbol_type_detection() {
        let sym = MachoSymbol {
            name: "_printf".into(),
            value: 0,
            section_index: 0,
            sym_type: MachoSymbolType::Undefined,
            is_external: true,
            is_debug: false,
            is_undefined: true,
        };
        assert!(sym.is_undefined);
        assert!(sym.is_external);
        assert_eq!(sym.sym_type, MachoSymbolType::Undefined);
    }

    // ── UniversalBinaryEntry fields ───────────────────────────────────────────

    #[test]
    fn universal_entry_fields() {
        let entry = UniversalBinaryEntry {
            arch: MachoArch::Arm64,
            offset: 0x4000,
            size: 0x8000,
            align: 14,
            data: vec![0; 0x8000],
        };
        assert_eq!(entry.arch, MachoArch::Arm64);
        assert_eq!(entry.offset, 0x4000);
        assert_eq!(entry.size, 0x8000);
        assert_eq!(entry.align, 14);
    }

    // ── Version decoding ──────────────────────────────────────────────────────

    #[test]
    fn decode_version_format() {
        // 10.15.4 → (10 << 16) | (15 << 8) | 4 = 0x000A0F04
        let v: u32 = (10 << 16) | (15 << 8) | 4;
        assert_eq!(MachoParser::decode_version(v), "10.15.4");
    }

    #[test]
    fn decode_version_one_two_three() {
        let v: u32 = (1 << 16) | (2 << 8) | 3;
        assert_eq!(MachoParser::decode_version(v), "1.2.3");
    }

    // ── MachoLoadCommandData::Dylib fields ───────────────────────────────────

    #[test]
    fn load_command_dylib_fields() {
        let lc = MachoLoadCommand {
            cmd: LC_LOAD_DYLIB,
            cmd_name: "LC_LOAD_DYLIB".into(),
            data: MachoLoadCommandData::Dylib {
                name: "/usr/lib/libSystem.B.dylib".into(),
                timestamp: 2,
                current_version: 0x050C_3B00,
                compatibility_version: 0x0001_0000,
            },
        };
        if let MachoLoadCommandData::Dylib {
            name,
            timestamp,
            current_version,
            compatibility_version,
        } = &lc.data
        {
            assert_eq!(name, "/usr/lib/libSystem.B.dylib");
            assert_eq!(*timestamp, 2);
            assert_eq!(*current_version, 0x050C_3B00);
            assert_eq!(*compatibility_version, 0x0001_0000);
        } else {
            panic!("Expected Dylib variant");
        }
    }

    // ── select_best_slice ────────────────────────────────────────────────────

    #[test]
    fn select_best_slice_prefers_x86_64() {
        let entries = vec![
            UniversalBinaryEntry {
                arch: MachoArch::Arm,
                offset: 0,
                size: 4,
                align: 0,
                data: vec![0; 4],
            },
            UniversalBinaryEntry {
                arch: MachoArch::X86_64,
                offset: 100,
                size: 4,
                align: 0,
                data: vec![0; 4],
            },
            UniversalBinaryEntry {
                arch: MachoArch::Arm64,
                offset: 200,
                size: 4,
                align: 0,
                data: vec![0; 4],
            },
        ];
        let best = MachoParser::select_best_slice(&entries).unwrap();
        assert_eq!(best.arch, MachoArch::X86_64);
    }

    #[test]
    fn select_best_slice_falls_back_to_arm64() {
        let entries = vec![
            UniversalBinaryEntry {
                arch: MachoArch::Arm,
                offset: 0,
                size: 4,
                align: 0,
                data: vec![0; 4],
            },
            UniversalBinaryEntry {
                arch: MachoArch::Arm64,
                offset: 100,
                size: 4,
                align: 0,
                data: vec![0; 4],
            },
        ];
        let best = MachoParser::select_best_slice(&entries).unwrap();
        assert_eq!(best.arch, MachoArch::Arm64);
    }

    #[test]
    fn select_best_slice_empty() {
        assert!(MachoParser::select_best_slice(&[]).is_none());
    }

    // ── MachoParser error handling ────────────────────────────────────────────

    #[test]
    fn parse_empty_bytes_is_error() {
        assert!(MachoParser::parse(&[]).is_err());
    }

    #[test]
    fn parse_wrong_magic_is_error() {
        let bad = vec![0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(MachoParser::parse_single(&bad).is_err());
    }

    // ── FunctionStartsParser ──────────────────────────────────────────────────

    #[test]
    fn function_starts_single_delta() {
        // base = 0x1000, delta = 0x10 → [0x1010]
        let data = vec![0x10u8]; // ULEB128 for 16
        let addrs = FunctionStartsParser::parse(&data, 0x1000);
        assert_eq!(addrs, vec![0x1010]);
    }

    #[test]
    fn function_starts_multiple_deltas() {
        // deltas: 0x10, 0x20, 0x00 (terminator)
        let data = vec![0x10u8, 0x20, 0x00];
        let addrs = FunctionStartsParser::parse(&data, 0x1000);
        // 0x1000 + 0x10 = 0x1010, 0x1010 + 0x20 = 0x1030
        assert_eq!(addrs, vec![0x1010, 0x1030]);
    }

    #[test]
    fn function_starts_empty_data() {
        let addrs = FunctionStartsParser::parse(&[], 0x1000);
        assert!(addrs.is_empty());
    }

    #[test]
    fn function_starts_uleb128_multibyte() {
        // ULEB128 encoding of 300 (0x12C): 0xAC 0x02
        let data = vec![0xACu8, 0x02, 0x00];
        let addrs = FunctionStartsParser::parse(&data, 0x1000);
        assert_eq!(addrs, vec![0x1000 + 300]);
    }

    // ── DyldInfoParser::read_sleb128 ──────────────────────────────────────────

    #[test]
    fn sleb128_positive() {
        let data = vec![0x01u8];
        let (v, n) = DyldInfoParser::read_sleb128(&data, 0);
        assert_eq!(v, 1);
        assert_eq!(n, 1);
    }

    #[test]
    fn sleb128_negative_minus_one() {
        // -1 in SLEB128: 0x7F
        let data = vec![0x7Fu8];
        let (v, n) = DyldInfoParser::read_sleb128(&data, 0);
        assert_eq!(v, -1);
        assert_eq!(n, 1);
    }

    #[test]
    fn sleb128_negative_128() {
        // -128 in SLEB128: 0x80 0x7F
        let data = vec![0x80u8, 0x7F];
        let (v, n) = DyldInfoParser::read_sleb128(&data, 0);
        assert_eq!(v, -128);
        assert_eq!(n, 2);
    }

    // ── DyldInfoParser::parse_exports (trivial trie) ──────────────────────────

    #[test]
    fn parse_exports_empty_data() {
        let entries = DyldInfoParser::parse_exports(&[]);
        assert!(entries.is_empty());
    }

    // ── DyldInfoParser::parse_bind ────────────────────────────────────────────

    #[test]
    fn parse_bind_done_opcode() {
        // Only a DONE opcode → no entries
        let data = vec![BIND_OPCODE_DONE];
        let entries = DyldInfoParser::parse_bind(&data);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_bind_set_symbol_and_do_bind() {
        // SET_DYLIB_ORDINAL_IMM(1) = 0x11
        // SET_SYMBOL_TRAILING_FLAGS_IMM(0) = 0x40; symbol = "_foo\0"
        // DO_BIND = 0x90
        // DONE = 0x00
        let mut data = vec![0x11u8]; // SET_DYLIB_ORDINAL_IMM, ordinal=1
        data.push(0x40); // SET_SYMBOL_TRAILING_FLAGS_IMM, flags=0
        data.extend_from_slice(b"_foo\0");
        data.push(0x90); // DO_BIND
        data.push(0x00); // DONE

        let entries = DyldInfoParser::parse_bind(&data);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].symbol_name, "_foo");
        assert_eq!(entries[0].library_ordinal, 1);
    }

    // ── FatBinaryParser ───────────────────────────────────────────────────────

    #[test]
    fn detect_fat_magic() {
        // CA FE BA BE
        let data = vec![0xCAu8, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0];
        assert!(FatBinaryParser::detect_fat(&data));
    }

    #[test]
    fn detect_fat_not_macho() {
        let data = vec![0xCFu8, 0xFA, 0xED, 0xFE];
        assert!(!FatBinaryParser::detect_fat(&data));
    }

    #[test]
    fn fat_list_arches_empty() {
        let data = vec![0xCAu8, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0]; // nfat=0
        let arches = FatBinaryParser::list_arches(&data);
        assert!(arches.is_empty());
    }

    #[test]
    fn fat_extract_arch_range() {
        // Build minimal fat header with 1 arch at offset 100, size 4
        let mut data = vec![0u8; 200];
        // magic BE
        data[0] = 0xCA;
        data[1] = 0xFE;
        data[2] = 0xBA;
        data[3] = 0xBE;
        // nfat = 1
        data[4] = 0;
        data[5] = 0;
        data[6] = 0;
        data[7] = 1;
        // fat_arch[0]: cputype=7 (x86) at BE
        data[8] = 0;
        data[9] = 0;
        data[10] = 0;
        data[11] = 7; // cputype
        data[12] = 0;
        data[13] = 0;
        data[14] = 0;
        data[15] = 3; // cpusubtype
        data[16] = 0;
        data[17] = 0;
        data[18] = 0;
        data[19] = 100; // offset
        data[20] = 0;
        data[21] = 0;
        data[22] = 0;
        data[23] = 4; // size
        data[24] = 0;
        data[25] = 0;
        data[26] = 0;
        data[27] = 12; // align
        // payload at offset 100
        data[100] = 0xAA;
        data[101] = 0xBB;
        data[102] = 0xCC;
        data[103] = 0xDD;

        let arches = FatBinaryParser::list_arches(&data);
        assert_eq!(arches.len(), 1);
        assert_eq!(arches[0].cputype, 7);
        assert_eq!(arches[0].offset, 100);
        assert_eq!(arches[0].size, 4);

        let slice = FatBinaryParser::extract_arch(&data, &arches[0]);
        assert_eq!(slice, vec![0xAAu8, 0xBB, 0xCC, 0xDD]);
    }

    // ── AnalyzerSymbol::parse_symtab ─────────────────────────────────────────

    #[test]
    fn analyzer_symbol_parse_empty() {
        let syms = AnalyzerSymbol::parse_symtab(&[], 0, 0, 0);
        assert!(syms.is_empty());
    }

    #[test]
    fn analyzer_symbol_parse_one_entry() {
        // Build a minimal nlist_64 entry + string table
        // nlist_64: n_strx(4) + n_type(1) + n_sect(1) + n_desc(2) + n_value(8) = 16 bytes
        let symoff: u32 = 0;
        let stroff: u32 = 16;
        let mut data = vec![0u8; 32];
        // n_strx = 0 (points to start of strtab)
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        // n_type = N_SECT | N_EXT = 0x0E | 0x01 = 0x0F
        data[4] = 0x0F;
        // n_sect = 1
        data[5] = 1;
        // n_desc = 0
        data[6] = 0;
        data[7] = 0;
        // n_value = 0xDEAD_BEEF
        data[8..16].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());
        // string table: "_main\0"
        data[16..22].copy_from_slice(b"_main\0");

        let syms = AnalyzerSymbol::parse_symtab(&data, symoff, 1, stroff);
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "_main");
        assert_eq!(syms[0].addr, 0xDEAD_BEEF);
        assert_eq!(syms[0].section, Some(1));
        assert!(syms[0].external);
    }

    // ── MachoAnalyzer ────────────────────────────────────────────────────────

    #[test]
    fn analyzer_report_from_minimal_binary() {
        let bytes = minimal_macho64();
        let report = MachoAnalyzer::analyze(&bytes);
        assert_eq!(report.arch, "x86_64");
        assert_eq!(report.file_type, "MH_EXECUTE");
        assert!(report.is_pie); // flags = 0x0020_0085 includes MH_PIE
        assert!(!report.has_arc);
        assert!(!report.has_bitcode);
        assert!(report.encryption.is_none());
    }

    #[test]
    fn analyzer_report_empty_data() {
        let report = MachoAnalyzer::analyze(&[]);
        assert_eq!(report.arch, "unknown");
    }

    // ── MachoLoadCommandEnum ─────────────────────────────────────────────────

    #[test]
    fn load_command_enum_parse_all_empty() {
        let bytes = minimal_macho64(); // ncmds = 0
        let cmds = MachoLoadCommandEnum::parse_all(&bytes, 32, 0, false);
        assert!(cmds.is_empty());
    }

    #[test]
    fn load_command_enum_unknown_variant() {
        let unknown = MachoLoadCommandEnum::Unknown {
            cmd: 0xFFFF,
            cmdsize: 8,
        };
        if let MachoLoadCommandEnum::Unknown { cmd, cmdsize } = unknown {
            assert_eq!(cmd, 0xFFFF);
            assert_eq!(cmdsize, 8);
        }
    }

    #[test]
    fn fat_binary_parser_detect_non_fat_short() {
        assert!(!FatBinaryParser::detect_fat(&[0xCA, 0xFE]));
    }

    // ── New architecture variants ─────────────────────────────────────────────

    #[test]
    fn arch_arm64_32() {
        assert_eq!(MachoArch::from_cputype(0x0200_000C), MachoArch::Arm64_32);
        assert_eq!(MachoArch::Arm64_32.pointer_size(), 4);
        assert_eq!(MachoArch::Arm64_32.name(), "arm64_32");
        assert_eq!(MachoArch::Arm64_32.endian(), Endian::Little);
    }

    #[test]
    fn arch_mips() {
        assert_eq!(MachoArch::from_cputype(8), MachoArch::Mips);
        assert_eq!(MachoArch::Mips.name(), "mips");
        assert_eq!(MachoArch::Mips.endian(), Endian::Big);
    }

    #[test]
    fn arch_sparc() {
        assert_eq!(MachoArch::from_cputype(14), MachoArch::Sparc);
        assert_eq!(MachoArch::Sparc.name(), "sparc");
    }

    #[test]
    fn arch_is_64bit() {
        assert!(MachoArch::X86_64.is_64bit());
        assert!(MachoArch::Arm64.is_64bit());
        assert!(MachoArch::PowerPc64.is_64bit());
        assert!(!MachoArch::X86.is_64bit());
        assert!(!MachoArch::Arm.is_64bit());
        assert!(!MachoArch::Arm64_32.is_64bit());
    }

    #[test]
    fn arch_subtype_arm64e() {
        let name = MachoArch::subtype_name(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
        assert_eq!(name, "arm64e");
    }

    #[test]
    fn arch_subtype_x86_64h() {
        let name = MachoArch::subtype_name(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H);
        assert_eq!(name, "x86_64h (Haswell)");
    }

    // ── New file type variants ────────────────────────────────────────────────

    #[test]
    fn filetype_core() {
        assert_eq!(MachoFileType::from_filetype(0x4), MachoFileType::Core);
        assert!(MachoFileType::Core.is_core());
        assert!(!MachoFileType::Core.is_executable());
        assert_eq!(MachoFileType::Core.name(), "MH_CORE");
    }

    #[test]
    fn filetype_fileset() {
        assert_eq!(MachoFileType::from_filetype(0xC), MachoFileType::Fileset);
        assert!(MachoFileType::Fileset.is_fileset());
        assert_eq!(MachoFileType::Fileset.name(), "MH_FILESET");
    }

    #[test]
    fn filetype_fvmlib() {
        assert_eq!(MachoFileType::from_filetype(0x3), MachoFileType::FvmLib);
        assert_eq!(MachoFileType::FvmLib.name(), "MH_FVMLIB");
    }

    #[test]
    fn filetype_preload() {
        assert_eq!(MachoFileType::from_filetype(0x5), MachoFileType::Preload);
        assert_eq!(MachoFileType::Preload.name(), "MH_PRELOAD");
    }

    // ── DiceKind ─────────────────────────────────────────────────────────────

    #[test]
    fn dice_kind_from_raw() {
        assert_eq!(DiceKind::from_raw(0x0001), DiceKind::Data);
        assert_eq!(DiceKind::from_raw(0x0002), DiceKind::JumpTable8);
        assert_eq!(DiceKind::from_raw(0x0003), DiceKind::JumpTable16);
        assert_eq!(DiceKind::from_raw(0x0004), DiceKind::JumpTable32);
        assert_eq!(DiceKind::from_raw(0x0005), DiceKind::AbsJumpTable32);
        assert_eq!(DiceKind::from_raw(0xFFFF), DiceKind::Unknown(0xFFFF));
    }

    #[test]
    fn dice_kind_name() {
        assert_eq!(DiceKind::Data.name(), "DICE_KIND_DATA");
        assert_eq!(DiceKind::JumpTable32.name(), "DICE_KIND_JUMP_TABLE32");
        assert_eq!(
            DiceKind::AbsJumpTable32.name(),
            "DICE_KIND_ABS_JUMP_TABLE32"
        );
        assert_eq!(DiceKind::Unknown(0xAB).name(), "DICE_KIND_UNKNOWN");
    }

    // ── DataInCodeParser ──────────────────────────────────────────────────────

    #[test]
    fn data_in_code_parse_single_entry() {
        // offset(4LE) + length(2LE) + kind(2LE)
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // offset
        data.extend_from_slice(&8u16.to_le_bytes()); // length
        data.extend_from_slice(&0x0004u16.to_le_bytes()); // DICE_KIND_JUMP_TABLE32
        let entries = DataInCodeParser::parse(&data);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].offset, 0x1000);
        assert_eq!(entries[0].length, 8);
        assert_eq!(entries[0].kind, DiceKind::JumpTable32);
    }

    #[test]
    fn data_in_code_parse_empty() {
        let entries = DataInCodeParser::parse(&[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn data_in_code_total_bytes() {
        let entries = vec![
            DataInCodeEntry {
                offset: 0,
                length: 4,
                kind: DiceKind::Data,
            },
            DataInCodeEntry {
                offset: 16,
                length: 8,
                kind: DiceKind::JumpTable32,
            },
        ];
        assert_eq!(DataInCodeParser::total_data_bytes(&entries), 12);
    }

    // ── RebaseParser ──────────────────────────────────────────────────────────

    #[test]
    fn rebase_parser_done_opcode() {
        let data = vec![REBASE_OPCODE_DONE];
        let entries = RebaseParser::parse(&data);
        assert!(entries.is_empty());
    }

    #[test]
    fn rebase_parser_set_segment_and_do_rebase() {
        let data = vec![
            REBASE_OPCODE_SET_TYPE_IMM | 1,                 // type = POINTER (1)
            REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 1,  // segment 1
            0x10,                                            // offset ULEB = 0x10
            REBASE_OPCODE_DO_REBASE_IMM_TIMES | 2,          // do rebase 2 times
        ];

        let entries = RebaseParser::parse(&data);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].segment_index, 1);
        assert_eq!(entries[0].segment_offset, 0x10);
        assert_eq!(entries[0].rebase_type, REBASE_TYPE_POINTER);
        assert_eq!(entries[1].segment_offset, 0x18); // 0x10 + 8
    }

    // ── ChainedFixupsParser ───────────────────────────────────────────────────

    #[test]
    fn chained_ptr_format_from_raw() {
        assert_eq!(ChainedPtrFormat::from_raw(1), ChainedPtrFormat::Arm64E);
        assert_eq!(ChainedPtrFormat::from_raw(2), ChainedPtrFormat::Ptr64);
        assert_eq!(
            ChainedPtrFormat::from_raw(99),
            ChainedPtrFormat::Unknown(99)
        );
    }

    #[test]
    fn chained_ptr_format_name() {
        assert_eq!(ChainedPtrFormat::Arm64E.name(), "DYLD_CHAINED_PTR_ARM64E");
        assert_eq!(ChainedPtrFormat::Ptr64.name(), "DYLD_CHAINED_PTR_64");
        assert_eq!(
            ChainedPtrFormat::Arm64EUserland24.name(),
            "DYLD_CHAINED_PTR_ARM64E_USERLAND24"
        );
    }

    #[test]
    fn chained_fixups_parse_empty_blob() {
        let imports = ChainedFixupsParser::parse_imports(&[]);
        assert!(imports.is_empty());
    }

    #[test]
    fn chained_fixups_parse_one_import() {
        // Build a minimal dyld_chained_fixups_header + 1 import
        let mut data = vec![0u8; 256];
        // fixups_version = 0
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        // starts_offset = 28 (skip header, no segments)
        data[4..8].copy_from_slice(&28u32.to_le_bytes());
        // imports_offset = 28 (right after header)
        data[8..12].copy_from_slice(&28u32.to_le_bytes());
        // symbols_offset = 32 (after 1 × 4-byte import entry)
        data[12..16].copy_from_slice(&32u32.to_le_bytes());
        // imports_count = 1
        data[16..20].copy_from_slice(&1u32.to_le_bytes());
        // imports_format = 1 (DYLD_CHAINED_IMPORT, 4 bytes each)
        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        // symbols_format = 0
        data[24..28].copy_from_slice(&0u32.to_le_bytes());
        // import entry: lib_ordinal=1(low 8 bits), weak=0, name_offset=0 (bits 9..31)
        // raw = (0 << 9) | (0 << 8) | 1 = 1
        data[28..32].copy_from_slice(&1u32.to_le_bytes());
        // symbol at offset 32: "_mySymbol\0"
        let sym = b"_mySymbol\0";
        data[32..32 + sym.len()].copy_from_slice(sym);

        let imports = ChainedFixupsParser::parse_imports(&data);
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].lib_ordinal, 1);
        assert_eq!(imports[0].name, "_mySymbol");
        assert!(!imports[0].weak_import);
        assert_eq!(imports[0].addend, 0);
    }

    // ── CodeSignatureParser ───────────────────────────────────────────────────

    #[test]
    fn code_signature_parse_too_small() {
        let result = CodeSignatureParser::parse(&[0u8; 4]);
        assert!(result.is_err());
    }

    #[test]
    fn code_signature_wrong_magic() {
        let mut data = vec![0u8; 20];
        data[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        let result = CodeSignatureParser::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn code_signature_superblob_empty_slots() {
        // Build a minimal SuperBlob with 0 slots
        let mut data = vec![0u8; 12];
        data[0..4].copy_from_slice(&0xFADE_0CC0u32.to_be_bytes()); // CSMAGIC_EMBEDDED_SIGNATURE
        data[4..8].copy_from_slice(&12u32.to_be_bytes()); // length
        data[8..12].copy_from_slice(&0u32.to_be_bytes()); // count = 0
        let info = CodeSignatureParser::parse(&data).unwrap();
        assert!(info.slots.is_empty());
        assert!(info.code_directory.is_none());
        assert!(!info.has_cms);
        assert!(!info.has_requirements);
    }

    #[test]
    fn code_directory_retains_verification_fields() {
        // A CodeDirectory whose header fields are all distinct, so that a field
        // silently dropped on the way into the struct shows up as a wrong value
        // rather than as a coincidence.
        let mut cd = vec![0u8; 48];
        cd[0..4].copy_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
        cd[4..8].copy_from_slice(&48u32.to_be_bytes()); // length
        cd[8..12].copy_from_slice(&0x0002_0100u32.to_be_bytes()); // version 2.1
        cd[12..16].copy_from_slice(&0x0000_0002u32.to_be_bytes()); // flags
        cd[16..20].copy_from_slice(&44u32.to_be_bytes()); // hash_offset
        cd[20..24].copy_from_slice(&46u32.to_be_bytes()); // ident_offset
        cd[24..28].copy_from_slice(&5u32.to_be_bytes()); // n_special_slots
        cd[28..32].copy_from_slice(&7u32.to_be_bytes()); // n_code_slots
        cd[32..36].copy_from_slice(&0x1234u32.to_be_bytes()); // code_limit
        cd[36] = 32; // hash_size (SHA-256)
        cd[37] = 2; // hash_type
        cd[38] = 1; // platform
        cd[39] = 12; // page_size (4 KiB as power of two)
        cd[40..44].copy_from_slice(&0u32.to_be_bytes()); // team_id offset: absent
        cd[46] = b'x'; // identifier at ident_offset, NUL-terminated by the tail

        let parsed = CodeSignatureParser::parse_code_directory(&cd)
            .expect("a well-formed CodeDirectory must parse");

        // Fields the struct already carried.
        assert_eq!(parsed.version, 0x0002_0100);
        assert_eq!(parsed.flags, 2);
        assert_eq!(parsed.code_slots, 7);
        assert_eq!(parsed.hash_size, 32);
        assert_eq!(parsed.hash_type, 2);
        assert_eq!(parsed.page_size, 12);
        assert_eq!(parsed.identifier, "x");

        // Fields the parser used to read and then discard. Without these a
        // caller can describe a signature but cannot verify one: it knows
        // neither where the hashes are nor how far they reach.
        assert_eq!(parsed.hash_offset, 44);
        assert_eq!(parsed.ident_offset, 46);
        assert_eq!(parsed.n_special_slots, 5);
        assert_eq!(parsed.code_limit, 0x1234);
        assert_eq!(parsed.platform, 1);
    }

    #[test]
    fn bind_threaded_opcode_keeps_cursor_aligned() {
        // A threaded stream: SET_BIND_ORDINAL_TABLE_SIZE_ULEB with an operand
        // whose byte value (0x40) is itself a valid opcode
        // (SET_SYMBOL_TRAILING_FLAGS_IMM). If the operand is not consumed it is
        // re-read as that opcode, which swallows a C string and desynchronises
        // the whole stream — so this input distinguishes "aligned" from
        // "accidentally survived".
        let stream = [
            0xD0u8, // THREADED, imm = 0 → a ULEB operand follows
            0x40,   // the operand
            0x10 | 3, // SET_DYLIB_ORDINAL_IMM, ordinal 3
            0x90,   // DO_BIND
            0x00,   // DONE
        ];
        let binds = DyldInfoParser::parse_bind(&stream);
        assert_eq!(binds.len(), 1, "the DO_BIND after the threaded opcode must be reached");
        assert_eq!(
            binds[0].library_ordinal, 3,
            "ordinal 3 proves the cursor stayed aligned across the threaded opcode"
        );
    }

    #[test]
    fn bind_unknown_opcode_stops_instead_of_fabricating() {
        // 0xE0 is not modelled by this decoder. Everything after it is operand
        // bytes we cannot interpret, so the decoder must stop and return what it
        // genuinely decoded rather than re-read those bytes as opcodes.
        let stream = [
            0x10 | 1, // SET_DYLIB_ORDINAL_IMM, ordinal 1
            0x90,     // DO_BIND  → one real entry
            0xE0,     // unmodelled opcode
            0x90,     // would become a second, fabricated entry if we skipped
            0x90,
        ];
        let binds = DyldInfoParser::parse_bind(&stream);
        assert_eq!(
            binds.len(),
            1,
            "only the entry decoded before the unknown opcode may be reported"
        );
    }

    // ── MachoHeaderFlags ──────────────────────────────────────────────────────

    #[test]
    fn header_flags_pie() {
        let flags = MachoHeaderFlags::from_raw(0x0020_0000);
        assert!(flags.is_pie);
        assert!(!flags.has_twolevel);
    }

    #[test]
    fn header_flags_twolevel() {
        let flags = MachoHeaderFlags::from_raw(0x0000_0080);
        assert!(flags.has_twolevel);
        assert!(!flags.is_pie);
    }

    #[test]
    fn header_flags_app_extension_safe() {
        let flags = MachoHeaderFlags::from_raw(0x0200_0000);
        assert!(flags.app_extension_safe);
    }

    #[test]
    fn header_flags_raw_preserved() {
        let raw = 0xDEAD_BEEF;
        let flags = MachoHeaderFlags::from_raw(raw);
        assert_eq!(flags.raw, raw);
    }

    // ── MachoInfo new convenience methods ─────────────────────────────────────

    #[test]
    fn info_has_objc_false_for_empty() {
        let info = info_with_segments();
        assert!(!info.has_objc());
    }

    #[test]
    fn info_has_swift_false_for_empty() {
        let info = info_with_segments();
        assert!(!info.has_swift());
    }

    #[test]
    fn info_function_count_zero() {
        let info = info_with_segments();
        assert_eq!(info.function_count(), 0);
    }

    #[test]
    fn info_data_in_code_count_zero() {
        let info = info_with_segments();
        assert_eq!(info.data_in_code_count(), 0);
    }

    #[test]
    fn info_is_signed_with_cms_none() {
        let info = info_with_segments();
        assert!(!info.is_signed_with_cms());
    }

    #[test]
    fn info_entitlements_none() {
        let info = info_with_segments();
        assert!(info.entitlements().is_none());
    }

    #[test]
    fn info_header_flags_decodes() {
        let mut info = info_with_segments();
        info.flags = MH_PIE | 0x80; // PIE + TWOLEVEL
        let hf = info.header_flags();
        assert!(hf.is_pie);
        assert!(hf.has_twolevel);
    }

    // ── SwiftMetadataParser ───────────────────────────────────────────────────

    #[test]
    fn swift_resolve_relative_ptr_positive() {
        let result = SwiftMetadataParser::resolve_relative_ptr(0x1000, 0x100);
        assert_eq!(result, 0x1100);
    }

    #[test]
    fn swift_resolve_relative_ptr_negative() {
        let result = SwiftMetadataParser::resolve_relative_ptr(0x1000, -0x100);
        assert_eq!(result, 0x0F00);
    }

    #[test]
    fn swift_metadata_parse_empty_segments() {
        let bytes = minimal_macho64();
        let segments: Vec<MachoSegment> = Vec::new();
        let mut types = Vec::new();
        let mut protos = Vec::new();
        SwiftMetadataParser::extract_from_segments(&bytes, &segments, &mut types, &mut protos);
        assert!(types.is_empty());
        assert!(protos.is_empty());
    }

    // ── Function starts in minimal parse ────────────────────────────────────

    #[test]
    fn function_starts_terminator_only() {
        let data = vec![0x00u8]; // zero delta = terminator
        let addrs = FunctionStartsParser::parse(&data, 0x2000);
        assert!(addrs.is_empty());
    }

    #[test]
    fn function_starts_sorted() {
        // Deltas: 0x30, 0x10 → [0x2030, 0x2040]  (already ascending, but test sort)
        let data = vec![0x30u8, 0x10, 0x00];
        let addrs = FunctionStartsParser::parse(&data, 0x2000);
        assert_eq!(addrs, vec![0x2030, 0x2040]);
    }

    // ── MachoLoadCommandEnum new variants ────────────────────────────────────

    #[test]
    fn lc_enum_dysymtab_fields() {
        let mut lc_bytes = vec![0u8; 80];
        lc_bytes[0..4].copy_from_slice(&LC_DYSYMTAB.to_le_bytes());
        lc_bytes[4..8].copy_from_slice(&80u32.to_le_bytes()); // cmdsize
        lc_bytes[8..12].copy_from_slice(&5u32.to_le_bytes()); // ilocalsym
        lc_bytes[12..16].copy_from_slice(&10u32.to_le_bytes()); // nlocalsym
        let cmds = MachoLoadCommandEnum::parse_all(&lc_bytes, 0, 1, false);
        if let MachoLoadCommandEnum::Dysymtab {
            ilocalsym,
            nlocalsym,
            ..
        } = &cmds[0]
        {
            assert_eq!(*ilocalsym, 5);
            assert_eq!(*nlocalsym, 10);
        } else {
            panic!("Expected Dysymtab");
        }
    }

    #[test]
    fn lc_enum_entry_point() {
        let mut lc_bytes = vec![0u8; 24];
        lc_bytes[0..4].copy_from_slice(&LC_MAIN.to_le_bytes());
        lc_bytes[4..8].copy_from_slice(&24u32.to_le_bytes());
        lc_bytes[8..16].copy_from_slice(&0x1000u64.to_le_bytes()); // entryoff
        lc_bytes[16..24].copy_from_slice(&0x8000u64.to_le_bytes()); // stacksize
        let cmds = MachoLoadCommandEnum::parse_all(&lc_bytes, 0, 1, false);
        if let MachoLoadCommandEnum::EntryPoint {
            entryoff,
            stacksize,
        } = &cmds[0]
        {
            assert_eq!(*entryoff, 0x1000);
            assert_eq!(*stacksize, 0x8000);
        } else {
            panic!("Expected EntryPoint");
        }
    }

    // ── MachoParser parse_single with LC_UUID ────────────────────────────────

    #[test]
    fn parse_macho64_with_uuid_lc() {
        let mut b = minimal_macho64();
        // Patch ncmds = 1, sizeofcmds = 24 in the header (offsets 16 and 20)
        b[16..20].copy_from_slice(&1u32.to_le_bytes());
        b[20..24].copy_from_slice(&24u32.to_le_bytes());
        // Append LC_UUID command (24 bytes)
        b.extend_from_slice(&LC_UUID.to_le_bytes());
        b.extend_from_slice(&24u32.to_le_bytes()); // cmdsize
        b.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]);
        let info = MachoParser::parse(&b).unwrap();
        let uuid = info.uuid.unwrap();
        assert_eq!(uuid[0], 0x01);
        assert_eq!(uuid[15], 0x10);
    }

    #[test]
    fn parse_macho64_with_rpath_lc() {
        let mut b = minimal_macho64();
        // rpath_command: cmd(4) + cmdsize(4) + path_off(4) + path_str
        // path starts at offset 12 from LC start
        let rpath_str = b"/usr/lib\0";
        let cmdsize = (12 + rpath_str.len() + 3) & !3; // align to 4
        b[16..20].copy_from_slice(&1u32.to_le_bytes()); // ncmds
        b[20..24].copy_from_slice(&(cmdsize as u32).to_le_bytes());
        b.extend_from_slice(&LC_RPATH.to_le_bytes());
        b.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        b.extend_from_slice(&12u32.to_le_bytes()); // path offset = 12
        b.extend_from_slice(rpath_str);
        b.resize(b.len() + (cmdsize - 12 - rpath_str.len()), 0);
        let info = MachoParser::parse(&b).unwrap();
        assert!(!info.rpaths.is_empty());
        assert!(info.rpaths[0].contains("/usr/lib"));
    }

    // ── DyldInfoParser parse_bind with ULEB ordinal ───────────────────────────

    #[test]
    fn parse_bind_uleb_ordinal() {
        let mut data = vec![
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB,
            0xAC, 0x02, // ULEB 300
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
        ];
        data.extend_from_slice(b"_bar\0");
        data.push(0x90); // DO_BIND
        data.push(0x00); // DONE
        let entries = DyldInfoParser::parse_bind(&data);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].symbol_name, "_bar");
        assert_eq!(entries[0].library_ordinal, 44); // 300 as u8 truncated
    }

    // ── FatBinaryParser with two arches ──────────────────────────────────────

    #[test]
    fn fat_list_two_arches() {
        let mut data = vec![0u8; 300];
        data[0] = 0xCA;
        data[1] = 0xFE;
        data[2] = 0xBA;
        data[3] = 0xBE; // magic
        data[4] = 0;
        data[5] = 0;
        data[6] = 0;
        data[7] = 2; // nfat = 2
        // arch 0: cputype=0x0100_0007 (x86_64), offset=100, size=4
        data[8..12].copy_from_slice(&0x0100_0007u32.to_be_bytes()); // cputype
        data[12..16].copy_from_slice(&3u32.to_be_bytes()); // cpusubtype
        data[16..20].copy_from_slice(&100u32.to_be_bytes()); // offset
        data[20..24].copy_from_slice(&4u32.to_be_bytes()); // size
        data[24..28].copy_from_slice(&12u32.to_be_bytes()); // align
        // arch 1: cputype=0x0100_000C (arm64), offset=200, size=4
        data[28..32].copy_from_slice(&0x0100_000Cu32.to_be_bytes());
        data[32..36].copy_from_slice(&0u32.to_be_bytes());
        data[36..40].copy_from_slice(&200u32.to_be_bytes());
        data[40..44].copy_from_slice(&4u32.to_be_bytes());
        data[44..48].copy_from_slice(&14u32.to_be_bytes());

        let arches = FatBinaryParser::list_arches(&data);
        assert_eq!(arches.len(), 2);
        assert_eq!(arches[0].cputype, 0x0100_0007);
        assert_eq!(arches[1].cputype, 0x0100_000C);
    }
}
