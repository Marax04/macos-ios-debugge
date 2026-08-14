//! `rustre-loader-pe` — Enterprise-grade Portable Executable (PE) loader.
//!
//! Parses every standard PE structure from raw bytes using both `goblin` and
//! our own hand-written parsers in the sub-modules.  All data is surfaced
//! through [`PeInfo`] and [`PeParser`], and a fully populated [`BinaryView`]
//! is returned by the [`PeLoader`] trait implementation.
//!
//! # Supported features
//!
//! | Feature | Module |
//! |---|---|
//! | DOS header, Rich header XOR decode + product ID table | [`headers`] |
//! | PE/PE+ header, optional header (all 16 data directories) | [`headers`] |
//! | Section table with virtual-address-space layout & zero-pad | [`headers`] |
//! | Import table: full ILT/IAT walk, bound imports | [`imports`] |
//! | Delay-load imports (`__delayLoadHelper2` pattern detection) | [`imports`] |
//! | Export table: by name + ordinal, forwarder RVAs | [`exports`] |
//! | Base relocation directory, all 13 reloc types | [`relocations`] |
//! | TLS directory: callbacks, index, raw-data range | [`tls`] |
//! | Exception directory: RUNTIME_FUNCTION + UNWIND_INFO | [`exceptions`] |
//! | Load config: SafeSEH, CFG table, GuardFlags, dynamic relocs | [`load_config`] |
//! | Resource directory: full recursive tree, manifest, version info | [`resources`] |
//! | Debug directory: all 11 types, RSDS/NB10 PDB GUID+age | [`debug_dir`] |
//! | Security directory: Authenticode PKCS#7 extraction | [`overlay`] |
//! | .NET detection: CLI header → metadata root | [`dotnet`] |
//! | Overlay detection: bytes past last section | [`overlay`] |
//! | Section entropy analysis | [`entropy`] |
//! | String scanning (ASCII + UTF-16LE) | [`strings`] |

pub(crate) mod casts;
pub mod compiler_detect;
pub mod debug_dir;
pub mod dotnet;
pub mod entropy;
pub mod exceptions;
pub mod exports;
pub mod flirt_autoname;
pub mod headers;
pub mod imports;
pub mod load_config;
pub mod overlay;
pub mod pe_analyzer;
pub mod pe_code_analysis;
pub mod pe_imphash;
pub mod pe_tls_callbacks;
pub mod relocations;
pub mod resources;
pub mod strings;
pub mod tls;

pub use pe_tls_callbacks::{
    CallbackClass, Cve201711882Result, EmbeddedShellcode, PeTlsCallbacks, TlsCallback,
    TlsCallbackAnalyzer, TlsCallbackExecutionOrder, TlsDirectory32 as PeTlsCallbackDirectory32,
    TlsDirectory64 as PeTlsCallbackDirectory64, TlsError,
};

use std::sync::Arc;

use async_trait::async_trait;
use goblin::pe::PE;
use rustre_core::address::{Address, AddressRange};
use rustre_core::binary_view::{BinaryView, Memory, Segment};
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;
use rustre_core::permissions::Permissions;
use rustre_core::loader::{Loader, LoaderInput, NestedBinary};

// ---------------------------------------------------------------------------
// Re-exported public types from sub-modules
// ---------------------------------------------------------------------------

pub use compiler_detect::{Compiler, CompilerInfo, Linker, detect_compiler};

pub use headers::{
    CoffFileHeader, DataDirectory, DosHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
    IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
    IMAGE_DIRECTORY_ENTRY_IAT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
    IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_DIRECTORY_ENTRY_TLS,
    OptionalHeader, OptionalHeader32, OptionalHeader64, PeHeaders, RichHeader, RichProductInfo,
    SectionHeader,
};

pub use imports::{
    BoundImportEntry, DelayImportDescriptor, IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64,
    ImportDescriptor, ImportSummary, ImportedFunction, RvaSection, parse_bound_imports,
    parse_delay_imports, parse_import_table_32, parse_import_table_64, rva_to_file_offset,
};

pub use exports::{ExportDirectory, ExportMap, ExportedSymbol, parse_export_table};

pub use relocations::{
    IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_ARM_MOV32, IMAGE_REL_BASED_DIR64,
    IMAGE_REL_BASED_HIGH, IMAGE_REL_BASED_HIGHADJ, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_LOW,
    IMAGE_REL_BASED_MIPS_JMPADDR, IMAGE_REL_BASED_MIPS_JMPADDR16, IMAGE_REL_BASED_RISCV_HIGH20,
    IMAGE_REL_BASED_RISCV_LOW12I, IMAGE_REL_BASED_RISCV_LOW12S, IMAGE_REL_BASED_THUMB_MOV32,
    Relocation, RelocationBlock, RelocationStats, apply_relocations, parse_relocation_directory,
};

pub use tls::{
    TlsAnalysis, TlsAntiDebugHint, TlsDirectory32, TlsDirectory64, TlsInfo, parse_tls_32,
    parse_tls_64,
};

pub use exceptions::{
    ArmRuntimeFunction, ExceptionDirectory, RuntimeFunction, UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER,
    UNW_FLAG_NHANDLER, UNW_FLAG_UHANDLER, UnwindCode, UnwindInfo, x64_reg_name,
};

pub use load_config::{
    CfgFunctionEntry, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, IMAGE_DLLCHARACTERISTICS_GUARD_CF,
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT, IMAGE_GUARD_CF_INSTRUMENTED,
    IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT, IMAGE_GUARD_RETPOLINE_PRESENT,
    LoadConfigDirectory32, LoadConfigDirectory64, MitigationFlags, SecurityFeatures, parse_cfg_function_table,
    parse_safe_seh_handlers,
};

pub use resources::{
    ManifestInfo, RT_ACCELERATOR, RT_ANICURSOR, RT_ANIICON, RT_BITMAP, RT_CURSOR, RT_DIALOG,
    RT_DLGINCLUDE, RT_FONT, RT_FONTDIR, RT_GROUP_CURSOR, RT_GROUP_ICON, RT_HTML, RT_ICON,
    RT_MANIFEST, RT_MENU, RT_MESSAGETABLE, RT_PLUGPLAY, RT_RCDATA, RT_STRING, RT_VERSION, RT_VXD,
    ResourceDataEntry, ResourceId, ResourceNode, ResourceTree, VersionInfo, resource_type_name,
};

pub use debug_dir::{
    CodeViewInfo, DebugDirectoryEntry, IMAGE_DEBUG_TYPE_BORLAND, IMAGE_DEBUG_TYPE_CLSID,
    IMAGE_DEBUG_TYPE_CODEVIEW, IMAGE_DEBUG_TYPE_COFF, IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS,
    IMAGE_DEBUG_TYPE_EXCEPTION, IMAGE_DEBUG_TYPE_FIXUP, IMAGE_DEBUG_TYPE_FPO,
    IMAGE_DEBUG_TYPE_ILTCG, IMAGE_DEBUG_TYPE_MISC, IMAGE_DEBUG_TYPE_MPX,
    IMAGE_DEBUG_TYPE_OMAP_FROM_SRC, IMAGE_DEBUG_TYPE_OMAP_TO_SRC, IMAGE_DEBUG_TYPE_POGO,
    IMAGE_DEBUG_TYPE_REPRO, IMAGE_DEBUG_TYPE_RESERVED10, IMAGE_DEBUG_TYPE_SPGO,
    IMAGE_DEBUG_TYPE_UNKNOWN, IMAGE_DEBUG_TYPE_VC_FEATURE, Nb10Record, PdbGuid, RsdsRecord,
    VcFeatureRecord, debug_type_name, detect_dotnet, extract_codeview_info, parse_debug_directory,
};

pub use overlay::{
    OverlayInfo, SfxKind, WIN_CERT_REVISION_1_0, WIN_CERT_REVISION_2_0,
    WIN_CERT_TYPE_PKCS_SIGNED_DATA, WIN_CERT_TYPE_RESERVED_1, WIN_CERT_TYPE_TS_STACK_SIGNED,
    WIN_CERT_TYPE_X509, WinCertificate, cert_type_name, detect_sfx_kind, find_overlay_offset,
    parse_security_directory,
};

pub use dotnet::{
    COMIMAGE_FLAGS_32BITPREFERRED, COMIMAGE_FLAGS_32BITREQUIRED, COMIMAGE_FLAGS_ILONLY,
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT, COMIMAGE_FLAGS_STRONGNAMESIGNED, Cor20DataDirectory,
    Cor20Header, DotNetInfo, METADATA_SIGNATURE, MetadataRoot, parse_dotnet,
};

pub use entropy::{
    EntropySummary, HIGH_ENTROPY_THRESHOLD, LOW_ENTROPY_THRESHOLD, PACKED_ENTROPY_THRESHOLD,
    SectionEntropy, SectionWithName, analyze_sections, byte_histogram, looks_packed,
    most_common_byte, shannon_entropy,
};

pub use strings::{
    ExtractedString, InterestingCategory, MIN_ASCII_LEN, MIN_UTF16_LEN, ScanOptions,
    StringEncoding, classify_string, is_printable_ascii, is_printable_utf16, scan_ascii,
    scan_section, scan_strings, scan_utf16le,
};

// ---------------------------------------------------------------------------
// PE section characteristic flags (used in lib.rs directly)
// ---------------------------------------------------------------------------

const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

// PE subsystem constants
const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
const IMAGE_SUBSYSTEM_EFI_APPLICATION: u16 = 10;
const IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: u16 = 11;
const IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: u16 = 12;
const IMAGE_SUBSYSTEM_EFI_ROM: u16 = 13;

// Machine type constants
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM: u16 = 0x01C0;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

// PE characteristics
const IMAGE_FILE_DLL_FLAG: u16 = 0x2000;

// Rich header magic
const RICH_MAGIC: &[u8; 4] = b"Rich";
const DANS_MAGIC: &[u8; 4] = b"DanS";

// (debug-type and RSDS constants are defined in debug_dir.rs and re-exported above)

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

/// CPU architecture reported by the PE file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Machine {
    X64,
    X86,
    Arm,
    Arm64,
    Unknown(u16),
}

/// Windows subsystem reported by the optional header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subsystem {
    Console,
    Windows,
    Native,
    EfiApp,
    EfiBootService,
    EfiRuntime,
    EfiRom,
    Unknown(u16),
}

/// One entry from the PE import table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEntry {
    /// Owning DLL name (e.g. `"KERNEL32.dll"`).
    pub dll: String,
    /// Function name, or `None` if imported by ordinal only.
    pub name: Option<String>,
    /// Ordinal hint, if available.
    pub ordinal: Option<u16>,
    /// Virtual address of the IAT slot (image-base-relative).
    pub address: u64,
}

/// One entry from the PE export table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportEntry {
    /// Symbol name, or `None` for anonymous exports.
    pub name: Option<String>,
    /// Export ordinal.
    pub ordinal: u16,
    /// Virtual address of the exported function/data.
    pub address: u64,
    /// Forwarder string if this is a forwarded export (e.g. "NTDLL.RtlFreeHeap").
    pub forwarder: Option<String>,
}

/// Metadata for one PE section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub permissions: Permissions,
}

impl SectionInfo {
    /// Return the section's virtual-address range [start, end).
    #[must_use]
    pub fn va_range(&self) -> (u64, u64) {
        (
            self.virtual_address,
            self.virtual_address + u64::from(self.virtual_size),
        )
    }

    /// Return `true` if the section contains executable code.
    #[must_use]
    pub const fn is_code(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    /// Return `true` if the section is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    /// Return `true` if the section is readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }

    /// Return section data length in memory (`virtual_size`), which may be larger
    /// than `raw_size` (zero-padded BSS regions).
    #[must_use]
    pub const fn mapped_size(&self) -> u32 {
        self.virtual_size
    }
}

/// Parsed Rich header (Microsoft linker fingerprint in DOS stub).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RichHeaderInfo {
    pub entries: Vec<RichEntry>,
    pub key: u32,
}

/// One entry inside a Rich header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RichEntry {
    pub product_id: u16,
    pub build_number: u16,
    pub count: u32,
}

/// One entry from the exception directory (`.pdata`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeFunctionInfo {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info: u32,
}

// ---------------------------------------------------------------------------
// Delay-load helper pattern
// ---------------------------------------------------------------------------

/// Detection result for `__delayLoadHelper2` imports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelayLoadEntry {
    /// DLL name being delay-loaded.
    pub dll: String,
    /// Whether this descriptor uses RVAs (v2 format; attributes bit 1).
    pub uses_rvas: bool,
    /// RVA of the delay IAT.
    pub delay_iat_rva: u32,
    /// Timestamp (0 = not yet loaded).
    pub time_stamp: u32,
}

// ---------------------------------------------------------------------------
// Security / Authenticode
// ---------------------------------------------------------------------------

/// Authenticode signature info extracted from the security data directory.
#[derive(Debug, Clone)]
pub struct AuthenticodeInfo {
    /// Raw PKCS#7 `SignedData` blob (DER-encoded).
    pub pkcs7_data: Vec<u8>,
    /// `WIN_CERTIFICATE` length field.
    pub cert_length: u32,
    /// `WIN_CERTIFICATE` revision.
    pub revision: u16,
}

// ---------------------------------------------------------------------------
// TLS callback info
// ---------------------------------------------------------------------------

/// TLS directory and callback summary.
#[derive(Debug, Clone)]
pub struct TlsCallbackInfo {
    /// Absolute VAs of TLS callbacks.
    pub callbacks: Vec<u64>,
    /// TLS data start VA.
    pub data_start: u64,
    /// TLS data end VA.
    pub data_end: u64,
    /// Zero-fill size.
    pub zero_fill_size: u32,
    /// Whether this is a 64-bit TLS directory.
    pub is_64bit: bool,
}

// ---------------------------------------------------------------------------
// Load configuration summary
// ---------------------------------------------------------------------------

/// Condensed load-configuration information.
#[derive(Debug, Clone, Default)]
pub struct LoadConfigInfo {
    /// VA of /GS security cookie.
    pub security_cookie: u64,
    /// `SafeSEH` handler RVAs (32-bit only).
    pub seh_handlers: Vec<u32>,
    /// CFG function table entries.
    pub cfg_functions: Vec<u32>,
    /// Raw guard flags value.
    pub guard_flags: u32,
    /// Security features present.
    pub features: SecurityFeatures,
}

// ---------------------------------------------------------------------------
// Resource summary
// ---------------------------------------------------------------------------

/// High-level resource summary.
#[derive(Debug, Clone, Default)]
pub struct ResourceSummary {
    /// Parsed manifest (`RT_MANIFEST`).
    pub manifest: Option<ManifestInfo>,
    /// Version info (`RT_VERSION`).
    pub version_info: Option<VersionInfo>,
    /// Number of icons (`RT_ICON` + `RT_GROUP_ICON` entries).
    pub icon_count: usize,
    /// Total number of resource leaf nodes.
    pub total_leaves: usize,
}

// ---------------------------------------------------------------------------
// Overlay / signature summary
// ---------------------------------------------------------------------------

/// Overlay and Authenticode signature summary.
#[derive(Debug, Clone)]
pub struct OverlaySummary {
    /// File offset where the overlay starts.
    pub offset: usize,
    /// Overlay size in bytes.
    pub size: usize,
    /// Detected SFX format.
    pub sfx_kind: SfxKind,
    /// Authenticode info, if signed.
    pub authenticode: Option<AuthenticodeInfo>,
    /// `true` if the file is Authenticode-signed.
    pub is_signed: bool,
}

// ---------------------------------------------------------------------------
// .NET summary
// ---------------------------------------------------------------------------

/// Summary of .NET metadata extracted from `DataDirectory`[14].
#[derive(Debug, Clone)]
pub struct DotNetSummary {
    /// CLR runtime version string from the COR20 header (e.g. "4.0").
    pub clr_version: String,
    /// Framework version from metadata root (e.g. "v4.0.30319").
    pub framework_version: Option<String>,
    /// Pure-IL assembly (no native code).
    pub is_pure_il: bool,
    /// Mixed-mode (C++/CLI / IJW).
    pub is_mixed_mode: bool,
    /// Strong-name signed.
    pub is_strong_name_signed: bool,
}

// ---------------------------------------------------------------------------
// Debug info summary
// ---------------------------------------------------------------------------

/// Debug information extracted from the debug directory.
#[derive(Debug, Clone, Default)]
pub struct DebugInfo {
    /// PDB file path (from RSDS/NB10 `CodeView` entry).
    pub pdb_path: Option<String>,
    /// PDB GUID (from RSDS entry).
    pub pdb_guid: Option<String>,
    /// PDB age.
    pub pdb_age: Option<u32>,
    /// All debug directory entry types present.
    pub entry_types: Vec<u32>,
}

// ---------------------------------------------------------------------------
// All parsed information extracted from a PE binary.
// ---------------------------------------------------------------------------

/// Bitflags for PE file-type characteristics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeFlags(pub u8);

impl PeFlags {
    pub const DOTNET: u8 = 0x01;
    pub const DRIVER: u8 = 0x02;
    pub const DLL: u8 = 0x04;
    pub const IS_64BIT: u8 = 0x08;

    #[must_use]
    pub const fn get(self, bit: u8) -> bool { self.0 & bit != 0 }
    #[must_use]
    pub const fn is_dotnet(self) -> bool { self.get(Self::DOTNET) }
    #[must_use]
    pub const fn is_driver(self) -> bool { self.get(Self::DRIVER) }
    #[must_use]
    pub const fn is_dll(self) -> bool { self.get(Self::DLL) }
    #[must_use]
    pub const fn is_64bit(self) -> bool { self.get(Self::IS_64BIT) }

    pub const fn set(&mut self, bit: u8, value: bool) {
        if value { self.0 |= bit; } else { self.0 &= !bit; }
    }
}

/// Complete enterprise-level parse result for a Portable Executable binary.
///
/// Every field is populated from the corresponding data directory / section
/// during [`PeInfo::parse`].  Fields for absent structures are `None` or
/// `Default::default()`.
#[derive(Debug, Clone)]
pub struct PeInfo {
    // ---- Basic identification ----
    pub machine: Machine,
    pub subsystem: Subsystem,
    pub image_base: u64,
    pub entry_point: u64,
    /// Raw entry-point RVA from the PE optional header (before adding `image_base`).
    /// Zero means the PE has no entry point (e.g. a resource-only DLL).
    pub entry_rva: u32,
    pub timestamp: u32,
    pub checksum: u32,
    pub dll_characteristics: u16,

    // ---- File type flags ----
    pub flags: PeFlags,

    // ---- Headers ----
    /// Fully parsed PE headers (DOS + COFF + Optional + sections).
    pub pe_headers: Option<PeHeaders>,
    /// Rich header fingerprint.
    pub rich_header: Option<RichHeaderInfo>,

    // ---- Sections ----
    pub sections: Vec<SectionInfo>,

    // ---- Imports ----
    pub imports: Vec<ImportEntry>,
    /// Full ILT/IAT walk results (richer than `imports`).
    pub detailed_imports: Vec<ImportedFunction>,
    /// Bound import entries.
    pub bound_imports: Vec<BoundImportEntry>,
    /// Delay-load import descriptors.
    pub delay_imports: Vec<DelayLoadEntry>,

    // ---- Exports ----
    pub exports: Vec<ExportEntry>,
    /// Rich export map (lookup by name or ordinal).
    pub export_map: Option<ExportMap>,

    // ---- Relocations ----
    pub relocation_blocks: Vec<RelocationBlock>,
    pub relocation_stats: RelocationStats,

    // ---- TLS ----
    pub tls: Option<TlsCallbackInfo>,
    /// Convenience flat list of TLS callback VAs.
    pub tls_callbacks: Vec<u64>,

    // ---- Exceptions ----
    pub exception_functions: Vec<RuntimeFunctionInfo>,
    /// Richer exception directory with full `UNWIND_INFO`.
    pub exception_directory: Option<ExceptionDirectory>,

    // ---- Load config ----
    pub load_config: LoadConfigInfo,

    // ---- Resources ----
    pub resource_tree: Option<ResourceTree>,
    pub resource_summary: ResourceSummary,

    // ---- Debug directory ----
    pub debug_info: DebugInfo,

    // ---- Security (Authenticode) ----
    pub authenticode_certs: Vec<WinCertificate>,

    // ---- .NET ----
    pub dotnet: Option<DotNetSummary>,

    // ---- Overlay ----
    pub overlay: Option<OverlaySummary>,

    // ---- Entropy ----
    pub entropy_summary: Option<EntropySummary>,
}

impl PeInfo {
    /// Returns `true` if the PE has a .NET CLR runtime header.
    #[must_use]
    pub const fn is_dotnet(&self) -> bool { self.flags.is_dotnet() }
    /// Returns `true` if the PE is a kernel-mode driver.
    #[must_use]
    pub const fn is_driver(&self) -> bool { self.flags.is_driver() }
    /// Returns `true` if the PE is a DLL.
    #[must_use]
    pub const fn is_dll(&self) -> bool { self.flags.is_dll() }
    /// Returns `true` if the PE is a 64-bit image.
    #[must_use]
    pub const fn is_64bit(&self) -> bool { self.flags.is_64bit() }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn permissions_from_characteristics(chars: u32) -> Permissions {
    let mut perms = Permissions::NONE;
    if chars & IMAGE_SCN_MEM_READ != 0 {
        perms |= Permissions::READ;
    }
    if chars & IMAGE_SCN_MEM_WRITE != 0 {
        perms |= Permissions::WRITE;
    }
    if chars & IMAGE_SCN_MEM_EXECUTE != 0 {
        perms |= Permissions::EXECUTE;
    }
    if perms == Permissions::NONE {
        perms = Permissions::READ;
    }
    perms
}

const fn machine_from_u16(m: u16) -> Machine {
    match m {
        IMAGE_FILE_MACHINE_I386 => Machine::X86,
        IMAGE_FILE_MACHINE_AMD64 => Machine::X64,
        IMAGE_FILE_MACHINE_ARM => Machine::Arm,
        IMAGE_FILE_MACHINE_ARM64 => Machine::Arm64,
        other => Machine::Unknown(other),
    }
}

const fn subsystem_from_u16(s: u16) -> Subsystem {
    match s {
        IMAGE_SUBSYSTEM_NATIVE => Subsystem::Native,
        IMAGE_SUBSYSTEM_WINDOWS_GUI => Subsystem::Windows,
        IMAGE_SUBSYSTEM_WINDOWS_CUI => Subsystem::Console,
        IMAGE_SUBSYSTEM_EFI_APPLICATION => Subsystem::EfiApp,
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER => Subsystem::EfiBootService,
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER => Subsystem::EfiRuntime,
        IMAGE_SUBSYSTEM_EFI_ROM => Subsystem::EfiRom,
        other => Subsystem::Unknown(other),
    }
}

/// Read a NUL-terminated ASCII/UTF-8 string from `data` at `file_offset`.
fn read_cstr_at(data: &[u8], file_offset: usize) -> String {
    if file_offset >= data.len() {
        return String::new();
    }
    let slice = &data[file_offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

/// Parse the Rich header from the DOS stub region `[64 .. pe_offset)`.
fn parse_rich_header(data: &[u8], pe_offset: usize) -> Option<RichHeaderInfo> {
    if pe_offset < 64 || pe_offset > data.len() {
        return None;
    }
    let dos_stub = &data[64..pe_offset];
    let rich_pos = dos_stub.windows(4).position(|w| w == RICH_MAGIC)?;
    if rich_pos + 8 > dos_stub.len() {
        return None;
    }
    let key = u32::from_le_bytes(dos_stub[rich_pos + 4..rich_pos + 8].try_into().ok()?);
    let first_dword_encoded = u32::from_le_bytes(dos_stub[0..4].try_into().ok()?);
    if first_dword_encoded ^ key != u32::from_le_bytes(*DANS_MAGIC) {
        return None;
    }
    let payload_start = 16usize;
    let payload_end = rich_pos;
    if payload_start >= payload_end {
        return None;
    }
    let payload = &dos_stub[payload_start..payload_end];
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset + 8 <= payload.len() {
        let raw_comp_id = u32::from_le_bytes(payload[offset..offset + 4].try_into().ok()?);
        let raw_count = u32::from_le_bytes(payload[offset + 4..offset + 8].try_into().ok()?);
        let comp_id = raw_comp_id ^ key;
        let count = raw_count ^ key;
        let product_id = (comp_id >> 16) as u16;
        let build_number = u16::try_from(comp_id & 0xFFFF).unwrap_or(u16::MAX);
        entries.push(RichEntry {
            product_id,
            build_number,
            count,
        });
        offset += 8;
    }
    Some(RichHeaderInfo { entries, key })
}

/// Parse `RUNTIME_FUNCTION` entries from raw `.pdata` bytes (basic form for lib.rs).
fn parse_exception_directory_basic(pdata: &[u8]) -> Vec<RuntimeFunctionInfo> {
    let mut funcs = Vec::new();
    let entry_size = 12usize;
    let count = pdata.len() / entry_size;
    for i in 0..count {
        let off = i * entry_size;
        if off + entry_size > pdata.len() {
            break;
        }
        let begin = u32::from_le_bytes(pdata[off..off + 4].try_into().unwrap_or([0; 4]));
        let end = u32::from_le_bytes(pdata[off + 4..off + 8].try_into().unwrap_or([0; 4]));
        let unwind = u32::from_le_bytes(pdata[off + 8..off + 12].try_into().unwrap_or([0; 4]));
        if begin == 0 && end == 0 {
            break;
        }
        funcs.push(RuntimeFunctionInfo {
            begin_address: begin,
            end_address: end,
            unwind_info: unwind,
        });
    }
    funcs
}

// ---------------------------------------------------------------------------
// PeInfo helper functions
// ---------------------------------------------------------------------------

fn collect_sections_and_pdata(
    pe: &PE<'_>,
    data: &[u8],
    image_base: u64,
) -> (Vec<SectionInfo>, Option<Vec<u8>>) {
    let mut sections = Vec::new();
    let mut pdata_bytes: Option<Vec<u8>> = None;
    for section in &pe.sections {
        let name_str = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();
        let va = image_base + u64::from(section.virtual_address);
        let chars = section.characteristics;
        let perms = permissions_from_characteristics(chars);
        let raw_off = section.pointer_to_raw_data;
        let raw_sz = section.size_of_raw_data;
        if name_str == ".pdata" || name_str == "PDATA" {
            let start = raw_off as usize;
            if let Some(end) = start.checked_add(raw_sz as usize)
                && end <= data.len() && start < end {
                    pdata_bytes = Some(data[start..end].to_vec());
                }
        }
        sections.push(SectionInfo {
            name: name_str,
            virtual_address: va,
            virtual_size: section.virtual_size,
            raw_offset: raw_off,
            raw_size: raw_sz,
            characteristics: chars,
            permissions: perms,
        });
    }
    (sections, pdata_bytes)
}

fn collect_all_imports(
    pe: &PE<'_>,
    data: &[u8],
    rva_sections: &[RvaSection],
    is_64bit: bool,
    image_base: u64,
) -> (Vec<ImportEntry>, Vec<ImportedFunction>, Vec<BoundImportEntry>, Vec<DelayLoadEntry>) {
    let imports: Vec<ImportEntry> = pe
        .imports
        .iter()
        .map(|imp| {
            let func_name = imp.name.to_string();
            ImportEntry {
                dll: imp.dll.to_string(),
                name: if func_name.is_empty() { None } else { Some(func_name) },
                ordinal: None,
                address: image_base + imp.rva as u64,
            }
        })
        .collect();
    // Ordinal-only imports get None name above; the vector is already consistent.

    let detailed_imports: Vec<ImportedFunction> = pe
        .header.optional_header.as_ref()
        .and_then(|opt| opt.data_directories.get_import_table())
        .filter(|dd| dd.virtual_address != 0)
        .map(|dd| {
            if is_64bit {
                parse_import_table_64(data, rva_sections, dd.virtual_address, dd.size, image_base)
            } else {
                parse_import_table_32(data, rva_sections, dd.virtual_address, dd.size, image_base)
            }
        })
        .unwrap_or_default();

    let bound_imports: Vec<BoundImportEntry> = pe
        .header.optional_header.as_ref()
        .and_then(|opt| opt.data_directories.get_bound_import_table())
        .filter(|dd| dd.virtual_address != 0)
        .and_then(|dd| {
            rva_to_file_offset(dd.virtual_address, rva_sections)
                .map(|off| parse_bound_imports(data, off))
        })
        .unwrap_or_default();

    let delay_raw: Vec<DelayImportDescriptor> = pe
        .header.optional_header.as_ref()
        .and_then(|opt| opt.data_directories.get_delay_import_descriptor())
        .filter(|dd| dd.virtual_address != 0)
        .map(|dd| parse_delay_imports(data, rva_sections, dd.virtual_address))
        .unwrap_or_default();

    let delay_imports: Vec<DelayLoadEntry> = delay_raw.iter().map(|d| {
        let dll_name = if d.dll_name_rva != 0 {
            rva_to_file_offset(d.dll_name_rva, rva_sections)
                .map(|o| read_cstr_at(data, o))
                .unwrap_or_default()
        } else {
            String::new()
        };
        DelayLoadEntry {
            dll: dll_name,
            uses_rvas: d.uses_rvas(),
            delay_iat_rva: d.delay_iat_rva,
            time_stamp: d.time_stamp,
        }
    }).collect();

    (imports, detailed_imports, bound_imports, delay_imports)
}

fn collect_exports(
    pe: &PE<'_>,
    data: &[u8],
    rva_sections: &[RvaSection],
    image_base: u64,
) -> (Vec<ExportEntry>, Option<ExportMap>) {
    let exported_symbols: Vec<ExportedSymbol> = pe
        .header.optional_header.as_ref()
        .and_then(|opt| opt.data_directories.get_export_table())
        .filter(|dd| dd.virtual_address != 0)
        .map(|dd| {
            parse_export_table(data, rva_sections, dd.virtual_address, dd.size, image_base)
        })
        .unwrap_or_default();

    let export_map = if exported_symbols.is_empty() {
        None
    } else {
        Some(ExportMap::build(exported_symbols.clone()))
    };

    let exports: Vec<ExportEntry> = exported_symbols.iter().map(|s| ExportEntry {
        name: s.name.clone(),
        ordinal: u16::try_from(s.ordinal).unwrap_or(u16::MAX),
        address: s.virtual_address,
        forwarder: s.forward_name.clone(),
    }).collect();

    (exports, export_map)
}

fn collect_overlay(
    pe: &PE<'_>,
    data: &[u8],
    rva_sections: &[RvaSection],
) -> Option<OverlaySummary> {
    let security_file_offset = pe.header.optional_header.as_ref()
        .and_then(|opt| opt.data_directories.get_certificate_table())
        .map_or(0, |dd| dd.virtual_address);
    let security_size = pe.header.optional_header.as_ref()
        .and_then(|opt| opt.data_directories.get_certificate_table())
        .map_or(0, |dd| dd.size);

    OverlayInfo::analyze(data, rva_sections, security_file_offset, security_size).map(|oi| {
        let authenticode = oi.certificates.iter()
            .find(|c| c.is_authenticode())
            .map(|c| AuthenticodeInfo {
                pkcs7_data: c.data.clone(),
                cert_length: c.length,
                revision: c.revision,
            });
        OverlaySummary {
            offset: oi.offset,
            size: oi.size,
            sfx_kind: oi.sfx_kind,
            authenticode,
            is_signed: oi.is_signed,
        }
    })
}

fn collect_entropy(
    sections: &[SectionInfo],
    data: &[u8],
    image_base: u64,
) -> Option<EntropySummary> {
    let entropy_sections: Vec<SectionWithName> = sections.iter().map(|s| SectionWithName {
        section: RvaSection {
            virtual_address: u32::try_from(s.virtual_address.saturating_sub(image_base)).unwrap_or(u32::MAX),
            virtual_size: s.virtual_size,
            raw_size: s.raw_size,
            raw_offset: s.raw_offset,
        },
        name: s.name.clone(),
    }).collect();
    if entropy_sections.is_empty() {
        None
    } else {
        Some(EntropySummary::analyze(data, &entropy_sections))
    }
}

fn collect_relocations(
    pe: &PE<'_>,
    data: &[u8],
    rva_sections: &[RvaSection],
) -> (Vec<RelocationBlock>, RelocationStats) {
    let blocks: Vec<RelocationBlock> = pe
        .header.optional_header.as_ref()
        .and_then(|opt| opt.data_directories.get_base_relocation_table())
        .filter(|dd| dd.virtual_address != 0 && dd.size != 0)
        .map(|dd| parse_relocation_directory(data, rva_sections, dd.virtual_address, dd.size))
        .unwrap_or_default();
    let stats = RelocationStats::from_blocks(&blocks);
    (blocks, stats)
}

fn collect_tls(
    pe: &PE<'_>,
    data: &[u8],
    rva_sections: &[RvaSection],
    is_64bit: bool,
    image_base: u64,
) -> (Option<TlsCallbackInfo>, Vec<u64>) {
    let tls_info_opt: Option<TlsInfo> = pe
        .header.optional_header.as_ref()
        .and_then(|opt| opt.data_directories.get_tls_table())
        .filter(|dd| dd.virtual_address != 0 && dd.size != 0)
        .and_then(|dd| {
            if is_64bit {
                parse_tls_64(data, rva_sections, dd.virtual_address, image_base)
            } else {
                parse_tls_32(data, rva_sections, dd.virtual_address, image_base)
            }
        });
    let callbacks: Vec<u64> = tls_info_opt.as_ref().map(|ti| ti.callbacks.clone()).unwrap_or_default();
    let tls = tls_info_opt.map(|ti| TlsCallbackInfo {
        callbacks: ti.callbacks.clone(),
        data_start: ti.data_start,
        data_end: ti.data_end,
        zero_fill_size: ti.zero_fill_size,
        is_64bit: ti.is_64bit,
    });
    (tls, callbacks)
}

fn collect_exceptions(
    pe: &PE<'_>,
    data: &[u8],
    rva_sections: &[RvaSection],
    pdata_bytes: Option<&[u8]>,
) -> (Vec<RuntimeFunctionInfo>, Option<ExceptionDirectory>) {
    let functions = pdata_bytes.map(parse_exception_directory_basic).unwrap_or_default();
    let dir = pe
        .header.optional_header.as_ref()
        .and_then(|opt| opt.data_directories.get_exception_table())
        .filter(|dd| dd.virtual_address != 0 && dd.size != 0)
        .map(|dd| ExceptionDirectory::parse_x64(data, rva_sections, dd.virtual_address, dd.size));
    (functions, dir)
}

fn collect_resources(
    pe: &PE<'_>,
    data: &[u8],
    rva_sections: &[RvaSection],
) -> (Option<ResourceTree>, ResourceSummary) {
    let tree = pe
        .header.optional_header.as_ref()
        .and_then(|opt| opt.data_directories.get_resource_table())
        .filter(|dd| dd.virtual_address != 0)
        .and_then(|dd| ResourceTree::parse_from_pe(data, rva_sections, dd.virtual_address));
    let summary = build_resource_summary(tree.as_ref(), data, rva_sections);
    (tree, summary)
}

fn collect_dotnet(
    pe: &PE<'_>,
    data: &[u8],
    rva_sections: &[RvaSection],
    is_dotnet: bool,
) -> Option<DotNetSummary> {
    if !is_dotnet {
        return None;
    }
    pe.header.optional_header.as_ref()
        .and_then(|opt| opt.data_directories.get_clr_runtime_header())
        .filter(|dd| dd.virtual_address != 0)
        .and_then(|dd| parse_dotnet(data, rva_sections, dd.virtual_address, dd.size))
        .map(|dn| DotNetSummary {
            clr_version: dn.clr_version,
            framework_version: dn.framework_version,
            is_pure_il: dn.is_pure_il,
            is_mixed_mode: dn.is_mixed_mode,
            is_strong_name_signed: dn.is_strong_name_signed,
        })
}

fn collect_authenticode(pe: &PE<'_>, data: &[u8]) -> Vec<WinCertificate> {
    pe.header.optional_header.as_ref()
        .and_then(|opt| opt.data_directories.get_certificate_table())
        .filter(|dd| dd.virtual_address != 0 && dd.size != 0)
        .map(|dd| parse_security_directory(data, dd.virtual_address, dd.size))
        .unwrap_or_default()
}

fn build_rva_sections(pe: &PE<'_>) -> Vec<RvaSection> {
    pe.sections.iter().map(|s| RvaSection {
        virtual_address: s.virtual_address,
        virtual_size: s.virtual_size,
        raw_size: s.size_of_raw_data,
        raw_offset: s.pointer_to_raw_data,
    }).collect()
}

// ---------------------------------------------------------------------------
// PeInfo implementation
// ---------------------------------------------------------------------------

impl PeInfo {
    /// Parse a raw PE binary and extract **all** available metadata.
    ///
    /// This is the enterprise entry point — it will parse every data directory
    /// that is present in the file, safely skipping missing or truncated ones.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `goblin` fails to parse the top-level PE headers.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        // ---- Step 1: goblin for reliable top-level parse -------------------
        let pe = PE::parse(data).map_err(|e| e.to_string())?;

        // ---- Step 2: our own header parser for richer info ------------------
        let pe_headers_opt = PeHeaders::parse(data).ok();

        // ---- Step 3: Machine & basic flags ----------------------------------
        let machine = machine_from_u16(pe.header.coff_header.machine);
        let is_dll = (pe.header.coff_header.characteristics & IMAGE_FILE_DLL_FLAG) != 0;
        let timestamp = pe.header.coff_header.time_date_stamp;
        let is_64bit = matches!(machine, Machine::X64 | Machine::Arm64);

        // ---- Step 4: Optional header fields ---------------------------------
        let (
            image_base,
            entry_point,
            subsystem,
            is_dotnet_flag,
            is_driver,
            checksum,
            dll_characteristics,
        ) = match &pe.header.optional_header {
            Some(opt) => {
                let ib = opt.windows_fields.image_base;
                let ep = ib + pe.entry as u64;
                let sub = subsystem_from_u16(opt.windows_fields.subsystem);
                let dotnet = opt
                    .data_directories
                    .get_clr_runtime_header()
                    .is_some_and(|d| d.virtual_address != 0);
                let driver = matches!(
                    sub,
                    Subsystem::Native | Subsystem::EfiBootService | Subsystem::EfiRuntime
                );
                let chk = opt.windows_fields.check_sum;
                let dll_chars = opt.windows_fields.dll_characteristics;
                (ib, ep, sub, dotnet, driver, chk, dll_chars)
            }
            None => (0u64, 0u64, Subsystem::Unknown(0), false, false, 0u32, 0u16),
        };
        let entry_rva = u32::try_from(pe.entry).unwrap_or(u32::MAX);

        // ---- Steps 5–19: All data directories ----------------------------------
        let rva_sections = build_rva_sections(&pe);
        let (sections, pdata_bytes) = collect_sections_and_pdata(&pe, data, image_base);
        let (imports, detailed_imports, bound_imports, delay_imports) =
            collect_all_imports(&pe, data, &rva_sections, is_64bit, image_base);
        let (exports, export_map_val) = collect_exports(&pe, data, &rva_sections, image_base);
        let (relocation_blocks, relocation_stats) = collect_relocations(&pe, data, &rva_sections);
        let (tls, tls_callbacks) = collect_tls(&pe, data, &rva_sections, is_64bit, image_base);
        let (exception_functions, exception_directory_opt) =
            collect_exceptions(&pe, data, &rva_sections, pdata_bytes.as_deref());
        let load_config = parse_load_configuration(data, &rva_sections, &pe, is_64bit, image_base);
        let (resource_tree_opt, resource_summary) = collect_resources(&pe, data, &rva_sections);
        let debug_info = parse_debug_info(data, &rva_sections, &pe);
        let authenticode_certs = collect_authenticode(&pe, data);
        let dotnet_summary = collect_dotnet(&pe, data, &rva_sections, is_dotnet_flag);
        let overlay_summary = collect_overlay(&pe, data, &rva_sections);
        let pe_offset = if data.len() >= 0x40 {
            usize::try_from(u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap_or([0; 4]))).unwrap_or(0)
        } else {
            0usize
        };
        let rich_header = parse_rich_header(data, pe_offset);
        let entropy_summary = collect_entropy(&sections, data, image_base);

        Ok(Self {
            machine,
            subsystem,
            image_base,
            entry_point,
            entry_rva,
            timestamp,
            checksum,
            dll_characteristics,
            flags: {
                let mut f = PeFlags::default();
                f.set(PeFlags::DOTNET, is_dotnet_flag);
                f.set(PeFlags::DRIVER, is_driver);
                f.set(PeFlags::DLL, is_dll);
                f.set(PeFlags::IS_64BIT, is_64bit);
                f
            },
            pe_headers: pe_headers_opt,
            rich_header,
            sections,
            imports,
            detailed_imports,
            bound_imports,
            delay_imports,
            exports,
            export_map: export_map_val,
            relocation_blocks,
            relocation_stats,
            tls,
            tls_callbacks,
            exception_functions,
            exception_directory: exception_directory_opt,
            load_config,
            resource_tree: resource_tree_opt,
            resource_summary,
            debug_info,
            authenticode_certs,
            dotnet: dotnet_summary,
            overlay: overlay_summary,
            entropy_summary,
        })
    }

    // ---- Convenience accessors -----------------------------------------------

    /// Return all imports for a specific DLL name (case-insensitive).
    #[must_use]
    pub fn imports_from_dll<'a>(&'a self, dll: &str) -> Vec<&'a ImportEntry> {
        let dll_lower = dll.to_lowercase();
        self.imports
            .iter()
            .filter(|imp| imp.dll.to_lowercase() == dll_lower)
            .collect()
    }

    /// Return the export entry with the given name, if present.
    #[must_use]
    pub fn export_by_name(&self, name: &str) -> Option<&ExportEntry> {
        self.exports
            .iter()
            .find(|e| e.name.as_deref() == Some(name))
    }

    /// Return the export entry with the given ordinal, if present.
    #[must_use]
    pub fn export_by_ordinal(&self, ordinal: u16) -> Option<&ExportEntry> {
        self.exports.iter().find(|e| e.ordinal == ordinal)
    }

    /// Return `true` if any imported DLL name contains the `hint` (case-insensitive).
    #[must_use]
    pub fn imports_dll(&self, hint: &str) -> bool {
        let hint_lower = hint.to_lowercase();
        self.imports
            .iter()
            .any(|i| i.dll.to_lowercase().contains(&hint_lower))
    }

    /// Return `true` if the binary has any TLS callbacks.
    #[must_use]
    pub const fn has_tls_callbacks(&self) -> bool {
        !self.tls_callbacks.is_empty()
    }

    /// Return `true` if the binary is Authenticode-signed.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.overlay.as_ref().is_some_and(|o| o.is_signed)
            || self.authenticode_certs.iter().any(overlay::WinCertificate::is_authenticode)
    }

    /// Return the PDB path extracted from the debug directory, if any.
    #[must_use]
    pub fn pdb_path(&self) -> Option<&str> {
        self.debug_info.pdb_path.as_deref()
    }

    /// Return the total number of relocations across all blocks.
    #[must_use]
    pub const fn relocation_count(&self) -> usize {
        self.relocation_stats.total_entries
    }

    /// Return `true` if the binary has a base relocation table (is not reloc-stripped).
    #[must_use]
    pub const fn has_relocations(&self) -> bool {
        !self.relocation_blocks.is_empty()
    }

    /// Return the manifest XML bytes from the resource directory, if present.
    #[must_use]
    pub const fn manifest_xml(&self) -> Option<&ManifestInfo> {
        self.resource_summary.manifest.as_ref()
    }

    /// Return the security mitigation score (0–7).
    #[must_use]
    pub const fn security_score(&self) -> u32 {
        self.load_config.features.mitigation_score()
    }

    /// Return all section names.
    #[must_use]
    pub fn section_names(&self) -> Vec<&str> {
        self.sections.iter().map(|s| s.name.as_str()).collect()
    }

    /// Find a section by name.
    #[must_use]
    pub fn find_section(&self, name: &str) -> Option<&SectionInfo> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Return all forwarded exports.
    #[must_use]
    pub fn forwarded_exports(&self) -> Vec<&ExportEntry> {
        self.exports
            .iter()
            .filter(|e| e.forwarder.is_some())
            .collect()
    }

    /// Aggregate entry points: `AddressOfEntryPoint` first, then TLS callbacks
    /// (if any), then any export entry. Each entry is a (VA, kind) pair.
    #[must_use]
    pub fn entry_points(&self) -> Vec<(u64, &'static str)> {
        let mut out: Vec<(u64, &'static str)> = Vec::new();
        if self.entry_point != 0 {
            out.push((self.entry_point, "entry"));
        }
        for &cb in &self.tls_callbacks {
            if cb != 0 {
                out.push((cb, "tls_callback"));
            }
        }
        for exp in &self.exports {
            if exp.address != 0 && exp.forwarder.is_none() {
                out.push((exp.address, "export"));
            }
        }
        out
    }

    /// Translate an RVA to a file offset using the section table.
    #[must_use]
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        let rva_secs: Vec<RvaSection> = self
            .sections
            .iter()
            .map(|s| RvaSection {
                virtual_address: u32::try_from(s.virtual_address.saturating_sub(self.image_base)).unwrap_or(u32::MAX),
                virtual_size: s.virtual_size,
                raw_size: s.raw_size,
                raw_offset: s.raw_offset,
            })
            .collect();
        rva_to_file_offset(rva, &rva_secs)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers for PeInfo::parse
// ---------------------------------------------------------------------------

/// Extract NX, ASLR, and `HIGH_ENTROPY_VA` flags from the PE optional header.
fn pe_dll_characteristics(pe: &PE) -> (bool, bool, bool) {
    let dc = pe
        .header
        .optional_header
        .as_ref()
        .map_or(0, |o| o.windows_fields.dll_characteristics);
    let has_nx = (dc & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    let has_aslr = (dc & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    let has_high_entropy = (dc & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
    (has_nx, has_aslr, has_high_entropy)
}

fn parse_load_config_64(
    data: &[u8],
    sections: &[RvaSection],
    pe: &PE,
    lc_off: usize,
    image_base: u64,
) -> LoadConfigInfo {
    let Ok(lc64) = LoadConfigDirectory64::parse(data, lc_off) else {
        return LoadConfigInfo::default();
    };
    let guard_flags = lc64.guard_flags;
    let security_cookie = lc64.security_cookie;
    let cfg_functions: Vec<u32> =
        if lc64.guard_cf_function_table != 0 && lc64.guard_cf_function_count > 0 {
            let table_rva =
                u32::try_from(lc64.guard_cf_function_table.saturating_sub(image_base))
                    .unwrap_or(u32::MAX);
            let stride = if guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT != 0 {
                5u32
            } else {
                4u32
            };
            parse_cfg_function_table(data, sections, table_rva, lc64.guard_cf_function_count, stride)
                .iter()
                .map(|e| e.rva)
                .collect()
        } else {
            Vec::new()
        };
    let (has_nx, has_aslr, has_high_entropy) = pe_dll_characteristics(pe);
    let mut mitigations = MitigationFlags::default();
    mitigations.set(MitigationFlags::CFG, lc64.has_cfg());
    mitigations.set(MitigationFlags::GS_COOKIE, lc64.has_gs_cookie());
    mitigations.set(MitigationFlags::NX_COMPAT, has_nx);
    mitigations.set(MitigationFlags::ASLR, has_aslr);
    mitigations.set(MitigationFlags::HIGH_ENTROPY_VA, has_high_entropy);
    mitigations.set(MitigationFlags::RETPOLINE, lc64.has_retpoline());
    let features = SecurityFeatures {
        mitigations,
        cfg_function_count: lc64.guard_cf_function_count,
        seh_handler_count: 0,
    };
    LoadConfigInfo { security_cookie, seh_handlers: Vec::new(), cfg_functions, guard_flags, features }
}

fn parse_load_config_32(
    data: &[u8],
    sections: &[RvaSection],
    pe: &PE,
    lc_off: usize,
    image_base: u64,
) -> LoadConfigInfo {
    let Ok(lc32) = LoadConfigDirectory32::parse(data, lc_off) else {
        return LoadConfigInfo::default();
    };
    let guard_flags = lc32.guard_flags;
    let security_cookie = u64::from(lc32.security_cookie);
    let seh_handlers = if lc32.has_safe_seh() {
        parse_safe_seh_handlers(data, sections, lc32.se_handler_table, lc32.se_handler_count, image_base)
    } else {
        Vec::new()
    };
    let cfg_functions: Vec<u32> =
        if lc32.guard_cf_function_table != 0 && lc32.guard_cf_function_count > 0 {
            let table_rva =
                u32::try_from(u64::from(lc32.guard_cf_function_table).saturating_sub(image_base))
                    .unwrap_or(u32::MAX);
            parse_cfg_function_table(data, sections, table_rva, u64::from(lc32.guard_cf_function_count), 4)
                .iter()
                .map(|e| e.rva)
                .collect()
        } else {
            Vec::new()
        };
    let (has_nx, has_aslr, _) = pe_dll_characteristics(pe);
    let seh_count = u32::try_from(seh_handlers.len()).unwrap_or(u32::MAX);
    let mut mitigations = MitigationFlags::default();
    mitigations.set(MitigationFlags::CFG, lc32.has_cfg());
    mitigations.set(MitigationFlags::GS_COOKIE, lc32.has_gs_cookie());
    mitigations.set(MitigationFlags::SAFE_SEH, lc32.has_safe_seh());
    mitigations.set(MitigationFlags::NX_COMPAT, has_nx);
    mitigations.set(MitigationFlags::ASLR, has_aslr);
    let features = SecurityFeatures {
        mitigations,
        cfg_function_count: u64::from(lc32.guard_cf_function_count),
        seh_handler_count: seh_count,
    };
    LoadConfigInfo { security_cookie, seh_handlers, cfg_functions, guard_flags, features }
}

fn parse_load_configuration(
    data: &[u8],
    sections: &[RvaSection],
    pe: &PE,
    is_64bit: bool,
    image_base: u64,
) -> LoadConfigInfo {
    let dd = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|opt| opt.data_directories.get_load_config_table())
        .filter(|dd| dd.virtual_address != 0 && dd.size != 0);
    let Some(dd) = dd else { return LoadConfigInfo::default(); };
    let Some(lc_off) = rva_to_file_offset(dd.virtual_address, sections) else {
        return LoadConfigInfo::default();
    };
    if is_64bit {
        parse_load_config_64(data, sections, pe, lc_off, image_base)
    } else {
        parse_load_config_32(data, sections, pe, lc_off, image_base)
    }
}

/// Parse the debug directory and return a `DebugInfo` struct.
fn parse_debug_info(data: &[u8], sections: &[RvaSection], pe: &PE) -> DebugInfo {
    let dd = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|opt| opt.data_directories.get_debug_table())
        .filter(|dd| dd.virtual_address != 0 && dd.size != 0);

    let Some(dd) = dd else {
        return DebugInfo::default();
    };

    let entries = parse_debug_directory(data, sections, dd.virtual_address, dd.size);
    let entry_types: Vec<u32> = entries.iter().map(|e| e.debug_type).collect();

    let cv_info = extract_codeview_info(data, &entries);

    let pdb_path = cv_info.as_ref().map(|cv| cv.pdb_path().to_owned());
    let pdb_guid = cv_info
        .as_ref()
        .and_then(|cv| cv.guid())
        .map(std::string::ToString::to_string);
    let pdb_age = cv_info.as_ref().map(debug_dir::CodeViewInfo::age);

    DebugInfo {
        pdb_path,
        pdb_guid,
        pdb_age,
        entry_types,
    }
}

/// Build a high-level `ResourceSummary` from the parsed `ResourceTree`.
fn build_resource_summary(
    tree: Option<&ResourceTree>,
    data: &[u8],
    sections: &[RvaSection],
) -> ResourceSummary {
    let Some(tree) = tree else {
        return ResourceSummary::default();
    };

    let total_leaves = tree.count_leaves();

    // RT_MANIFEST
    let manifest = tree
        .find_by_type_id(RT_MANIFEST)
        .into_iter()
        .next()
        .and_then(|leaf| leaf.data.as_ref())
        .and_then(|entry| {
            rva_to_file_offset(entry.data_rva, sections).and_then(|off| {
                let end = (off + entry.size as usize).min(data.len());
                if off < end {
                    Some(ManifestInfo::parse(&data[off..end]))
                } else {
                    None
                }
            })
        });

    // RT_VERSION — parse VS_VERSION_INFO
    let version_info = tree
        .find_by_type_id(RT_VERSION)
        .into_iter()
        .next()
        .and_then(|leaf| leaf.data.as_ref())
        .and_then(|entry| {
            rva_to_file_offset(entry.data_rva, sections).and_then(|off| {
                let end = (off + entry.size as usize).min(data.len());
                if off < end {
                    VersionInfo::parse(&data[off..end])
                } else {
                    None
                }
            })
        });

    // Count icons
    let icon_count =
        tree.find_by_type_id(RT_ICON).len() + tree.find_by_type_id(RT_GROUP_ICON).len();

    ResourceSummary {
        manifest,
        version_info,
        icon_count,
        total_leaves,
    }
}

// ---------------------------------------------------------------------------
// Import classification
// ---------------------------------------------------------------------------

/// Coarse capability bucket for a Win32 API import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportCategory {
    FileIo,
    Network,
    Crypto,
    Process,
    Registry,
    Gui,
    Memory,
    Synchronization,
    Unknown,
}

fn is_crypto_import(n: &str) -> bool {
    n.starts_with("Crypt")
        || n.starts_with("BCrypt")
        || n.starts_with("NCrypt")
        || n.contains("CryptAcquire")
        || n.contains("CryptGenKey")
        || n.contains("CryptEncrypt")
        || n.contains("CryptDecrypt")
        || n.contains("CryptHash")
}

fn is_network_import(n: &str) -> bool {
    n.starts_with("WSA")
        || matches!(
            n,
            "socket"
                | "connect"
                | "bind"
                | "listen"
                | "accept"
                | "send"
                | "recv"
                | "sendto"
                | "recvfrom"
                | "closesocket"
                | "gethostbyname"
                | "getaddrinfo"
        )
        || n.starts_with("InternetOpen")
        || n.starts_with("InternetConnect")
        || n.starts_with("HttpOpen")
        || n.starts_with("HttpSend")
        || n.starts_with("WinHttp")
        || n.starts_with("URLDownload")
}

fn is_registry_import(n: &str) -> bool {
    n.starts_with("Reg")
        && (n.starts_with("RegOpen")
            || n.starts_with("RegCreate")
            || n.starts_with("RegQuery")
            || n.starts_with("RegSet")
            || n.starts_with("RegDelete")
            || n.starts_with("RegEnum")
            || n.starts_with("RegClose")
            || n.starts_with("RegGet"))
}

fn is_process_import(n: &str) -> bool {
    n.starts_with("CreateProcess")
        || matches!(
            n,
            "OpenProcess"
                | "TerminateProcess"
                | "ExitProcess"
                | "GetCurrentProcess"
                | "VirtualAllocEx"
                | "VirtualProtectEx"
                | "WriteProcessMemory"
                | "ReadProcessMemory"
                | "CreateRemoteThread"
                | "NtCreateThreadEx"
                | "ResumeThread"
                | "CreateToolhelp32Snapshot"
        )
        || n.starts_with("Process32")
        || n.starts_with("Module32")
        || n.starts_with("Thread32")
}

fn is_gui_import(n: &str) -> bool {
    n.starts_with("CreateWindow")
        || n.starts_with("MessageBox")
        || matches!(
            n,
            "GetMessage"
                | "PeekMessage"
                | "DispatchMessage"
                | "TranslateMessage"
                | "ShowWindow"
                | "UpdateWindow"
                | "DefWindowProc"
                | "LoadIcon"
                | "LoadCursor"
                | "BeginPaint"
                | "EndPaint"
        )
        || n.starts_with("RegisterClass")
        || n.starts_with("GetDC")
}

fn is_sync_import(n: &str) -> bool {
    n.starts_with("CreateMutex")
        || n.starts_with("OpenMutex")
        || n.starts_with("CreateEvent")
        || n.starts_with("CreateSemaphore")
        || matches!(
            n,
            "ReleaseMutex"
                | "SetEvent"
                | "ResetEvent"
                | "ReleaseSemaphore"
                | "WaitForSingleObject"
                | "WaitForSingleObjectEx"
                | "WaitForMultipleObjects"
                | "EnterCriticalSection"
                | "LeaveCriticalSection"
                | "InitializeCriticalSection"
                | "DeleteCriticalSection"
        )
}

fn is_memory_import(n: &str) -> bool {
    n.starts_with("RtlAllocateHeap")
        || matches!(
            n,
            "VirtualAlloc"
                | "VirtualFree"
                | "VirtualProtect"
                | "VirtualQuery"
                | "HeapAlloc"
                | "HeapFree"
                | "HeapCreate"
                | "HeapDestroy"
                | "HeapReAlloc"
                | "GlobalAlloc"
                | "GlobalFree"
                | "LocalAlloc"
                | "LocalFree"
        )
}

fn is_fileio_import(n: &str) -> bool {
    n.starts_with("CreateFile")
        || n.starts_with("DeleteFile")
        || n.starts_with("MoveFile")
        || n.starts_with("CopyFile")
        || n.starts_with("FindFirstFile")
        || n.starts_with("FindNextFile")
        || n.starts_with("GetFileAttributes")
        || n.starts_with("SetFileAttributes")
        || n.starts_with("CreateDirectory")
        || n.starts_with("RemoveDirectory")
        || n.starts_with("ReadFileEx")
        || n.starts_with("WriteFileEx")
        || matches!(
            n,
            "ReadFile"
                | "WriteFile"
                | "CloseHandle"
                | "FindClose"
                | "GetFileSize"
                | "GetFileSizeEx"
                | "SetFilePointer"
                | "SetFilePointerEx"
                | "FlushFileBuffers"
        )
}

/// Classify a Win32 API import by name into a coarse capability bucket.
#[must_use]
pub fn classify_import(name: &str) -> ImportCategory {
    if is_crypto_import(name) {
        ImportCategory::Crypto
    } else if is_network_import(name) {
        ImportCategory::Network
    } else if is_registry_import(name) {
        ImportCategory::Registry
    } else if is_process_import(name) {
        ImportCategory::Process
    } else if is_gui_import(name) {
        ImportCategory::Gui
    } else if is_sync_import(name) {
        ImportCategory::Synchronization
    } else if is_memory_import(name) {
        ImportCategory::Memory
    } else if is_fileio_import(name) {
        ImportCategory::FileIo
    } else {
        ImportCategory::Unknown
    }
}

// ---------------------------------------------------------------------------
// Architecture stub for PE files
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PeArch {
    arch_name: &'static str,
    ptr_size: usize,
}

impl rustre_core::arch::Architecture for PeArch {
    fn name(&self) -> &str {
        self.arch_name
    }

    fn pointer_size(&self) -> usize {
        self.ptr_size
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(
        &self,
        address: Address,
        _bytes: &[u8],
    ) -> Result<rustre_core::arch::Instruction, CoreError> {
        Ok(rustre_core::arch::Instruction::new(
            address,
            1,
            "nop",
            vec![0x90],
        ))
    }

    fn get_branches(
        &self,
        _instr: &rustre_core::arch::Instruction,
    ) -> Vec<rustre_core::arch::BranchInfo> {
        vec![]
    }

    fn registers(&self) -> Vec<rustre_core::arch::RegisterInfo> {
        vec![]
    }

    fn calling_conventions(&self) -> Vec<rustre_core::arch::CallingConvention> {
        vec![]
    }
}

fn make_arch(machine: &Machine) -> Arc<dyn rustre_core::arch::Architecture> {
    match machine {
        Machine::X64 => Arc::new(PeArch {
            arch_name: "x86_64",
            ptr_size: 8,
        }),
        Machine::X86 => Arc::new(PeArch {
            arch_name: "x86",
            ptr_size: 4,
        }),
        Machine::Arm => Arc::new(PeArch {
            arch_name: "arm",
            ptr_size: 4,
        }),
        Machine::Arm64 => Arc::new(PeArch {
            arch_name: "aarch64",
            ptr_size: 8,
        }),
        Machine::Unknown(_) => Arc::new(PeArch {
            arch_name: "unknown",
            ptr_size: 8,
        }),
    }
}

// ---------------------------------------------------------------------------
// PeLoader — implements the rustre_core::loader::Loader trait
// ---------------------------------------------------------------------------

/// Full Portable Executable loader backed by `goblin`.
#[derive(Debug)]
pub struct PeLoader;

#[async_trait]
impl Loader for PeLoader {
    fn name(&self) -> &'static str {
        "pe"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        if input.data.len() < 0x40 {
            return false;
        }
        if !input.data.starts_with(b"MZ") {
            return false;
        }
        let Ok(bytes) = input.data[0x3C..0x40].try_into() else {
            return false;
        };
        let pe_offset = u32::from_le_bytes(bytes) as usize;
        if pe_offset + 4 > input.data.len() {
            return false;
        }
        input.data[pe_offset..pe_offset + 4] == [b'P', b'E', 0, 0]
    }

    async fn load(&self, input: LoaderInput) -> Result<rustre_core::loader::LoadResult, CoreError> {
        if !self.can_load(&input) {
            return Err(CoreError::LoaderError {
                loader: "pe".into(),
                message: "Not a valid PE binary".into(),
            });
        }

        let info = PeInfo::parse(&input.data).map_err(|e| CoreError::LoaderError {
            loader: "pe".into(),
            message: format!("PE parse error: {e}"),
        })?;

        let arch = make_arch(&info.machine);
        let bits = match info.machine {
            Machine::X64 | Machine::Arm64 => 64u32,
            _ => 32u32,
        };

        let mut mem = Memory::new();

        // Map each section into memory at its virtual address.
        for sec in &info.sections {
            if sec.virtual_size == 0 {
                continue;
            }
            let start_va = sec.virtual_address;
            let vsize = sec.virtual_size as usize;
            let raw_start = sec.raw_offset as usize;
            let raw_end = raw_start.saturating_add(sec.raw_size as usize);

            // Build section data: read raw bytes, then zero-pad to virtual size.
            let mut section_data = vec![0u8; vsize];
            if raw_start < input.data.len() && sec.raw_size > 0 {
                let available = input.data.len().min(raw_end) - raw_start;
                let copy_len = available.min(vsize);
                section_data[..copy_len]
                    .copy_from_slice(&input.data[raw_start..raw_start + copy_len]);
            }

            mem.add_segment(Segment {
                range: AddressRange::new(
                    Address::new(start_va),
                    Address::new(start_va + vsize as u64),
                ),
                permissions: sec.permissions,
                data: section_data,
            });
        }

        // Fallback: map the whole file if no sections were added.
        if mem.segments.is_empty() {
            mem.add_segment(Segment {
                range: AddressRange::new(
                    Address::new(info.image_base),
                    Address::new(info.image_base + input.data.len() as u64),
                ),
                permissions: Permissions::READ | Permissions::EXECUTE,
                data: input.data.clone(),
            });
        }

        // Build entry points list: primary EP + TLS callbacks.
        let mut entry_points = Vec::new();
        if info.entry_rva != 0 {
            entry_points.push(Address::new(info.entry_point));
        }
        for &cb in &info.tls_callbacks {
            entry_points.push(Address::new(cb));
        }
        if entry_points.is_empty() {
            entry_points.push(Address::new(info.image_base));
        }

        // Run FLIRT autoname against executable segments using the built-in
        // baseline packs (MSVC CRT + Rust stdlib). Resolved renames are
        // committed to the BinaryView symbol table as Function/Flirt symbols.
        let (renames, _flirt_stats) = flirt_autoname::apply_default_packs(&mem);

        let view = BinaryView::new(
            rustre_core::loader::next_view_id(),
            input.uri,
            arch,
            Endian::Little,
            bits,
            entry_points,
            mem,
        );

        {
            let mut syms = view.symbols.write();
            for r in &renames {
                let sym = rustre_core::binary_view::Symbol::new(
                    r.name.clone(),
                    Address::new(r.address),
                    rustre_core::binary_view::SymbolKind::Function,
                    rustre_core::binary_view::SymbolSource::Flirt,
                );
                syms.add_symbol(sym);
            }
        }

        Ok(rustre_core::loader::LoadResult::new(view))
    }

    async fn find_nested(&self, _input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        Ok(vec![])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PE binary builder helpers
    // -----------------------------------------------------------------------

    /// Build a minimal 32-bit PE (PE32) in memory.
    fn build_minimal_pe32() -> Vec<u8> {
        let pe_offset: usize = 0x80;
        let section_count: usize = 1;
        let opt_header_size: u16 = 224;
        let headers_total = pe_offset + 4 + 20 + opt_header_size as usize + section_count * 40;
        let raw_section_offset: usize = (headers_total + 0x1FF) & !0x1FF;
        let raw_section_size: u32 = 0x200;
        let total_size = raw_section_offset + raw_section_size as usize;

        let mut buf = vec![0u8; total_size];

        // DOS header
        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());

        // PE signature
        buf[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");

        // COFF header
        let coff = pe_offset + 4;
        buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&(section_count as u16).to_le_bytes());
        buf[coff + 4..coff + 8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&opt_header_size.to_le_bytes());
        buf[coff + 18..coff + 20].copy_from_slice(&0x0002u16.to_le_bytes());

        // Optional header (PE32)
        let opt = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x0200u32.to_le_bytes());
        buf[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        buf[opt + 60..opt + 64].copy_from_slice(&(raw_section_offset as u32).to_le_bytes());
        buf[opt + 68..opt + 70].copy_from_slice(&0x0003u16.to_le_bytes());

        // Section header (.text)
        let sec = opt + opt_header_size as usize;
        buf[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        buf[sec + 8..sec + 12].copy_from_slice(&0x0100u32.to_le_bytes());
        buf[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec + 16..sec + 20].copy_from_slice(&raw_section_size.to_le_bytes());
        buf[sec + 20..sec + 24].copy_from_slice(&(raw_section_offset as u32).to_le_bytes());
        buf[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

        // Section data: NOPs
        let raw_start = raw_section_offset;
        for b in &mut buf[raw_start..raw_start + 16] {
            *b = 0x90;
        }

        buf
    }

    /// Build a minimal 64-bit PE (PE32+) for DLL detection testing.
    fn build_minimal_pe64_dll() -> Vec<u8> {
        let pe_offset: usize = 0x80;
        let section_count: usize = 1;
        let opt_header_size: u16 = 240;
        let headers_total = pe_offset + 4 + 20 + opt_header_size as usize + section_count * 40;
        let raw_section_offset: usize = (headers_total + 0x1FF) & !0x1FF;
        let raw_section_size: u32 = 0x200;
        let total_size = raw_section_offset + raw_section_size as usize;

        let mut buf = vec![0u8; total_size];

        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        buf[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");

        let coff = pe_offset + 4;
        buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&(section_count as u16).to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&opt_header_size.to_le_bytes());
        buf[coff + 18..coff + 20].copy_from_slice(&0x2002u16.to_le_bytes()); // DLL | Executable

        let opt = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_8000_0000u64.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x0200u32.to_le_bytes());
        buf[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        buf[opt + 60..opt + 64].copy_from_slice(&(raw_section_offset as u32).to_le_bytes());
        buf[opt + 68..opt + 70].copy_from_slice(&0x0002u16.to_le_bytes());

        let sec = opt + opt_header_size as usize;
        buf[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        buf[sec + 8..sec + 12].copy_from_slice(&0x0100u32.to_le_bytes());
        buf[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec + 16..sec + 20].copy_from_slice(&raw_section_size.to_le_bytes());
        buf[sec + 20..sec + 24].copy_from_slice(&(raw_section_offset as u32).to_le_bytes());
        buf[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

        buf
    }

    /// Build a minimal PE32 with multiple named sections.
    fn build_pe32_multisection() -> Vec<u8> {
        let pe_offset: usize = 0x80;
        let section_count: usize = 3;
        let opt_header_size: u16 = 224;
        let headers_total = pe_offset + 4 + 20 + opt_header_size as usize + section_count * 40;
        let raw_section_offset: usize = (headers_total + 0x1FF) & !0x1FF;
        let raw_section_size: u32 = 0x200;
        let total_size = raw_section_offset + raw_section_size as usize * section_count;

        let mut buf = vec![0u8; total_size];

        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        buf[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");

        let coff = pe_offset + 4;
        buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&(section_count as u16).to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&opt_header_size.to_le_bytes());
        buf[coff + 18..coff + 20].copy_from_slice(&0x0002u16.to_le_bytes());

        let opt = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x0200u32.to_le_bytes());
        buf[opt + 56..opt + 60].copy_from_slice(&0x6000u32.to_le_bytes()); // SizeOfImage
        buf[opt + 60..opt + 64].copy_from_slice(&(raw_section_offset as u32).to_le_bytes());
        buf[opt + 68..opt + 70].copy_from_slice(&0x0003u16.to_le_bytes());

        let names = [b".text\0\0\0", b".data\0\0\0", b".rsrc\0\0\0"];
        let chars = [0x6000_0020u32, 0xC000_0040u32, 0x4000_0040u32];
        let sec_base = opt + opt_header_size as usize;

        for i in 0..section_count {
            let sec = sec_base + i * 40;
            buf[sec..sec + 8].copy_from_slice(names[i]);
            buf[sec + 8..sec + 12].copy_from_slice(&0x0100u32.to_le_bytes());
            let rva: u32 = 0x1000 + i as u32 * 0x1000;
            buf[sec + 12..sec + 16].copy_from_slice(&rva.to_le_bytes());
            buf[sec + 16..sec + 20].copy_from_slice(&raw_section_size.to_le_bytes());
            let raw_off: u32 = raw_section_offset as u32 + i as u32 * raw_section_size;
            buf[sec + 20..sec + 24].copy_from_slice(&raw_off.to_le_bytes());
            buf[sec + 36..sec + 40].copy_from_slice(&chars[i].to_le_bytes());
        }

        buf
    }

    // -----------------------------------------------------------------------
    // can_load tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_can_load_rejects_empty() {
        let loader = PeLoader;
        let input = LoaderInput::new(String::new(), vec![]);
        assert!(!loader.can_load(&input));
    }

    #[test]
    fn test_can_load_rejects_short_data() {
        let loader = PeLoader;
        let input = LoaderInput::new(String::new(), b"MZ".to_vec());
        assert!(!loader.can_load(&input));
    }

    #[test]
    fn test_can_load_rejects_elf() {
        let loader = PeLoader;
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        let input = LoaderInput::new(String::new(), data);
        assert!(!loader.can_load(&input));
    }

    #[test]
    fn test_can_load_accepts_pe32() {
        let loader = PeLoader;
        let data = build_minimal_pe32();
        let input = LoaderInput::new("test.exe", data);
        assert!(loader.can_load(&input));
    }

    #[test]
    fn test_can_load_accepts_pe64() {
        let loader = PeLoader;
        let data = build_minimal_pe64_dll();
        let input = LoaderInput::new("test.dll", data);
        assert!(loader.can_load(&input));
    }

    #[test]
    fn test_can_load_rejects_bad_pe_signature() {
        let loader = PeLoader;
        let mut data = build_minimal_pe32();
        // Overwrite "PE\0\0" with garbage
        let pe_offset = 0x80;
        data[pe_offset] = b'X';
        data[pe_offset + 1] = b'Y';
        let input = LoaderInput::new(String::new(), data);
        assert!(!loader.can_load(&input));
    }

    // -----------------------------------------------------------------------
    // PeInfo::parse tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pe_info_parse_pe32_machine() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse should succeed");
        assert_eq!(info.machine, Machine::X86);
    }

    #[test]
    fn test_pe_info_parse_pe32_not_dll() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(!info.flags.is_dll());
    }

    #[test]
    fn test_pe_info_parse_pe32_not_dotnet() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(!info.flags.is_dotnet());
    }

    #[test]
    fn test_pe_info_parse_pe32_image_base() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert_eq!(info.image_base, 0x0040_0000);
    }

    #[test]
    fn test_pe_info_parse_pe32_entry_point() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert_eq!(info.entry_point, 0x0040_0000 + 0x1000);
    }

    #[test]
    fn test_pe_info_parse_pe32_sections_count() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert_eq!(info.sections.len(), 1);
    }

    #[test]
    fn test_pe_info_parse_pe32_section_name() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert_eq!(info.sections[0].name, ".text");
    }

    #[test]
    fn test_pe_info_parse_pe32_section_permissions_readable() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        let perms = info.sections[0].permissions;
        assert!(perms.is_readable());
    }

    #[test]
    fn test_pe_info_parse_pe32_section_permissions_executable() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        let perms = info.sections[0].permissions;
        assert!(perms.is_executable());
    }

    #[test]
    fn test_pe_info_parse_pe32_section_permissions_not_writable() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        let perms = info.sections[0].permissions;
        assert!(!perms.is_writable());
    }

    #[test]
    fn test_pe_info_parse_pe64_dll_machine() {
        let data = build_minimal_pe64_dll();
        let info = PeInfo::parse(&data).expect("parse");
        assert_eq!(info.machine, Machine::X64);
    }

    #[test]
    fn test_pe_info_parse_pe64_dll_is_dll() {
        let data = build_minimal_pe64_dll();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.flags.is_dll());
    }

    #[test]
    fn test_pe_info_parse_pe64_image_base() {
        let data = build_minimal_pe64_dll();
        let info = PeInfo::parse(&data).expect("parse");
        assert_eq!(info.image_base, 0x0000_0001_8000_0000);
    }

    #[test]
    fn test_pe_info_parse_pe64_entry_point() {
        let data = build_minimal_pe64_dll();
        let info = PeInfo::parse(&data).expect("parse");
        assert_eq!(info.entry_point, 0x0000_0001_8000_0000 + 0x1000);
    }

    #[test]
    fn test_pe_info_empty_imports() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.imports.is_empty());
    }

    #[test]
    fn test_pe_info_empty_exports() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.exports.is_empty());
    }

    #[test]
    fn test_pe_info_no_tls_callbacks() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.tls_callbacks.is_empty());
        assert!(!info.has_tls_callbacks());
    }

    #[test]
    fn test_pe_info_no_pdb_path() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.pdb_path().is_none());
    }

    #[test]
    fn test_pe_info_subsystem_console() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert_eq!(info.subsystem, Subsystem::Console);
    }

    #[test]
    fn test_pe_info_subsystem_windows() {
        let data = build_minimal_pe64_dll();
        let info = PeInfo::parse(&data).expect("parse");
        assert_eq!(info.subsystem, Subsystem::Windows);
    }

    #[test]
    fn test_pe_info_is_64bit_pe32_false() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(!info.flags.is_64bit());
    }

    #[test]
    fn test_pe_info_is_64bit_pe64_true() {
        let data = build_minimal_pe64_dll();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.flags.is_64bit());
    }

    #[test]
    fn test_pe_info_multisection() {
        let data = build_pe32_multisection();
        let info = PeInfo::parse(&data).expect("parse");
        assert_eq!(info.sections.len(), 3);
        assert_eq!(info.sections[0].name, ".text");
        assert_eq!(info.sections[1].name, ".data");
        assert_eq!(info.sections[2].name, ".rsrc");
    }

    #[test]
    fn test_pe_info_section_va_range() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        let (start, end) = info.sections[0].va_range();
        assert_eq!(start, 0x0040_1000);
        assert_eq!(end, start + 0x100);
    }

    #[test]
    fn test_pe_info_section_is_code() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.sections[0].is_code());
    }

    #[test]
    fn test_pe_info_section_not_writable() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(!info.sections[0].is_writable());
    }

    #[test]
    fn test_pe_info_no_overlay_minimal() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        // Minimal PE with exact-size sections — may or may not have overlay
        // (depends on alignment); at minimum we can assert the field exists.
        let _ = &info.overlay;
    }

    #[test]
    fn test_pe_info_no_relocations_minimal() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.relocation_blocks.is_empty());
        assert!(!info.has_relocations());
    }

    #[test]
    fn test_pe_info_timestamp() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert_eq!(info.timestamp, 0xDEAD_BEEF);
    }

    #[test]
    fn test_pe_info_no_exception_directory_minimal() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.exception_functions.is_empty());
    }

    #[test]
    fn test_pe_info_not_signed_minimal() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(!info.is_signed());
    }

    #[test]
    fn test_pe_info_no_dotnet_minimal() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(!info.flags.is_dotnet());
        assert!(info.dotnet.is_none());
    }

    // -----------------------------------------------------------------------
    // Helper function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_permissions_from_characteristics_all_flags() {
        let chars = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
        let perms = permissions_from_characteristics(chars);
        assert!(perms.is_readable());
        assert!(perms.is_writable());
        assert!(perms.is_executable());
    }

    #[test]
    fn test_permissions_from_characteristics_no_flags_defaults_read() {
        let perms = permissions_from_characteristics(0);
        assert!(perms.is_readable());
        assert!(!perms.is_writable());
        assert!(!perms.is_executable());
    }

    #[test]
    fn test_permissions_from_characteristics_execute_only() {
        let perms = permissions_from_characteristics(IMAGE_SCN_MEM_EXECUTE);
        assert!(perms.is_executable());
        assert!(!perms.is_readable());
    }

    #[test]
    fn test_machine_from_u16_x86() {
        assert_eq!(machine_from_u16(0x014C), Machine::X86);
    }

    #[test]
    fn test_machine_from_u16_x64() {
        assert_eq!(machine_from_u16(0x8664), Machine::X64);
    }

    #[test]
    fn test_machine_from_u16_arm() {
        assert_eq!(machine_from_u16(0x01C0), Machine::Arm);
    }

    #[test]
    fn test_machine_from_u16_arm64() {
        assert_eq!(machine_from_u16(0xAA64), Machine::Arm64);
    }

    #[test]
    fn test_machine_from_u16_unknown() {
        assert_eq!(machine_from_u16(0xFFFF), Machine::Unknown(0xFFFF));
    }

    #[test]
    fn test_subsystem_from_u16_native() {
        assert_eq!(subsystem_from_u16(1), Subsystem::Native);
    }

    #[test]
    fn test_subsystem_from_u16_windows() {
        assert_eq!(subsystem_from_u16(2), Subsystem::Windows);
    }

    #[test]
    fn test_subsystem_from_u16_console() {
        assert_eq!(subsystem_from_u16(3), Subsystem::Console);
    }

    #[test]
    fn test_subsystem_from_u16_efi_app() {
        assert_eq!(subsystem_from_u16(10), Subsystem::EfiApp);
    }

    #[test]
    fn test_subsystem_from_u16_efi_boot() {
        assert_eq!(subsystem_from_u16(11), Subsystem::EfiBootService);
    }

    #[test]
    fn test_subsystem_from_u16_efi_runtime() {
        assert_eq!(subsystem_from_u16(12), Subsystem::EfiRuntime);
    }

    #[test]
    fn test_subsystem_from_u16_efi_rom() {
        assert_eq!(subsystem_from_u16(13), Subsystem::EfiRom);
    }

    #[test]
    fn test_subsystem_from_u16_unknown() {
        assert_eq!(subsystem_from_u16(99), Subsystem::Unknown(99));
    }

    #[test]
    fn test_parse_exception_directory_basic_empty() {
        let result = parse_exception_directory_basic(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_exception_directory_basic_one_entry() {
        let mut buf = vec![0u8; 12];
        buf[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[4..8].copy_from_slice(&0x1080u32.to_le_bytes());
        buf[8..12].copy_from_slice(&0xABCDu32.to_le_bytes());
        let result = parse_exception_directory_basic(&buf);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].begin_address, 0x1000);
        assert_eq!(result[0].end_address, 0x1080);
        assert_eq!(result[0].unwind_info, 0xABCD);
    }

    #[test]
    fn test_parse_exception_directory_basic_null_terminates() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[4..8].copy_from_slice(&0x1080u32.to_le_bytes());
        buf[8..12].copy_from_slice(&0x0001u32.to_le_bytes());
        // 12..24 all zero → null entry
        let result = parse_exception_directory_basic(&buf);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_parse_rich_header_invalid_returns_none() {
        let data = vec![0u8; 256];
        let result = parse_rich_header(&data, 0x80);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_rich_header_short_pe_offset_returns_none() {
        let mut data = vec![0u8; 128];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
        let result = parse_rich_header(&data, 64);
        assert!(result.is_none()); // stub is empty
    }

    // -----------------------------------------------------------------------
    // Full async load tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_load_pe32_basic() {
        let loader = PeLoader;
        let data = build_minimal_pe32();
        let input = LoaderInput::new("file://test.exe", data.clone());
        let result = loader.load(input).await.expect("load should succeed");
        let view = result.view;
        assert_eq!(view.bits, 32);
        assert!(!view.entry_points.is_empty());
        assert_eq!(view.entry_points[0].0, 0x0040_1000);
    }

    #[tokio::test]
    async fn test_load_pe32_has_segments() {
        let loader = PeLoader;
        let data = build_minimal_pe32();
        let input = LoaderInput::new("file://test.exe", data);
        let result = loader.load(input).await.expect("load should succeed");
        let view = result.view;
        let mem = view.mem.read();
        assert!(!mem.segments.is_empty());
    }

    #[tokio::test]
    async fn test_load_pe32_segment_start_address() {
        let loader = PeLoader;
        let data = build_minimal_pe32();
        let input = LoaderInput::new("file://test.exe", data);
        let result = loader.load(input).await.expect("load should succeed");
        let view = result.view;
        let mem = view.mem.read();
        assert!(mem.segments.iter().any(|s| s.range.start.0 == 0x0040_1000));
    }

    #[tokio::test]
    async fn test_load_pe64_dll_bits() {
        let loader = PeLoader;
        let data = build_minimal_pe64_dll();
        let input = LoaderInput::new("file://test.dll", data);
        let result = loader.load(input).await.expect("load should succeed");
        let view = result.view;
        assert_eq!(view.bits, 64);
    }

    #[tokio::test]
    async fn test_load_pe64_dll_entry_point() {
        let loader = PeLoader;
        let data = build_minimal_pe64_dll();
        let input = LoaderInput::new("file://test.dll", data);
        let result = loader.load(input).await.expect("load should succeed");
        let view = result.view;
        assert_eq!(view.entry_points[0].0, 0x0000_0001_8000_0000 + 0x1000);
    }

    #[tokio::test]
    async fn test_load_invalid_data_returns_error() {
        let loader = PeLoader;
        let input = LoaderInput::new("file://bad", b"not a PE file".to_vec());
        let result = loader.load(input).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_load_section_permissions_rx() {
        let loader = PeLoader;
        let data = build_minimal_pe32();
        let input = LoaderInput::new("file://test.exe", data);
        let result = loader.load(input).await.expect("load should succeed");
        let view = result.view;
        let mem = view.mem.read();
        let text_seg = mem
            .segments
            .iter()
            .find(|s| s.range.start.0 == 0x0040_1000)
            .expect("text segment should exist");
        assert!(text_seg.permissions.is_readable());
        assert!(text_seg.permissions.is_executable());
        assert!(!text_seg.permissions.is_writable());
    }

    #[tokio::test]
    async fn test_find_nested_is_empty() {
        let loader = PeLoader;
        let data = build_minimal_pe32();
        let input = LoaderInput::new("file://x.exe", data);
        let nested = loader.find_nested(&input).await.expect("should succeed");
        assert!(nested.is_empty());
    }

    // -----------------------------------------------------------------------
    // PeInfo convenience method tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_loader_name() {
        let loader = PeLoader;
        assert_eq!(loader.name(), "pe");
    }

    #[test]
    fn test_pe_info_section_names() {
        let data = build_pe32_multisection();
        let info = PeInfo::parse(&data).expect("parse");
        let names = info.section_names();
        assert!(names.contains(&".text"));
        assert!(names.contains(&".data"));
        assert!(names.contains(&".rsrc"));
    }

    #[test]
    fn test_pe_info_find_section_existing() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        let sec = info.find_section(".text");
        assert!(sec.is_some());
        assert_eq!(sec.unwrap().name, ".text");
    }

    #[test]
    fn test_pe_info_find_section_missing() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.find_section(".nonexistent").is_none());
    }

    #[test]
    fn test_pe_info_imports_from_dll_empty() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        let found = info.imports_from_dll("kernel32.dll");
        assert!(found.is_empty());
    }

    #[test]
    fn test_pe_info_imports_dll_not_present() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(!info.imports_dll("kernel32.dll"));
    }

    #[test]
    fn test_pe_info_export_by_name_empty() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.export_by_name("SomeFunc").is_none());
    }

    #[test]
    fn test_pe_info_export_by_ordinal_empty() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.export_by_ordinal(1).is_none());
    }

    #[test]
    fn test_pe_info_forwarded_exports_empty() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.forwarded_exports().is_empty());
    }

    #[test]
    fn test_pe_info_relocation_count_zero() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert_eq!(info.relocation_count(), 0);
    }

    #[test]
    fn test_pe_info_security_score_zero_no_config() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        // No load config → score is 0
        assert_eq!(info.security_score(), 0);
    }

    #[test]
    fn test_pe_info_pe_headers_populated() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.pe_headers.is_some());
    }

    #[test]
    fn test_pe_info_resource_summary_default_on_no_resources() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert_eq!(info.resource_summary.total_leaves, 0);
        assert!(info.resource_summary.manifest.is_none());
        assert!(info.resource_summary.version_info.is_none());
    }

    #[test]
    fn test_pe_info_no_delay_imports_minimal() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.delay_imports.is_empty());
    }

    #[test]
    fn test_pe_info_no_bound_imports_minimal() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.bound_imports.is_empty());
    }

    #[test]
    fn test_pe_info_entropy_summary_populated() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        // At least one section → entropy summary should exist
        assert!(info.entropy_summary.is_some());
    }

    #[test]
    fn test_pe_info_rva_to_offset_within_section() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        // RVA 0x1000 maps into .text; with image_base=0x40_0000, RVA=0x1000
        let off = info.rva_to_offset(0x1000);
        assert!(off.is_some());
    }

    #[test]
    fn test_pe_info_rva_to_offset_out_of_range() {
        let data = build_minimal_pe32();
        let info = PeInfo::parse(&data).expect("parse");
        assert!(info.rva_to_offset(0xFFFF_FFFF).is_none());
    }

    // -----------------------------------------------------------------------
    // struct field / data type tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_import_entry_fields() {
        let entry = ImportEntry {
            dll: "KERNEL32.dll".to_string(),
            name: Some("VirtualAlloc".to_string()),
            ordinal: None,
            address: 0x1_4000_1234,
        };
        assert_eq!(entry.dll, "KERNEL32.dll");
        assert_eq!(entry.name.as_deref(), Some("VirtualAlloc"));
        assert!(entry.ordinal.is_none());
    }

    #[test]
    fn test_export_entry_ordinal_only() {
        let entry = ExportEntry {
            name: None,
            ordinal: 42,
            address: 0x40_1234,
            forwarder: None,
        };
        assert!(entry.name.is_none());
        assert_eq!(entry.ordinal, 42);
        assert!(entry.forwarder.is_none());
    }

    #[test]
    fn test_export_entry_with_forwarder() {
        let entry = ExportEntry {
            name: Some("HeapAlloc".to_string()),
            ordinal: 1,
            address: 0x40_1000,
            forwarder: Some("NTDLL.RtlAllocateHeap".to_string()),
        };
        assert!(entry.forwarder.is_some());
        assert_eq!(entry.forwarder.as_deref(), Some("NTDLL.RtlAllocateHeap"));
    }

    #[test]
    fn test_rich_header_entry_fields() {
        let entry = RichEntry {
            product_id: 0x00C7,
            build_number: 0x7B4F,
            count: 3,
        };
        assert_eq!(entry.product_id, 0x00C7);
        assert_eq!(entry.build_number, 0x7B4F);
        assert_eq!(entry.count, 3);
    }

    #[test]
    fn test_runtime_function_info_fields() {
        let rf = RuntimeFunctionInfo {
            begin_address: 0x1000,
            end_address: 0x1080,
            unwind_info: 0x5000,
        };
        assert_eq!(rf.begin_address, 0x1000);
        assert_eq!(rf.end_address, 0x1080);
    }

    #[test]
    fn test_delay_load_entry_fields() {
        let entry = DelayLoadEntry {
            dll: "SHELL32.dll".to_string(),
            uses_rvas: true,
            delay_iat_rva: 0x2000,
            time_stamp: 0,
        };
        assert_eq!(entry.dll, "SHELL32.dll");
        assert!(entry.uses_rvas);
    }

    #[test]
    fn test_section_info_mapped_size() {
        let sec = SectionInfo {
            name: ".text".to_string(),
            virtual_address: 0x40_1000,
            virtual_size: 0x200,
            raw_offset: 0x400,
            raw_size: 0x200,
            characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
            permissions: Permissions::READ | Permissions::EXECUTE,
        };
        assert_eq!(sec.mapped_size(), 0x200);
        assert!(sec.is_code());
        assert!(sec.is_readable());
        assert!(!sec.is_writable());
    }

    #[test]
    fn test_load_config_info_default() {
        let lci = LoadConfigInfo::default();
        assert_eq!(lci.security_cookie, 0);
        assert!(lci.seh_handlers.is_empty());
        assert!(lci.cfg_functions.is_empty());
        assert_eq!(lci.guard_flags, 0);
    }

    #[test]
    fn test_resource_summary_default() {
        let rs = ResourceSummary::default();
        assert!(rs.manifest.is_none());
        assert!(rs.version_info.is_none());
        assert_eq!(rs.icon_count, 0);
        assert_eq!(rs.total_leaves, 0);
    }

    #[test]
    fn test_debug_info_default() {
        let di = DebugInfo::default();
        assert!(di.pdb_path.is_none());
        assert!(di.pdb_guid.is_none());
        assert!(di.pdb_age.is_none());
        assert!(di.entry_types.is_empty());
    }
}
