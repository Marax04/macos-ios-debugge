//! `rustre-pe-tools`
//!
//! PE (Portable Executable) format analysis — imports, exports, sections,
//! resources, signatures, overlay detection, checksum verification,
//! DLL characteristics, rich header parsing, and security feature detection.
//!
//! ## Sub-modules
//!
//! * [`cff_editor`]       — CFF (Common File Format) in-memory PE editor.
//! * [`pe_rebuild`]       — PE rebuilder: OEP detection, IAT fixup, import
//!   table reconstruction, section alignment, checksum.
//! * [`resource_parser`]  — PE resource directory parser: walk, extract,
//!   parse `VS_VERSION_INFO`.

pub mod cff_editor;
pub mod import_analysis;
/// Windows PE side-by-side / RT_MANIFEST parser.
pub mod pe_manifest_parser;
/// Backward-compat alias — prefer [`pe_manifest_parser`].
pub use pe_manifest_parser as manifest_parser;
pub mod pe_anomaly_detector;
pub mod pe_anomaly_scanner;
pub mod pe_overlay_analyzer;
pub mod pe_patcher;
pub mod pe_rebuild;
pub mod pe_sign_checker;
pub mod pe_statistics;
pub mod pe_validation;
pub mod resource_parser;
pub mod pe_checksum_calculator;
pub mod pe_overlay_extractor;
pub mod pe_rich_header;

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// parking_lot brought in via Cargo.toml; used in tests via RwLock if needed.
use parking_lot::RwLock;

/// Errors produced by PE parsing operations.
#[derive(Debug, Error)]
pub enum PeError {
    /// Not a PE file — bad MZ magic.
    #[error("not a PE file: bad magic {0:#x}")]
    NotPe(u16),
    /// Input buffer is too short.
    #[error("buffer too short: need {needed} got {got}")]
    TooShort { needed: usize, got: usize },
    /// PE header is structurally invalid.
    #[error("invalid PE header: {0}")]
    InvalidHeader(String),
    /// Named section does not exist.
    #[error("section not found: {0}")]
    SectionNotFound(String),
    /// Import table could not be parsed.
    #[error("import table corrupt")]
    ImportTableCorrupt,
    /// Export table could not be parsed.
    #[error("export table corrupt")]
    ExportTableCorrupt,
    /// Named resource does not exist.
    #[error("resource not found: {0}")]
    ResourceNotFound(String),
    /// I/O error wrapper.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Serde-JSON error wrapper.
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// PeMachine
// ---------------------------------------------------------------------------

/// PE COFF machine type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeMachine {
    /// Unknown or unsupported machine.
    Unknown,
    /// x86 (IA-32).
    I386,
    /// x86-64 (AMD64).
    Amd64,
    /// ARM (Thumb / Thumb-2).
    Arm,
    /// ARM64 (`AArch64`).
    Arm64,
    /// MIPS32.
    Mips32,
    /// RISC-V 32-bit.
    Riscv32,
    /// RISC-V 64-bit.
    Riscv64,
    /// Itanium (IA-64).
    Ia64,
}

impl PeMachine {
    /// Convert a raw COFF machine value to a `PeMachine`.
    #[must_use]
    pub const fn from_value(v: u16) -> Self {
        match v {
            0x014c => Self::I386,
            0x8664 => Self::Amd64,
            0x01c0 | 0x01c4 => Self::Arm,
            0xaa64 => Self::Arm64,
            0x0166 => Self::Mips32,
            0x5032 => Self::Riscv32,
            0x5064 => Self::Riscv64,
            0x0200 => Self::Ia64,
            _ => Self::Unknown,
        }
    }

    /// Raw COFF machine value.
    #[must_use]
    pub const fn to_value(self) -> u16 {
        match self {
            Self::I386 => 0x014c,
            Self::Amd64 => 0x8664,
            Self::Arm => 0x01c4,
            Self::Arm64 => 0xaa64,
            Self::Mips32 => 0x0166,
            Self::Riscv32 => 0x5032,
            Self::Riscv64 => 0x5064,
            Self::Ia64 => 0x0200,
            Self::Unknown => 0x0000,
        }
    }

    /// Natural pointer size in bytes for this architecture.
    #[must_use]
    pub const fn pointer_size(self) -> usize {
        match self {
            Self::Amd64 | Self::Arm64 | Self::Ia64 | Self::Riscv64 => 8,
            _ => 4,
        }
    }

    /// Returns `true` if this is a 64-bit architecture.
    #[must_use]
    pub const fn is_64bit(self) -> bool {
        self.pointer_size() == 8
    }

    /// Convert this [`PeMachine`] to the canonical [`rustre_core::arch_mode::Mode`].
    ///
    /// This enables interoperability with the rest of the `RustRE` platform (e.g.
    /// disassemblers and analysis passes that accept a `Mode`).
    #[must_use]
    pub const fn to_core_mode(self) -> rustre_core::arch_mode::Mode {
        match self {
            Self::I386 => rustre_core::arch_mode::Mode::X86_32,
            Self::Amd64 | Self::Ia64 | Self::Unknown => rustre_core::arch_mode::Mode::X86_64,
            Self::Arm => rustre_core::arch_mode::Mode::Arm32,
            Self::Arm64 => rustre_core::arch_mode::Mode::Aarch64,
            Self::Mips32 => rustre_core::arch_mode::Mode::Mips32Le,
            Self::Riscv32 => rustre_core::arch_mode::Mode::RiscV32,
            Self::Riscv64 => rustre_core::arch_mode::Mode::RiscV64,
        }
    }
}

impl fmt::Display for PeMachine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::I386 => "i386",
            Self::Amd64 => "x86_64",
            Self::Arm => "ARM",
            Self::Arm64 => "ARM64",
            Self::Mips32 => "MIPS32",
            Self::Riscv32 => "RISC-V 32",
            Self::Riscv64 => "RISC-V 64",
            Self::Ia64 => "IA-64",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// PeSubsystem
// ---------------------------------------------------------------------------

/// PE optional-header subsystem field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeSubsystem {
    /// Unknown subsystem.
    Unknown,
    /// Device driver / native Windows.
    Native,
    /// Windows GUI application.
    WindowsGui,
    /// Windows console application.
    WindowsCui,
    /// POSIX console application.
    PosixCui,
    /// EFI application.
    EfiApplication,
    /// EFI boot service driver.
    EfiBootDriver,
    /// EFI runtime driver.
    EfiRuntimeDriver,
    /// Xbox application.
    Xbox,
}

impl PeSubsystem {
    /// Convert a raw subsystem value to a `PeSubsystem`.
    #[must_use]
    pub const fn from_value(v: u16) -> Self {
        match v {
            1 => Self::Native,
            2 => Self::WindowsGui,
            3 => Self::WindowsCui,
            7 => Self::PosixCui,
            10 => Self::EfiApplication,
            11 => Self::EfiBootDriver,
            12 => Self::EfiRuntimeDriver,
            14 => Self::Xbox,
            _ => Self::Unknown,
        }
    }

    /// Raw subsystem value.
    #[must_use]
    pub const fn to_value(self) -> u16 {
        match self {
            Self::Unknown => 0,
            Self::Native => 1,
            Self::WindowsGui => 2,
            Self::WindowsCui => 3,
            Self::PosixCui => 7,
            Self::EfiApplication => 10,
            Self::EfiBootDriver => 11,
            Self::EfiRuntimeDriver => 12,
            Self::Xbox => 14,
        }
    }

    /// Returns `true` if this subsystem is a console (CUI) application.
    #[must_use]
    pub const fn is_console(self) -> bool {
        matches!(self, Self::WindowsCui | Self::PosixCui)
    }

    /// Returns `true` if this subsystem is an EFI variant.
    #[must_use]
    pub const fn is_efi(self) -> bool {
        matches!(
            self,
            Self::EfiApplication | Self::EfiBootDriver | Self::EfiRuntimeDriver
        )
    }
}

impl fmt::Display for PeSubsystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// DllCharacteristics
// ---------------------------------------------------------------------------

/// Parsed DLL characteristics flags from the optional header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct DllCharacteristics(pub u16);

impl DllCharacteristics {
    /// `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA` — 64-bit ASLR with high-entropy.
    pub const HIGH_ENTROPY_VA: u16 = 0x0020;
    /// `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` — ASLR enabled.
    pub const DYNAMIC_BASE: u16 = 0x0040;
    /// `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` — code integrity check required.
    pub const FORCE_INTEGRITY: u16 = 0x0080;
    /// `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` — NX (DEP) compatible.
    pub const NX_COMPAT: u16 = 0x0100;
    /// `IMAGE_DLLCHARACTERISTICS_NO_ISOLATION` — no manifest isolation.
    pub const NO_ISOLATION: u16 = 0x0200;
    /// `IMAGE_DLLCHARACTERISTICS_NO_SEH` — no structured exception handling.
    pub const NO_SEH: u16 = 0x0400;
    /// `IMAGE_DLLCHARACTERISTICS_NO_BIND` — do not bind the image.
    pub const NO_BIND: u16 = 0x0800;
    /// `IMAGE_DLLCHARACTERISTICS_APPCONTAINER` — image must execute in `AppContainer`.
    pub const APPCONTAINER: u16 = 0x1000;
    /// `IMAGE_DLLCHARACTERISTICS_WDM_DRIVER` — WDM driver.
    pub const WDM_DRIVER: u16 = 0x2000;
    /// `IMAGE_DLLCHARACTERISTICS_GUARD_CF` — Control Flow Guard enabled.
    pub const GUARD_CF: u16 = 0x4000;
    /// `IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE` — TS-aware.
    pub const TERMINAL_SERVER_AWARE: u16 = 0x8000;

    /// Returns `true` if ASLR (`DYNAMIC_BASE`) is enabled.
    #[must_use]
    pub const fn has_aslr(self) -> bool {
        (self.0 & Self::DYNAMIC_BASE) != 0
    }

    /// Returns `true` if high-entropy ASLR is enabled.
    #[must_use]
    pub const fn has_high_entropy_va(self) -> bool {
        (self.0 & Self::HIGH_ENTROPY_VA) != 0
    }

    /// Returns `true` if NX / DEP is enabled.
    #[must_use]
    pub const fn has_nx(self) -> bool {
        (self.0 & Self::NX_COMPAT) != 0
    }

    /// Returns `true` if Control Flow Guard is enabled.
    #[must_use]
    pub const fn has_cfg(self) -> bool {
        (self.0 & Self::GUARD_CF) != 0
    }

    /// Returns `true` if SEH is disabled.
    #[must_use]
    pub const fn no_seh(self) -> bool {
        (self.0 & Self::NO_SEH) != 0
    }

    /// Returns `true` if force integrity is set.
    #[must_use]
    pub const fn force_integrity(self) -> bool {
        (self.0 & Self::FORCE_INTEGRITY) != 0
    }

    /// Returns `true` if the image is AppContainer-restricted.
    #[must_use]
    pub const fn is_appcontainer(self) -> bool {
        (self.0 & Self::APPCONTAINER) != 0
    }

    /// Collect the names of all set flags as a `Vec<&'static str>`.
    #[must_use]
    pub fn flag_names(self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.has_high_entropy_va() {
            v.push("HIGH_ENTROPY_VA");
        }
        if self.has_aslr() {
            v.push("DYNAMIC_BASE");
        }
        if self.force_integrity() {
            v.push("FORCE_INTEGRITY");
        }
        if self.has_nx() {
            v.push("NX_COMPAT");
        }
        if (self.0 & Self::NO_ISOLATION) != 0 {
            v.push("NO_ISOLATION");
        }
        if self.no_seh() {
            v.push("NO_SEH");
        }
        if (self.0 & Self::NO_BIND) != 0 {
            v.push("NO_BIND");
        }
        if self.is_appcontainer() {
            v.push("APPCONTAINER");
        }
        if (self.0 & Self::WDM_DRIVER) != 0 {
            v.push("WDM_DRIVER");
        }
        if self.has_cfg() {
            v.push("GUARD_CF");
        }
        if (self.0 & Self::TERMINAL_SERVER_AWARE) != 0 {
            v.push("TERMINAL_SERVER_AWARE");
        }
        v
    }
}

impl fmt::Display for DllCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#06x} [{}]", self.0, self.flag_names().join(", "))
    }
}

// ---------------------------------------------------------------------------
// PeSection
// ---------------------------------------------------------------------------

/// A PE section header together with its raw data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSection {
    /// Section name (up to 8 bytes, NUL-stripped).
    pub name: String,
    /// Relative virtual address of the section.
    pub virtual_address: u32,
    /// Virtual size of the section.
    pub virtual_size: u32,
    /// File offset of the raw data.
    pub raw_offset: u32,
    /// Size of the raw data on disk.
    pub raw_size: u32,
    /// Section characteristics flags.
    pub characteristics: u32,
    /// Raw bytes read from the file for this section.
    pub data: Vec<u8>,
}

impl PeSection {
    /// Returns `true` if the section has the executable flag set.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        (self.characteristics & 0x2000_0000) != 0
    }

    /// Returns `true` if the section has the writable flag set.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        (self.characteristics & 0x8000_0000) != 0
    }

    /// Returns `true` if the section has the readable flag set.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        (self.characteristics & 0x4000_0000) != 0
    }

    /// Returns `true` if the section contains initialised data.
    #[must_use]
    pub const fn contains_initialized_data(&self) -> bool {
        (self.characteristics & 0x0000_0040) != 0
    }

    /// Returns `true` if the section contains code.
    #[must_use]
    pub const fn contains_code(&self) -> bool {
        (self.characteristics & 0x0000_0020) != 0
    }

    /// Returns `true` if the section is discardable (e.g. `.reloc`, `.debug`).
    #[must_use]
    pub const fn is_discardable(&self) -> bool {
        (self.characteristics & 0x0200_0000) != 0
    }

    /// Shannon entropy of the section data (0.0 – 8.0).
    #[must_use]
    pub fn entropy(&self) -> f64 {
        compute_entropy(&self.data)
    }

    /// Returns `true` if this section appears packed/encrypted (entropy > 7.0).
    #[must_use]
    pub fn is_likely_packed(&self) -> bool {
        self.entropy() > 7.0
    }

    /// Byte frequency histogram (256 entries).
    #[must_use]
    pub fn byte_histogram(&self) -> [u64; 256] {
        let mut freq = [0u64; 256];
        for &b in &self.data {
            freq[b as usize] += 1;
        }
        freq
    }

    /// Most common byte value in the section data.
    #[must_use]
    pub fn most_common_byte(&self) -> Option<u8> {
        if self.data.is_empty() {
            return None;
        }
        let hist = self.byte_histogram();
        hist.iter()
            .enumerate()
            .max_by_key(|&(_, &c)| c)
            .map(|(b, _)| u8::try_from(b).unwrap_or(0))
    }

    /// Count occurrences of a specific byte in the section.
    #[must_use]
    pub fn count_byte(&self, byte: u8) -> usize {
        self.data
            .iter()
            .fold(0usize, |acc, &b| acc + usize::from(b == byte))
    }

    /// Return a human-readable summary of the section permissions (e.g. `"r-x"`).
    #[must_use]
    pub fn permission_string(&self) -> String {
        let r = if self.is_readable() { 'r' } else { '-' };
        let w = if self.is_writable() { 'w' } else { '-' };
        let x = if self.is_executable() { 'x' } else { '-' };
        format!("{r}{w}{x}")
    }
}

impl fmt::Display for PeSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} VA={:#x} sz={:#x} raw={:#x}",
            self.name, self.virtual_address, self.virtual_size, self.raw_size
        )
    }
}

// ---------------------------------------------------------------------------
// PeImport / PeExport / DataDir
// ---------------------------------------------------------------------------

/// A single imported function or ordinal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeImport {
    /// DLL that contains this import.
    pub dll: String,
    /// Function name, if imported by name.
    pub name: Option<String>,
    /// Ordinal number, if imported by ordinal.
    pub ordinal: Option<u16>,
    /// Import hint.
    pub hint: u16,
    /// IAT slot RVA.
    pub iat_rva: u32,
}

impl fmt::Display for PeImport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(n) = &self.name {
            write!(f, "{}!{}", self.dll, n)
        } else {
            write!(f, "{}!ord#{}", self.dll, self.ordinal.unwrap_or(0))
        }
    }
}

/// A single exported function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeExport {
    /// Export name, if present.
    pub name: Option<String>,
    /// Export ordinal.
    pub ordinal: u16,
    /// RVA of the exported function.
    pub rva: u32,
    /// Forwarder string, if this is a forwarded export.
    pub forwarder: Option<String>,
}

impl fmt::Display for PeExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("<unnamed>");
        write!(f, "{}@{} -> {:#x}", name, self.ordinal, self.rva)
    }
}

/// A PE data-directory entry (RVA + size).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DataDir {
    /// Relative virtual address of the directory.
    pub rva: u32,
    /// Size of the directory data in bytes.
    pub size: u32,
}

impl DataDir {
    /// Returns `true` if this data directory is present (non-zero RVA).
    #[must_use]
    pub const fn is_present(self) -> bool {
        self.rva != 0
    }
}

impl fmt::Display for DataDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RVA={:#x} size={:#x}", self.rva, self.size)
    }
}

// ---------------------------------------------------------------------------
// Well-known data-directory indices
// ---------------------------------------------------------------------------

/// Well-known PE data-directory indices.
pub mod data_dir_index {
    /// Export directory.
    pub const EXPORT: usize = 0;
    /// Import directory.
    pub const IMPORT: usize = 1;
    /// Resource directory.
    pub const RESOURCE: usize = 2;
    /// Exception directory.
    pub const EXCEPTION: usize = 3;
    /// Security (certificate) directory.
    pub const SECURITY: usize = 4;
    /// Base relocation table.
    pub const BASERELOC: usize = 5;
    /// Debug directory.
    pub const DEBUG: usize = 6;
    /// TLS directory.
    pub const TLS: usize = 9;
    /// Load configuration directory.
    pub const LOAD_CONFIG: usize = 10;
    /// Bound import directory.
    pub const BOUND_IMPORT: usize = 11;
    /// Import address table directory.
    pub const IAT: usize = 12;
    /// Delay-load import descriptors.
    pub const DELAY_IMPORT: usize = 13;
    /// COM+ runtime header (CLR metadata).
    pub const COM_DESCRIPTOR: usize = 14;
}

// ---------------------------------------------------------------------------
// RichHeader
// ---------------------------------------------------------------------------

/// A single entry in the PE Rich header (compiler/linker product + count).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RichEntry {
    /// Tool/product identifier (high 16 bits of the DWORD pair).
    pub product_id: u16,
    /// Build number (low 16 bits).
    pub build_number: u16,
    /// Usage count (number of objects built with this tool).
    pub count: u32,
}

impl fmt::Display for RichEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "product={:#06x} build={} count={}",
            self.product_id, self.build_number, self.count
        )
    }
}

/// Parsed Rich header from the DOS stub area.
///
/// The Rich header is an undocumented Microsoft extension placed between the
/// DOS stub and the PE signature.  It records what compiler/linker tools were
/// used to build the image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichHeader {
    /// XOR key used to obfuscate the Rich header.
    pub xor_key: u32,
    /// Decoded entries.
    pub entries: Vec<RichEntry>,
}

impl RichHeader {
    /// Attempt to parse the Rich header from the raw file bytes.
    ///
    /// Returns `None` if no Rich header is present.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Search for the "Rich" magic (0x52696368) within the DOS stub
        // (between offset 0x40 and the PE offset stored at [60..64]).
        if data.len() < 64 {
            return None;
        }
        let pe_off = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        let search_end = pe_off.min(data.len());

        // Locate "Rich" marker (LE bytes: 52 69 63 68)
        let rich_pos = (0..search_end.saturating_sub(3)).find(|&i| &data[i..i + 4] == b"Rich")?;

        let xor_key = u32::from_le_bytes(data[rich_pos + 4..rich_pos + 8].try_into().ok()?);

        // The "DanS" marker sits at the start of the encrypted block.
        // When XOR'd with the key, the first DWORD should equal 0x44616E53 ("DanS").
        let dans_marker: u32 = 0x4461_6E53;
        // Search backwards for the (encrypted) DanS
        let dans_pos = (0..rich_pos).rev().find(|&i| {
            if i + 4 > data.len() {
                return false;
            }
            let v = u32::from_le_bytes(data[i..i + 4].try_into().unwrap_or([0; 4]));
            v ^ xor_key == dans_marker
        })?;

        // Entries are 8-byte pairs between (dans_pos + 16) and rich_pos.
        let entry_start = dans_pos + 16; // skip DanS + 3 padding DWORDs
        let entry_end = rich_pos;
        if entry_start > entry_end {
            return None;
        }

        let mut entries = Vec::new();
        let mut pos = entry_start;
        while pos + 8 <= entry_end {
            let dw1 = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) ^ xor_key;
            let dw2 = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().ok()?) ^ xor_key;
            let product_id = (dw1 >> 16) as u16;
            let build_number = (dw1 & 0xFFFF) as u16;
            let count = dw2;
            entries.push(RichEntry {
                product_id,
                build_number,
                count,
            });
            pos += 8;
        }

        Some(Self { xor_key, entries })
    }
}

// ---------------------------------------------------------------------------
// PeFile
// ---------------------------------------------------------------------------

/// A fully parsed PE file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeFile {
    /// Target machine type.
    pub machine: PeMachine,
    /// Subsystem the image requires.
    pub subsystem: PeSubsystem,
    /// Preferred load address.
    pub image_base: u64,
    /// RVA of the image entry point.
    pub entry_point: u32,
    /// `true` if the image is a DLL.
    pub is_dll: bool,
    /// `true` if the image uses PE32+ (64-bit) optional header.
    pub is_64bit: bool,
    /// COFF timestamp.
    pub time_stamp: u32,
    /// PE checksum stored in the optional header.
    pub checksum: u32,
    /// Parsed DLL characteristics flags.
    pub dll_characteristics: DllCharacteristics,
    /// Section table.
    pub sections: Vec<PeSection>,
    /// Parsed import list (populated by [`PeFile::parse_imports`]).
    pub imports: Vec<PeImport>,
    /// Parsed export list (populated by [`PeFile::parse_exports`]).
    pub exports: Vec<PeExport>,
    /// Up to 16 data directory entries.
    pub data_dirs: Vec<DataDir>,
    /// Data appended after all sections ("overlay"), if any.
    pub overlay: Option<Vec<u8>>,
    /// Parsed Rich header, if present.
    pub rich_header: Option<RichHeader>,
}

impl PeFile {
    /// Parse a PE file from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PeError`] if the data is not a valid PE file.
    pub fn parse(data: &[u8]) -> Result<Self, PeError> {
        // ---- MZ header ----
        if data.len() < 64 {
            return Err(PeError::TooShort { needed: 64, got: data.len() });
        }
        if data[0] != 0x4D || data[1] != 0x5A {
            return Err(PeError::NotPe(u16::from_le_bytes([data[0], data[1]])));
        }
        let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        if pe_offset.checked_add(24).is_none_or(|end| end > data.len()) {
            return Err(PeError::InvalidHeader("PE offset out of range".to_string()));
        }
        if data[pe_offset..pe_offset + 4] != [0x50, 0x45, 0x00, 0x00] {
            return Err(PeError::InvalidHeader("PE signature missing".to_string()));
        }
        // ---- COFF header ----
        let machine = PeMachine::from_value(u16::from_le_bytes([data[pe_offset + 4], data[pe_offset + 5]]));
        let num_sections = u16::from_le_bytes([data[pe_offset + 6], data[pe_offset + 7]]) as usize;
        let time_stamp = u32::from_le_bytes(data[pe_offset + 8..pe_offset + 12].try_into().unwrap_or([0; 4]));
        let opt_hdr_size = u16::from_le_bytes([data[pe_offset + 20], data[pe_offset + 21]]) as usize;
        let characteristics = u16::from_le_bytes([data[pe_offset + 22], data[pe_offset + 23]]);
        let is_dll = (characteristics & 0x2000) != 0;
        // ---- Optional header ----
        let opt_offset = pe_offset + 24;
        if opt_offset + 2 > data.len() {
            return Err(PeError::InvalidHeader("no optional header".to_string()));
        }
        let is_64bit = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]) == 0x020B;
        let (image_base, entry_point, subsystem, checksum, num_dirs, dll_chars) =
            Self::parse_optional_header(data, opt_offset, is_64bit)?;
        // ---- Data directories ----
        let dir_offset = if is_64bit { opt_offset + 112 } else { opt_offset + 96 };
        let data_dirs = Self::parse_data_dirs(data, dir_offset, num_dirs);
        // ---- Section table ----
        let sect_offset = opt_offset + opt_hdr_size;
        let (sections, max_end) = Self::parse_section_table(data, sect_offset, num_sections);
        // ---- Overlay detection ----
        let overlay = if max_end > 0 && max_end < data.len() { Some(data[max_end..].to_vec()) } else { None };
        let rich_header = RichHeader::parse(data);
        Ok(Self {
            machine, subsystem, image_base, entry_point, is_dll, is_64bit,
            time_stamp, checksum, dll_characteristics: dll_chars,
            sections, imports: vec![], exports: vec![], data_dirs, overlay, rich_header,
        })
    }

    fn parse_optional_header(data: &[u8], opt_offset: usize, is_64bit: bool)
        -> Result<(u64, u32, PeSubsystem, u32, usize, DllCharacteristics), PeError>
    {
        let r4 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap_or([0; 4]));
        let r2 = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]);
        if is_64bit {
            if opt_offset + 112 > data.len() {
                return Err(PeError::TooShort { needed: opt_offset + 112, got: data.len() });
            }
            let base = u64::from_le_bytes(data[opt_offset + 24..opt_offset + 32].try_into().unwrap_or([0; 8]));
            let nd = r4(opt_offset + 108) as usize;
            Ok((base, r4(opt_offset + 16), PeSubsystem::from_value(r2(opt_offset + 68)),
                r4(opt_offset + 64), nd, DllCharacteristics(r2(opt_offset + 70))))
        } else {
            if opt_offset + 96 > data.len() {
                return Err(PeError::TooShort { needed: opt_offset + 96, got: data.len() });
            }
            let base = u64::from(r4(opt_offset + 28));
            let nd = r4(opt_offset + 92) as usize; // PE32 NumberOfRvaAndSizes at +92
            Ok((base, r4(opt_offset + 16), PeSubsystem::from_value(r2(opt_offset + 68)),
                r4(opt_offset + 64), nd, DllCharacteristics(r2(opt_offset + 70))))
        }
    }

    fn parse_data_dirs(data: &[u8], dir_offset: usize, num_dirs: usize) -> Vec<DataDir> {
        let mut dirs = Vec::new();
        for i in 0..num_dirs.min(16) {
            let off = dir_offset + i * 8;
            if off + 8 <= data.len() {
                let rva = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
                let size = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap_or([0; 4]));
                dirs.push(DataDir { rva, size });
            }
        }
        dirs
    }

    fn parse_section_table(data: &[u8], sect_offset: usize, num_sections: usize) -> (Vec<PeSection>, usize) {
        let mut sections = Vec::new();
        let mut max_end: usize = 0;
        for i in 0..num_sections {
            let off = sect_offset + i * 40;
            if off + 40 > data.len() { break; }
            let name = String::from_utf8_lossy(&data[off..off + 8]).trim_end_matches('\0').to_string();
            let virtual_size   = u32::from_le_bytes(data[off +  8..off + 12].try_into().unwrap_or([0; 4]));
            let virtual_address = u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap_or([0; 4]));
            let raw_size       = u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap_or([0; 4]));
            let raw_offset     = u32::from_le_bytes(data[off + 20..off + 24].try_into().unwrap_or([0; 4]));
            let characteristics_val = u32::from_le_bytes(data[off + 36..off + 40].try_into().unwrap_or([0; 4]));
            let sec_data = if raw_offset > 0 && raw_size > 0 {
                let start = raw_offset as usize;
                let end = (start + raw_size as usize).min(data.len());
                if start < data.len() { data[start..end].to_vec() } else { vec![] }
            } else { vec![] };
            let end = (raw_offset as usize).saturating_add(raw_size as usize);
            if end > max_end { max_end = end; }
            sections.push(PeSection { name, virtual_address, virtual_size, raw_offset, raw_size, characteristics: characteristics_val, data: sec_data });
        }
        (sections, max_end)
    }

    /// Parse the import directory table from raw file bytes and populate
    /// [`PeFile::imports`].
    ///
    /// Requires the original raw bytes that were used to construct this
    /// `PeFile`.  The import table is read from data directory index 1.
    ///
    /// # Errors
    ///
    /// Returns [`PeError::ImportTableCorrupt`] if the table cannot be parsed.
    pub fn parse_imports(&mut self, data: &[u8]) -> Result<(), PeError> {
        let import_dir = match self.data_dirs.get(data_dir_index::IMPORT) {
            Some(d) if d.is_present() => *d,
            _ => return Ok(()), // no imports
        };

        let Some(mut offset) = self.rva_to_offset(import_dir.rva) else {
            return Err(PeError::ImportTableCorrupt);
        };

        self.imports.clear();

        // Each import descriptor is 20 bytes.
        loop {
            if offset + 20 > data.len() {
                break;
            }
            // IMAGE_IMPORT_DESCRIPTOR
            let original_first_thunk =
                u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]));
            // time_date_stamp at offset+4
            // forwarder_chain at offset+8
            let name_rva =
                u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap_or([0; 4]));
            let first_thunk =
                u32::from_le_bytes(data[offset + 16..offset + 20].try_into().unwrap_or([0; 4]));
            offset += 20;

            // Null descriptor terminates the table.
            if name_rva == 0 && first_thunk == 0 {
                break;
            }

            let dll_name = match self.rva_to_offset(name_rva) {
                Some(o) => read_cstr(data, o),
                None => continue,
            };

            // Use OriginalFirstThunk if available, else FirstThunk.
            let thunk_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };

            let mut iat_rva = first_thunk;
            let Some(mut thunk_off) = self.rva_to_offset(thunk_rva) else {
                continue;
            };

            let entry_size: usize = if self.is_64bit { 8 } else { 4 };

            loop {
                if thunk_off + entry_size > data.len() {
                    break;
                }

                let entry: u64 = if self.is_64bit {
                    u64::from_le_bytes(data[thunk_off..thunk_off + 8].try_into().unwrap_or([0; 8]))
                } else {
                    u64::from(u32::from_le_bytes(
                        data[thunk_off..thunk_off + 4].try_into().unwrap_or([0; 4]),
                    ))
                };

                if entry == 0 {
                    break;
                }

                let ordinal_flag: u64 = if self.is_64bit {
                    0x8000_0000_0000_0000
                } else {
                    0x8000_0000
                };

                let import = if (entry & ordinal_flag) != 0 {
                    // Import by ordinal
                    let ord = (entry & 0xFFFF) as u16;
                    PeImport {
                        dll: dll_name.clone(),
                        name: None,
                        ordinal: Some(ord),
                        hint: 0,
                        iat_rva,
                    }
                } else {
                    // Import by name — entry is an RVA to IMAGE_IMPORT_BY_NAME
                    let ibn_rva = (entry & 0xFFFF_FFFF) as u32;
                    match self.rva_to_offset(ibn_rva) {
                        Some(ibn_off) if ibn_off + 2 < data.len() => {
                            let hint = u16::from_le_bytes(
                                data[ibn_off..ibn_off + 2].try_into().unwrap_or([0; 2]),
                            );
                            let func_name = read_cstr(data, ibn_off + 2);
                            PeImport {
                                dll: dll_name.clone(),
                                name: Some(func_name),
                                ordinal: None,
                                hint,
                                iat_rva,
                            }
                        }
                        _ => {
                            thunk_off += entry_size;
                            iat_rva += u32::try_from(entry_size).unwrap_or(u32::MAX);
                            continue;
                        }
                    }
                };

                self.imports.push(import);
                thunk_off += entry_size;
                iat_rva += u32::try_from(entry_size).unwrap_or(u32::MAX);
            }
        }

        Ok(())
    }

    /// Parse the export directory table from raw file bytes and populate
    /// [`PeFile::exports`].
    ///
    /// # Errors
    ///
    /// Returns [`PeError::ExportTableCorrupt`] if the table cannot be parsed.
    pub fn parse_exports(&mut self, data: &[u8]) -> Result<(), PeError> {
        let export_dir = match self.data_dirs.get(data_dir_index::EXPORT) {
            Some(d) if d.is_present() => *d,
            _ => return Ok(()), // no exports
        };
        let Some(dir_off) = self.rva_to_offset(export_dir.rva) else {
            return Err(PeError::ExportTableCorrupt);
        };
        if dir_off + 40 > data.len() {
            return Err(PeError::ExportTableCorrupt);
        }
        let (ordinal_base, num_functions, num_names, addr_table_rva, name_table_rva, ord_table_rva) =
            Self::read_export_dir_header(data, dir_off);
        let Some(addr_table_off) = self.rva_to_offset(addr_table_rva) else {
            return Err(PeError::ExportTableCorrupt);
        };
        let name_map = self.build_export_name_map(data, num_names, name_table_rva, ord_table_rva);
        self.exports.clear();
        let export_dir_start = export_dir.rva;
        let export_dir_end = export_dir.rva.saturating_add(export_dir.size);
        for i in 0..(num_functions as usize).min(65536) {
            let Some(func_rva_off) = i.checked_mul(4).and_then(|o| addr_table_off.checked_add(o)) else {
                break;
            };
            if func_rva_off + 4 > data.len() { break; }
            let func_rva = u32::from_le_bytes(data[func_rva_off..func_rva_off + 4].try_into().unwrap_or([0; 4]));
            if func_rva == 0 { continue; } // gap in the EAT
            let ordinal = u16::try_from(u32::try_from(i).unwrap_or(u32::MAX).saturating_add(ordinal_base)).unwrap_or(u16::MAX);
            let name = u16::try_from(i).ok().and_then(|k| name_map.get(&k).cloned());
            let forwarder = if func_rva >= export_dir_start && func_rva < export_dir_end {
                self.rva_to_offset(func_rva).map(|o| read_cstr(data, o))
            } else {
                None
            };
            self.exports.push(PeExport { name, ordinal, rva: func_rva, forwarder });
        }
        Ok(())
    }

    // IMAGE_EXPORT_DIRECTORY: ordinal_base, num_functions, num_names, EAT RVA, ENT RVA, EOT RVA
    fn read_export_dir_header(data: &[u8], dir_off: usize) -> (u32, u32, u32, u32, u32, u32) {
        let r4 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap_or([0; 4]));
        (r4(dir_off + 16), r4(dir_off + 20), r4(dir_off + 24), r4(dir_off + 28), r4(dir_off + 32), r4(dir_off + 36))
    }

    // Build ordinal-index → name map from the Export Name Table and Export Ordinal Table.
    fn build_export_name_map(&self, data: &[u8], num_names: u32, name_table_rva: u32, ord_table_rva: u32) -> HashMap<u16, String> {
        let mut name_map: HashMap<u16, String> = HashMap::new();
        let (Some(name_table_off), Some(ord_table_off)) = (
            self.rva_to_offset(name_table_rva),
            self.rva_to_offset(ord_table_rva),
        ) else { return name_map; };
        for i in 0..(num_names as usize).min(65536) {
            let (Some(name_rva_off), Some(ord_off)) = (
                i.checked_mul(4).and_then(|o| name_table_off.checked_add(o)),
                i.checked_mul(2).and_then(|o| ord_table_off.checked_add(o)),
            ) else { break; };
            if name_rva_off + 4 > data.len() || ord_off + 2 > data.len() { break; }
            let name_rva = u32::from_le_bytes(data[name_rva_off..name_rva_off + 4].try_into().unwrap_or([0; 4]));
            let ordinal_idx = u16::from_le_bytes(data[ord_off..ord_off + 2].try_into().unwrap_or([0; 2]));
            if let Some(name_off) = self.rva_to_offset(name_rva) {
                name_map.insert(ordinal_idx, read_cstr(data, name_off));
            }
        }
        name_map
    }

    /// Find a section by its name.
    #[must_use]
    pub fn section_by_name(&self, name: &str) -> Option<&PeSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Find the section that contains the given RVA.
    #[must_use]
    pub fn section_at_rva(&self, rva: u32) -> Option<&PeSection> {
        self.sections.iter().find(|s| {
            rva >= s.virtual_address
                && rva < s.virtual_address.saturating_add(s.virtual_size.max(s.raw_size))
        })
    }

    /// Convert an RVA to a file offset.
    #[must_use]
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        let s = self.section_at_rva(rva)?;
        let delta = rva.checked_sub(s.virtual_address)?;
        delta.checked_add(s.raw_offset).map(|v| v as usize)
    }

    /// Return the canonical [`rustre_core::arch_mode::Mode`] for this PE image.
    ///
    /// This enables downstream analysis passes (disassemblers, lifters, …) that
    /// operate on `Mode` to consume a `PeFile` directly without a separate
    /// machine-type translation step.
    #[must_use]
    pub const fn arch_mode(&self) -> rustre_core::arch_mode::Mode {
        self.machine.to_core_mode()
    }

    /// Group imports by DLL name.
    #[must_use]
    pub fn imports_by_dll(&self) -> HashMap<String, Vec<&PeImport>> {
        let mut m: HashMap<String, Vec<&PeImport>> = HashMap::new();
        for imp in &self.imports {
            m.entry(imp.dll.clone()).or_default().push(imp);
        }
        m
    }

    /// Returns `true` if the image has ASLR enabled (`DYNAMIC_BASE`).
    #[must_use]
    pub const fn has_aslr(&self) -> bool {
        self.dll_characteristics.has_aslr()
    }

    /// Returns `true` if the image has NX (DEP) protection enabled.
    #[must_use]
    pub const fn has_nx(&self) -> bool {
        self.dll_characteristics.has_nx()
    }

    /// Returns `true` if Control Flow Guard is enabled.
    #[must_use]
    pub const fn has_cfg(&self) -> bool {
        self.dll_characteristics.has_cfg()
    }

    /// Shannon entropy across all section data combined.
    #[must_use]
    pub fn overall_entropy(&self) -> f64 {
        let mut freq = [0u64; 256];
        let mut total: u64 = 0;
        for s in &self.sections {
            for &b in &s.data {
                freq[b as usize] += 1;
            }
            total += s.data.len() as u64;
        }
        if total == 0 {
            return 0.0;
        }
        let len = f64::from(u32::try_from(total).unwrap_or(u32::MAX));
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Approximate file size (end of last raw section data).
    #[must_use]
    pub fn size(&self) -> usize {
        self.sections
            .iter()
            .map(|s| (s.raw_offset as usize).saturating_add(s.raw_size as usize))
            .max()
            .unwrap_or(0)
    }

    /// Serialize the parsed PE metadata to JSON.
    ///
    /// # Errors
    ///
    /// Returns [`PeError`] if serialization fails.
    pub fn to_json(&self) -> Result<String, PeError> {
        serde_json::to_string_pretty(self).map_err(PeError::Serde)
    }

    /// Return the data directory at a given index (0-based), if present.
    #[must_use]
    pub fn data_dir(&self, index: usize) -> Option<DataDir> {
        self.data_dirs.get(index).copied()
    }

    /// Return all section names.
    #[must_use]
    pub fn section_names(&self) -> Vec<&str> {
        self.sections.iter().map(|s| s.name.as_str()).collect()
    }

    /// Returns `true` if there is a `.NET / CLR` runtime header (COM descriptor directory).
    #[must_use]
    pub fn is_dotnet(&self) -> bool {
        self.data_dirs
            .get(data_dir_index::COM_DESCRIPTOR)
            .is_some_and(|d| d.is_present())
    }

    /// Returns `true` if there is a security (certificate) directory.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.data_dirs
            .get(data_dir_index::SECURITY)
            .is_some_and(|d| d.is_present())
    }

    /// Returns `true` if the image has a base-relocation table.
    #[must_use]
    pub fn has_relocations(&self) -> bool {
        self.data_dirs
            .get(data_dir_index::BASERELOC)
            .is_some_and(|d| d.is_present())
    }

    /// Returns `true` if the image has a TLS directory.
    #[must_use]
    pub fn has_tls(&self) -> bool {
        self.data_dirs
            .get(data_dir_index::TLS)
            .is_some_and(|d| d.is_present())
    }

    /// Returns the highest-entropy section, if any sections exist.
    #[must_use]
    pub fn highest_entropy_section(&self) -> Option<&PeSection> {
        self.sections.iter().max_by(|a, b| {
            a.entropy()
                .partial_cmp(&b.entropy())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Returns sections that appear packed or encrypted (entropy > 7.0).
    #[must_use]
    pub fn packed_sections(&self) -> Vec<&PeSection> {
        self.sections
            .iter()
            .filter(|s| s.is_likely_packed())
            .collect()
    }

    /// Check whether the file-embedded checksum matches a recomputed one.
    ///
    /// Returns `None` if the stored checksum is 0 (not set).
    #[must_use]
    pub fn verify_checksum(&self, raw: &[u8]) -> Option<bool> {
        if self.checksum == 0 {
            return None;
        }
        Some(compute_pe_checksum(raw) == self.checksum)
    }

    /// Return a security summary as a [`SecuritySummary`].
    #[must_use]
    pub fn security_summary(&self) -> SecuritySummary {
        SecuritySummary {
            aslr: AslrFlags {
                aslr: self.has_aslr(),
                high_entropy_va: self.dll_characteristics.has_high_entropy_va(),
            },
            protection: ProtectionFlags {
                nx: self.has_nx(),
                cfg: self.has_cfg(),
                no_seh: self.dll_characteristics.no_seh(),
            },
            integrity: IntegrityFlags {
                force_integrity: self.dll_characteristics.force_integrity(),
                appcontainer: self.dll_characteristics.is_appcontainer(),
                is_signed: self.is_signed(),
            },
            runtime: RuntimeFlags {
                has_tls: self.has_tls(),
                is_dotnet: self.is_dotnet(),
            },
        }
    }

    /// Return all imports whose DLL name contains the given substring (case-insensitive).
    #[must_use]
    pub fn imports_from_dll(&self, dll_fragment: &str) -> Vec<&PeImport> {
        let lower = dll_fragment.to_ascii_lowercase();
        self.imports
            .iter()
            .filter(|i| i.dll.to_ascii_lowercase().contains(&lower))
            .collect()
    }

    /// Return all exports whose name contains the given substring (case-insensitive).
    #[must_use]
    pub fn find_exports(&self, name_fragment: &str) -> Vec<&PeExport> {
        let lower = name_fragment.to_ascii_lowercase();
        self.exports
            .iter()
            .filter(|e| {
                e.name
                    .as_deref()
                    .is_some_and(|n| n.to_ascii_lowercase().contains(&lower))
            })
            .collect()
    }

    /// Return all imports whose function name contains the given substring
    /// (case-insensitive).
    #[must_use]
    pub fn find_imports(&self, name_fragment: &str) -> Vec<&PeImport> {
        let lower = name_fragment.to_ascii_lowercase();
        self.imports
            .iter()
            .filter(|i| {
                i.name
                    .as_deref()
                    .is_some_and(|n| n.to_ascii_lowercase().contains(&lower))
            })
            .collect()
    }

    /// Total number of imports across all DLLs.
    #[must_use]
    pub const fn import_count(&self) -> usize {
        self.imports.len()
    }

    /// Unique DLL names referenced in the import table.
    #[must_use]
    pub fn imported_dlls(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        self.imports
            .iter()
            .filter(|i| seen.insert(i.dll.as_str()))
            .map(|i| i.dll.as_str())
            .collect()
    }
}

impl fmt::Display for PeFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PE {} {} sections={} imports={} exports={}",
            self.machine,
            if self.is_dll { "DLL" } else { "EXE" },
            self.sections.len(),
            self.imports.len(),
            self.exports.len()
        )
    }
}

// ---------------------------------------------------------------------------
// SecuritySummary
// ---------------------------------------------------------------------------

/// ASLR-related security flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AslrFlags {
    /// ASLR (`DYNAMIC_BASE`) is enabled.
    pub aslr: bool,
    /// High-entropy 64-bit ASLR is enabled.
    pub high_entropy_va: bool,
}

/// Memory-protection security flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionFlags {
    /// NX / DEP (`NX_COMPAT`) is enabled.
    pub nx: bool,
    /// Control Flow Guard is enabled.
    pub cfg: bool,
    /// SEH is disabled (`NO_SEH`).
    pub no_seh: bool,
}

/// Code-integrity and isolation flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityFlags {
    /// Force integrity check is set.
    pub force_integrity: bool,
    /// `AppContainer` isolation is required.
    pub appcontainer: bool,
    /// A certificate (Authenticode) directory is present.
    pub is_signed: bool,
}

/// Runtime-metadata flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFlags {
    /// A TLS directory is present.
    pub has_tls: bool,
    /// .NET CLR runtime header is present.
    pub is_dotnet: bool,
}

/// High-level security feature summary for a PE image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecuritySummary {
    /// ASLR feature group.
    pub aslr: AslrFlags,
    /// Memory-protection feature group.
    pub protection: ProtectionFlags,
    /// Code-integrity and isolation feature group.
    pub integrity: IntegrityFlags,
    /// Runtime-metadata feature group.
    pub runtime: RuntimeFlags,
}

impl SecuritySummary {
    /// Returns a numeric "hardening score" 0–10 (one point per feature present).
    #[must_use]
    pub fn score(&self) -> u32 {
        u32::try_from(
            [
                self.aslr.aslr,
                self.aslr.high_entropy_va,
                self.protection.nx,
                self.protection.cfg,
                self.protection.no_seh,
                self.integrity.force_integrity,
                self.integrity.appcontainer,
                self.integrity.is_signed,
                !self.runtime.has_tls, // no TLS callbacks is slightly better from an attack surface view
                self.runtime.is_dotnet, // managed code has its own mitigations
            ]
            .iter()
            .filter(|&&v| v)
            .count(),
        )
        .unwrap_or(u32::MAX)
    }
}

impl fmt::Display for SecuritySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "score={} ASLR={} NX={} CFG={} signed={}",
            self.score(),
            self.aslr.aslr,
            self.protection.nx,
            self.protection.cfg,
            self.integrity.is_signed
        )
    }
}

// ---------------------------------------------------------------------------
// Shannon entropy helper
// ---------------------------------------------------------------------------

/// Compute Shannon entropy (bits) over a byte slice.  Returns 0.0 for empty input.
#[must_use]
pub fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / len;
            -p * p.log2()
        })
        .sum()
}

// ---------------------------------------------------------------------------
// PE checksum computation
// ---------------------------------------------------------------------------

/// Compute the standard PE checksum for a file image.
///
/// This is the algorithm used by `ImageNtHeaders->OptionalHeader.CheckSum` and
/// by `CheckSumMappedFile` in `imagehlp.dll`.
///
/// The checksum field itself (at a well-known offset inside the optional header)
/// is treated as zero during computation.
#[must_use]
pub fn compute_pe_checksum(data: &[u8]) -> u32 {
    // The checksum field is at pe_offset+24+64 (PE32+) or pe_offset+24+64 (PE32).
    // Easier: just zero those 4 bytes conceptually by computing around them.

    // Find the offset of the checksum field.
    let Some(checksum_offset) = find_checksum_offset(data) else {
        return 0;
    };

    let mut checksum: u64 = 0;
    let len = data.len();

    let mut i = 0usize;
    while i + 1 < len {
        // Skip the 4-byte checksum field: any word whose byte range overlaps
        // [checksum_offset, checksum_offset+4) is zeroed.  Using a range check
        // (rather than exact equality) handles the case where checksum_offset is
        // odd (malformed / fuzz input) without silently producing a wrong result.
        if i < checksum_offset + 4 && i + 2 > checksum_offset {
            i += 2;
            continue;
        }
        let word = u64::from(u16::from_le_bytes([data[i], data[i + 1]]));
        checksum += word;
        if checksum > 0xFFFF_FFFF {
            checksum = (checksum & 0xFFFF_FFFF) + (checksum >> 32);
        }
        i += 2;
    }
    if !len.is_multiple_of(2) {
        checksum += u64::from(data[len - 1]);
    }
    // Fold to 16 bits
    while checksum > 0xFFFF {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    u32::try_from((checksum + u64::try_from(len).unwrap_or(u64::MAX)) & 0xFFFF_FFFF)
        .unwrap_or(u32::MAX)
}

/// Returns the file offset of the PE checksum field, if parseable.
#[must_use]
fn find_checksum_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 64 {
        return None;
    }
    let pe_off = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if pe_off + 28 > data.len() {
        return None;
    }
    // Optional header starts at pe_off + 24; checksum is at +64 in both PE32 and PE32+
    Some(pe_off + 24 + 64)
}

// ---------------------------------------------------------------------------
// String reading helper
// ---------------------------------------------------------------------------

/// Read a NUL-terminated C string from `data` starting at `offset`.
#[must_use]
fn read_cstr(data: &[u8], offset: usize) -> String {
    let slice = &data[offset.min(data.len())..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// PeBuilder — minimal valid PE factory used in tests
// ---------------------------------------------------------------------------

/// Builds a minimal but structurally valid PE byte stream.
pub struct PeBuilder {
    machine: PeMachine,
    is_64bit: bool,
    sections: Vec<(String, Vec<u8>, u32)>,
    /// DLL characteristics to embed in the optional header.
    pub dll_characteristics: u16,
    /// Whether the output image is a DLL.
    pub is_dll: bool,
}

impl PeBuilder {
    /// Create a builder targeting AMD64 (PE32+).
    #[must_use]
    pub const fn new_x64() -> Self {
        Self {
            machine: PeMachine::Amd64,
            is_64bit: true,
            sections: vec![],
            dll_characteristics: 0,
            is_dll: false,
        }
    }

    /// Create a builder targeting i386 (PE32).
    #[must_use]
    pub const fn new_x86() -> Self {
        Self {
            machine: PeMachine::I386,
            is_64bit: false,
            sections: vec![],
            dll_characteristics: 0,
            is_dll: false,
        }
    }

    /// Enable ASLR + NX + high-entropy ASLR on the built image.
    pub const fn with_hardened_flags(&mut self) -> &mut Self {
        self.dll_characteristics |= DllCharacteristics::DYNAMIC_BASE
            | DllCharacteristics::NX_COMPAT
            | DllCharacteristics::HIGH_ENTROPY_VA;
        self
    }

    /// Add a section with the given name, data and characteristics flags.
    pub fn add_section(&mut self, name: &str, data: Vec<u8>, chars: u32) -> &mut Self {
        self.sections.push((name.to_string(), data, chars));
        self
    }

    /// Assemble and return a minimal valid PE byte stream.
    ///
    /// Layout:
    /// ```text
    /// [DOS header 64 bytes][PE signature 4][COFF 20][OptHdr][DataDirs 16×8][SectionTable N×40][Section data…]
    /// ```
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        const FILE_ALIGN: u32 = 0x200;
        const SECT_ALIGN: u32 = 0x1000;

        // Optional-header sizes
        let opt_hdr_size: u32 = if self.is_64bit { 240 } else { 224 };
        // Number of data-dir entries we emit (16 standard)
        let num_dirs: u32 = 16;

        let num_sections = u16::try_from(self.sections.len()).unwrap_or(u16::MAX);

        // PE header starts at offset 64 (right after DOS stub)
        let pe_offset: u32 = 64;
        // Section table starts right after: 4 (sig) + 20 (COFF) + opt_hdr_size
        let sect_table_offset = pe_offset + 4 + 20 + opt_hdr_size;
        // Raw data begins on next file-alignment boundary after the headers
        let headers_size = sect_table_offset + u32::from(num_sections) * 40;
        let raw_data_start = align_up(headers_size, FILE_ALIGN);

        // Pre-compute section layout
        let mut layout: Vec<(u32, u32, u32)> = Vec::new(); // (raw_offset, raw_size, va)
        let mut cur_raw = raw_data_start;
        let mut cur_va: u32 = SECT_ALIGN; // first section VA
        for (_, data, _) in &self.sections {
            let raw_sz = align_up(u32::try_from(data.len()).unwrap_or(u32::MAX), FILE_ALIGN);
            let virt_sz = align_up(u32::try_from(data.len()).unwrap_or(u32::MAX), SECT_ALIGN);
            layout.push((cur_raw, raw_sz, cur_va));
            cur_raw += raw_sz;
            cur_va += virt_sz;
        }
        let image_size = cur_va;

        // Machine value
        let machine_val: u16 = self.machine.to_value();

        let total_size = if layout.is_empty() {
            raw_data_start as usize
        } else {
            let (ro, rs, _) = layout[layout.len() - 1];
            (ro + rs) as usize
        };
        let mut buf = vec![0u8; total_size];

        // ----- DOS header -----
        buf[0] = 0x4D;
        buf[1] = 0x5A; // MZ
        // e_lfanew at offset 60
        buf[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        // ----- PE signature -----
        let p = pe_offset as usize;
        buf[p..p + 4].copy_from_slice(b"PE\0\0");

        // ----- COFF header (20 bytes at p+4) -----
        let c = p + 4;
        buf[c..c + 2].copy_from_slice(&machine_val.to_le_bytes());
        buf[c + 2..c + 4].copy_from_slice(&num_sections.to_le_bytes());
        // timestamp = 0
        // symbol table ptr = 0, num symbols = 0
        buf[c + 16..c + 18].copy_from_slice(
            &u16::try_from(opt_hdr_size)
                .unwrap_or(u16::MAX)
                .to_le_bytes(),
        );
        // characteristics: executable image (0x0002) + (large address aware 0x0020) + DLL bit
        let char_flags: u16 = 0x0022 | if self.is_dll { 0x2000 } else { 0 };
        buf[c + 18..c + 20].copy_from_slice(&char_flags.to_le_bytes());

        // ----- Optional header -----
        let o = p + 24;
        let magic: u16 = if self.is_64bit { 0x020B } else { 0x010B };
        buf[o..o + 2].copy_from_slice(&magic.to_le_bytes());
        // MajorLinkerVersion = 14
        buf[o + 2] = 14;
        // AddressOfEntryPoint
        let ep_rva: u32 = if layout.is_empty() { 0 } else { layout[0].2 };
        buf[o + 16..o + 20].copy_from_slice(&ep_rva.to_le_bytes());
        if self.is_64bit {
            // ImageBase (8 bytes at o+24)
            let image_base: u64 = 0x0000_0001_4000_0000;
            buf[o + 24..o + 32].copy_from_slice(&image_base.to_le_bytes());
            // SectionAlignment
            buf[o + 32..o + 36].copy_from_slice(&SECT_ALIGN.to_le_bytes());
            // FileAlignment
            buf[o + 36..o + 40].copy_from_slice(&FILE_ALIGN.to_le_bytes());
            // SizeOfImage
            buf[o + 56..o + 60].copy_from_slice(&image_size.to_le_bytes());
            // SizeOfHeaders
            buf[o + 60..o + 64].copy_from_slice(&raw_data_start.to_le_bytes());
            // Checksum = 0
            // Subsystem = 3 (CUI)
            buf[o + 68] = 3;
            // DllCharacteristics
            buf[o + 70..o + 72].copy_from_slice(&self.dll_characteristics.to_le_bytes());
            // NumberOfRvaAndSizes
            buf[o + 108..o + 112].copy_from_slice(&num_dirs.to_le_bytes());
        } else {
            // ImageBase (4 bytes at o+28)
            let image_base: u32 = 0x0040_0000;
            buf[o + 28..o + 32].copy_from_slice(&image_base.to_le_bytes());
            // SectionAlignment
            buf[o + 32..o + 36].copy_from_slice(&SECT_ALIGN.to_le_bytes());
            // FileAlignment
            buf[o + 36..o + 40].copy_from_slice(&FILE_ALIGN.to_le_bytes());
            // SizeOfImage
            buf[o + 56..o + 60].copy_from_slice(&image_size.to_le_bytes());
            // SizeOfHeaders
            buf[o + 60..o + 64].copy_from_slice(&raw_data_start.to_le_bytes());
            // Checksum = 0
            // Subsystem = 3 (CUI)
            buf[o + 68] = 3;
            // DllCharacteristics
            buf[o + 70..o + 72].copy_from_slice(&self.dll_characteristics.to_le_bytes());
            // NumberOfRvaAndSizes at o+92
            buf[o + 92..o + 96].copy_from_slice(&num_dirs.to_le_bytes());
        }

        // ----- Section table -----
        let st = sect_table_offset as usize;
        for (i, (name, data, chars)) in self.sections.iter().enumerate() {
            let (raw_off, raw_sz, va) = layout[i];
            let virt_sz = u32::try_from(data.len()).unwrap_or(u32::MAX);
            let off = st + i * 40;
            // Name (8 bytes)
            let name_bytes = name.as_bytes();
            let copy_len = name_bytes.len().min(8);
            buf[off..off + copy_len].copy_from_slice(&name_bytes[..copy_len]);
            // VirtualSize
            buf[off + 8..off + 12].copy_from_slice(&virt_sz.to_le_bytes());
            // VirtualAddress
            buf[off + 12..off + 16].copy_from_slice(&va.to_le_bytes());
            // SizeOfRawData
            buf[off + 16..off + 20].copy_from_slice(&raw_sz.to_le_bytes());
            // PointerToRawData
            buf[off + 20..off + 24].copy_from_slice(&raw_off.to_le_bytes());
            // Characteristics
            buf[off + 36..off + 40].copy_from_slice(&chars.to_le_bytes());
        }

        // ----- Section data -----
        for (i, (_, data, _)) in self.sections.iter().enumerate() {
            let (raw_off, _, _) = layout[i];
            let start = raw_off as usize;
            let end = start + data.len();
            buf[start..end].copy_from_slice(data);
        }

        buf
    }
}

impl fmt::Debug for PeBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeBuilder({:?} {})",
            self.machine,
            if self.is_64bit { "64" } else { "32" }
        )
    }
}

/// Align `value` up to the next multiple of `align`.
#[must_use]
pub const fn align_up(value: u32, align: u32) -> u32 {
    if align == 0 {
        return value;
    }
    value.saturating_add(align - 1) & !(align - 1)
}

// ---------------------------------------------------------------------------
// PeCache — thread-safe parsed PE cache (demonstrates parking_lot usage)
// ---------------------------------------------------------------------------

/// A simple thread-safe cache mapping file paths to parsed [`PeFile`] objects.
pub struct PeCache {
    inner: RwLock<HashMap<String, PeFile>>,
}

impl PeCache {
    /// Create an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Insert a parsed PE into the cache under `key`.
    pub fn insert(&self, key: String, pe: PeFile) {
        self.inner.write().insert(key, pe);
    }

    /// Retrieve a clone of a cached PE by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<PeFile> {
        self.inner.read().get(key).cloned()
    }

    /// Remove and return a cached PE by key.
    #[must_use]
    pub fn remove(&self, key: &str) -> Option<PeFile> {
        self.inner.write().remove(key)
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.inner.write().clear();
    }

    /// Number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Returns `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    /// Return all cached keys as a sorted `Vec<String>`.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.inner.read().keys().cloned().collect();
        keys.sort();
        keys
    }
}

impl Default for PeCache {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PeCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeCache({})", self.len())
    }
}

// ---------------------------------------------------------------------------
// PeScanResult — quick classification result
// ---------------------------------------------------------------------------

/// The result of a quick structural scan of a PE file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeScanResult {
    /// Detected machine architecture.
    pub machine: PeMachine,
    /// Whether it appears packed (any section entropy > 7.0).
    pub likely_packed: bool,
    /// Highest section entropy value found.
    pub max_entropy: f64,
    /// Names of high-entropy (packed) sections.
    pub packed_section_names: Vec<String>,
    /// Number of unique imported DLLs.
    pub dll_count: usize,
    /// Total import count.
    pub import_count: usize,
    /// Total export count.
    pub export_count: usize,
    /// Whether an overlay was detected.
    pub has_overlay: bool,
    /// Security summary.
    pub security: SecuritySummary,
}

impl fmt::Display for PeScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "machine={} packed={} max_entropy={:.2} dlls={} security=[{}]",
            self.machine, self.likely_packed, self.max_entropy, self.dll_count, self.security
        )
    }
}

/// Perform a quick scan of a PE and return a [`PeScanResult`].
///
/// # Errors
///
/// Returns [`PeError`] if the file cannot be parsed.
pub fn scan_pe(data: &[u8]) -> Result<PeScanResult, PeError> {
    let mut pe = PeFile::parse(data)?;
    let _ = pe.parse_imports(data);
    let _ = pe.parse_exports(data);

    let max_entropy = pe
        .sections
        .iter()
        .map(PeSection::entropy)
        .fold(0.0f64, f64::max);
    let likely_packed = max_entropy > 7.0;
    let packed_section_names = pe
        .sections
        .iter()
        .filter(|s| s.is_likely_packed())
        .map(|s| s.name.clone())
        .collect();
    let dll_count = pe.imported_dlls().len();
    let import_count = pe.import_count();
    let export_count = pe.exports.len();
    let has_overlay = pe.overlay.is_some();
    let security = pe.security_summary();

    Ok(PeScanResult {
        machine: pe.machine,
        likely_packed,
        max_entropy,
        packed_section_names,
        dll_count,
        import_count,
        export_count,
        has_overlay,
        security,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- helpers -----------------------------------------------------------

    fn minimal_x64_pe() -> Vec<u8> {
        let mut b = PeBuilder::new_x64();
        b.add_section(".text", vec![0x90u8; 16], 0x6000_0020);
        b.add_section(".data", vec![0u8; 8], 0xC000_0040);
        b.build()
    }

    fn minimal_x86_pe() -> Vec<u8> {
        let mut b = PeBuilder::new_x86();
        b.add_section(".text", vec![0xCCu8; 32], 0x6000_0020);
        b.build()
    }

    fn empty_section_pe() -> Vec<u8> {
        PeBuilder::new_x64().build()
    }

    fn hardened_x64_pe() -> Vec<u8> {
        let mut b = PeBuilder::new_x64();
        b.with_hardened_flags();
        b.add_section(".text", vec![0x90u8; 64], 0x6000_0020);
        b.build()
    }

    // ---- PeError display ---------------------------------------------------

    #[test]
    fn test_pe_error_not_pe() {
        let e = PeError::NotPe(0x1234);
        assert!(e.to_string().contains("bad magic"));
    }

    #[test]
    fn test_pe_error_too_short() {
        let e = PeError::TooShort {
            needed: 100,
            got: 10,
        };
        assert!(e.to_string().contains("need 100"));
    }

    #[test]
    fn test_pe_error_invalid_header() {
        let e = PeError::InvalidHeader("test".to_string());
        assert!(e.to_string().contains("test"));
    }

    #[test]
    fn test_pe_error_section_not_found() {
        let e = PeError::SectionNotFound(".bss".to_string());
        assert!(e.to_string().contains(".bss"));
    }

    #[test]
    fn test_pe_error_import_corrupt() {
        let e = PeError::ImportTableCorrupt;
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_pe_error_export_corrupt() {
        let e = PeError::ExportTableCorrupt;
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_pe_error_resource_not_found() {
        let e = PeError::ResourceNotFound("RT_ICON".to_string());
        assert!(e.to_string().contains("RT_ICON"));
    }

    // ---- PeMachine ---------------------------------------------------------

    #[test]
    fn test_machine_from_value_known() {
        assert_eq!(PeMachine::from_value(0x014c), PeMachine::I386);
        assert_eq!(PeMachine::from_value(0x8664), PeMachine::Amd64);
        assert_eq!(PeMachine::from_value(0xaa64), PeMachine::Arm64);
        assert_eq!(PeMachine::from_value(0x01c4), PeMachine::Arm);
        assert_eq!(PeMachine::from_value(0x0166), PeMachine::Mips32);
        assert_eq!(PeMachine::from_value(0x5032), PeMachine::Riscv32);
        assert_eq!(PeMachine::from_value(0x5064), PeMachine::Riscv64);
        assert_eq!(PeMachine::from_value(0x0200), PeMachine::Ia64);
    }

    #[test]
    fn test_machine_from_value_unknown() {
        assert_eq!(PeMachine::from_value(0xFFFF), PeMachine::Unknown);
    }

    #[test]
    fn test_machine_pointer_size() {
        assert_eq!(PeMachine::Amd64.pointer_size(), 8);
        assert_eq!(PeMachine::Arm64.pointer_size(), 8);
        assert_eq!(PeMachine::Ia64.pointer_size(), 8);
        assert_eq!(PeMachine::Riscv64.pointer_size(), 8);
        assert_eq!(PeMachine::I386.pointer_size(), 4);
        assert_eq!(PeMachine::Arm.pointer_size(), 4);
    }

    #[test]
    fn test_machine_display() {
        assert_eq!(PeMachine::Amd64.to_string(), "x86_64");
        assert_eq!(PeMachine::I386.to_string(), "i386");
        assert_eq!(PeMachine::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_machine_is_64bit() {
        assert!(PeMachine::Amd64.is_64bit());
        assert!(PeMachine::Arm64.is_64bit());
        assert!(!PeMachine::I386.is_64bit());
        assert!(!PeMachine::Arm.is_64bit());
    }

    #[test]
    fn test_machine_roundtrip_value() {
        for m in [
            PeMachine::I386,
            PeMachine::Amd64,
            PeMachine::Arm,
            PeMachine::Arm64,
            PeMachine::Mips32,
            PeMachine::Riscv32,
            PeMachine::Riscv64,
            PeMachine::Ia64,
        ] {
            assert_eq!(PeMachine::from_value(m.to_value()), m);
        }
    }

    // ---- PeSubsystem -------------------------------------------------------

    #[test]
    fn test_subsystem_from_value() {
        assert_eq!(PeSubsystem::from_value(2), PeSubsystem::WindowsGui);
        assert_eq!(PeSubsystem::from_value(3), PeSubsystem::WindowsCui);
        assert_eq!(PeSubsystem::from_value(10), PeSubsystem::EfiApplication);
        assert_eq!(PeSubsystem::from_value(0xFF), PeSubsystem::Unknown);
    }

    #[test]
    fn test_subsystem_display() {
        let s = PeSubsystem::WindowsGui.to_string();
        assert!(!s.is_empty());
    }

    #[test]
    fn test_subsystem_is_console() {
        assert!(PeSubsystem::WindowsCui.is_console());
        assert!(PeSubsystem::PosixCui.is_console());
        assert!(!PeSubsystem::WindowsGui.is_console());
    }

    #[test]
    fn test_subsystem_is_efi() {
        assert!(PeSubsystem::EfiApplication.is_efi());
        assert!(PeSubsystem::EfiBootDriver.is_efi());
        assert!(PeSubsystem::EfiRuntimeDriver.is_efi());
        assert!(!PeSubsystem::WindowsGui.is_efi());
    }

    #[test]
    fn test_subsystem_roundtrip() {
        for sub in [
            PeSubsystem::Unknown,
            PeSubsystem::Native,
            PeSubsystem::WindowsGui,
            PeSubsystem::WindowsCui,
            PeSubsystem::PosixCui,
            PeSubsystem::EfiApplication,
            PeSubsystem::EfiBootDriver,
            PeSubsystem::EfiRuntimeDriver,
            PeSubsystem::Xbox,
        ] {
            assert_eq!(PeSubsystem::from_value(sub.to_value()), sub);
        }
    }

    // ---- DllCharacteristics ------------------------------------------------

    #[test]
    fn test_dll_chars_flags() {
        let dc =
            DllCharacteristics(DllCharacteristics::DYNAMIC_BASE | DllCharacteristics::NX_COMPAT);
        assert!(dc.has_aslr());
        assert!(dc.has_nx());
        assert!(!dc.has_cfg());
        assert!(!dc.no_seh());
    }

    #[test]
    fn test_dll_chars_flag_names() {
        let dc = DllCharacteristics(
            DllCharacteristics::DYNAMIC_BASE
                | DllCharacteristics::NX_COMPAT
                | DllCharacteristics::GUARD_CF,
        );
        let names = dc.flag_names();
        assert!(names.contains(&"DYNAMIC_BASE"));
        assert!(names.contains(&"NX_COMPAT"));
        assert!(names.contains(&"GUARD_CF"));
        assert!(!names.contains(&"APPCONTAINER"));
    }

    #[test]
    fn test_dll_chars_display() {
        let dc = DllCharacteristics(DllCharacteristics::DYNAMIC_BASE);
        let s = dc.to_string();
        assert!(s.contains("DYNAMIC_BASE"));
    }

    // ---- PeBuilder / PeFile::parse roundtrip -------------------------------

    #[test]
    fn test_parse_x64_pe() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).expect("should parse");
        assert_eq!(pe.machine, PeMachine::Amd64);
        assert!(pe.is_64bit);
        assert!(!pe.is_dll);
        assert_eq!(pe.sections.len(), 2);
    }

    #[test]
    fn test_parse_x86_pe() {
        let bytes = minimal_x86_pe();
        let pe = PeFile::parse(&bytes).expect("should parse x86");
        assert_eq!(pe.machine, PeMachine::I386);
        assert!(!pe.is_64bit);
    }

    #[test]
    fn test_parse_no_sections() {
        let bytes = empty_section_pe();
        let pe = PeFile::parse(&bytes).expect("empty-section pe");
        assert_eq!(pe.sections.len(), 0);
    }

    #[test]
    fn test_parse_bad_magic() {
        let mut bytes = minimal_x64_pe();
        bytes[0] = 0xFF; // corrupt MZ
        let err = PeFile::parse(&bytes).expect_err("should fail");
        assert!(matches!(err, PeError::NotPe(_)));
    }

    #[test]
    fn test_parse_too_short() {
        let err = PeFile::parse(&[0u8; 10]).expect_err("too short");
        assert!(matches!(err, PeError::TooShort { .. }));
    }

    #[test]
    fn test_section_names() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        let names = pe.section_names();
        assert!(names.contains(&".text"));
        assert!(names.contains(&".data"));
    }

    #[test]
    fn test_section_by_name_found() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(pe.section_by_name(".text").is_some());
    }

    #[test]
    fn test_section_by_name_missing() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(pe.section_by_name(".bss").is_none());
    }

    #[test]
    fn test_section_at_rva() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        // First section starts at VA 0x1000
        let s = pe.section_at_rva(0x1000);
        assert!(s.is_some());
    }

    #[test]
    fn test_rva_to_offset() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        let off = pe.rva_to_offset(0x1000);
        assert!(off.is_some());
    }

    #[test]
    fn test_section_flags() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        let text = pe.section_by_name(".text").unwrap();
        assert!(text.is_executable()); // 0x6000_0020 has CODE+EXECUTE bits
        let data = pe.section_by_name(".data").unwrap();
        assert!(data.is_writable()); // 0xC000_0040 has WRITE+READ bits
    }

    #[test]
    fn test_section_display() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        let s = pe.section_by_name(".text").unwrap();
        assert!(s.to_string().contains(".text"));
    }

    #[test]
    fn test_overall_entropy() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        let e = pe.overall_entropy();
        assert!((0.0..=8.0).contains(&e));
    }

    #[test]
    fn test_section_entropy() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        let e = pe.section_by_name(".text").unwrap().entropy();
        assert!((0.0..=8.0).contains(&e));
    }

    #[test]
    fn test_pe_size() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(pe.size() > 0);
    }

    #[test]
    fn test_pe_display() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        let s = pe.to_string();
        assert!(s.contains("PE"));
        assert!(s.contains("sections=2"));
    }

    #[test]
    fn test_imports_by_dll_empty() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(pe.imports_by_dll().is_empty());
    }

    #[test]
    fn test_to_json() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        let j = pe.to_json().unwrap();
        assert!(j.contains("machine"));
    }

    #[test]
    fn test_has_aslr_nx_default_zero() {
        // Builder sets dll_characteristics = 0 by default
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        // No flags set → ASLR and NX are false
        assert!(!pe.has_aslr());
        assert!(!pe.has_nx());
    }

    #[test]
    fn test_hardened_pe_flags() {
        let bytes = hardened_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(pe.has_aslr());
        assert!(pe.has_nx());
        assert!(pe.dll_characteristics.has_high_entropy_va());
    }

    #[test]
    fn test_data_dir() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        // data_dir(0) may be present or absent depending on section count
        let _ = pe.data_dir(0);
    }

    #[test]
    fn test_import_display() {
        let imp = PeImport {
            dll: "kernel32.dll".to_string(),
            name: Some("CreateFile".to_string()),
            ordinal: None,
            hint: 0,
            iat_rva: 0x1234,
        };
        assert_eq!(imp.to_string(), "kernel32.dll!CreateFile");

        let imp_ord = PeImport {
            dll: "ntdll.dll".to_string(),
            name: None,
            ordinal: Some(5),
            hint: 0,
            iat_rva: 0x5678,
        };
        assert!(imp_ord.to_string().contains("ord#5"));
    }

    #[test]
    fn test_export_display() {
        let exp = PeExport {
            name: Some("MyFunc".to_string()),
            ordinal: 1,
            rva: 0x1000,
            forwarder: None,
        };
        assert!(exp.to_string().contains("MyFunc"));
    }

    #[test]
    fn test_data_dir_display() {
        let d = DataDir {
            rva: 0x1000,
            size: 0x200,
        };
        assert!(d.to_string().contains("RVA="));
    }

    #[test]
    fn test_data_dir_is_present() {
        let present = DataDir {
            rva: 0x1000,
            size: 0x200,
        };
        assert!(present.is_present());
        let absent = DataDir { rva: 0, size: 0 };
        assert!(!absent.is_present());
    }

    #[test]
    fn test_compute_entropy_empty() {
        assert!(compute_entropy(&[]).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_entropy_uniform() {
        let data = vec![0x41u8; 256];
        assert!(compute_entropy(&data).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_entropy_max() {
        // All 256 values present exactly once — maximum entropy = 8 bits
        let data: Vec<u8> = (0u8..=255u8).collect();
        let e = compute_entropy(&data);
        assert!((7.9..=8.1).contains(&e));
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 0x200), 0);
        assert_eq!(align_up(1, 0x200), 0x200);
        assert_eq!(align_up(0x200, 0x200), 0x200);
        assert_eq!(align_up(0x201, 0x200), 0x400);
    }

    #[test]
    fn test_pe_cache() {
        let cache = PeCache::new();
        assert!(cache.is_empty());
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        cache.insert("test.exe".to_string(), pe);
        assert_eq!(cache.len(), 1);
        assert!(cache.get("test.exe").is_some());
        assert!(cache.get("missing").is_none());
    }

    #[test]
    fn test_pe_builder_debug() {
        let b = PeBuilder::new_x64();
        assert!(format!("{b:?}").contains("64"));
    }

    #[test]
    fn test_pe_cache_debug() {
        let cache = PeCache::default();
        assert!(format!("{cache:?}").contains("PeCache"));
    }

    // ---- new tests added in the expansion ----------------------------------

    #[test]
    fn test_pe_cache_remove() {
        let cache = PeCache::new();
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        cache.insert("a.exe".to_string(), pe.clone());
        cache.insert("b.exe".to_string(), pe);
        assert_eq!(cache.len(), 2);
        let removed = cache.remove("a.exe");
        assert!(removed.is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_pe_cache_clear() {
        let cache = PeCache::new();
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        cache.insert("x.exe".to_string(), pe);
        assert!(!cache.is_empty());
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_pe_cache_keys() {
        let cache = PeCache::new();
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        cache.insert("z.exe".to_string(), pe.clone());
        cache.insert("a.exe".to_string(), pe);
        let keys = cache.keys();
        assert_eq!(keys, vec!["a.exe", "z.exe"]);
    }

    #[test]
    fn test_section_permission_string() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        let text = pe.section_by_name(".text").unwrap();
        let perm = text.permission_string();
        assert_eq!(perm.len(), 3);
        assert!(perm.contains('x'));
    }

    #[test]
    fn test_section_contains_code() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        let text = pe.section_by_name(".text").unwrap();
        // 0x6000_0020 = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
        assert!(text.contains_code());
    }

    #[test]
    fn test_section_most_common_byte() {
        let sec = PeSection {
            name: ".test".to_string(),
            virtual_address: 0x1000,
            virtual_size: 8,
            raw_offset: 0x200,
            raw_size: 8,
            characteristics: 0,
            data: vec![0xCC, 0xCC, 0xCC, 0x90, 0x90, 0x00, 0x00, 0x00],
        };
        assert_eq!(sec.most_common_byte(), Some(0xCC));
    }

    #[test]
    fn test_section_count_byte() {
        let sec = PeSection {
            name: ".test".to_string(),
            virtual_address: 0x1000,
            virtual_size: 4,
            raw_offset: 0x200,
            raw_size: 4,
            characteristics: 0,
            data: vec![0x90, 0x90, 0x90, 0xCC],
        };
        assert_eq!(sec.count_byte(0x90), 3);
        assert_eq!(sec.count_byte(0xCC), 1);
        assert_eq!(sec.count_byte(0x00), 0);
    }

    #[test]
    fn test_section_byte_histogram_sum() {
        let sec = PeSection {
            name: ".test".to_string(),
            virtual_address: 0x1000,
            virtual_size: 4,
            raw_offset: 0x200,
            raw_size: 4,
            characteristics: 0,
            data: vec![0x00, 0x01, 0x02, 0x03],
        };
        let hist = sec.byte_histogram();
        let total: u64 = hist.iter().sum();
        assert_eq!(total, 4);
    }

    #[test]
    fn test_section_most_common_byte_empty() {
        let sec = PeSection {
            name: ".empty".to_string(),
            virtual_address: 0,
            virtual_size: 0,
            raw_offset: 0,
            raw_size: 0,
            characteristics: 0,
            data: vec![],
        };
        assert_eq!(sec.most_common_byte(), None);
    }

    #[test]
    fn test_highest_entropy_section() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        // With the nop sled, both sections have low entropy but the method
        // should return Some.
        assert!(pe.highest_entropy_section().is_some());
    }

    #[test]
    fn test_packed_sections_none_for_low_entropy() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        // nop sled has zero entropy — no packed sections expected
        assert!(pe.packed_sections().is_empty());
    }

    #[test]
    fn test_packed_sections_detected() {
        // Create a section with near-random data (high entropy)
        let mut rng_data = Vec::with_capacity(4096);
        let mut lcg: u64 = 0xDEAD_BEEF_1234_5678;
        for _ in 0..4096 {
            lcg = lcg
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            rng_data.push(u8::try_from((lcg >> 33) & 0xFF).unwrap_or(0));
        }
        let mut b = PeBuilder::new_x64();
        b.add_section(".pack", rng_data, 0x6000_0020);
        let bytes = b.build();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(!pe.packed_sections().is_empty());
    }

    #[test]
    fn test_is_dotnet_false() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(!pe.is_dotnet());
    }

    #[test]
    fn test_is_signed_false() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(!pe.is_signed());
    }

    #[test]
    fn test_has_relocations_false() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(!pe.has_relocations());
    }

    #[test]
    fn test_has_tls_false() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(!pe.has_tls());
    }

    #[test]
    fn test_security_summary_hardened() {
        let bytes = hardened_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        let ss = pe.security_summary();
        assert!(ss.aslr.aslr);
        assert!(ss.protection.nx);
        assert!(ss.aslr.high_entropy_va);
        assert!(!ss.protection.cfg);
    }

    #[test]
    fn test_security_summary_score() {
        let bytes = hardened_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        let ss = pe.security_summary();
        // aslr + nx + high_entropy_va = at least 3
        assert!(ss.score() >= 3);
    }

    #[test]
    fn test_security_summary_display() {
        let bytes = hardened_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        let s = pe.security_summary().to_string();
        assert!(s.contains("score="));
        assert!(s.contains("ASLR=true"));
    }

    #[test]
    fn test_parse_imports_no_import_dir() {
        let bytes = minimal_x64_pe();
        let mut pe = PeFile::parse(&bytes).unwrap();
        // No import directory set → should succeed with empty list
        let result = pe.parse_imports(&bytes);
        assert!(result.is_ok());
        assert!(pe.imports.is_empty());
    }

    #[test]
    fn test_parse_exports_no_export_dir() {
        let bytes = minimal_x64_pe();
        let mut pe = PeFile::parse(&bytes).unwrap();
        let result = pe.parse_exports(&bytes);
        assert!(result.is_ok());
        assert!(pe.exports.is_empty());
    }

    #[test]
    fn test_imported_dlls_empty() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(pe.imported_dlls().is_empty());
    }

    #[test]
    fn test_import_count_with_manual_entries() {
        let bytes = minimal_x64_pe();
        let mut pe = PeFile::parse(&bytes).unwrap();
        pe.imports.push(PeImport {
            dll: "kernel32.dll".to_string(),
            name: Some("VirtualAlloc".to_string()),
            ordinal: None,
            hint: 1,
            iat_rva: 0x3000,
        });
        pe.imports.push(PeImport {
            dll: "kernel32.dll".to_string(),
            name: Some("VirtualFree".to_string()),
            ordinal: None,
            hint: 2,
            iat_rva: 0x3008,
        });
        assert_eq!(pe.import_count(), 2);
        assert_eq!(pe.imported_dlls(), vec!["kernel32.dll"]);
    }

    #[test]
    fn test_find_imports() {
        let bytes = minimal_x64_pe();
        let mut pe = PeFile::parse(&bytes).unwrap();
        pe.imports.push(PeImport {
            dll: "kernel32.dll".to_string(),
            name: Some("CreateFile".to_string()),
            ordinal: None,
            hint: 0,
            iat_rva: 0x3000,
        });
        pe.imports.push(PeImport {
            dll: "ntdll.dll".to_string(),
            name: Some("NtQuerySystemInformation".to_string()),
            ordinal: None,
            hint: 0,
            iat_rva: 0x3008,
        });
        let found = pe.find_imports("createfile");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name.as_deref(), Some("CreateFile"));
    }

    #[test]
    fn test_imports_from_dll() {
        let bytes = minimal_x64_pe();
        let mut pe = PeFile::parse(&bytes).unwrap();
        pe.imports.push(PeImport {
            dll: "kernel32.dll".to_string(),
            name: Some("ExitProcess".to_string()),
            ordinal: None,
            hint: 0,
            iat_rva: 0x3000,
        });
        pe.imports.push(PeImport {
            dll: "ntdll.dll".to_string(),
            name: Some("NtClose".to_string()),
            ordinal: None,
            hint: 0,
            iat_rva: 0x3008,
        });
        let k32 = pe.imports_from_dll("kernel32");
        assert_eq!(k32.len(), 1);
        assert_eq!(k32[0].name.as_deref(), Some("ExitProcess"));
    }

    #[test]
    fn test_find_exports() {
        let bytes = minimal_x64_pe();
        let mut pe = PeFile::parse(&bytes).unwrap();
        pe.exports.push(PeExport {
            name: Some("GetProcAddress".to_string()),
            ordinal: 1,
            rva: 0x1100,
            forwarder: None,
        });
        pe.exports.push(PeExport {
            name: Some("LoadLibraryA".to_string()),
            ordinal: 2,
            rva: 0x1200,
            forwarder: None,
        });
        let found = pe.find_exports("getproc");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name.as_deref(), Some("GetProcAddress"));
    }

    #[test]
    fn test_verify_checksum_zero_returns_none() {
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        // builder leaves checksum = 0
        assert_eq!(pe.checksum, 0);
        assert!(pe.verify_checksum(&bytes).is_none());
    }

    #[test]
    fn test_compute_pe_checksum_returns_u32() {
        let bytes = minimal_x64_pe();
        let cs = compute_pe_checksum(&bytes);
        // Just verify it doesn't panic and returns something
        let _ = cs;
    }

    #[test]
    fn test_scan_pe_minimal() {
        let bytes = minimal_x64_pe();
        let result = scan_pe(&bytes).unwrap();
        assert_eq!(result.machine, PeMachine::Amd64);
        assert!(!result.likely_packed);
        assert!(!result.has_overlay);
        assert_eq!(result.import_count, 0);
    }

    #[test]
    fn test_scan_pe_result_display() {
        let bytes = minimal_x64_pe();
        let result = scan_pe(&bytes).unwrap();
        let s = result.to_string();
        assert!(s.contains("machine="));
        assert!(s.contains("packed="));
    }

    #[test]
    fn test_scan_pe_packed_detected() {
        let mut rng_data = Vec::with_capacity(4096);
        let mut lcg: u64 = 0xCAFE_BABE_DEAD_BEEF;
        for _ in 0..4096 {
            lcg = lcg
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            rng_data.push(u8::try_from((lcg >> 33) & 0xFF).unwrap_or(0));
        }
        let mut b = PeBuilder::new_x64();
        b.add_section(".pack", rng_data, 0x6000_0020);
        let bytes = b.build();
        let result = scan_pe(&bytes).unwrap();
        assert!(result.likely_packed);
        assert!(result.max_entropy > 7.0);
        assert!(!result.packed_section_names.is_empty());
    }

    #[test]
    fn test_overlay_detection() {
        let mut bytes = minimal_x64_pe();
        // Append an "overlay"
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(pe.overlay.is_some());
        let ov = pe.overlay.as_ref().unwrap();
        assert_eq!(ov, &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_rich_header_no_rich_in_minimal() {
        // Our minimal builder doesn't produce a Rich header
        let bytes = minimal_x64_pe();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(pe.rich_header.is_none());
    }

    #[test]
    fn test_rich_entry_display() {
        let e = RichEntry {
            product_id: 0x00FF,
            build_number: 1234,
            count: 3,
        };
        let s = e.to_string();
        assert!(s.contains("product="));
        assert!(s.contains("build=1234"));
        assert!(s.contains("count=3"));
    }

    #[test]
    fn test_read_cstr() {
        let data = b"hello\x00world";
        assert_eq!(read_cstr(data, 0), "hello");
        assert_eq!(read_cstr(data, 6), "world");
    }

    #[test]
    fn test_read_cstr_no_null() {
        let data = b"abc";
        assert_eq!(read_cstr(data, 0), "abc");
    }

    #[test]
    fn test_dll_chars_appcontainer() {
        let dc = DllCharacteristics(DllCharacteristics::APPCONTAINER);
        assert!(dc.is_appcontainer());
        let names = dc.flag_names();
        assert!(names.contains(&"APPCONTAINER"));
    }

    #[test]
    fn test_dll_chars_no_seh() {
        let dc = DllCharacteristics(DllCharacteristics::NO_SEH);
        assert!(dc.no_seh());
    }

    #[test]
    fn test_dll_chars_force_integrity() {
        let dc = DllCharacteristics(DllCharacteristics::FORCE_INTEGRITY);
        assert!(dc.force_integrity());
    }

    #[test]
    fn test_dll_builder_with_dll_flag() {
        let mut b = PeBuilder::new_x64();
        b.is_dll = true;
        b.add_section(".text", vec![0x90u8; 16], 0x6000_0020);
        let bytes = b.build();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(pe.is_dll);
    }

    #[test]
    fn test_data_dir_index_constants() {
        assert_eq!(data_dir_index::EXPORT, 0);
        assert_eq!(data_dir_index::IMPORT, 1);
        assert_eq!(data_dir_index::SECURITY, 4);
        assert_eq!(data_dir_index::TLS, 9);
        assert_eq!(data_dir_index::COM_DESCRIPTOR, 14);
    }

    #[test]
    fn test_section_is_not_packed_for_zeros() {
        let sec = PeSection {
            name: ".bss".to_string(),
            virtual_address: 0x1000,
            virtual_size: 64,
            raw_offset: 0x200,
            raw_size: 64,
            characteristics: 0xC000_0040,
            data: vec![0u8; 64],
        };
        assert!(!sec.is_likely_packed());
        assert!(sec.entropy().abs() < f64::EPSILON);
    }

    #[test]
    fn test_section_is_discardable() {
        let sec = PeSection {
            name: ".reloc".to_string(),
            virtual_address: 0x5000,
            virtual_size: 16,
            raw_offset: 0x600,
            raw_size: 16,
            // IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ
            characteristics: 0x0200_0000 | 0x4000_0000,
            data: vec![0u8; 16],
        };
        assert!(sec.is_discardable());
        assert!(sec.is_readable());
    }

    #[test]
    fn test_align_up_zero_align() {
        assert_eq!(align_up(7, 0), 7);
    }

    #[test]
    fn test_align_up_power_of_two() {
        assert_eq!(align_up(4095, 4096), 4096);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
    }
}
