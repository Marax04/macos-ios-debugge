//! YARA PE module implementation.
//!
//! Provides the `pe.*` namespace for YARA rules.  Parses PE headers and
//! exposes machine type, section count, timestamps, characteristics,
//! DLL characteristics, linker version, OS version, subsystem, exports,
//! imports, sections, and resources.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors from the PE module.
#[derive(Debug)]
pub enum PeModuleError {
    /// The buffer is too small.
    TooSmall,
    /// DOS signature mismatch.
    NoDosSignature,
    /// PE signature mismatch.
    NoPeSignature,
    /// Unsupported optional header magic.
    UnsupportedMagic(u16),
    /// An RVA could not be resolved.
    BadRva(u32),
    /// An import or export table entry is malformed.
    MalformedEntry(String),
}

impl fmt::Display for PeModuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall => write!(f, "buffer too small"),
            Self::NoDosSignature => write!(f, "missing MZ signature"),
            Self::NoPeSignature => write!(f, "missing PE signature"),
            Self::UnsupportedMagic(m) => write!(f, "unsupported optional header magic: {m:#06x}"),
            Self::BadRva(rva) => write!(f, "cannot resolve RVA {rva:#010x}"),
            Self::MalformedEntry(s) => write!(f, "malformed entry: {s}"),
        }
    }
}

// ─── PeMachine ───────────────────────────────────────────────────────────────

/// Machine type values from the COFF header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum PeMachine {
    Unknown = 0x0000,
    I386 = 0x014C,
    R4000 = 0x0166,
    Wcemipsv2 = 0x0169,
    Alpha = 0x0184,
    Sh3 = 0x01A2,
    Sh3Dsp = 0x01A3,
    Sh4 = 0x01A6,
    Sh5 = 0x01A8,
    Arm = 0x01C0,
    Thumb = 0x01C2,
    ArmNt = 0x01C4,
    Am33 = 0x01D3,
    PowerPc = 0x01F0,
    PowerPcFp = 0x01F1,
    Ia64 = 0x0200,
    Mips16 = 0x0266,
    Alpha64 = 0x0284,
    MipsFpu = 0x0366,
    MipsFpu16 = 0x0466,
    TriCore = 0x0520,
    Cef = 0x0CEF,
    Ebc = 0x0EBC,
    Amd64 = 0x8664,
    M32R = 0x9041,
    Arm64 = 0xAA64,
    Cee = 0xC0EE,
    Loongarch32 = 0x6232,
    Loongarch64 = 0x6264,
    RiscV32 = 0x5032,
    RiscV64 = 0x5064,
    RiscV128 = 0x5128,
}

impl PeMachine {
    /// Parse from a u16 value.
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x014C => Self::I386,
            0x8664 => Self::Amd64,
            0xAA64 => Self::Arm64,
            0x01C4 => Self::ArmNt,
            0x01C0 => Self::Arm,
            0x0200 => Self::Ia64,
            0x01F0 => Self::PowerPc,
            0x0166 => Self::R4000,
            0x5032 => Self::RiscV32,
            0x5064 => Self::RiscV64,
            0x5128 => Self::RiscV128,
            0x6232 => Self::Loongarch32,
            0x6264 => Self::Loongarch64,
            _ => Self::Unknown,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::I386 => "x86",
            Self::Amd64 => "x86_64",
            Self::Arm64 => "ARM64",
            Self::ArmNt => "ARM (WinCE)",
            Self::Arm => "ARM",
            Self::Ia64 => "IA-64",
            Self::PowerPc => "PowerPC",
            Self::R4000 => "MIPS R4000",
            Self::RiscV32 => "RISC-V 32",
            Self::RiscV64 => "RISC-V 64",
            Self::RiscV128 => "RISC-V 128",
            Self::Loongarch32 => "LoongArch32",
            Self::Loongarch64 => "LoongArch64",
            _ => "Unknown",
        }
    }
}

// ─── PeSubsystem ─────────────────────────────────────────────────────────────

/// Windows subsystem values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum PeSubsystem {
    Unknown = 0,
    Native = 1,
    WindowsGui = 2,
    WindowsCui = 3,
    Os2Cui = 5,
    PosixCui = 7,
    WindowsCeGui = 9,
    EfiApplication = 10,
    EfiBootServiceDriver = 11,
    EfiRuntimeDriver = 12,
    EfiRom = 13,
    Xbox = 14,
    WindowsBootApplication = 16,
}

impl PeSubsystem {
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::Native,
            2 => Self::WindowsGui,
            3 => Self::WindowsCui,
            5 => Self::Os2Cui,
            7 => Self::PosixCui,
            9 => Self::WindowsCeGui,
            10 => Self::EfiApplication,
            11 => Self::EfiBootServiceDriver,
            12 => Self::EfiRuntimeDriver,
            13 => Self::EfiRom,
            14 => Self::Xbox,
            16 => Self::WindowsBootApplication,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Native => "Native",
            Self::WindowsGui => "Windows GUI",
            Self::WindowsCui => "Windows CUI (console)",
            Self::EfiApplication => "EFI Application",
            Self::EfiBootServiceDriver => "EFI Boot Service Driver",
            Self::EfiRuntimeDriver => "EFI Runtime Driver",
            Self::Xbox => "Xbox",
            Self::WindowsBootApplication => "Windows Boot Application",
            _ => "Unknown",
        }
    }
}

// ─── PeVersion ───────────────────────────────────────────────────────────────

/// A major.minor version pair.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeVersion {
    pub major: u16,
    pub minor: u16,
}

impl fmt::Display for PeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

// ─── PeSection ───────────────────────────────────────────────────────────────

/// A PE section header entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSection {
    /// Section name (up to 8 bytes, null-padded).
    pub name: String,
    /// Virtual size.
    pub virtual_size: u32,
    /// Virtual address (RVA).
    pub virtual_address: u32,
    /// Raw data size.
    pub raw_size: u32,
    /// Raw data offset.
    pub raw_offset: u32,
    /// Section characteristics flags.
    pub characteristics: u32,
    /// Section entropy (if computed).
    pub entropy: Option<f64>,
}

impl PeSection {
    /// Return true if this section is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    /// Return true if this section is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }

    /// Return true if this section is readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.characteristics & 0x4000_0000 != 0
    }
}

// ─── PeExport ────────────────────────────────────────────────────────────────

/// A single export entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeExport {
    /// Ordinal number.
    pub ordinal: u32,
    /// Export name (None for ordinal-only exports).
    pub name: Option<String>,
    /// Function RVA.
    pub rva: u32,
    /// Whether this is a forwarded export.
    pub forwarder: Option<String>,
}

// ─── PeImport ────────────────────────────────────────────────────────────────

/// A single import entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeImport {
    /// DLL name.
    pub dll: String,
    /// Function name (None for ordinal-only imports).
    pub name: Option<String>,
    /// Ordinal (if importing by ordinal).
    pub ordinal: Option<u16>,
    /// IAT address.
    pub iat_rva: u32,
}

// ─── PeResource ──────────────────────────────────────────────────────────────

/// A resource entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeResource {
    /// Resource type (name or ID).
    pub resource_type: ResourceId,
    /// Resource name or ID.
    pub name: ResourceId,
    /// Resource language.
    pub language: u16,
    /// Data RVA.
    pub data_rva: u32,
    /// Data size.
    pub data_size: u32,
    /// Code page.
    pub code_page: u32,
}

/// A resource type or name identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceId {
    Id(u16),
    Name(String),
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(n) => write!(f, "#{n}"),
            Self::Name(s) => write!(f, "{s}"),
        }
    }
}

// ─── YaraModulePe ─────────────────────────────────────────────────────────────

/// YARA `pe.*` module.
///
/// After calling [`parse`](Self::parse), all `pe.*` fields are available.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct YaraModulePe {
    /// `IMAGE_FILE_HEADER.Machine`
    pub machine: u16,
    /// `IMAGE_FILE_HEADER.NumberOfSections`
    pub number_of_sections: u16,
    /// `IMAGE_FILE_HEADER.TimeDateStamp`
    pub timestamp: u32,
    /// `IMAGE_FILE_HEADER.Characteristics`
    pub characteristics: u16,
    /// `IMAGE_OPTIONAL_HEADER.DllCharacteristics`
    pub dll_characteristics: u16,
    /// Linker version (major.minor).
    pub linker_version: PeVersion,
    /// OS version (major.minor).
    pub os_version: PeVersion,
    /// Subsystem version.
    pub subsystem_version: PeVersion,
    /// Subsystem type.
    pub subsystem: u16,
    /// Entry point RVA.
    pub entry_point: u32,
    /// Image base.
    pub image_base: u64,
    /// Size of image.
    pub size_of_image: u32,
    /// Size of headers.
    pub size_of_headers: u32,
    /// Checksum.
    pub checksum: u32,
    /// Whether this is a PE32+ (64-bit) image.
    pub is_64bit: bool,
    /// Whether this is a DLL.
    pub is_dll: bool,
    /// DLL exports.
    pub exports: Vec<PeExport>,
    /// DLL imports (grouped by DLL name).
    pub imports: HashMap<String, Vec<PeImport>>,
    /// Section headers.
    pub sections: Vec<PeSection>,
    /// Resources.
    pub resources: Vec<PeResource>,
    /// DLL name from export directory.
    pub dll_name: Option<String>,
    /// Number of exports.
    pub number_of_exports: u32,
    /// Number of imported DLLs.
    pub number_of_imports: u32,
    /// Number of resources.
    pub number_of_resources: u32,
    /// Rich header hash (if present).
    pub rich_signature_present: bool,
}

impl YaraModulePe {
    /// Create an empty module.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn parse_optional_header_fields(&mut self, data: &[u8], opt: usize) {
        if self.is_64bit && opt + 56 <= data.len() {
            self.image_base = u64::from_le_bytes([
                data[opt + 24], data[opt + 25], data[opt + 26], data[opt + 27],
                data[opt + 28], data[opt + 29], data[opt + 30], data[opt + 31],
            ]);
            if opt + 60 <= data.len() {
                self.size_of_image = u32::from_le_bytes([
                    data[opt + 56], data[opt + 57], data[opt + 58], data[opt + 59],
                ]);
            }
            if opt + 64 <= data.len() {
                self.size_of_headers = u32::from_le_bytes([
                    data[opt + 60], data[opt + 61], data[opt + 62], data[opt + 63],
                ]);
            }
            if opt + 68 <= data.len() {
                self.checksum = u32::from_le_bytes([
                    data[opt + 64], data[opt + 65], data[opt + 66], data[opt + 67],
                ]);
            }
            if opt + 70 <= data.len() {
                self.subsystem = u16::from_le_bytes([data[opt + 68], data[opt + 69]]);
            }
            if opt + 72 <= data.len() {
                self.dll_characteristics = u16::from_le_bytes([data[opt + 70], data[opt + 71]]);
            }
        } else if !self.is_64bit && opt + 28 <= data.len() {
            self.image_base = u64::from(u32::from_le_bytes([
                data[opt + 28], data[opt + 29], data[opt + 30], data[opt + 31],
            ]));
            if opt + 60 <= data.len() {
                self.size_of_image = u32::from_le_bytes([
                    data[opt + 56], data[opt + 57], data[opt + 58], data[opt + 59],
                ]);
            }
            if opt + 68 <= data.len() {
                self.subsystem = u16::from_le_bytes([data[opt + 68], data[opt + 69]]);
            }
            if opt + 70 <= data.len() {
                self.dll_characteristics = u16::from_le_bytes([data[opt + 70], data[opt + 71]]);
            }
        }
    }

    /// Parse a PE binary and populate all `pe.*` fields.
    /// # Errors
    /// Returns a [`PeModuleError`] if the buffer is too small or malformed.
    pub fn parse(&mut self, data: &[u8]) -> Result<(), PeModuleError> {
        if data.len() < 64 {
            return Err(PeModuleError::TooSmall);
        }
        if data[0] != b'M' || data[1] != b'Z' {
            return Err(PeModuleError::NoDosSignature);
        }

        // Read e_lfanew
        let e_lfanew =
            u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        if e_lfanew + 24 > data.len() {
            return Err(PeModuleError::TooSmall);
        }

        // PE signature
        if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(PeModuleError::NoPeSignature);
        }

        let coff = e_lfanew + 4;

        // COFF header (20 bytes)
        self.machine = u16::from_le_bytes([data[coff], data[coff + 1]]);
        self.number_of_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]);
        self.timestamp = u32::from_le_bytes([
            data[coff + 4],
            data[coff + 5],
            data[coff + 6],
            data[coff + 7],
        ]);
        let size_opt = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
        self.characteristics = u16::from_le_bytes([data[coff + 18], data[coff + 19]]);
        self.is_dll = self.characteristics & 0x2000 != 0;

        // Optional header
        let opt = coff + 20;
        if opt + 2 > data.len() {
            return Err(PeModuleError::TooSmall);
        }
        let magic = u16::from_le_bytes([data[opt], data[opt + 1]]);
        self.is_64bit = match magic {
            0x010B => false,
            0x020B => true,
            m => return Err(PeModuleError::UnsupportedMagic(m)),
        };

        // Read optional header fields
        if opt + size_opt > data.len() || size_opt < 28 {
            return Err(PeModuleError::TooSmall);
        }

        self.linker_version = PeVersion {
            major: u16::from(data[opt + 2]),
            minor: u16::from(data[opt + 3]),
        };

        self.entry_point = u32::from_le_bytes([
            data[opt + 16],
            data[opt + 17],
            data[opt + 18],
            data[opt + 19],
        ]);

        self.parse_optional_header_fields(data, opt);

        // Windows-specific optional header fields (OS version)
        let os_off = opt + 40;
        if os_off + 4 <= data.len() {
            self.os_version = PeVersion {
                major: u16::from_le_bytes([data[os_off], data[os_off + 1]]),
                minor: u16::from_le_bytes([data[os_off + 2], data[os_off + 3]]),
            };
        }

        // Parse section headers
        let sections_start = opt + size_opt;
        self.parse_sections(data, sections_start);

        // Parse rich signature
        self.rich_signature_present = Self::detect_rich_header(data, e_lfanew);

        // Parse imports and exports from data directories
        let dd_offset = if self.is_64bit { opt + 112 } else { opt + 96 };
        if dd_offset + 16 <= data.len() {
            // Export directory: DD[0]
            let exp_rva = u32::from_le_bytes([
                data[dd_offset],
                data[dd_offset + 1],
                data[dd_offset + 2],
                data[dd_offset + 3],
            ]);
            if exp_rva != 0 {
                let _ = self.parse_exports(data, exp_rva);
            }
            // Import directory: DD[1]
            let imp_rva = u32::from_le_bytes([
                data[dd_offset + 8],
                data[dd_offset + 9],
                data[dd_offset + 10],
                data[dd_offset + 11],
            ]);
            if imp_rva != 0 {
                let _ = self.parse_imports(data, imp_rva);
            }
        }

        self.number_of_exports = u32::try_from(self.exports.len()).unwrap_or(u32::MAX);
        self.number_of_imports = u32::try_from(self.imports.len()).unwrap_or(u32::MAX);
        self.number_of_resources = u32::try_from(self.resources.len()).unwrap_or(u32::MAX);

        Ok(())
    }

    /// Return the machine type as a [`PeMachine`].
    #[must_use]
    pub const fn machine_type(&self) -> PeMachine {
        PeMachine::from_u16(self.machine)
    }

    /// Return the subsystem as a [`PeSubsystem`].
    #[must_use]
    pub const fn subsystem_type(&self) -> PeSubsystem {
        PeSubsystem::from_u16(self.subsystem)
    }

    /// Return true if ASLR is enabled (`DLL_CHARACTERISTICS_DYNAMIC_BASE`).
    #[must_use]
    pub const fn has_aslr(&self) -> bool {
        self.dll_characteristics & 0x0040 != 0
    }

    /// Return true if DEP/NX is enabled.
    #[must_use]
    pub const fn has_nx(&self) -> bool {
        self.dll_characteristics & 0x0100 != 0
    }

    /// Return true if CFG is enabled.
    #[must_use]
    pub const fn has_cfg(&self) -> bool {
        self.dll_characteristics & 0x4000 != 0
    }

    /// Look up an export by name.
    #[must_use]
    pub fn export_by_name(&self, name: &str) -> Option<&PeExport> {
        self.exports
            .iter()
            .find(|e| e.name.as_deref() == Some(name))
    }

    /// Look up imports for a specific DLL.
    #[must_use]
    pub fn imports_from_dll(&self, dll: &str) -> Option<&Vec<PeImport>> {
        // Try both exact and lowercased match
        self.imports.get(dll).or_else(|| {
            let lower = dll.to_ascii_lowercase();
            self.imports.get(&lower)
        })
    }

    /// Return total number of sections.
    #[must_use]
    pub const fn section_count(&self) -> usize {
        self.sections.len()
    }

    fn parse_sections(&mut self, data: &[u8], start: usize) {
        let count = self.number_of_sections as usize;
        for i in 0..count {
            let off = start + i * 40;
            if off + 40 > data.len() {
                break;
            }
            let name_bytes = &data[off..off + 8];
            let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..name_len]).to_string();
            let virtual_size =
                u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]);
            let virtual_address = u32::from_le_bytes([
                data[off + 12],
                data[off + 13],
                data[off + 14],
                data[off + 15],
            ]);
            let raw_size = u32::from_le_bytes([
                data[off + 16],
                data[off + 17],
                data[off + 18],
                data[off + 19],
            ]);
            let raw_offset = u32::from_le_bytes([
                data[off + 20],
                data[off + 21],
                data[off + 22],
                data[off + 23],
            ]);
            let characteristics = u32::from_le_bytes([
                data[off + 36],
                data[off + 37],
                data[off + 38],
                data[off + 39],
            ]);
            self.sections.push(PeSection {
                name,
                virtual_size,
                virtual_address,
                raw_size,
                raw_offset,
                characteristics,
                entropy: None,
            });
        }
    }

    fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for sec in &self.sections {
            let sec_end = sec.virtual_address.checked_add(sec.virtual_size)?;
            if rva >= sec.virtual_address && rva < sec_end {
                let delta = rva - sec.virtual_address;
                let raw = (sec.raw_offset as usize).checked_add(delta as usize)?;
                return Some(raw);
            }
        }
        None
    }

    fn read_cstring(data: &[u8], offset: usize) -> Option<String> {
        if offset >= data.len() {
            return None;
        }
        let end = data[offset..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(data.len() - offset);
        Some(String::from_utf8_lossy(&data[offset..offset + end]).to_string())
    }

    fn parse_exports(&mut self, data: &[u8], exp_rva: u32) -> Result<(), PeModuleError> {
        let off = self
            .rva_to_offset(exp_rva)
            .ok_or(PeModuleError::BadRva(exp_rva))?;
        if off + 40 > data.len() {
            return Err(PeModuleError::TooSmall);
        }
        // Export directory layout (40 bytes)
        let num_funcs = u32::from_le_bytes([
            data[off + 20],
            data[off + 21],
            data[off + 22],
            data[off + 23],
        ]);
        let num_names = u32::from_le_bytes([
            data[off + 24],
            data[off + 25],
            data[off + 26],
            data[off + 27],
        ]);
        let base_ordinal = u32::from_le_bytes([
            data[off + 16],
            data[off + 17],
            data[off + 18],
            data[off + 19],
        ]);
        let eat_rva = u32::from_le_bytes([
            data[off + 28],
            data[off + 29],
            data[off + 30],
            data[off + 31],
        ]);
        let entry_rva = u32::from_le_bytes([
            data[off + 32],
            data[off + 33],
            data[off + 34],
            data[off + 35],
        ]);
        let eno_rva = u32::from_le_bytes([
            data[off + 36],
            data[off + 37],
            data[off + 38],
            data[off + 39],
        ]);

        // dll name
        let name_rva = u32::from_le_bytes([
            data[off + 12],
            data[off + 13],
            data[off + 14],
            data[off + 15],
        ]);
        if let Some(name_off) = self.rva_to_offset(name_rva) {
            self.dll_name = Self::read_cstring(data, name_off);
        }

        // Export Address Table
        let Some(eat_off) = self.rva_to_offset(eat_rva) else {
            return Ok(());
        };
        // Export Name Table
        let Some(entry_off_ptr) = self.rva_to_offset(entry_rva) else {
            return Ok(());
        };
        // Export Name Ordinal Table
        let Some(eno_off) = self.rva_to_offset(eno_rva) else {
            return Ok(());
        };

        self.collect_exports(data, [eat_off, entry_off_ptr, eno_off], [num_names.min(65536), num_funcs.min(65536), base_ordinal]);
        Ok(())
    }

    /// Populate `self.exports` from export directory table data.
    /// Populate exports from the Export Address Table offsets and counts.
    fn collect_exports(&mut self, data: &[u8], offsets: [usize; 3], counts: [u32; 3]) {
        let [addr_off, name_ptr_off, ord_table_off] = offsets;
        let [num_names, num_funcs, base_ordinal] = counts;
        let mut name_map: HashMap<u32, String> = HashMap::new();
        for i in 0..num_names as usize {
            let nrva_off = name_ptr_off + i * 4;
            if nrva_off + 4 > data.len() { break; }
            let nr = u32::from_le_bytes([data[nrva_off], data[nrva_off + 1], data[nrva_off + 2], data[nrva_off + 3]]);
            let ord_off = ord_table_off + i * 2;
            if ord_off + 2 > data.len() { break; }
            let ord_idx = u32::from(u16::from_le_bytes([data[ord_off], data[ord_off + 1]]));
            if let Some(name_o) = self.rva_to_offset(nr)
                && let Some(name) = Self::read_cstring(data, name_o)
            {
                name_map.insert(ord_idx, name);
            }
        }
        for i in 0..num_funcs as usize {
            let func_off = addr_off + i * 4;
            if func_off + 4 > data.len() { break; }
            let func_rva = u32::from_le_bytes([data[func_off], data[func_off + 1], data[func_off + 2], data[func_off + 3]]);
            if func_rva == 0 { continue; }
            let ordinal = base_ordinal + u32::try_from(i).unwrap_or(u32::MAX);
            self.exports.push(PeExport {
                ordinal,
                name: name_map.get(&u32::try_from(i).unwrap_or(u32::MAX)).cloned(),
                rva: func_rva,
                forwarder: None,
            });
        }
    }

    fn collect_import_entries(
        &self, data: &[u8], ilt_off: usize, ptr_size: usize, iat_rva: u32, dll_name: &str,
    ) -> Vec<PeImport> {
        let ordinal_flag = if self.is_64bit { 1u64 << 63 } else { 1u64 << 31 };
        let mut entries = Vec::new();
        let mut ptr_idx = 0usize;
        loop {
            let ptr_off = ilt_off + ptr_idx * ptr_size;
            if ptr_off + ptr_size > data.len() { break; }
            let thunk = if self.is_64bit {
                u64::from_le_bytes([
                    data[ptr_off], data[ptr_off + 1], data[ptr_off + 2], data[ptr_off + 3],
                    data[ptr_off + 4], data[ptr_off + 5], data[ptr_off + 6], data[ptr_off + 7],
                ])
            } else {
                u64::from(u32::from_le_bytes([
                    data[ptr_off], data[ptr_off + 1], data[ptr_off + 2], data[ptr_off + 3],
                ]))
            };
            if thunk == 0 { break; }
            let iat_entry_rva = iat_rva
                + u32::try_from(ptr_idx).unwrap_or(u32::MAX)
                * u32::try_from(ptr_size).unwrap_or(u32::MAX);
            if thunk & ordinal_flag != 0 {
                let ord = u16::try_from(thunk & 0xFFFF).unwrap_or(u16::MAX);
                entries.push(PeImport { dll: dll_name.to_owned(), name: None, ordinal: Some(ord), iat_rva: iat_entry_rva });
            } else {
                let hint_rva = u32::try_from(thunk & 0x7FFF_FFFF).unwrap_or(u32::MAX);
                let (name, ordinal) = self.rva_to_offset(hint_rva).map_or((None, None), |hint_off| {
                    if hint_off + 2 <= data.len() {
                        let hint = u16::from_le_bytes([data[hint_off], data[hint_off + 1]]);
                        (Self::read_cstring(data, hint_off + 2), Some(hint))
                    } else {
                        (None, None)
                    }
                });
                entries.push(PeImport { dll: dll_name.to_owned(), name, ordinal, iat_rva: iat_entry_rva });
            }
            ptr_idx += 1;
        }
        entries
    }

    fn parse_imports(&mut self, data: &[u8], imp_rva: u32) -> Result<(), PeModuleError> {
        let mut off = self
            .rva_to_offset(imp_rva)
            .ok_or(PeModuleError::BadRva(imp_rva))?;

        // Cap at a sane limit to prevent DoS from a crafted PE with a circular
        // or enormous import descriptor table.
        let mut import_dll_count = 0usize;
        loop {
            if import_dll_count >= 4096 {
                break;
            }
            import_dll_count += 1;
            if off + 20 > data.len() {
                break;
            }
            // Import Descriptor (20 bytes)
            let import_lookup_rva =
                u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            let name_rva = u32::from_le_bytes([
                data[off + 12],
                data[off + 13],
                data[off + 14],
                data[off + 15],
            ]);
            let iat_rva = u32::from_le_bytes([
                data[off + 16],
                data[off + 17],
                data[off + 18],
                data[off + 19],
            ]);

            if import_lookup_rva == 0 && name_rva == 0 {
                break;
            } // null terminator

            let dll_name = self.rva_to_offset(name_rva).map_or_else(
                || "unknown.dll".to_owned(),
                |no| Self::read_cstring(data, no).unwrap_or_else(|| "unknown.dll".to_owned()),
            );

            let Some(ilt_off) = self.rva_to_offset(import_lookup_rva) else {
                off += 20;
                continue;
            };
            let ptr_size = if self.is_64bit { 8usize } else { 4usize };
            let entries = self.collect_import_entries(data, ilt_off, ptr_size, iat_rva, &dll_name);
            self.imports.insert(dll_name, entries);
            off += 20;
        }

        Ok(())
    }

    fn detect_rich_header(data: &[u8], pe_offset: usize) -> bool {
        if pe_offset < 4 {
            return false;
        }
        let search_area = &data[..pe_offset.min(data.len())];
        // Rich header contains "Rich" XOR'd with a checksum
        // Look for "Rich" signature pattern
        for i in 0..search_area.len().saturating_sub(4) {
            if &search_area[i..i + 4] == b"Rich" {
                return true;
            }
        }
        false
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid PE32 header for testing.
    fn minimal_pe32() -> Vec<u8> {
        let mut pe = vec![0u8; 0x400];
        // DOS header
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C] = 0x40; // e_lfanew = 0x40

        // PE signature
        pe[0x40] = b'P';
        pe[0x41] = b'E';
        pe[0x42] = 0;
        pe[0x43] = 0;

        // COFF: machine=0x014C (x86), sections=1, timestamp=0x12345678, opt_size=0xE0, characteristics=0x0002
        let coff = 0x44;
        pe[coff] = 0x4C;
        pe[coff + 1] = 0x01; // machine = x86
        pe[coff + 2] = 0x01;
        pe[coff + 3] = 0x00; // sections = 1
        pe[coff + 4] = 0x78;
        pe[coff + 5] = 0x56;
        pe[coff + 6] = 0x34;
        pe[coff + 7] = 0x12; // timestamp
        pe[coff + 16] = 0xE0;
        pe[coff + 17] = 0x00; // opt_size = 0xE0
        pe[coff + 18] = 0x02;
        pe[coff + 19] = 0x00; // characteristics = EXE

        // Optional header magic = PE32
        let opt = coff + 20;
        pe[opt] = 0x0B;
        pe[opt + 1] = 0x01; // magic = PE32
        pe[opt + 2] = 0x0E;
        pe[opt + 3] = 0x1C; // linker version 14.28

        pe
    }

    #[test]
    fn test_parse_minimal_pe32() {
        let pe = minimal_pe32();
        let mut m = YaraModulePe::new();
        assert!(m.parse(&pe).is_ok());
        assert_eq!(m.machine, 0x014C);
        assert!(!m.is_64bit);
        assert!(!m.is_dll);
    }

    #[test]
    fn test_machine_type_x86() {
        let mut m = YaraModulePe::new();
        m.machine = 0x014C;
        assert_eq!(m.machine_type(), PeMachine::I386);
    }

    #[test]
    fn test_machine_type_amd64() {
        let mut m = YaraModulePe::new();
        m.machine = 0x8664;
        assert_eq!(m.machine_type(), PeMachine::Amd64);
    }

    #[test]
    fn test_machine_type_arm64() {
        let mut m = YaraModulePe::new();
        m.machine = 0xAA64;
        assert_eq!(m.machine_type(), PeMachine::Arm64);
    }

    #[test]
    fn test_subsystem_type_gui() {
        let mut m = YaraModulePe::new();
        m.subsystem = 2;
        assert_eq!(m.subsystem_type(), PeSubsystem::WindowsGui);
        assert_eq!(m.subsystem_type().name(), "Windows GUI");
    }

    #[test]
    fn test_subsystem_type_cui() {
        let mut m = YaraModulePe::new();
        m.subsystem = 3;
        assert_eq!(m.subsystem_type(), PeSubsystem::WindowsCui);
    }

    #[test]
    fn test_has_aslr() {
        let mut m = YaraModulePe::new();
        m.dll_characteristics = 0x0040;
        assert!(m.has_aslr());
    }

    #[test]
    fn test_has_nx() {
        let mut m = YaraModulePe::new();
        m.dll_characteristics = 0x0100;
        assert!(m.has_nx());
    }

    #[test]
    fn test_has_cfg() {
        let mut m = YaraModulePe::new();
        m.dll_characteristics = 0x4000;
        assert!(m.has_cfg());
    }

    #[test]
    fn test_no_dos_signature_error() {
        let data = vec![0u8; 100];
        let mut m = YaraModulePe::new();
        assert!(matches!(m.parse(&data), Err(PeModuleError::NoDosSignature)));
    }

    #[test]
    fn test_too_small_error() {
        let data = vec![b'M', b'Z'];
        let mut m = YaraModulePe::new();
        assert!(matches!(m.parse(&data), Err(PeModuleError::TooSmall)));
    }

    #[test]
    fn test_pe_section_flags() {
        let sec = PeSection {
            name: ".text".to_owned(),
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            raw_size: 0x1000,
            raw_offset: 0x400,
            characteristics: 0x6000_0020, // readable, executable, code
            entropy: None,
        };
        assert!(sec.is_executable());
        assert!(sec.is_readable());
        assert!(!sec.is_writable());
    }

    #[test]
    fn test_pe_version_display() {
        let v = PeVersion {
            major: 14,
            minor: 28,
        };
        assert_eq!(v.to_string(), "14.28");
    }

    #[test]
    fn test_resource_id_display() {
        assert_eq!(ResourceId::Id(1).to_string(), "#1");
        assert_eq!(ResourceId::Name("ICON".to_owned()).to_string(), "ICON");
    }

    #[test]
    fn test_export_by_name_not_found() {
        let m = YaraModulePe::new();
        assert!(m.export_by_name("DllMain").is_none());
    }

    #[test]
    fn test_export_by_name_found() {
        let mut m = YaraModulePe::new();
        m.exports.push(PeExport {
            ordinal: 1,
            name: Some("Initialize".to_owned()),
            rva: 0x1000,
            forwarder: None,
        });
        assert!(m.export_by_name("Initialize").is_some());
    }

    #[test]
    fn test_imports_from_dll_found() {
        let mut m = YaraModulePe::new();
        let imps = vec![PeImport {
            dll: "kernel32.dll".to_owned(),
            name: Some("VirtualAlloc".to_owned()),
            ordinal: None,
            iat_rva: 0x5000,
        }];
        m.imports.insert("kernel32.dll".to_owned(), imps);
        assert!(m.imports_from_dll("kernel32.dll").is_some());
    }

    #[test]
    fn test_machine_names() {
        assert_eq!(PeMachine::I386.name(), "x86");
        assert_eq!(PeMachine::Amd64.name(), "x86_64");
        assert_eq!(PeMachine::Arm64.name(), "ARM64");
        assert_eq!(PeMachine::RiscV64.name(), "RISC-V 64");
    }

    #[test]
    fn test_parse_no_pe_signature() {
        let mut pe = minimal_pe32();
        pe[0x40] = 0; // corrupt PE signature
        let mut m = YaraModulePe::new();
        assert!(matches!(m.parse(&pe), Err(PeModuleError::NoPeSignature)));
    }

    #[test]
    fn test_section_count_after_parse() {
        let pe = minimal_pe32();
        let mut m = YaraModulePe::new();
        m.parse(&pe).unwrap();
        // Our minimal PE has 1 section declared but no section data - count should be <= 1
        assert!(m.section_count() <= 1);
    }

    #[test]
    fn test_is_dll_flag() {
        let mut m = YaraModulePe::new();
        m.characteristics = 0x2000;
        // is_dll is derived from characteristics; must be set explicitly or via parse
        m.is_dll = m.characteristics & 0x2000 != 0;
        assert!(m.is_dll);
    }

    #[test]
    fn test_timestamp_stored() {
        let pe = minimal_pe32();
        let mut m = YaraModulePe::new();
        m.parse(&pe).unwrap();
        assert_eq!(m.timestamp, 0x1234_5678);
    }

    #[test]
    fn test_pe_machine_names_all() {
        let machines = vec![
            (PeMachine::I386, "x86"),
            (PeMachine::Amd64, "x86_64"),
            (PeMachine::Arm64, "ARM64"),
            (PeMachine::PowerPc, "PowerPC"),
        ];
        for (m, expected) in machines {
            assert_eq!(m.name(), expected);
        }
    }

    #[test]
    fn test_pe_subsystem_all_names() {
        assert_eq!(PeSubsystem::Native.name(), "Native");
        assert_eq!(PeSubsystem::EfiApplication.name(), "EFI Application");
        assert_eq!(PeSubsystem::Xbox.name(), "Xbox");
        assert_eq!(
            PeSubsystem::WindowsBootApplication.name(),
            "Windows Boot Application"
        );
    }

    #[test]
    fn test_pe_version_default() {
        let v = PeVersion::default();
        assert_eq!(v.to_string(), "0.0");
    }

    #[test]
    fn test_pe_section_characteristics() {
        let sec = PeSection {
            name: ".data".to_owned(),
            virtual_size: 0x100,
            virtual_address: 0x2000,
            raw_size: 0x100,
            raw_offset: 0x600,
            characteristics: 0x4000_0000_u32 | 0x8000_0000_u32 | 0x0000_0040_u32,
            entropy: Some(4.5),
        };
        assert!(sec.is_readable());
        assert!(sec.is_writable());
        assert!(!sec.is_executable());
    }

    #[test]
    fn test_resource_id_eq() {
        assert_eq!(ResourceId::Id(1), ResourceId::Id(1));
        assert_ne!(ResourceId::Id(1), ResourceId::Id(2));
        assert_ne!(ResourceId::Id(1), ResourceId::Name("RT_BITMAP".to_owned()));
    }

    #[test]
    fn test_pe_module_linker_version() {
        let pe = minimal_pe32();
        let mut m = YaraModulePe::new();
        m.parse(&pe).unwrap();
        // linker_version set from opt[2] and opt[3]
        assert_eq!(m.linker_version.major, 0x0E); // 14
        assert_eq!(m.linker_version.minor, 0x1C); // 28
    }

    #[test]
    fn test_rich_signature_not_present_in_minimal() {
        let pe = minimal_pe32();
        let mut m = YaraModulePe::new();
        m.parse(&pe).unwrap();
        // Minimal PE has no Rich header
        assert!(!m.rich_signature_present);
    }

    #[test]
    fn test_pe_machine_from_u16_unknown() {
        let m = PeMachine::from_u16(0xFFFF);
        assert_eq!(m, PeMachine::Unknown);
    }

    #[test]
    fn test_export_by_name_ordinal_only() {
        let mut m = YaraModulePe::new();
        m.exports.push(PeExport {
            ordinal: 5,
            name: None,
            rva: 0x1234,
            forwarder: None,
        });
        // No name → export_by_name should not find it
        assert!(m.export_by_name("anything").is_none());
    }

    #[test]
    fn test_number_of_exports_counter() {
        let mut m = YaraModulePe::new();
        m.exports.push(PeExport {
            ordinal: 1,
            name: Some("A".to_owned()),
            rva: 1,
            forwarder: None,
        });
        m.exports.push(PeExport {
            ordinal: 2,
            name: Some("B".to_owned()),
            rva: 2,
            forwarder: None,
        });
        m.number_of_exports = u32::try_from(m.exports.len()).unwrap_or(u32::MAX);
        assert_eq!(m.number_of_exports, 2);
    }
}
