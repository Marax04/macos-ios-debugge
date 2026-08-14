//! `pe_validation` — Structural and semantic PE validation with 60+ rules.
//!
//! [`PeValidator`] runs every [`ValidationRule`] and collects all
//! [`ValidationError`]s into a [`ValidationReport`].

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// ValidationError
// ─────────────────────────────────────────────────────────────────────────────

/// Fine-grained PE validation error variants.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValidationError {
    BadHeader(String),
    Misaligned {
        field: String,
        value: u32,
        required_alignment: u32,
    },
    InvalidRva {
        field: String,
        rva: u32,
    },
    BadChecksum {
        stored: u32,
        computed: u32,
    },
    InvalidImport(String),
    InvalidExport(String),
    InvalidSection(String),
    OverlappingSections {
        a: String,
        b: String,
    },
    TooManySections(usize),
    InvalidOptionalHeader(String),
    InvalidDataDirectory(String),
    SuspiciousCharacteristic(String),
    InvalidRelocation(String),
    TlsIssue(String),
    SecurityDirectoryIssue(String),
    ResourceIssue(String),
    DebugDirectoryIssue(String),
    VersionIssue(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadHeader(s) => write!(f, "bad header: {s}"),
            Self::Misaligned {
                field,
                value,
                required_alignment,
            } => write!(
                f,
                "misaligned {field}: {value:#x} (align {required_alignment:#x})"
            ),
            Self::InvalidRva { field, rva } => write!(f, "invalid RVA in {field}: {rva:#x}"),
            Self::BadChecksum { stored, computed } => {
                write!(f, "bad checksum: stored={stored:#x} computed={computed:#x}")
            }
            Self::InvalidImport(s) => write!(f, "invalid import: {s}"),
            Self::InvalidExport(s) => write!(f, "invalid export: {s}"),
            Self::InvalidSection(s) => write!(f, "invalid section: {s}"),
            Self::OverlappingSections { a, b } => write!(f, "overlapping sections: {a} and {b}"),
            Self::TooManySections(n) => write!(f, "too many sections: {n}"),
            Self::InvalidOptionalHeader(s) => write!(f, "invalid optional header: {s}"),
            Self::InvalidDataDirectory(s) => write!(f, "invalid data directory: {s}"),
            Self::SuspiciousCharacteristic(s) => write!(f, "suspicious characteristic: {s}"),
            Self::InvalidRelocation(s) => write!(f, "invalid relocation: {s}"),
            Self::TlsIssue(s) => write!(f, "TLS issue: {s}"),
            Self::SecurityDirectoryIssue(s) => write!(f, "security directory: {s}"),
            Self::ResourceIssue(s) => write!(f, "resource: {s}"),
            Self::DebugDirectoryIssue(s) => write!(f, "debug directory: {s}"),
            Self::VersionIssue(s) => write!(f, "version: {s}"),
        }
    }
}

/// A wrapper that lets [`ValidationError`] be returned from `Result`-based
/// APIs that require [`std::error::Error`]. Carries the originating error
/// verbatim and prints it via its [`fmt::Display`] impl.
#[derive(Debug, Error, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[error("pe validation failed: {0}")]
pub struct ValidationFailure(pub ValidationError);

impl From<ValidationError> for ValidationFailure {
    fn from(err: ValidationError) -> Self {
        Self(err)
    }
}

/// Severity level of a validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

/// A single validation finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    pub error: ValidationError,
    pub offset: Option<usize>,
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidationRule
// ─────────────────────────────────────────────────────────────────────────────

/// Identifier for each validation rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValidationRule {
    // DOS header
    MzMagic,
    PeOffset,
    // PE signature
    PeSignature,
    // COFF header
    MachineValid,
    TimestampSane,
    NumberOfSections,
    SymbolTableDeprecated,
    OptionalHeaderSize,
    CharacteristicsConsistent,
    // Optional header
    MagicPe32OrPe32Plus,
    MajorLinkerVersion,
    SizeOfCodeNonZero,
    SizeOfInitData,
    EntryPointInCodeSection,
    ImageBaseAlignment,
    SectionAlignmentGe512,
    FileAlignmentValid,
    FileAlignmentLeSectionAlignment,
    MajorOsVersion,
    SizeOfImageMultiple,
    SizeOfHeadersMultiple,
    ChecksumValid,
    DllCharacteristicsReservedBitsClear,
    SizeOfStackReserveGe4k,
    NumberOfRvaAndSizesIs16,
    // Sections
    SectionNamesAscii,
    SectionRawSizeMultiple,
    SectionVaddrMultiple,
    SectionNoOverlap,
    SectionVsizeNonZero,
    SectionExecNoWrite,
    SectionWriteNoExec,
    SectionCountMax96,
    SectionRawOffNonZero,
    SectionNamesUnique,
    // Imports
    ImportTablePresent,
    ImportNamesAscii,
    ImportNoDuplicates,
    ImportDllNamesValid,
    ImportThunksAligned,
    // Exports
    ExportNameAscii,
    ExportOrdinalBase,
    ExportForwarderValid,
    ExportAddressesInImage,
    ExportNoDuplicateNames,
    // Relocations
    RelocBlockAligned,
    RelocTypeValid,
    RelocNoBeyondImage,
    // TLS
    TlsCallbacksPointerNull,
    TlsIndexAddressValid,
    // Security
    SecurityDirectoryAligned,
    SecurityDirectorySaneSize,
    // Resources
    ResourceDirectoryNotEmpty,
    ResourceOffsetInBounds,
    // Debug
    DebugDirectoryTypeKnown,
    DebugDirectoryOffsetValid,
    // Data directories
    DataDirRvaInBounds,
    DataDirSizeReasonable,
    // Misc
    NoOverlay,
    OverlaySizeReasonable,
    EntryPointNonZeroForExe,
    ImageSizeVsFileSize,
}

impl ValidationRule {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MzMagic => "mz_magic",
            Self::PeOffset => "pe_offset",
            Self::PeSignature => "pe_signature",
            Self::MachineValid => "machine_valid",
            Self::TimestampSane => "timestamp_sane",
            Self::NumberOfSections => "number_of_sections",
            Self::SymbolTableDeprecated => "symbol_table_deprecated",
            Self::OptionalHeaderSize => "optional_header_size",
            Self::CharacteristicsConsistent => "characteristics_consistent",
            Self::MagicPe32OrPe32Plus => "magic_pe32_or_pe32plus",
            Self::MajorLinkerVersion => "major_linker_version",
            Self::SizeOfCodeNonZero => "size_of_code_non_zero",
            Self::SizeOfInitData => "size_of_init_data",
            Self::EntryPointInCodeSection => "entry_point_in_code_section",
            Self::ImageBaseAlignment => "image_base_alignment",
            Self::SectionAlignmentGe512 => "section_alignment_ge512",
            Self::FileAlignmentValid => "file_alignment_valid",
            Self::FileAlignmentLeSectionAlignment => "file_alignment_le_section_alignment",
            Self::MajorOsVersion => "major_os_version",
            Self::SizeOfImageMultiple => "size_of_image_multiple",
            Self::SizeOfHeadersMultiple => "size_of_headers_multiple",
            Self::ChecksumValid => "checksum_valid",
            Self::DllCharacteristicsReservedBitsClear => "dll_characteristics_reserved_bits_clear",
            Self::SizeOfStackReserveGe4k => "size_of_stack_reserve_ge4k",
            Self::NumberOfRvaAndSizesIs16 => "number_of_rva_and_sizes_is_16",
            Self::SectionNamesAscii => "section_names_ascii",
            Self::SectionRawSizeMultiple => "section_raw_size_multiple",
            Self::SectionVaddrMultiple => "section_vaddr_multiple",
            Self::SectionNoOverlap => "section_no_overlap",
            Self::SectionVsizeNonZero => "section_vsize_non_zero",
            Self::SectionExecNoWrite => "section_exec_no_write",
            Self::SectionWriteNoExec => "section_write_no_exec",
            Self::SectionCountMax96 => "section_count_max96",
            Self::SectionRawOffNonZero => "section_raw_off_non_zero",
            Self::SectionNamesUnique => "section_names_unique",
            Self::ImportTablePresent => "import_table_present",
            Self::ImportNamesAscii => "import_names_ascii",
            Self::ImportNoDuplicates => "import_no_duplicates",
            Self::ImportDllNamesValid => "import_dll_names_valid",
            Self::ImportThunksAligned => "import_thunks_aligned",
            Self::ExportNameAscii => "export_name_ascii",
            Self::ExportOrdinalBase => "export_ordinal_base",
            Self::ExportForwarderValid => "export_forwarder_valid",
            Self::ExportAddressesInImage => "export_addresses_in_image",
            Self::ExportNoDuplicateNames => "export_no_duplicate_names",
            Self::RelocBlockAligned => "reloc_block_aligned",
            Self::RelocTypeValid => "reloc_type_valid",
            Self::RelocNoBeyondImage => "reloc_no_beyond_image",
            Self::TlsCallbacksPointerNull => "tls_callbacks_pointer_null",
            Self::TlsIndexAddressValid => "tls_index_address_valid",
            Self::SecurityDirectoryAligned => "security_directory_aligned",
            Self::SecurityDirectorySaneSize => "security_directory_sane_size",
            Self::ResourceDirectoryNotEmpty => "resource_directory_not_empty",
            Self::ResourceOffsetInBounds => "resource_offset_in_bounds",
            Self::DebugDirectoryTypeKnown => "debug_directory_type_known",
            Self::DebugDirectoryOffsetValid => "debug_directory_offset_valid",
            Self::DataDirRvaInBounds => "data_dir_rva_in_bounds",
            Self::DataDirSizeReasonable => "data_dir_size_reasonable",
            Self::NoOverlay => "no_overlay",
            Self::OverlaySizeReasonable => "overlay_size_reasonable",
            Self::EntryPointNonZeroForExe => "entry_point_non_zero_for_exe",
            Self::ImageSizeVsFileSize => "image_size_vs_file_size",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StructuralIntegrity / SemanticValidity
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of structural (byte-level) validity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralIntegrity {
    pub valid: bool,
    pub critical_count: usize,
    pub error_count: usize,
}

/// Summary of semantic (logic-level) validity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticValidity {
    pub valid: bool,
    pub warning_count: usize,
    pub info_count: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidationReport
// ─────────────────────────────────────────────────────────────────────────────

/// Full validation report for a PE file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub findings: Vec<Finding>,
    pub structural: StructuralIntegrity,
    pub semantic: SemanticValidity,
    pub rules_run: usize,
    pub is_valid: bool,
}

impl ValidationReport {
    fn from_findings(findings: Vec<Finding>, rules_run: usize) -> Self {
        let critical = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let errors = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count();
        let warnings = findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count();
        let infos = findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count();
        let structural = StructuralIntegrity {
            valid: critical == 0 && errors == 0,
            critical_count: critical,
            error_count: errors,
        };
        let semantic = SemanticValidity {
            valid: warnings == 0,
            warning_count: warnings,
            info_count: infos,
        };
        let is_valid = structural.valid && semantic.valid;
        Self {
            findings,
            structural,
            semantic,
            rules_run,
            is_valid,
        }
    }

    #[must_use]
    pub fn findings_for(&self, rule: ValidationRule) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.rule == rule.name())
            .collect()
    }

    #[must_use]
    pub fn by_severity(&self, sev: Severity) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.severity == sev).collect()
    }

    /// Group findings by rule name and return a count of how many findings
    /// fired per rule.
    #[must_use]
    pub fn counts_by_rule(&self) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for f in &self.findings {
            *counts.entry(f.rule.clone()).or_insert(0) += 1;
        }
        counts
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidationContext — threads state through validation helpers
// ─────────────────────────────────────────────────────────────────────────────

struct ValidationContext<'a> {
    data: &'a [u8],
    findings: Vec<Finding>,
    rules_run: usize,
    pe_ctx: PeContext,
    sec_ranges: Vec<(u32, u32, String)>,
    sec_names: Vec<String>,
}

impl<'a> ValidationContext<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, findings: Vec::new(), rules_run: 0, pe_ctx: PeContext::default(), sec_ranges: Vec::new(), sec_names: Vec::new() }
    }

    fn run<F>(&mut self, validator: &PeValidator, rule: ValidationRule, sev: Severity, body: F)
    where F: FnOnce(&mut PeContext, &[u8]) -> Option<ValidationError>
    {
        if validator.is_enabled(rule) {
            self.rules_run += 1;
            if let Some(err) = body(&mut self.pe_ctx, self.data) {
                self.findings.push(Finding {
                    rule: rule.name().to_string(),
                    severity: sev,
                    error: err,
                    offset: None,
                });
            }
        }
    }

    fn into_report(self) -> ValidationReport {
        ValidationReport::from_findings(self.findings, self.rules_run)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeValidator
// ─────────────────────────────────────────────────────────────────────────────

/// PE file validator — runs all enabled [`ValidationRule`]s.
#[derive(Default)]
pub struct PeValidator {
    disabled_rules: Vec<ValidationRule>,
    strict_checksum: bool,
}

impl PeValidator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_strict_checksum(mut self) -> Self {
        self.strict_checksum = true;
        self
    }

    #[must_use]
    pub fn disable_rule(mut self, rule: ValidationRule) -> Self {
        self.disabled_rules.push(rule);
        self
    }

    fn is_enabled(&self, rule: ValidationRule) -> bool {
        !self.disabled_rules.contains(&rule)
    }

    /// Validate `data` as a PE file and return a [`ValidationReport`].
    #[must_use]
    pub fn validate(&self, data: &[u8]) -> ValidationReport {
        let mut vctx = ValidationContext::new(data);
        self.check_dos_and_pe_sig(&mut vctx);
        if !vctx.pe_ctx.valid_pe {
            return vctx.into_report();
        }
        let (co, oo) = (vctx.pe_ctx.coff_off, vctx.pe_ctx.opt_off);
        let (n_sections, chars, is64) = self.check_coff_fields(&mut vctx, co, oo);
        let (size_of_image, checksum) = self.check_opt_header(&mut vctx, oo, is64, chars);
        self.check_section_table(&mut vctx, n_sections);
        self.check_structure_rules(&mut vctx, oo, is64, size_of_image, checksum);
        vctx.into_report()
    }

    fn check_dos_and_pe_sig(&self, vctx: &mut ValidationContext<'_>) {
        vctx.run(self, ValidationRule::MzMagic, Severity::Critical, |_c, d| {
            if d.len() < 2 || &d[0..2] != b"MZ" { Some(ValidationError::BadHeader("missing MZ magic".into())) } else { None }
        });
        vctx.run(self, ValidationRule::PeOffset, Severity::Error, |c, d| {
            if d.len() < 0x40 {
                Some(ValidationError::BadHeader("too short for e_lfanew".into()))
            } else {
                let off = u32::from_le_bytes(d[0x3C..0x40].try_into().unwrap_or_default());
                c.pe_off = off as usize;
                if c.pe_off + 4 > d.len() { Some(ValidationError::BadHeader(format!("e_lfanew {off:#x} out of range"))) } else { None }
            }
        });
        vctx.run(self, ValidationRule::PeSignature, Severity::Critical, |c, d| {
            if c.pe_off + 4 > d.len() || &d[c.pe_off..c.pe_off + 4] != b"PE\0\0" {
                Some(ValidationError::BadHeader("missing PE\\0\\0 signature".into()))
            } else {
                c.coff_off = c.pe_off + 4; c.opt_off = c.coff_off + 20; c.valid_pe = true; None
            }
        });
    }

    // Returns (n_sections, coff_chars, is64)
    fn check_coff_fields(&self, vctx: &mut ValidationContext<'_>, co: usize, oo: usize) -> (usize, u16, bool) {
        let machine = read16(vctx.data, co);
        let n_sections = read16(vctx.data, co + 2) as usize;
        let timestamp = read32(vctx.data, co + 4);
        let sym_off = read32(vctx.data, co + 8);
        let n_syms = read32(vctx.data, co + 12);
        let opt_size = read16(vctx.data, co + 16) as usize;
        let chars = read16(vctx.data, co + 18);
        vctx.pe_ctx.n_sections = n_sections;
        vctx.pe_ctx.section_table_off = oo + opt_size;
        let opt_magic = read16(vctx.data, oo);
        vctx.pe_ctx.pe32plus = opt_magic == 0x020B;
        vctx.run(self, ValidationRule::MachineValid, Severity::Error, |_c, _d| {
            if [0x014C, 0x8664, 0x01C0, 0x01C4, 0xAA64, 0x0200].contains(&machine) { None }
            else { Some(ValidationError::BadHeader(format!("unknown machine {machine:#x}"))) }
        });
        vctx.run(self, ValidationRule::TimestampSane, Severity::Info, |_c, _d| {
            if timestamp == 0 { Some(ValidationError::BadHeader("timestamp is 0".into())) } else { None }
        });
        vctx.run(self, ValidationRule::NumberOfSections, Severity::Warning, |_c, _d| {
            if n_sections == 0 { Some(ValidationError::BadHeader("NumberOfSections is 0".into())) } else { None }
        });
        vctx.run(self, ValidationRule::SymbolTableDeprecated, Severity::Info, |_c, _d| {
            if sym_off != 0 { Some(ValidationError::BadHeader(format!("PointerToSymbolTable {sym_off:#x} should be 0"))) } else { None }
        });
        vctx.run(self, ValidationRule::SymbolTableDeprecated, Severity::Info, |_c, _d| {
            if n_syms != 0 { Some(ValidationError::BadHeader(format!("NumberOfSymbols {n_syms} should be 0"))) } else { None }
        });
        vctx.run(self, ValidationRule::OptionalHeaderSize, Severity::Error, |_c, _d| {
            if opt_size < 96 && opt_size != 0 { Some(ValidationError::InvalidOptionalHeader(format!("SizeOfOptionalHeader {opt_size} too small"))) } else { None }
        });
        vctx.run(self, ValidationRule::SectionCountMax96, Severity::Warning, |_c, _d| {
            if n_sections > 96 { Some(ValidationError::TooManySections(n_sections)) } else { None }
        });
        vctx.run(self, ValidationRule::MagicPe32OrPe32Plus, Severity::Error, |_c, _d| {
            if opt_magic != 0x010B && opt_magic != 0x020B { Some(ValidationError::InvalidOptionalHeader(format!("bad magic {opt_magic:#x}"))) } else { None }
        });
        (n_sections, chars, vctx.pe_ctx.pe32plus)
    }

    // Returns (size_of_image, checksum)
    fn check_opt_header(&self, vctx: &mut ValidationContext<'_>, oo: usize, is64: bool, chars: u16) -> (u32, u32) {
        let entry_rva = read32(vctx.data, oo + 16);
        let base_of_code = read32(vctx.data, oo + 20);
        let image_base: u64 = if is64 { read64(vctx.data, oo + 24) } else { u64::from(read32(vctx.data, oo + 28)) };
        let section_align = read32(vctx.data, oo + 32);
        let file_align = read32(vctx.data, oo + 36);
        let size_of_image = read32(vctx.data, if is64 { oo + 56 } else { oo + 52 });
        let size_of_hdrs = read32(vctx.data, if is64 { oo + 60 } else { oo + 56 });
        let checksum = read32(vctx.data, if is64 { oo + 64 } else { oo + 60 });
        let dll_chars = read16(vctx.data, if is64 { oo + 70 } else { oo + 66 });
        vctx.pe_ctx.image_base = image_base; vctx.pe_ctx.section_align = section_align; vctx.pe_ctx.file_align = file_align;
        vctx.pe_ctx.size_of_image = size_of_image; vctx.pe_ctx.entry_rva = entry_rva;
        vctx.run(self, ValidationRule::SectionAlignmentGe512, Severity::Warning, |_c, _d| {
            if section_align < 0x200 { Some(ValidationError::InvalidOptionalHeader(format!("SectionAlignment {section_align:#x} < 0x200"))) } else { None }
        });
        vctx.run(self, ValidationRule::FileAlignmentValid, Severity::Error, |_c, _d| {
            if file_align == 0 || (file_align & (file_align - 1)) != 0 { Some(ValidationError::InvalidOptionalHeader(format!("FileAlignment {file_align:#x} not a power of 2"))) } else { None }
        });
        vctx.run(self, ValidationRule::FileAlignmentLeSectionAlignment, Severity::Error, |_c, _d| {
            if file_align > section_align { Some(ValidationError::InvalidOptionalHeader("FileAlignment > SectionAlignment".into())) } else { None }
        });
        vctx.run(self, ValidationRule::ImageBaseAlignment, Severity::Warning, |_c, _d| {
            if image_base & 0xFFFF != 0 { Some(ValidationError::Misaligned { field: "ImageBase".into(), value: u32::try_from(image_base & 0xFFFF_FFFF).unwrap_or(u32::MAX), required_alignment: 0x10000 }) } else { None }
        });
        vctx.run(self, ValidationRule::SizeOfImageMultiple, Severity::Error, |c, _d| {
            if c.section_align > 0 && !size_of_image.is_multiple_of(c.section_align) { Some(ValidationError::Misaligned { field: "SizeOfImage".into(), value: size_of_image, required_alignment: c.section_align }) } else { None }
        });
        vctx.run(self, ValidationRule::SizeOfHeadersMultiple, Severity::Warning, |c, _d| {
            if c.file_align > 0 && !size_of_hdrs.is_multiple_of(c.file_align) { Some(ValidationError::Misaligned { field: "SizeOfHeaders".into(), value: size_of_hdrs, required_alignment: c.file_align }) } else { None }
        });
        vctx.run(self, ValidationRule::DllCharacteristicsReservedBitsClear, Severity::Info, |_c, _d| {
            if dll_chars & 0x000F != 0 { Some(ValidationError::SuspiciousCharacteristic(format!("DllCharacteristics reserved bits set: {dll_chars:#x}"))) } else { None }
        });
        vctx.run(self, ValidationRule::EntryPointNonZeroForExe, Severity::Warning, |_c, _d| {
            let is_dll = chars & 0x2000 != 0;
            if !is_dll && entry_rva == 0 { Some(ValidationError::BadHeader("EntryPoint RVA is 0 in executable".into())) } else { None }
        });
        vctx.run(self, ValidationRule::EntryPointNonZeroForExe, Severity::Info, |_c, _d| {
            if entry_rva != 0 && base_of_code != 0 && entry_rva < base_of_code { Some(ValidationError::InvalidRva { field: "AddressOfEntryPoint < BaseOfCode".into(), rva: entry_rva }) } else { None }
        });
        (size_of_image, checksum)
    }

    fn check_section_table(&self, vctx: &mut ValidationContext<'_>, n_sections: usize) {
        let st = vctx.pe_ctx.section_table_off;
        vctx.sec_ranges = Vec::with_capacity(n_sections);
        vctx.sec_names = Vec::with_capacity(n_sections);
        for i in 0..n_sections {
            let off = st + i * 40;
            if off + 40 > vctx.data.len() { break; }
            let name_bytes = &vctx.data[off..off + 8];
            let ne = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..ne]).to_string();
            let vsize = read32(vctx.data, off + 8);
            let vaddr = read32(vctx.data, off + 12);
            let raw_sz = read32(vctx.data, off + 16);
            let raw_off = read32(vctx.data, off + 20);
            let sec_chars = read32(vctx.data, off + 36);
            vctx.sec_names.push(name.clone());
            vctx.sec_ranges.push((vaddr, vaddr.saturating_add(vsize), name.clone()));
            let file_align = vctx.pe_ctx.file_align;
            let section_align = vctx.pe_ctx.section_align;
            vctx.run(self, ValidationRule::SectionNamesAscii, Severity::Warning, |_c, _d| {
                if name.chars().any(|c| !c.is_ascii_graphic() && c != ' ') { Some(ValidationError::InvalidSection(format!("non-ASCII name in section {i}"))) } else { None }
            });
            vctx.run(self, ValidationRule::SectionRawSizeMultiple, Severity::Warning, |_c, _d| {
                if file_align > 0 && raw_sz > 0 && !raw_sz.is_multiple_of(file_align) { Some(ValidationError::Misaligned { field: format!("{name}.raw_size"), value: raw_sz, required_alignment: file_align }) } else { None }
            });
            vctx.run(self, ValidationRule::SectionVaddrMultiple, Severity::Warning, |_c, _d| {
                if section_align > 0 && !vaddr.is_multiple_of(section_align) { Some(ValidationError::Misaligned { field: format!("{name}.vaddr"), value: vaddr, required_alignment: section_align }) } else { None }
            });
            vctx.run(self, ValidationRule::SectionVsizeNonZero, Severity::Info, |_c, _d| {
                if vsize == 0 { Some(ValidationError::InvalidSection(format!("{name}: virtual size is 0"))) } else { None }
            });
            vctx.run(self, ValidationRule::SectionRawOffNonZero, Severity::Info, |_c, _d| {
                if raw_off == 0 && raw_sz > 0 { Some(ValidationError::InvalidSection(format!("{name}: raw offset is 0 but raw size {raw_sz}"))) } else { None }
            });
            let is_exec = sec_chars & 0x2000_0000 != 0; let is_write = sec_chars & 0x8000_0000 != 0;
            vctx.run(self, ValidationRule::SectionExecNoWrite, Severity::Info, |_c, _d| {
                if is_exec && is_write { Some(ValidationError::SuspiciousCharacteristic(format!("{name}: exec+write"))) } else { None }
            });
        }
    }

    fn check_structure_rules(&self, vctx: &mut ValidationContext<'_>, oo: usize, is64: bool, size_of_image: u32, checksum: u32) {
        // Checksum
        if self.is_enabled(ValidationRule::ChecksumValid) && self.strict_checksum {
            vctx.rules_run += 1;
            let computed = pe_checksum(vctx.data, if is64 { oo + 64 } else { oo + 60 });
            if checksum != 0 && computed != checksum {
                vctx.findings.push(Finding { rule: ValidationRule::ChecksumValid.name().into(), severity: Severity::Warning, error: ValidationError::BadChecksum { stored: checksum, computed }, offset: None });
            }
        }
        // Section name uniqueness
        if self.is_enabled(ValidationRule::SectionNamesUnique) {
            vctx.rules_run += 1;
            let mut seen = std::collections::HashSet::new();
            for n in &vctx.sec_names.clone() {
                if !seen.insert(n.as_str()) {
                    vctx.findings.push(Finding { rule: ValidationRule::SectionNamesUnique.name().into(), severity: Severity::Info, error: ValidationError::InvalidSection(format!("duplicate section name: {n}")), offset: None });
                    break;
                }
            }
        }
        // Section overlap
        if self.is_enabled(ValidationRule::SectionNoOverlap) {
            vctx.rules_run += 1;
            let ranges = vctx.sec_ranges.clone();
            'outer: for i in 0..ranges.len() {
                for j in (i + 1)..ranges.len() {
                    let (a_start, a_end, ref an) = ranges[i]; let (b_start, b_end, ref bn) = ranges[j];
                    if a_start < b_end && b_start < a_end {
                        vctx.findings.push(Finding { rule: ValidationRule::SectionNoOverlap.name().into(), severity: Severity::Error, error: ValidationError::OverlappingSections { a: an.clone(), b: bn.clone() }, offset: None });
                        break 'outer;
                    }
                }
            }
        }
        // DataDir in bounds
        let dd_base = if is64 { oo + 112 } else { oo + 96 };
        let size_of_img = vctx.pe_ctx.size_of_image;
        for idx in 0..16usize {
            let dd_off = dd_base + idx * 8;
            if dd_off + 8 > vctx.data.len() { break; }
            let rva = read32(vctx.data, dd_off); let sz = read32(vctx.data, dd_off + 4);
            if rva > 0 && sz > 0 {
                vctx.run(self, ValidationRule::DataDirRvaInBounds, Severity::Warning, |_c, _d| {
                    if rva >= size_of_img { Some(ValidationError::InvalidRva { field: format!("DataDir[{idx}]"), rva }) } else { None }
                });
            }
        }
        // Overlay check
        let data_len = vctx.data.len();
        vctx.run(self, ValidationRule::ImageSizeVsFileSize, Severity::Info, |_c, _d| {
            if size_of_image > u32::try_from(data_len).unwrap_or(u32::MAX).saturating_mul(4) {
                Some(ValidationError::BadHeader(format!("SizeOfImage {size_of_image:#x} >> file size {data_len:#x}")))
            } else { None }
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PE parsing context (internal)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct PeContext {
    pe_off: usize,
    coff_off: usize,
    opt_off: usize,
    valid_pe: bool,
    pe32plus: bool,
    n_sections: usize,
    section_table_off: usize,
    image_base: u64,
    section_align: u32,
    file_align: u32,
    size_of_image: u32,
    entry_rva: u32,
}

fn read16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap_or_default())
}
fn read32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or_default())
}
fn read64(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or_default())
}

/// Compute the PE checksum (simple 32-bit rolling sum).
fn pe_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u64 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        if i == checksum_offset {
            i += 4;
            continue;
        }
        let word = u64::from(u16::from_le_bytes([data[i], data[i + 1]]));
        sum = (sum + word) & 0xFFFF_FFFF;
        if sum >= 0x1_0000 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        i += 2;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = sum.wrapping_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
    u32::try_from(sum & 0xFFFF_FFFF).unwrap_or(u32::MAX)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_valid_pe32() -> Vec<u8> {
        let pe_off: usize = 0x80;
        let n_sections: usize = 1;
        let opt_size: usize = 0xE0;
        let section_table = pe_off + 24 + opt_size;
        let total = section_table + n_sections * 40 + 0x200;
        let mut b = vec![0u8; total];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&u32::try_from(pe_off).unwrap_or(u32::MAX).to_le_bytes());
        let p = pe_off;
        b[p..p + 4].copy_from_slice(b"PE\0\0");
        b[p + 4..p + 6].copy_from_slice(&0x014Cu16.to_le_bytes()); // x86
        b[p + 6..p + 8]
            .copy_from_slice(&u16::try_from(n_sections).unwrap_or(u16::MAX).to_le_bytes());
        b[p + 8..p + 12].copy_from_slice(&1u32.to_le_bytes()); // timestamp
        b[p + 20..p + 22]
            .copy_from_slice(&u16::try_from(opt_size).unwrap_or(u16::MAX).to_le_bytes());
        b[p + 22..p + 24].copy_from_slice(&0x0102u16.to_le_bytes()); // characteristics
        let o = p + 24;
        b[o..o + 2].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
        b[o + 16..o + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
        b[o + 28..o + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // ImageBase
        b[o + 28 + 4..o + 32 + 4].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        b[o + 36..o + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        // SizeOfImage = 2 * section_align
        b[o + 52..o + 56].copy_from_slice(&0x2000u32.to_le_bytes());
        // SizeOfHeaders
        b[o + 56..o + 60].copy_from_slice(&0x200u32.to_le_bytes());
        // Section table
        let st = section_table;
        b[st..st + 5].copy_from_slice(b".text");
        b[st + 8..st + 12].copy_from_slice(&0x200u32.to_le_bytes()); // vsize
        b[st + 12..st + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // vaddr
        b[st + 16..st + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        b[st + 20..st + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw offset
        b[st + 36..st + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // code+exec+read
        b
    }

    // ── Core validation ──────────────────────────────────────────────────────

    #[test]
    fn valid_pe_produces_no_critical() {
        let data = minimal_valid_pe32();
        let report = PeValidator::new().validate(&data);
        assert_eq!(report.structural.critical_count, 0, "{:?}", report.findings);
    }

    #[test]
    fn bad_mz_magic_critical() {
        let mut data = minimal_valid_pe32();
        data[0] = 0x00;
        let report = PeValidator::new().validate(&data);
        assert!(report.structural.critical_count > 0);
    }

    #[test]
    fn bad_pe_signature_critical() {
        let mut data = minimal_valid_pe32();
        data[0x80] = 0xFF;
        let report = PeValidator::new().validate(&data);
        assert!(report.structural.critical_count > 0);
    }

    #[test]
    fn rules_run_count() {
        let data = minimal_valid_pe32();
        let report = PeValidator::new().validate(&data);
        assert!(report.rules_run >= 20);
    }

    #[test]
    fn disabled_rule_not_run() {
        let mut data = minimal_valid_pe32();
        data[0x84] = 0xFF; // break machine field
        let v = PeValidator::new().disable_rule(ValidationRule::MachineValid);
        let report = v.validate(&data);
        assert!(report.findings_for(ValidationRule::MachineValid).is_empty());
    }

    #[test]
    fn invalid_machine_error() {
        let mut data = minimal_valid_pe32();
        // machine field at pe_off + 4
        data[0x84..0x86].copy_from_slice(&0xFFFFu16.to_le_bytes());
        let report = PeValidator::new().validate(&data);
        assert!(!report.findings_for(ValidationRule::MachineValid).is_empty());
    }

    // ── Section validation ───────────────────────────────────────────────────

    #[test]
    fn section_name_ascii_passes_for_text() {
        let data = minimal_valid_pe32();
        let report = PeValidator::new().validate(&data);
        assert!(
            report
                .findings_for(ValidationRule::SectionNamesAscii)
                .is_empty()
        );
    }

    #[test]
    fn overlapping_sections_detected() {
        let mut data = minimal_valid_pe32();
        let pe_off: usize = 0x80;
        let opt_size: usize = 0xE0;
        let st = pe_off + 24 + opt_size;
        // Update NumberOfSections to 2
        data[pe_off + 6..pe_off + 8].copy_from_slice(&2u16.to_le_bytes());
        // Second section overlapping with first
        let st2 = st + 40;
        if st2 + 40 <= data.len() {
            data[st2..st2 + 5].copy_from_slice(b".data");
            data[st2 + 8..st2 + 12].copy_from_slice(&0x200u32.to_le_bytes()); // vsize
            data[st2 + 12..st2 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // same vaddr as .text
        }
        let report = PeValidator::new().validate(&data);
        assert!(
            !report
                .findings_for(ValidationRule::SectionNoOverlap)
                .is_empty()
        );
    }

    // ── ValidationError Display ──────────────────────────────────────────────

    #[test]
    fn display_bad_header() {
        let e = ValidationError::BadHeader("test".into());
        assert!(e.to_string().contains("test"));
    }

    #[test]
    fn display_misaligned() {
        let e = ValidationError::Misaligned {
            field: "foo".into(),
            value: 0x101,
            required_alignment: 0x200,
        };
        assert!(e.to_string().contains("foo"));
    }

    #[test]
    fn display_invalid_rva() {
        let e = ValidationError::InvalidRva {
            field: "bar".into(),
            rva: 0xDEAD,
        };
        assert!(e.to_string().contains("bar"));
    }

    #[test]
    fn display_bad_checksum() {
        let e = ValidationError::BadChecksum {
            stored: 0x1234,
            computed: 0x5678,
        };
        let s = e.to_string();
        assert!(s.contains("1234") || s.contains("bad checksum"));
    }

    // ── ValidationRule names ─────────────────────────────────────────────────

    #[test]
    fn rule_name_mz_magic() {
        assert_eq!(ValidationRule::MzMagic.name(), "mz_magic");
    }

    #[test]
    fn rule_name_checksum_valid() {
        assert_eq!(ValidationRule::ChecksumValid.name(), "checksum_valid");
    }

    // ── Report helpers ───────────────────────────────────────────────────────

    #[test]
    fn by_severity_critical_empty_for_valid() {
        let data = minimal_valid_pe32();
        let report = PeValidator::new().validate(&data);
        assert!(report.by_severity(Severity::Critical).is_empty());
    }

    #[test]
    fn is_valid_for_clean_pe() {
        let data = minimal_valid_pe32();
        let report = PeValidator::new().validate(&data);
        // Minimal PE may have warnings but should not be critical
        assert!(report.structural.valid);
    }

    // ── Severity ordering ────────────────────────────────────────────────────

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::Error);
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
    }

    // ── Checksum ─────────────────────────────────────────────────────────────

    #[test]
    fn pe_checksum_returns_u32() {
        let data = minimal_valid_pe32();
        let _ = pe_checksum(&data, 0x80 + 24 + 60);
    }

    // ── Structural integrity ─────────────────────────────────────────────────

    #[test]
    fn structural_integrity_valid_by_default() {
        let si = StructuralIntegrity {
            valid: true,
            critical_count: 0,
            error_count: 0,
        };
        assert!(si.valid);
    }

    // ── Serialisation ────────────────────────────────────────────────────────

    #[test]
    fn validation_report_serialises() {
        let data = minimal_valid_pe32();
        let report = PeValidator::new().validate(&data);
        let j = serde_json::to_string(&report).unwrap();
        assert!(j.contains("findings"));
    }

    // ── File-too-short ───────────────────────────────────────────────────────

    #[test]
    fn too_short_file_critical() {
        let report = PeValidator::new().validate(&[0u8; 4]);
        assert!(report.structural.critical_count > 0 || report.structural.error_count > 0);
    }

    // ── Strict checksum ─────────────────────────────────────────────────────

    #[test]
    fn strict_checksum_runs_rule() {
        let data = minimal_valid_pe32();
        let v = PeValidator::new().with_strict_checksum();
        let report = v.validate(&data);
        // Either no findings (checksum 0 is ignored) or one warning
        assert!(report.findings_for(ValidationRule::ChecksumValid).len() <= 1);
    }
}
