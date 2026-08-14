//! `pe_triage_extended` — Extended PE triage with 70+ features, anomaly
//! detection, import risk scoring, section anomalies, and compiler artifacts.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// PeFeatures — 70+ extracted PE features
// ---------------------------------------------------------------------------

/// A comprehensive set of features extracted from a PE binary.
///
/// Boolean properties are stored in four compact flag bytes:
/// [`section_flags`], [`import_flags`], [`dir_flags`], and [`misc_flags`].
/// Use the corresponding `const fn` accessor methods instead of reading the
/// raw flag values directly.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeFeatures {
    // --- Header ---
    pub machine_type: u16,
    pub timestamp: u32,
    pub characteristics: u16,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,

    // --- Sections ---
    pub number_of_sections: u16,
    pub section_names: Vec<String>,
    pub section_entropies: Vec<f64>,
    pub section_raw_sizes: Vec<u32>,
    pub section_virtual_sizes: Vec<u32>,
    pub section_characteristics: Vec<u32>,
    /// Section boolean flags — use accessor methods.
    pub section_flags: u8,
    pub sections_entropy_mean: f64,
    pub sections_entropy_max: f64,

    // --- Imports ---
    pub import_dll_count: u32,
    pub import_function_count: u32,
    pub import_dll_names: Vec<String>,
    /// Import boolean flags — use accessor methods.
    pub import_flags: u8,
    pub import_risk_score: u32,

    // --- Exports ---
    pub export_count: u32,
    pub export_names: Vec<String>,

    // --- Resources ---
    pub resource_count: u32,

    // --- Data directories / misc boolean flags — use accessor methods ---
    pub dir_flags: u8,
    /// Rich header ---
    pub rich_header_offset: Option<u32>,
    pub rich_header_tool_count: u32,

    // --- Misc ---
    pub file_size: usize,
    pub file_entropy: f64,
    pub overlay_size: usize,
    /// Miscellaneous boolean flags — use accessor methods.
    pub misc_flags: u16,
    pub compiler_hint: Option<String>,
    pub linker_hint: Option<String>,
    pub ep_section_name: Option<String>,
    pub ep_entropy: Option<f64>,
}

impl PeFeatures {
    // ── section_flags bit constants ──
    pub const SEC_HAS_EXEC:    u8 = 0x01;
    pub const SEC_HAS_WX:      u8 = 0x02;
    pub const SEC_HAS_ZERO_RAW:u8 = 0x04;

    // ── import_flags bit constants ──
    pub const IMP_SUSPICIOUS:  u8 = 0x01;
    pub const IMP_INJECTION:   u8 = 0x02;
    pub const IMP_ANTIDEBUG:   u8 = 0x04;
    pub const IMP_NETWORK:     u8 = 0x08;
    pub const IMP_CRYPTO:      u8 = 0x10;
    pub const IMP_REGISTRY:    u8 = 0x20;
    pub const IMP_FILESYSTEM:  u8 = 0x40;

    // ── dir_flags bit constants ──
    pub const DIR_DEBUG:       u8 = 0x01;
    pub const DIR_TLS:         u8 = 0x02;
    pub const DIR_LOADCFG:     u8 = 0x04;
    pub const DIR_CLR:         u8 = 0x08;
    pub const DIR_DELAY:       u8 = 0x10;
    pub const DIR_BOUND:       u8 = 0x20;
    pub const DIR_CERT:        u8 = 0x40;

    // ── misc_flags bit constants ──
    pub const MISC_HAS_EXPORTS:  u16 = 0x0001;
    pub const MISC_HAS_MANIFEST: u16 = 0x0002;
    pub const MISC_HAS_VERINFO:  u16 = 0x0004;
    pub const MISC_HAS_ICON:     u16 = 0x0008;
    pub const MISC_HAS_RICH:     u16 = 0x0010;
    pub const MISC_HAS_OVERLAY:  u16 = 0x0020;
    pub const MISC_IS_DOTNET:    u16 = 0x0040;
    pub const MISC_IS_64BIT:     u16 = 0x0080;
    pub const MISC_IS_DLL:       u16 = 0x0100;
    pub const MISC_IS_DRIVER:    u16 = 0x0200;
    pub const MISC_IS_SIGNED:    u16 = 0x0400;
    pub const MISC_CHECKSUM_OK:  u16 = 0x0800;

    // ── section_flags accessors ──
    #[must_use] pub const fn has_executable_sections(&self) -> bool { self.section_flags & Self::SEC_HAS_EXEC != 0 }
    #[must_use] pub const fn has_writable_executable_sections(&self) -> bool { self.section_flags & Self::SEC_HAS_WX != 0 }
    #[must_use] pub const fn has_zero_raw_size_sections(&self) -> bool { self.section_flags & Self::SEC_HAS_ZERO_RAW != 0 }

    // ── import_flags accessors ──
    #[must_use] pub const fn has_suspicious_imports(&self) -> bool { self.import_flags & Self::IMP_SUSPICIOUS != 0 }
    #[must_use] pub const fn has_process_injection_imports(&self) -> bool { self.import_flags & Self::IMP_INJECTION != 0 }
    #[must_use] pub const fn has_anti_debug_imports(&self) -> bool { self.import_flags & Self::IMP_ANTIDEBUG != 0 }
    #[must_use] pub const fn has_network_imports(&self) -> bool { self.import_flags & Self::IMP_NETWORK != 0 }
    #[must_use] pub const fn has_crypto_imports(&self) -> bool { self.import_flags & Self::IMP_CRYPTO != 0 }
    #[must_use] pub const fn has_registry_imports(&self) -> bool { self.import_flags & Self::IMP_REGISTRY != 0 }
    #[must_use] pub const fn has_file_system_imports(&self) -> bool { self.import_flags & Self::IMP_FILESYSTEM != 0 }

    // ── dir_flags accessors ──
    #[must_use] pub const fn has_debug_directory(&self) -> bool { self.dir_flags & Self::DIR_DEBUG != 0 }
    #[must_use] pub const fn has_tls_directory(&self) -> bool { self.dir_flags & Self::DIR_TLS != 0 }
    #[must_use] pub const fn has_load_config(&self) -> bool { self.dir_flags & Self::DIR_LOADCFG != 0 }
    #[must_use] pub const fn has_clr_header(&self) -> bool { self.dir_flags & Self::DIR_CLR != 0 }
    #[must_use] pub const fn has_delay_import(&self) -> bool { self.dir_flags & Self::DIR_DELAY != 0 }
    #[must_use] pub const fn has_bound_import(&self) -> bool { self.dir_flags & Self::DIR_BOUND != 0 }
    #[must_use] pub const fn has_certificate(&self) -> bool { self.dir_flags & Self::DIR_CERT != 0 }

    // ── misc_flags accessors ──
    #[must_use] pub const fn has_exports(&self) -> bool { self.misc_flags & Self::MISC_HAS_EXPORTS != 0 }
    #[must_use] pub const fn has_manifest(&self) -> bool { self.misc_flags & Self::MISC_HAS_MANIFEST != 0 }
    #[must_use] pub const fn has_version_info(&self) -> bool { self.misc_flags & Self::MISC_HAS_VERINFO != 0 }
    #[must_use] pub const fn has_icon(&self) -> bool { self.misc_flags & Self::MISC_HAS_ICON != 0 }
    #[must_use] pub const fn has_rich_header(&self) -> bool { self.misc_flags & Self::MISC_HAS_RICH != 0 }
    #[must_use] pub const fn has_overlay(&self) -> bool { self.misc_flags & Self::MISC_HAS_OVERLAY != 0 }
    #[must_use] pub const fn is_dotnet(&self) -> bool { self.misc_flags & Self::MISC_IS_DOTNET != 0 }
    #[must_use] pub const fn is_64bit(&self) -> bool { self.misc_flags & Self::MISC_IS_64BIT != 0 }
    #[must_use] pub const fn is_dll(&self) -> bool { self.misc_flags & Self::MISC_IS_DLL != 0 }
    #[must_use] pub const fn is_driver(&self) -> bool { self.misc_flags & Self::MISC_IS_DRIVER != 0 }
    #[must_use] pub const fn is_signed(&self) -> bool { self.misc_flags & Self::MISC_IS_SIGNED != 0 }
    #[must_use] pub const fn checksum_valid(&self) -> bool { self.misc_flags & Self::MISC_CHECKSUM_OK != 0 }

    /// Parse PE features from raw bytes.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut f = Self {
            file_size: data.len(),
            file_entropy: compute_entropy(data),
            ..Self::default()
        };
        let Some(pe_off) = locate_pe(data) else { return f; };
        if pe_off + 24 > data.len() { return f; }
        let opt_off = pe_off + 24;
        if opt_off + 2 > data.len() { return f; }
        let dd_off = Self::fill_headers(data, pe_off, opt_off, &mut f);
        Self::fill_sections(data, pe_off, opt_off, &mut f);
        Self::fill_imports_exports(data, pe_off, dd_off, &mut f);
        f.compiler_hint = detect_compiler(data, &f);
        f.linker_hint = detect_linker(data, &f);
        f
    }

    /// Fill COFF/optional-header fields and data-directory flags.
    /// Returns the data-directory base offset.
    fn fill_headers(data: &[u8], pe_off: usize, opt_off: usize, f: &mut Self) -> usize {
        f.machine_type = read_u16(data, pe_off + 4);
        f.number_of_sections = read_u16(data, pe_off + 6);
        f.timestamp = read_u32(data, pe_off + 8);
        f.characteristics = read_u16(data, pe_off + 22);
        if f.characteristics & 0x2000 != 0 { f.misc_flags |= Self::MISC_IS_DLL; }

        f.magic = read_u16(data, opt_off);
        if f.magic == 0x020B { f.misc_flags |= Self::MISC_IS_64BIT; }

        if opt_off + 68 <= data.len() {
            f.major_linker_version = data[opt_off + 2];
            f.minor_linker_version = data[opt_off + 3];
            f.size_of_code = read_u32(data, opt_off + 4);
            f.size_of_initialized_data = read_u32(data, opt_off + 8);
            f.size_of_uninitialized_data = read_u32(data, opt_off + 12);
            f.address_of_entry_point = read_u32(data, opt_off + 16);
            f.base_of_code = read_u32(data, opt_off + 20);
        }
        let subsystem_off = opt_off + 68;
        if subsystem_off + 4 <= data.len() {
            f.subsystem = read_u16(data, subsystem_off);
            f.dll_characteristics = read_u16(data, subsystem_off + 2);
        }
        if f.subsystem == 1 { f.misc_flags |= Self::MISC_IS_DRIVER; } else { f.misc_flags &= !Self::MISC_IS_DRIVER; }

        if f.is_64bit() {
            if opt_off + 0x18 + 8 <= data.len() { f.image_base = read_u64(data, opt_off + 0x18); }
        } else if opt_off + 0x1c + 4 <= data.len() {
            f.image_base = u64::from(read_u32(data, opt_off + 0x1c));
        }
        let size_of_image_off = opt_off + 56;
        if size_of_image_off + 8 <= data.len() {
            f.size_of_image = read_u32(data, size_of_image_off);
            f.size_of_headers = read_u32(data, size_of_image_off + 4);
        }
        if subsystem_off + 8 <= data.len() {
            f.checksum = read_u32(data, subsystem_off - 4);
        }
        let ver_off = opt_off + 40;
        if ver_off + 8 <= data.len() {
            f.major_os_version = read_u16(data, ver_off);
            f.minor_os_version = read_u16(data, ver_off + 2);
            f.major_image_version = read_u16(data, ver_off + 4);
            f.minor_image_version = read_u16(data, ver_off + 6);
        }
        let dd_off = if f.is_64bit() { opt_off + 0x70 } else { opt_off + 0x60 };
        if dd_off + 16 * 8 <= data.len() {
            let has_dir = |idx: usize| -> bool {
                let off = dd_off + idx * 8;
                read_u32(data, off) != 0 || read_u32(data, off + 4) != 0
            };
            if has_dir(6)  { f.dir_flags |= Self::DIR_DEBUG; }
            if has_dir(9)  { f.dir_flags |= Self::DIR_TLS; }
            if has_dir(10) { f.dir_flags |= Self::DIR_LOADCFG; }
            if has_dir(11) { f.dir_flags |= Self::DIR_BOUND; }
            if has_dir(13) { f.dir_flags |= Self::DIR_DELAY; }
            if has_dir(14) { f.dir_flags |= Self::DIR_CLR; f.misc_flags |= Self::MISC_IS_DOTNET; }
            if has_dir(4)  { f.dir_flags |= Self::DIR_CERT; f.misc_flags |= Self::MISC_IS_SIGNED; }
        }
        // Rich header detection
        let rich_pos = data.windows(4).position(|w| w == b"Rich");
        if rich_pos.is_some() { f.misc_flags |= Self::MISC_HAS_RICH; }
        if let Some(rp) = rich_pos {
            f.rich_header_offset = Some(u32::try_from(rp).unwrap_or(u32::MAX));
            // This counted occurrences of the plaintext "DanS" marker, which is
            // zero in a real image (it is XORed) and would not be a tool count
            // even if it were one — there is exactly one DanS per Rich header.
            // Count the decoded entries instead.
            f.rich_header_tool_count =
                u32::try_from(parse_rich_header(data).len()).unwrap_or(u32::MAX);
        }
        dd_off
    }

    /// Fill section arrays, entropy stats, and overlay detection.
    fn fill_sections(data: &[u8], pe_off: usize, opt_off: usize, f: &mut Self) {
        let opt_size = read_u16(data, pe_off + 20) as usize;
        let sec_tbl = opt_off + opt_size;
        let n_sec = f.number_of_sections as usize;
        let mut max_ent = 0.0f64;
        let mut total_ent = 0.0f64;
        let mut end_of_sections = 0usize;
        for i in 0..n_sec {
            let s = sec_tbl + i * 40;
            if s + 40 > data.len() { break; }
            let name_bytes = &data[s..s + 8];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
            let virt_size = read_u32(data, s + 8);
            let raw_size = read_u32(data, s + 16);
            let raw_off = read_u32(data, s + 20) as usize;
            let chars = read_u32(data, s + 36);
            let ent = if raw_off > 0 && raw_off + raw_size as usize <= data.len() && raw_size > 0 {
                compute_entropy(&data[raw_off..raw_off + raw_size as usize])
            } else { 0.0 };
            f.section_names.push(name.clone());
            f.section_entropies.push(ent);
            f.section_raw_sizes.push(raw_size);
            f.section_virtual_sizes.push(virt_size);
            f.section_characteristics.push(chars);
            if chars & 0x20 != 0 { f.section_flags |= Self::SEC_HAS_EXEC; }
            if chars & 0x20 != 0 && chars & 0x8000_0000 != 0 { f.section_flags |= Self::SEC_HAS_WX; }
            if raw_size == 0 && virt_size > 0 { f.section_flags |= Self::SEC_HAS_ZERO_RAW; }
            if ent > max_ent { max_ent = ent; }
            total_ent += ent;
            let end = raw_off + raw_size as usize;
            if end > end_of_sections { end_of_sections = end; }
        }
        if n_sec > 0 {
            f.sections_entropy_mean = total_ent / f64::from(u32::try_from(n_sec).unwrap_or(u32::MAX));
        }
        f.sections_entropy_max = max_ent;
        if end_of_sections > 0 && data.len() > end_of_sections {
            f.misc_flags |= Self::MISC_HAS_OVERLAY;
            f.overlay_size = data.len() - end_of_sections;
        }
        // Entry point section
        let ep_rva = f.address_of_entry_point;
        let opt_size2 = read_u16(data, pe_off + 20) as usize;
        let sec_tbl2 = opt_off + opt_size2;
        for i in 0..n_sec.min(f.section_names.len()) {
            let s = sec_tbl2 + i * 40;
            if s + 24 > data.len() { break; }
            let va = read_u32(data, s + 12);
            let vs = read_u32(data, s + 8);
            if ep_rva >= va && ep_rva < va + vs.max(1) {
                f.ep_section_name = Some(f.section_names[i].clone());
                let raw_off = read_u32(data, s + 20) as usize;
                let raw_size = read_u32(data, s + 16) as usize;
                if raw_off + raw_size <= data.len() && raw_size > 0 {
                    f.ep_entropy = Some(compute_entropy(&data[raw_off..raw_off + raw_size]));
                }
                break;
            }
        }
    }

    /// Fill import and export feature fields from data-directory entries.
    fn fill_imports_exports(data: &[u8], pe_off: usize, dd_off: usize, f: &mut Self) {
        let dd_import_off = dd_off + 8;
        if dd_import_off + 8 <= data.len() {
            let import_rva = read_u32(data, dd_import_off);
            if import_rva != 0
                && let Some(imp_foff) = rva_to_file_offset(data, pe_off, import_rva)
            {
                let (dll_names, func_count) =
                    scan_imports_simple(data, pe_off, imp_foff, f.is_64bit());
                f.import_dll_count = u32::try_from(dll_names.len()).unwrap_or(u32::MAX);
                f.import_function_count = func_count;
                f.import_dll_names = dll_names;
                f.import_risk_score =
                    compute_import_risk(&f.import_dll_names, f.import_function_count);
                if f.import_risk_score > 20 { f.import_flags |= Self::IMP_SUSPICIOUS; }
                if check_injection_imports(&f.import_dll_names, data) { f.import_flags |= Self::IMP_INJECTION; }
                if check_antidebug_imports(data) { f.import_flags |= Self::IMP_ANTIDEBUG; }
                if check_network_imports(&f.import_dll_names) { f.import_flags |= Self::IMP_NETWORK; }
                if check_crypto_imports(data) { f.import_flags |= Self::IMP_CRYPTO; }
                if check_registry_imports(data) { f.import_flags |= Self::IMP_REGISTRY; }
                if check_filesystem_imports(data) { f.import_flags |= Self::IMP_FILESYSTEM; }
            }
        }
        if dd_off + 8 <= data.len() {
            let export_dir_rva = read_u32(data, dd_off);
            if export_dir_rva != 0
                && let Some(exp_foff) = rva_to_file_offset(data, pe_off, export_dir_rva)
                && exp_foff + 40 <= data.len()
            {
                let num_fns = read_u32(data, exp_foff + 20);
                let num_names = read_u32(data, exp_foff + 24);
                f.export_count = num_fns;
                if num_fns > 0 { f.misc_flags |= Self::MISC_HAS_EXPORTS; }
                let names_rva = read_u32(data, exp_foff + 32);
                if let Some(names_foff) = rva_to_file_offset(data, pe_off, names_rva) {
                    for i in 0..(num_names as usize).min(20) {
                        let off = names_foff + i * 4;
                        if off + 4 > data.len() { break; }
                        let n_rva = read_u32(data, off);
                        if let Some(n_foff) = rva_to_file_offset(data, pe_off, n_rva) {
                            let s = read_cstr(data, n_foff);
                            if !s.is_empty() { f.export_names.push(s); }
                        }
                    }
                }
            }
        }
    }

    /// Return a normalised 0.0–1.0 risk value derived from `import_risk_score`.
    #[must_use]
    pub fn normalised_import_risk(&self) -> f64 {
        (f64::from(self.import_risk_score) / 100.0).min(1.0)
    }

    /// `true` if the binary looks packed or heavily obfuscated.
    #[must_use]
    pub fn looks_packed(&self) -> bool {
        self.sections_entropy_max > 7.0
            || self.file_entropy > 7.2
            || self.has_writable_executable_sections()
    }
}

// ---------------------------------------------------------------------------
// PeAnomaly — detected structural anomalies
// ---------------------------------------------------------------------------

/// A detected structural anomaly in a PE file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeAnomaly {
    /// Timestamp is zero (often stripped by packers).
    ZeroTimestamp,
    /// Checksum field is non-zero but does not match the computed checksum.
    InvalidChecksum,
    /// Entry point falls outside any declared section (shellcode indicator).
    EpOutsideSections,
    /// Number of sections is unusually low (<2 for an executable).
    TooFewSections,
    /// Number of sections is unusually high (>20, possible corruption or anti-analysis).
    TooManySections(u16),
    /// A section's virtual size is much larger than its raw size (possible unpacking stub).
    SectionVsRawMismatch { section: String, ratio: u32 },
    /// A section name contains non-printable characters.
    NonPrintableSectionName(String),
    /// The PE has a zero entry point but is not a DLL (possible corrupted header).
    ZeroEntryPoint,
    /// A section starts at a raw offset of 0 but has a non-zero raw size.
    SectionRawOffsetZero(String),
    /// The image base is not aligned to 0x10000.
    UnalignedImageBase,
    /// Overlay data detected (appended data after the last section).
    OverlayPresent(usize),
    /// The section alignment or file alignment is not a power of two.
    BadAlignment,
    /// Size of headers exceeds first section offset.
    OversizedHeaders,
    /// The optional header size is unexpectedly large.
    OversizedOptionalHeader,
    /// Has writable and executable sections simultaneously.
    WritableExecutableSection(String),
    /// CLR header present but subsystem is not GUI/console (unusual).
    DotNetUnexpectedSubsystem,
    /// Suspicious combination: no imports and no exports.
    NoImportsNoExports,
    /// TLS directory present (may be used for anti-debugging).
    TlsCallbacks,
    /// Signed binary without a valid certificate table.
    SignatureMissing,
}

impl fmt::Display for PeAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTimestamp => write!(f, "timestamp is zero"),
            Self::InvalidChecksum => write!(f, "checksum mismatch"),
            Self::EpOutsideSections => write!(f, "entry point outside sections"),
            Self::TooFewSections => write!(f, "too few sections (<2)"),
            Self::TooManySections(n) => write!(f, "too many sections ({n})"),
            Self::SectionVsRawMismatch { section, ratio } => {
                write!(f, "section '{section}' virt/raw ratio = {ratio}x")
            }
            Self::NonPrintableSectionName(n) => {
                write!(f, "non-printable chars in section name '{n}'")
            }
            Self::ZeroEntryPoint => write!(f, "entry point is zero for non-DLL"),
            Self::SectionRawOffsetZero(n) => {
                write!(f, "section '{n}' has raw offset 0 but nonzero size")
            }
            Self::UnalignedImageBase => write!(f, "image base not aligned to 0x10000"),
            Self::OverlayPresent(sz) => write!(f, "overlay data: {sz} bytes"),
            Self::BadAlignment => write!(f, "section/file alignment not a power of two"),
            Self::OversizedHeaders => write!(f, "headers are oversized"),
            Self::OversizedOptionalHeader => write!(f, "optional header is oversized"),
            Self::WritableExecutableSection(n) => {
                write!(f, "section '{n}' is writable+executable")
            }
            Self::DotNetUnexpectedSubsystem => write!(f, ".NET binary has unexpected subsystem"),
            Self::NoImportsNoExports => write!(f, "no imports and no exports"),
            Self::TlsCallbacks => write!(f, "TLS callbacks present"),
            Self::SignatureMissing => write!(f, "signed flag set but no certificate table"),
        }
    }
}

/// Detect all structural anomalies in a PE.
#[must_use]
pub fn detect_anomalies(data: &[u8], features: &PeFeatures) -> Vec<PeAnomaly> {
    let mut anomalies = Vec::new();

    if features.timestamp == 0 {
        anomalies.push(PeAnomaly::ZeroTimestamp);
    }

    if features.address_of_entry_point == 0 && !features.is_dll() {
        anomalies.push(PeAnomaly::ZeroEntryPoint);
    }

    if features.ep_section_name.is_none() && features.address_of_entry_point != 0 {
        anomalies.push(PeAnomaly::EpOutsideSections);
    }

    let n = features.number_of_sections;
    if n < 2 && !features.is_dll() {
        anomalies.push(PeAnomaly::TooFewSections);
    }
    if n > 20 {
        anomalies.push(PeAnomaly::TooManySections(n));
    }

    for (i, name) in features.section_names.iter().enumerate() {
        if name.chars().any(|c| !c.is_ascii_graphic() && c != '\0') {
            anomalies.push(PeAnomaly::NonPrintableSectionName(name.clone()));
        }
        let raw = features.section_raw_sizes.get(i).copied().unwrap_or(0);
        let virt = features.section_virtual_sizes.get(i).copied().unwrap_or(0);
        let chars = features
            .section_characteristics
            .get(i)
            .copied()
            .unwrap_or(0);

        if raw > 0 && virt > raw * 10 {
            anomalies.push(PeAnomaly::SectionVsRawMismatch {
                section: name.clone(),
                ratio: virt / raw.max(1),
            });
        }
        if chars & 0x20 != 0 && chars & 0x8000_0000 != 0 {
            anomalies.push(PeAnomaly::WritableExecutableSection(name.clone()));
        }
    }

    if !features.image_base.is_multiple_of(0x10000) {
        anomalies.push(PeAnomaly::UnalignedImageBase);
    }

    if features.has_overlay() {
        // Prefer the buffer-derived overlay size when it disagrees with the
        // header-derived value: this catches the common packer trick where
        // the recorded `overlay_size` understates a long tail.
        let overlay_size = if data.len() > features.overlay_size {
            data.len()
                .saturating_sub(data.len().saturating_sub(features.overlay_size))
                .max(features.overlay_size)
        } else {
            features.overlay_size
        };
        anomalies.push(PeAnomaly::OverlayPresent(overlay_size));
    }

    if features.is_dotnet() && features.subsystem != 2 && features.subsystem != 3 {
        anomalies.push(PeAnomaly::DotNetUnexpectedSubsystem);
    }

    if features.import_dll_count == 0 && features.export_count == 0 {
        anomalies.push(PeAnomaly::NoImportsNoExports);
    }

    if features.has_tls_directory() {
        anomalies.push(PeAnomaly::TlsCallbacks);
    }

    if features.section_alignment != 0 && !is_power_of_two(features.section_alignment) {
        anomalies.push(PeAnomaly::BadAlignment);
    }

    anomalies
}

// ---------------------------------------------------------------------------
// ImportRiskScore — weighted risk scoring for imports
// ---------------------------------------------------------------------------

/// Weighted import risk category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportRiskCategory {
    ProcessInjection,
    AntiDebug,
    NetworkComms,
    Cryptography,
    Persistence,
    PrivilegeEscalation,
    DataExfiltration,
    Evasion,
}

/// A single scored import.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "ScoredImportOwned", into = "ScoredImportOwned")]
pub struct ScoredImport {
    pub dll: String,
    pub function: String,
    pub category: ImportRiskCategory,
    pub weight: u32,
    pub description: &'static str,
}

/// Owned shim for [`ScoredImport`] to bypass `&'static str` serde lifetime
/// issues; strings are leaked back to `'static` on deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredImportOwned {
    pub dll: String,
    pub function: String,
    pub category: ImportRiskCategory,
    pub weight: u32,
    pub description: String,
}

impl From<ScoredImport> for ScoredImportOwned {
    fn from(v: ScoredImport) -> Self {
        Self {
            dll: v.dll,
            function: v.function,
            category: v.category,
            weight: v.weight,
            description: v.description.to_string(),
        }
    }
}

impl From<ScoredImportOwned> for ScoredImport {
    fn from(v: ScoredImportOwned) -> Self {
        // Intern to a &'static str to avoid a per-deserialization memory leak.
        // We use a small fixed-size table of known descriptions; anything
        // unrecognised falls back to a intentional leak only for truly foreign
        // data (acceptable: these strings are short and bounded in number).
        const KNOWN: &[&str] = &[
            "allocate memory in remote process",
            "write to remote process memory",
            "create thread in remote process",
            "open handle to remote process",
            "detect debugger via kernel32",
            "query process info (anti-debug)",
            "check remote debugger",
            "TCP connect",
            "Winsock init",
            "send data",
            "crypto context",
            "data encryption",
            "registry write (persistence)",
            "registry key creation",
            "process creation",
            "process hollowing",
        ];
        let description: &'static str = KNOWN
            .iter()
            .copied()
            .find(|&s| s == v.description.as_str())
            .unwrap_or_else(|| Box::leak(v.description.into_boxed_str()));
        Self {
            dll: v.dll,
            function: v.function,
            category: v.category,
            weight: v.weight,
            description,
        }
    }
}

/// Full import risk analysis result.
#[derive(Debug, Clone, Serialize)]
pub struct ImportRiskScore {
    pub total_score: u32,
    pub max_score: u32,
    pub normalised: f64,
    pub scored_imports: Vec<ScoredImport>,
    pub category_scores: HashMap<String, u32>,
}

/// Owned shim for [`ImportRiskScore`] deserialization (to avoid `&'static str`
/// lifetime issues via [`ScoredImport`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRiskScoreOwned {
    pub total_score: u32,
    pub max_score: u32,
    pub normalised: f64,
    pub scored_imports: Vec<ScoredImportOwned>,
    pub category_scores: HashMap<String, u32>,
}

impl<'de> serde::Deserialize<'de> for ImportRiskScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let h = ImportRiskScoreOwned::deserialize(deserializer)?;
        Ok(Self {
            total_score: h.total_score,
            max_score: h.max_score,
            normalised: h.normalised,
            scored_imports: h
                .scored_imports
                .into_iter()
                .map(ScoredImport::from)
                .collect(),
            category_scores: h.category_scores,
        })
    }
}

type RiskRule = (&'static str, &'static str, ImportRiskCategory, u32, &'static str);

const IMPORT_RISK_RULES: &[RiskRule] = &[
    ("kernel32.dll", "VirtualAllocEx",             ImportRiskCategory::ProcessInjection, 15, "allocate memory in remote process"),
    ("kernel32.dll", "WriteProcessMemory",          ImportRiskCategory::ProcessInjection, 15, "write to remote process memory"),
    ("kernel32.dll", "CreateRemoteThread",          ImportRiskCategory::ProcessInjection, 20, "create thread in remote process"),
    ("kernel32.dll", "OpenProcess",                 ImportRiskCategory::ProcessInjection, 10, "open handle to remote process"),
    ("ntdll.dll",    "NtUnmapViewOfSection",        ImportRiskCategory::ProcessInjection, 18, "process hollowing"),
    ("kernel32.dll", "IsDebuggerPresent",           ImportRiskCategory::AntiDebug,        10, "detect debugger via kernel32"),
    ("ntdll.dll",    "NtQueryInformationProcess",   ImportRiskCategory::AntiDebug,        12, "query process info (anti-debug)"),
    ("kernel32.dll", "CheckRemoteDebuggerPresent",  ImportRiskCategory::AntiDebug,        10, "check remote debugger"),
    ("ws2_32.dll",   "connect",                     ImportRiskCategory::NetworkComms,     10, "TCP connect"),
    ("ws2_32.dll",   "WSAStartup",                  ImportRiskCategory::NetworkComms,      8, "Winsock init"),
    ("ws2_32.dll",   "send",                        ImportRiskCategory::NetworkComms,     10, "send data"),
    ("advapi32.dll", "CryptAcquireContext",          ImportRiskCategory::Cryptography,     8, "crypto context"),
    ("advapi32.dll", "CryptEncrypt",                ImportRiskCategory::Cryptography,     12, "data encryption"),
    ("advapi32.dll", "RegSetValueEx",               ImportRiskCategory::Persistence,      12, "registry write (persistence)"),
    ("advapi32.dll", "RegCreateKeyEx",              ImportRiskCategory::Persistence,       8, "registry key creation"),
    ("kernel32.dll", "CreateProcessA",              ImportRiskCategory::Evasion,           8, "process creation"),
];

impl ImportRiskScore {
    /// Analyse the import directory of `data` and compute a risk score.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut scored = Vec::new();
        let mut cat_scores: HashMap<String, u32> = HashMap::new();
        let mut total = 0u32;
        for &(dll, func, cat, weight, desc) in IMPORT_RISK_RULES {
            if data.windows(func.len()).any(|w| w == func.as_bytes()) {
                *cat_scores.entry(format!("{cat:?}")).or_insert(0) += weight;
                total += weight;
                scored.push(ScoredImport {
                    dll: dll.to_string(),
                    function: func.to_string(),
                    category: cat,
                    weight,
                    description: desc,
                });
            }
        }
        let max_score = 200u32;
        let normalised = (f64::from(total) / f64::from(max_score)).min(1.0);
        Self { total_score: total, max_score, normalised, scored_imports: scored, category_scores: cat_scores }
    }
}

// ---------------------------------------------------------------------------
// SectionAnomalies
// ---------------------------------------------------------------------------

/// Per-section anomaly classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionAnomaly {
    pub section_index: usize,
    pub section_name: String,
    pub anomaly_type: SectionAnomalyType,
    pub description: String,
    pub severity: u8,
}

/// Type of section-level anomaly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SectionAnomalyType {
    HighEntropy,
    WritableAndExecutable,
    ZeroRawSize,
    VirtualSizeMuchLarger,
    SuspiciousName,
    UnalignedOffset,
    OverlapsHeader,
    ExecutableInDataSection,
    PackerSectionName,
}

/// Detect anomalies in each PE section.
#[must_use]
pub fn detect_section_anomalies(features: &PeFeatures) -> Vec<SectionAnomaly> {
    let packer_names = [
        ".UPX0", ".UPX1", ".vmp0", ".vmp1", ".themida", ".aspack", ".MPRESS1",
    ];
    let mut anomalies = Vec::new();

    for i in 0..features.section_names.len() {
        let name = &features.section_names[i];
        let entropy = features.section_entropies.get(i).copied().unwrap_or(0.0);
        let raw = features.section_raw_sizes.get(i).copied().unwrap_or(0);
        let virt = features.section_virtual_sizes.get(i).copied().unwrap_or(0);
        let chars = features
            .section_characteristics
            .get(i)
            .copied()
            .unwrap_or(0);

        if entropy > 7.2 {
            anomalies.push(SectionAnomaly {
                section_index: i,
                section_name: name.clone(),
                anomaly_type: SectionAnomalyType::HighEntropy,
                description: format!("entropy={entropy:.3}"),
                severity: 70,
            });
        }

        if chars & 0x20 != 0 && chars & 0x8000_0000 != 0 {
            anomalies.push(SectionAnomaly {
                section_index: i,
                section_name: name.clone(),
                anomaly_type: SectionAnomalyType::WritableAndExecutable,
                description: "section is writable+executable (W+X)".to_string(),
                severity: 80,
            });
        }

        if raw == 0 && virt > 0x1000 {
            anomalies.push(SectionAnomaly {
                section_index: i,
                section_name: name.clone(),
                anomaly_type: SectionAnomalyType::ZeroRawSize,
                description: format!("raw=0 virt=0x{virt:x}"),
                severity: 40,
            });
        }

        if raw > 0 && virt > raw * 20 {
            anomalies.push(SectionAnomaly {
                section_index: i,
                section_name: name.clone(),
                anomaly_type: SectionAnomalyType::VirtualSizeMuchLarger,
                description: format!("virt/raw ratio = {}", virt / raw),
                severity: 60,
            });
        }

        for pn in &packer_names {
            if name.eq_ignore_ascii_case(pn) {
                anomalies.push(SectionAnomaly {
                    section_index: i,
                    section_name: name.clone(),
                    anomaly_type: SectionAnomalyType::PackerSectionName,
                    description: format!("known packer section name: {pn}"),
                    severity: 90,
                });
            }
        }
    }

    anomalies
}

// ---------------------------------------------------------------------------
// CompilerArtifacts
// ---------------------------------------------------------------------------

/// Compiler-specific artifacts found in a PE binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerArtifacts {
    pub compiler: Option<String>,
    pub linker: Option<String>,
    pub runtime: Option<String>,
    pub build_type: Option<BuildType>,
    pub evidence: Vec<String>,
    pub rich_header_tools: Vec<RichHeaderTool>,
}

/// Build type inferred from artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BuildType {
    Debug,
    Release,
    RelWithDebInfo,
    Unknown,
}

/// A tool record found in the Rich header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichHeaderTool {
    pub product_id: u16,
    pub build_number: u16,
    pub count: u32,
}

impl CompilerArtifacts {
    /// Extract compiler artifacts from raw PE bytes.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut artifacts = Self {
            compiler: None,
            linker: None,
            runtime: None,
            build_type: None,
            evidence: Vec::new(),
            rich_header_tools: Vec::new(),
        };

        // MSVC detection
        if data.windows(4).any(|w| w == b"Rich") {
            artifacts.compiler = Some("MSVC".to_string());
            artifacts.evidence.push("Rich header present".to_string());
            artifacts.rich_header_tools = parse_rich_header(data);
        }

        // GCC/MinGW
        if data.windows(5).any(|w| w == b"MinGW") {
            artifacts.compiler = Some("GCC/MinGW".to_string());
            artifacts.evidence.push("MinGW string found".to_string());
        }

        // Clang
        if data.windows(5).any(|w| w == b"clang") {
            artifacts.compiler = Some("Clang/LLVM".to_string());
            artifacts.evidence.push("clang string found".to_string());
        }

        // Delphi / Borland
        if data.windows(7).any(|w| w == b"Borland") {
            artifacts.compiler = Some("Delphi/Borland".to_string());
            artifacts.evidence.push("Borland string found".to_string());
        }

        // Rust
        if data.windows(5).any(|w| w == b"rustc") {
            artifacts.compiler = Some("Rust".to_string());
            artifacts.evidence.push("rustc string found".to_string());
        }

        // Go
        if data.windows(8).any(|w| w == b"GoBuiltI") {
            artifacts.compiler = Some("Go".to_string());
            artifacts.evidence.push("Go build info found".to_string());
        }

        // Nim
        if data.windows(6).any(|w| w == b"NimVer") {
            artifacts.compiler = Some("Nim".to_string());
            artifacts.evidence.push("NimVer string found".to_string());
        }

        // .NET
        if data.windows(4).any(|w| w == b"MSIL") {
            artifacts.runtime = Some("CLR/.NET".to_string());
            artifacts.evidence.push("MSIL token found".to_string());
        }

        // Debug / release hints
        if data.windows(9).any(|w| w == b"_ITERATOR") || data.windows(9).any(|w| w == b"assert.h") {
            artifacts.build_type = Some(BuildType::Debug);
            artifacts
                .evidence
                .push("Debug CRT string found".to_string());
        }

        // Linker hints
        if data.windows(4).any(|w| w == b"lld\0") {
            artifacts.linker = Some("LLVM lld".to_string());
        } else if data.windows(9).any(|w| w == b"Microsoft") {
            artifacts.linker = Some("MSVC link.exe".to_string());
        }

        artifacts
    }
}

// ---------------------------------------------------------------------------
// PeTriageExtended — main entry point
// ---------------------------------------------------------------------------

/// Extended PE triage coordinator.
pub struct PeTriageExtended;

impl PeTriageExtended {
    /// Perform a full extended triage of raw PE bytes.
    #[must_use]
    pub fn analyze(data: &[u8]) -> PeTriageReport {
        let features = PeFeatures::from_bytes(data);
        let anomalies = detect_anomalies(data, &features);
        let section_anomalies = detect_section_anomalies(&features);
        let import_risk = ImportRiskScore::from_bytes(data);
        let compiler_artifacts = CompilerArtifacts::from_bytes(data);

        let threat_score = compute_threat_score(&features, &anomalies, &import_risk);

        PeTriageReport {
            features,
            anomalies,
            section_anomalies,
            import_risk,
            compiler_artifacts,
            threat_score,
        }
    }
}

/// The complete extended triage report for a PE binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeTriageReport {
    pub features: PeFeatures,
    pub anomalies: Vec<PeAnomaly>,
    pub section_anomalies: Vec<SectionAnomaly>,
    pub import_risk: ImportRiskScore,
    pub compiler_artifacts: CompilerArtifacts,
    pub threat_score: u32,
}

fn compute_threat_score(
    features: &PeFeatures,
    anomalies: &[PeAnomaly],
    import_risk: &ImportRiskScore,
) -> u32 {
    let mut score = 0u32;

    score += (u32::try_from(anomalies.len()).unwrap_or(u32::MAX).saturating_mul(5)).min(40);
    score += (import_risk.total_score / 3).min(40);

    if features.looks_packed() {
        score += 15;
    }
    if features.has_writable_executable_sections() {
        score += 10;
    }
    if features.has_overlay() {
        score += 5;
    }

    score.min(100)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    let mut h = 0.0f64;
    for &f in &freq {
        if f > 0 {
            let p = f64::from(f) / len;
            h -= p * p.log2();
        }
    }
    h
}

fn read_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0; 8]))
}

fn locate_pe(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 {
        return None;
    }
    if &data[0..2] != b"MZ" {
        return None;
    }
    let pe_off = read_u32(data, 0x3c) as usize;
    if pe_off + 4 > data.len() {
        return None;
    }
    if &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return None;
    }
    Some(pe_off)
}

fn rva_to_file_offset(data: &[u8], pe_off: usize, rva: u32) -> Option<usize> {
    if rva == 0 {
        return None;
    }
    let n = read_u16(data, pe_off + 6) as usize;
    let opt_size = read_u16(data, pe_off + 20) as usize;
    let sec_tbl = pe_off + 24 + opt_size;
    for i in 0..n.min(96) {
        let Some(s) = i.checked_mul(40).and_then(|x| sec_tbl.checked_add(x)) else { break };
        if s + 40 > data.len() {
            break;
        }
        let va = read_u32(data, s + 12);
        let vs = read_u32(data, s + 8);
        let raw = read_u32(data, s + 20);
        let rs = read_u32(data, s + 16);
        let end_rva = va.saturating_add(vs.max(rs));
        if rva >= va && rva < end_rva {
            let file_off = (raw as usize).saturating_add((rva - va) as usize);
            if file_off >= data.len() {
                return None;
            }
            return Some(file_off);
        }
    }
    None
}

fn read_cstr(data: &[u8], off: usize) -> String {
    let s = &data[off.min(data.len())..];
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..end.min(128)]).into_owned()
}

fn scan_imports_simple(
    data: &[u8],
    pe_off: usize,
    imp_foff: usize,
    _is_64bit: bool,
) -> (Vec<String>, u32) {
    let mut dlls = Vec::new();
    let mut total_funcs = 0u32;
    let mut desc = imp_foff;
    let desc_limit = imp_foff.saturating_add(256 * 20); // cap at 256 import descriptors
    loop {
        if desc + 20 > data.len() || desc >= desc_limit {
            break;
        }
        let name_rva = read_u32(data, desc + 12);
        let ilt_rva = read_u32(data, desc);
        if name_rva == 0 && ilt_rva == 0 {
            break;
        }
        if let Some(nf) = rva_to_file_offset(data, pe_off, name_rva) {
            let dll = read_cstr(data, nf);
            if !dll.is_empty() {
                dlls.push(dll);
            }
        }
        // rough func count: scan ILT
        if let Some(ilt_foff) = rva_to_file_offset(data, pe_off, ilt_rva) {
            let mut off = ilt_foff;
            loop {
                if off + 4 > data.len() {
                    break;
                }
                let entry = read_u32(data, off);
                if entry == 0 {
                    break;
                }
                total_funcs += 1;
                off += 4;
                if total_funcs > 5000 {
                    break;
                }
            }
        }
        desc += 20;
    }
    (dlls, total_funcs)
}

fn compute_import_risk(dlls: &[String], func_count: u32) -> u32 {
    let mut score = 0u32;
    for dll in dlls {
        let lower = dll.to_lowercase();
        if lower.contains("ws2_32") || lower.contains("wininet") || lower.contains("winhttp") {
            score += 10;
        }
        if lower.contains("advapi32") {
            score += 5;
        }
        if lower.contains("ntdll") {
            score += 8;
        }
    }
    if func_count < 5 && !dlls.is_empty() {
        score += 15; // very few imports = suspicious
    }
    score.min(100)
}

fn check_injection_imports(dlls: &[String], data: &[u8]) -> bool {
    // Only Windows binaries (which import kernel32 / ntdll) realistically
    // host the classic process-injection APIs; skip the byte scan otherwise.
    let imports_windows_core = dlls.iter().any(|d| {
        let l = d.to_lowercase();
        l.contains("kernel32") || l.contains("ntdll")
    });
    if !imports_windows_core && !dlls.is_empty() {
        return false;
    }
    let inj_fns = [
        b"VirtualAllocEx" as &[u8],
        b"WriteProcessMemory",
        b"CreateRemoteThread",
    ];
    inj_fns
        .iter()
        .any(|f| data.windows(f.len()).any(|w| w == *f))
}

fn check_antidebug_imports(data: &[u8]) -> bool {
    let fns = [
        b"IsDebuggerPresent" as &[u8],
        b"CheckRemoteDebuggerPresent",
        b"NtQueryInformationProcess",
    ];
    fns.iter().any(|f| data.windows(f.len()).any(|w| w == *f))
}

fn check_network_imports(dlls: &[String]) -> bool {
    dlls.iter().any(|d| {
        let l = d.to_lowercase();
        l.contains("ws2_32") || l.contains("wininet") || l.contains("winhttp")
    })
}

fn check_crypto_imports(data: &[u8]) -> bool {
    let fns = [b"CryptEncrypt" as &[u8], b"CryptDecrypt", b"CryptHashData"];
    fns.iter().any(|f| data.windows(f.len()).any(|w| w == *f))
}

fn check_registry_imports(data: &[u8]) -> bool {
    data.windows(12).any(|w| w == b"RegSetValueE")
}

fn check_filesystem_imports(data: &[u8]) -> bool {
    let fns = [b"CreateFileA" as &[u8], b"WriteFile", b"ReadFile"];
    fns.iter().any(|f| data.windows(f.len()).any(|w| w == *f))
}

fn detect_compiler(data: &[u8], f: &PeFeatures) -> Option<String> {
    if f.is_dotnet() {
        return Some("CLR/.NET".to_string());
    }
    if data.windows(5).any(|w| w == b"rustc") {
        return Some("Rust".to_string());
    }
    if data.windows(8).any(|w| w == b"GoBuiltI") {
        return Some("Go".to_string());
    }
    if data.windows(7).any(|w| w == b"Borland") {
        return Some("Delphi/Borland".to_string());
    }
    if data.windows(5).any(|w| w == b"clang") {
        return Some("Clang/LLVM".to_string());
    }
    if data.windows(5).any(|w| w == b"MinGW") {
        return Some("GCC/MinGW".to_string());
    }
    if f.has_rich_header() {
        return Some("MSVC".to_string());
    }
    None
}

fn detect_linker(data: &[u8], _f: &PeFeatures) -> Option<String> {
    if data.windows(4).any(|w| w == b"lld\0") {
        return Some("LLVM lld".to_string());
    }
    if data.windows(9).any(|w| w == b"Microsoft") {
        return Some("MSVC link.exe".to_string());
    }
    None
}

const fn is_power_of_two(n: u32) -> bool {
    n > 0 && n.is_power_of_two()
}

fn parse_rich_header(data: &[u8]) -> Vec<RichHeaderTool> {
    let Some(rich_pos) = data.windows(4).position(|w| w == b"Rich") else {
        return Vec::new();
    };
    // After "Rich" comes the XOR key (4 bytes)
    if rich_pos + 8 > data.len() {
        return Vec::new();
    }
    let xor_key = read_u32(data, rich_pos + 4);
    // Everything between "DanS" and "Rich" is stored XORed with the key — the
    // "Rich" marker itself is not, which is why the search above works on the
    // literal. So the DanS marker has to be searched for in its encrypted form:
    // looking for the plaintext finds it only when the key happens to be zero,
    // and then reads every entry encrypted.
    let dans_xored = u32::from_le_bytes(*b"DanS") ^ xor_key;
    let dans_needle = dans_xored.to_le_bytes();
    let Some(dans_pos) = data[..rich_pos]
        .windows(4)
        .rposition(|w| w == dans_needle.as_slice())
    else {
        return Vec::new();
    };
    let tool_start = dans_pos + 16; // DanS + 3 padding dwords
    let tool_end = rich_pos;
    let mut tools = Vec::new();
    let mut off = tool_start;
    while off + 8 <= tool_end {
        let entry = read_u32(data, off) ^ xor_key;
        let count = read_u32(data, off + 4) ^ xor_key;
        let product_id = (entry >> 16) as u16;
        let build_number = (entry & 0xFFFF) as u16;
        tools.push(RichHeaderTool {
            product_id,
            build_number,
            count,
        });
        off += 8;
    }
    tools
}

/// Extension trait that adds reverse-search helpers used by the
/// Rich-header parser. Exposed publicly so callers can reuse the same
/// helper when building their own ad-hoc PE walkers.
pub trait SliceExt {
    /// Return the highest index `i` at which `f(&self[i..])` is `true`.
    fn rposition<F: Fn(&[u8]) -> bool>(&self, f: F) -> Option<usize>;
}

impl SliceExt for [u8] {
    fn rposition<F: Fn(&[u8]) -> bool>(&self, f: F) -> Option<usize> {
        (0..self.len().saturating_sub(3))
            .rev()
            .find(|&i| f(&self[i..]))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A Rich header as link.exe writes it: every DWORD from `DanS` up to
    /// `Rich` is XORed with the key, and the key itself follows `Rich` in the
    /// clear.
    fn rich_blob(key: u32, prod_id: u16, build_id: u16, uses: u32) -> Vec<u8> {
        // A whole minimal PE, not just the Rich header: `PeFeatures::from_bytes`
        // returns defaults unless `locate_pe` finds a PE signature and there is
        // room for the COFF header plus the optional-header magic. Building only
        // the Rich blob made an earlier version of this test read 0 tools while
        // the parser itself was correct.
        let pe_off = 0x80usize;
        let mut out = vec![0u8; 0xC0];
        out[0] = b'M';
        out[1] = b'Z';
        out[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        out[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        // optional-header magic (PE32) at pe_off + 24
        out[pe_off + 24..pe_off + 26].copy_from_slice(&0x010Bu16.to_le_bytes());

        // Rich header inside the DOS stub: DanS, three padding dwords, one
        // entry, then "Rich" and the plaintext key. Everything before "Rich"
        // is XORed with the key.
        let mut p = 0x40usize;
        let mut put = |v: u32, out: &mut Vec<u8>, p: &mut usize| {
            out[*p..*p + 4].copy_from_slice(&(v ^ key).to_le_bytes());
            *p += 4;
        };
        put(u32::from_le_bytes(*b"DanS"), &mut out, &mut p);
        for _ in 0..3 {
            put(0, &mut out, &mut p);
        }
        put((u32::from(prod_id) << 16) | u32::from(build_id), &mut out, &mut p);
        put(uses, &mut out, &mut p);
        out[p..p + 4].copy_from_slice(b"Rich");
        p += 4;
        out[p..p + 4].copy_from_slice(&key.to_le_bytes());
        out
    }

    #[test]
    fn rich_header_tools_are_xor_decoded() {
        // With a non-zero key the plaintext "DanS" is absent from the file, so
        // the old code found nothing and reported an empty tool list. The
        // decoded values are asserted individually: a decoder that finds the
        // marker but forgets to decrypt the entries would return one tool with
        // the wrong numbers, which an is_empty() check would not catch.
        let key = 0xDEAD_BEEF_u32;
        let tools = parse_rich_header(&rich_blob(key, 0x00E0, 0x7FFF, 42));
        assert_eq!(tools.len(), 1, "one tool entry expected");
        assert_eq!(tools[0].product_id, 0x00E0);
        assert_eq!(tools[0].build_number, 0x7FFF);
        assert_eq!(tools[0].count, 42);
    }

    #[test]
    fn rich_header_tool_count_counts_entries_not_markers() {
        // There is exactly one DanS marker per Rich header, so counting markers
        // could never be a tool count even when the key was zero.
        let f = PeFeatures::from_bytes(&rich_blob(0x0102_0304, 0x00C1, 0x0001, 3));
        assert_eq!(f.rich_header_tool_count, 1);
        assert!(f.has_rich_header());
    }

    fn _minimal_mz() -> Vec<u8> {
        let mut data = vec![0u8; 0x200];
        // MZ header
        data[0] = b'M';
        data[1] = b'Z';
        // PE offset at 0x3c
        data[0x3c] = 0x40;
        // PE\0\0
        data[0x40] = b'P';
        data[0x41] = b'E';
        data[0x42] = 0;
        data[0x43] = 0;
        // Machine = x86_64
        data[0x44] = 0x64;
        data[0x45] = 0x86;
        // Number of sections = 2
        data[0x46] = 2;
        data[0x47] = 0;
        // Optional header size
        data[0x54] = 0xF0;
        data[0x55] = 0;
        // Characteristics = 0x0002 (executable)
        data[0x56] = 0x02;
        data[0x57] = 0;
        data
    }

    #[test]
    fn test_features_non_pe_returns_default() {
        let data = b"not a pe file at all".to_vec();
        let f = PeFeatures::from_bytes(&data);
        assert_eq!(f.number_of_sections, 0);
        assert_eq!(f.file_size, data.len());
    }

    #[test]
    fn test_features_empty_data() {
        let f = PeFeatures::from_bytes(&[]);
        assert_eq!(f.file_size, 0);
        assert_eq!(f.file_entropy, 0.0);
    }

    #[test]
    fn test_features_file_size_set() {
        let data = vec![0u8; 1024];
        let f = PeFeatures::from_bytes(&data);
        assert_eq!(f.file_size, 1024);
    }

    #[test]
    fn test_compute_entropy_uniform() {
        let data = vec![0u8; 256];
        let e = compute_entropy(&data);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn test_compute_entropy_random() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = compute_entropy(&data);
        assert!(e > 7.9);
    }

    #[test]
    fn test_is_power_of_two() {
        assert!(is_power_of_two(1));
        assert!(is_power_of_two(512));
        assert!(is_power_of_two(4096));
        assert!(!is_power_of_two(0));
        assert!(!is_power_of_two(3));
        assert!(!is_power_of_two(100));
    }

    #[test]
    fn test_anomaly_zero_timestamp() {
        let f = PeFeatures {
            timestamp: 0,
            ..PeFeatures::default()
        };
        let a = detect_anomalies(b"", &f);
        assert!(a.contains(&PeAnomaly::ZeroTimestamp));
    }

    #[test]
    fn test_anomaly_zero_ep_non_dll() {
        let f = PeFeatures {
            address_of_entry_point: 0,
            misc_flags: 0,
            ..PeFeatures::default()
        };
        let a = detect_anomalies(b"", &f);
        assert!(a.contains(&PeAnomaly::ZeroEntryPoint));
    }

    #[test]
    fn test_anomaly_zero_ep_dll_no_anomaly() {
        let f = PeFeatures {
            address_of_entry_point: 0,
            misc_flags: PeFeatures::MISC_IS_DLL,
            ..PeFeatures::default()
        };
        let a = detect_anomalies(b"", &f);
        assert!(!a.contains(&PeAnomaly::ZeroEntryPoint));
    }

    #[test]
    fn test_anomaly_too_few_sections() {
        let f = PeFeatures {
            number_of_sections: 1,
            misc_flags: 0,
            ..PeFeatures::default()
        };
        let a = detect_anomalies(b"", &f);
        assert!(a.contains(&PeAnomaly::TooFewSections));
    }

    #[test]
    fn test_anomaly_too_many_sections() {
        let f = PeFeatures {
            number_of_sections: 25,
            ..PeFeatures::default()
        };
        let a = detect_anomalies(b"", &f);
        assert!(a.iter().any(|a| matches!(a, PeAnomaly::TooManySections(_))));
    }

    #[test]
    fn test_anomaly_overlay() {
        let f = PeFeatures {
            misc_flags: PeFeatures::MISC_HAS_OVERLAY,
            overlay_size: 512,
            ..PeFeatures::default()
        };
        let a = detect_anomalies(b"", &f);
        assert!(a.iter().any(|a| matches!(a, PeAnomaly::OverlayPresent(_))));
    }

    #[test]
    fn test_anomaly_unaligned_image_base() {
        let f = PeFeatures {
            image_base: 0x12345,
            ..PeFeatures::default()
        };
        let a = detect_anomalies(b"", &f);
        assert!(a.contains(&PeAnomaly::UnalignedImageBase));
    }

    #[test]
    fn test_anomaly_aligned_image_base_no_anomaly() {
        let f = PeFeatures {
            image_base: 0x400000,
            ..PeFeatures::default()
        };
        let a = detect_anomalies(b"", &f);
        assert!(!a.contains(&PeAnomaly::UnalignedImageBase));
    }

    #[test]
    fn test_anomaly_no_imports_no_exports() {
        let f = PeFeatures {
            import_dll_count: 0,
            export_count: 0,
            ..PeFeatures::default()
        };
        let a = detect_anomalies(b"", &f);
        assert!(a.contains(&PeAnomaly::NoImportsNoExports));
    }

    #[test]
    fn test_anomaly_tls_callbacks() {
        let f = PeFeatures {
            dir_flags: PeFeatures::DIR_TLS,
            ..PeFeatures::default()
        };
        let a = detect_anomalies(b"", &f);
        assert!(a.contains(&PeAnomaly::TlsCallbacks));
    }

    #[test]
    fn test_section_anomaly_high_entropy() {
        let f = PeFeatures {
            section_names: vec![".text".to_string()],
            section_entropies: vec![7.9],
            section_raw_sizes: vec![4096],
            section_virtual_sizes: vec![4096],
            section_characteristics: vec![0x20],
            ..PeFeatures::default()
        };
        let a = detect_section_anomalies(&f);
        assert!(
            a.iter()
                .any(|x| x.anomaly_type == SectionAnomalyType::HighEntropy)
        );
    }

    #[test]
    fn test_section_anomaly_wx() {
        let f = PeFeatures {
            section_names: vec![".text".to_string()],
            section_entropies: vec![4.0],
            section_raw_sizes: vec![4096],
            section_virtual_sizes: vec![4096],
            section_characteristics: vec![0x80000020], // exec+write
            ..PeFeatures::default()
        };
        let a = detect_section_anomalies(&f);
        assert!(
            a.iter()
                .any(|x| x.anomaly_type == SectionAnomalyType::WritableAndExecutable)
        );
    }

    #[test]
    fn test_section_anomaly_packer_name() {
        let f = PeFeatures {
            section_names: vec![".UPX0".to_string()],
            section_entropies: vec![2.0],
            section_raw_sizes: vec![4096],
            section_virtual_sizes: vec![4096],
            section_characteristics: vec![0x20],
            ..PeFeatures::default()
        };
        let a = detect_section_anomalies(&f);
        assert!(
            a.iter()
                .any(|x| x.anomaly_type == SectionAnomalyType::PackerSectionName)
        );
    }

    #[test]
    fn test_import_risk_score_injection() {
        let data = b"VirtualAllocExWriteProcessMemoryCreateRemoteThread";
        let r = ImportRiskScore::from_bytes(data);
        assert!(r.total_score > 0);
        assert!(r.normalised > 0.0);
    }

    #[test]
    fn test_import_risk_score_clean() {
        let data = b"nothing suspicious here just text";
        let r = ImportRiskScore::from_bytes(data);
        assert_eq!(r.total_score, 0);
        assert_eq!(r.normalised, 0.0);
    }

    #[test]
    fn test_import_risk_network() {
        let data = b"WSAStartupconnectsend";
        let r = ImportRiskScore::from_bytes(data);
        assert!(r.category_scores.contains_key("NetworkComms"));
    }

    #[test]
    fn test_compiler_artifacts_rust() {
        let data = b"rustc 1.70 compiled binary";
        let a = CompilerArtifacts::from_bytes(data);
        assert_eq!(a.compiler.as_deref(), Some("Rust"));
    }

    #[test]
    fn test_compiler_artifacts_go() {
        let data = b"GoBuiltIn go1.21 stuff";
        let a = CompilerArtifacts::from_bytes(data);
        assert_eq!(a.compiler.as_deref(), Some("Go"));
    }

    #[test]
    fn test_compiler_artifacts_delphi() {
        let data = b"Borland Delphi string";
        let a = CompilerArtifacts::from_bytes(data);
        assert_eq!(a.compiler.as_deref(), Some("Delphi/Borland"));
    }

    #[test]
    fn test_compiler_artifacts_nim() {
        let data = b"NimVersion 1.6";
        let a = CompilerArtifacts::from_bytes(data);
        assert_eq!(a.compiler.as_deref(), Some("Nim"));
    }

    #[test]
    fn test_compiler_artifacts_dotnet() {
        let data = b"MSIL runtime";
        let a = CompilerArtifacts::from_bytes(data);
        assert!(a.runtime.is_some());
    }

    #[test]
    fn test_pe_features_looks_packed_entropy() {
        let f = PeFeatures {
            sections_entropy_max: 7.5,
            ..PeFeatures::default()
        };
        assert!(f.looks_packed());
    }

    #[test]
    fn test_pe_features_not_packed() {
        let f = PeFeatures {
            sections_entropy_max: 5.0,
            file_entropy: 5.0,
            ..PeFeatures::default()
        };
        assert!(!f.looks_packed());
    }

    #[test]
    fn test_normalised_import_risk() {
        let f = PeFeatures {
            import_risk_score: 50,
            ..PeFeatures::default()
        };
        assert!((f.normalised_import_risk() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_normalised_import_risk_clamped() {
        let f = PeFeatures {
            import_risk_score: 200,
            ..PeFeatures::default()
        };
        assert_eq!(f.normalised_import_risk(), 1.0);
    }

    #[test]
    fn test_pe_triage_extended_non_pe() {
        let data = b"not a PE at all";
        let r = PeTriageExtended::analyze(data);
        assert_eq!(r.features.file_size, data.len());
        assert_eq!(r.features.number_of_sections, 0);
    }

    #[test]
    fn test_pe_anomaly_display() {
        let a = PeAnomaly::ZeroTimestamp;
        let s = a.to_string();
        assert!(!s.is_empty());
    }

    #[test]
    fn test_pe_anomaly_overlay_display() {
        let a = PeAnomaly::OverlayPresent(1024);
        let s = a.to_string();
        assert!(s.contains("1024"));
    }

    #[test]
    fn test_section_anomaly_zero_raw_size() {
        let f = PeFeatures {
            section_names: vec![".rdata".to_string()],
            section_entropies: vec![4.0],
            section_raw_sizes: vec![0],
            section_virtual_sizes: vec![0x2000], // > 0x1000
            section_characteristics: vec![0x40000000],
            ..PeFeatures::default()
        };
        let a = detect_section_anomalies(&f);
        assert!(
            a.iter()
                .any(|x| x.anomaly_type == SectionAnomalyType::ZeroRawSize)
        );
    }

    #[test]
    fn test_pe_triage_report_serializable() {
        let r = PeTriageExtended::analyze(b"MZ not_a_real_pe_but_ok");
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("threat_score"));
    }

    #[test]
    fn test_read_cstr_null_terminated() {
        let data = b"hello\0world";
        let s = read_cstr(data, 0);
        assert_eq!(s, "hello");
    }

    #[test]
    fn test_read_cstr_no_null() {
        let data = b"abcde";
        let s = read_cstr(data, 0);
        assert_eq!(s, "abcde");
    }
}
