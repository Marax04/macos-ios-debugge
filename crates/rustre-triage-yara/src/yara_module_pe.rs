//! `yara_module_pe` — YARA PE module implementation.
//!
//! Exposes PE header fields, sections, imports, exports, resources, version
//! info, digital signature presence, section entropy, and import hash to
//! YARA rules.  Parsing is done from raw bytes with no external dependencies.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from PE module parsing.
#[derive(Debug, Error)]
pub enum PeModuleError {
    /// Input too short to be a valid PE.
    #[error("data too short: need {need} bytes, have {have}")]
    TooShort {
        /// Bytes required.
        need: usize,
        /// Bytes available.
        have: usize,
    },
    /// Missing or invalid MZ magic.
    #[error("invalid MZ magic")]
    InvalidMzMagic,
    /// Invalid PE signature offset.
    #[error("PE signature offset {0:#x} out of range")]
    PeOffsetOutOfRange(u32),
    /// Invalid PE signature.
    #[error("invalid PE signature")]
    InvalidPeSignature,
    /// Unsupported optional header magic.
    #[error("unsupported optional header magic: {0:#06x}")]
    UnsupportedOptionalMagic(u16),
}

// ─────────────────────────────────────────────────────────────────────────────
// SectionInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Information about a single PE section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    /// Section name (up to 8 bytes, NUL-stripped).
    pub name: String,
    /// Virtual address of the section.
    pub virtual_address: u32,
    /// Virtual size of the section.
    pub virtual_size: u32,
    /// Raw data offset in the file.
    pub raw_offset: u32,
    /// Size of raw data.
    pub raw_size: u32,
    /// Section characteristics flags.
    pub characteristics: u32,
    /// Computed Shannon entropy of the raw section data.
    pub entropy: f64,
    /// MD5 hash of the raw section data (hex string).
    pub md5: String,
}

impl SectionInfo {
    /// Whether this section is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    /// Whether this section is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }

    /// Whether this section is readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.characteristics & 0x4000_0000 != 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ImportInfo
// ─────────────────────────────────────────────────────────────────────────────

/// A single imported symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    /// DLL name (lowercase).
    pub dll: String,
    /// Function name (empty for ordinal-only imports).
    pub name: String,
    /// Import ordinal (0 if name-only).
    pub ordinal: u16,
    /// IAT address.
    pub address: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// PeModuleData
// ─────────────────────────────────────────────────────────────────────────────

/// All PE metadata extracted by the module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeModuleData {
    /// Machine type field from the COFF header.
    pub machine: u16,
    /// Number of sections.
    pub number_of_sections: u16,
    /// TimeDateStamp from COFF header.
    pub timestamp: u32,
    /// Characteristics from COFF header.
    pub characteristics: u16,
    /// Optional header magic: 0x010B = PE32, 0x020B = PE32+.
    pub optional_magic: u16,
    /// Linker version (major.minor).
    pub linker_version: (u8, u8),
    /// Subsystem field.
    pub subsystem: u16,
    /// DLL characteristics.
    pub dll_characteristics: u16,
    /// Size of image (virtual).
    pub size_of_image: u32,
    /// Entry point RVA.
    pub entry_point: u32,
    /// Image base address.
    pub image_base: u64,
    /// Whether this is a 64-bit PE (PE32+).
    pub is_64bit: bool,
    /// Whether the binary has a digital signature (Authenticode).
    pub has_signature: bool,
    /// Sections parsed from the section table.
    pub sections: Vec<SectionInfo>,
    /// Imports parsed from the import directory.
    pub imports: Vec<ImportInfo>,
    /// Export names parsed from the export directory.
    pub exports: Vec<String>,
    /// Export ordinals.
    pub export_ordinals: Vec<u16>,
    /// Version info strings (FileVersion, ProductVersion, etc.).
    pub version_info: HashMap<String, String>,
    /// Import hash (imphash) — MD5 of sorted `dll.func` list (lowercase, hex).
    pub imphash: String,
    /// Number of data directories present.
    pub num_data_dirs: u32,
    /// Data directory entries: (rva, size) indexed by directory index.
    pub data_directories: Vec<(u32, u32)>,
}

// ─────────────────────────────────────────────────────────────────────────────
// PeModuleAccess — field accessor helper
// ─────────────────────────────────────────────────────────────────────────────

/// Accessor for PE module data fields, for use from YARA rule conditions.
pub struct PeModuleAccess<'a> {
    data: &'a PeModuleData,
}

impl<'a> PeModuleAccess<'a> {
    /// Create a new accessor.
    #[must_use]
    pub fn new(data: &'a PeModuleData) -> Self {
        Self { data }
    }

    /// Machine type.
    #[must_use]
    pub const fn machine(&self) -> u16 {
        self.data.machine
    }

    /// Number of sections.
    #[must_use]
    pub const fn number_of_sections(&self) -> u16 {
        self.data.number_of_sections
    }

    /// Timestamp.
    #[must_use]
    pub const fn timestamp(&self) -> u32 {
        self.data.timestamp
    }

    /// Entry point RVA.
    #[must_use]
    pub const fn entry_point(&self) -> u32 {
        self.data.entry_point
    }

    /// Image base.
    #[must_use]
    pub const fn image_base(&self) -> u64 {
        self.data.image_base
    }

    /// Whether this PE is 64-bit.
    #[must_use]
    pub const fn is_64bit(&self) -> bool {
        self.data.is_64bit
    }

    /// Whether a digital signature is present.
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.data.has_signature
    }

    /// Section entropy for section at `index`.
    #[must_use]
    pub fn section_entropy(&self, index: usize) -> Option<f64> {
        self.data.sections.get(index).map(|s| s.entropy)
    }

    /// Look up a section by name.
    #[must_use]
    pub fn section_by_name(&self, name: &str) -> Option<&SectionInfo> {
        self.data.sections.iter().find(|s| s.name == name)
    }

    /// Import hash.
    #[must_use]
    pub fn imphash(&self) -> &str {
        &self.data.imphash
    }

    /// Whether a given function is imported (case-insensitive).
    #[must_use]
    pub fn imports(&self, func: &str) -> bool {
        let lower = func.to_lowercase();
        self.data.imports.iter().any(|i| i.name.to_lowercase() == lower)
    }

    /// Whether a function from a given DLL is imported.
    #[must_use]
    pub fn imports_from(&self, dll: &str, func: &str) -> bool {
        let dll_lower = dll.to_lowercase();
        let func_lower = func.to_lowercase();
        self.data.imports.iter().any(|i| {
            i.dll.to_lowercase() == dll_lower && i.name.to_lowercase() == func_lower
        })
    }

    /// Number of imports.
    #[must_use]
    pub fn import_count(&self) -> usize {
        self.data.imports.len()
    }

    /// Whether a given function is exported.
    #[must_use]
    pub fn exports(&self, name: &str) -> bool {
        self.data.exports.iter().any(|e| e == name)
    }

    /// Version string value by key.
    #[must_use]
    pub fn version_info(&self, key: &str) -> Option<&str> {
        self.data.version_info.get(key).map(String::as_str)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeModule
// ─────────────────────────────────────────────────────────────────────────────

/// YARA PE module — parses a PE binary and exposes metadata.
#[derive(Debug, Clone, Default)]
pub struct PeModule;

impl PeModule {
    /// Create a new `PeModule`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Parse `data` as a PE binary and return [`PeModuleData`].
    ///
    /// # Errors
    ///
    /// Returns [`PeModuleError`] on any parse failure.
    pub fn parse(&self, data: &[u8]) -> Result<PeModuleData, PeModuleError> {
        // Minimum size: 64 bytes for the DOS header
        if data.len() < 64 {
            return Err(PeModuleError::TooShort { need: 64, have: data.len() });
        }
        // MZ magic
        if &data[0..2] != b"MZ" {
            return Err(PeModuleError::InvalidMzMagic);
        }
        // PE offset at DOS+0x3C
        let pe_offset_raw = read_u32_le(data, 0x3C);
        let pe_offset = usize::try_from(pe_offset_raw).unwrap_or(usize::MAX);
        // Use saturating_add to avoid integer overflow on 32-bit targets where
        // a crafted pe_offset close to usize::MAX would wrap the bounds check.
        if pe_offset.saturating_add(24) > data.len() {
            return Err(PeModuleError::PeOffsetOutOfRange(pe_offset_raw));
        }
        // PE signature
        if &data[pe_offset..pe_offset + 4] != b"PE\x00\x00" {
            return Err(PeModuleError::InvalidPeSignature);
        }

        // COFF header at pe_offset+4
        let coff = pe_offset + 4;
        let machine = read_u16_le(data, coff);
        let number_of_sections = read_u16_le(data, coff + 2);
        let timestamp = read_u32_le(data, coff + 4);
        let size_of_optional = usize::from(read_u16_le(data, coff + 16));
        let characteristics = read_u16_le(data, coff + 18);

        // Optional header at coff+20
        let opt = coff + 20;
        if opt + 2 > data.len() {
            return Err(PeModuleError::TooShort { need: opt + 2, have: data.len() });
        }
        let optional_magic = read_u16_le(data, opt);
        let is_64bit = match optional_magic {
            0x010B => false, // PE32
            0x020B => true,  // PE32+
            other => return Err(PeModuleError::UnsupportedOptionalMagic(other)),
        };
        let linker_major = data.get(opt + 2).copied().unwrap_or(0);
        let linker_minor = data.get(opt + 3).copied().unwrap_or(0);

        // EntryPoint, ImageBase
        let entry_point = read_u32_le(data, opt + 16);
        let (image_base, subsystem_off, dll_chars_off) = if is_64bit {
            let ib = read_u64_le(data, opt + 24);
            (ib, opt + 68, opt + 70)
        } else {
            let ib = u64::from(read_u32_le(data, opt + 28));
            (ib, opt + 68, opt + 70)
        };
        let subsystem = read_u16_le_safe(data, subsystem_off);
        let dll_characteristics = read_u16_le_safe(data, dll_chars_off);
        let size_of_image = read_u32_le_safe(data, opt + 56);

        // Data directories
        let dd_off = if is_64bit { opt + 112 } else { opt + 96 };
        let num_data_dirs = if dd_off + 4 <= data.len() {
            read_u32_le(data, dd_off)
        } else {
            0
        };
        let mut data_directories = Vec::new();
        for i in 0..usize::try_from(num_data_dirs.min(16)).unwrap_or(16) {
            let base = dd_off + 4 + i * 8;
            if base + 8 <= data.len() {
                let rva = read_u32_le(data, base);
                let size = read_u32_le(data, base + 4);
                data_directories.push((rva, size));
            }
        }

        // Has signature? data directory index 4 = security directory
        let has_signature = data_directories
            .get(4)
            .is_some_and(|&(rva, size)| rva != 0 && size != 0);

        // Section table at coff + 20 + size_of_optional
        let section_table_off = coff + 20 + size_of_optional;
        let sections = parse_sections(data, section_table_off, usize::from(number_of_sections));

        // Imports: data directory index 1
        let imports = if let Some(&(imp_rva, imp_size)) = data_directories.get(1) {
            if imp_rva != 0 && imp_size != 0 {
                parse_imports(data, imp_rva, &sections)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Exports: data directory index 0
        let (exports, export_ordinals) =
            if let Some(&(exp_rva, exp_size)) = data_directories.first() {
                if exp_rva != 0 && exp_size != 0 {
                    parse_exports(data, exp_rva, &sections)
                } else {
                    (Vec::new(), Vec::new())
                }
            } else {
                (Vec::new(), Vec::new())
            };

        // Imphash
        let imphash = compute_imphash(&imports);

        Ok(PeModuleData {
            machine,
            number_of_sections,
            timestamp,
            characteristics,
            optional_magic,
            linker_version: (linker_major, linker_minor),
            subsystem,
            dll_characteristics,
            size_of_image,
            entry_point,
            image_base,
            is_64bit,
            has_signature,
            sections,
            imports,
            exports,
            export_ordinals,
            version_info: HashMap::new(),
            imphash,
            num_data_dirs,
            data_directories,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: section parsing
// ─────────────────────────────────────────────────────────────────────────────

fn parse_sections(data: &[u8], table_off: usize, count: usize) -> Vec<SectionInfo> {
    let mut sections = Vec::with_capacity(count.min(96));
    for i in 0..count.min(96) {
        let base = table_off + i * 40;
        if base + 40 > data.len() {
            break;
        }
        let name_bytes = &data[base..base + 8];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_end_matches('\x00')
            .to_string();
        let virtual_size = read_u32_le(data, base + 8);
        let virtual_address = read_u32_le(data, base + 12);
        let raw_size = read_u32_le(data, base + 16);
        let raw_offset = read_u32_le(data, base + 20);
        let characteristics = read_u32_le(data, base + 36);

        // Extract raw bytes for entropy + md5
        let raw_start = usize::try_from(raw_offset).unwrap_or(usize::MAX);
        let raw_end = raw_start.saturating_add(usize::try_from(raw_size).unwrap_or(usize::MAX)).min(data.len());
        let raw_data = if raw_start < data.len() {
            &data[raw_start..raw_end]
        } else {
            &[]
        };

        let entropy = shannon_entropy(raw_data);
        let md5 = simple_md5_hex(raw_data);

        sections.push(SectionInfo {
            name,
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
            characteristics,
            entropy,
            md5,
        });
    }
    sections
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: import parsing
// ─────────────────────────────────────────────────────────────────────────────

fn rva_to_offset(rva: u32, sections: &[SectionInfo]) -> Option<usize> {
    for s in sections {
        // Use saturating addition to avoid u32 overflow on crafted sections
        // where virtual_address + virtual_size wraps past 0xFFFF_FFFF.
        let section_end = s.virtual_address.saturating_add(s.virtual_size.max(s.raw_size));
        if rva >= s.virtual_address && rva < section_end {
            // Both terms fit in usize on any supported target (u32 <= usize::MAX).
            let off = usize::try_from(rva - s.virtual_address).unwrap_or(usize::MAX)
                .saturating_add(usize::try_from(s.raw_offset).unwrap_or(usize::MAX));
            return Some(off);
        }
    }
    None
}

fn parse_imports(data: &[u8], imp_rva: u32, sections: &[SectionInfo]) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    let Some(mut off) = rva_to_offset(imp_rva, sections) else {
        return imports;
    };

    // Cap the number of import descriptors to prevent unbounded loops on
    // crafted PE files that contain a circular or excessively large import
    // directory table.
    const MAX_IMPORT_DESCRIPTORS: usize = 4096;
    let mut descriptor_count = 0usize;
    loop {
        if descriptor_count >= MAX_IMPORT_DESCRIPTORS {
            break;
        }
        descriptor_count += 1;

        if off + 20 > data.len() {
            break;
        }
        let orig_first_thunk = read_u32_le(data, off);
        let dll_name_rva = read_u32_le(data, off + 12);
        let first_thunk = read_u32_le(data, off + 16);

        // All-zero entry = end of import directory
        if orig_first_thunk == 0 && dll_name_rva == 0 && first_thunk == 0 {
            break;
        }

        let dll_name = if let Some(name_off) = rva_to_offset(dll_name_rva, sections) {
            read_cstring(data, name_off).to_lowercase()
        } else {
            String::new()
        };

        // Walk the INT (or IAT if INT is absent)
        let thunk_rva = if orig_first_thunk != 0 { orig_first_thunk } else { first_thunk };
        if let Some(mut thunk_off) = rva_to_offset(thunk_rva, sections) {
            let mut iat_off_opt = rva_to_offset(first_thunk, sections);
            // Cap thunk entries per DLL to prevent unbounded loops on crafted PEs.
            const MAX_THUNK_ENTRIES: usize = 65536;
            let mut thunk_count = 0usize;
            loop {
                if thunk_count >= MAX_THUNK_ENTRIES { break; }
                thunk_count += 1;
                if thunk_off + 4 > data.len() {
                    break;
                }
                let entry = read_u32_le(data, thunk_off);
                let iat_addr = iat_off_opt.map_or(0u64, |o| {
                    if o + 4 <= data.len() {
                        u64::from(read_u32_le(data, o))
                    } else {
                        0
                    }
                });
                if entry == 0 {
                    break;
                }
                let is_ordinal = (entry & 0x8000_0000) != 0;
                if is_ordinal {
                    imports.push(ImportInfo {
                        dll: dll_name.clone(),
                        name: String::new(),
                        ordinal: u16::try_from(entry & 0xFFFF).unwrap_or(u16::MAX),
                        address: iat_addr,
                    });
                } else {
                    let hint_rva = entry & 0x7FFF_FFFF;
                    let func_name = if let Some(hint_off) = rva_to_offset(hint_rva, sections) {
                        if hint_off + 2 < data.len() {
                            read_cstring(data, hint_off + 2)
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };
                    imports.push(ImportInfo {
                        dll: dll_name.clone(),
                        name: func_name,
                        ordinal: 0,
                        address: iat_addr,
                    });
                }
                thunk_off += 4;
                if let Some(ref mut iao) = iat_off_opt {
                    *iao += 4;
                }
            }
        }
        off += 20;
    }
    imports
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: export parsing
// ─────────────────────────────────────────────────────────────────────────────

fn parse_exports(
    data: &[u8],
    exp_rva: u32,
    sections: &[SectionInfo],
) -> (Vec<String>, Vec<u16>) {
    let mut names = Vec::new();
    let mut ordinals = Vec::new();

    let Some(off) = rva_to_offset(exp_rva, sections) else {
        return (names, ordinals);
    };
    if off + 40 > data.len() {
        return (names, ordinals);
    }
    let num_names = usize::try_from(read_u32_le(data, off + 24)).unwrap_or(usize::MAX);
    let name_ptr_rva = read_u32_le(data, off + 32);
    let ord_table_rva = read_u32_le(data, off + 36);
    let ordinal_base = read_u16_le(data, off + 12);

    let Some(name_ptr_off) = rva_to_offset(name_ptr_rva, sections) else {
        return (names, ordinals);
    };
    let Some(ord_off) = rva_to_offset(ord_table_rva, sections) else {
        return (names, ordinals);
    };

    for i in 0..num_names.min(4096) {
        let ptr_off = name_ptr_off + i * 4;
        if ptr_off + 4 > data.len() {
            break;
        }
        let name_rva = read_u32_le(data, ptr_off);
        if let Some(name_off) = rva_to_offset(name_rva, sections) {
            names.push(read_cstring(data, name_off));
        }
        let ord_entry_off = ord_off + i * 2;
        if ord_entry_off + 2 <= data.len() {
            ordinals.push(read_u16_le(data, ord_entry_off).wrapping_add(ordinal_base));
        }
    }

    (names, ordinals)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: imphash computation
// ─────────────────────────────────────────────────────────────────────────────

fn compute_imphash(imports: &[ImportInfo]) -> String {
    let mut entries: Vec<String> = imports
        .iter()
        .filter(|i| !i.name.is_empty())
        .map(|i| {
            let dll = i.dll.trim_end_matches(".dll").to_lowercase();
            let func = i.name.to_lowercase();
            format!("{dll}.{func}")
        })
        .collect();
    entries.sort();
    let joined = entries.join(",");
    simple_md5_hex(joined.as_bytes())
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: byte-reading helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_u16_le(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() { return 0; }
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn read_u16_le_safe(data: &[u8], off: usize) -> u16 {
    read_u16_le(data, off)
}

fn read_u32_le(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() { return 0; }
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn read_u32_le_safe(data: &[u8], off: usize) -> u32 {
    read_u32_le(data, off)
}

fn read_u64_le(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() { return 0; }
    u64::from_le_bytes([
        data[off], data[off+1], data[off+2], data[off+3],
        data[off+4], data[off+5], data[off+6], data[off+7],
    ])
}

fn read_cstring(data: &[u8], off: usize) -> String {
    let end = data[off..].iter().position(|&b| b == 0).unwrap_or(data.len() - off);
    String::from_utf8_lossy(&data[off..off + end]).into_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: entropy and MD5
// ─────────────────────────────────────────────────────────────────────────────

/// Compute Shannon entropy of `data`.
fn shannon_entropy(data: &[u8]) -> f64 {
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

/// Minimal MD5 implementation (RFC 1321) for sections and imphash.
/// Returns lowercase hex string.
fn simple_md5_hex(data: &[u8]) -> String {
    let digest = md5_digest(data);
    let mut out = String::with_capacity(32);
    for b in &digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn md5_digest(data: &[u8]) -> [u8; 16] {
    // Per-round shift amounts
    const S: [u32; 64] = [
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5, 9,14,20,5, 9,14,20,5, 9,14,20,5, 9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21,
    ];
    // Precomputed constants K[i] = floor(2^32 * |sin(i+1)|)
    const K: [u32; 64] = [
        0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee, 0xf57c_0faf, 0x4787_c62a, 0xa830_4613, 0xfd46_9501,
        0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be, 0x6b90_1122, 0xfd98_7193, 0xa679_438e, 0x49b4_0821,
        0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa, 0xd62f_105d, 0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8,
        0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed, 0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a,
        0xfffa_3942, 0x8771_f681, 0x6d9d_6122, 0xfde5_380c, 0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70,
        0x289b_7ec6, 0xeaa1_27fa, 0xd4ef_3085, 0x0488_1d05, 0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665,
        0xf429_2244, 0x432a_ff97, 0xab94_23a7, 0xfc93_a039, 0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
        0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1, 0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb, 0xeb86_d391,
    ];

    // Pad message
    let orig_len = data.len();
    let orig_len_u64 = u64::try_from(orig_len).unwrap_or(u64::MAX);
    let bit_len = orig_len_u64.wrapping_mul(8);
    let pad_len = usize::try_from((55u64.wrapping_sub(orig_len_u64)) & 63).unwrap_or(63) + 1;
    let mut msg = data.to_vec();
    msg.push(0x80);
    msg.resize(orig_len + pad_len, 0);
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (idx, word) in m.iter_mut().enumerate() {
            *word = u32::from_le_bytes([chunk[idx*4], chunk[idx*4+1], chunk[idx*4+2], chunk[idx*4+3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64usize {
            let (f, g): (u32, usize) = match i {
                0..=15  => (b & c | !b & d,             i),
                16..=31 => (d & b | !d & c,             (5*i+1) & 15),
                32..=47 => (b ^ c ^ d,                  (3*i+5) & 15),
                _       => (c ^ (b | !d),               (7*i) & 15),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]).rotate_left(S[i]));
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a0.to_le_bytes());
    result[4..8].copy_from_slice(&b0.to_le_bytes());
    result[8..12].copy_from_slice(&c0.to_le_bytes());
    result[12..16].copy_from_slice(&d0.to_le_bytes());
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe32() -> Vec<u8> {
        let mut pe = vec![0u8; 0x200];
        // MZ magic
        pe[0] = b'M'; pe[1] = b'Z';
        // PE offset at 0x3C = 0x40
        pe[0x3C] = 0x40;
        // PE signature at 0x40
        pe[0x40] = b'P'; pe[0x41] = b'E'; pe[0x42] = 0; pe[0x43] = 0;
        // COFF: machine=x86(0x014c), sections=1, chars=0x0002
        pe[0x44] = 0x4C; pe[0x45] = 0x01; // machine
        pe[0x46] = 0x01; pe[0x47] = 0x00; // number_of_sections = 1
        pe[0x48..0x4C].copy_from_slice(&0u32.to_le_bytes()); // timestamp
        pe[0x50] = 0x00; pe[0x51] = 0x00; // optional header size = 0 for minimal
        // Increase optional header size to PE32 standard
        pe[0x54] = 0xE0; pe[0x55] = 0x00; // size_of_optional_header = 0xE0
        pe[0x56] = 0x02; pe[0x57] = 0x00; // characteristics
        // Optional header at 0x58: PE32 magic
        pe[0x58] = 0x0B; pe[0x59] = 0x01; // magic = 0x010B
        // linker version
        pe[0x5A] = 14; pe[0x5B] = 0;
        // Entry point
        pe[0x68] = 0x00; pe[0x69] = 0x10; pe[0x6A] = 0x00; pe[0x6B] = 0x00;
        // ImageBase
        pe[0x74] = 0x00; pe[0x75] = 0x00; pe[0x76] = 0x40; pe[0x77] = 0x00;
        // SizeOfImage
        pe[0x98] = 0x00; pe[0x99] = 0x10; pe[0x9A] = 0x00; pe[0x9B] = 0x00;
        // NumberOfRvaAndSizes
        pe[0xB4] = 0x10; // 16 data directories
        // Section table starts at 0x58 + 0xE0 = 0x138
        let sec = 0x58 + 0xE0;
        pe[sec..sec+8].copy_from_slice(b".text\x00\x00\x00");
        // virtual_size = 0x100
        pe[sec+8] = 0x00; pe[sec+9] = 0x01; pe[sec+10] = 0x00; pe[sec+11] = 0x00;
        // virtual_address = 0x1000
        pe[sec+12] = 0x00; pe[sec+13] = 0x10; pe[sec+14] = 0x00; pe[sec+15] = 0x00;
        // raw_size = 0x00
        pe[sec+16..sec+20].copy_from_slice(&0u32.to_le_bytes());
        // raw_offset = 0
        pe[sec+20..sec+24].copy_from_slice(&0u32.to_le_bytes());
        // characteristics = 0x60000020 (executable, readable, code)
        pe[sec+36] = 0x20; pe[sec+37] = 0x00; pe[sec+38] = 0x00; pe[sec+39] = 0x60;
        pe
    }

    #[test]
    fn test_parse_minimal_pe() {
        let data = minimal_pe32();
        let module = PeModule::new();
        let result = module.parse(&data);
        assert!(result.is_ok(), "parse failed: {:?}", result);
        let pe = result.unwrap();
        assert_eq!(pe.machine, 0x014C);
        assert_eq!(pe.number_of_sections, 1);
        assert!(!pe.is_64bit);
        assert_eq!(pe.image_base, 0x00400000);
    }

    #[test]
    fn test_parse_invalid_mz() {
        let data = vec![0u8; 100];
        let module = PeModule::new();
        assert!(matches!(module.parse(&data), Err(PeModuleError::InvalidMzMagic)));
    }

    #[test]
    fn test_parse_too_short() {
        let data = vec![b'M', b'Z'];
        let module = PeModule::new();
        assert!(matches!(module.parse(&data), Err(PeModuleError::TooShort { .. })));
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        let data: Vec<u8> = (0..=255u8).cycle().take(256).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_shannon_entropy_constant() {
        let data = vec![0xAAu8; 1000];
        let e = shannon_entropy(&data);
        assert!(e < 0.01);
    }

    #[test]
    fn test_md5_empty() {
        let h = simple_md5_hex(b"");
        assert_eq!(h, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_md5_hello() {
        let h = simple_md5_hex(b"hello");
        assert_eq!(h, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_section_flags() {
        let s = SectionInfo {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: 0x100,
            raw_offset: 0x400,
            raw_size: 0x100,
            characteristics: 0x60000020,
            entropy: 0.0,
            md5: String::new(),
        };
        assert!(s.is_executable());
        assert!(s.is_readable());
        assert!(!s.is_writable());
    }

    #[test]
    fn test_accessor_methods() {
        let data = minimal_pe32();
        let module = PeModule::new();
        let pe = module.parse(&data).unwrap();
        let acc = PeModuleAccess::new(&pe);
        assert_eq!(acc.machine(), 0x014C);
        assert!(!acc.is_signed());
        assert!(!acc.is_64bit());
        assert_eq!(acc.import_count(), 0);
    }
}
