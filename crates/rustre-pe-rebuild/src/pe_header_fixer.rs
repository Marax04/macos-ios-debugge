// rustre-pe-rebuild/src/pe_header_fixer.rs
// Fix PE header fields: CheckSum, SizeOfImage, SizeOfHeaders, TimeDateStamp,
// ImageBase, DataDirectory entries, NumberOfSections.

use std::collections::HashMap;
use std::fmt;

// ─── PE constants ─────────────────────────────────────────────────────────────

const DOS_SIGNATURE:  u16 = 0x5A4D;  // MZ
const PE_SIGNATURE:   u32 = 0x0000_4550;  // PE\0\0
const OPT_HDR32_MAGIC: u16 = 0x010B;
const OPT_HDR64_MAGIC: u16 = 0x020B;

/// Number of data directory entries in a standard PE optional header.
pub const NUM_DATA_DIRECTORIES: usize = 16;

// Data directory indices.
pub const DD_EXPORT:       usize = 0;
pub const DD_IMPORT:       usize = 1;
pub const DD_RESOURCE:     usize = 2;
pub const DD_EXCEPTION:    usize = 3;
pub const DD_SECURITY:     usize = 4;
pub const DD_BASERELOC:    usize = 5;
pub const DD_DEBUG:        usize = 6;
pub const DD_ARCHITECTURE: usize = 7;
pub const DD_GLOBALPTR:    usize = 8;
pub const DD_TLS:          usize = 9;
pub const DD_LOADCONFIG:   usize = 10;
pub const DD_BOUNDIMPORT:  usize = 11;
pub const DD_IAT:          usize = 12;
pub const DD_DELAYIMPORT:  usize = 13;
pub const DD_CLRRUNTIME:   usize = 14;
pub const DD_RESERVED:     usize = 15;

/// Conventional name of a data directory index.
///
/// The `DD_*` indices above were declared and never read, so a change
/// report could only say `DataDirectory[6]` and the reader had to know the
/// table by heart. This routes every index through its documented name.
#[must_use]
pub const fn data_dir_name(index: usize) -> &'static str {
    match index {
        DD_EXPORT       => "Export",
        DD_IMPORT       => "Import",
        DD_RESOURCE     => "Resource",
        DD_EXCEPTION    => "Exception",
        DD_SECURITY     => "Security",
        DD_BASERELOC    => "BaseReloc",
        DD_DEBUG        => "Debug",
        DD_ARCHITECTURE => "Architecture",
        DD_GLOBALPTR    => "GlobalPtr",
        DD_TLS          => "TLS",
        DD_LOADCONFIG   => "LoadConfig",
        DD_BOUNDIMPORT  => "BoundImport",
        DD_IAT          => "IAT",
        DD_DELAYIMPORT  => "DelayImport",
        DD_CLRRUNTIME   => "CLRRuntime",
        DD_RESERVED     => "Reserved",
        _               => "OutOfRange",
    }
}

// ─── Data directory entry ─────────────────────────────────────────────────────

/// One `IMAGE_DATA_DIRECTORY` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataDirEntry {
    pub virtual_address: u32,
    pub size: u32,
}

impl DataDirEntry {
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }

    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 8 { return None; }
        Some(Self {
            virtual_address: u32::from_le_bytes(b[0..4].try_into().ok()?),
            size:            u32::from_le_bytes(b[4..8].try_into().ok()?),
        })
    }

    #[must_use]
    pub fn to_bytes(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&self.virtual_address.to_le_bytes());
        out[4..8].copy_from_slice(&self.size.to_le_bytes());
        out
    }
}

impl fmt::Display for DataDirEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RVA=0x{:08x} Size=0x{:x}", self.virtual_address, self.size)
    }
}

// ─── Header field ─────────────────────────────────────────────────────────────

/// Which header field is being modified.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HeaderField {
    CheckSum,
    SizeOfImage,
    SizeOfHeaders,
    TimeDateStamp,
    ImageBase,
    NumberOfSections,
    DataDirectory(usize),
    EntryPoint,
    SizeOfCode,
    SizeOfInitializedData,
    BaseOfCode,
}

impl fmt::Display for HeaderField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CheckSum              => write!(f, "CheckSum"),
            Self::SizeOfImage           => write!(f, "SizeOfImage"),
            Self::SizeOfHeaders         => write!(f, "SizeOfHeaders"),
            Self::TimeDateStamp         => write!(f, "TimeDateStamp"),
            Self::ImageBase             => write!(f, "ImageBase"),
            Self::NumberOfSections      => write!(f, "NumberOfSections"),
            Self::DataDirectory(i)      => {
                write!(f, "DataDirectory[{i}] ({})", data_dir_name(*i))
            }
            Self::EntryPoint            => write!(f, "AddressOfEntryPoint"),
            Self::SizeOfCode            => write!(f, "SizeOfCode"),
            Self::SizeOfInitializedData => write!(f, "SizeOfInitializedData"),
            Self::BaseOfCode            => write!(f, "BaseOfCode"),
        }
    }
}

/// A single change record for a header field.
#[derive(Debug, Clone)]
pub struct FieldChange {
    pub field: HeaderField,
    pub old_value: u64,
    pub new_value: u64,
    pub byte_offset: usize,
}

// ─── Fix result ───────────────────────────────────────────────────────────────

/// The result of a PE header fix pass.
#[derive(Debug, Clone)]
pub struct FixResult {
    pub changes: Vec<FieldChange>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    /// Computed checksum (may differ from written value if `fix_checksum=false`).
    pub computed_checksum: u32,
}

impl FixResult {
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }

    #[must_use]
    pub const fn change_count(&self) -> usize {
        self.changes.len()
    }
}

// ─── Validation result ────────────────────────────────────────────────────────

/// Validation check on a PE header field.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub field: HeaderField,
    pub is_valid: bool,
    pub actual_value: u64,
    pub expected_value: Option<u64>,
    pub message: String,
}

impl ValidationResult {
    #[must_use]
    pub fn ok(field: HeaderField, value: u64, msg: impl Into<String>) -> Self {
        Self { field, is_valid: true, actual_value: value, expected_value: None,
            message: msg.into() }
    }

    #[must_use]
    pub fn fail(field: HeaderField, actual: u64, expected: u64, msg: impl Into<String>) -> Self {
        Self { field, is_valid: false, actual_value: actual,
            expected_value: Some(expected), message: msg.into() }
    }
}

// ─── PE layout ────────────────────────────────────────────────────────────────

/// Offsets of key fields in a parsed PE, filled during parse.
#[derive(Debug, Clone)]
pub struct PeLayout {
    pub e_lfanew: u32,
    pub file_hdr_off: usize,
    pub opt_hdr_off: usize,
    pub is_64bit: bool,
    pub opt_magic: u16,
    // Offsets of specific fields in the optional header (relative to file start).
    pub checksum_off: usize,
    pub size_of_image_off: usize,
    pub size_of_headers_off: usize,
    pub image_base_off: usize,
    pub entry_point_off: usize,
    pub data_dir_off: usize,
    pub timestamp_off: usize,
    pub section_table_off: usize,
    pub num_sections: u16,
}

// ─── PE Header Fixer ─────────────────────────────────────────────────────────

/// Bitflags for which header fields the fixer should update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FixerFlags(pub u8);

impl FixerFlags {
    pub const FIX_CHECKSUM:        u8 = 0x01;
    pub const FIX_SIZE_OF_IMAGE:   u8 = 0x02;
    pub const FIX_SIZE_OF_HEADERS: u8 = 0x04;
    pub const FIX_TIMESTAMP:       u8 = 0x08;
    pub const FIX_IMAGE_BASE:      u8 = 0x10;
    pub const FIX_DATA_DIRECTORIES: u8 = 0x20;
    pub const FIX_NUM_SECTIONS:    u8 = 0x40;

    #[must_use]
    pub const fn fix_checksum(self) -> bool        { self.0 & Self::FIX_CHECKSUM != 0 }
    #[must_use]
    pub const fn fix_size_of_image(self) -> bool   { self.0 & Self::FIX_SIZE_OF_IMAGE != 0 }
    #[must_use]
    pub const fn fix_size_of_headers(self) -> bool { self.0 & Self::FIX_SIZE_OF_HEADERS != 0 }
    #[must_use]
    pub const fn fix_timestamp(self) -> bool       { self.0 & Self::FIX_TIMESTAMP != 0 }
    #[must_use]
    pub const fn fix_image_base(self) -> bool      { self.0 & Self::FIX_IMAGE_BASE != 0 }
    #[must_use]
    pub const fn fix_data_directories(self) -> bool { self.0 & Self::FIX_DATA_DIRECTORIES != 0 }
    #[must_use]
    pub const fn fix_num_sections(self) -> bool    { self.0 & Self::FIX_NUM_SECTIONS != 0 }
}

/// Configuration for the header fixer.
#[derive(Debug, Clone)]
pub struct FixerConfig {
    pub flags: FixerFlags,
    pub new_timestamp: Option<u32>,
    pub new_image_base: Option<u64>,
    /// Known-correct data directory overrides: index → (rva, size).
    pub data_dir_overrides: HashMap<usize, (u32, u32)>,
}

impl Default for FixerConfig {
    fn default() -> Self {
        Self {
            flags: FixerFlags(
                FixerFlags::FIX_CHECKSUM
                | FixerFlags::FIX_SIZE_OF_IMAGE
                | FixerFlags::FIX_SIZE_OF_HEADERS
                | FixerFlags::FIX_NUM_SECTIONS,
            ),
            new_timestamp: None,
            new_image_base: None,
            data_dir_overrides: HashMap::new(),
        }
    }
}

/// Fixes fields in a PE header byte buffer.
pub struct PeHeaderFixer {
    pub config: FixerConfig,
}

impl PeHeaderFixer {
    #[must_use]
    pub const fn new(config: FixerConfig) -> Self {
        Self { config }
    }

    /// Parse a PE from raw bytes and return its layout.
    #[must_use]
    pub fn parse_layout(&self, pe: &[u8]) -> Option<PeLayout> {
        if pe.len() < 64 { return None; }
        let sig = u16::from_le_bytes(pe[0..2].try_into().ok()?);
        if sig != DOS_SIGNATURE { return None; }
        let e_lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into().ok()?);
        let pe_off = e_lfanew as usize;
        if pe_off + 24 > pe.len() { return None; }
        let pe_sig = u32::from_le_bytes(pe[pe_off..pe_off+4].try_into().ok()?);
        if pe_sig != PE_SIGNATURE { return None; }

        let file_hdr_off = pe_off + 4;
        let num_sections = u16::from_le_bytes(pe[file_hdr_off+2..file_hdr_off+4].try_into().ok()?);
        let timestamp_off = file_hdr_off + 4;
        let size_of_opt_hdr = u16::from_le_bytes(pe[file_hdr_off+16..file_hdr_off+18].try_into().ok()?);

        let opt_hdr_off = file_hdr_off + 20;
        if opt_hdr_off + 2 > pe.len() { return None; }
        let opt_magic = u16::from_le_bytes(pe[opt_hdr_off..opt_hdr_off+2].try_into().ok()?);
        let is_64bit = opt_magic == OPT_HDR64_MAGIC;

        if !is_64bit && opt_magic != OPT_HDR32_MAGIC { return None; }

        // Field offsets within optional header.
        let (checksum_off, size_of_image_off, size_of_headers_off, image_base_off,
            entry_point_off, data_dir_off) = if is_64bit {
            // PE32+
            (opt_hdr_off + 64,   // CheckSum
             opt_hdr_off + 56,   // SizeOfImage
             opt_hdr_off + 60,   // SizeOfHeaders
             opt_hdr_off + 24,   // ImageBase (8 bytes)
             opt_hdr_off + 16,   // AddressOfEntryPoint
             opt_hdr_off + 112,  // DataDirectory
            )
        } else {
            // PE32
            (opt_hdr_off + 64,
             opt_hdr_off + 56,
             opt_hdr_off + 60,
             opt_hdr_off + 28,   // ImageBase (4 bytes)
             opt_hdr_off + 16,
             opt_hdr_off + 96,   // DataDirectory
            )
        };

        let section_table_off = opt_hdr_off + size_of_opt_hdr as usize;

        Some(PeLayout {
            e_lfanew,
            file_hdr_off,
            opt_hdr_off,
            is_64bit,
            opt_magic,
            checksum_off,
            size_of_image_off,
            size_of_headers_off,
            image_base_off,
            entry_point_off,
            data_dir_off,
            timestamp_off,
            section_table_off,
            num_sections,
        })
    }

    /// Compute the PE checksum for a file.
    /// Standard algorithm: sum all 16-bit words, fold carry into low 16 bits,
    /// then add file size.
    #[must_use]
    pub fn compute_checksum(pe: &[u8], checksum_off: usize) -> u32 {
        let mut sum: u64 = 0;
        let len = pe.len();
        let mut i = 0usize;
        while i + 1 < len {
            let word = if i == checksum_off || i == checksum_off + 1 {
                0u16
            } else {
                u16::from_le_bytes([pe[i], pe[i + 1]])
            };
            sum += u64::from(word);
            if sum > 0xFFFF_FFFF {
                sum = (sum & 0xFFFF_FFFF) + (sum >> 32);
            }
            i += 2;
        }
        if !len.is_multiple_of(2) {
            sum += u64::from(pe[len - 1]);
        }
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += sum >> 16;
        (u32::try_from(sum).unwrap_or(u32::MAX) & 0xFFFF) + u32::try_from(len).unwrap_or(u32::MAX)
    }

    /// Validate header fields, returning a list of check results.
    #[must_use]
    pub fn validate(&self, pe: &[u8]) -> Vec<ValidationResult> {
        let Some(layout) = self.parse_layout(pe) else {
            return vec![ValidationResult::fail(
                HeaderField::CheckSum, 0, 0,
                "failed to parse PE layout",
            )];
        };
        let mut results = Vec::new();

        // CheckSum
        let file_cs = u32::from_le_bytes(
            pe[layout.checksum_off..layout.checksum_off+4].try_into().unwrap_or_default());
        let computed_cs = Self::compute_checksum(pe, layout.checksum_off);
        if file_cs == computed_cs {
            results.push(ValidationResult::ok(HeaderField::CheckSum, u64::from(file_cs),
                "checksum matches"));
        } else {
            results.push(ValidationResult::fail(HeaderField::CheckSum, u64::from(file_cs),
                u64::from(computed_cs), "checksum mismatch"));
        }

        // SizeOfImage
        let soi = u32::from_le_bytes(
            pe[layout.size_of_image_off..layout.size_of_image_off+4].try_into().unwrap_or_default());
        results.push(ValidationResult::ok(HeaderField::SizeOfImage, u64::from(soi),
            format!("SizeOfImage = 0x{soi:x}")));

        // SizeOfHeaders
        let soh = u32::from_le_bytes(
            pe[layout.size_of_headers_off..layout.size_of_headers_off+4].try_into().unwrap_or_default());
        results.push(ValidationResult::ok(HeaderField::SizeOfHeaders, u64::from(soh),
            format!("SizeOfHeaders = 0x{soh:x}")));

        // NumberOfSections sanity
        if layout.num_sections == 0 || layout.num_sections > 96 {
            results.push(ValidationResult::fail(HeaderField::NumberOfSections,
                u64::from(layout.num_sections), 1,
                "NumberOfSections is out of expected range"));
        } else {
            results.push(ValidationResult::ok(HeaderField::NumberOfSections,
                u64::from(layout.num_sections), "OK"));
        }

        results
    }

    /// Fix all configured header fields in-place; return a change log.
    pub fn fix(&self, pe: &mut [u8]) -> FixResult {
        let Some(layout) = self.parse_layout(pe) else {
            return FixResult {
                changes: vec![],
                errors: vec!["could not parse PE layout".into()],
                warnings: vec![],
                computed_checksum: 0,
            };
        };

        let mut changes = Vec::new();
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        self.apply_size_fixes(pe, &layout, &mut changes);
        self.apply_timestamp_fix(pe, &layout, &mut changes);
        self.apply_image_base_fix(pe, &layout, &mut changes, &mut warnings);
        self.apply_data_dir_fixes(pe, &layout, &mut changes);

        // ── CheckSum (last, after all other fixes) ──────────────────────────
        let computed_checksum = Self::compute_checksum(pe, layout.checksum_off);
        if self.config.flags.fix_checksum() {
            let old = u64::from(u32::from_le_bytes(
                pe[layout.checksum_off..layout.checksum_off+4]
                    .try_into().unwrap_or_default()));
            pe[layout.checksum_off..layout.checksum_off+4]
                .copy_from_slice(&computed_checksum.to_le_bytes());
            if old != u64::from(computed_checksum) {
                changes.push(FieldChange {
                    field: HeaderField::CheckSum,
                    old_value: old, new_value: u64::from(computed_checksum),
                    byte_offset: layout.checksum_off,
                });
            }
        }

        // Validate SizeOfImage didn't shrink.
        if let Some(soi_change) = changes
            .iter()
            .find(|c| matches!(c.field, HeaderField::SizeOfImage))
            .filter(|c| c.new_value < c.old_value)
        {
            errors.push(format!(
                "SizeOfImage shrank from {:#x} to {:#x}",
                soi_change.old_value, soi_change.new_value
            ));
        }
        FixResult { changes, errors, warnings, computed_checksum }
    }

    fn apply_size_fixes(&self, pe: &mut [u8], layout: &PeLayout, changes: &mut Vec<FieldChange>) {
        if self.config.flags.fix_size_of_image()
            && let Some(new_soi) = Self::compute_size_of_image(pe, layout)
        {
            let old = u64::from(u32::from_le_bytes(
                pe[layout.size_of_image_off..layout.size_of_image_off+4]
                    .try_into().unwrap_or_default()));
            if old != u64::from(new_soi) {
                pe[layout.size_of_image_off..layout.size_of_image_off+4]
                    .copy_from_slice(&new_soi.to_le_bytes());
                changes.push(FieldChange {
                    field: HeaderField::SizeOfImage,
                    old_value: old, new_value: u64::from(new_soi),
                    byte_offset: layout.size_of_image_off,
                });
            }
        }
        if self.config.flags.fix_size_of_headers() {
            let hdr_end = layout.section_table_off + usize::from(layout.num_sections) * 40;
            let new_soh = u32::try_from((hdr_end + 0x1FF) & !0x1FF).unwrap_or(u32::MAX);
            let old = u64::from(u32::from_le_bytes(
                pe[layout.size_of_headers_off..layout.size_of_headers_off+4]
                    .try_into().unwrap_or_default()));
            if old != u64::from(new_soh) {
                pe[layout.size_of_headers_off..layout.size_of_headers_off+4]
                    .copy_from_slice(&new_soh.to_le_bytes());
                changes.push(FieldChange {
                    field: HeaderField::SizeOfHeaders,
                    old_value: old, new_value: u64::from(new_soh),
                    byte_offset: layout.size_of_headers_off,
                });
            }
        }
    }

    fn apply_timestamp_fix(&self, pe: &mut [u8], layout: &PeLayout, changes: &mut Vec<FieldChange>) {
        if self.config.flags.fix_timestamp() {
            let ts = self.config.new_timestamp.unwrap_or(0);
            let old = u64::from(u32::from_le_bytes(
                pe[layout.timestamp_off..layout.timestamp_off+4]
                    .try_into().unwrap_or_default()));
            pe[layout.timestamp_off..layout.timestamp_off+4]
                .copy_from_slice(&ts.to_le_bytes());
            changes.push(FieldChange {
                field: HeaderField::TimeDateStamp,
                old_value: old, new_value: u64::from(ts),
                byte_offset: layout.timestamp_off,
            });
        }
    }

    fn apply_image_base_fix(
        &self, pe: &mut [u8], layout: &PeLayout,
        changes: &mut Vec<FieldChange>, warnings: &mut Vec<String>,
    ) {
        if !self.config.flags.fix_image_base() { return; }
        let Some(new_base) = self.config.new_image_base else {
            warnings.push("fix_image_base=true but no new_image_base provided".into());
            return;
        };
        if layout.is_64bit {
            let old = u64::from_le_bytes(
                pe[layout.image_base_off..layout.image_base_off+8]
                    .try_into().unwrap_or_default());
            pe[layout.image_base_off..layout.image_base_off+8]
                .copy_from_slice(&new_base.to_le_bytes());
            changes.push(FieldChange {
                field: HeaderField::ImageBase,
                old_value: old, new_value: new_base,
                byte_offset: layout.image_base_off,
            });
        } else {
            let new_base32 = u32::try_from(new_base).unwrap_or(u32::MAX);
            let old = u64::from(u32::from_le_bytes(
                pe[layout.image_base_off..layout.image_base_off+4]
                    .try_into().unwrap_or_default()));
            pe[layout.image_base_off..layout.image_base_off+4]
                .copy_from_slice(&new_base32.to_le_bytes());
            changes.push(FieldChange {
                field: HeaderField::ImageBase,
                old_value: old, new_value: u64::from(new_base32),
                byte_offset: layout.image_base_off,
            });
        }
    }

    fn apply_data_dir_fixes(&self, pe: &mut [u8], layout: &PeLayout, changes: &mut Vec<FieldChange>) {
        if !self.config.flags.fix_data_directories() { return; }
        for (&idx, &(rva, sz)) in &self.config.data_dir_overrides {
            if idx >= NUM_DATA_DIRECTORIES { continue; }
            let off = layout.data_dir_off + idx * 8;
            if off + 8 > pe.len() { continue; }
            let old_dd = DataDirEntry::from_bytes(&pe[off..off+8]).unwrap_or_default();
            let new_dd = DataDirEntry { virtual_address: rva, size: sz };
            pe[off..off+8].copy_from_slice(&new_dd.to_bytes());
            changes.push(FieldChange {
                field: HeaderField::DataDirectory(idx),
                old_value: (u64::from(old_dd.virtual_address) << 32) | u64::from(old_dd.size),
                new_value: (u64::from(rva) << 32) | u64::from(sz),
                byte_offset: off,
            });
        }
    }

    fn compute_size_of_image(pe: &[u8], layout: &PeLayout) -> Option<u32> {
        let (sect_align, file_align) = {
            // Original code reads SectionAlignment from +56 and FileAlignment
            // from +52; the relative ordering is preserved here.
            let fa_off = layout.opt_hdr_off + 52;
            let sa_off = layout.opt_hdr_off + 56;
            if sa_off + 4 > pe.len() { return None; }
            (
                u32::from_le_bytes(pe[sa_off..sa_off+4].try_into().ok()?),
                u32::from_le_bytes(pe[fa_off..fa_off+4].try_into().ok()?),
            )
        };
        let sa = if sect_align == 0 { 0x1000 } else { sect_align };
        // Sanity: SectionAlignment must not be smaller than FileAlignment.
        debug_assert!(file_align == 0 || sa >= file_align);
        let mut max_end: u32 = 0;
        for i in 0..layout.num_sections as usize {
            let off = layout.section_table_off + i * 40;
            if off + 40 > pe.len() { break; }
            let va   = u32::from_le_bytes(pe[off+12..off+16].try_into().ok()?);
            let vsz  = u32::from_le_bytes(pe[off+8..off+12].try_into().ok()?);
            let end = va + ((vsz + sa - 1) & !(sa - 1));
            if end > max_end { max_end = end; }
        }
        if max_end == 0 { return None; }
        Some((max_end + sa - 1) & !(sa - 1))
    }
}

impl Default for PeHeaderFixer {
    fn default() -> Self {
        Self::new(FixerConfig::default())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_dir_entry_roundtrip() {
        let dd = DataDirEntry { virtual_address: 0x1234_5678, size: 0xABCD };
        let bytes = dd.to_bytes();
        let parsed = DataDirEntry::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, dd);
    }

    #[test]
    fn test_data_dir_entry_is_present() {
        assert!(DataDirEntry { virtual_address: 0x1000, size: 0x100 }.is_present());
        assert!(!DataDirEntry::default().is_present());
    }

    #[test]
    fn test_checksum_empty() {
        let cs = PeHeaderFixer::compute_checksum(&[], 0);
        assert_eq!(cs, 0);
    }

    #[test]
    fn test_checksum_consistency() {
        let data: Vec<u8> = (0..=255u8).collect();
        let cs1 = PeHeaderFixer::compute_checksum(&data, 999);
        let cs2 = PeHeaderFixer::compute_checksum(&data, 999);
        assert_eq!(cs1, cs2);
    }

    #[test]
    fn test_validation_result_display() {
        let r = ValidationResult::ok(HeaderField::CheckSum, 0xDEAD, "matches");
        assert!(r.is_valid);
        assert_eq!(r.actual_value, 0xDEAD);
    }

    #[test]
    fn test_validation_fail() {
        let r = ValidationResult::fail(HeaderField::SizeOfImage, 0x1000, 0x2000, "too small");
        assert!(!r.is_valid);
        assert_eq!(r.expected_value, Some(0x2000));
    }

    #[test]
    fn test_header_field_display() {
        assert_eq!(format!("{}", HeaderField::CheckSum), "CheckSum");
        assert_eq!(
            format!("{}", HeaderField::DataDirectory(5)),
            "DataDirectory[5] (BaseReloc)"
        );
        // every declared index resolves to its documented name
        assert_eq!(data_dir_name(DD_EXPORT), "Export");
        assert_eq!(data_dir_name(DD_EXCEPTION), "Exception");
        assert_eq!(data_dir_name(DD_ARCHITECTURE), "Architecture");
        assert_eq!(data_dir_name(DD_GLOBALPTR), "GlobalPtr");
        assert_eq!(data_dir_name(DD_TLS), "TLS");
        assert_eq!(data_dir_name(DD_LOADCONFIG), "LoadConfig");
        assert_eq!(data_dir_name(DD_BOUNDIMPORT), "BoundImport");
        assert_eq!(data_dir_name(DD_DELAYIMPORT), "DelayImport");
        assert_eq!(data_dir_name(DD_CLRRUNTIME), "CLRRuntime");
        assert_eq!(data_dir_name(DD_RESERVED), "Reserved");
        assert_eq!(data_dir_name(DD_SECURITY), "Security");
        assert_eq!(data_dir_name(DD_RESOURCE), "Resource");
        assert_eq!(data_dir_name(DD_DEBUG), "Debug");
        assert_eq!(data_dir_name(NUM_DATA_DIRECTORIES), "OutOfRange");
        assert_eq!(format!("{}", HeaderField::ImageBase), "ImageBase");
    }

    #[test]
    fn test_fix_result_is_clean() {
        let r = FixResult {
            changes: vec![],
            errors: vec![],
            warnings: vec![],
            computed_checksum: 0,
        };
        assert!(r.is_clean());
        assert_eq!(r.change_count(), 0);
    }

    #[test]
    fn test_parse_invalid_dos() {
        let fixer = PeHeaderFixer::default();
        let result = fixer.parse_layout(&[0x00, 0x00]);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_too_short() {
        let fixer = PeHeaderFixer::default();
        let result = fixer.parse_layout(&[0x4D, 0x5A]);
        assert!(result.is_none());
    }

    #[test]
    fn test_data_dir_const_values() {
        assert_eq!(DD_IMPORT, 1);
        assert_eq!(DD_BASERELOC, 5);
        assert_eq!(DD_IAT, 12);
        assert_eq!(NUM_DATA_DIRECTORIES, 16);
    }
}
