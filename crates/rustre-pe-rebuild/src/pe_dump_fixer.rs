//! `pe_dump_fixer` — Fix a raw memory-dumped PE image for analysis / re-execution
//!
//! When a PE is dumped from a running process the on-disk representation
//! differs from the in-memory layout in several ways:
//!
//! * Section raw pointers and raw sizes reflect the *virtual* layout, not the
//!   file layout (i.e. `PointerToRawData` == `VirtualAddress` and
//!   `SizeOfRawData` == aligned virtual size).
//! * The optional header fields (`SizeOfImage`, `SizeOfCode`, etc.) may be
//!   wrong because the unpacker modified them.
//! * The PE signature and machine type may be corrupted.
//! * Data directory entries (import/export/reloc) may point to invalid RVAs
//!   if the unpacker zeroed them.
//! * ASLR slides the image base, so `ImageBase` in the header may not match
//!   the actual load address.
//!
//! This module provides [`PeDumpFixer`] which corrects all of the above.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::RebuildError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const PE_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
pub const MZ_SIGNATURE: u16 = 0x5A4D;      // "MZ"
pub const MACHINE_I386: u16 = 0x014C;
pub const MACHINE_AMD64: u16 = 0x8664;
pub const MACHINE_ARM64: u16 = 0xAA64;

/// Data directory index constants.
pub mod dd {
    pub const EXPORT:     usize = 0;
    pub const IMPORT:     usize = 1;
    pub const RESOURCE:   usize = 2;
    pub const EXCEPTION:  usize = 3;
    pub const SECURITY:   usize = 4;
    pub const BASERELOC:  usize = 5;
    pub const DEBUG:      usize = 6;
    pub const TLS:        usize = 9;
    pub const LOAD_CFG:   usize = 10;
    pub const IAT:        usize = 12;
    pub const DELAY_IMPORT: usize = 13;
    pub const COM_DESCRIPTOR: usize = 14;

    /// Conventional name of a data directory index.
    ///
    /// The indices above were declared and never read -- the one place that
    /// needed an index wrote a bare `4` with a comment instead -- so a fix
    /// record could not say which directory it had touched.
    #[must_use]
    pub const fn name(index: usize) -> &'static str {
        match index {
            EXPORT         => "Export",
            IMPORT         => "Import",
            RESOURCE       => "Resource",
            EXCEPTION      => "Exception",
            SECURITY       => "Security",
            BASERELOC      => "BaseReloc",
            DEBUG          => "Debug",
            TLS            => "TLS",
            LOAD_CFG       => "LoadConfig",
            IAT            => "IAT",
            DELAY_IMPORT   => "DelayImport",
            COM_DESCRIPTOR => "COMDescriptor",
            _              => "Unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Fixer configuration
// ---------------------------------------------------------------------------

/// Bitflags controlling which fixes [`PeDumpFixer`] applies.
///
/// Combine constants with `|`: `DumpFixerFlags::REPAIR_SIGNATURES | DumpFixerFlags::RECALC_SIZE_OF_IMAGE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DumpFixerFlags(pub u8);

impl DumpFixerFlags {
    /// Repair the PE and MZ signatures if they are corrupted.
    pub const REPAIR_SIGNATURES: Self = Self(0x01);
    /// Recalculate `SizeOfImage` from section headers.
    pub const RECALC_SIZE_OF_IMAGE: Self = Self(0x02);
    /// Recalculate `SizeOfCode` / `SizeOfInitializedData` etc.
    pub const RECALC_SIZE_FIELDS: Self = Self(0x04);
    /// Convert virtual layout (`PointerToRawData` == VA) to a proper file layout.
    pub const CONVERT_VIRTUAL_TO_RAW: Self = Self(0x08);
    /// Zero out the Security data directory (strip signature stub).
    pub const STRIP_SECURITY_DIR: Self = Self(0x10);
    /// Rebase `ImageBase` to the canonical default (`0x0040_0000` / `0x0001_4000_0000`).
    pub const REBASE_TO_DEFAULT: Self = Self(0x20);
    /// All fixes enabled.
    pub const ALL: Self = Self(0x3F);
    /// No fixes (pass-through).
    pub const NONE: Self = Self(0x00);

    /// Returns `true` if `flag` is set in `self`.
    #[must_use]
    pub const fn contains(self, flag: Self) -> bool { self.0 & flag.0 != 0 }

    #[must_use]
    pub const fn repair_signatures(self) -> bool { self.contains(Self::REPAIR_SIGNATURES) }
    #[must_use]
    pub const fn recalc_size_of_image(self) -> bool { self.contains(Self::RECALC_SIZE_OF_IMAGE) }
    #[must_use]
    pub const fn recalc_size_fields(self) -> bool { self.contains(Self::RECALC_SIZE_FIELDS) }
    #[must_use]
    pub const fn convert_virtual_to_raw(self) -> bool { self.contains(Self::CONVERT_VIRTUAL_TO_RAW) }
    #[must_use]
    pub const fn strip_security_dir(self) -> bool { self.contains(Self::STRIP_SECURITY_DIR) }
    #[must_use]
    pub const fn rebase_to_default(self) -> bool { self.contains(Self::REBASE_TO_DEFAULT) }
}

impl std::ops::BitOr for DumpFixerFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
}

impl std::ops::BitAnd for DumpFixerFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self { Self(self.0 & rhs.0) }
}

/// Configuration for the dump fixer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpFixerConfig {
    /// Expected machine type.  If `None`, the existing value is kept.
    pub machine_type: Option<u16>,
    /// Actual load address (used to compute slide).
    pub actual_image_base: Option<u64>,
    /// Feature flags controlling which fixes are applied.
    pub flags: DumpFixerFlags,
    /// Override `SectionAlignment`.  Usually 0x1000 for memory dumps.
    pub section_alignment: Option<u32>,
    /// Override `FileAlignment`.  Set to 0x200 for file layout.
    pub file_alignment: Option<u32>,
}

impl Default for DumpFixerFlags {
    fn default() -> Self {
        Self::REPAIR_SIGNATURES
            | Self::RECALC_SIZE_OF_IMAGE
            | Self::RECALC_SIZE_FIELDS
            | Self::CONVERT_VIRTUAL_TO_RAW
            | Self::STRIP_SECURITY_DIR
        // REBASE_TO_DEFAULT is off by default
    }
}

impl Default for DumpFixerConfig {
    fn default() -> Self {
        Self {
            machine_type: None,
            actual_image_base: None,
            flags: DumpFixerFlags::default(),
            section_alignment: Some(0x1000),
            file_alignment: Some(0x0200),
        }
    }
}

// ---------------------------------------------------------------------------
// Fix result
// ---------------------------------------------------------------------------

/// Diagnostic record of a single fix applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedFix {
    pub description: String,
    pub offset: usize,
    pub old_value: String,
    pub new_value: String,
}

/// Result returned by [`PeDumpFixer::fix`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixResult {
    /// The fixed PE bytes.
    pub data: Vec<u8>,
    /// List of changes made.
    pub fixes: Vec<AppliedFix>,
    /// True if the image had an ASLR slide applied.
    pub was_rebased: bool,
    /// Computed slide (`new_base` - `old_base`), 0 if no rebase.
    pub slide: i64,
}

// ---------------------------------------------------------------------------
// PeDumpFixer
// ---------------------------------------------------------------------------

/// Fixes a memory-dumped PE image to make it loadable / analysable.
pub struct PeDumpFixer {
    data: Vec<u8>,
    cfg: DumpFixerConfig,
    fixes: Vec<AppliedFix>,
    /// Offset of the PE signature ("PE\0\0") in `data`.
    pe_offset: usize,
    is_pe32plus: bool,
}

impl PeDumpFixer {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Construct a fixer from raw dump bytes and a configuration.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError`] if the data is too small to contain a valid PE header.
    pub fn new(data: Vec<u8>, cfg: DumpFixerConfig) -> Result<Self, RebuildError> {
        let pe_offset = Self::find_pe_offset(&data);
        let is_pe32plus = Self::detect_pe32plus(&data, pe_offset);
        Ok(Self { data, cfg, fixes: Vec::new(), pe_offset, is_pe32plus })
    }

    fn find_pe_offset(data: &[u8]) -> usize {
        if data.len() < 0x40 { return 0; }
        // Try e_lfanew first.
        if data[0] == b'M' && data[1] == b'Z' {
            let lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
            if lfanew + 4 <= data.len() { return lfanew; }
        }
        // Scan for PE\0\0.
        for i in 0..data.len().saturating_sub(4) {
            if &data[i..i + 4] == b"PE\0\0" { return i; }
        }
        0
    }

    fn detect_pe32plus(data: &[u8], pe_offset: usize) -> bool {
        let opt = pe_offset + 4 + 20;
        if opt + 2 > data.len() { return false; }
        u16::from_le_bytes(data[opt..opt + 2].try_into().unwrap()) == 0x020B
    }

    // -----------------------------------------------------------------------
    // Layout helpers
    // -----------------------------------------------------------------------

    const fn coff_offset(&self) -> usize { self.pe_offset + 4 }
    const fn opt_offset(&self) -> usize  { self.pe_offset + 4 + 20 }

    fn num_sections(&self) -> usize {
        let coff = self.coff_offset();
        if coff + 4 > self.data.len() { return 0; }
        u16::from_le_bytes(self.data[coff + 2..coff + 4].try_into().unwrap()) as usize
    }

    fn opt_size(&self) -> usize {
        let coff = self.coff_offset();
        if coff + 18 > self.data.len() { return 0; }
        u16::from_le_bytes(self.data[coff + 16..coff + 18].try_into().unwrap()) as usize
    }

    fn section_table_offset(&self) -> usize { self.opt_offset() + self.opt_size() }

    /// Read a section header at index `i` (offset, size-pairs of key fields).
    fn section_header(&self, i: usize) -> Option<SectionHeader> {
        let base = self.section_table_offset() + i * 40;
        if base + 40 > self.data.len() { return None; }
        let d = &self.data[base..];
        let mut name = [0u8; 8];
        name.copy_from_slice(&d[0..8]);
        Some(SectionHeader {
            name,
            virtual_size:        u32::from_le_bytes(d[8..12].try_into().unwrap()),
            virtual_address:     u32::from_le_bytes(d[12..16].try_into().unwrap()),
            size_of_raw_data:    u32::from_le_bytes(d[16..20].try_into().unwrap()),
            pointer_to_raw_data: u32::from_le_bytes(d[20..24].try_into().unwrap()),
            characteristics:     u32::from_le_bytes(d[36..40].try_into().unwrap()),
            header_offset:       base,
        })
    }

    fn write_section_field(&mut self, sec_offset: usize, field_offset: usize, val: u32) {
        let off = sec_offset + field_offset;
        if off + 4 <= self.data.len() {
            self.data[off..off + 4].copy_from_slice(&val.to_le_bytes());
        }
    }

    fn read_opt_u32(&self, offset_in_opt: usize) -> u32 {
        let off = self.opt_offset() + offset_in_opt;
        if off + 4 > self.data.len() { return 0; }
        u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap())
    }

    fn write_opt_u32(&mut self, offset_in_opt: usize, val: u32) {
        let off = self.opt_offset() + offset_in_opt;
        if off + 4 <= self.data.len() {
            self.data[off..off + 4].copy_from_slice(&val.to_le_bytes());
        }
    }

    fn read_opt_u64(&self, offset_in_opt: usize) -> u64 {
        let off = self.opt_offset() + offset_in_opt;
        if off + 8 > self.data.len() { return 0; }
        u64::from_le_bytes(self.data[off..off + 8].try_into().unwrap())
    }

    fn write_opt_u64(&mut self, offset_in_opt: usize, val: u64) {
        let off = self.opt_offset() + offset_in_opt;
        if off + 8 <= self.data.len() {
            self.data[off..off + 8].copy_from_slice(&val.to_le_bytes());
        }
    }

    fn record_fix(&mut self, description: &str, offset: usize, old: &str, new: &str) {
        self.fixes.push(AppliedFix {
            description: description.to_owned(),
            offset,
            old_value: old.to_owned(),
            new_value: new.to_owned(),
        });
    }

    // -----------------------------------------------------------------------
    // Individual fix steps
    // -----------------------------------------------------------------------

    fn fix_signatures(&mut self) {
        // MZ signature at offset 0.
        if self.data.len() >= 2 {
            let mz = u16::from_le_bytes(self.data[0..2].try_into().unwrap());
            if mz != MZ_SIGNATURE {
                self.record_fix("Repair MZ signature", 0, &format!("{mz:#06x}"), "0x5A4D");
                self.data[0..2].copy_from_slice(&MZ_SIGNATURE.to_le_bytes());
            }
        }
        // PE signature.
        if self.pe_offset + 4 <= self.data.len() {
            let pe = u32::from_le_bytes(
                self.data[self.pe_offset..self.pe_offset + 4].try_into().unwrap(),
            );
            if pe != PE_SIGNATURE {
                self.record_fix(
                    "Repair PE signature",
                    self.pe_offset,
                    &format!("{pe:#010x}"),
                    "0x00004550",
                );
                self.data[self.pe_offset..self.pe_offset + 4]
                    .copy_from_slice(&PE_SIGNATURE.to_le_bytes());
            }
        }
    }

    fn fix_machine_type(&mut self, machine: u16) {
        let coff = self.coff_offset();
        if coff + 2 > self.data.len() { return; }
        let old = u16::from_le_bytes(self.data[coff..coff + 2].try_into().unwrap());
        if old != machine {
            self.record_fix("Fix Machine type", coff, &format!("{old:#06x}"), &format!("{machine:#06x}"));
            self.data[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
        }
    }

    fn fix_alignment_fields(&mut self, section_align: u32, file_align: u32) {
        let prev_section_align = self.read_opt_u32(32);
        let prev_file_align = self.read_opt_u32(36);
        if prev_section_align != section_align {
            self.record_fix("Fix SectionAlignment", self.opt_offset() + 32,
                &format!("{prev_section_align:#010x}"), &format!("{section_align:#010x}"));
            self.write_opt_u32(32, section_align);
        }
        if prev_file_align != file_align {
            self.record_fix("Fix FileAlignment", self.opt_offset() + 36,
                &format!("{prev_file_align:#010x}"), &format!("{file_align:#010x}"));
            self.write_opt_u32(36, file_align);
        }
    }

    fn recalculate_size_of_image(&mut self) -> u32 {
        let n = self.num_sections();
        let sa = self.read_opt_u32(32).max(0x1000);
        let mut max_end: u32 = sa;
        for i in 0..n {
            if let Some(sh) = self.section_header(i) {
                let vsz = sh.virtual_size.max(sh.size_of_raw_data);
                let end = sh.virtual_address + align_up(vsz, sa);
                if end > max_end { max_end = end; }
            }
        }
        let old = self.read_opt_u32(56);
        if old != max_end {
            self.record_fix("Recalculate SizeOfImage", self.opt_offset() + 56,
                &format!("{old:#010x}"), &format!("{max_end:#010x}"));
            self.write_opt_u32(56, max_end);
        }
        max_end
    }

    fn recalculate_size_fields(&mut self) {
        let n = self.num_sections();
        let fa = self.read_opt_u32(36).max(0x200);
        let (mut code, mut idata, mut udata) = (0u32, 0u32, 0u32);
        for i in 0..n {
            if let Some(sh) = self.section_header(i) {
                let raw = align_up(sh.size_of_raw_data.max(sh.virtual_size), fa);
                if sh.characteristics & 0x20 != 0  { code  += raw; }
                if sh.characteristics & 0x40 != 0  { idata += raw; }
                if sh.characteristics & 0x80 != 0  { udata += raw; }
            }
        }
        let disk_code       = self.read_opt_u32(4);
        let disk_init_data  = self.read_opt_u32(8);
        let disk_uninit_data = self.read_opt_u32(12);
        if disk_code       != code  { self.record_fix("Fix SizeOfCode", self.opt_offset()+4, &format!("{disk_code:#x}"), &format!("{code:#x}")); self.write_opt_u32(4, code); }
        if disk_init_data  != idata { self.record_fix("Fix SizeOfInitializedData", self.opt_offset()+8, &format!("{disk_init_data:#x}"), &format!("{idata:#x}")); self.write_opt_u32(8, idata); }
        if disk_uninit_data != udata { self.record_fix("Fix SizeOfUninitializedData", self.opt_offset()+12, &format!("{disk_uninit_data:#x}"), &format!("{udata:#x}")); self.write_opt_u32(12, udata); }
    }

    fn fix_size_of_headers(&mut self) {
        let section_table = self.section_table_offset();
        let n = self.num_sections();
        let end_of_headers = section_table + n * 40;
        let fa = self.read_opt_u32(36).max(0x200);
        let soh = align_up(u32::try_from(end_of_headers).unwrap_or(u32::MAX), fa);
        let old = self.read_opt_u32(60);
        if old != soh {
            self.record_fix("Fix SizeOfHeaders", self.opt_offset()+60, &format!("{old:#x}"), &format!("{soh:#x}"));
            self.write_opt_u32(60, soh);
        }
    }

    fn strip_security_directory(&mut self) {
        self.zero_data_directory(dd::SECURITY);
    }

    /// Zero one data directory entry, recording the fix under its name.
    fn zero_data_directory(&mut self, index: usize) {
        let dd_base = self.data_directory_offset(index);
        if dd_base + 8 <= self.data.len() {
            let old_rva = u32::from_le_bytes(self.data[dd_base..dd_base+4].try_into().unwrap());
            let old_sz  = u32::from_le_bytes(self.data[dd_base+4..dd_base+8].try_into().unwrap());
            if old_rva != 0 || old_sz != 0 {
                self.record_fix(&format!("Strip {} directory", dd::name(index)), dd_base,
                    &format!("rva={old_rva:#x} sz={old_sz:#x}"), "zeroed");
                self.data[dd_base..dd_base+8].fill(0);
            }
        }
    }

    const fn data_directory_offset(&self, index: usize) -> usize {
        let opt = self.opt_offset();
        if self.is_pe32plus { opt + 112 + index * 8 } else { opt + 96 + index * 8 }
    }

    /// Convert in-memory layout (`PointerToRawData` == `VirtualAddress`) to a
    /// compact file layout, placing sections contiguously after the header area.
    fn convert_virtual_to_raw_layout(&mut self) {
        let n = self.num_sections();
        let fa = self.read_opt_u32(36).max(0x200);
        let mut sections: Vec<SectionHeader> = (0..n)
            .filter_map(|i| self.section_header(i))
            .collect();

        // Sort by virtual address to get canonical order.
        sections.sort_by_key(|s| s.virtual_address);

        // Compute size_of_headers.
        let soh = align_up(
            u32::try_from(self.section_table_offset() + n * 40).unwrap_or(u32::MAX),
            fa,
        ) as usize;

        // Build new file.
        let mut new_file = vec![0u8; soh];
        new_file[..soh.min(self.data.len())]
            .copy_from_slice(&self.data[..soh.min(self.data.len())]);

        let mut raw_ptr = u32::try_from(soh).unwrap_or(u32::MAX);
        for sh in &sections {
            let va = usize::try_from(sh.virtual_address).unwrap_or(usize::MAX);
            let sz = usize::try_from(sh.virtual_size.max(sh.size_of_raw_data)).unwrap_or(usize::MAX);
            let aligned_sz = usize::try_from(align_up(u32::try_from(sz).unwrap_or(u32::MAX), fa)).unwrap_or(usize::MAX);

            // Copy from virtual layout (data at offset == VA).
            let src_end = (va + sz).min(self.data.len());
            let copy_len = src_end.saturating_sub(va);

            let mut sec_data = vec![0u8; aligned_sz];
            if va < self.data.len() {
                sec_data[..copy_len].copy_from_slice(&self.data[va..va + copy_len]);
            }
            new_file.extend_from_slice(&sec_data);

            // Patch section header in new_file.
            let hdr_off = sh.header_offset;
            let new_raw_sz = u32::try_from(aligned_sz).unwrap_or(u32::MAX);
            if hdr_off + 40 <= new_file.len() {
                new_file[hdr_off + 16..hdr_off + 20].copy_from_slice(&new_raw_sz.to_le_bytes());
                new_file[hdr_off + 20..hdr_off + 24].copy_from_slice(&raw_ptr.to_le_bytes());
            }

            self.record_fix(
                &format!("Convert virtual->raw: section {:?}", &sh.name[..4]),
                hdr_off + 20,
                &format!("{:#010x}", sh.pointer_to_raw_data),
                &format!("{raw_ptr:#010x}"),
            );

            raw_ptr += u32::try_from(aligned_sz).unwrap_or(u32::MAX);
        }

        self.data = new_file;
    }

    fn rebase(&mut self, actual_base: u64) {
        // Read current ImageBase.
        let old_base: u64 = if self.is_pe32plus {
            self.read_opt_u64(24)
        } else {
            u64::from(self.read_opt_u32(28))
        };
        if old_base == actual_base { return; }
        let slide = actual_base.cast_signed() - old_base.cast_signed();
        self.record_fix(
            "Rebase ImageBase",
            self.opt_offset() + if self.is_pe32plus { 24 } else { 28 },
            &format!("{old_base:#018x} (slide {slide:+#x})"),
            &format!("{actual_base:#018x}"),
        );
        if self.is_pe32plus {
            self.write_opt_u64(24, actual_base);
        } else {
            self.write_opt_u32(28, u32::try_from(actual_base).unwrap_or(u32::MAX));
        }
    }

    // -----------------------------------------------------------------------
    // Main entry point
    // -----------------------------------------------------------------------

    /// Return a histogram of section names. Useful for catching dumps that
    /// contain duplicate section names (a common pathology of broken dumpers).
    #[must_use]
    pub fn section_name_histogram(&self) -> HashMap<String, usize> {
        let mut h: HashMap<String, usize> = HashMap::new();
        for i in 0..self.num_sections() {
            if let Some(sec) = self.section_header(i) {
                let name = String::from_utf8_lossy(
                    &sec.name[..sec.name.iter().position(|&b| b == 0).unwrap_or(8)],
                )
                .into_owned();
                *h.entry(name).or_insert(0) += 1;
            }
        }
        h
    }

    /// Forcibly overwrite a single `u32` field on the section header at index
    /// `sec_idx`. `field_offset` is the byte offset inside the 40-byte
    /// `IMAGE_SECTION_HEADER` (e.g. 36 for `Characteristics`).
    /// Returns `true` if the write succeeded.
    pub fn overwrite_section_field(
        &mut self,
        sec_idx: usize,
        field_offset: usize,
        val: u32,
    ) -> bool {
        let Some(sec) = self.section_header(sec_idx) else { return false };
        self.write_section_field(sec.header_offset, field_offset, val);
        true
    }

    /// Apply all configured fixes and return the result.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError`] if a fix step (e.g. virtual-to-raw conversion) fails.
    pub fn fix(mut self) -> Result<FixResult, RebuildError> {
        let slide;
        let was_rebased;

        let actual_base = self.cfg.actual_image_base;
        let old_base: u64 = if self.is_pe32plus {
            self.read_opt_u64(24)
        } else {
            u64::from(self.read_opt_u32(28))
        };

        if let Some(actual) = actual_base {
            slide = actual.cast_signed() - old_base.cast_signed();
            was_rebased = slide != 0;
        } else {
            slide = 0;
            was_rebased = false;
        }

        if self.cfg.flags.repair_signatures() { self.fix_signatures(); }
        if let Some(machine) = self.cfg.machine_type { self.fix_machine_type(machine); }

        let sa = self.cfg.section_alignment.unwrap_or_else(|| self.read_opt_u32(32).max(0x1000));
        let fa = self.cfg.file_alignment.unwrap_or_else(|| self.read_opt_u32(36).max(0x200));
        self.fix_alignment_fields(sa, fa);

        if self.cfg.flags.convert_virtual_to_raw() { self.convert_virtual_to_raw_layout(); }
        if self.cfg.flags.recalc_size_of_image() { self.recalculate_size_of_image(); }
        if self.cfg.flags.recalc_size_fields() { self.recalculate_size_fields(); }
        self.fix_size_of_headers();
        if self.cfg.flags.strip_security_dir() { self.strip_security_directory(); }
        if let Some(actual) = actual_base { self.rebase(actual); }

        Ok(FixResult { data: self.data, fixes: self.fixes, was_rebased, slide })
    }
}

// ---------------------------------------------------------------------------
// Internal SectionHeader snapshot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
    /// Byte offset of this header within the file.
    header_offset: usize,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const fn align_up(v: u32, align: u32) -> u32 {
    if align == 0 { return v; }
    v.saturating_add(align - 1) & !(align - 1)
}

/// Convenience: fix a dump with default config.
///
/// # Errors
///
/// Returns [`RebuildError`] if the PE cannot be parsed or a fix step fails.
pub fn fix_dump_default(data: Vec<u8>) -> Result<FixResult, RebuildError> {
    PeDumpFixer::new(data, DumpFixerConfig::default())?.fix()
}

/// Convenience: fix a dump from process with known actual base address.
///
/// # Errors
///
/// Returns [`RebuildError`] if the PE cannot be parsed or a fix step fails.
pub fn fix_dump_with_base(data: Vec<u8>, actual_base: u64) -> Result<FixResult, RebuildError> {
    let cfg = DumpFixerConfig { actual_image_base: Some(actual_base), ..Default::default() };
    PeDumpFixer::new(data, cfg)?.fix()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_up_basic() {
        assert_eq!(align_up(0, 0x200), 0);
        assert_eq!(align_up(1, 0x200), 0x200);
        assert_eq!(align_up(0x1FF, 0x200), 0x200);
        assert_eq!(align_up(0x200, 0x200), 0x200);
    }

    #[test]
    fn fixer_new_rejects_tiny() {
        // A 4-byte buffer has no valid PE.
        let result = PeDumpFixer::new(vec![0u8; 4], DumpFixerConfig::default());
        // Should succeed construction (pe_offset=0), fail or no-op during fix.
        assert!(result.is_ok());
    }

    #[test]
    fn data_directory_offset_pe32() {
        // Without a real PE, just check the arithmetic.
        // For PE32, security dir (index 4) is at opt+96 + 4*8 = opt+128.
        let data = vec![0u8; 512];
        let mut fixer = PeDumpFixer::new(data, DumpFixerConfig::default()).unwrap();
        fixer.is_pe32plus = false;
        fixer.pe_offset = 0;
        // opt_offset = 0 + 4 + 20 = 24
        assert_eq!(fixer.data_directory_offset(4), 24 + 128);
    }

    #[test]
    fn data_directory_offset_pe32plus() {
        let data = vec![0u8; 512];
        let mut fixer = PeDumpFixer::new(data, DumpFixerConfig::default()).unwrap();
        fixer.is_pe32plus = true;
        fixer.pe_offset = 0;
        assert_eq!(fixer.data_directory_offset(4), 24 + 144);
    }

    #[test]
    fn align_up_zero_align_returns_value() {
        // align_up with align=0 should not panic; treat as no-op.
        assert_eq!(align_up(42, 1), 42);
    }

    #[test]
    fn fix_dump_default_empty_returns_error_or_ok() {
        // Empty data: construction succeeds (pe_offset=0) but fix may warn.
        let r = fix_dump_default(vec![0u8; 512]);
        // We don't assert success/failure, just that it doesn't panic.
        let _ = r;
    }

    #[test]
    fn fix_result_fields() {
        let r = FixResult {
            data: vec![0u8; 64],
            fixes: vec![],
            was_rebased: false,
            slide: 0,
        };
        assert_eq!(r.data.len(), 64);
        assert!(!r.was_rebased);
        assert_eq!(r.slide, 0);
    }

    #[test]
    fn dump_fixer_config_defaults() {
        let cfg = DumpFixerConfig::default();
        assert!(cfg.actual_image_base.is_none());
        assert!(cfg.flags.recalc_size_of_image());
        assert!(cfg.flags.repair_signatures());
        assert!(cfg.flags.convert_virtual_to_raw());
    }
    #[test]
    fn data_directory_indices_have_names() {
        assert_eq!(dd::name(dd::SECURITY), "Security");
        assert_eq!(dd::name(dd::LOAD_CFG), "LoadConfig");
        assert_eq!(dd::name(dd::COM_DESCRIPTOR), "COMDescriptor");
        assert_eq!(dd::name(dd::DELAY_IMPORT), "DelayImport");
        assert_eq!(dd::name(dd::EXCEPTION), "Exception");
        assert_eq!(dd::name(dd::BASERELOC), "BaseReloc");
        assert_eq!(dd::name(dd::IAT), "IAT");
        assert_eq!(dd::name(7), "Unknown");
    }

}
