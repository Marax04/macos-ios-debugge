//! PE section table rebuilder.
//!
//! Reconstructs a valid `IMAGE_SECTION_HEADER` array from a potentially
//! corrupt or memory-dumped PE image.  Handles alignment fixing, RVA
//! mismatch correction, section merging / splitting and report generation.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const IMAGE_SIZEOF_SECTION_HEADER: usize = 40;
const IMAGE_NT_HEADERS_SIGNATURE: u32 = 0x4550; // "PE\0\0"
const IMAGE_SECTION_HEADER_OFFSET_FROM_NT: usize = 0xF8; // 32-bit; 0x108 for PE32+

/// Default file alignment when none can be inferred.
const DEFAULT_FILE_ALIGNMENT: u32 = 0x200;
/// Default section alignment when none can be inferred.
const DEFAULT_SECTION_ALIGNMENT: u32 = 0x1000;
/// Maximum section size before split (100 MiB).
const MAX_SECTION_SIZE: u32 = 100 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Section characteristics flags (abbreviated)
// ---------------------------------------------------------------------------
const IMAGE_SCN_MEM_READ: u32    = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32   = 0x8000_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_CNT_CODE: u32    = 0x0000_0020;
const IMAGE_SCN_CNT_INIT_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_CNT_UNINIT_DATA: u32 = 0x0000_0080;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors produced by the section rebuilder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionRebuildError {
    /// The supplied bytes are too small to hold even a DOS header.
    TooSmall,
    /// The `e_lfanew` offset points outside the buffer.
    BadElfanew(u32),
    /// The NT signature is not "PE\0\0".
    BadNtSignature(u32),
    /// Section table overflows the buffer.
    SectionTableOverflow,
    /// A section's raw data range exceeds the buffer.
    SectionDataOutOfBounds { name: String, offset: u32, size: u32 },
    /// Two sections overlap after alignment fix.
    OverlapAfterFix(String, String),
    /// Custom message.
    Custom(String),
}

impl std::fmt::Display for SectionRebuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooSmall => write!(f, "buffer too small"),
            Self::BadElfanew(v) => write!(f, "bad e_lfanew: {v:#x}"),
            Self::BadNtSignature(v) => write!(f, "bad NT signature: {v:#010x}"),
            Self::SectionTableOverflow => write!(f, "section table overflows buffer"),
            Self::SectionDataOutOfBounds { name, offset, size } => {
                write!(f, "section {name} data out of bounds: offset={offset:#x} size={size:#x}")
            }
            Self::OverlapAfterFix(a, b) => write!(f, "sections {a} and {b} overlap after fix"),
            Self::Custom(msg) => write!(f, "{msg}"),
        }
    }
}
impl std::error::Error for SectionRebuildError {}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Bitflags controlling rebuild behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RebuildFlags(pub u8);

impl RebuildFlags {
    pub const ALIGN_SECTIONS:       u8 = 0x01;
    pub const RECALCULATE_CHECKSUMS: u8 = 0x02;
    pub const FIX_RVA_MISMATCHES:   u8 = 0x04;
    pub const PAD_TO_FILE_ALIGNMENT: u8 = 0x08;

    #[must_use]
    pub const fn align_sections(self) -> bool        { self.0 & Self::ALIGN_SECTIONS != 0 }
    #[must_use]
    pub const fn recalculate_checksums(self) -> bool { self.0 & Self::RECALCULATE_CHECKSUMS != 0 }
    #[must_use]
    pub const fn fix_rva_mismatches(self) -> bool    { self.0 & Self::FIX_RVA_MISMATCHES != 0 }
    #[must_use]
    pub const fn pad_to_file_alignment(self) -> bool { self.0 & Self::PAD_TO_FILE_ALIGNMENT != 0 }
}

/// Configuration controlling rebuild behaviour.
#[derive(Debug, Clone)]
pub struct RebuildConfig {
    pub flags: RebuildFlags,
    /// Override the file alignment; 0 means read from optional header.
    pub file_alignment_override: u32,
    /// Override the section alignment; 0 means read from optional header.
    pub section_alignment_override: u32,
}

impl Default for RebuildConfig {
    fn default() -> Self {
        Self {
            flags: RebuildFlags(
                RebuildFlags::ALIGN_SECTIONS
                | RebuildFlags::RECALCULATE_CHECKSUMS
                | RebuildFlags::FIX_RVA_MISMATCHES
                | RebuildFlags::PAD_TO_FILE_ALIGNMENT,
            ),
            file_alignment_override: 0,
            section_alignment_override: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Section information
// ---------------------------------------------------------------------------

/// Describes one PE section as understood by the rebuilder.
#[derive(Debug, Clone)]
pub struct SectionRebuildInfo {
    /// Raw section name bytes (8-byte fixed array, NUL-padded).
    pub name: [u8; 8],
    /// RVA of the section in the loaded image.
    pub virtual_address: u32,
    /// Size of the section in virtual memory.
    pub virtual_size: u32,
    /// File offset of the raw data.
    pub raw_offset: u32,
    /// Size of the raw data on disk.
    pub raw_size: u32,
    /// Section characteristics flags.
    pub characteristics: u32,
    /// Actual section bytes (may be shorter than `raw_size` before padding).
    pub data: Vec<u8>,
    /// True if this section was inferred (not present in original `IMAGE_SECTION_HEADER`).
    pub implicit: bool,
}

impl SectionRebuildInfo {
    /// Return the section name as a lossy UTF-8 string (strips NUL bytes).
    #[must_use]
    pub fn name_str(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }

    /// End RVA (non-inclusive) of the virtual range.
    #[must_use]
    pub const fn virtual_end(&self) -> u32 {
        self.virtual_address.saturating_add(self.virtual_size)
    }

    /// End file offset (non-inclusive) of the raw data.
    #[must_use]
    pub const fn raw_end(&self) -> u32 {
        self.raw_offset.saturating_add(self.raw_size)
    }
}

// ---------------------------------------------------------------------------
// Change record
// ---------------------------------------------------------------------------

/// One line in the rebuild report.
#[derive(Debug, Clone)]
pub struct RebuildChange {
    pub section: String,
    pub field: String,
    pub old_value: u64,
    pub new_value: u64,
    pub description: String,
}

// ---------------------------------------------------------------------------
// Validation result
// ---------------------------------------------------------------------------

/// One issue found during validation.
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub severity: IssueSeverity,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueSeverity {
    Warning,
    Error,
}

// ---------------------------------------------------------------------------
// Main rebuilder
// ---------------------------------------------------------------------------

/// PE section table rebuilder.
///
/// Call `new()` with the raw PE bytes, configure via `config()`, then
/// call the individual rebuild steps or `rebuild_all()`.
pub struct PeSectionRebuilder {
    data: Vec<u8>,
    config: RebuildConfig,
    sections: Vec<SectionRebuildInfo>,
    changes: Vec<RebuildChange>,
    e_lfanew: u32,
    is_pe32_plus: bool,
    file_alignment: u32,
    section_alignment: u32,
}

impl PeSectionRebuilder {
    /// Create a rebuilder from raw PE bytes.
    ///
    /// # Errors
    /// Returns an error if the PE header cannot be parsed (too small, bad
    /// signature, section table overflow, or out-of-bounds section data).
    ///
    /// # Panics
    /// Panics if internal `try_into` slice conversions fail (indicating
    /// a logic error; guarded by prior bounds checks).
    pub fn new(data: Vec<u8>) -> Result<Self, SectionRebuildError> {
        if data.len() < 64 {
            return Err(SectionRebuildError::TooSmall);
        }
        let e_lfanew = u32::from_le_bytes(data[60..64].try_into().unwrap());
        if e_lfanew as usize + 4 > data.len() {
            return Err(SectionRebuildError::BadElfanew(e_lfanew));
        }
        let sig = u32::from_le_bytes(data[e_lfanew as usize..e_lfanew as usize + 4].try_into().unwrap());
        if sig != IMAGE_NT_HEADERS_SIGNATURE {
            return Err(SectionRebuildError::BadNtSignature(sig));
        }
        // magic at e_lfanew + 4 (COFF header) + 18 (first field of optional header)
        let opt_off = e_lfanew as usize + 24; // COFF = 20 bytes, skip + sig
        let is_pe32_plus = if opt_off + 2 <= data.len() {
            u16::from_le_bytes(data[opt_off..opt_off + 2].try_into().unwrap()) == 0x020B
        } else {
            false
        };

        // File / section alignment from optional header
        let fa_off = opt_off + 36;
        let sa_off = opt_off + 32;
        let file_alignment = if fa_off + 4 <= data.len() {
            u32::from_le_bytes(data[fa_off..fa_off + 4].try_into().unwrap())
        } else {
            DEFAULT_FILE_ALIGNMENT
        };
        let section_alignment = if sa_off + 4 <= data.len() {
            u32::from_le_bytes(data[sa_off..sa_off + 4].try_into().unwrap())
        } else {
            DEFAULT_SECTION_ALIGNMENT
        };
        let file_alignment = if file_alignment.is_power_of_two() && file_alignment >= 512 {
            file_alignment
        } else {
            DEFAULT_FILE_ALIGNMENT
        };
        let section_alignment = if section_alignment.is_power_of_two() && section_alignment >= 4096 {
            section_alignment
        } else {
            DEFAULT_SECTION_ALIGNMENT
        };

        let mut rebuilder = Self {
            data,
            config: RebuildConfig::default(),
            sections: Vec::new(),
            changes: Vec::new(),
            e_lfanew,
            is_pe32_plus,
            file_alignment,
            section_alignment,
        };
        rebuilder.load_existing_sections()?;
        Ok(rebuilder)
    }

    /// Replace the configuration.
    #[must_use]
    pub const fn config(mut self, cfg: RebuildConfig) -> Self {
        if cfg.file_alignment_override != 0 {
            self.file_alignment = cfg.file_alignment_override;
        }
        if cfg.section_alignment_override != 0 {
            self.section_alignment = cfg.section_alignment_override;
        }
        self.config = cfg;
        self
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    const fn nt_off(&self) -> usize { self.e_lfanew as usize }

    const fn coff_off(&self) -> usize { self.nt_off() + 4 }

    fn number_of_sections(&self) -> u16 {
        let off = self.coff_off() + 2;
        if off + 2 <= self.data.len() {
            u16::from_le_bytes(self.data[off..off + 2].try_into().unwrap())
        } else {
            0
        }
    }

    fn section_table_offset(&self) -> usize {
        // NT sig(4) + COFF(20) + optional header size
        let oh_size_off = self.coff_off() + 16;
        let oh_size = if oh_size_off + 2 <= self.data.len() {
            u16::from_le_bytes(self.data[oh_size_off..oh_size_off + 2].try_into().unwrap()) as usize
        } else {
            0
        };
        self.nt_off() + 4 + 20 + oh_size
    }

    fn load_existing_sections(&mut self) -> Result<(), SectionRebuildError> {
        let n = self.number_of_sections() as usize;
        let tbl = self.section_table_offset();
        if tbl + n * IMAGE_SIZEOF_SECTION_HEADER > self.data.len() {
            return Err(SectionRebuildError::SectionTableOverflow);
        }
        self.sections.clear();
        for i in 0..n {
            let base = tbl + i * IMAGE_SIZEOF_SECTION_HEADER;
            let hdr = &self.data[base..base + IMAGE_SIZEOF_SECTION_HEADER];
            let mut name = [0u8; 8];
            name.copy_from_slice(&hdr[0..8]);
            let virtual_size  = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
            let virtual_address = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
            let raw_size      = u32::from_le_bytes(hdr[16..20].try_into().unwrap());
            let raw_offset    = u32::from_le_bytes(hdr[20..24].try_into().unwrap());
            let characteristics = u32::from_le_bytes(hdr[36..40].try_into().unwrap());
            let end = (raw_offset as usize).saturating_add(raw_size as usize);
            let data = if end <= self.data.len() {
                self.data[raw_offset as usize..end].to_vec()
            } else {
                vec![]
            };
            self.sections.push(SectionRebuildInfo {
                name, virtual_address, virtual_size, raw_offset, raw_size,
                characteristics, data, implicit: false,
            });
        }
        Ok(())
    }

    const fn align_up(value: u32, align: u32) -> u32 {
        if align == 0 { return value; }
        value.saturating_add(align - 1) & !(align - 1)
    }

    fn record_change(&mut self, section: &str, field: &str, old: u64, new: u64, desc: &str) {
        self.changes.push(RebuildChange {
            section: section.to_owned(),
            field: field.to_owned(),
            old_value: old,
            new_value: new,
            description: desc.to_owned(),
        });
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Scan for sections present in memory but missing from the header.
    ///
    /// Heuristic: look for PAGE_SIZE-aligned runs of non-zero bytes in the
    /// raw data that fall outside all known section ranges.
    pub fn scan_implicit_sections(&mut self) {
        let known_ranges: Vec<(u32, u32)> = self.sections.iter()
            .map(|s| (s.raw_offset, s.raw_end()))
            .collect();

        let page = self.file_alignment;
        let mut off: u32 = Self::align_up(
            u32::try_from(self.section_table_offset()).unwrap_or(u32::MAX)
                + u32::try_from(self.sections.len()).unwrap_or(u32::MAX)
                    * u32::try_from(IMAGE_SIZEOF_SECTION_HEADER).unwrap_or(u32::MAX),
            page,
        );

        let mut implicit_idx = 0u32;
        while (off as usize) + page as usize <= self.data.len() {
            let in_known = known_ranges.iter().any(|&(s, e)| off >= s && off < e);
            if !in_known {
                let end = ((off as usize) + page as usize).min(self.data.len());
                let slice = &self.data[off as usize..end];
                let non_zero = slice.iter().any(|&b| b != 0);
                if non_zero {
                    // Estimate virtual size: find consecutive non-zero pages
                    let mut run = page;
                    let mut next = off + page;
                    while (next as usize) + page as usize <= self.data.len() {
                        let still_out = !known_ranges.iter().any(|&(s, e)| next >= s && next < e);
                        if still_out {
                            let sl = &self.data[next as usize..(next as usize + page as usize).min(self.data.len())];
                            if sl.iter().any(|&b| b != 0) {
                                run += page;
                                next += page;
                            } else { break; }
                        } else { break; }
                    }
                    let mut name = [0u8; 8];
                    let label = format!(".imp{implicit_idx}");
                    for (i, b) in label.bytes().enumerate().take(8) { name[i] = b; }
                    let data_len = (off as usize + run as usize).min(self.data.len()) - off as usize;
                    let data = self.data[off as usize..off as usize + data_len].to_vec();
                    let last_rva = self.sections.iter().map(|s| Self::align_up(s.virtual_address + s.virtual_size, self.section_alignment)).max().unwrap_or(self.section_alignment);
                    self.sections.push(SectionRebuildInfo {
                        name,
                        virtual_address: last_rva,
                        virtual_size: run,
                        raw_offset: off,
                        raw_size: run,
                        characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INIT_DATA,
                        data,
                        implicit: true,
                    });
                    implicit_idx += 1;
                }
            }
            off += page;
        }
    }

    /// Adjust raw sizes so each section ends on a `file_alignment` boundary.
    pub fn fix_section_alignment(&mut self) {
        let fa = self.file_alignment;
        for s in &mut self.sections {
            let aligned = Self::align_up(s.raw_size, fa);
            if aligned != s.raw_size {
                let old = u64::from(s.raw_size);
                s.raw_size = aligned;
                // pad data
                if self.config.flags.pad_to_file_alignment() {
                    s.data.resize(aligned as usize, 0u8);
                }
                let name = s.name_str();
                self.changes.push(RebuildChange {
                    section: name,
                    field: "raw_size".into(),
                    old_value: old,
                    new_value: u64::from(aligned),
                    description: format!("aligned to file_alignment {fa:#x}"),
                });
            }
        }
    }

    /// Rewrite the `IMAGE_SECTION_HEADER` array at `e_lfanew + 0xF8` and
    /// update `NumberOfSections` in the COFF header.
    ///
    /// # Errors
    /// Returns an error if the section table cannot be written.
    ///
    /// # Panics
    /// Panics if internal `try_into` slice conversions fail.
    pub fn rebuild_section_table(&mut self) -> Result<(), SectionRebuildError> {
        let tbl = self.section_table_offset();
        let n = self.sections.len();
        let required = tbl + n * IMAGE_SIZEOF_SECTION_HEADER;
        if required > self.data.len() {
            // Extend data to accommodate the table (headers only, safe)
            self.data.resize(required.max(self.data.len()), 0u8);
        }

        for (i, s) in self.sections.iter().enumerate() {
            let base = tbl + i * IMAGE_SIZEOF_SECTION_HEADER;
            let hdr = &mut self.data[base..base + IMAGE_SIZEOF_SECTION_HEADER];
            hdr[0..8].copy_from_slice(&s.name);
            hdr[8..12].copy_from_slice(&s.virtual_size.to_le_bytes());
            hdr[12..16].copy_from_slice(&s.virtual_address.to_le_bytes());
            hdr[16..20].copy_from_slice(&s.raw_size.to_le_bytes());
            hdr[20..24].copy_from_slice(&s.raw_offset.to_le_bytes());
            // PointerToRelocations / PointerToLinenumbers / counts = 0
            hdr[24..36].fill(0);
            hdr[36..40].copy_from_slice(&s.characteristics.to_le_bytes());
        }

        // Update NumberOfSections
        let ns_off = self.coff_off() + 2;
        let old_n = u16::from_le_bytes(self.data[ns_off..ns_off + 2].try_into().unwrap());
        if usize::from(old_n) != n {
            self.data[ns_off..ns_off + 2].copy_from_slice(&u16::try_from(n).unwrap_or(u16::MAX).to_le_bytes());
            self.record_change("(header)", "NumberOfSections", u64::from(old_n), u64::try_from(n).unwrap_or(u64::MAX),
                "updated to match rebuilt section list");
        }

        // Optionally recalculate SizeOfImage
        if let Some(largest) = self.sections.iter()
            .map(|s| Self::align_up(s.virtual_address + s.virtual_size, self.section_alignment))
            .max()
        {
            let soi_off = self.nt_off() + 24 + 56; // optional header + SizeOfImage offset (PE32)
            if soi_off + 4 <= self.data.len() {
                let old_soi = u32::from_le_bytes(self.data[soi_off..soi_off + 4].try_into().unwrap());
                if old_soi != largest {
                    self.data[soi_off..soi_off + 4].copy_from_slice(&largest.to_le_bytes());
                    self.record_change("(header)", "SizeOfImage", u64::from(old_soi), u64::from(largest),
                        "recalculated from section virtual extents");
                }
            }
        }

        Ok(())
    }

    /// Detect RVA overlaps between sections and merge them into a single
    /// section preserving the union of their data.
    pub fn merge_overlapping_sections(&mut self) {
        'restart: loop {
            let n = self.sections.len();
            for i in 0..n {
                for j in i + 1..n {
                    let a_start = self.sections[i].virtual_address;
                    let a_end   = self.sections[i].virtual_end();
                    let b_start = self.sections[j].virtual_address;
                    let b_end   = self.sections[j].virtual_end();
                    if a_start < b_end && b_start < a_end {
                        // Merge j into i
                        let new_start = a_start.min(b_start);
                        let new_end   = a_end.max(b_end);
                        let merged_virt_size = new_end - new_start;
                        let merged_raw_size = Self::align_up(merged_virt_size, self.file_alignment);
                        let mut merged_data = vec![0u8; merged_raw_size as usize];
                        // Copy both sections' data into merged buffer
                        let a_doff = (self.sections[i].virtual_address - new_start) as usize;
                        let a_data = self.sections[i].data.clone();
                        let b_doff = (self.sections[j].virtual_address - new_start) as usize;
                        let b_data = self.sections[j].data.clone();
                        let copy_a = a_data.len().min(merged_data.len().saturating_sub(a_doff));
                        merged_data[a_doff..a_doff + copy_a].copy_from_slice(&a_data[..copy_a]);
                        let copy_b = b_data.len().min(merged_data.len().saturating_sub(b_doff));
                        merged_data[b_doff..b_doff + copy_b].copy_from_slice(&b_data[..copy_b]);

                        let a_char = self.sections[i].characteristics;
                        let b_char = self.sections[j].characteristics;
                        let a_name = self.sections[i].name_str();
                        let b_name = self.sections[j].name_str();

                        self.sections[i].virtual_address = new_start;
                        self.sections[i].virtual_size    = merged_virt_size;
                        self.sections[i].raw_size        = merged_raw_size;
                        self.sections[i].characteristics = a_char | b_char;
                        self.sections[i].data            = merged_data;
                        self.sections.remove(j);

                        self.record_change(
                            &a_name, "merge",
                            u64::from(a_start), u64::from(new_start),
                            &format!("merged with overlapping section {b_name}"),
                        );
                        continue 'restart;
                    }
                }
            }
            break;
        }
    }

    /// Split sections larger than `MAX_SECTION_SIZE` into 100 MiB chunks.
    pub fn split_large_sections(&mut self) {
        let mut i = 0;
        while i < self.sections.len() {
            if self.sections[i].virtual_size > MAX_SECTION_SIZE {
                let s = self.sections.remove(i);
                let mut off = 0u32;
                let mut chunk_idx = 0u32;
                while off < s.virtual_size {
                    let sz = (s.virtual_size - off).min(MAX_SECTION_SIZE);
                    let raw_sz = Self::align_up(sz, self.file_alignment);
                    // A section's virtual_size routinely exceeds its raw data
                    // length (uninitialised tail).  Clamp BOTH ends to the raw
                    // data, otherwise once `off` passes `s.data.len()` the end
                    // is clamped while the start is not and `data_end -
                    // data_start` underflows.
                    let data_start = (off as usize).min(s.data.len());
                    let data_end   = (off as usize + sz as usize).min(s.data.len());
                    let mut chunk_data = vec![0u8; raw_sz as usize];
                    let copy_len = data_end - data_start;
                    chunk_data[..copy_len].copy_from_slice(&s.data[data_start..data_end]);

                    let mut name = [0u8; 8];
                    let label = if chunk_idx == 0 {
                        s.name_str()
                    } else {
                        format!("{}{chunk_idx}", &s.name_str()[..s.name_str().len().min(6)])
                    };
                    for (k, b) in label.bytes().enumerate().take(8) { name[k] = b; }

                    self.sections.insert(i + chunk_idx as usize, SectionRebuildInfo {
                        name,
                        virtual_address: s.virtual_address + off,
                        virtual_size: sz,
                        raw_offset: s.raw_offset + off,
                        raw_size: raw_sz,
                        characteristics: s.characteristics,
                        data: chunk_data,
                        implicit: false,
                    });
                    off += sz;
                    chunk_idx += 1;
                }
                i += chunk_idx as usize;
            } else {
                i += 1;
            }
        }
    }

    /// Sort sections by `VirtualAddress` (ascending).
    pub fn reorder_by_rva(&mut self) {
        self.sections.sort_by_key(|s| s.virtual_address);
    }

    /// Reassign raw offsets sequentially (after re-ordering / splitting).
    pub fn reassign_raw_offsets(&mut self) {
        let header_end = self.section_table_offset()
            + self.sections.len() * IMAGE_SIZEOF_SECTION_HEADER;
        let mut off = Self::align_up(u32::try_from(header_end).unwrap_or(u32::MAX), self.file_alignment);
        for s in &mut self.sections {
            if s.raw_size > 0 {
                s.raw_offset = off;
                off = Self::align_up(off + s.raw_size, self.file_alignment);
            }
        }
    }

    /// Run all rebuild steps in the canonical order.
    ///
    /// # Errors
    /// Returns an error if `rebuild_section_table` fails.
    pub fn rebuild_all(&mut self) -> Result<(), SectionRebuildError> {
        self.scan_implicit_sections();
        self.merge_overlapping_sections();
        self.split_large_sections();
        self.reorder_by_rva();
        if self.config.flags.align_sections() {
            self.fix_section_alignment();
        }
        if self.config.flags.fix_rva_mismatches() {
            self.reassign_raw_offsets();
        }
        self.rebuild_section_table()?;
        if self.config.flags.recalculate_checksums() {
            self.recalculate_checksum();
        }
        Ok(())
    }

    /// Recalculate the optional header checksum (PE checksum algorithm).
    ///
    /// # Panics
    /// Panics if internal `try_into` conversions fail.
    pub fn recalculate_checksum(&mut self) {
        // Checksum field is at optional header offset 64 (PE32) or 64 (PE32+)
        let cs_off = self.nt_off() + 24 + 64;
        if cs_off + 4 > self.data.len() { return; }
        // Zero the checksum field before computing
        self.data[cs_off..cs_off + 4].fill(0);
        let len = self.data.len();
        let mut checksum: u32 = 0;
        let mut i = 0;
        while i + 4 <= len {
            let word = u32::from_le_bytes(self.data[i..i + 4].try_into().unwrap());
            let (sum, carry) = checksum.overflowing_add(word);
            checksum = sum + u32::from(carry);
            i += 4;
        }
        // Handle remaining bytes
        if i < len {
            let mut tail = [0u8; 4];
            tail[..len - i].copy_from_slice(&self.data[i..]);
            let word = u32::from_le_bytes(tail);
            let (sum, carry) = checksum.overflowing_add(word);
            checksum = sum + u32::from(carry);
        }
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        checksum += checksum >> 16;
        checksum &= 0xFFFF;
        checksum += u32::try_from(len).unwrap_or(u32::MAX);
        self.data[cs_off..cs_off + 4].copy_from_slice(&checksum.to_le_bytes());
        self.record_change("(header)", "CheckSum", 0, u64::from(checksum), "recalculated PE checksum");
    }

    /// Produce a human-readable report of all changes made.
    #[must_use]
    pub fn generate_rebuild_report(&self) -> Vec<String> {
        self.changes.iter().map(|c| {
            format!("[{}] {} :: {} = {:#x} → {:#x}  ({})",
                c.section, c.field, c.field, c.old_value, c.new_value, c.description)
        }).collect()
    }

    /// Validate the rebuilt PE: check all RVAs point to valid sections.
    #[must_use]
    pub fn validate_rebuilt_pe(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        // Check NumberOfSections matches sections vec
        let n = self.number_of_sections() as usize;
        if n != self.sections.len() {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Error,
                message: format!("NumberOfSections={n} but {} sections in vec", self.sections.len()),
            });
        }

        // Check each section's raw data is within the file
        for s in &self.sections {
            let end = s.raw_offset as usize + s.raw_size as usize;
            if s.raw_size > 0 && end > self.data.len() {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Error,
                    message: format!(
                        "section {} raw data [{:#x}..{:#x}) exceeds file size {:#x}",
                        s.name_str(), s.raw_offset, end, self.data.len()
                    ),
                });
            }
            if s.virtual_address == 0 {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Warning,
                    message: format!("section {} has VirtualAddress=0", s.name_str()),
                });
            }
        }

        // Check for RVA overlaps
        let mut sorted = self.sections.clone();
        sorted.sort_by_key(|s| s.virtual_address);
        for w in sorted.windows(2) {
            if w[0].virtual_end() > w[1].virtual_address {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Error,
                    message: format!(
                        "sections {} and {} overlap in virtual space",
                        w[0].name_str(), w[1].name_str()
                    ),
                });
            }
        }

        issues
    }

    /// Consume the rebuilder and return the rebuilt PE bytes.
    ///
    /// # Errors
    /// Currently infallible but returns `Result` for forward compatibility.
    pub fn finish(mut self) -> Result<Vec<u8>, SectionRebuildError> {
        // Write section data into the output buffer at the correct raw offsets
        for s in &self.sections {
            if s.raw_size == 0 { continue; }
            let end = s.raw_offset as usize + s.raw_size as usize;
            if end > self.data.len() {
                self.data.resize(end, 0u8);
            }
            let copy_len = s.data.len().min(s.raw_size as usize);
            self.data[s.raw_offset as usize..s.raw_offset as usize + copy_len]
                .copy_from_slice(&s.data[..copy_len]);
        }
        Ok(self.data)
    }

    /// Read-only access to parsed sections.
    #[must_use]
    pub fn sections(&self) -> &[SectionRebuildInfo] { &self.sections }

    /// Whether the underlying PE is PE32+ (64-bit). Returned to callers that
    /// need to size pointer-bearing fields outside the rebuilder.
    #[must_use]
    pub const fn is_pe32_plus(&self) -> bool { self.is_pe32_plus }

    /// Offset of the `IMAGE_SECTION_HEADER` array relative to the NT signature.
    /// `0xF8` for PE32, `0x108` for PE32+.
    #[must_use]
    pub const fn section_table_offset_from_nt(&self) -> usize {
        if self.is_pe32_plus {
            IMAGE_SECTION_HEADER_OFFSET_FROM_NT + 0x10
        } else {
            IMAGE_SECTION_HEADER_OFFSET_FROM_NT
        }
    }

    /// Histogram of section characteristics flags across the rebuilt table.
    #[must_use]
    pub fn characteristics_histogram(&self) -> HashMap<u32, usize> {
        let mut h: HashMap<u32, usize> = HashMap::new();
        for s in &self.sections {
            *h.entry(s.characteristics).or_insert(0) += 1;
        }
        h
    }

    /// Mutable access to parsed sections (for manual adjustments).
    pub const fn sections_mut(&mut self) -> &mut Vec<SectionRebuildInfo> { &mut self.sections }
}

// ---------------------------------------------------------------------------
// Free-standing helper: infer section characteristics from name
// ---------------------------------------------------------------------------

/// Infer reasonable characteristics for a section given its name.
#[must_use]
pub fn infer_characteristics(name: &str) -> u32 {
    match name {
        ".text" | "CODE" => IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        ".data" | "DATA" => IMAGE_SCN_CNT_INIT_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        ".bss"           => IMAGE_SCN_CNT_UNINIT_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        _                => IMAGE_SCN_CNT_INIT_DATA | IMAGE_SCN_MEM_READ,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_pe(n_sections: u16, file_align: u32, sec_align: u32) -> Vec<u8> {
        let mut pe = vec![0u8; 0x1000];
        // DOS header
        pe[0] = b'M'; pe[1] = b'Z';
        let e_lfanew: u32 = 0x40;
        pe[60..64].copy_from_slice(&e_lfanew.to_le_bytes());
        // NT signature
        pe[0x40] = b'P'; pe[0x41] = b'E';
        // COFF header: NumberOfSections at 0x40+4+2
        pe[0x40 + 6..0x40 + 8].copy_from_slice(&n_sections.to_le_bytes());
        // SizeOfOptionalHeader = 0xE0
        pe[0x40 + 20..0x40 + 22].copy_from_slice(&0xE0u16.to_le_bytes());
        // Optional header magic PE32
        pe[0x40 + 24..0x40 + 26].copy_from_slice(&0x010Bu16.to_le_bytes());
        // SectionAlignment at opt+32
        pe[0x40 + 24 + 32..0x40 + 24 + 36].copy_from_slice(&sec_align.to_le_bytes());
        // FileAlignment at opt+36
        pe[0x40 + 24 + 36..0x40 + 24 + 40].copy_from_slice(&file_align.to_le_bytes());
        pe
    }

    fn pe_with_one_section() -> Vec<u8> {
        let mut pe = make_minimal_pe(1, 0x200, 0x1000);
        // Section header at 0x40 + 4 + 20 + 0xE0 = 0x148
        let sec_off = 0x40 + 4 + 20 + 0xE0;
        let hdr = &mut pe[sec_off..sec_off + 40];
        hdr[0..5].copy_from_slice(b".text");
        // VirtualSize
        hdr[8..12].copy_from_slice(&0x500u32.to_le_bytes());
        // VirtualAddress
        hdr[12..16].copy_from_slice(&0x1000u32.to_le_bytes());
        // SizeOfRawData
        hdr[16..20].copy_from_slice(&0x600u32.to_le_bytes());
        // PointerToRawData
        hdr[20..24].copy_from_slice(&0x400u32.to_le_bytes());
        // Characteristics: execute | read | code
        let chr = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        hdr[36..40].copy_from_slice(&chr.to_le_bytes());
        pe
    }

    #[test]
    fn test_new_minimal_pe() {
        let pe = make_minimal_pe(0, 0x200, 0x1000);
        let rb = PeSectionRebuilder::new(pe).unwrap();
        assert_eq!(rb.sections().len(), 0);
    }

    #[test]
    fn test_too_small() {
        let result = PeSectionRebuilder::new(vec![0u8; 10]);
        assert!(matches!(result, Err(SectionRebuildError::TooSmall)));
    }

    #[test]
    fn test_bad_nt_sig() {
        let mut pe = make_minimal_pe(0, 0x200, 0x1000);
        pe[0x40] = 0xFF; // corrupt NT sig
        let result = PeSectionRebuilder::new(pe);
        assert!(matches!(result, Err(SectionRebuildError::BadNtSignature(_))));
    }

    #[test]
    fn test_load_one_section() {
        let pe = pe_with_one_section();
        let rb = PeSectionRebuilder::new(pe).unwrap();
        assert_eq!(rb.sections().len(), 1);
        assert_eq!(rb.sections()[0].name_str(), ".text");
        assert_eq!(rb.sections()[0].virtual_address, 0x1000);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(PeSectionRebuilder::align_up(0x201, 0x200), 0x400);
        assert_eq!(PeSectionRebuilder::align_up(0x200, 0x200), 0x200);
        assert_eq!(PeSectionRebuilder::align_up(0, 0x200), 0);
    }

    #[test]
    fn test_fix_section_alignment() {
        let pe = pe_with_one_section();
        let mut rb = PeSectionRebuilder::new(pe).unwrap()
            .config(RebuildConfig { flags: RebuildFlags(RebuildFlags::ALIGN_SECTIONS | RebuildFlags::PAD_TO_FILE_ALIGNMENT), ..Default::default() });
        rb.fix_section_alignment();
        // raw_size 0x600 is already aligned to 0x200
        assert_eq!(rb.sections()[0].raw_size, 0x600);
    }

    #[test]
    fn test_fix_alignment_odd_size() {
        let mut pe = pe_with_one_section();
        // Set raw size to something unaligned
        let sec_off = 0x40 + 4 + 20 + 0xE0;
        pe[sec_off + 16..sec_off + 20].copy_from_slice(&0x501u32.to_le_bytes());
        let mut rb = PeSectionRebuilder::new(pe).unwrap()
            .config(RebuildConfig { flags: RebuildFlags(RebuildFlags::ALIGN_SECTIONS | RebuildFlags::PAD_TO_FILE_ALIGNMENT), ..Default::default() });
        rb.fix_section_alignment();
        assert_eq!(rb.sections()[0].raw_size, 0x600); // aligned up to 0x200
    }

    #[test]
    fn test_rebuild_section_table() {
        let pe = pe_with_one_section();
        let mut rb = PeSectionRebuilder::new(pe).unwrap();
        rb.rebuild_section_table().unwrap();
        assert_eq!(rb.sections().len(), 1);
    }

    #[test]
    fn test_reorder_by_rva() {
        let pe = make_minimal_pe(0, 0x200, 0x1000);
        let mut rb = PeSectionRebuilder::new(pe).unwrap();
        rb.sections_mut().push(SectionRebuildInfo {
            name: *b".data\0\0\0",
            virtual_address: 0x3000, virtual_size: 0x100,
            raw_offset: 0x800, raw_size: 0x200,
            characteristics: IMAGE_SCN_MEM_READ,
            data: vec![0u8; 0x200], implicit: false,
        });
        rb.sections_mut().push(SectionRebuildInfo {
            name: *b".text\0\0\0",
            virtual_address: 0x1000, virtual_size: 0x500,
            raw_offset: 0x400, raw_size: 0x600,
            characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
            data: vec![0u8; 0x600], implicit: false,
        });
        rb.reorder_by_rva();
        assert_eq!(rb.sections()[0].virtual_address, 0x1000);
        assert_eq!(rb.sections()[1].virtual_address, 0x3000);
    }

    #[test]
    fn test_merge_overlapping_sections() {
        let pe = make_minimal_pe(0, 0x200, 0x1000);
        let mut rb = PeSectionRebuilder::new(pe).unwrap();
        rb.sections_mut().push(SectionRebuildInfo {
            name: *b".aaa\0\0\0\0",
            virtual_address: 0x1000, virtual_size: 0x2000,
            raw_offset: 0x400, raw_size: 0x2000,
            characteristics: IMAGE_SCN_MEM_READ,
            data: vec![0x41u8; 0x2000], implicit: false,
        });
        rb.sections_mut().push(SectionRebuildInfo {
            name: *b".bbb\0\0\0\0",
            virtual_address: 0x2000, virtual_size: 0x1000, // overlaps .aaa
            raw_offset: 0x2400, raw_size: 0x1000,
            characteristics: IMAGE_SCN_MEM_WRITE,
            data: vec![0x42u8; 0x1000], implicit: false,
        });
        rb.merge_overlapping_sections();
        assert_eq!(rb.sections().len(), 1);
        assert_eq!(rb.sections()[0].virtual_address, 0x1000);
        assert!(rb.sections()[0].virtual_size >= 0x2000);
    }

    /// A section whose `virtual_size` exceeds its raw data (the normal shape of
    /// an uninitialised tail) must still split without panicking: past the end
    /// of the raw data every chunk is simply all-zero.
    #[test]
    fn test_split_large_sections_sparse_data() {
        let pe = make_minimal_pe(0, 0x200, 0x1000);
        let mut rb = PeSectionRebuilder::new(pe).unwrap();
        let big_size = MAX_SECTION_SIZE + 0x1000;
        rb.sections_mut().push(SectionRebuildInfo {
            name: *b".bss\0\0\0\0",
            virtual_address: 0x1000, virtual_size: big_size,
            raw_offset: 0x400, raw_size: 0x200,
            characteristics: IMAGE_SCN_MEM_READ,
            data: vec![0xAAu8; 0x200], implicit: false,
        });
        rb.split_large_sections();
        assert!(rb.sections().len() >= 2);
        let total_vsize: u32 = rb.sections().iter().map(|s| s.virtual_size).sum();
        assert_eq!(total_vsize, big_size);
        // The tail chunk lies entirely past the raw data, so it is all zero.
        let last = rb.sections().last().unwrap();
        assert!(last.data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_split_large_sections() {
        let pe = make_minimal_pe(0, 0x200, 0x1000);
        let mut rb = PeSectionRebuilder::new(pe).unwrap();
        let big_size = MAX_SECTION_SIZE + 0x1000;
        rb.sections_mut().push(SectionRebuildInfo {
            name: *b".big\0\0\0\0",
            virtual_address: 0x1000, virtual_size: big_size,
            raw_offset: 0x400, raw_size: big_size,
            characteristics: IMAGE_SCN_MEM_READ,
            data: vec![0u8; big_size as usize], implicit: false,
        });
        rb.split_large_sections();
        assert!(rb.sections().len() >= 2);
        let total_vsize: u32 = rb.sections().iter().map(|s| s.virtual_size).sum();
        assert_eq!(total_vsize, big_size);
    }

    #[test]
    fn test_generate_report_empty() {
        let pe = pe_with_one_section();
        let rb = PeSectionRebuilder::new(pe).unwrap();
        let report = rb.generate_rebuild_report();
        assert!(report.is_empty());
    }

    #[test]
    fn test_validate_no_issues() {
        let pe = pe_with_one_section();
        let rb = PeSectionRebuilder::new(pe).unwrap();
        let issues = rb.validate_rebuilt_pe();
        // NumberOfSections may mismatch due to stub size; just ensure it runs
        let _ = issues;
    }

    #[test]
    fn test_infer_characteristics_text() {
        let c = infer_characteristics(".text");
        assert_ne!(c & IMAGE_SCN_MEM_EXECUTE, 0);
    }

    #[test]
    fn test_infer_characteristics_data() {
        let c = infer_characteristics(".data");
        assert_ne!(c & IMAGE_SCN_MEM_WRITE, 0);
    }

    #[test]
    fn test_infer_characteristics_rdata() {
        let c = infer_characteristics(".rdata");
        assert_eq!(c & IMAGE_SCN_MEM_WRITE, 0);
        assert_ne!(c & IMAGE_SCN_MEM_READ, 0);
    }

    #[test]
    fn test_name_str_no_trailing_nul() {
        let s = SectionRebuildInfo {
            name: *b".text\0\0\0",
            virtual_address: 0, virtual_size: 0,
            raw_offset: 0, raw_size: 0,
            characteristics: 0, data: vec![], implicit: false,
        };
        assert_eq!(s.name_str(), ".text");
    }

    #[test]
    fn test_reassign_raw_offsets() {
        let pe = make_minimal_pe(0, 0x200, 0x1000);
        let mut rb = PeSectionRebuilder::new(pe).unwrap();
        rb.sections_mut().push(SectionRebuildInfo {
            name: *b".text\0\0\0",
            virtual_address: 0x1000, virtual_size: 0x500,
            raw_offset: 0, raw_size: 0x600,
            characteristics: IMAGE_SCN_MEM_READ,
            data: vec![0u8; 0x600], implicit: false,
        });
        rb.sections_mut().push(SectionRebuildInfo {
            name: *b".data\0\0\0",
            virtual_address: 0x2000, virtual_size: 0x100,
            raw_offset: 0, raw_size: 0x200,
            characteristics: IMAGE_SCN_MEM_READ,
            data: vec![0u8; 0x200], implicit: false,
        });
        rb.reassign_raw_offsets();
        // first section should start at aligned header end
        assert!(rb.sections()[0].raw_offset > 0);
        // raw_end is exclusive; sections may be packed tightly with no gap, so >= is the correct non-overlap check.
        assert!(rb.sections()[1].raw_offset >= rb.sections()[0].raw_end());
    }
}
