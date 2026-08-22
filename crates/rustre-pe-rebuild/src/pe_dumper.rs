//! PE file dumper from live memory.
//!
//! Reconstructs a valid on-disk PE from a loaded in-memory image by fixing
//! loader-applied transformations: restoring `PointerToRawData` values,
//! resetting zeroed optional-header fields, computing the corrected
//! `SizeOfImage`, and optionally harvesting overlay data and security
//! certificates.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DOS_MAGIC: u16 = 0x5A4D; // "MZ"
const PE_SIGNATURE: u32 = 0x4550; // "PE\0\0"
const OPT_MAGIC_PE32: u16 = 0x010B;
const OPT_MAGIC_PE32PLUS: u16 = 0x020B;

// COFF field offsets relative to COFF header start (NT+4)
const COFF_NUMBER_OF_SECTIONS: usize = 2;   // u16 at COFF+2
const COFF_SIZE_OF_OPT_HDR: usize    = 16;  // u16 at COFF+16

// Optional header (PE32) field offsets relative to optional header start
const OPT_SECTION_ALIGNMENT: usize = 32;    // u32
const OPT_FILE_ALIGNMENT: usize    = 36;    // u32
const OPT_SIZE_OF_IMAGE: usize     = 56;    // u32
const OPT_SIZE_OF_HEADERS: usize   = 60;    // u32
const OPT_CHECKSUM: usize          = 64;    // u32

// Security directory index
const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;

/// INT/IAT entry size for PE32 vs PE32+
const PTR_SIZE_32: usize = 4;
const PTR_SIZE_64: usize = 8;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Source of PE data to dump.
#[derive(Debug, Clone)]
pub enum DumpSource {
    /// Live process identified by PID (simulated in unit tests).
    ProcessId(u32),
    /// A specific memory region base + size.
    MemoryRegion { base: u64, size: usize },
    /// Raw bytes already read into memory.
    RawBytes(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Bitflags controlling the dump operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DumpFlags(pub u8);

impl DumpFlags {
    pub const FIX_PE_HEADER:       u8 = 0x01;
    pub const REALIGN_SECTIONS:    u8 = 0x02;
    pub const REBUILD_IMPORTS:     u8 = 0x04;
    pub const DUMP_OVERLAY:        u8 = 0x08;
    pub const INCLUDE_CERTIFICATE: u8 = 0x10;

    #[must_use]
    pub const fn fix_pe_header(self) -> bool       { self.0 & Self::FIX_PE_HEADER != 0 }
    #[must_use]
    pub const fn realign_sections(self) -> bool    { self.0 & Self::REALIGN_SECTIONS != 0 }
    #[must_use]
    pub const fn rebuild_imports(self) -> bool     { self.0 & Self::REBUILD_IMPORTS != 0 }
    #[must_use]
    pub const fn dump_overlay(self) -> bool        { self.0 & Self::DUMP_OVERLAY != 0 }
    #[must_use]
    pub const fn include_certificate(self) -> bool { self.0 & Self::INCLUDE_CERTIFICATE != 0 }
}

/// Options controlling the dump operation.
#[derive(Debug, Clone)]
pub struct DumpOptions {
    pub flags: DumpFlags,
}

impl Default for DumpOptions {
    fn default() -> Self {
        Self {
            flags: DumpFlags(DumpFlags::FIX_PE_HEADER | DumpFlags::REALIGN_SECTIONS),
        }
    }
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

/// Output of a dump operation.
#[derive(Debug, Clone, Default)]
pub struct PeDumpResult {
    /// The raw in-memory image (minimal processing).
    pub raw_pe: Vec<u8>,
    /// The reconstructed on-disk PE (after all fixes).
    pub fixed_pe: Vec<u8>,
    /// Human-readable list of changes that were applied.
    pub changes_applied: Vec<String>,
    /// Non-fatal issues discovered during validation.
    pub validation_errors: Vec<String>,
}

// ---------------------------------------------------------------------------
// Internal section descriptor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SectionDesc {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl SectionDesc {
    #[must_use]
    pub fn name_str(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }
}

// ---------------------------------------------------------------------------
// Dumper
// ---------------------------------------------------------------------------

/// PE file dumper — reads a PE image from memory and reconstructs the
/// original on-disk representation.
pub struct PeDumper {
    options: DumpOptions,
}

impl PeDumper {
    /// Create a new dumper with the specified options.
    #[must_use]
    pub const fn new(options: DumpOptions) -> Self {
        Self { options }
    }

    /// Dump a PE image from the given source.
    ///
    /// # Errors
    /// Returns an error if the PE cannot be parsed or the source is
    /// unavailable (live memory access is not supported in this build).
    pub fn dump_from_memory(&self, source: DumpSource) -> Result<PeDumpResult, DumpError> {
        let raw = match source {
            DumpSource::RawBytes(bytes) => bytes,
            DumpSource::ProcessId(_pid) => {
                // In a real implementation this would call ReadProcessMemory.
                // Here we return an error to indicate a live process is required.
                return Err(DumpError::LiveMemoryUnavailable);
            }
            DumpSource::MemoryRegion { base: _, size: _ } => {
                return Err(DumpError::LiveMemoryUnavailable);
            }
        };

        // Parse basic structure
        let ctx = PeContext::parse(&raw)?;

        let mut fixed = raw.clone();
        let mut changes_applied = Vec::new();

        if self.options.flags.fix_pe_header() {
            Self::fix_nt_header(&mut fixed, &ctx, &mut changes_applied)?;
        }

        if self.options.flags.realign_sections() {
            fixed = Self::realign_sections(&fixed, &ctx, &mut changes_applied)?;
        }

        if self.options.flags.dump_overlay() {
            let overlay = Self::overlay_data(&raw, &ctx);
            if !overlay.is_empty() {
                fixed.extend_from_slice(&overlay);
                changes_applied.push(format!(
                    "appended {} bytes of overlay data", overlay.len()
                ));
            }
        }

        if !self.options.flags.include_certificate() {
            Self::strip_certificate_directory(&mut fixed, &ctx, &mut changes_applied);
        }

        let mut result = PeDumpResult { raw_pe: raw, changes_applied, ..PeDumpResult::default() };

        // Validate
        result.validation_errors = Self::validate(&fixed);
        result.fixed_pe = fixed;
        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Header fixing
    // -----------------------------------------------------------------------

    /// Reset loader-modified optional header fields.
    ///
    /// The Windows loader zeros several fields when mapping a PE: it clears
    /// `Misc.PhysicalAddress` (union with `VirtualSize`), may adjust `SizeOfImage`,
    /// and may zero the loader-reserved field at offset 68 of the optional
    /// header.  This function restores reasonable values.
    /// # Errors
    /// Returns an error if header fields cannot be fixed.
    ///
    /// # Panics
    /// Panics if internal `try_into` slice conversions fail.
    pub fn fix_nt_header(
        data: &mut [u8],
        ctx: &PeContext,
        changes: &mut Vec<String>,
    ) -> Result<(), DumpError> {
        let opt = ctx.opt_off;

        // SizeOfImage: recalculate from sections
        let last_section_end = ctx.sections.iter()
            .map(|s| align_up(s.virtual_address + s.virtual_size, ctx.section_alignment))
            .max()
            .unwrap_or(ctx.section_alignment);

        let size_of_image_off = opt + OPT_SIZE_OF_IMAGE;
        if size_of_image_off + 4 <= data.len() {
            let old_soi = u32::from_le_bytes(data[size_of_image_off..size_of_image_off + 4].try_into().unwrap());
            if old_soi != last_section_end {
                data[size_of_image_off..size_of_image_off + 4].copy_from_slice(&last_section_end.to_le_bytes());
                changes.push(format!(
                    "SizeOfImage corrected: {old_soi:#x} → {last_section_end:#x}"
                ));
            }
        }

        // Misc.VirtualSize (first field of optional header, also Misc.PhysicalAddress)
        // The loader sometimes zeroes this; restore from SizeOfHeaders
        let size_of_headers_off = opt + OPT_SIZE_OF_HEADERS;
        if size_of_headers_off + 4 <= data.len() {
            let headers_size = u32::from_le_bytes(data[size_of_headers_off..size_of_headers_off + 4].try_into().unwrap());
            if headers_size == 0 {
                // Estimate: header ends after section table
                let estimated = align_up(
                    u32::try_from(ctx.section_table_off).unwrap_or(u32::MAX)
                        + u32::try_from(ctx.sections.len()).unwrap_or(u32::MAX) * 40,
                    ctx.file_alignment,
                );
                data[size_of_headers_off..size_of_headers_off + 4].copy_from_slice(&estimated.to_le_bytes());
                changes.push(format!(
                    "SizeOfHeaders estimated: {estimated:#x}"
                ));
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Section realignment
    // -----------------------------------------------------------------------

    /// Restore `PointerToRawData` values that the loader has zeroed or
    /// recalculated.  The in-memory image has all sections at their virtual
    /// addresses; we reconstruct the on-disk layout by packing them
    /// sequentially starting after the header region.
    ///
    /// # Errors
    /// Currently infallible but returns `Result` for forward compatibility.
    ///
    /// # Panics
    /// Panics if internal `try_into` slice conversions fail.
    pub fn realign_sections(
        data: &[u8],
        ctx: &PeContext,
        changes: &mut Vec<String>,
    ) -> Result<Vec<u8>, DumpError> {
        // `section_table_off` is `e_lfanew + 24 + SizeOfOptionalHeader`, and
        // `file_alignment` is any power of two >= 512 the file cares to name --
        // neither is bounded by `data.len()`. Both the addition and the
        // alignment therefore have to saturate rather than wrap.
        let header_end = align_up(
            u32::try_from(ctx.section_table_off)
                .unwrap_or(u32::MAX)
                .saturating_add(
                    u32::try_from(ctx.sections.len())
                        .unwrap_or(u32::MAX)
                        .saturating_mul(40),
                ),
            ctx.file_alignment,
        );

        if header_end as usize > data.len() {
            return Err(DumpError::HeaderPastEndOfImage {
                header_end,
                len: data.len(),
            });
        }

        // Build the new on-disk layout
        let mut disk_offset = header_end;
        // `header_end <= data.len()` is proven immediately above; slicing
        // `data[..header_end]` unguarded used to panic on any image whose
        // SizeOfOptionalHeader or FileAlignment pushed the header past the end.
        let mut new_data: Vec<u8> = data[..header_end as usize].to_vec();
        // Ensure new_data is exactly header_end in size
        new_data.resize(header_end as usize, 0u8);

        for (i, s) in ctx.sections.iter().enumerate() {
            if s.virtual_size == 0 { continue; }
            let raw_size = align_up(s.virtual_size, ctx.file_alignment);

            // Extract section data from virtual address in original buffer
            let va_off = s.virtual_address as usize;
            let va_end = va_off + s.virtual_size as usize;
            let src_slice = if va_end <= data.len() {
                data[va_off..va_end].to_vec()
            } else if va_off < data.len() {
                let mut v = data[va_off..].to_vec();
                v.resize(s.virtual_size as usize, 0u8);
                v
            } else {
                vec![0u8; s.virtual_size as usize]
            };

            let mut padded = src_slice;
            padded.resize(raw_size as usize, 0u8);
            new_data.extend_from_slice(&padded);

            // Patch the section header in the header region
            let hdr_off = ctx.section_table_off + i * 40;
            if hdr_off + 40 <= new_data.len() {
                let old_ptr = u32::from_le_bytes(
                    new_data[hdr_off + 20..hdr_off + 24].try_into().unwrap()
                );
                if old_ptr != disk_offset || new_data[hdr_off + 16..hdr_off + 20] != raw_size.to_le_bytes() {
                    new_data[hdr_off + 16..hdr_off + 20].copy_from_slice(&raw_size.to_le_bytes());
                    new_data[hdr_off + 20..hdr_off + 24].copy_from_slice(&disk_offset.to_le_bytes());
                    changes.push(format!(
                        "section[{i}] ({}) PointerToRawData: {old_ptr:#x} → {disk_offset:#x}, SizeOfRawData: {raw_size:#x}",
                        s.name_str()
                    ));
                }
            }

            disk_offset += raw_size;
        }

        Ok(new_data)
    }

    // -----------------------------------------------------------------------
    // Module handle lookup
    // -----------------------------------------------------------------------

    /// Look up a PE header in `ldr_data` (simulated PEB.Ldr entries) by
    /// matching the given base address.
    ///
    /// In a real implementation this would walk the actual PEB loader data
    /// list.  Here we accept a slice of (base, name) pairs as test input.
    #[must_use]
    pub fn pe_from_module_handle(
        ldr_data: &[(u64, &str)],
        target_base: u64,
    ) -> Option<String> {
        ldr_data.iter()
            .find(|&&(base, _)| base == target_base)
            .map(|&(_, name)| name.to_owned())
    }

    // -----------------------------------------------------------------------
    // Memory protection check
    // -----------------------------------------------------------------------

    /// Check whether the memory at `address` in a given page map is
    /// accessible.  `page_map` maps page-aligned addresses to `true`
    /// (accessible) / `false` (inaccessible).
    #[must_use]
    pub fn detect_unmap_protection(
        page_map: &HashMap<u64, bool>,
        address: u64,
        page_size: u64,
    ) -> bool {
        let page_base = address & !(page_size - 1);
        *page_map.get(&page_base).unwrap_or(&false)
    }

    // -----------------------------------------------------------------------
    // Overlay
    // -----------------------------------------------------------------------

    /// Return bytes that appear after the last section's raw data end.
    #[must_use]
    pub fn overlay_data(data: &[u8], ctx: &PeContext) -> Vec<u8> {
        let last_end = ctx.sections.iter()
            .map(|s| s.pointer_to_raw_data as usize + s.size_of_raw_data as usize)
            .max()
            .unwrap_or(0);
        if last_end < data.len() {
            data[last_end..].to_vec()
        } else {
            vec![]
        }
    }

    // -----------------------------------------------------------------------
    // Certificate strip
    // -----------------------------------------------------------------------

    fn strip_certificate_directory(
        data: &mut [u8],
        ctx: &PeContext,
        changes: &mut Vec<String>,
    ) {
        // Data directory base: opt_off + 96 (PE32) or 112 (PE32+)
        let dd_base = ctx.opt_off + if ctx.is_pe32plus { 112 } else { 96 };
        let cert_off = dd_base + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
        if cert_off + 8 > data.len() { return; }
        let va = u32::from_le_bytes(data[cert_off..cert_off + 4].try_into().unwrap());
        let sz = u32::from_le_bytes(data[cert_off + 4..cert_off + 8].try_into().unwrap());
        if va == 0 || sz == 0 { return; }
        // Zero the directory entry
        data[cert_off..cert_off + 8].fill(0);
        changes.push(format!("stripped security certificate directory (va={va:#x}, size={sz:#x})"));
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    fn validate(data: &[u8]) -> Vec<String> {
        let mut issues = Vec::new();
        if data.len() < 64 {
            issues.push("buffer too small for DOS header".into());
            return issues;
        }
        let magic = u16::from_le_bytes(data[0..2].try_into().unwrap());
        if magic != DOS_MAGIC {
            issues.push(format!("bad MZ magic: {magic:#06x}"));
        }
        let e_lfanew = u32::from_le_bytes(data[60..64].try_into().unwrap()) as usize;
        if e_lfanew + 4 > data.len() {
            issues.push(format!("e_lfanew={e_lfanew:#x} out of bounds"));
            return issues;
        }
        let sig = u32::from_le_bytes(data[e_lfanew..e_lfanew + 4].try_into().unwrap());
        if sig != PE_SIGNATURE {
            issues.push(format!("bad PE signature: {sig:#010x}"));
        }
        issues
    }
}

// ---------------------------------------------------------------------------
// PeContext — minimal parsed PE information
// ---------------------------------------------------------------------------

/// Parsed context extracted from a PE image buffer.
#[derive(Debug, Clone)]
pub struct PeContext {
    pub e_lfanew: usize,
    pub opt_off: usize,
    pub is_pe32plus: bool,
    pub section_table_off: usize,
    pub file_alignment: u32,
    pub section_alignment: u32,
    pub sections: Vec<SectionDesc>,
}

impl PeContext {
    /// Parse a PE buffer into a `PeContext`.
    ///
    /// # Errors
    /// Returns an error if the buffer is too small, the DOS/PE magic is wrong,
    /// or the `e_lfanew` offset is out of bounds.
    ///
    /// # Panics
    /// Panics if internal `try_into` conversions fail.
    pub fn parse(data: &[u8]) -> Result<Self, DumpError> {
        if data.len() < 64 { return Err(DumpError::TooSmall); }
        let magic = u16::from_le_bytes(data[0..2].try_into().unwrap());
        if magic != DOS_MAGIC { return Err(DumpError::BadMagic(u32::from(magic))); }
        let e_lfanew = u32::from_le_bytes(data[60..64].try_into().unwrap()) as usize;
        if e_lfanew + 4 > data.len() { return Err(DumpError::BadElfanew(u32::try_from(e_lfanew).unwrap_or(u32::MAX))); }
        let pe_sig = u32::from_le_bytes(data[e_lfanew..e_lfanew + 4].try_into().unwrap());
        if pe_sig != PE_SIGNATURE { return Err(DumpError::BadPeSignature(pe_sig)); }

        let coff_off = e_lfanew + 4;
        let opt_off  = coff_off + 20;
        let is_pe32plus = if opt_off + 2 <= data.len() {
            u16::from_le_bytes(data[opt_off..opt_off + 2].try_into().unwrap()) == OPT_MAGIC_PE32PLUS
        } else { false };

        let oh_size = if coff_off + COFF_SIZE_OF_OPT_HDR + 2 <= data.len() {
            u16::from_le_bytes(
                data[coff_off + COFF_SIZE_OF_OPT_HDR..coff_off + COFF_SIZE_OF_OPT_HDR + 2].try_into().unwrap()
            ) as usize
        } else { 0 };

        let section_table_off = opt_off + oh_size;
        let n_sections = if coff_off + COFF_NUMBER_OF_SECTIONS + 2 <= data.len() {
            u16::from_le_bytes(
                data[coff_off + COFF_NUMBER_OF_SECTIONS..coff_off + COFF_NUMBER_OF_SECTIONS + 2].try_into().unwrap()
            ) as usize
        } else { 0 };

        let file_alignment = if opt_off + OPT_FILE_ALIGNMENT + 4 <= data.len() {
            u32::from_le_bytes(data[opt_off + OPT_FILE_ALIGNMENT..opt_off + OPT_FILE_ALIGNMENT + 4].try_into().unwrap())
        } else { 0x200 };
        let section_alignment = if opt_off + OPT_SECTION_ALIGNMENT + 4 <= data.len() {
            u32::from_le_bytes(data[opt_off + OPT_SECTION_ALIGNMENT..opt_off + OPT_SECTION_ALIGNMENT + 4].try_into().unwrap())
        } else { 0x1000 };
        let file_alignment = if file_alignment.is_power_of_two() && file_alignment >= 512 { file_alignment } else { 0x200 };
        let section_alignment = if section_alignment.is_power_of_two() && section_alignment >= 4096 { section_alignment } else { 0x1000 };

        let mut sections = Vec::with_capacity(n_sections);
        for i in 0..n_sections {
            let base = section_table_off + i * 40;
            if base + 40 > data.len() { break; }
            let h = &data[base..base + 40];
            let mut name = [0u8; 8];
            name.copy_from_slice(&h[0..8]);
            sections.push(SectionDesc {
                name,
                virtual_size:        u32::from_le_bytes(h[8..12].try_into().unwrap()),
                virtual_address:     u32::from_le_bytes(h[12..16].try_into().unwrap()),
                size_of_raw_data:    u32::from_le_bytes(h[16..20].try_into().unwrap()),
                pointer_to_raw_data: u32::from_le_bytes(h[20..24].try_into().unwrap()),
                characteristics:     u32::from_le_bytes(h[36..40].try_into().unwrap()),
            });
        }

        Ok(Self { e_lfanew, opt_off, is_pe32plus, section_table_off, file_alignment, section_alignment, sections })
    }
}

impl PeContext {
    /// Magic value of the optional header (`0x010B` PE32 or `0x020B` PE32+).
    #[must_use]
    pub const fn opt_magic(&self) -> u16 {
        if self.is_pe32plus { OPT_MAGIC_PE32PLUS } else { OPT_MAGIC_PE32 }
    }

    /// Byte size of an IAT / INT entry for this image (4 for PE32, 8 for PE32+).
    #[must_use]
    pub const fn pointer_size(&self) -> usize {
        if self.is_pe32plus { PTR_SIZE_64 } else { PTR_SIZE_32 }
    }

    /// Absolute file offset of the optional header's `CheckSum` field.
    #[must_use]
    pub const fn checksum_field_offset(&self) -> usize {
        self.opt_off + OPT_CHECKSUM
    }

    /// Histogram of section characteristics flag bits across `self.sections`.
    #[must_use]
    pub fn section_characteristics_histogram(&self) -> HashMap<u32, usize> {
        let mut h: HashMap<u32, usize> = HashMap::new();
        for s in &self.sections {
            *h.entry(s.characteristics).or_insert(0) += 1;
        }
        h
    }
}

// ---------------------------------------------------------------------------
// Alignment helper
// ---------------------------------------------------------------------------

const fn align_up(value: u32, align: u32) -> u32 {
    if align == 0 { return value; }
    value.saturating_add(align - 1) & !(align - 1)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DumpError {
    TooSmall,
    BadMagic(u32),
    BadElfanew(u32),
    BadPeSignature(u32),
    LiveMemoryUnavailable,
    /// The declared header region (`section_table_off + n_sections * 40`,
    /// aligned up to `FileAlignment`) runs past the end of the buffer.
    HeaderPastEndOfImage { header_end: u32, len: usize },
    Custom(String),
}

impl std::fmt::Display for DumpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooSmall => write!(f, "buffer too small"),
            Self::BadMagic(v) => write!(f, "bad DOS magic: {v:#x}"),
            Self::BadElfanew(v) => write!(f, "bad e_lfanew: {v:#x}"),
            Self::BadPeSignature(v) => write!(f, "bad PE signature: {v:#010x}"),
            Self::LiveMemoryUnavailable => write!(f, "live memory access not available in this build"),
            Self::HeaderPastEndOfImage { header_end, len } => write!(
                f,
                "declared header end {header_end:#x} is past the end of the {len}-byte image"
            ),
            Self::Custom(msg) => write!(f, "{msg}"),
        }
    }
}
impl std::error::Error for DumpError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe(n_sections: u16, fa: u32, sa: u32) -> Vec<u8> {
        let e_lfanew: u32 = 0x40;
        let oh_size: u16 = 0xE0;
        let sec_tbl = e_lfanew as usize + 4 + 20 + oh_size as usize;
        let needed = sec_tbl + n_sections as usize * 40 + 0x600;
        // Ensure buffer is large enough for tests that index at VA 0x1000 or later.
        let total = needed.max(0x2000);
        let mut pe = vec![0u8; total];
        pe[0] = b'M'; pe[1] = b'Z';
        pe[60..64].copy_from_slice(&e_lfanew.to_le_bytes());
        pe[e_lfanew as usize..e_lfanew as usize + 4].copy_from_slice(b"PE\0\0");
        // NumberOfSections
        pe[e_lfanew as usize + 6..e_lfanew as usize + 8].copy_from_slice(&n_sections.to_le_bytes());
        // SizeOfOptionalHeader
        pe[e_lfanew as usize + 20..e_lfanew as usize + 22].copy_from_slice(&oh_size.to_le_bytes());
        let opt = e_lfanew as usize + 24;
        // Magic PE32
        pe[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        // SectionAlignment
        pe[opt + 32..opt + 36].copy_from_slice(&sa.to_le_bytes());
        // FileAlignment
        pe[opt + 36..opt + 40].copy_from_slice(&fa.to_le_bytes());
        // SizeOfImage
        pe[opt + 56..opt + 60].copy_from_slice(&(sa * 4).to_le_bytes());
        pe
    }

    fn add_section(pe: &mut [u8], idx: usize, name: [u8; 8], va: u32, vsz: u32, ptr: u32, rsz: u32) {
        let e_lfanew = u32::from_le_bytes(pe[60..64].try_into().unwrap()) as usize;
        let oh_size = u16::from_le_bytes(pe[e_lfanew + 20..e_lfanew + 22].try_into().unwrap()) as usize;
        let base = e_lfanew + 4 + 20 + oh_size + idx * 40;
        if base + 40 <= pe.len() {
            pe[base..base + 8].copy_from_slice(&name);
            pe[base + 8..base + 12].copy_from_slice(&vsz.to_le_bytes());
            pe[base + 12..base + 16].copy_from_slice(&va.to_le_bytes());
            pe[base + 16..base + 20].copy_from_slice(&rsz.to_le_bytes());
            pe[base + 20..base + 24].copy_from_slice(&ptr.to_le_bytes());
        }
    }

    #[test]
    fn test_parse_context_minimal() {
        let pe = minimal_pe(0, 0x200, 0x1000);
        let ctx = PeContext::parse(&pe).unwrap();
        assert_eq!(ctx.file_alignment, 0x200);
        assert_eq!(ctx.section_alignment, 0x1000);
        assert_eq!(ctx.sections.len(), 0);
    }

    #[test]
    fn test_parse_context_bad_magic() {
        let mut pe = minimal_pe(0, 0x200, 0x1000);
        pe[0] = 0xFF;
        assert!(matches!(PeContext::parse(&pe), Err(DumpError::BadMagic(_))));
    }

    #[test]
    fn test_parse_one_section() {
        let mut pe = minimal_pe(1, 0x200, 0x1000);
        add_section(&mut pe, 0, *b".text\0\0\0", 0x1000, 0x500, 0x400, 0x600);
        let ctx = PeContext::parse(&pe).unwrap();
        assert_eq!(ctx.sections.len(), 1);
        assert_eq!(ctx.sections[0].virtual_address, 0x1000);
    }

    #[test]
    fn test_dump_raw_bytes_roundtrip() {
        let pe = minimal_pe(0, 0x200, 0x1000);
        let dumper = PeDumper::new(DumpOptions { flags: DumpFlags(0) });
        let result = dumper.dump_from_memory(DumpSource::RawBytes(pe.clone())).unwrap();
        assert_eq!(result.raw_pe, pe);
    }

    #[test]
    fn test_live_process_unavailable() {
        let dumper = PeDumper::new(DumpOptions::default());
        let result = dumper.dump_from_memory(DumpSource::ProcessId(1234));
        assert!(matches!(result, Err(DumpError::LiveMemoryUnavailable)));
    }

    #[test]
    fn test_fix_size_of_image() {
        let mut pe = minimal_pe(1, 0x200, 0x1000);
        add_section(&mut pe, 0, *b".text\0\0\0", 0x1000, 0x500, 0x400, 0x600);
        let ctx = PeContext::parse(&pe).unwrap();
        let mut changes = Vec::new();
        PeDumper::fix_nt_header(&mut pe, &ctx, &mut changes).unwrap();
        // SizeOfImage should be set to align_up(0x1000 + 0x500, 0x1000) = 0x2000
        let e_lfanew = 0x40usize;
        let opt = e_lfanew + 24;
        let soi = u32::from_le_bytes(pe[opt + 56..opt + 60].try_into().unwrap());
        assert_eq!(soi, 0x2000);
    }

    #[test]
    fn test_realign_sections_sets_pointer() {
        let mut pe = minimal_pe(1, 0x200, 0x1000);
        // section with ptr=0 (loader zeroed)
        add_section(&mut pe, 0, *b".text\0\0\0", 0x1000, 0x400, 0, 0);
        // Put some data at virtual address 0x1000
        pe[0x1000..0x1000 + 4].copy_from_slice(&[0xCC, 0xCC, 0xCC, 0xCC]);
        let ctx = PeContext::parse(&pe).unwrap();
        let mut changes = Vec::new();
        PeDumper::realign_sections(&mut pe, &ctx, &mut changes).unwrap();
        assert!(!changes.is_empty());
    }

    #[test]
    fn test_overlay_data_empty() {
        let pe = minimal_pe(0, 0x200, 0x1000);
        let ctx = PeContext::parse(&pe).unwrap();
        let overlay = PeDumper::overlay_data(&pe, &ctx);
        // No sections → everything or nothing is overlay; key: no panic
        let _ = overlay;
    }

    #[test]
    fn test_overlay_data_has_bytes() {
        let mut pe = minimal_pe(1, 0x200, 0x1000);
        add_section(&mut pe, 0, *b".text\0\0\0", 0x1000, 0x100, 0x400, 0x200);
        // The section ends at 0x400 + 0x200 = 0x600, so bytes after 0x600 are overlay
        pe[0x600] = 0xDE; pe[0x601] = 0xAD;
        let ctx = PeContext::parse(&pe).unwrap();
        let overlay = PeDumper::overlay_data(&pe, &ctx);
        assert!(!overlay.is_empty());
    }

    #[test]
    fn test_pe_from_module_handle_found() {
        let ldr = vec![(0x0001_4000_0000_u64, "ntdll.dll"), (0x7ff8_0000_0000_u64, "kernel32.dll")];
        let result = PeDumper::pe_from_module_handle(&ldr, 0x0001_4000_0000_u64);
        assert_eq!(result, Some("ntdll.dll".to_owned()));
    }

    #[test]
    fn test_pe_from_module_handle_not_found() {
        let ldr = vec![(0x0001_4000_0000_u64, "ntdll.dll")];
        let result = PeDumper::pe_from_module_handle(&ldr, 0xDEAD_0000_u64);
        assert_eq!(result, None);
    }

    #[test]
    fn test_detect_unmap_protection_accessible() {
        let mut map = HashMap::new();
        map.insert(0x1000u64, true);
        assert!(PeDumper::detect_unmap_protection(&map, 0x1234, 0x1000));
    }

    #[test]
    fn test_detect_unmap_protection_inaccessible() {
        let mut map = HashMap::new();
        map.insert(0x1000u64, false);
        assert!(!PeDumper::detect_unmap_protection(&map, 0x1000, 0x1000));
    }

    #[test]
    fn test_detect_unmap_protection_missing_page() {
        let map = HashMap::new();
        assert!(!PeDumper::detect_unmap_protection(&map, 0x5000, 0x1000));
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0x201, 0x200), 0x400);
        assert_eq!(align_up(0x400, 0x200), 0x400);
        assert_eq!(align_up(0, 0x1000), 0);
    }

    #[test]
    fn test_dump_options_default() {
        let opts = DumpOptions::default();
        assert!(opts.flags.fix_pe_header());
        assert!(opts.flags.realign_sections());
        assert!(!opts.flags.rebuild_imports());
    }

    #[test]
    fn test_context_section_name() {
        let mut pe = minimal_pe(1, 0x200, 0x1000);
        add_section(&mut pe, 0, *b".rdata\0\0", 0x2000, 0x100, 0x400, 0x200);
        let ctx = PeContext::parse(&pe).unwrap();
        assert_eq!(ctx.sections[0].name_str(), ".rdata");
    }

    #[test]
    fn test_full_dump_pipeline() {
        let mut pe = minimal_pe(1, 0x200, 0x1000);
        add_section(&mut pe, 0, *b".text\0\0\0", 0x1000, 0x400, 0, 0);
        for i in 0x1000..0x1400usize {
            if i < pe.len() { pe[i] = u8::try_from(i & 0xFF).unwrap_or(0xFF); }
        }
        let dumper = PeDumper::new(DumpOptions::default());
        let result = dumper.dump_from_memory(DumpSource::RawBytes(pe)).unwrap();
        assert!(!result.fixed_pe.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Hostile-header regression tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod hostile_header_tests {
    use super::{PeContext, PeDumper};

    /// Minimal PE whose `SizeOfOptionalHeader` and `FileAlignment` are chosen
    /// by the attacker. The buffer stays small on purpose.
    fn crafted_pe(oh_size: u16, file_alignment: u32, total: usize) -> Vec<u8> {
        let e_lfanew: u32 = 0x40;
        let mut pe = vec![0u8; total];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[60..64].copy_from_slice(&e_lfanew.to_le_bytes());
        let nt = e_lfanew as usize;
        pe[nt..nt + 4].copy_from_slice(b"PE\0\0");
        // COFF: NumberOfSections = 0, SizeOfOptionalHeader = oh_size
        pe[nt + 20..nt + 22].copy_from_slice(&oh_size.to_le_bytes());
        let opt = nt + 24;
        pe[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
        pe[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        pe[opt + 36..opt + 40].copy_from_slice(&file_alignment.to_le_bytes());
        pe
    }

    #[test]
    fn oversized_optional_header_is_rejected_not_panicked() {
        // SizeOfOptionalHeader = 0xFFFF pushes section_table_off to ~0x1_0057,
        // far past this 512-byte buffer. `data[..header_end]` used to panic.
        let pe = crafted_pe(0xFFFF, 0x200, 512);
        let ctx = PeContext::parse(&pe).expect("header parse should still succeed");
        let mut changes = Vec::new();
        let r = PeDumper::realign_sections(&pe, &ctx, &mut changes);
        assert!(r.is_err(), "expected a typed error, got Ok");
    }

    #[test]
    fn huge_file_alignment_is_rejected_not_panicked() {
        // 0x8000_0000 is a power of two >= 512, so it survives sanitisation and
        // aligns header_end up to 2 GiB.
        let pe = crafted_pe(0xE0, 0x8000_0000, 1024);
        let ctx = PeContext::parse(&pe).expect("header parse should still succeed");
        assert_eq!(ctx.file_alignment, 0x8000_0000);
        let mut changes = Vec::new();
        let r = PeDumper::realign_sections(&pe, &ctx, &mut changes);
        assert!(r.is_err(), "expected a typed error, got Ok");
    }

    #[test]
    fn well_formed_header_still_realigns() {
        let pe = crafted_pe(0xE0, 0x200, 0x2000);
        let ctx = PeContext::parse(&pe).expect("parse");
        let mut changes = Vec::new();
        assert!(PeDumper::realign_sections(&pe, &ctx, &mut changes).is_ok());
    }
}
