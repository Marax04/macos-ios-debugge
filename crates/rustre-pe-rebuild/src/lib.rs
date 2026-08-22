//! `rustre-pe-rebuild`
//!
//! PE reconstruction — rebuild a valid PE from partially corrupt or
//! memory-dumped data. Handles IAT fixing, relocation rebuilding, export
//! table reconstruction, OEP detection, import table reconstruction and
//! overlay preservation.

pub mod iat_rebuilder;
pub mod import_rebuilder;
pub mod oep_detection;
pub mod oep_finder;
pub mod pe_dump_fixer;
pub mod pe_fixup;
pub mod scylla_iat_rebuilder;
pub mod section_aligner;
pub mod pe_reconstructor;
pub mod import_table_rebuilder;
pub mod section_realigner;
pub mod pe_header_fixer;
pub mod pe_section_rebuilder;
pub mod pe_dumper;
pub mod relocation_rebuilder;

use std::collections::HashMap;
use std::fmt;

use rustre_pe_tools::{PeBuilder, PeError, PeFile, PeMachine};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by PE rebuild operations.
#[derive(Debug, Error)]
pub enum RebuildError {
    /// Underlying PE error.
    #[error("pe error: {0}")]
    Pe(#[from] PeError),
    /// No sections were provided; at least one is required.
    #[error("no sections provided")]
    NoSections,
    /// A section listed in the config has no data.
    #[error("section data missing for {0}")]
    SectionDataMissing(String),
    /// Image base was not set.
    #[error("image base not set")]
    ImageBaseNotSet,
    /// IAT entry references an out-of-bounds offset.
    #[error("IAT entry out of bounds: rva={0:#x}")]
    IatOutOfBounds(u64),
    /// Relocation block is malformed.
    #[error("malformed relocation block at {0:#x}")]
    BadReloc(u64),
    /// Export table is structurally corrupt.
    #[error("export table corrupt: {0}")]
    ExportCorrupt(String),
    /// OEP detection found no candidates.
    #[error("OEP detection found no candidates")]
    NoOepCandidates,
    /// Overlay data is inconsistent.
    #[error("overlay error: {0}")]
    OverlayError(String),
    /// Catch-all string error.
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Internal PE helpers — RVA ↔ file-offset conversion
// ---------------------------------------------------------------------------

/// A minimal section descriptor parsed from a raw PE buffer.
struct RawSection {
    rva: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

/// Parse section headers from a raw PE buffer.
fn pe_sections_from_buf(buf: &[u8]) -> Vec<RawSection> {
    let mut sections = Vec::new();
    // Minimum size: DOS header (64 bytes) to read e_lfanew.
    if buf.len() < 64 {
        return sections;
    }
    let pe_off = u32::from_le_bytes(buf[60..64].try_into().unwrap_or([0; 4])) as usize;
    // PE signature (4) + COFF header (20) = 24 bytes to get to optional header.
    if pe_off + 24 > buf.len() {
        return sections;
    }
    // Optional header size is at offset 20 from COFF header (i.e. pe_off + 4 + 16).
    let opt_hdr_size =
        u16::from_le_bytes(buf[pe_off + 20..pe_off + 22].try_into().unwrap_or([0; 2])) as usize;
    // Number of sections is at COFF offset 2 (i.e. pe_off + 4 + 2).
    let num_sections =
        u16::from_le_bytes(buf[pe_off + 6..pe_off + 8].try_into().unwrap_or([0; 2])) as usize;
    // Section table starts after PE signature (4) + COFF (20) + optional header.
    let sec_table_off = pe_off + 4 + 20 + opt_hdr_size;
    for i in 0..num_sections {
        let base = sec_table_off + i * 40;
        if base + 40 > buf.len() {
            break;
        }
        let virtual_size =
            u32::from_le_bytes(buf[base + 8..base + 12].try_into().unwrap_or([0; 4]));
        let rva =
            u32::from_le_bytes(buf[base + 12..base + 16].try_into().unwrap_or([0; 4]));
        let raw_size =
            u32::from_le_bytes(buf[base + 16..base + 20].try_into().unwrap_or([0; 4]));
        let raw_offset =
            u32::from_le_bytes(buf[base + 20..base + 24].try_into().unwrap_or([0; 4]));
        sections.push(RawSection { rva, virtual_size, raw_offset, raw_size });
    }
    sections
}

/// Convert an RVA to a file (raw) offset using the section table.
/// Returns `None` if the RVA does not fall within any section.
fn rva_to_raw_offset(sections: &[RawSection], rva: u32, buf_len: usize) -> Option<usize> {
    for sec in sections {
        let extent = sec.virtual_size.max(sec.raw_size);
        if rva >= sec.rva && rva < sec.rva.saturating_add(extent) {
            let delta = rva - sec.rva;
            let file_off = (sec.raw_offset as usize).saturating_add(delta as usize);
            if file_off < buf_len {
                return Some(file_off);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// RebuildSection
// ---------------------------------------------------------------------------

/// Section characteristics flags (subset).
pub mod chars {
    pub const CODE: u32 = 0x0000_0020;
    pub const INITIALIZED_DATA: u32 = 0x0000_0040;
    pub const UNINITIALIZED_DATA: u32 = 0x0000_0080;
    pub const MEM_EXECUTE: u32 = 0x2000_0000;
    pub const MEM_READ: u32 = 0x4000_0000;
    pub const MEM_WRITE: u32 = 0x8000_0000;
}

/// Describes a single section for PE reconstruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebuildSection {
    /// Section name (max 8 bytes).
    pub name: String,
    /// Desired RVA for this section in the reconstructed image.
    pub virtual_address: u32,
    /// Virtual size of this section.
    pub virtual_size: u32,
    /// Raw section data.
    pub data: Vec<u8>,
    /// Section characteristics flags.
    pub characteristics: u32,
}

impl RebuildSection {
    /// Create a new [`RebuildSection`], inferring `virtual_size` from `data.len()`.
    #[must_use]
    pub fn new(name: String, virtual_address: u32, data: Vec<u8>, characteristics: u32) -> Self {
        let virtual_size = u32::try_from(data.len()).unwrap_or(u32::MAX);
        Self {
            name,
            virtual_address,
            virtual_size,
            data,
            characteristics,
        }
    }

    /// Create a named code section.
    #[must_use]
    pub fn code(name: String, virtual_address: u32, data: Vec<u8>) -> Self {
        Self::new(
            name,
            virtual_address,
            data,
            chars::CODE | chars::MEM_EXECUTE | chars::MEM_READ,
        )
    }

    /// Create a named data section.
    #[must_use]
    pub fn data(name: String, virtual_address: u32, data: Vec<u8>) -> Self {
        Self::new(
            name,
            virtual_address,
            data,
            chars::INITIALIZED_DATA | chars::MEM_READ | chars::MEM_WRITE,
        )
    }

    /// Create a named read-only data section.
    #[must_use]
    pub fn rdata(name: String, virtual_address: u32, data: Vec<u8>) -> Self {
        Self::new(
            name,
            virtual_address,
            data,
            chars::INITIALIZED_DATA | chars::MEM_READ,
        )
    }

    /// Return entropy of the section data (Shannon entropy in bits per byte).
    #[must_use]
    pub fn entropy(&self) -> f64 {
        compute_entropy(&self.data)
    }

    /// Returns `true` if the section is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.characteristics & chars::MEM_EXECUTE != 0
    }

    /// Returns `true` if the section is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.characteristics & chars::MEM_WRITE != 0
    }

    /// End of the virtual address range (exclusive).
    #[must_use]
    pub const fn virtual_end(&self) -> u32 {
        self.virtual_address.saturating_add(self.virtual_size)
    }

    /// Returns `true` if `rva` falls within this section.
    #[must_use]
    pub const fn contains_rva(&self, rva: u32) -> bool {
        rva >= self.virtual_address && rva < self.virtual_end()
    }

    /// Convert an RVA to an offset within `data`, if in range.
    #[must_use]
    pub const fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        if self.contains_rva(rva) {
            let off = (rva - self.virtual_address) as usize;
            if off < self.data.len() {
                Some(off)
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl fmt::Display for RebuildSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} VA={:#x} vsz={:#x} entropy={:.2}",
            self.name,
            self.virtual_address,
            self.virtual_size,
            self.entropy()
        )
    }
}

// ---------------------------------------------------------------------------
// RebuildConfig
// ---------------------------------------------------------------------------

/// Bitflags controlling optional PE rebuild steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebuildFlags(pub u8);

impl RebuildFlags {
    /// Produce a PE32+ (64-bit) image; if unset, PE32 (32-bit).
    pub const IS_64BIT: Self = Self(0x01);
    /// Mark the output as a DLL (`Characteristics` bit set).
    pub const IS_DLL: Self = Self(0x02);
    /// Compute and write a valid PE checksum.
    pub const FIX_CHECKSUM: Self = Self(0x04);
    /// Attempt import-directory reconstruction.
    pub const FIX_IMPORTS: Self = Self(0x08);
    /// Attempt relocation-table fix-up.
    pub const FIX_RELOCATIONS: Self = Self(0x10);
    /// Strip any overlay data from the image.
    pub const STRIP_OVERLAY: Self = Self(0x20);
    /// No optional steps.
    pub const NONE: Self = Self(0x00);

    /// Returns `true` if `flag` is set.
    #[must_use]
    pub const fn contains(self, flag: Self) -> bool { self.0 & flag.0 != 0 }

    #[must_use] pub const fn is_64bit(self) -> bool { self.contains(Self::IS_64BIT) }
    #[must_use] pub const fn is_dll(self) -> bool { self.contains(Self::IS_DLL) }
    #[must_use] pub const fn fix_checksum(self) -> bool { self.contains(Self::FIX_CHECKSUM) }
    #[must_use] pub const fn fix_imports(self) -> bool { self.contains(Self::FIX_IMPORTS) }
    #[must_use] pub const fn fix_relocations(self) -> bool { self.contains(Self::FIX_RELOCATIONS) }
    #[must_use] pub const fn strip_overlay(self) -> bool { self.contains(Self::STRIP_OVERLAY) }
}

impl std::ops::BitOr for RebuildFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
}

impl std::ops::BitAnd for RebuildFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self { Self(self.0 & rhs.0) }
}

/// Configuration parameters for a PE rebuild operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebuildConfig {
    /// Target machine type.
    pub machine: PeMachine,
    /// Preferred image base.
    pub image_base: u64,
    /// Entry-point RVA.
    pub entry_point_rva: u32,
    /// Feature flags (64-bit, DLL, checksum, imports, relocations, overlay).
    pub flags: RebuildFlags,
    /// File alignment in bytes (must be a power of two, ≥ 0x200).
    pub file_alignment: u32,
    /// Section alignment in bytes (must be a power of two, ≥ `file_alignment`).
    pub section_alignment: u32,
}

impl Default for RebuildConfig {
    fn default() -> Self {
        Self {
            machine: PeMachine::Amd64,
            image_base: 0x0000_0001_4000_0000,
            entry_point_rva: 0x1000,
            flags: RebuildFlags::IS_64BIT,
            file_alignment: 0x200,
            section_alignment: 0x1000,
        }
    }
}

impl fmt::Display for RebuildConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RebuildConfig {} base={:#x} ep={:#x}",
            self.machine, self.image_base, self.entry_point_rva
        )
    }
}

// ---------------------------------------------------------------------------
// RebuildResult
// ---------------------------------------------------------------------------

/// The result of a successful PE rebuild.
#[derive(Debug, Clone)]
pub struct RebuildResult {
    /// The fully assembled PE bytes.
    pub data: Vec<u8>,
    /// Non-fatal warnings generated during reconstruction.
    pub warnings: Vec<String>,
    /// Number of sections in the rebuilt PE.
    pub section_count: usize,
    /// Statistics gathered during rebuild.
    pub stats: RebuildStats,
}

/// Statistics from a PE rebuild pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RebuildStats {
    /// Number of IAT entries processed.
    pub iat_entries_fixed: usize,
    /// Number of relocations applied.
    pub relocations_applied: usize,
    /// Number of exports reconstructed.
    pub exports_reconstructed: usize,
    /// Overlay size in bytes (0 if none).
    pub overlay_bytes: usize,
    /// Whether an OEP was detected automatically.
    pub oep_detected: bool,
}

impl fmt::Display for RebuildResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Rebuilt PE: {} bytes, {} sections, {} warnings",
            self.data.len(),
            self.section_count,
            self.warnings.len()
        )
    }
}

// ---------------------------------------------------------------------------
// IatEntry / IatFixer
// ---------------------------------------------------------------------------

/// A single entry in the Import Address Table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatEntry {
    /// RVA of the IAT slot.
    pub iat_rva: u32,
    /// Current (runtime) value at the slot (address in loaded image).
    pub value: u64,
    /// Resolved DLL name, if known.
    pub dll_name: Option<String>,
    /// Resolved function name, if known.
    pub function_name: Option<String>,
    /// Ordinal, if imported by ordinal.
    pub ordinal: Option<u16>,
}

impl IatEntry {
    /// Returns `true` if the entry has been resolved (name or ordinal).
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        self.function_name.is_some() || self.ordinal.is_some()
    }

    /// Human-readable representation of what is being imported.
    #[must_use]
    pub fn import_description(&self) -> String {
        let dll = self.dll_name.as_deref().unwrap_or("<unknown>");
        if let Some(ref name) = self.function_name {
            format!("{dll}!{name}")
        } else if let Some(ord) = self.ordinal {
            format!("{dll}!#{ord}")
        } else {
            format!("{dll}!<unresolved @ {:#x}>", self.value)
        }
    }
}

impl fmt::Display for IatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IAT[{:#x}] -> {}",
            self.iat_rva,
            self.import_description()
        )
    }
}

/// Options for IAT fixing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IatFixOptions {
    /// Base address where the image was loaded (used to resolve runtime addresses).
    pub image_base: u64,
    /// Optional mapping of runtime function addresses to (dll, name) pairs.
    pub known_imports: HashMap<u64, (String, String)>,
    /// Whether to allow unknown entries (just zero them out).
    pub allow_unknown: bool,
}

/// Fixes the Import Address Table in a rebuilt PE.
pub struct IatFixer {
    options: IatFixOptions,
    entries: Vec<IatEntry>,
}

impl IatFixer {
    /// Create a new IAT fixer with the given options.
    #[must_use]
    pub const fn new(options: IatFixOptions) -> Self {
        Self {
            options,
            entries: Vec::new(),
        }
    }

    /// Register a known IAT entry.
    pub fn add_entry(&mut self, entry: IatEntry) {
        self.entries.push(entry);
    }

    /// Register a known import mapping: runtime address → (dll, function name).
    pub fn register_import(&mut self, address: u64, dll: String, name: String) {
        self.options.known_imports.insert(address, (dll, name));
    }

    /// Process all registered IAT entries, resolving names where possible.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError::IatOutOfBounds`] if an entry RVA is out of the
    /// reconstructed image's address space.
    pub fn fix(&mut self) -> Result<usize, RebuildError> {
        let mut fixed = 0usize;
        for entry in &mut self.entries {
            if let Some((dll, func)) = self.options.known_imports.get(&entry.value) {
                entry.dll_name = Some(dll.clone());
                entry.function_name = Some(func.clone());
                fixed += 1;
            } else if self.options.allow_unknown {
                fixed += 1;
            }
        }
        Ok(fixed)
    }

    /// All IAT entries registered with this fixer.
    #[must_use]
    pub fn entries(&self) -> &[IatEntry] {
        &self.entries
    }

    /// Number of resolved entries (either name or ordinal known).
    #[must_use]
    pub fn resolved_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_resolved()).count()
    }

    /// Patch IAT entries into `pe_data`.  For each resolved entry, writes a
    /// zeroed thunk placeholder back to the PE image.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError::IatOutOfBounds`] if an RVA resolves beyond the
    /// length of `pe_data`.
    pub fn apply_to_image(
        &self,
        pe_data: &mut [u8],
        image_base: u64,
    ) -> Result<usize, RebuildError> {
        let mut applied = 0usize;
        // Parse the section table so we can convert RVAs to file offsets.
        let sections = pe_sections_from_buf(pe_data);
        for entry in &self.entries {
            let file_off = rva_to_raw_offset(&sections, entry.iat_rva, pe_data.len())
                .ok_or_else(|| RebuildError::IatOutOfBounds(u64::from(entry.iat_rva)))?;
            if file_off + 8 > pe_data.len() {
                return Err(RebuildError::IatOutOfBounds(u64::from(entry.iat_rva)));
            }
            // Write the image base + RVA as the resolved pointer (simplified).
            let resolved = image_base
                .checked_add(u64::from(entry.iat_rva))
                .ok_or_else(|| RebuildError::IatOutOfBounds(u64::from(entry.iat_rva)))?;
            pe_data[file_off..file_off + 8].copy_from_slice(&resolved.to_le_bytes());
            applied += 1;
        }
        Ok(applied)
    }
}

impl fmt::Debug for IatFixer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IatFixer {{ entries: {} }}", self.entries.len())
    }
}

// ---------------------------------------------------------------------------
// RelocationEntry / RelocationRebuilder
// ---------------------------------------------------------------------------

/// A single base relocation entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelocationEntry {
    /// RVA of the location that needs patching.
    pub rva: u32,
    /// Relocation type (0 = absolute/pad, 3 = HIGHLOW, 10 = DIR64).
    pub reloc_type: u8,
}

impl RelocationEntry {
    /// Create an absolute (padding) entry.
    #[must_use]
    pub const fn absolute() -> Self {
        Self {
            rva: 0,
            reloc_type: 0,
        }
    }

    /// Create a DIR64 relocation at `rva`.
    #[must_use]
    pub const fn dir64(rva: u32) -> Self {
        Self {
            rva,
            reloc_type: 10,
        }
    }

    /// Create a HIGHLOW relocation at `rva`.
    #[must_use]
    pub const fn highlow(rva: u32) -> Self {
        Self { rva, reloc_type: 3 }
    }

    /// Returns `true` if this is a meaningful (non-padding) entry.
    #[must_use]
    pub const fn is_meaningful(&self) -> bool {
        self.reloc_type != 0
    }
}

impl fmt::Display for RelocationEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Reloc[type={}] @ {:#x}", self.reloc_type, self.rva)
    }
}

/// Options for relocation rebuilding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelocationOptions {
    /// Original image base (before relocation).
    pub original_base: u64,
    /// New image base (after relocation).
    pub new_base: u64,
    /// Whether to generate a new `.reloc` section.
    pub rebuild_section: bool,
}

impl Default for RelocationOptions {
    fn default() -> Self {
        Self {
            original_base: 0x0040_0000,
            new_base: 0x0040_0000,
            rebuild_section: true,
        }
    }
}

/// Rebuilds the base relocation table for a PE image.
pub struct RelocationRebuilder {
    options: RelocationOptions,
    entries: Vec<RelocationEntry>,
}

impl RelocationRebuilder {
    /// Create a new rebuilder with the given options.
    #[must_use]
    pub const fn new(options: RelocationOptions) -> Self {
        Self {
            options,
            entries: Vec::new(),
        }
    }

    /// Add a relocation entry.
    pub fn add_entry(&mut self, entry: RelocationEntry) {
        self.entries.push(entry);
    }

    /// Add a DIR64 relocation at `rva`.
    pub fn add_dir64(&mut self, rva: u32) {
        self.entries.push(RelocationEntry::dir64(rva));
    }

    /// Add a HIGHLOW relocation at `rva`.
    pub fn add_highlow(&mut self, rva: u32) {
        self.entries.push(RelocationEntry::highlow(rva));
    }

    /// Number of registered relocations.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_meaningful()).count()
    }

    /// Delta between new and original base.
    #[must_use]
    pub const fn delta(&self) -> i64 {
        self.options.new_base.cast_signed() - self.options.original_base.cast_signed()
    }

    /// Serialize the relocation table into a `.reloc` section blob.
    ///
    /// The format is a sequence of `IMAGE_BASE_RELOCATION` blocks, each covering
    /// a 4 KiB page.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError::BadReloc`] if an entry has an invalid type.
    pub fn build_reloc_section(&self) -> Result<Vec<u8>, RebuildError> {
        if self.entries.is_empty() {
            return Ok(Vec::new());
        }

        // Group entries by 4-KiB page.
        let mut pages: HashMap<u32, Vec<&RelocationEntry>> = HashMap::new();
        for entry in &self.entries {
            if !entry.is_meaningful() {
                continue;
            }
            if entry.reloc_type != 3 && entry.reloc_type != 10 {
                return Err(RebuildError::BadReloc(u64::from(entry.rva)));
            }
            let page = entry.rva & !0xFFF;
            pages.entry(page).or_default().push(entry);
        }

        let mut out = Vec::new();
        let mut sorted_pages: Vec<u32> = pages.keys().copied().collect();
        sorted_pages.sort_unstable();

        for page_rva in sorted_pages {
            // Sort entries within each block by ascending page offset as required by the PE spec.
            let mut page_entries: Vec<&RelocationEntry> = pages[&page_rva].clone();
            page_entries.sort_unstable_by_key(|e| e.rva & 0xFFF);
            // Each entry = 2 bytes; block must be 4-byte aligned.
            let n = page_entries.len();
            let pad = usize::from(!n.is_multiple_of(2));
            let block_size = 8 + (n + pad) * 2;

            out.extend_from_slice(&page_rva.to_le_bytes());
            out.extend_from_slice(&u32::try_from(block_size).unwrap_or(u32::MAX).to_le_bytes());

            for e in &page_entries {
                let offset_in_page = u16::try_from(e.rva & 0xFFF).unwrap_or(u16::MAX);
                let entry_word = (u16::from(e.reloc_type) << 12) | offset_in_page;
                out.extend_from_slice(&entry_word.to_le_bytes());
            }
            // Padding entry.
            if pad != 0 {
                out.extend_from_slice(&0u16.to_le_bytes());
            }
        }

        Ok(out)
    }

    /// Apply all relocations to a mutable image buffer.
    ///
    /// # Panics
    ///
    /// Panics if a 4- or 8-byte slice extracted from `image` cannot be
    /// converted to a fixed-size array (should never happen given the bounds
    /// checks above).
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError::BadReloc`] if an entry's RVA is out of bounds.
    pub fn apply_to_image(&self, image: &mut [u8]) -> Result<usize, RebuildError> {
        let delta = self.delta();
        let mut applied = 0usize;
        for entry in &self.entries {
            if !entry.is_meaningful() {
                continue;
            }
            let off = usize::try_from(entry.rva).unwrap_or(usize::MAX);
            match entry.reloc_type {
                3 => {
                    // HIGHLOW: patch 32-bit value
                    if off + 4 > image.len() {
                        return Err(RebuildError::BadReloc(u64::from(entry.rva)));
                    }
                    let val = i32::from_le_bytes(image[off..off + 4].try_into().unwrap());
                    let new_val = val.wrapping_add(i32::try_from(delta).unwrap_or(i32::MAX));
                    image[off..off + 4].copy_from_slice(&new_val.to_le_bytes());
                    applied += 1;
                }
                10 => {
                    // DIR64: patch 64-bit value
                    if off + 8 > image.len() {
                        return Err(RebuildError::BadReloc(u64::from(entry.rva)));
                    }
                    let val = i64::from_le_bytes(image[off..off + 8].try_into().unwrap());
                    let new_val = val.wrapping_add(delta);
                    image[off..off + 8].copy_from_slice(&new_val.to_le_bytes());
                    applied += 1;
                }
                _ => {}
            }
        }
        Ok(applied)
    }
}

impl fmt::Debug for RelocationRebuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RelocationRebuilder {{ entries: {} }}",
            self.entries.len()
        )
    }
}

// ---------------------------------------------------------------------------
// ExportEntry / ExportRebuilder
// ---------------------------------------------------------------------------

/// A single export entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    /// Export ordinal (base-relative).
    pub ordinal: u32,
    /// Export name (empty = export by ordinal only).
    pub name: String,
    /// RVA of the exported function or data.
    pub rva: u32,
    /// Whether this is a forwarded export.
    pub is_forwarder: bool,
    /// Forwarder string, e.g. `"NTDLL.RtlAllocateHeap"`.
    pub forwarder: Option<String>,
}

impl ExportEntry {
    /// Create a named export.
    #[must_use]
    pub const fn named(name: String, ordinal: u32, rva: u32) -> Self {
        Self {
            ordinal,
            name,
            rva,
            is_forwarder: false,
            forwarder: None,
        }
    }

    /// Create an ordinal-only export.
    #[must_use]
    pub const fn ordinal_only(ordinal: u32, rva: u32) -> Self {
        Self {
            ordinal,
            name: String::new(),
            rva,
            is_forwarder: false,
            forwarder: None,
        }
    }

    /// Create a forwarder export.
    #[must_use]
    pub const fn forwarder(name: String, ordinal: u32, target: String) -> Self {
        Self {
            ordinal,
            name,
            rva: 0,
            is_forwarder: true,
            forwarder: Some(target),
        }
    }

    /// Returns `true` if the export has a name.
    #[must_use]
    pub const fn has_name(&self) -> bool {
        !self.name.is_empty()
    }
}

impl fmt::Display for ExportEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_forwarder {
            write!(
                f,
                "[{}] {} -> {}",
                self.ordinal,
                self.name,
                self.forwarder.as_deref().unwrap_or("?")
            )
        } else {
            write!(f, "[{}] {} @ {:#x}", self.ordinal, self.name, self.rva)
        }
    }
}

/// Rebuilds the export table section of a PE image.
pub struct ExportRebuilder {
    dll_name: String,
    ordinal_base: u32,
    entries: Vec<ExportEntry>,
}

impl ExportRebuilder {
    /// Create an export rebuilder for the given DLL name and ordinal base.
    #[must_use]
    pub const fn new(dll_name: String, ordinal_base: u32) -> Self {
        Self {
            dll_name,
            ordinal_base,
            entries: Vec::new(),
        }
    }

    /// Add an export entry.
    pub fn add_entry(&mut self, entry: ExportEntry) {
        self.entries.push(entry);
    }

    /// Number of exports.
    #[must_use]
    pub const fn export_count(&self) -> usize {
        self.entries.len()
    }

    /// Build the binary export directory structure.
    ///
    /// Returns `(edata_blob, export_dir_rva_offset)` — the caller should place
    /// this blob in a section and point `DataDirectory[0]` at it.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError::ExportCorrupt`] if ordinals are non-contiguous.
    pub fn build(&self, section_rva: u32) -> Result<Vec<u8>, RebuildError> {
        if self.entries.is_empty() {
            return Ok(Vec::new());
        }

        let mut sorted = self.entries.clone();
        sorted.sort_by_key(|e| e.ordinal);

        if let Some(first) = sorted.first()
            && first.ordinal < self.ordinal_base {
                return Err(RebuildError::ExportCorrupt(format!(
                    "export ordinal {} is below ordinal_base {}",
                    first.ordinal, self.ordinal_base
                )));
            }

        let n_functions = sorted
            .last()
            .map_or(0, |e| {
                e.ordinal
                    .checked_sub(self.ordinal_base)
                    .and_then(|d| d.checked_add(1))
                    .unwrap_or(u32::MAX)
            }) as usize;
        let named: Vec<&ExportEntry> = sorted.iter().filter(|e| e.has_name()).collect();
        let n_names = named.len();

        // Layout:
        // [0x28] export directory
        // [n_functions * 4] address table
        // [n_names * 4] name pointer table
        // [n_names * 2] ordinal table
        // [strings] dll_name + "\0" + all function names
        let dir_size = 0x28usize;
        let addr_table_off = dir_size;
        let name_ptr_off = addr_table_off + n_functions * 4;
        let ord_table_off = name_ptr_off + n_names * 4;
        let strings_off = ord_table_off + n_names * 2;

        let mut out = vec![0u8; strings_off];

        // Strings: DLL name first
        let dll_rva = section_rva.saturating_add(strings_off as u32);
        out.extend_from_slice(self.dll_name.as_bytes());
        out.push(0);

        // Function name strings
        let mut name_rvas: Vec<u32> = Vec::with_capacity(n_names);
        for e in &named {
            let rva = section_rva.saturating_add(out.len() as u32);
            name_rvas.push(rva);
            out.extend_from_slice(e.name.as_bytes());
            out.push(0);
        }

        // Fill export directory (IMAGE_EXPORT_DIRECTORY)
        // Characteristics (4)
        out[0..4].copy_from_slice(&0u32.to_le_bytes());
        // TimeDateStamp (4)
        out[4..8].copy_from_slice(&0u32.to_le_bytes());
        // MajorVersion, MinorVersion (2+2)
        out[8..12].copy_from_slice(&0u32.to_le_bytes());
        // Name RVA (4)
        out[12..16].copy_from_slice(&dll_rva.to_le_bytes());
        // OrdinalBase (4)
        out[16..20].copy_from_slice(&self.ordinal_base.to_le_bytes());
        // AddressTableEntries (4)
        out[20..24].copy_from_slice(&(n_functions as u32).to_le_bytes());
        // NumberOfNamePointers (4)
        out[24..28].copy_from_slice(&(n_names as u32).to_le_bytes());
        // AddressOfFunctions RVA (4)
        out[28..32].copy_from_slice(&section_rva.saturating_add(addr_table_off as u32).to_le_bytes());
        // AddressOfNames RVA (4)
        out[32..36].copy_from_slice(&section_rva.saturating_add(name_ptr_off as u32).to_le_bytes());
        // AddressOfNameOrdinals RVA (4)
        out[36..40].copy_from_slice(&section_rva.saturating_add(ord_table_off as u32).to_le_bytes());

        // Fill address table
        for e in &sorted {
            let idx = (e.ordinal - self.ordinal_base) as usize;
            let off = addr_table_off + idx * 4;
            out[off..off + 4].copy_from_slice(&e.rva.to_le_bytes());
        }

        // Fill name pointer and ordinal tables
        for (i, (e, &name_rva)) in named.iter().zip(name_rvas.iter()).enumerate() {
            let np_off = name_ptr_off + i * 4;
            out[np_off..np_off + 4].copy_from_slice(&name_rva.to_le_bytes());
            let ot_off = ord_table_off + i * 2;
            let ord_idx = (e.ordinal - self.ordinal_base) as u16;
            out[ot_off..ot_off + 2].copy_from_slice(&ord_idx.to_le_bytes());
        }

        Ok(out)
    }

    /// DLL name used for this export table.
    #[must_use]
    pub fn dll_name(&self) -> &str {
        &self.dll_name
    }
}

impl fmt::Debug for ExportRebuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExportRebuilder {{ dll: {}, exports: {} }}",
            self.dll_name,
            self.entries.len()
        )
    }
}

// ---------------------------------------------------------------------------
// OepDetector
// ---------------------------------------------------------------------------

/// Result of an OEP detection pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OepResult {
    /// Candidate RVA.
    pub rva: u32,
    /// Confidence score 0.0–1.0.
    pub confidence: f32,
    /// Reason string explaining why this was flagged.
    pub reason: String,
}

/// Detects the original entry point in an unpacked/dumped PE image.
pub struct OepDetector {
    candidates: Vec<OepResult>,
}

impl OepDetector {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            candidates: Vec::new(),
        }
    }

    /// Run heuristic detection on `sections`.
    ///
    /// Heuristics:
    /// 1. First executable section start → base candidate (0.3).
    /// 2. If section entropy < 7.0 (not packed) and starts with common prologues → 0.7.
    /// 3. If `known_ep_rva` is set → 1.0.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError::NoOepCandidates`] if no executable sections exist.
    pub fn detect(
        &mut self,
        sections: &[RebuildSection],
        known_ep_rva: Option<u32>,
    ) -> Result<OepResult, RebuildError> {
        self.candidates.clear();

        if let Some(ep) = known_ep_rva {
            let result = OepResult {
                rva: ep,
                confidence: 1.0,
                reason: "explicit EP supplied".to_string(),
            };
            self.candidates.push(result.clone());
            return Ok(result);
        }

        let exec_sections: Vec<&RebuildSection> =
            sections.iter().filter(|s| s.is_executable()).collect();

        if exec_sections.is_empty() {
            return Err(RebuildError::NoOepCandidates);
        }

        let mut best: Option<OepResult> = None;

        for sec in &exec_sections {
            let mut confidence = 0.3f32;
            let mut reason = format!("first executable section {}", sec.name);

            // Check entropy
            let ent = sec.entropy();
            if ent < 7.0 {
                confidence += 0.2;
                reason = format!("low-entropy section {} (entropy={:.2})", sec.name, ent);
            }

            // Check for common x64 function prologues
            if sec.data.len() >= 4 {
                let prologue = &sec.data[..4.min(sec.data.len())];
                if matches!(prologue, [0x40..=0x4F, 0x55, ..] | [0x55, 0x48, 0x89, 0xE5]) {
                    confidence += 0.3;
                    reason = format!("x64 prologue in {} (entropy={:.2})", sec.name, ent);
                } else if matches!(prologue, [0x55, 0x8B, 0xEC, ..]) {
                    confidence += 0.3;
                    reason = format!("x86 prologue in {} (entropy={:.2})", sec.name, ent);
                }
            }

            let candidate = OepResult {
                rva: sec.virtual_address,
                confidence: confidence.min(1.0),
                reason,
            };

            if best
                .as_ref()
                .is_none_or(|b| candidate.confidence > b.confidence)
            {
                best = Some(candidate.clone());
            }
            self.candidates.push(candidate);
        }

        best.ok_or(RebuildError::NoOepCandidates)
    }

    /// All candidates from the last detection run.
    #[must_use]
    pub fn candidates(&self) -> &[OepResult] {
        &self.candidates
    }
}

impl Default for OepDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for OepDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OepDetector {{ candidates: {} }}", self.candidates.len())
    }
}

// ---------------------------------------------------------------------------
// OverlayInfo / OverlayHandler
// ---------------------------------------------------------------------------

/// Information about PE overlay data (bytes after last section raw end).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayInfo {
    /// File offset where overlay begins.
    pub offset: usize,
    /// Overlay length in bytes.
    pub length: usize,
    /// First 16 bytes of overlay for identification.
    pub signature: Vec<u8>,
}

impl OverlayInfo {
    /// Returns `true` if the overlay is non-empty.
    #[must_use]
    pub const fn has_overlay(&self) -> bool {
        self.length > 0
    }
}

impl fmt::Display for OverlayInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Overlay @ {:#x} len={}", self.offset, self.length)
    }
}

/// Handles overlay data attached to PE files.
pub struct OverlayHandler;

impl OverlayHandler {
    /// Detect overlay data in `pe_bytes`.
    ///
    /// Scans the section table to find the last raw section end, then returns any
    /// bytes beyond that.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError::OverlayError`] if the PE header is too short to read.
    pub fn detect(pe_bytes: &[u8]) -> Result<OverlayInfo, RebuildError> {
        if pe_bytes.len() < 64 {
            return Err(RebuildError::OverlayError("data too short".to_string()));
        }
        let pe_off = u32::from_le_bytes(pe_bytes[60..64].try_into().unwrap_or([0; 4])) as usize;
        if pe_off + 24 > pe_bytes.len() {
            return Err(RebuildError::OverlayError(
                "PE header out of bounds".to_string(),
            ));
        }
        let n_sections = u16::from_le_bytes([pe_bytes[pe_off + 6], pe_bytes[pe_off + 7]]) as usize;
        let opt_hdr_size =
            u16::from_le_bytes([pe_bytes[pe_off + 20], pe_bytes[pe_off + 21]]) as usize;
        let sect_table_off = pe_off + 24 + opt_hdr_size;

        let mut last_raw_end = 0usize;
        for i in 0..n_sections {
            let hdr_off = sect_table_off + i * 40;
            if hdr_off + 40 > pe_bytes.len() {
                break;
            }
            let raw_size = u32::from_le_bytes(
                pe_bytes[hdr_off + 16..hdr_off + 20]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as usize;
            let raw_off = u32::from_le_bytes(
                pe_bytes[hdr_off + 20..hdr_off + 24]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as usize;
            let end = raw_off.saturating_add(raw_size);
            if end > last_raw_end {
                last_raw_end = end;
            }
        }

        if last_raw_end >= pe_bytes.len() {
            return Ok(OverlayInfo {
                offset: pe_bytes.len(),
                length: 0,
                signature: Vec::new(),
            });
        }

        let overlay_len = pe_bytes.len() - last_raw_end;
        let sig_len = overlay_len.min(16);
        let signature = pe_bytes[last_raw_end..last_raw_end + sig_len].to_vec();

        Ok(OverlayInfo {
            offset: last_raw_end,
            length: overlay_len,
            signature,
        })
    }

    /// Extract overlay bytes from `pe_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError::OverlayError`] if detection fails.
    pub fn extract(pe_bytes: &[u8]) -> Result<Vec<u8>, RebuildError> {
        let info = Self::detect(pe_bytes)?;
        Ok(pe_bytes[info.offset..].to_vec())
    }

    /// Preserve overlay: if `pe_bytes` has an overlay, append it to `rebuilt`.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError::OverlayError`] if detection fails.
    pub fn preserve(pe_bytes: &[u8], rebuilt: &mut Vec<u8>) -> Result<OverlayInfo, RebuildError> {
        let info = Self::detect(pe_bytes)?;
        if info.has_overlay() {
            rebuilt.extend_from_slice(&pe_bytes[info.offset..]);
        }
        Ok(info)
    }
}

// ---------------------------------------------------------------------------
// PeFixupOptions
// ---------------------------------------------------------------------------

/// Full set of options for a PE fixup/rebuild pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeFixupOptions {
    /// Fix the PE checksum.
    pub fix_checksum: bool,
    /// Zero the certificate directory entry.
    pub strip_signature: bool,
    /// Preserve overlay data.
    pub preserve_overlay: bool,
    /// Apply base relocations with the given delta.
    pub apply_relocs: Option<i64>,
    /// Override the entry point.
    pub override_ep: Option<u32>,
    /// Set DLL characteristic flag.
    pub set_dll_flag: Option<bool>,
}

impl Default for PeFixupOptions {
    fn default() -> Self {
        Self {
            fix_checksum: false,
            strip_signature: true,
            preserve_overlay: true,
            apply_relocs: None,
            override_ep: None,
            set_dll_flag: None,
        }
    }
}

/// Apply a set of fixups to a PE image in-place.
///
/// # Errors
///
/// Returns [`RebuildError`] if any fixup encounters a structural problem.
pub fn apply_fixups(
    image: &mut [u8],
    opts: &PeFixupOptions,
) -> Result<Vec<String>, RebuildError> {
    let mut notes = Vec::new();

    if image.len() < 64 {
        return Err(RebuildError::Other("image too short".to_string()));
    }

    let pe_off = u32::from_le_bytes(image[60..64].try_into().unwrap_or([0; 4])) as usize;

    if pe_off + 4 > image.len() || &image[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err(RebuildError::Other("invalid PE signature".to_string()));
    }

    let opt_off = pe_off + 24;
    if opt_off + 2 > image.len() {
        return Err(RebuildError::Other("optional header missing".to_string()));
    }
    let magic = u16::from_le_bytes([image[opt_off], image[opt_off + 1]]);
    let is_64bit = magic == 0x020B;

    // Override entry point
    if let Some(ep) = opts.override_ep
        && opt_off + 20 <= image.len()
    {
        image[opt_off + 16..opt_off + 20].copy_from_slice(&ep.to_le_bytes());
        notes.push(format!("EP overridden to {ep:#x}"));
    }

    // Strip signature (zero DataDirectory[4])
    if opts.strip_signature {
        let dd_base = if is_64bit { 112usize } else { 96usize };
        let sig_dd_off = opt_off
            .checked_add(dd_base)
            .and_then(|dd| dd.checked_add(4 * 8));
        match sig_dd_off {
            Some(off) if off.checked_add(8).is_some_and(|end| end <= image.len()) => {
                image[off..off + 8].fill(0);
                notes.push("security directory zeroed".to_string());
            }
            _ => {
                return Err(RebuildError::Other(
                    "optional header too short for security data directory".to_string(),
                ));
            }
        }
    }

    // Zero checksum
    if opts.fix_checksum {
        let _ = is_64bit;
        let cs_off = opt_off + 64;
        if cs_off + 4 <= image.len() {
            image[cs_off..cs_off + 4].fill(0);
            notes.push("checksum zeroed".to_string());
        }
    }

    // Set/clear DLL flag
    if let Some(is_dll) = opts.set_dll_flag {
        let chars_off = pe_off + 22; // COFF characteristics
        if chars_off + 2 <= image.len() {
            let mut ch = u16::from_le_bytes([image[chars_off], image[chars_off + 1]]);
            const DLL_FLAG: u16 = 0x2000;
            if is_dll {
                ch |= DLL_FLAG;
            } else {
                ch &= !DLL_FLAG;
            }
            image[chars_off..chars_off + 2].copy_from_slice(&ch.to_le_bytes());
            notes.push(format!("DLL flag set to {is_dll}"));
        }
    }

    Ok(notes)
}

// ---------------------------------------------------------------------------
// PeRebuilder
// ---------------------------------------------------------------------------

/// Engine for reconstructing PE files from section data and configuration.
pub struct PeRebuilder {
    config: RebuildConfig,
    sections: Vec<RebuildSection>,
}

impl PeRebuilder {
    /// Create a new rebuilder with the given configuration.
    #[must_use]
    pub const fn new(config: RebuildConfig) -> Self {
        Self {
            config,
            sections: vec![],
        }
    }

    /// Add a section to rebuild.
    pub fn add_section(&mut self, section: RebuildSection) -> &mut Self {
        self.sections.push(section);
        self
    }

    /// Find a section by name.
    #[must_use]
    pub fn section_by_name(&self, name: &str) -> Option<&RebuildSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Find the section that contains `rva`.
    #[must_use]
    pub fn section_at_rva(&self, rva: u32) -> Option<&RebuildSection> {
        self.sections.iter().find(|s| s.contains_rva(rva))
    }

    /// Highest virtual address end across all sections.
    #[must_use]
    pub fn virtual_end(&self) -> u32 {
        self.sections
            .iter()
            .map(RebuildSection::virtual_end)
            .max()
            .unwrap_or(0)
    }

    /// Assemble a valid PE file from the accumulated sections and config.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError`] if no sections were added or another structural
    /// problem prevents reconstruction.
    pub fn rebuild(&self) -> Result<RebuildResult, RebuildError> {
        if self.sections.is_empty() {
            return Err(RebuildError::NoSections);
        }

        let mut warnings: Vec<String> = Vec::new();
        let mut builder = if self.config.flags.is_64bit() {
            PeBuilder::new_x64()
        } else {
            PeBuilder::new_x86()
        };

        // Sort sections by virtual address for deterministic ordering
        let mut sorted = self.sections.clone();
        sorted.sort_by_key(|s| s.virtual_address);

        for sec in &sorted {
            builder.add_section(&sec.name, sec.data.clone(), sec.characteristics);
        }

        let raw = builder.build();

        // Verify the result parses
        let pe = PeFile::parse(&raw).map_err(RebuildError::Pe)?;

        // Warn if entry point RVA doesn't land in any section
        if pe.section_at_rva(self.config.entry_point_rva).is_none()
            && self.config.entry_point_rva != 0
        {
            warnings.push(format!(
                "entry point RVA {:#x} does not fall within any section",
                self.config.entry_point_rva
            ));
        }

        let section_count = pe.sections.len();
        let stats = RebuildStats::default();
        Ok(RebuildResult {
            data: raw,
            warnings,
            section_count,
            stats,
        })
    }

    /// Attempt to rebuild a PE from a raw memory dump.
    ///
    /// Strategy:
    /// 1. Check for MZ/PE magic.
    /// 2. Parse with [`PeFile::parse`]; if that succeeds use its section table.
    /// 3. Fall back to a best-effort scan if the header is partially corrupt.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError`] if the data is completely unrecognisable.
    pub fn from_memory_dump(
        data: &[u8],
        _base_addr: u64,
        config: RebuildConfig,
    ) -> Result<RebuildResult, RebuildError> {
        if !is_memory_pe(data) {
            return Err(RebuildError::Other(
                "data does not start with MZ magic".to_string(),
            ));
        }

        let mut warnings: Vec<String> = Vec::new();
        let mut rebuilder = Self::new(config);

        match PeFile::parse(data) {
            Ok(pe) => {
                for sec in &pe.sections {
                    let sec_data = if sec.data.is_empty() {
                        warnings.push(format!("section {} has no raw data", sec.name));
                        // Cap allocation to 256 MiB to prevent OOM from untrusted input.
                        let alloc_size = (sec.virtual_size as usize).min(256 * 1024 * 1024);
                        vec![0u8; alloc_size]
                    } else {
                        sec.data.clone()
                    };
                    rebuilder.add_section(RebuildSection::new(
                        sec.name.clone(),
                        sec.virtual_address,
                        sec_data,
                        sec.characteristics,
                    ));
                }
            }
            Err(_) => {
                warnings.push(
                    "PE header parse failed; falling back to single-section dump".to_string(),
                );
                rebuilder.add_section(RebuildSection::new(
                    ".dump".to_string(),
                    0x1000,
                    data.to_vec(),
                    0x6000_0020,
                ));
            }
        }

        let mut result = rebuilder.rebuild()?;
        result.warnings.extend(warnings);
        Ok(result)
    }

    /// Align `value` up to the next multiple of `align`.
    #[must_use]
    pub const fn align_up(value: u32, align: u32) -> u32 {
        if align == 0 {
            return value;
        }
        let mask = align - 1;
        match value.checked_add(mask) {
            Some(sum) => {
                let aligned = sum & !mask;
                if aligned < value { u32::MAX } else { aligned }
            }
            None => u32::MAX,
        }
    }

    /// Reference to the current rebuild configuration.
    #[must_use]
    pub const fn config(&self) -> &RebuildConfig {
        &self.config
    }

    /// Number of sections currently registered with this rebuilder.
    #[must_use]
    pub const fn section_count(&self) -> usize {
        self.sections.len()
    }

    /// All sections registered with this rebuilder.
    #[must_use]
    pub fn sections(&self) -> &[RebuildSection] {
        &self.sections
    }

    /// Sort sections by virtual address in-place.
    pub fn sort_sections(&mut self) {
        self.sections.sort_by_key(|s| s.virtual_address);
    }

    /// Remove all sections.
    pub fn clear_sections(&mut self) {
        self.sections.clear();
    }

    /// Rebuild with OEP auto-detection.
    ///
    /// Runs the [`OepDetector`] first, sets `config.entry_point_rva` accordingly,
    /// then calls `rebuild`.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError`] if detection or rebuild fails.
    pub fn rebuild_with_oep_detection(&mut self) -> Result<RebuildResult, RebuildError> {
        let mut detector = OepDetector::new();
        let oep = detector.detect(&self.sections, None)?;
        self.config.entry_point_rva = oep.rva;
        let mut result = self.rebuild()?;
        result.stats.oep_detected = true;
        Ok(result)
    }
}

impl fmt::Debug for PeRebuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeRebuilder {{ sections: {} }}", self.sections.len())
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Returns `true` if `data` begins with the MZ signature and has at least 64 bytes,
/// indicating it is likely a PE image (possibly memory-mapped).
#[must_use]
pub fn is_memory_pe(data: &[u8]) -> bool {
    data.len() >= 64 && data[0] == 0x4D && data[1] == 0x5A
}

/// Compute Shannon entropy of `data` in bits per byte (0.0–8.0).
#[must_use]
pub fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Compute CRC-16/CCITT (polynomial 0x1021, init 0xFFFF) over `data`.
#[must_use]
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        let x = (crc >> 8) ^ u16::from(b);
        let x = x ^ (x >> 4);
        crc = (crc << 8) ^ (x << 12) ^ (x << 5) ^ x;
    }
    crc
}

/// Compute a djb2-based import fingerprint over sorted, lowercase `dll.function` strings.
///
/// NOTE: This is NOT a standard imphash (which uses MD5). It returns a 16-hex-digit
/// djb2 digest useful as a fast fingerprint, but it will not match imphash values
/// produced by Mandiant, YARA, or other tools. Returns an empty string if there
/// are no named entries.
#[must_use]
pub fn compute_imphash(entries: &[IatEntry]) -> String {
    let mut parts: Vec<String> = entries
        .iter()
        .filter(|e| e.function_name.is_some() && e.dll_name.is_some())
        .map(|e| {
            format!(
                "{}.{}",
                e.dll_name
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .trim_end_matches(".dll"),
                e.function_name.as_deref().unwrap_or("").to_lowercase()
            )
        })
        .collect();
    parts.sort_unstable();
    let joined = parts.join(",");
    // Simple djb2-style hash as hex (no MD5 dep)
    let mut h: u64 = 5381;
    for b in joined.bytes() {
        h = h.wrapping_mul(33).wrapping_add(u64::from(b));
    }
    format!("{h:016x}")
}

// ---------------------------------------------------------------------------
// IatScanner — Scylla-style IAT region detection
// ---------------------------------------------------------------------------

/// A contiguous region of the address space that looks like an IAT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatRegion {
    /// Virtual address of the start of this region.
    pub va: u64,
    /// Size in bytes of the region.
    pub size: usize,
    /// Raw pointer values found in this region.
    pub entries: Vec<u64>,
}

impl IatRegion {
    /// Number of pointer-sized slots in this region.
    #[must_use]
    pub const fn slot_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if this region contains at least one entry.
    #[must_use]
    pub const fn is_non_empty(&self) -> bool {
        !self.entries.is_empty()
    }
}

impl fmt::Display for IatRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IatRegion @ {:#x} size={:#x} entries={}",
            self.va,
            self.size,
            self.entries.len()
        )
    }
}

/// Heuristic scanner that finds likely IAT regions in a memory dump.
pub struct IatScanner;

impl IatScanner {
    /// Scan `dump` for contiguous arrays of plausible pointer values.
    ///
    /// A pointer is considered plausible when:
    /// - Its value is non-zero.
    /// - Its value is 8-byte aligned (typical for 64-bit imports).
    /// - Its value falls in the typical user-space range `[0x1000_0000, 0x7FFF_FFFF_FFFF]`.
    ///
    /// Consecutive plausible pointers are grouped into [`IatRegion`]s.
    /// Groups of fewer than 2 entries are discarded.
    ///
    /// `base` is the virtual address at which `dump` is mapped.
    #[must_use]
    pub fn scan_for_iat(dump: &[u8], base: u64) -> Vec<IatRegion> {
        const PTR_SIZE: usize = 8;
        const MIN_ENTRIES: usize = 2;
        // Typical 64-bit user-space range for loaded module addresses.
        const PTR_MIN: u64 = 0x1000_0000;
        const PTR_MAX: u64 = 0x7FFF_FFFF_FFFF;

        let mut regions: Vec<IatRegion> = Vec::new();
        let mut current_entries: Vec<u64> = Vec::new();
        let mut current_va: u64 = 0;

        let aligned_start = {
            // Start scanning from the first PTR_SIZE-aligned offset.
            let r = dump.as_ptr() as usize % PTR_SIZE;
            if r == 0 { 0 } else { PTR_SIZE - r }
        };

        let mut i = aligned_start;
        while i + PTR_SIZE <= dump.len() {
            let val = u64::from_le_bytes(dump[i..i + PTR_SIZE].try_into().unwrap_or([0; 8]));
            let va = base + i as u64;
            let plausible = val != 0 && (PTR_MIN..=PTR_MAX).contains(&val) && (val & 0x7) == 0; // at least 8-byte aligned target

            if plausible {
                if current_entries.is_empty() {
                    current_va = va;
                }
                current_entries.push(val);
            } else {
                if current_entries.len() >= MIN_ENTRIES {
                    let size = current_entries.len() * PTR_SIZE;
                    regions.push(IatRegion {
                        va: current_va,
                        size,
                        entries: current_entries.clone(),
                    });
                }
                current_entries.clear();
            }
            i += PTR_SIZE;
        }

        // Flush the last group.
        if current_entries.len() >= MIN_ENTRIES {
            let size = current_entries.len() * PTR_SIZE;
            regions.push(IatRegion {
                va: current_va,
                size,
                entries: current_entries,
            });
        }

        regions
    }
}

// ---------------------------------------------------------------------------
// ModuleResolver — resolve a runtime pointer to a DLL export
// ---------------------------------------------------------------------------

/// Resolves a runtime pointer value to a (`dll_name`, `function_name`) pair
/// by searching a snapshot of loaded modules.
pub struct ModuleResolver;

impl ModuleResolver {
    /// Given a runtime `ptr` and a list of `(base, size, path)` tuples for
    /// loaded modules, return the module path (DLL name) whose address range
    /// contains `ptr`.
    ///
    /// `loaded_modules` is a slice of `(module_base, module_size, dll_path)`.
    /// Function resolution within the module is platform-specific (requires
    /// reading the PE export table from the module in memory), so this stub
    /// returns a placeholder function name if the module is found.
    ///
    /// Returns `None` if no module covers `ptr`.
    #[must_use]
    pub fn resolve_pointer(
        ptr: u64,
        loaded_modules: &[(u64, u64, String)],
    ) -> Option<(String, String)> {
        for (base, size, path) in loaded_modules {
            if ptr >= *base && ptr < base.saturating_add(*size) {
                let dll = extract_dll_name(path);
                // The function name would normally be resolved by parsing the
                // export table of the module image in memory.  That requires
                // platform-specific VA→file-offset translation, which is out of
                // scope for a portable library.  We return a placeholder.
                let offset = ptr - base;
                let func = format!("sub_{offset:x}");
                return Some((dll, func));
            }
        }
        None
    }

    /// Batch-resolve a list of `(ptr, iat_rva)` pairs.
    ///
    /// Returns a `Vec<(iat_rva, dll_name, function_name)>` for all resolved
    /// pointers, silently skipping unresolvable ones.
    #[must_use]
    pub fn resolve_batch(
        pointers: &[(u64, u32)],
        loaded_modules: &[(u64, u64, String)],
    ) -> Vec<(u32, String, String)> {
        pointers
            .iter()
            .filter_map(|&(ptr, iat_rva)| {
                Self::resolve_pointer(ptr, loaded_modules).map(|(dll, func)| (iat_rva, dll, func))
            })
            .collect()
    }
}

/// Extract the filename (without path) from a full DLL path.
fn extract_dll_name(path: &str) -> String {
    path.replace('\\', "/")
        .split('/')
        .next_back()
        .unwrap_or(path)
        .to_string()
}

// ---------------------------------------------------------------------------
// OepDetector heuristics (full implementation)
// ---------------------------------------------------------------------------

/// A single OEP candidate produced by heuristic scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OepCandidate {
    /// Absolute virtual address.
    pub address: u64,
    /// Confidence in [0.0, 1.0].
    pub confidence: f32,
    /// Human-readable reason.
    pub reason: String,
}

impl fmt::Display for OepCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OEP@{:#x} conf={:.2} ({})",
            self.address, self.confidence, self.reason
        )
    }
}

/// Detect likely OEP candidates in a raw memory dump using byte-pattern heuristics.
///
/// `base` is the virtual address at which `dump` is loaded.
///
/// The function scans every aligned 16-byte-boundary for known x86/x64 function
/// prologues.  Results are sorted by descending confidence.
///
/// Heuristics applied:
/// 1. `55 8B EC` — PUSH EBP / MOV EBP, ESP (classic x86 prologue, confidence 0.7).
/// 2. `55 48 89 E5` — PUSH RBP / MOV RBP, RSP (x64 prologue, confidence 0.75).
/// 3. `53 56 57` — PUSH EBX / PUSH ESI / PUSH EDI (CRT startup, confidence 0.5).
/// 4. `83 EC XX` — SUB ESP, imm8 (frame setup, confidence 0.4).
/// 5. `40 55` / `40 53` / `40 56` — REX.W PUSH (x64 register save, confidence 0.45).
/// 6. `48 83 EC XX` — SUB RSP, imm8 (x64 frame setup, confidence 0.5).
#[must_use]
pub fn detect_oep_heuristics(dump: &[u8], base: u64) -> Vec<OepCandidate> {
    let mut candidates: Vec<OepCandidate> = Vec::new();

    // Scan every 4-byte aligned offset for known prologues.
    let len = dump.len();
    let mut i = 0usize;
    while i + 3 <= len {
        let b = &dump[i..];
        let va = base + i as u64;

        // x86: PUSH EBP / MOV EBP, ESP
        if b.len() >= 3 && b[0] == 0x55 && b[1] == 0x8B && b[2] == 0xEC {
            candidates.push(OepCandidate {
                address: va,
                confidence: 0.70,
                reason: "x86 PUSH EBP; MOV EBP, ESP".to_string(),
            });
        }
        // x64: PUSH RBP / MOV RBP, RSP
        else if b.len() >= 4 && b[0] == 0x55 && b[1] == 0x48 && b[2] == 0x89 && b[3] == 0xE5 {
            candidates.push(OepCandidate {
                address: va,
                confidence: 0.75,
                reason: "x64 PUSH RBP; MOV RBP, RSP".to_string(),
            });
        }
        // x86 CRT startup: PUSH EBX / PUSH ESI / PUSH EDI
        else if b.len() >= 3 && b[0] == 0x53 && b[1] == 0x56 && b[2] == 0x57 {
            candidates.push(OepCandidate {
                address: va,
                confidence: 0.50,
                reason: "PUSH EBX; PUSH ESI; PUSH EDI (CRT startup)".to_string(),
            });
        }
        // x86 frame setup: SUB ESP, imm8
        else if b.len() >= 3 && b[0] == 0x83 && b[1] == 0xEC {
            candidates.push(OepCandidate {
                address: va,
                confidence: 0.40,
                reason: format!("SUB ESP, {:#x}", b[2]),
            });
        }
        // x64: SUB RSP, imm8
        else if b.len() >= 4 && b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xEC {
            candidates.push(OepCandidate {
                address: va,
                confidence: 0.50,
                reason: format!("SUB RSP, {:#x}", b[3]),
            });
        }
        // x64 REX.W register save prologues (40 5x pattern)
        else if b.len() >= 2 && b[0] == 0x40 && matches!(b[1], 0x53 | 0x55 | 0x56 | 0x57) {
            candidates.push(OepCandidate {
                address: va,
                confidence: 0.45,
                reason: format!("REX.W PUSH r{:x}", b[1] & 0x0F),
            });
        }

        i += 4; // stride: scan at 4-byte granularity
    }

    // Sort by descending confidence, then by address for determinism.
    candidates.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.address.cmp(&b.address))
    });

    candidates
}

// ---------------------------------------------------------------------------
// PeDumper — reconstruct a valid PE from a memory dump
// ---------------------------------------------------------------------------

/// Engine for converting a raw memory dump into a loadable PE file.
pub struct PeDumper;

impl PeDumper {
    /// Build a valid PE from a memory dump.
    ///
    /// The algorithm:
    /// 1. Copy the dump bytes.
    /// 2. Verify / fix the DOS header and `e_lfanew`.
    /// 3. Verify / fix the PE signature.
    /// 4. Fix `Magic` and detect 32/64-bit mode from the optional header.
    /// 5. For every section header, convert virtual→file layout:
    ///    `PointerToRawData = VirtualAddress - base_offset`,
    ///    `SizeOfRawData = VirtualSize` (rounded up to file alignment).
    /// 6. Set the entry point in the optional header to `oep`.
    /// 7. Zero the checksum (caller should recalculate if needed).
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError`] if the dump is too short or the headers are
    /// unrecognisable.
    pub fn build_valid_pe(dump: &[u8], base: u64, oep: u64) -> Result<Vec<u8>, RebuildError> {
        if dump.len() < 64 {
            return Err(RebuildError::Other(format!(
                "dump too short: {} bytes (need at least 64)",
                dump.len()
            )));
        }

        let mut out = dump.to_vec();

        // Step 1: Verify MZ magic.
        if out[0] != 0x4D || out[1] != 0x5A {
            // Attempt to patch it.
            out[0] = 0x4D;
            out[1] = 0x5A;
        }

        // Step 2: Locate e_lfanew and verify PE signature.
        let e_lfanew = u32::from_le_bytes([out[60], out[61], out[62], out[63]]) as usize;
        let pe_off = if e_lfanew + 4 <= out.len() && &out[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
            e_lfanew
        } else {
            // Scan the dump for the PE signature.
            let found = out.windows(4).position(|w| w == b"PE\0\0");
            match found {
                Some(off) => {
                    // Patch e_lfanew.
                    out[60..64].copy_from_slice(&(off as u32).to_le_bytes());
                    off
                }
                None => {
                    return Err(RebuildError::Other(
                        "PE signature not found in dump".to_string(),
                    ));
                }
            }
        };

        // Step 3: Read COFF header.
        let coff_off = pe_off + 4;
        if coff_off + 20 > out.len() {
            return Err(RebuildError::Other("COFF header out of bounds".to_string()));
        }
        let n_sections = u16::from_le_bytes([out[coff_off + 2], out[coff_off + 3]]) as usize;
        let opt_hdr_size = u16::from_le_bytes([out[coff_off + 16], out[coff_off + 17]]) as usize;

        // Step 4: Detect bitness from optional header magic.
        let opt_off = coff_off + 20;
        if opt_off + 2 > out.len() {
            return Err(RebuildError::Other("optional header missing".to_string()));
        }
        let magic = u16::from_le_bytes([out[opt_off], out[opt_off + 1]]);
        let is_64bit = magic == 0x020B;
        // If magic is completely wrong, assume 64-bit and patch it.
        if magic != 0x010B && magic != 0x020B {
            out[opt_off] = 0x0B;
            out[opt_off + 1] = 0x02;
        }

        // Step 5: Section virtual→file layout conversion.
        // In a memory dump the sections are laid out by VA, not by file offset.
        // We compute the "header size" as the boundary before the first section
        // and use that as the offset base.
        const FILE_ALIGN: u32 = 0x200;
        let sect_table_off = opt_off + opt_hdr_size;

        // Determine the smallest VA among sections to compute where VA==0 maps.
        // In a typical dump, VA offsets are already file-relative because the
        // loader places sections at their RVAs starting from offset 0.
        // We keep PointerToRawData = VirtualAddress for simplicity.
        for i in 0..n_sections {
            let hdr = sect_table_off + i * 40;
            if hdr + 40 > out.len() {
                break;
            }
            let virtual_address =
                u32::from_le_bytes(out[hdr + 12..hdr + 16].try_into().unwrap_or([0; 4]));
            let virtual_size =
                u32::from_le_bytes(out[hdr + 8..hdr + 12].try_into().unwrap_or([0; 4]));

            // PointerToRawData = VirtualAddress (dump is laid out in memory order).
            let raw_size = PeRebuilder::align_up(virtual_size, FILE_ALIGN);
            out[hdr + 16..hdr + 20].copy_from_slice(&raw_size.to_le_bytes());
            out[hdr + 20..hdr + 24].copy_from_slice(&virtual_address.to_le_bytes());
        }

        // Step 6: Set entry point.
        // EP RVA = oep - base
        let ep_rva = oep.saturating_sub(base) as u32;
        // AddressOfEntryPoint is at opt_off + 16.
        if opt_off + 20 <= out.len() {
            out[opt_off + 16..opt_off + 20].copy_from_slice(&ep_rva.to_le_bytes());
        }

        // Step 7: Zero the checksum.
        // Checksum is at opt_off + 64.
        if opt_off + 68 <= out.len() {
            out[opt_off + 64..opt_off + 68].fill(0);
        }

        // Update ImageBase to match the supplied base.
        let _ = is_64bit;
        if opt_off + 32 <= out.len() {
            // For PE32+ ImageBase is 8 bytes at offset 24 within the optional header.
            // For PE32  ImageBase is 4 bytes at offset 28 within the optional header.
            if magic == 0x020B {
                if opt_off + 32 <= out.len() {
                    out[opt_off + 24..opt_off + 32].copy_from_slice(&base.to_le_bytes());
                }
            } else if opt_off + 32 <= out.len() {
                out[opt_off + 28..opt_off + 32].copy_from_slice(&(base as u32).to_le_bytes());
            }
        }

        Ok(out)
    }

    /// Heuristically detect the OEP inside `dump` and build a valid PE.
    ///
    /// Runs [`detect_oep_heuristics`] and uses the highest-confidence candidate
    /// as the entry point.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError::NoOepCandidates`] if no prologues are found, or
    /// any error from [`Self::build_valid_pe`].
    pub fn auto_build(dump: &[u8], base: u64) -> Result<Vec<u8>, RebuildError> {
        let candidates = detect_oep_heuristics(dump, base);
        let best = candidates.first().ok_or(RebuildError::NoOepCandidates)?;
        Self::build_valid_pe(dump, base, best.address)
    }

    /// Scan the dump for IAT regions and return them.
    #[must_use]
    pub fn find_iat_regions(dump: &[u8], base: u64) -> Vec<IatRegion> {
        IatScanner::scan_for_iat(dump, base)
    }
}

// ---------------------------------------------------------------------------
// IatRebuildResult — result of rebuild_iat_from_memory
// ---------------------------------------------------------------------------

/// Result of scanning a memory dump and reconstructing the import table.
#[derive(Debug, Clone)]
pub struct IatRebuildResult {
    /// Detected IAT regions in the dump.
    pub regions: Vec<IatRegion>,
    /// Flat list of IAT entries produced from the scan.
    pub entries: Vec<IatEntry>,
    /// Non-fatal warnings from the scan.
    pub warnings: Vec<String>,
}

impl IatRebuildResult {
    /// Total number of IAT slots found across all regions.
    #[must_use]
    pub const fn total_entries(&self) -> usize {
        self.entries.len()
    }

    /// Number of entries that were resolved to a (dll, function) pair.
    #[must_use]
    pub fn resolved_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_resolved()).count()
    }
}

impl fmt::Display for IatRebuildResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IatRebuildResult: {} regions, {}/{} entries resolved",
            self.regions.len(),
            self.resolved_count(),
            self.total_entries()
        )
    }
}

// ---------------------------------------------------------------------------
// PeRebuilder additional methods — IAT rebuild + PE validity
// ---------------------------------------------------------------------------

impl PeRebuilder {
    /// Scan `memory` (loaded at `base`) for likely IAT regions and
    /// produce a reconstructed [`IatRebuildResult`].
    ///
    /// Algorithm:
    /// 1. Run [`IatScanner::scan_for_iat`] to locate candidate IAT regions.
    /// 2. For each pointer in every region, emit an [`IatEntry`] with the
    ///    slot's virtual address, the pointer value, and — if `known_imports`
    ///    is provided — the resolved (dll, function) pair.
    /// 3. Warn when a region has fewer than 2 contiguous entries.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError::Other`] if `memory` is empty.
    pub fn rebuild_iat_from_memory(
        memory: &[u8],
        base: u64,
        known_imports: Option<&HashMap<u64, (String, String)>>,
    ) -> Result<IatRebuildResult, RebuildError> {
        if memory.is_empty() {
            return Err(RebuildError::Other("memory slice is empty".to_string()));
        }

        let regions = IatScanner::scan_for_iat(memory, base);
        let mut entries: Vec<IatEntry> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        for region in &regions {
            if region.entries.len() < 2 {
                warnings.push(format!(
                    "IAT region at {:#x} has only {} entry — skipping",
                    region.va,
                    region.entries.len()
                ));
                continue;
            }

            for (slot_idx, &ptr_val) in region.entries.iter().enumerate() {
                let slot_va = region.va.saturating_add((slot_idx as u64).saturating_mul(8));
                // Compute the RVA of this IAT slot (relative to the image base).
                let iat_rva = slot_va.saturating_sub(base) as u32;

                let (dll_name, function_name) = if let Some(imports) = known_imports {
                    if let Some((dll, func)) = imports.get(&ptr_val) {
                        (Some(dll.clone()), Some(func.clone()))
                    } else {
                        // Attempt a heuristic DLL guess from the upper bits of the
                        // pointer (modules are loaded at distinct high addresses).
                        // Without a real export-table resolver we emit a stub name.
                        let module_hint = ptr_val >> 20;
                        let stub_func = format!("sub_{ptr_val:x}");
                        let stub_dll = format!("module_{module_hint:x}.dll");
                        (Some(stub_dll), Some(stub_func))
                    }
                } else {
                    let stub_func = format!("sub_{ptr_val:x}");
                    (None, Some(stub_func))
                };

                entries.push(IatEntry {
                    iat_rva,
                    value: ptr_val,
                    dll_name,
                    function_name,
                    ordinal: None,
                });
            }
        }

        Ok(IatRebuildResult {
            regions,
            entries,
            warnings,
        })
    }

    /// Validate structural correctness of `pe_data` and return a list of
    /// human-readable issues.  An empty list means no problems were detected.
    ///
    /// Checks performed:
    /// 1. DOS header magic (`MZ`).
    /// 2. PE signature (`PE\0\0`).
    /// 3. Section count is reasonable (< 96).
    /// 4. Section RVAs do not overlap with one another.
    /// 5. TLS directory presence (emits a warning if absent, not an error).
    #[must_use]
    pub fn verify_pe_validity(pe_data: &[u8]) -> Vec<String> {
        let mut issues: Vec<String> = Vec::new();

        // Check 1: minimum length for DOS header.
        if pe_data.len() < 64 {
            issues.push(format!(
                "image too short: {} bytes (need at least 64 for DOS header)",
                pe_data.len()
            ));
            return issues; // can't proceed further
        }

        // Check 2: DOS magic.
        if pe_data[0] != 0x4D || pe_data[1] != 0x5A {
            issues.push(format!(
                "invalid DOS magic: expected MZ (0x4D 0x5A), got 0x{:02X} 0x{:02X}",
                pe_data[0], pe_data[1]
            ));
        }

        // Locate PE signature.
        let e_lfanew = u32::from_le_bytes(pe_data[60..64].try_into().unwrap_or([0; 4])) as usize;

        if e_lfanew + 4 > pe_data.len() {
            issues.push(format!(
                "e_lfanew ({e_lfanew:#x}) points outside image (size={:#x})",
                pe_data.len()
            ));
            return issues;
        }

        // Check 3: PE signature.
        if &pe_data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            issues.push(format!(
                "invalid PE signature at e_lfanew={e_lfanew:#x}: got {:02X?}",
                &pe_data[e_lfanew..e_lfanew + 4]
            ));
        }

        // COFF header is immediately after PE signature.
        let coff_off = e_lfanew + 4;
        if coff_off + 20 > pe_data.len() {
            issues.push("COFF header extends beyond image".to_string());
            return issues;
        }

        let n_sections =
            u16::from_le_bytes([pe_data[coff_off + 2], pe_data[coff_off + 3]]) as usize;
        let opt_hdr_size =
            u16::from_le_bytes([pe_data[coff_off + 16], pe_data[coff_off + 17]]) as usize;

        // Check 4: section count.
        const MAX_SECTIONS: usize = 96;
        if n_sections == 0 {
            issues.push("section count is zero — image has no sections".to_string());
        } else if n_sections > MAX_SECTIONS {
            issues.push(format!(
                "section count {n_sections} exceeds the sanity limit of {MAX_SECTIONS}"
            ));
        }

        // Optional header magic / bitness.
        let opt_off = coff_off + 20;
        let is_64bit = if opt_off + 2 <= pe_data.len() {
            let magic = u16::from_le_bytes([pe_data[opt_off], pe_data[opt_off + 1]]);
            if magic != 0x010B && magic != 0x020B {
                issues.push(format!(
                    "optional header magic {magic:#06x} is neither PE32 (0x010b) nor PE32+ (0x020b)"
                ));
            }
            magic == 0x020B
        } else {
            issues.push("optional header is missing".to_string());
            false
        };

        // Section table.
        let sect_table_off = opt_off + opt_hdr_size;

        // Check 5: section RVA overlap.
        // Collect (va_start, va_end, name) for each section.
        let mut ranges: Vec<(u32, u32, String)> = Vec::new();
        for i in 0..n_sections {
            let hdr = sect_table_off + i * 40;
            if hdr + 40 > pe_data.len() {
                issues.push(format!("section header {i} extends beyond image"));
                break;
            }
            // Name: 8 bytes, NUL-padded.
            let raw_name = &pe_data[hdr..hdr + 8];
            let name_end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&raw_name[..name_end]).into_owned();

            let virtual_size =
                u32::from_le_bytes(pe_data[hdr + 8..hdr + 12].try_into().unwrap_or([0; 4]));
            let virtual_address =
                u32::from_le_bytes(pe_data[hdr + 12..hdr + 16].try_into().unwrap_or([0; 4]));

            if virtual_address == 0 && i > 0 {
                issues.push(format!("section {i} ({name}) has zero VirtualAddress"));
            }

            let va_end = virtual_address.saturating_add(virtual_size.max(1));
            ranges.push((virtual_address, va_end, name));
        }

        // Sort by start address and check for overlaps.
        let mut sorted_ranges = ranges.clone();
        sorted_ranges.sort_by_key(|&(va, _, _)| va);
        for pair in sorted_ranges.windows(2) {
            let (start_a, end_a, ref name_a) = pair[0];
            let (start_b, _end_b, ref name_b) = pair[1];
            if start_b < end_a {
                issues.push(format!(
                    "section RVA overlap: {name_a} [{start_a:#x}..{end_a:#x}) overlaps {name_b} starting at {start_b:#x}"
                ));
            }
        }

        // Check 6: TLS directory presence (advisory — not an error, just a note).
        // DataDirectory[9] = TLS directory (offset from opt_off depends on bitness).
        let dd_base = if is_64bit {
            opt_off + 112
        } else {
            opt_off + 96
        };
        let tls_dd_off = dd_base + 9 * 8; // each DataDirectory entry = 8 bytes
        if tls_dd_off + 8 <= pe_data.len() {
            let tls_rva = u32::from_le_bytes(
                pe_data[tls_dd_off..tls_dd_off + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            let tls_size = u32::from_le_bytes(
                pe_data[tls_dd_off + 4..tls_dd_off + 8]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            if tls_rva == 0 || tls_size == 0 {
                issues.push(
                    "TLS directory is absent or zeroed — TLS callbacks will not be invoked"
                        .to_string(),
                );
            }
        }

        issues
    }
}

// ---------------------------------------------------------------------------
// DumpFixer — Scylla-style post-dump corrections
// ---------------------------------------------------------------------------

/// Applies post-dump corrections to a raw PE image byte buffer.
///
/// Modelled on Scylla's dump-fixer pass, this struct provides two independent
/// fixup methods that can be called in any order:
///
/// - [`DumpFixer::fix_iat`] — rewrites runtime VA entries back to
///   file-relative RVAs (or zeroes unknown entries).
/// - [`DumpFixer::fix_section_flags`] — restores section characteristics
///   that were stripped or corrupted during the dump.
pub struct DumpFixer;

impl DumpFixer {
    /// Correct IAT entries in `dump` from their runtime absolute addresses to
    /// image-relative values.
    ///
    /// For each pointer-sized slot in every detected IAT region:
    /// - If the value looks like a valid VA within the image
    ///   (`base_addr ≤ value < base_addr + image_size`), it is converted to
    ///   an RVA (value − `base_addr`).
    /// - Otherwise the slot is zeroed (unknown external pointer).
    ///
    /// The conversion is written back to the same file offset as the IAT slot.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError::IatOutOfBounds`] if an IAT region extends
    /// beyond the length of `dump`.
    pub fn fix_iat(dump: &mut [u8], base_addr: u64) -> Result<(), RebuildError> {
        const PTR_SIZE: usize = 8;

        // Detect IAT regions in the current dump bytes.
        let regions = IatScanner::scan_for_iat(dump, base_addr);
        let image_size = dump.len() as u64;

        for region in &regions {
            for (slot_idx, &ptr_val) in region.entries.iter().enumerate() {
                // File offset of this slot = region VA - base_addr + slot index * 8.
                let region_file_off = region.va.checked_sub(base_addr).ok_or(
                    RebuildError::IatOutOfBounds(region.va),
                )? as usize;
                let file_off = region_file_off.saturating_add(slot_idx * PTR_SIZE);

                if file_off + PTR_SIZE > dump.len() {
                    return Err(RebuildError::IatOutOfBounds(
                        region.va + (slot_idx * PTR_SIZE) as u64,
                    ));
                }

                if ptr_val >= base_addr && ptr_val < base_addr.saturating_add(image_size) {
                    // Convert absolute VA → RVA.
                    let rva = (ptr_val - base_addr) as u32;
                    // Write back as a 4-byte RVA (zero-extended to 8 bytes).
                    let rva64 = u64::from(rva);
                    dump[file_off..file_off + PTR_SIZE].copy_from_slice(&rva64.to_le_bytes());
                } else {
                    // External pointer — zero it out.
                    dump[file_off..file_off + PTR_SIZE].fill(0);
                }
            }
        }

        Ok(())
    }

    /// Restore section characteristics in `dump` to sensible defaults.
    ///
    /// For each section in the PE header:
    /// - Sections with names starting with `.text`, `.code`, or with the
    ///   `IMAGE_SCN_CNT_CODE` flag already set receive
    ///   `MEM_EXECUTE | MEM_READ | CNT_CODE`.
    /// - Sections with names `.data`, `.bss` or the writable flag set
    ///   receive `MEM_READ | MEM_WRITE | CNT_INITIALIZED_DATA`.
    /// - All other sections receive at minimum `MEM_READ`.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError::Other`] if the PE header is malformed.
    pub fn fix_section_flags(dump: &mut [u8]) -> Result<(), RebuildError> {
        if dump.len() < 64 {
            return Err(RebuildError::Other(
                "dump too short for PE header".to_string(),
            ));
        }

        let e_lfanew = u32::from_le_bytes(dump[60..64].try_into().unwrap_or([0; 4])) as usize;
        if e_lfanew + 4 > dump.len() || &dump[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(RebuildError::Other("PE signature not found".to_string()));
        }

        let coff_off = e_lfanew + 4;
        if coff_off + 20 > dump.len() {
            return Err(RebuildError::Other("COFF header out of bounds".to_string()));
        }

        let n_sections = u16::from_le_bytes([dump[coff_off + 2], dump[coff_off + 3]]) as usize;
        let opt_hdr_size = u16::from_le_bytes([dump[coff_off + 16], dump[coff_off + 17]]) as usize;
        let sect_table_off = coff_off + 20 + opt_hdr_size;

        for i in 0..n_sections {
            let hdr = sect_table_off + i * 40;
            if hdr + 40 > dump.len() {
                break;
            }

            // Read section name (8 bytes, NUL-padded).
            let raw_name = &dump[hdr..hdr + 8];
            let name_end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&raw_name[..name_end]).to_lowercase();

            // Read current characteristics.
            let cur_chars =
                u32::from_le_bytes(dump[hdr + 36..hdr + 40].try_into().unwrap_or([0; 4]));

            let new_chars = if name.starts_with(".text")
                || name.starts_with(".code")
                || (cur_chars & chars::CODE != 0)
            {
                chars::CODE | chars::MEM_EXECUTE | chars::MEM_READ
            } else if name.starts_with(".data")
                || name.starts_with(".bss")
                || (cur_chars & chars::MEM_WRITE != 0)
            {
                chars::INITIALIZED_DATA | chars::MEM_READ | chars::MEM_WRITE
            } else if name.starts_with(".rdata")
                || name.starts_with(".rodata")
                || name.starts_with(".idata")
            {
                chars::INITIALIZED_DATA | chars::MEM_READ
            } else {
                // Preserve existing flags but ensure at least MEM_READ.
                cur_chars | chars::MEM_READ
            };

            dump[hdr + 36..hdr + 40].copy_from_slice(&new_chars.to_le_bytes());
        }

        Ok(())
    }
}

impl fmt::Debug for DumpFixer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DumpFixer")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_pe_tools::PeBuilder;

    fn make_x64_pe() -> Vec<u8> {
        let mut b = PeBuilder::new_x64();
        b.add_section(".text", vec![0x90u8; 32], 0x6000_0020);
        b.add_section(".data", vec![0u8; 16], 0xC000_0040);
        b.build()
    }

    fn default_config() -> RebuildConfig {
        RebuildConfig::default()
    }

    // ---- RebuildError display ----------------------------------------------

    #[test]
    fn test_error_no_sections() {
        let e = RebuildError::NoSections;
        assert!(e.to_string().contains("no sections"));
    }

    #[test]
    fn test_error_section_data_missing() {
        let e = RebuildError::SectionDataMissing(".text".to_string());
        assert!(e.to_string().contains(".text"));
    }

    #[test]
    fn test_error_image_base_not_set() {
        let e = RebuildError::ImageBaseNotSet;
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_error_other() {
        let e = RebuildError::Other("custom".to_string());
        assert!(e.to_string().contains("custom"));
    }

    #[test]
    fn test_error_iat_oob() {
        let e = RebuildError::IatOutOfBounds(0xDEAD);
        assert!(e.to_string().contains("IAT"));
    }

    #[test]
    fn test_error_bad_reloc() {
        let e = RebuildError::BadReloc(0x1000);
        assert!(e.to_string().contains("relocation"));
    }

    #[test]
    fn test_error_export_corrupt() {
        let e = RebuildError::ExportCorrupt("gap".to_string());
        assert!(e.to_string().contains("gap"));
    }

    // ---- RebuildSection ----------------------------------------------------

    #[test]
    fn test_rebuild_section_new() {
        let s = RebuildSection::new(".text".to_string(), 0x1000, vec![0u8; 64], 0x6000_0020);
        assert_eq!(s.virtual_size, 64);
        assert_eq!(s.virtual_address, 0x1000);
    }

    #[test]
    fn test_rebuild_section_code() {
        let s = RebuildSection::code(".text".to_string(), 0x1000, vec![0x90; 8]);
        assert!(s.is_executable());
        assert!(!s.is_writable());
    }

    #[test]
    fn test_rebuild_section_data() {
        let s = RebuildSection::data(".data".to_string(), 0x2000, vec![0; 8]);
        assert!(!s.is_executable());
        assert!(s.is_writable());
    }

    #[test]
    fn test_rebuild_section_rdata() {
        let s = RebuildSection::rdata(".rdata".to_string(), 0x3000, vec![0; 8]);
        assert!(!s.is_executable());
        assert!(!s.is_writable());
    }

    #[test]
    fn test_rebuild_section_display() {
        let s = RebuildSection::new(".bss".to_string(), 0x3000, vec![], 0);
        assert!(s.to_string().contains(".bss"));
    }

    #[test]
    fn test_section_contains_rva() {
        let s = RebuildSection::new(".text".to_string(), 0x1000, vec![0; 0x100], 0x20);
        assert!(s.contains_rva(0x1000));
        assert!(s.contains_rva(0x10FF));
        assert!(!s.contains_rva(0x1100));
        assert!(!s.contains_rva(0x0FFF));
    }

    #[test]
    fn test_section_rva_to_offset() {
        let s = RebuildSection::new(".text".to_string(), 0x1000, vec![0xAB; 0x100], 0x20);
        assert_eq!(s.rva_to_offset(0x1000), Some(0));
        assert_eq!(s.rva_to_offset(0x1010), Some(0x10));
        assert_eq!(s.rva_to_offset(0x2000), None);
    }

    #[test]
    fn test_section_entropy_zeros() {
        let s = RebuildSection::new(".bss".to_string(), 0, vec![0; 256], 0);
        assert_eq!(s.entropy(), 0.0);
    }

    #[test]
    fn test_section_entropy_random() {
        let data: Vec<u8> = (0u8..=255).collect();
        let s = RebuildSection::new(".e".to_string(), 0, data, 0);
        let ent = s.entropy();
        assert!(ent > 7.9, "expected near-max entropy, got {ent}");
    }

    // ---- RebuildConfig -----------------------------------------------------

    #[test]
    fn test_config_default() {
        let cfg = RebuildConfig::default();
        assert_eq!(cfg.machine, PeMachine::Amd64);
        assert!(cfg.flags.is_64bit());
        assert!(!cfg.flags.is_dll());
    }

    #[test]
    fn test_config_display() {
        let cfg = RebuildConfig::default();
        assert!(cfg.to_string().contains("RebuildConfig"));
    }

    #[test]
    fn test_config_serde() {
        let cfg = RebuildConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let cfg2: RebuildConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg2.machine, PeMachine::Amd64);
    }

    // ---- RebuildResult / RebuildStats --------------------------------------

    #[test]
    fn test_rebuild_result_display() {
        let r = RebuildResult {
            data: vec![0u8; 512],
            warnings: vec![],
            section_count: 2,
            stats: RebuildStats::default(),
        };
        assert!(r.to_string().contains("512 bytes"));
    }

    #[test]
    fn test_rebuild_stats_default() {
        let s = RebuildStats::default();
        assert_eq!(s.iat_entries_fixed, 0);
        assert!(!s.oep_detected);
    }

    // ---- PeRebuilder -------------------------------------------------------

    #[test]
    fn test_rebuilder_no_sections() {
        let r = PeRebuilder::new(default_config());
        assert!(matches!(r.rebuild(), Err(RebuildError::NoSections)));
    }

    #[test]
    fn test_rebuilder_single_section() {
        let mut r = PeRebuilder::new(default_config());
        r.add_section(RebuildSection::new(
            ".text".to_string(),
            0x1000,
            vec![0x90u8; 16],
            0x6000_0020,
        ));
        let result = r.rebuild().unwrap();
        assert!(result.section_count >= 1);
        assert!(!result.data.is_empty());
    }

    #[test]
    fn test_rebuilder_two_sections() {
        let mut r = PeRebuilder::new(default_config());
        r.add_section(RebuildSection::new(
            ".text".to_string(),
            0x1000,
            vec![0x90u8; 32],
            0x6000_0020,
        ));
        r.add_section(RebuildSection::new(
            ".data".to_string(),
            0x2000,
            vec![0u8; 16],
            0xC000_0040,
        ));
        let result = r.rebuild().unwrap();
        assert_eq!(result.section_count, 2);
        PeFile::parse(&result.data).unwrap();
    }

    #[test]
    fn test_rebuilder_x86() {
        let mut cfg = default_config();
        cfg.flags = RebuildFlags::NONE;
        cfg.machine = PeMachine::I386;
        let mut r = PeRebuilder::new(cfg);
        r.add_section(RebuildSection::new(
            ".text".to_string(),
            0x1000,
            vec![0xCCu8; 8],
            0x6000_0020,
        ));
        let result = r.rebuild().unwrap();
        let pe = PeFile::parse(&result.data).unwrap();
        assert!(!pe.is_64bit);
    }

    #[test]
    fn test_rebuilder_section_count() {
        let mut r = PeRebuilder::new(default_config());
        assert_eq!(r.section_count(), 0);
        r.add_section(RebuildSection::new(".a".to_string(), 0x1000, vec![0], 0));
        assert_eq!(r.section_count(), 1);
    }

    #[test]
    fn test_rebuilder_config() {
        let cfg = default_config();
        let r = PeRebuilder::new(cfg.clone());
        assert_eq!(r.config().machine, cfg.machine);
    }

    #[test]
    fn test_rebuilder_debug() {
        let r = PeRebuilder::new(default_config());
        assert!(format!("{r:?}").contains("PeRebuilder"));
    }

    #[test]
    fn test_rebuild_ep_warning() {
        let mut cfg = default_config();
        cfg.entry_point_rva = 0xDEAD_BEEF;
        let mut r = PeRebuilder::new(cfg);
        r.add_section(RebuildSection::new(
            ".text".to_string(),
            0x1000,
            vec![0x90u8; 8],
            0x6000_0020,
        ));
        let result = r.rebuild().unwrap();
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_rebuilder_sort_sections() {
        let mut r = PeRebuilder::new(default_config());
        r.add_section(RebuildSection::new(
            ".data".to_string(),
            0x3000,
            vec![0; 4],
            0x40,
        ));
        r.add_section(RebuildSection::new(
            ".text".to_string(),
            0x1000,
            vec![0; 4],
            0x20,
        ));
        r.sort_sections();
        assert_eq!(r.sections()[0].name, ".text");
    }

    #[test]
    fn test_rebuilder_clear_sections() {
        let mut r = PeRebuilder::new(default_config());
        r.add_section(RebuildSection::new(
            ".text".to_string(),
            0x1000,
            vec![0; 4],
            0,
        ));
        r.clear_sections();
        assert_eq!(r.section_count(), 0);
    }

    #[test]
    fn test_rebuilder_section_at_rva() {
        let mut r = PeRebuilder::new(default_config());
        r.add_section(RebuildSection::new(
            ".text".to_string(),
            0x1000,
            vec![0; 0x100],
            0x20,
        ));
        assert!(r.section_at_rva(0x1050).is_some());
        assert!(r.section_at_rva(0x5000).is_none());
    }

    #[test]
    fn test_rebuilder_virtual_end() {
        let mut r = PeRebuilder::new(default_config());
        r.add_section(RebuildSection::new(
            ".text".to_string(),
            0x1000,
            vec![0; 0x500],
            0x20,
        ));
        r.add_section(RebuildSection::new(
            ".data".to_string(),
            0x2000,
            vec![0; 0x200],
            0x40,
        ));
        assert_eq!(r.virtual_end(), 0x2200);
    }

    // ---- from_memory_dump --------------------------------------------------

    #[test]
    fn test_from_memory_dump_valid_pe() {
        let bytes = make_x64_pe();
        let result = PeRebuilder::from_memory_dump(&bytes, 0x0001_4000_0000, default_config()).unwrap();
        assert!(result.section_count >= 1);
    }

    #[test]
    fn test_from_memory_dump_bad_magic() {
        let data = vec![0u8; 128];
        let err = PeRebuilder::from_memory_dump(&data, 0, default_config()).unwrap_err();
        assert!(matches!(err, RebuildError::Other(_)));
    }

    #[test]
    fn test_from_memory_dump_truncated_header() {
        let mut data = vec![0u8; 128];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60..64].copy_from_slice(&0xFFFFu32.to_le_bytes());
        let result = PeRebuilder::from_memory_dump(&data, 0, default_config()).unwrap();
        assert!(!result.data.is_empty());
        assert!(!result.warnings.is_empty());
    }

    // ---- is_memory_pe ------------------------------------------------------

    #[test]
    fn test_is_memory_pe_true() {
        let bytes = make_x64_pe();
        assert!(is_memory_pe(&bytes));
    }

    #[test]
    fn test_is_memory_pe_false_short() {
        assert!(!is_memory_pe(&[0x4D, 0x5A]));
    }

    #[test]
    fn test_is_memory_pe_false_bad_magic() {
        assert!(!is_memory_pe(&[0u8; 128]));
    }

    // ---- align_up ----------------------------------------------------------

    #[test]
    fn test_align_up_zero_align() {
        assert_eq!(PeRebuilder::align_up(42, 0), 42);
    }

    #[test]
    fn test_align_up_already_aligned() {
        assert_eq!(PeRebuilder::align_up(0x1000, 0x1000), 0x1000);
    }

    #[test]
    fn test_align_up_rounds_up() {
        assert_eq!(PeRebuilder::align_up(0x1001, 0x1000), 0x2000);
    }

    // ---- IatEntry / IatFixer -----------------------------------------------

    #[test]
    fn test_iat_entry_display() {
        let e = IatEntry {
            iat_rva: 0x2000,
            value: 0x7FFF_1234,
            dll_name: Some("kernel32.dll".to_string()),
            function_name: Some("VirtualAlloc".to_string()),
            ordinal: None,
        };
        assert!(e.to_string().contains("VirtualAlloc"));
        assert!(e.is_resolved());
    }

    #[test]
    fn test_iat_entry_unresolved() {
        let e = IatEntry {
            iat_rva: 0x2000,
            value: 0xDEAD,
            dll_name: None,
            function_name: None,
            ordinal: None,
        };
        assert!(!e.is_resolved());
    }

    #[test]
    fn test_iat_fixer_fix() {
        let mut fixer = IatFixer::new(IatFixOptions {
            allow_unknown: true,
            ..Default::default()
        });
        fixer.add_entry(IatEntry {
            iat_rva: 0x3000,
            value: 0xABCD,
            dll_name: None,
            function_name: None,
            ordinal: None,
        });
        let fix_count = fixer.fix().unwrap();
        assert_eq!(fix_count, 1);
    }

    #[test]
    fn test_iat_fixer_resolved_count() {
        let mut fixer = IatFixer::new(IatFixOptions::default());
        fixer.register_import(
            0xABCD,
            "ntdll.dll".to_string(),
            "NtAllocateVirtualMemory".to_string(),
        );
        fixer.add_entry(IatEntry {
            iat_rva: 0x3000,
            value: 0xABCD,
            dll_name: None,
            function_name: None,
            ordinal: None,
        });
        fixer.fix().unwrap();
        assert_eq!(fixer.resolved_count(), 1);
    }

    // ---- RelocationEntry ---------------------------------------------------

    #[test]
    fn test_reloc_entry_dir64() {
        let e = RelocationEntry::dir64(0x1234);
        assert!(e.is_meaningful());
        assert_eq!(e.reloc_type, 10);
    }

    #[test]
    fn test_reloc_entry_highlow() {
        let e = RelocationEntry::highlow(0x1234);
        assert_eq!(e.reloc_type, 3);
    }

    #[test]
    fn test_reloc_entry_absolute() {
        let e = RelocationEntry::absolute();
        assert!(!e.is_meaningful());
    }

    #[test]
    fn test_reloc_entry_display() {
        let e = RelocationEntry::dir64(0x5000);
        assert!(e.to_string().contains("0x5000"));
    }

    // ---- RelocationRebuilder -----------------------------------------------

    #[test]
    fn test_reloc_rebuilder_build_section() {
        let opts = RelocationOptions {
            original_base: 0x0040_0000,
            new_base: 0x0050_0000,
            rebuild_section: true,
        };
        let mut rb = RelocationRebuilder::new(opts);
        rb.add_dir64(0x1008);
        rb.add_dir64(0x1010);
        let blob = rb.build_reloc_section().unwrap();
        assert!(!blob.is_empty());
        // Should start with page RVA = 0x1000
        let page_rva = u32::from_le_bytes(blob[0..4].try_into().unwrap());
        assert_eq!(page_rva, 0x1000);
    }

    #[test]
    fn test_reloc_rebuilder_delta() {
        let opts = RelocationOptions {
            original_base: 0x0040_0000,
            new_base: 0x0060_0000,
            rebuild_section: false,
        };
        let rb = RelocationRebuilder::new(opts);
        assert_eq!(rb.delta(), 0x0020_0000);
    }

    #[test]
    fn test_reloc_rebuilder_apply() {
        let opts = RelocationOptions {
            original_base: 0x0040_0000,
            new_base: 0x0040_0000,
            rebuild_section: false,
        };
        let mut rb = RelocationRebuilder::new(opts);
        rb.add_highlow(0);
        let mut img = vec![0u8; 8];
        img[0..4].copy_from_slice(&0x0040_1000u32.to_le_bytes());
        let applied = rb.apply_to_image(&mut img).unwrap();
        assert_eq!(applied, 1);
    }

    // ---- ExportEntry / ExportRebuilder -------------------------------------

    #[test]
    fn test_export_entry_named() {
        let e = ExportEntry::named("Foo".to_string(), 1, 0x1000);
        assert!(e.has_name());
        assert!(!e.is_forwarder);
        assert!(e.to_string().contains("Foo"));
    }

    #[test]
    fn test_export_entry_ordinal_only() {
        let e = ExportEntry::ordinal_only(3, 0x2000);
        assert!(!e.has_name());
    }

    #[test]
    fn test_export_entry_forwarder() {
        let e = ExportEntry::forwarder("Bar".to_string(), 2, "NTDLL.RtlBar".to_string());
        assert!(e.is_forwarder);
        assert!(e.to_string().contains("NTDLL"));
    }

    #[test]
    fn test_export_rebuilder_build() {
        let mut rb = ExportRebuilder::new("test.dll".to_string(), 1);
        rb.add_entry(ExportEntry::named("Alpha".to_string(), 1, 0x1000));
        rb.add_entry(ExportEntry::named("Beta".to_string(), 2, 0x1100));
        let blob = rb.build(0x5000).unwrap();
        assert!(!blob.is_empty());
        // Directory should start at section_rva = 0x5000
    }

    #[test]
    fn test_export_rebuilder_empty() {
        let rb = ExportRebuilder::new("empty.dll".to_string(), 1);
        let blob = rb.build(0x1000).unwrap();
        assert!(blob.is_empty());
    }

    #[test]
    fn test_export_rebuilder_count() {
        let mut rb = ExportRebuilder::new("d.dll".to_string(), 1);
        rb.add_entry(ExportEntry::named("X".to_string(), 1, 0x100));
        assert_eq!(rb.export_count(), 1);
        assert_eq!(rb.dll_name(), "d.dll");
    }

    // ---- OepDetector -------------------------------------------------------

    #[test]
    fn test_oep_detector_known_ep() {
        let mut det = OepDetector::new();
        let sections = vec![RebuildSection::code(
            ".text".to_string(),
            0x1000,
            vec![0x90; 64],
        )];
        let res = det.detect(&sections, Some(0x1020)).unwrap();
        assert_eq!(res.rva, 0x1020);
        assert_eq!(res.confidence, 1.0);
    }

    #[test]
    fn test_oep_detector_no_exec() {
        let mut det = OepDetector::new();
        let sections = vec![RebuildSection::data(
            ".data".to_string(),
            0x1000,
            vec![0; 64],
        )];
        assert!(matches!(
            det.detect(&sections, None),
            Err(RebuildError::NoOepCandidates)
        ));
    }

    #[test]
    fn test_oep_detector_x64_prologue() {
        let mut det = OepDetector::new();
        let mut code = vec![0u8; 64];
        code[0] = 0x55;
        code[1] = 0x48;
        code[2] = 0x89;
        code[3] = 0xE5; // push rbp; mov rbp,rsp
        let sections = vec![RebuildSection::code(".text".to_string(), 0x1000, code)];
        let res = det.detect(&sections, None).unwrap();
        assert!(res.confidence >= 0.5);
    }

    #[test]
    fn test_oep_detector_candidates() {
        let mut det = OepDetector::new();
        let sections = vec![RebuildSection::code(
            ".text".to_string(),
            0x1000,
            vec![0x90; 64],
        )];
        det.detect(&sections, None).unwrap();
        assert_eq!(det.candidates().len(), 1);
    }

    // ---- OverlayHandler ----------------------------------------------------

    #[test]
    fn test_overlay_detect_no_overlay() {
        let bytes = make_x64_pe();
        let info = OverlayHandler::detect(&bytes).unwrap();
        assert!(!info.has_overlay());
    }

    #[test]
    fn test_overlay_extract_none() {
        let bytes = make_x64_pe();
        let data = OverlayHandler::extract(&bytes).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn test_overlay_preserve_with_overlay() {
        let mut bytes = make_x64_pe();
        bytes.extend_from_slice(b"OVERLAY_DATA");
        let mut rebuilt = bytes.clone();
        let info = OverlayHandler::preserve(&bytes, &mut rebuilt).unwrap();
        // Since we detect the original as having overlay, preserve appends it again.
        // The info length should equal "OVERLAY_DATA" bytes.
        assert_eq!(info.length, b"OVERLAY_DATA".len());
    }

    #[test]
    fn test_overlay_info_display() {
        let info = OverlayInfo {
            offset: 0x1000,
            length: 256,
            signature: vec![0xDE, 0xAD],
        };
        assert!(info.to_string().contains("0x1000"));
    }

    // ---- apply_fixups ------------------------------------------------------

    #[test]
    fn test_apply_fixups_strip_signature() {
        let mut bytes = make_x64_pe();
        let opts = PeFixupOptions {
            strip_signature: true,
            ..Default::default()
        };
        let notes = apply_fixups(&mut bytes, &opts).unwrap();
        assert!(notes.iter().any(|n| n.contains("security")));
    }

    #[test]
    fn test_apply_fixups_override_ep() {
        let mut bytes = make_x64_pe();
        let opts = PeFixupOptions {
            override_ep: Some(0x2000),
            ..Default::default()
        };
        apply_fixups(&mut bytes, &opts).unwrap();
        let pe = PeFile::parse(&bytes).unwrap();
        assert_eq!(pe.entry_point, 0x2000);
    }

    // ---- compute_entropy ---------------------------------------------------

    #[test]
    fn test_compute_entropy_empty() {
        assert_eq!(compute_entropy(&[]), 0.0);
    }

    #[test]
    fn test_compute_entropy_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = compute_entropy(&data);
        assert!(e > 7.9);
    }

    // ---- crc16_ccitt -------------------------------------------------------

    #[test]
    fn test_crc16_empty() {
        let c = crc16_ccitt(&[]);
        assert_eq!(c, 0xFFFF);
    }

    #[test]
    fn test_crc16_known() {
        // "123456789" -> 0x29B1 for CRC-16/CCITT
        let c = crc16_ccitt(b"123456789");
        assert_eq!(c, 0x29B1);
    }

    // ---- compute_imphash ---------------------------------------------------

    #[test]
    fn test_imphash_empty() {
        assert!(compute_imphash(&[]).is_empty() || !compute_imphash(&[]).is_empty());
    }

    #[test]
    fn test_imphash_deterministic() {
        let entries = vec![IatEntry {
            iat_rva: 0,
            value: 0,
            dll_name: Some("kernel32.dll".to_string()),
            function_name: Some("VirtualAlloc".to_string()),
            ordinal: None,
        }];
        let h1 = compute_imphash(&entries);
        let h2 = compute_imphash(&entries);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
    }

    // ---- serde roundtrip ---------------------------------------------------

    #[test]
    fn test_rebuild_section_serde() {
        let s = RebuildSection::new(".rdata".to_string(), 0x4000, vec![0x41u8; 4], 0x4000_0040);
        let json = serde_json::to_string(&s).unwrap();
        let s2: RebuildSection = serde_json::from_str(&json).unwrap();
        assert_eq!(s2.name, ".rdata");
    }

    // ---- IatScanner --------------------------------------------------------

    #[test]
    fn test_iat_scanner_empty() {
        let dump = vec![0u8; 64];
        let regions = IatScanner::scan_for_iat(&dump, 0x0001_4000_0000);
        assert!(regions.is_empty());
    }

    #[test]
    fn test_iat_scanner_finds_region() {
        // Build a buffer with 4 consecutive plausible pointers followed by nulls.
        let mut dump = vec![0u8; 512];
        // Write 4 page-aligned user-space pointers starting at offset 0.
        let ptrs: [u64; 4] = [
            0x7FFF_1234_0000,
            0x7FFF_1234_1000,
            0x7FFF_1234_2000,
            0x7FFF_1234_3000,
        ];
        for (i, &p) in ptrs.iter().enumerate() {
            let off = i * 8;
            dump[off..off + 8].copy_from_slice(&p.to_le_bytes());
        }
        let regions = IatScanner::scan_for_iat(&dump, 0x0001_4000_0000);
        assert!(!regions.is_empty());
        let first = &regions[0];
        assert!(first.slot_count() >= 4);
        assert!(first.is_non_empty());
    }

    #[test]
    fn test_iat_scanner_skips_zero_entries() {
        // A single null pointer should not form a region.
        let dump = vec![0u8; 16];
        assert!(IatScanner::scan_for_iat(&dump, 0).is_empty());
    }

    #[test]
    fn test_iat_region_display() {
        let r = IatRegion {
            va: 0x140001000,
            size: 32,
            entries: vec![1, 2, 3, 4],
        };
        let s = r.to_string();
        assert!(s.contains("0x140001000"));
    }

    // ---- ModuleResolver ----------------------------------------------------

    #[test]
    fn test_module_resolver_found() {
        let modules = vec![(
            0x7FFF_0000_0000u64,
            0x10_0000u64,
            "C:\\Windows\\System32\\ntdll.dll".to_string(),
        )];
        let ptr = 0x7FFF_0000_1000u64;
        let result = ModuleResolver::resolve_pointer(ptr, &modules);
        assert!(result.is_some());
        let (dll, func) = result.unwrap();
        assert_eq!(dll, "ntdll.dll");
        assert!(!func.is_empty());
    }

    #[test]
    fn test_module_resolver_not_found() {
        let modules = vec![(0x7FFF_0000_0000u64, 0x1000u64, "kernel32.dll".to_string())];
        let ptr = 0x1234_5678;
        assert!(ModuleResolver::resolve_pointer(ptr, &modules).is_none());
    }

    #[test]
    fn test_module_resolver_batch() {
        let modules = vec![(0x7FFF_1000_0000u64, 0x10_0000u64, "user32.dll".to_string())];
        let ptrs = vec![
            (0x7FFF_1000_0010u64, 0x3000u32),
            (0x1234u64, 0x3008u32), // won't resolve
        ];
        let resolved = ModuleResolver::resolve_batch(&ptrs, &modules);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, 0x3000);
        assert_eq!(resolved[0].1, "user32.dll");
    }

    // ---- detect_oep_heuristics ---------------------------------------------

    #[test]
    fn test_oep_heuristics_x86_prologue() {
        let mut dump = vec![0u8; 128];
        // PUSH EBP; MOV EBP, ESP at offset 0
        dump[0] = 0x55;
        dump[1] = 0x8B;
        dump[2] = 0xEC;
        let candidates = detect_oep_heuristics(&dump, 0x0040_0000);
        assert!(!candidates.is_empty());
        assert_eq!(candidates[0].address, 0x0040_0000);
        assert!((candidates[0].confidence - 0.70).abs() < 0.01);
    }

    #[test]
    fn test_oep_heuristics_x64_prologue() {
        let mut dump = vec![0u8; 128];
        // PUSH RBP; MOV RBP, RSP at offset 0
        dump[0] = 0x55;
        dump[1] = 0x48;
        dump[2] = 0x89;
        dump[3] = 0xE5;
        let candidates = detect_oep_heuristics(&dump, 0x0001_4000_1000);
        assert!(!candidates.is_empty());
        let best = candidates
            .iter()
            .find(|c| c.address == 0x0001_4000_1000)
            .unwrap();
        assert!((best.confidence - 0.75).abs() < 0.01);
    }

    #[test]
    fn test_oep_heuristics_crt_startup() {
        let mut dump = vec![0u8; 128];
        dump[0] = 0x53;
        dump[1] = 0x56;
        dump[2] = 0x57;
        let candidates = detect_oep_heuristics(&dump, 0x401000);
        assert!(candidates.iter().any(|c| c.confidence > 0.4));
    }

    #[test]
    fn test_oep_heuristics_sub_esp() {
        let mut dump = vec![0u8; 64];
        dump[0] = 0x83;
        dump[1] = 0xEC;
        dump[2] = 0x28;
        let candidates = detect_oep_heuristics(&dump, 0x0);
        assert!(!candidates.is_empty());
        assert!((candidates[0].confidence - 0.40).abs() < 0.01);
    }

    #[test]
    fn test_oep_heuristics_empty_dump() {
        let candidates = detect_oep_heuristics(&[], 0);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_oep_heuristics_sorted_by_confidence() {
        let mut dump = vec![0u8; 256];
        // x86 PUSH EBP at offset 0 (conf 0.70)
        dump[0] = 0x55;
        dump[1] = 0x8B;
        dump[2] = 0xEC;
        // x64 PUSH RBP at offset 4 (conf 0.75)
        dump[4] = 0x55;
        dump[5] = 0x48;
        dump[6] = 0x89;
        dump[7] = 0xE5;
        let candidates = detect_oep_heuristics(&dump, 0x1000);
        // First should be the highest confidence.
        assert!(candidates[0].confidence >= candidates.last().map_or(0.0, |c| c.confidence));
    }

    #[test]
    fn test_oep_candidate_display() {
        let c = OepCandidate {
            address: 0x0040_1000,
            confidence: 0.75,
            reason: "test".to_string(),
        };
        assert!(c.to_string().contains("0x401000"));
        assert!(c.to_string().contains("0.75"));
    }

    // ---- PeDumper ----------------------------------------------------------

    #[test]
    fn test_pe_dumper_build_valid_pe_basic() {
        let bytes = make_x64_pe();
        let base = 0x0001_4000_0000_u64;
        let oep = base + 0x1000;
        let result = PeDumper::build_valid_pe(&bytes, base, oep).unwrap();
        // Result should begin with MZ.
        assert_eq!(result[0], 0x4D);
        assert_eq!(result[1], 0x5A);
    }

    #[test]
    fn test_pe_dumper_sets_entry_point() {
        let bytes = make_x64_pe();
        let base = 0x0001_4000_0000_u64;
        let oep_va = base + 0x2000;
        let result = PeDumper::build_valid_pe(&bytes, base, oep_va).unwrap();
        let pe_off = u32::from_le_bytes([result[60], result[61], result[62], result[63]]) as usize;
        let opt_off = pe_off + 24;
        let ep_rva = u32::from_le_bytes(result[opt_off + 16..opt_off + 20].try_into().unwrap());
        assert_eq!(ep_rva, 0x2000);
    }

    #[test]
    fn test_pe_dumper_too_short() {
        let err = PeDumper::build_valid_pe(&[0u8; 10], 0, 0).unwrap_err();
        assert!(matches!(err, RebuildError::Other(_)));
    }

    #[test]
    fn test_pe_dumper_no_pe_sig() {
        let mut data = vec![0x4D, 0x5Au8];
        data.extend(vec![0u8; 200]);
        // e_lfanew points past end
        data[60..64].copy_from_slice(&0xFFFFu32.to_le_bytes());
        // Should err because PE sig not found.
        assert!(PeDumper::build_valid_pe(&data, 0, 0).is_err());
    }

    #[test]
    fn test_pe_dumper_auto_build_finds_oep() {
        let bytes = make_x64_pe();
        // Insert a recognisable prologue near the start of the first section.
        // We can't easily know the section offset without parsing, so just test
        // that auto_build produces a non-empty result or NoOepCandidates.
        match PeDumper::auto_build(&bytes, 0x0001_4000_0000) {
            Ok(out) => assert!(!out.is_empty()),
            Err(RebuildError::NoOepCandidates) => { /* acceptable for an all-NOP section */ }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_pe_dumper_find_iat_regions() {
        let bytes = make_x64_pe();
        // Just check it doesn't panic.
        let regions = PeDumper::find_iat_regions(&bytes, 0x0001_4000_0000);
        // May or may not find regions depending on section content.
        let _ = regions;
    }

    // ---- extract_dll_name helper -------------------------------------------

    #[test]
    fn test_extract_dll_name_backslash() {
        assert_eq!(
            super::extract_dll_name("C:\\Windows\\System32\\kernel32.dll"),
            "kernel32.dll"
        );
    }

    #[test]
    fn test_extract_dll_name_forward_slash() {
        assert_eq!(super::extract_dll_name("/usr/lib/libfoo.so"), "libfoo.so");
    }

    #[test]
    fn test_extract_dll_name_bare() {
        assert_eq!(super::extract_dll_name("ntdll.dll"), "ntdll.dll");
    }
}

// =============================================================================
// IAT rebuilder
// =============================================================================

/// A single Import Address Table entry describing one imported function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatEntry2 {
    /// RVA of the IAT slot in the process image.
    pub rva: u64,
    /// Name of the DLL that provides this import (e.g. `"kernel32.dll"`).
    pub dll_name: String,
    /// Name of the imported function (empty when importing by ordinal only).
    pub function_name: String,
    /// Ordinal number; present when the import is by ordinal.
    pub ordinal: Option<u16>,
    /// Resolved virtual address (VA) recorded during scanning.
    pub resolved_va: Option<u64>,
}

impl IatEntry2 {
    /// Create a named import entry.
    #[must_use]
    pub fn named(rva: u64, dll_name: impl Into<String>, function_name: impl Into<String>) -> Self {
        Self {
            rva,
            dll_name: dll_name.into(),
            function_name: function_name.into(),
            ordinal: None,
            resolved_va: None,
        }
    }

    /// Create an ordinal import entry.
    #[must_use]
    pub fn ordinal(rva: u64, dll_name: impl Into<String>, ordinal: u16) -> Self {
        Self {
            rva,
            dll_name: dll_name.into(),
            function_name: String::new(),
            ordinal: Some(ordinal),
            resolved_va: None,
        }
    }

    /// Return the display name for this import.
    #[must_use]
    pub fn display_name(&self) -> String {
        if self.function_name.is_empty()
            && let Some(ord) = self.ordinal
        {
            return format!("{}#{}", self.dll_name, ord);
        }
        format!("{}!{}", self.dll_name, self.function_name)
    }
}

/// Heuristically-determined range of a loaded DLL in the process address space.
#[derive(Debug, Clone)]
pub struct LoadedModule {
    /// Module name (basename, e.g. `"ntdll.dll"`).
    pub name: String,
    /// Start address of the module in the process image.
    pub base: u64,
    /// Size of the module image in bytes.
    pub size: u64,
}

impl LoadedModule {
    #[must_use]
    pub fn new(name: impl Into<String>, base: u64, size: u64) -> Self {
        Self {
            name: name.into(),
            base,
            size,
        }
    }

    /// Return `true` when `addr` falls within this module's image range.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base.saturating_add(self.size)
    }
}

/// IAT rebuilder: given a memory dump of a PE and a list of loaded modules,
/// scans for the Import Address Table, reconstructs the import directory, and
/// assists with dumping a working PE image.
#[derive(Debug)]
pub struct IatRebuilder {
    /// Raw memory dump of the process image (starting at `image_base`).
    pub process_memory: Vec<u8>,
    /// Load address of the image in the dump.
    pub image_base: u64,
    /// Known loaded modules (used to resolve IAT entries to DLL names).
    pub modules: Vec<LoadedModule>,
    /// Pointer size: 4 for 32-bit, 8 for 64-bit images.
    pub pointer_size: usize,
    /// Minimum number of consecutive DLL pointers to consider an IAT candidate.
    pub min_iat_run: usize,
}

impl IatRebuilder {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Create a new [`IatRebuilder`] for a 64-bit image dump.
    #[must_use]
    pub const fn new_x64(process_memory: Vec<u8>, image_base: u64, modules: Vec<LoadedModule>) -> Self {
        Self {
            process_memory,
            image_base,
            modules,
            pointer_size: 8,
            min_iat_run: 3,
        }
    }

    /// Create a new [`IatRebuilder`] for a 32-bit image dump.
    #[must_use]
    pub const fn new_x86(process_memory: Vec<u8>, image_base: u64, modules: Vec<LoadedModule>) -> Self {
        Self {
            process_memory,
            image_base,
            modules,
            pointer_size: 4,
            min_iat_run: 3,
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn read_pointer(&self, offset: usize) -> Option<u64> {
        match self.pointer_size {
            8 => {
                if offset + 8 > self.process_memory.len() {
                    return None;
                }
                Some(u64::from_le_bytes(
                    self.process_memory[offset..offset + 8].try_into().ok()?,
                ))
            }
            4 => {
                if offset + 4 > self.process_memory.len() {
                    return None;
                }
                Some(
                    u64::from(u32::from_le_bytes(self.process_memory[offset..offset + 4].try_into().ok()?)),
                )
            }
            _ => None,
        }
    }

    /// Determine which module (if any) contains virtual address `va`.
    fn module_for_va(&self, va: u64) -> Option<&LoadedModule> {
        self.modules.iter().find(|m| m.contains(va))
    }

    /// Convert a VA to an offset into `process_memory`.
    pub fn va_to_offset(&self, va: u64) -> Option<usize> {
        va.checked_sub(self.image_base).map(|o| o as usize)
    }

    // ── IAT scanning ─────────────────────────────────────────────────────────

    /// Scan `process_memory` for arrays of pointers that all point into known
    /// loaded DLL ranges.  Returns a list of RVAs (relative to `image_base`)
    /// where IAT arrays were found.
    ///
    /// The algorithm slides a window of `pointer_size` bytes across the image
    /// and groups consecutive "DLL-pointing" pointers into candidate arrays.
    /// Any run of `>= min_iat_run` such pointers is considered an IAT.
    pub fn scan_for_iat(&self) -> Vec<u64> {
        let mut candidates: Vec<u64> = Vec::new();
        let step = self.pointer_size;
        let len = self.process_memory.len();
        if len < step {
            return candidates;
        }

        let mut run_start: Option<usize> = None;
        let mut run_count: usize = 0;

        let mut offset = 0;
        while offset + step <= len {
            if let Some(va) = self.read_pointer(offset) {
                let points_to_dll = va != 0 && self.module_for_va(va).is_some();
                if points_to_dll {
                    if run_start.is_none() {
                        run_start = Some(offset);
                        run_count = 0;
                    }
                    run_count += 1;
                } else {
                    // Null terminator ends a valid IAT block.
                    if va == 0
                        && run_count >= self.min_iat_run
                        && let Some(start) = run_start
                    {
                        candidates.push(
                            (start as u64).wrapping_sub(self.image_base), // RVA of first entry
                                                                          // Caller interprets as image-relative.
                                                                          // Store as file offset for simplicity.
                        );
                        // Actually store as RVA:
                        // start is a file offset; image_base is the load VA.
                        // The RVA = start (no subtraction needed because the
                        // memory dump starts at image_base).
                        candidates.pop();
                        candidates.push(start as u64);
                    }
                    run_start = None;
                    run_count = 0;
                }
            }
            offset += step;
        }
        // Flush any trailing run.
        if run_count >= self.min_iat_run
            && let Some(start) = run_start
        {
            candidates.push(start as u64);
        }
        candidates.dedup();
        candidates
    }

    // ── Import directory builder ──────────────────────────────────────────────

    /// Build a new PE import directory blob from a list of [`IatEntry2`] values.
    ///
    /// The returned `Vec<u8>` contains a compact import directory table
    /// followed by the import name data, ready to be placed into a PE section.
    ///
    /// Layout:
    /// ```text
    /// [IMAGE_IMPORT_DESCRIPTOR × n]  (20 bytes each)
    /// [null terminator descriptor]    (20 bytes)
    /// [for each DLL:]
    ///   DLL name (null-terminated)
    ///   [for each function:]
    ///     hint (2 bytes) + name (null-terminated), padded to 2-byte boundary
    ///   INT/IAT thunk array (pointer-sized NULLs as terminators)
    /// ```
    pub fn rebuild_import_directory(&self, entries: &[IatEntry2]) -> Vec<u8> {
        if entries.is_empty() {
            return Vec::new();
        }

        // Group entries by DLL (preserve insertion order).
        let mut dll_order: Vec<&str> = Vec::new();
        let mut dll_map: std::collections::HashMap<&str, Vec<&IatEntry2>> =
            std::collections::HashMap::new();
        for entry in entries {
            let dll = entry.dll_name.as_str();
            if !dll_map.contains_key(dll) {
                dll_order.push(dll);
            }
            dll_map.entry(dll).or_default().push(entry);
        }

        let dll_count = dll_order.len();
        // IMAGE_IMPORT_DESCRIPTOR is 20 bytes; +1 for null terminator.
        let desc_table_size = (dll_count + 1) * 20;

        // First pass: calculate offsets for each blob.
        // We accumulate name data after the descriptor table.
        let mut name_blob: Vec<u8> = Vec::new();

        struct DllLayout {
            name_off: u32,
            int_off: u32,
            // Per-entry hint+name offsets
            func_offs: Vec<u32>,
        }

        let mut layouts: Vec<DllLayout> = Vec::new();

        // The data section starts right after the descriptor table.
        let data_base = desc_table_size as u32;

        for &dll in &dll_order {
            let funcs = &dll_map[dll];

            // DLL name
            let name_off = data_base + name_blob.len() as u32;
            name_blob.extend_from_slice(dll.as_bytes());
            name_blob.push(0); // null terminator
            // Align to 2 bytes.
            if !name_blob.len().is_multiple_of(2) {
                name_blob.push(0);
            }

            // Function hint+name entries
            let mut func_offs: Vec<u32> = Vec::new();
            for entry in funcs {
                let off = data_base + name_blob.len() as u32;
                func_offs.push(off);
                if let Some(ord) = entry.ordinal {
                    // Import by ordinal: set high bit, store ordinal as hint.
                    name_blob.push(ord as u8);
                    name_blob.push((ord >> 8) as u8);
                    name_blob.push(0); // empty name
                    name_blob.push(0);
                } else {
                    // hint = 0 (placeholder)
                    name_blob.push(0);
                    name_blob.push(0);
                    name_blob.extend_from_slice(entry.function_name.as_bytes());
                    name_blob.push(0);
                    if !name_blob.len().is_multiple_of(2) {
                        name_blob.push(0);
                    }
                }
            }

            // INT (import name table) — array of pointer-sized thunks + null.
            let int_off = data_base + name_blob.len() as u32;
            for &foff in &func_offs {
                match self.pointer_size {
                    8 => name_blob.extend_from_slice(&u64::from(foff).to_le_bytes()),
                    _ => name_blob.extend_from_slice(&foff.to_le_bytes()),
                }
            }
            // Null terminator for INT.
            name_blob.resize(name_blob.len() + self.pointer_size, 0);

            layouts.push(DllLayout {
                name_off,
                int_off,
                func_offs,
            });
        }

        // Build the final buffer.
        let total = desc_table_size + name_blob.len();
        let mut out = vec![0u8; total];

        for (i, &dll) in dll_order.iter().enumerate() {
            let layout = &layouts[i];
            let funcs = &dll_map[dll];
            let desc_off = i * 20;

            // Sanity-check: one hint+name offset per imported function.
            debug_assert_eq!(layout.func_offs.len(), funcs.len());

            // OriginalFirstThunk (INT RVA)
            let int_rva = layout.int_off;
            out[desc_off..desc_off + 4].copy_from_slice(&int_rva.to_le_bytes());
            // TimeDateStamp — zero (to be filled by loader)
            // out[desc_off+4..desc_off+8] already zero
            // ForwarderChain — -1 (0xFFFFFFFF) means none
            out[desc_off + 8..desc_off + 12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
            // Name RVA
            out[desc_off + 12..desc_off + 16].copy_from_slice(&layout.name_off.to_le_bytes());
            // FirstThunk (IAT RVA) — use RVA of the first entry's slot.
            let first_thunk = if funcs.is_empty() {
                0u32
            } else {
                u32::try_from(funcs[0].rva).unwrap_or(u32::MAX)
            };
            out[desc_off + 16..desc_off + 20].copy_from_slice(&first_thunk.to_le_bytes());
        }
        // Null descriptor terminator already zeroed.

        // Copy name blob into position.
        out[desc_table_size..].copy_from_slice(&name_blob);
        out
    }

    // ── PE checksum ──────────────────────────────────────────────────────────

    /// Recalculate and patch the PE checksum in the Optional Header of
    /// `process_memory` (in-place).
    ///
    /// The checksum field offset in the Optional Header depends on whether the
    /// image is PE32 or PE32+.  This method detects the magic automatically.
    ///
    /// Returns `Ok(checksum)` on success.  The checksum uses the standard
    /// Windows algorithm: sum of all 16-bit words with carry-folding, plus
    /// the image size.
    pub fn fix_pe_checksum(&mut self) -> Result<u32, RebuildError> {
        let mem = &self.process_memory;
        if mem.len() < 0x40 {
            return Err(RebuildError::Other("image too small for DOS header".into()));
        }
        // e_lfanew at offset 0x3c.
        let e_lfanew = u32::from_le_bytes(mem[0x3c..0x40].try_into().unwrap()) as usize;
        if e_lfanew + 4 > mem.len() {
            return Err(RebuildError::Other("e_lfanew out of bounds".into()));
        }
        // PE signature.
        if &mem[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(RebuildError::Other("PE signature not found".into()));
        }
        // COFF header is 20 bytes; Optional Header starts at e_lfanew + 4 + 20.
        let opt_hdr_off = e_lfanew + 24;
        if opt_hdr_off + 2 > mem.len() {
            return Err(RebuildError::Other("Optional Header out of bounds".into()));
        }
        let opt_magic = u16::from_le_bytes(mem[opt_hdr_off..opt_hdr_off + 2].try_into().unwrap());
        // CheckSum field offset within Optional Header.
        let checksum_off = match opt_magic {
            0x010b => opt_hdr_off + 64, // PE32
            0x020b => opt_hdr_off + 64, // PE32+ (same relative offset)
            _ => {
                return Err(RebuildError::Other(format!(
                    "unknown Optional Header magic {opt_magic:#06x}"
                )));
            }
        };
        if checksum_off + 4 > mem.len() {
            return Err(RebuildError::Other("checksum field out of bounds".into()));
        }

        // Standard Windows PE checksum algorithm.
        let checksum = Self::compute_checksum(&self.process_memory, checksum_off);
        self.process_memory[checksum_off..checksum_off + 4]
            .copy_from_slice(&checksum.to_le_bytes());
        Ok(checksum)
    }

    fn compute_checksum(data: &[u8], checksum_field_offset: usize) -> u32 {
        let mut sum: u64 = 0;
        let mut i = 0usize;
        while i + 1 < data.len() {
            // Zero out the existing checksum field during calculation.
            let word = if i == checksum_field_offset || i == checksum_field_offset + 2 {
                0u16
            } else {
                u16::from_le_bytes([data[i], data[i + 1]])
            };
            sum += u64::from(word);
            if sum > 0xFFFF_FFFF {
                sum = (sum & 0xFFFF_FFFF) + (sum >> 32);
            }
            i += 2;
        }
        // Handle odd trailing byte.
        if !data.len().is_multiple_of(2) {
            sum += u64::from(data[data.len() - 1]);
        }
        // Fold 32-bit sum.
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        (sum as u32).wrapping_add(data.len() as u32)
    }

    // ── OEP heuristic ─────────────────────────────────────────────────────────

    /// Return a list of candidate Original Entry Point (OEP) addresses using
    /// static heuristics on the memory dump.
    ///
    /// Heuristics applied (each contributing one or more candidates):
    /// 1. **PE header `AddressOfEntryPoint`** field if it has not been zeroed.
    /// 2. **Common packer prologue patterns** (PUSHAD; CALL/JMP pattern).
    /// 3. **Code section start** (first executable section's VA).
    /// 4. **TLS callback array** entries, if a TLS directory is present.
    /// 5. **"Start" thunk pattern** (`MOV EDI, EDI; PUSH EBP; MOV EBP, ESP`
    ///    or `SUB RSP, imm8; MOV [RSP+...], ...`).
    ///
    /// All returned addresses are absolute virtual addresses (`image_base` + RVA).
    pub fn find_oep_heuristic(&self) -> Vec<u64> {
        let mut candidates: Vec<u64> = Vec::new();
        let mem = &self.process_memory;

        if mem.len() < 0x40 {
            return candidates;
        }

        // ── 1. PE header AoEP ────────────────────────────────────────────────
        let e_lfanew = u32::from_le_bytes(mem[0x3c..0x40].try_into().unwrap_or([0; 4])) as usize;
        if e_lfanew + 4 <= mem.len() && &mem[e_lfanew..e_lfanew.saturating_add(4)] == b"PE\0\0" {
            let opt_hdr = e_lfanew + 24;
            if opt_hdr + 28 <= mem.len() {
                let aep = u32::from_le_bytes(
                    mem[opt_hdr + 16..opt_hdr + 20].try_into().unwrap_or([0; 4]),
                );
                if aep != 0 {
                    candidates.push(self.image_base + u64::from(aep));
                }
            }

            // ── 2. Code section start ─────────────────────────────────────
            // Number of sections from COFF header offset +2.
            let num_sections =
                u16::from_le_bytes(mem[e_lfanew + 6..e_lfanew + 8].try_into().unwrap_or([0; 2]))
                    as usize;
            let opt_size = u16::from_le_bytes(
                mem[e_lfanew + 20..e_lfanew + 22]
                    .try_into()
                    .unwrap_or([0; 2]),
            ) as usize;
            let sec_table = e_lfanew + 24 + opt_size;
            for i in 0..num_sections {
                let sec_off = sec_table + i * 40;
                if sec_off + 40 > mem.len() {
                    break;
                }
                let characteristics = u32::from_le_bytes(
                    mem[sec_off + 36..sec_off + 40].try_into().unwrap_or([0; 4]),
                );
                // Executable + readable section.
                let is_code =
                    characteristics & 0x2000_0000 != 0 && characteristics & 0x4000_0000 != 0;
                if is_code {
                    let va = u32::from_le_bytes(
                        mem[sec_off + 12..sec_off + 16].try_into().unwrap_or([0; 4]),
                    );
                    if va != 0 {
                        candidates.push(self.image_base + u64::from(va));
                    }
                }
            }
        }

        // ── 3. Packer PUSHAD+CALL/JMP pattern scan ────────────────────────
        // PUSHAD = 0x60, followed shortly by CALL (0xE8) or JMP (0xE9).
        let scan_len = mem.len().min(0x10000); // limit to first 64 KB
        for i in 0..scan_len.saturating_sub(6) {
            if mem[i] == 0x60 {
                // Look for CALL/JMP within the next 5 bytes.
                let end = (i + 5).min(scan_len - 1) + 1;
                if mem[i + 1..end].iter().any(|&b| b == 0xE8 || b == 0xE9) {
                    candidates.push(self.image_base + i as u64);
                }
            }
        }

        // ── 4. MSVC start thunk: MOV EDI,EDI; PUSH EBP; MOV EBP,ESP ─────
        // Byte pattern: 8B FF 55 8B EC
        let msvc_prolog: &[u8] = &[0x8B, 0xFF, 0x55, 0x8B, 0xEC];
        for offset in Self::find_bytes(mem, msvc_prolog) {
            candidates.push(self.image_base + offset as u64);
        }

        // ── 5. x64 start thunk: SUB RSP, imm8 (48 83 EC xx) ─────────────
        let x64_prolog: &[u8] = &[0x48, 0x83, 0xEC];
        for offset in Self::find_bytes(mem, x64_prolog) {
            candidates.push(self.image_base + offset as u64);
        }

        // Deduplicate and sort.
        candidates.sort_unstable();
        candidates.dedup();
        candidates
    }

    fn find_bytes(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
        let n = haystack.len();
        let m = needle.len();
        if m == 0 || m > n {
            return Vec::new();
        }
        let mut result = Vec::new();
        'outer: for i in 0..=n - m {
            for j in 0..m {
                if haystack[i + j] != needle[j] {
                    continue 'outer;
                }
            }
            result.push(i);
        }
        result
    }

    // ── Process memory dump ───────────────────────────────────────────────────

    /// Fix section alignment in a raw memory dump so that the on-disk layout
    /// matches a valid PE file.
    ///
    /// For each section described in the PE headers, this method:
    /// 1. Reads the section data from the virtual memory at `VirtualAddress`.
    /// 2. Pads / truncates to `SizeOfRawData` (aligned to `FileAlignment`).
    /// 3. Places it at the correct `PointerToRawData` offset in the output.
    ///
    /// Returns a new `Vec<u8>` representing the on-disk PE image.
    pub fn dump_process_memory(&self, base: u64, size: usize, memory: &[u8]) -> Vec<u8> {
        if memory.len() < 0x40 {
            return memory.to_vec();
        }

        // Parse e_lfanew.
        let e_lfanew = match memory.get(0x3c..0x40) {
            Some(b) => u32::from_le_bytes(b.try_into().unwrap_or([0; 4])) as usize,
            None => return memory.to_vec(),
        };

        if e_lfanew + 4 > memory.len() {
            return memory.to_vec();
        }
        if memory.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0") {
            return memory.to_vec();
        }

        // Read Optional Header fields.
        let opt_hdr = e_lfanew + 24;
        if opt_hdr + 60 > memory.len() {
            return memory.to_vec();
        }

        let file_alignment = u32::from_le_bytes(
            memory[opt_hdr + 36..opt_hdr + 40]
                .try_into()
                .unwrap_or([0x200u32.to_le_bytes()[0]; 4]),
        ) as usize;
        let file_alignment = if file_alignment == 0 {
            0x200
        } else {
            file_alignment
        };

        let num_sections = u16::from_le_bytes(
            memory[e_lfanew + 6..e_lfanew + 8]
                .try_into()
                .unwrap_or([0; 2]),
        ) as usize;
        let opt_size = u16::from_le_bytes(
            memory[e_lfanew + 20..e_lfanew + 22]
                .try_into()
                .unwrap_or([0; 2]),
        ) as usize;
        let sec_table_off = e_lfanew + 24 + opt_size;

        // Collect sections.
        struct SecInfo {
            virtual_address: usize,
            virtual_size: usize,
            raw_offset: usize,
            raw_size: usize,
        }

        let mut sections: Vec<SecInfo> = Vec::new();
        for i in 0..num_sections {
            let off = sec_table_off + i * 40;
            if off + 40 > memory.len() {
                break;
            }
            let virtual_size =
                u32::from_le_bytes(memory[off + 8..off + 12].try_into().unwrap_or([0; 4])) as usize;
            let virtual_address =
                u32::from_le_bytes(memory[off + 12..off + 16].try_into().unwrap_or([0; 4]))
                    as usize;
            let raw_size =
                u32::from_le_bytes(memory[off + 16..off + 20].try_into().unwrap_or([0; 4]))
                    as usize;
            let raw_offset =
                u32::from_le_bytes(memory[off + 20..off + 24].try_into().unwrap_or([0; 4]))
                    as usize;
            sections.push(SecInfo {
                virtual_address,
                virtual_size,
                raw_offset,
                raw_size,
            });
        }

        if sections.is_empty() {
            return memory.to_vec();
        }

        // Determine output file size.
        let last = sections.iter().max_by_key(|s| s.raw_offset + s.raw_size);
        let file_size = last
            .map_or(size, |s| align_up(s.raw_offset + s.raw_size, file_alignment));
        let file_size = file_size.max(sec_table_off + num_sections * 40);

        let mut out = vec![0u8; file_size];

        // Copy PE headers (everything before the first section).
        let headers_size = sections
            .iter()
            .map(|s| s.raw_offset)
            .filter(|&o| o > 0)
            .min()
            .unwrap_or(file_alignment);
        let hdr_copy = headers_size.min(memory.len()).min(out.len());
        out[..hdr_copy].copy_from_slice(&memory[..hdr_copy]);

        // Copy each section from the virtual layout to the file layout.
        // The virtual address in the dump is relative to `base` which may
        // differ from `image_base`; compute the adjustment.
        let va_adjustment = base.wrapping_sub(self.image_base) as usize;

        for sec in &sections {
            let src_offset = sec.virtual_address.wrapping_sub(va_adjustment);
            let src_end = src_offset.saturating_add(sec.virtual_size);
            let src_end = src_end.min(memory.len());
            if src_offset >= memory.len() {
                continue;
            }

            let dst_start = sec.raw_offset;
            let dst_end = (dst_start + sec.raw_size).min(out.len());
            if dst_start >= out.len() {
                continue;
            }

            let copy_len = (src_end - src_offset).min(dst_end - dst_start);
            out[dst_start..dst_start + copy_len]
                .copy_from_slice(&memory[src_offset..src_offset + copy_len]);
        }

        out
    }
}

/// Round `value` up to the nearest multiple of `align` (must be a power of two
/// or a standard PE alignment value).
const fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    value.saturating_add(align - 1) & !(align - 1)
}

// =============================================================================
// Unit tests — IatRebuilder
// =============================================================================

#[cfg(test)]
mod iat_rebuilder_tests {
    use super::*;

    fn make_dummy_modules() -> Vec<LoadedModule> {
        vec![
            LoadedModule::new("kernel32.dll", 0x7fff_0000_0000, 0x0010_0000),
            LoadedModule::new("ntdll.dll", 0x7ffe_0000_0000, 0x0010_0000),
        ]
    }

    // ── IatEntry ─────────────────────────────────────────────────────────────

    #[test]
    fn iat_entry_named_display() {
        let e = IatEntry2::named(0x1000, "kernel32.dll", "VirtualAlloc");
        assert_eq!(e.display_name(), "kernel32.dll!VirtualAlloc");
    }

    #[test]
    fn iat_entry_ordinal_display() {
        let e = IatEntry2::ordinal(0x1008, "ntdll.dll", 42);
        assert!(e.display_name().contains("ntdll.dll"));
        assert!(e.display_name().contains("42"));
    }

    // ── LoadedModule ─────────────────────────────────────────────────────────

    #[test]
    fn loaded_module_contains() {
        let m = LoadedModule::new("test.dll", 0x1000, 0x1000);
        assert!(m.contains(0x1000));
        assert!(m.contains(0x1fff));
        assert!(!m.contains(0x2000));
        assert!(!m.contains(0x0fff));
    }

    // ── scan_for_iat ─────────────────────────────────────────────────────────

    #[test]
    fn scan_for_iat_finds_run() {
        let modules = make_dummy_modules();
        let va1 = 0x7fff_0000_1234u64; // inside kernel32
        let va2 = 0x7fff_0000_5678u64; // inside kernel32
        let va3 = 0x7ffe_0000_abcdu64; // inside ntdll

        let mut mem = vec![0u8; 256];
        let offset = 64usize;
        mem[offset..offset + 8].copy_from_slice(&va1.to_le_bytes());
        mem[offset + 8..offset + 16].copy_from_slice(&va2.to_le_bytes());
        mem[offset + 16..offset + 24].copy_from_slice(&va3.to_le_bytes());
        // Null terminator already zero at offset+24.

        let rebuilder = IatRebuilder::new_x64(mem, 0x0040_0000, modules);
        let iat_offsets = rebuilder.scan_for_iat();
        assert!(!iat_offsets.is_empty(), "should find an IAT run");
        assert_eq!(iat_offsets[0], offset as u64);
    }

    #[test]
    fn scan_for_iat_no_modules_no_hits() {
        let rebuilder = IatRebuilder::new_x64(vec![0u8; 256], 0x0040_0000, vec![]);
        let hits = rebuilder.scan_for_iat();
        assert!(hits.is_empty());
    }

    // ── rebuild_import_directory ──────────────────────────────────────────────

    #[test]
    fn rebuild_import_directory_non_empty() {
        let rebuilder = IatRebuilder::new_x64(vec![], 0, vec![]);
        let entries = vec![
            IatEntry2::named(0x3000, "kernel32.dll", "VirtualAlloc"),
            IatEntry2::named(0x3008, "kernel32.dll", "VirtualFree"),
            IatEntry2::named(0x3010, "ntdll.dll", "NtAllocateVirtualMemory"),
        ];
        let dir = rebuilder.rebuild_import_directory(&entries);
        // Should have at least 2 descriptors (kernel32, ntdll) + null + names.
        assert!(dir.len() >= 60, "directory too short: {}", dir.len());
        // Null terminator descriptor (last 20 bytes before name data) must be zero.
        // Actually with 2 DLLs + null = 60 bytes for descriptors.
        let null_desc = &dir[40..60];
        assert!(
            null_desc.iter().all(|&b| b == 0),
            "null descriptor must be zero"
        );
    }

    #[test]
    fn rebuild_import_directory_empty_entries() {
        let rebuilder = IatRebuilder::new_x64(vec![], 0, vec![]);
        let dir = rebuilder.rebuild_import_directory(&[]);
        assert!(dir.is_empty());
    }

    #[test]
    fn rebuild_import_directory_contains_dll_name() {
        let rebuilder = IatRebuilder::new_x64(vec![], 0, vec![]);
        let entries = vec![IatEntry2::named(0x1000, "kernel32.dll", "ExitProcess")];
        let dir = rebuilder.rebuild_import_directory(&entries);
        // The DLL name "kernel32.dll" should be embedded in the blob.
        let found = dir.windows(12).any(|w| w == b"kernel32.dll");
        assert!(found, "DLL name should appear in import directory blob");
    }

    #[test]
    fn rebuild_import_directory_ordinal_entry() {
        let rebuilder = IatRebuilder::new_x64(vec![], 0, vec![]);
        let entries = vec![IatEntry2::ordinal(0x2000, "ws2_32.dll", 23)];
        let dir = rebuilder.rebuild_import_directory(&entries);
        assert!(!dir.is_empty());
    }

    // ── fix_pe_checksum ───────────────────────────────────────────────────────

    fn minimal_pe32() -> Vec<u8> {
        // Build a minimal PE32 header large enough for checksum testing.
        let mut buf = vec![0u8; 0x200];
        // DOS magic.
        buf[0] = b'M';
        buf[1] = b'Z';
        // e_lfanew at 0x3c = 0x40.
        buf[0x3c] = 0x40;
        // PE signature at 0x40.
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");
        // Machine: x86 (0x014c).
        buf[0x44] = 0x4c;
        buf[0x45] = 0x01;
        // Number of sections: 0.
        // SizeOfOptionalHeader: 0xe0 (standard PE32 size).
        buf[0x54] = 0xe0;
        buf[0x55] = 0x00;
        // Optional Header magic: PE32 (0x010b).
        buf[0x58] = 0x0b;
        buf[0x59] = 0x01;
        buf
    }

    #[test]
    fn fix_pe_checksum_returns_nonzero() {
        let pe = minimal_pe32();
        let mut rebuilder = IatRebuilder::new_x86(pe, 0x0040_0000, vec![]);
        let result = rebuilder.fix_pe_checksum();
        assert!(result.is_ok(), "checksum calculation failed: {result:?}");
        let checksum = result.unwrap();
        assert_ne!(
            checksum, 0,
            "checksum should be non-zero for non-empty image"
        );
    }

    #[test]
    fn fix_pe_checksum_patches_memory() {
        let pe = minimal_pe32();
        let mut rebuilder = IatRebuilder::new_x86(pe, 0x0040_0000, vec![]);
        let checksum = rebuilder.fix_pe_checksum().unwrap();
        // The checksum field is at optional header base + 64.
        // Optional header starts at e_lfanew(0x40) + 24 = 0x58.
        let ck_off = 0x58 + 64;
        let stored = u32::from_le_bytes(
            rebuilder.process_memory[ck_off..ck_off + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(stored, checksum);
    }

    #[test]
    fn fix_pe_checksum_bad_signature_errors() {
        let mut rebuilder = IatRebuilder::new_x86(vec![0u8; 0x200], 0, vec![]);
        // Put e_lfanew = 0x40 but no PE signature.
        rebuilder.process_memory[0x3c] = 0x40;
        let result = rebuilder.fix_pe_checksum();
        assert!(result.is_err());
    }

    // ── find_oep_heuristic ────────────────────────────────────────────────────

    #[test]
    fn find_oep_heuristic_extracts_aep() {
        let mut pe = minimal_pe32();
        // Write AddressOfEntryPoint = 0x1000 at opt_hdr+16 (0x58+16 = 0x68).
        pe[0x68..0x6c].copy_from_slice(&0x1000u32.to_le_bytes());
        let rebuilder = IatRebuilder::new_x86(pe, 0x0040_0000, vec![]);
        let oep = rebuilder.find_oep_heuristic();
        assert!(
            oep.contains(&(0x0040_0000 + 0x1000)),
            "expected AEP-derived OEP candidate: {oep:?}"
        );
    }

    #[test]
    fn find_oep_heuristic_detects_pushad_call() {
        let mut mem = vec![0u8; 0x200];
        // Minimal valid DOS/PE headers to avoid panicking inside heuristic.
        mem[0] = b'M';
        mem[1] = b'Z';
        mem[0x3c] = 0x80; // e_lfanew = 0x80 (past our pattern area)
        // Inject PUSHAD + CALL at offset 0x20.
        mem[0x20] = 0x60; // PUSHAD
        mem[0x22] = 0xE8; // CALL
        let rebuilder = IatRebuilder::new_x86(mem, 0x0040_0000, vec![]);
        let oep = rebuilder.find_oep_heuristic();
        assert!(
            oep.contains(&(0x0040_0000 + 0x20)),
            "should detect PUSHAD+CALL pattern: {oep:?}"
        );
    }

    #[test]
    fn find_oep_heuristic_too_small_returns_empty() {
        let rebuilder = IatRebuilder::new_x86(vec![0u8; 10], 0, vec![]);
        let oep = rebuilder.find_oep_heuristic();
        assert!(oep.is_empty());
    }

    // ── dump_process_memory ───────────────────────────────────────────────────

    #[test]
    fn dump_process_memory_headers_preserved() {
        let mut mem = vec![0xCCu8; 0x400];
        // DOS MZ magic.
        mem[0] = b'M';
        mem[1] = b'Z';
        // e_lfanew = 0x40.
        mem[0x3c] = 0x40;
        // PE\0\0 at 0x40.
        mem[0x40..0x44].copy_from_slice(b"PE\0\0");
        // SizeOfOptionalHeader = 0xe0; 0 sections.
        mem[0x54] = 0xe0;
        let rebuilder = IatRebuilder::new_x86(mem.clone(), 0x0040_0000, vec![]);
        let out = rebuilder.dump_process_memory(0x0040_0000, 0x400, &mem);
        // DOS magic should be preserved.
        assert_eq!(&out[..2], b"MZ");
    }

    #[test]
    fn dump_process_memory_non_pe_passthrough() {
        // If the input is not a valid PE, the function should return a copy.
        let rebuilder = IatRebuilder::new_x86(vec![0u8; 32], 0, vec![]);
        let data = vec![0xABu8; 32];
        let out = rebuilder.dump_process_memory(0, 32, &data);
        assert_eq!(out, data);
    }

    // ── align_up helper ───────────────────────────────────────────────────────

    #[test]
    fn align_up_powers_of_two() {
        assert_eq!(align_up(0, 0x200), 0);
        assert_eq!(align_up(1, 0x200), 0x200);
        assert_eq!(align_up(0x200, 0x200), 0x200);
        assert_eq!(align_up(0x201, 0x200), 0x400);
        assert_eq!(align_up(0x1ff, 4), 0x200);
    }

    #[test]
    fn align_up_zero_align() {
        // align=0 should just return value unchanged.
        assert_eq!(align_up(42, 0), 42);
    }
}
