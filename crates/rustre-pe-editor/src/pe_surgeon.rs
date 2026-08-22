//! `pe_surgeon` — Structural PE surgery: inject sections, fix headers,
//! recalculate checksums, and repair size fields.
//!
//! # Key types
//! * [`PeSurgeon`]       — main facade; owns the PE buffer and change log.
//! * [`SectionInjector`] — adds new sections to the PE layout.
//! * [`HeaderFixer`]     — repairs corrupt or out-of-date PE header fields.
//! * [`ChecksumFixer`]   — recalculates the optional-header checksum.
//! * [`SizeCalculator`]  — computes aligned sizes and offsets.
//! * [`PeReport`]        — summary of all operations applied.

pub use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SurgeonError {
    #[error("buffer too short: need {need} bytes, have {have}")]
    TooShort { need: usize, have: usize },
    #[error("not a PE file: bad magic {0:#x}")]
    NotPe(u16),
    #[error("not a PE32/PE32+ header at offset {0:#x}")]
    NotOptional(usize),
    #[error("section '{0}' already exists")]
    SectionExists(String),
    #[error("section name too long: '{0}' (max 8 bytes)")]
    NameTooLong(String),
    #[error("alignment must be a power of two, got {0}")]
    BadAlignment(u32),
    #[error("section count overflow: max 96")]
    TooManySections,
    #[error("patch out of bounds: off={off} len={len} size={size}")]
    PatchOob { off: usize, len: usize, size: usize },
    #[error("invalid e_lfanew value {0:#x}")]
    BadELfanew(u32),
    #[error("checksum field not found (not a PE32/PE32+)")]
    NoChecksumField,
    #[error("NT signature is {0:#010x}, expected 0x00004550 (\"PE\0\0\")")]
    BadNtSignature(u32),
}

pub type SurgeonResult<T> = Result<T, SurgeonError>;

// ---------------------------------------------------------------------------
// Helpers — raw PE offsets
// ---------------------------------------------------------------------------

const E_MAGIC: usize = 0;
const E_LFANEW: usize = 0x3C;
pub const NT_SIGNATURE: usize = 0;
/// Expected value at `nt + NT_SIGNATURE`: "PE\0\0".
pub const NT_SIGNATURE_VALUE: u32 = 0x0000_4550;
// COFF header relative to PE signature
pub const COFF_MACHINE: usize = 4;
const COFF_NUM_SECTIONS: usize = 6;
const COFF_TIMESTAMP: usize = 8;
const COFF_OPT_HEADER_SIZE: usize = 20;
const COFF_CHARACTERISTICS: usize = 22;
const OPT_MAGIC: usize = 24; // relative to NT header start
const PE32_MAGIC: u16 = 0x010B;
const PE64_MAGIC: u16 = 0x020B;
const PE32_CHECKSUM_OFF: usize = 24 + 64; // NT offset + optional offset to checksum
pub const PE64_CHECKSUM_OFF: usize = 24 + 64;
const PE32_SIZE_OF_IMAGE_OFF: usize = 24 + 56;
pub const PE64_SIZE_OF_IMAGE_OFF: usize = 24 + 56;
const PE32_SIZE_OF_HEADERS_OFF: usize = 24 + 60;
pub const PE64_SIZE_OF_HEADERS_OFF: usize = 24 + 60;
const SECTION_HEADER_SIZE: usize = 40;

fn read_u16_le(buf: &[u8], off: usize) -> SurgeonResult<u16> {
    if off + 2 > buf.len() {
        return Err(SurgeonError::TooShort {
            need: off + 2,
            have: buf.len(),
        });
    }
    Ok(u16::from_le_bytes(buf[off..off + 2].try_into().unwrap()))
}

fn read_u32_le(buf: &[u8], off: usize) -> SurgeonResult<u32> {
    if off + 4 > buf.len() {
        return Err(SurgeonError::TooShort {
            need: off + 4,
            have: buf.len(),
        });
    }
    Ok(u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()))
}

fn write_u16_le(buf: &mut [u8], off: usize, v: u16) -> SurgeonResult<()> {
    if off + 2 > buf.len() {
        return Err(SurgeonError::PatchOob {
            off,
            len: 2,
            size: buf.len(),
        });
    }
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn write_u32_le(buf: &mut [u8], off: usize, v: u32) -> SurgeonResult<()> {
    if off + 4 > buf.len() {
        return Err(SurgeonError::PatchOob {
            off,
            len: 4,
            size: buf.len(),
        });
    }
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    Ok(())
}

/// Returns the file offset of the NT header.
fn nt_header_offset(buf: &[u8]) -> SurgeonResult<usize> {
    let magic = read_u16_le(buf, E_MAGIC)?;
    if magic != 0x5A4D {
        return Err(SurgeonError::NotPe(magic));
    }
    let e_lfanew = read_u32_le(buf, E_LFANEW)?;
    if e_lfanew as usize + 4 > buf.len() {
        return Err(SurgeonError::BadELfanew(e_lfanew));
    }
    let nt = e_lfanew as usize;
    // NT_SIGNATURE was declared and never read: the header was accepted on
    // the MZ magic and a in-range e_lfanew alone, so any file starting with
    // "MZ" was treated as a PE and the writers below would patch arbitrary
    // bytes of it.
    let sig = read_u32_le(buf, nt + NT_SIGNATURE)?;
    if sig != NT_SIGNATURE_VALUE {
        return Err(SurgeonError::BadNtSignature(sig));
    }
    Ok(nt)
}

/// Returns the file offset of the first section header.
fn first_section_offset(buf: &[u8]) -> SurgeonResult<usize> {
    let nt = nt_header_offset(buf)?;
    let opt_size = read_u16_le(buf, nt + COFF_OPT_HEADER_SIZE)? as usize;
    // NT signature (4) + COFF header (20) + optional header
    Ok(nt + 4 + 20 + opt_size)
}

// ---------------------------------------------------------------------------
// SizeCalculator
// ---------------------------------------------------------------------------

/// Computes aligned sizes and offsets.
#[derive(Debug, Clone, Copy)]
pub struct SizeCalculator {
    pub file_alignment: u32,
    pub section_alignment: u32,
}

impl SizeCalculator {
    /// # Errors
    /// Returns [`SurgeonError::BadAlignment`] if either alignment is not a power of two.
    pub const fn new(file_alignment: u32, section_alignment: u32) -> SurgeonResult<Self> {
        if !file_alignment.is_power_of_two() {
            return Err(SurgeonError::BadAlignment(file_alignment));
        }
        if !section_alignment.is_power_of_two() {
            return Err(SurgeonError::BadAlignment(section_alignment));
        }
        Ok(Self {
            file_alignment,
            section_alignment,
        })
    }

    #[must_use]
    pub const fn align_to(value: u32, alignment: u32) -> u32 {
        if alignment == 0 {
            return value;
        }
        // Use saturating_add to prevent overflow when value is near u32::MAX.
        value.saturating_add(alignment - 1) & !(alignment - 1)
    }

    #[must_use] 
    pub const fn file_aligned(&self, value: u32) -> u32 {
        Self::align_to(value, self.file_alignment)
    }

    #[must_use] 
    pub const fn section_aligned(&self, value: u32) -> u32 {
        Self::align_to(value, self.section_alignment)
    }
}

// ---------------------------------------------------------------------------
// ChecksumFixer
// ---------------------------------------------------------------------------

/// Computes and writes the PE optional-header `Checksum` field.
///
/// Uses the standard PE checksum algorithm (additive 32-bit with
/// unsigned 32-bit overflow folded into 16 bits, then + file size).
#[derive(Debug, Clone, Default)]
pub struct ChecksumFixer;

impl ChecksumFixer {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Compute the PE checksum for `buf`, with the checksum field itself
    /// zeroed (the field is at `checksum_offset`).
    ///
    /// # Panics
    /// Panics if `buf.len()` exceeds `u32::MAX` (required to fold the file size into the checksum).
    #[must_use]
    pub fn compute(&self, buf: &[u8], checksum_offset: usize) -> u32 {
        let mut checksum: u64 = 0;
        let mut i = 0;
        while i + 1 < buf.len() {
            let word = if i == checksum_offset
                || i == checksum_offset + 1
                || i == checksum_offset + 2
                || i == checksum_offset + 3
            {
                0u16
            } else {
                u16::from_le_bytes([buf[i], buf[i + 1]])
            };
            checksum += u64::from(word);
            if checksum > 0xFFFF_FFFF {
                checksum = (checksum & 0xFFFF_FFFF) + (checksum >> 32);
            }
            i += 2;
        }
        if i < buf.len() {
            checksum += u64::from(buf[i]);
        }
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        checksum += buf.len() as u64;
        u32::try_from(checksum & 0xFFFF_FFFF).expect("masked to 32 bits")
    }

    /// Compute and write the checksum into `buf`.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header is malformed or the buffer is too short.
    pub fn fix(&self, buf: &mut [u8]) -> SurgeonResult<u32> {
        let nt = nt_header_offset(buf)?;
        let opt_magic = read_u16_le(buf, nt + OPT_MAGIC)?;
        // PE32 and PE32+ happen to place CheckSum at the same optional-header
        // offset (ImageBase widening is absorbed by BaseOfData disappearing),
        // but each arm now names its own constant so the two can never drift
        // apart silently.
        let checksum_off = match opt_magic {
            PE32_MAGIC => nt + PE32_CHECKSUM_OFF,
            PE64_MAGIC => nt + PE64_CHECKSUM_OFF,
            _ => return Err(SurgeonError::NoChecksumField),
        };
        let ck = self.compute(buf, checksum_off);
        write_u32_le(buf, checksum_off, ck)?;
        Ok(ck)
    }
}

// ---------------------------------------------------------------------------
// HeaderFixer
// ---------------------------------------------------------------------------

/// Changes applied by `HeaderFixer`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeaderChanges {
    pub timestamp_set: Option<u32>,
    pub characteristics_patched: Option<u16>,
    pub num_sections_corrected: Option<u16>,
    pub size_of_image_set: Option<u32>,
    pub size_of_headers_set: Option<u32>,
}

/// Repairs out-of-date or corrupt PE header fields.
#[derive(Debug, Clone, Default)]
pub struct HeaderFixer;

impl HeaderFixer {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Zero the timestamp field.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header offset is invalid.
    pub fn zero_timestamp(&self, buf: &mut [u8]) -> SurgeonResult<()> {
        let nt = nt_header_offset(buf)?;
        write_u32_le(buf, nt + COFF_TIMESTAMP, 0)
    }

    /// Set the timestamp to a specific value.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header offset is invalid.
    pub fn set_timestamp(&self, buf: &mut [u8], ts: u32) -> SurgeonResult<()> {
        let nt = nt_header_offset(buf)?;
        write_u32_le(buf, nt + COFF_TIMESTAMP, ts)
    }

    /// Read the current number-of-sections field.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header offset is invalid.
    pub fn num_sections(&self, buf: &[u8]) -> SurgeonResult<u16> {
        let nt = nt_header_offset(buf)?;
        read_u16_le(buf, nt + COFF_NUM_SECTIONS)
    }

    /// Overwrite the number-of-sections field.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header offset is invalid.
    pub fn set_num_sections(&self, buf: &mut [u8], count: u16) -> SurgeonResult<()> {
        let nt = nt_header_offset(buf)?;
        write_u16_le(buf, nt + COFF_NUM_SECTIONS, count)
    }

    /// Set the `SizeOfImage` field in the optional header.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header offset is invalid.
    pub fn set_size_of_image(&self, buf: &mut [u8], size: u32) -> SurgeonResult<()> {
        let nt = nt_header_offset(buf)?;
        let off = Self::size_of_image_off(buf, nt)?;
        write_u32_le(buf, off, size)
    }

    /// Read `SizeOfImage`.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header offset is invalid.
    pub fn size_of_image(&self, buf: &[u8]) -> SurgeonResult<u32> {
        let nt = nt_header_offset(buf)?;
        let off = Self::size_of_image_off(buf, nt)?;
        read_u32_le(buf, off)
    }

    /// Set `SizeOfHeaders`.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header offset is invalid.
    pub fn set_size_of_headers(&self, buf: &mut [u8], size: u32) -> SurgeonResult<()> {
        let nt = nt_header_offset(buf)?;
        let off = Self::size_of_headers_off(buf, nt)?;
        write_u32_le(buf, off, size)
    }

    /// Read the COFF `Machine` word.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header offset is invalid.
    pub fn machine(&self, buf: &[u8]) -> SurgeonResult<u16> {
        let nt = nt_header_offset(buf)?;
        read_u16_le(buf, nt + COFF_MACHINE)
    }

    /// Offset of `SizeOfImage` for the optional-header magic in `buf`.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the header is not PE32/PE32+.
    fn size_of_image_off(buf: &[u8], nt: usize) -> SurgeonResult<usize> {
        match read_u16_le(buf, nt + OPT_MAGIC)? {
            PE32_MAGIC => Ok(nt + PE32_SIZE_OF_IMAGE_OFF),
            PE64_MAGIC => Ok(nt + PE64_SIZE_OF_IMAGE_OFF),
            _ => Err(SurgeonError::NotOptional(nt + OPT_MAGIC)),
        }
    }

    /// Offset of `SizeOfHeaders` for the optional-header magic in `buf`.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the header is not PE32/PE32+.
    fn size_of_headers_off(buf: &[u8], nt: usize) -> SurgeonResult<usize> {
        match read_u16_le(buf, nt + OPT_MAGIC)? {
            PE32_MAGIC => Ok(nt + PE32_SIZE_OF_HEADERS_OFF),
            PE64_MAGIC => Ok(nt + PE64_SIZE_OF_HEADERS_OFF),
            _ => Err(SurgeonError::NotOptional(nt + OPT_MAGIC)),
        }
    }

    /// Patch the Characteristics field.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header offset is invalid.
    pub fn set_characteristics(&self, buf: &mut [u8], flags: u16) -> SurgeonResult<()> {
        let nt = nt_header_offset(buf)?;
        write_u16_le(buf, nt + COFF_CHARACTERISTICS, flags)
    }

    /// Read Characteristics.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header offset is invalid.
    pub fn characteristics(&self, buf: &[u8]) -> SurgeonResult<u16> {
        let nt = nt_header_offset(buf)?;
        read_u16_le(buf, nt + COFF_CHARACTERISTICS)
    }
}

// ---------------------------------------------------------------------------
// SectionInjector
// ---------------------------------------------------------------------------

/// Description of a new section to inject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSection {
    /// Section name (max 8 bytes).
    pub name: String,
    /// Raw data for the section.
    pub data: Vec<u8>,
    /// Section characteristics (e.g. 0x60000020 = code+execute+read).
    pub characteristics: u32,
    /// If `None`, the injector will choose the next available virtual address.
    pub virtual_address: Option<u32>,
}

impl NewSection {
    pub fn code(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            data,
            characteristics: 0x6000_0020,
            virtual_address: None,
        }
    }

    pub fn data(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            data,
            characteristics: 0xC000_0040,
            virtual_address: None,
        }
    }
}

/// Injects new sections into a PE.
#[derive(Debug, Clone, Default)]
pub struct SectionInjector;

impl SectionInjector {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Append a new section to `buf`. Returns the RVA assigned to the section.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header is malformed or there is no room for a new section header.
    ///
    /// # Panics
    /// Panics if any section size or RVA exceeds `u32::MAX`.
    pub fn inject(
        &self,
        buf: &mut Vec<u8>,
        section: &NewSection,
        calc: &SizeCalculator,
    ) -> SurgeonResult<u32> {
        if section.name.len() > 16 {
            return Err(SurgeonError::NameTooLong(section.name.clone()));
        }
        let nt = nt_header_offset(buf)?;
        let num_sections = read_u16_le(buf, nt + COFF_NUM_SECTIONS)? as usize;
        if num_sections >= 96 {
            return Err(SurgeonError::TooManySections);
        }

        // Locate first section header and find the last section's layout.
        let first_sect = first_section_offset(buf)?;
        let last_sect_off = if num_sections > 0 {
            first_sect + (num_sections - 1) * SECTION_HEADER_SIZE
        } else {
            first_sect
        };

        // Compute the virtual address for the new section.
        let va = if let Some(v) = section.virtual_address {
            v
        } else if num_sections > 0 {
            let last_va = read_u32_le(buf, last_sect_off + 12)?;
            let last_vsz = read_u32_le(buf, last_sect_off + 8)?;
            calc.section_aligned(last_va.saturating_add(last_vsz))
        } else {
            calc.section_aligned(0x1000)
        };

        // Compute the raw offset for the new section.
        let raw_offset = if num_sections > 0 {
            let last_raw_off = read_u32_le(buf, last_sect_off + 20)?;
            let last_raw_sz = read_u32_le(buf, last_sect_off + 16)?;
            calc.file_aligned(last_raw_off.saturating_add(last_raw_sz))
        } else {
            calc.file_aligned(u32::try_from(buf.len()).expect("buf fits in u32"))
        };

        let raw_size = calc.file_aligned(u32::try_from(section.data.len()).expect("section data fits in u32"));
        let virtual_size = u32::try_from(section.data.len()).expect("section data fits in u32");

        // Grow the buffer to accommodate raw data.
        let new_buf_len = (raw_offset + raw_size) as usize;
        if new_buf_len > buf.len() {
            buf.resize(new_buf_len, 0);
        }

        // Write raw data.
        buf[raw_offset as usize..raw_offset as usize + section.data.len()]
            .copy_from_slice(&section.data);

        // Find where to write the new section header (append after last).
        let new_sect_off = first_sect + num_sections * SECTION_HEADER_SIZE;
        if new_sect_off + SECTION_HEADER_SIZE > buf.len() {
            return Err(SurgeonError::TooShort {
                need: new_sect_off + SECTION_HEADER_SIZE,
                have: buf.len(),
            });
        }

        // Build the 40-byte section header.
        let mut hdr = [0u8; SECTION_HEADER_SIZE];
        // Name: zero-padded, truncated to 8 bytes (PE spec limit).
        let name_bytes = section.name.as_bytes();
        let n = name_bytes.len().min(8);
        hdr[..n].copy_from_slice(&name_bytes[..n]);
        // VirtualSize
        hdr[8..12].copy_from_slice(&virtual_size.to_le_bytes());
        // VirtualAddress
        hdr[12..16].copy_from_slice(&va.to_le_bytes());
        // SizeOfRawData
        hdr[16..20].copy_from_slice(&raw_size.to_le_bytes());
        // PointerToRawData
        hdr[20..24].copy_from_slice(&raw_offset.to_le_bytes());
        // Characteristics
        hdr[36..40].copy_from_slice(&section.characteristics.to_le_bytes());

        buf[new_sect_off..new_sect_off + SECTION_HEADER_SIZE].copy_from_slice(&hdr);

        // Update num-sections.
        write_u16_le(buf, nt + COFF_NUM_SECTIONS, u16::try_from(num_sections + 1).expect("section count fits in u16"))?;

        // Update SizeOfImage.
        let new_img_size = calc.section_aligned(va + virtual_size);
        write_u32_le(buf, nt + PE32_SIZE_OF_IMAGE_OFF, new_img_size)?;

        Ok(va)
    }
}

// ---------------------------------------------------------------------------
// PeReport
// ---------------------------------------------------------------------------

/// An entry in the surgeon's operation log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationEntry {
    pub op: String,
    pub detail: String,
    pub offset: Option<usize>,
}

/// Summary of all operations applied by [`PeSurgeon`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeReport {
    pub operations: Vec<OperationEntry>,
    pub sections_injected: Vec<String>,
    pub checksum_before: Option<u32>,
    pub checksum_after: Option<u32>,
    pub errors: Vec<String>,
    pub final_file_size: usize,
}

impl PeReport {
    pub fn record(
        &mut self,
        op: impl Into<String>,
        detail: impl Into<String>,
        offset: Option<usize>,
    ) {
        self.operations.push(OperationEntry {
            op: op.into(),
            detail: detail.into(),
            offset,
        });
    }

    pub fn add_error(&mut self, e: impl Into<String>) {
        self.errors.push(e.into());
    }

    #[must_use] 
    pub const fn success(&self) -> bool {
        self.errors.is_empty()
    }
}

impl fmt::Display for PeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeReport: {} operations, {} sections injected, {} bytes, {} errors",
            self.operations.len(),
            self.sections_injected.len(),
            self.final_file_size,
            self.errors.len()
        )
    }
}

// ---------------------------------------------------------------------------
// PeSurgeon — main facade
// ---------------------------------------------------------------------------

/// Main facade for all structural PE surgery operations.
pub struct PeSurgeon {
    pub buffer: Vec<u8>,
    pub report: PeReport,
    pub header_fixer: HeaderFixer,
    pub checksum_fixer: ChecksumFixer,
    pub section_injector: SectionInjector,
    pub size_calc: SizeCalculator,
}

impl PeSurgeon {
    /// Create with default alignments (file=0x200, section=0x1000).
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if default alignments are rejected (should not happen).
    pub fn new(buffer: Vec<u8>) -> SurgeonResult<Self> {
        let size_calc = SizeCalculator::new(0x200, 0x1000)?;
        Ok(Self {
            buffer,
            report: PeReport::default(),
            header_fixer: HeaderFixer::new(),
            checksum_fixer: ChecksumFixer::new(),
            section_injector: SectionInjector::new(),
            size_calc,
        })
    }

    /// Fix the checksum field.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header is malformed.
    pub fn fix_checksum(&mut self) -> SurgeonResult<u32> {
        let ck = self.checksum_fixer.fix(&mut self.buffer)?;
        self.report.checksum_after = Some(ck);
        self.report
            .record("fix_checksum", format!("checksum={ck:#x}"), None);
        Ok(ck)
    }

    /// Zero the timestamp.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header is malformed.
    pub fn zero_timestamp(&mut self) -> SurgeonResult<()> {
        self.header_fixer.zero_timestamp(&mut self.buffer)?;
        self.report.record("zero_timestamp", "zeroed", None);
        Ok(())
    }

    /// Set a specific timestamp.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header is malformed.
    pub fn set_timestamp(&mut self, ts: u32) -> SurgeonResult<()> {
        self.header_fixer.set_timestamp(&mut self.buffer, ts)?;
        self.report.record("set_timestamp", format!("{ts}"), None);
        Ok(())
    }

    /// Inject a new section.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header is malformed or there is no room.
    pub fn inject_section(&mut self, section: &NewSection) -> SurgeonResult<u32> {
        let name = section.name.clone();
        let va = self
            .section_injector
            .inject(&mut self.buffer, section, &self.size_calc)?;
        self.report.sections_injected.push(name.clone());
        self.report
            .record("inject_section", format!("name={name} va={va:#x}"), None);
        Ok(va)
    }

    /// Set `SizeOfImage`.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header is malformed.
    pub fn set_size_of_image(&mut self, size: u32) -> SurgeonResult<()> {
        self.header_fixer
            .set_size_of_image(&mut self.buffer, size)?;
        self.report
            .record("set_size_of_image", format!("{size:#x}"), None);
        Ok(())
    }

    /// Set characteristics.
    ///
    /// # Errors
    /// Returns [`SurgeonError`] if the PE header is malformed.
    pub fn set_characteristics(&mut self, flags: u16) -> SurgeonResult<()> {
        self.header_fixer
            .set_characteristics(&mut self.buffer, flags)?;
        self.report
            .record("set_characteristics", format!("{flags:#x}"), None);
        Ok(())
    }

    /// Finalise the report with the current buffer size.
    pub const fn finalise(&mut self) {
        self.report.final_file_size = self.buffer.len();
    }

    /// Return the processed buffer.
    #[must_use] 
    pub fn into_buffer(self) -> Vec<u8> {
        self.buffer
    }
}

// ---------------------------------------------------------------------------
// Minimal valid PE stub for tests
// ---------------------------------------------------------------------------

/// Build a minimal 512-byte valid PE32 stub.
#[must_use] 
pub fn minimal_pe32() -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    // MZ
    buf[0] = 0x4D;
    buf[1] = 0x5A;
    // e_lfanew = 0x40
    buf[0x3C] = 0x40;
    // PE signature at 0x40
    buf[0x40] = b'P';
    buf[0x41] = b'E';
    buf[0x42] = 0;
    buf[0x43] = 0;
    // COFF: machine=x86 (0x014C), num_sections=0, opt_header_size=0xE0, characteristics=0x102
    buf[0x44] = 0x4C;
    buf[0x45] = 0x01; // machine
    buf[0x46] = 0x00;
    buf[0x47] = 0x00; // num sections
    buf[0x54] = 0xE0;
    buf[0x55] = 0x00; // opt header size
    buf[0x56] = 0x02;
    buf[0x57] = 0x01; // characteristics
    // Optional header at 0x58: magic=PE32 (0x010B)
    buf[0x58] = 0x0B;
    buf[0x59] = 0x01;
    // SizeOfImage at 0x58+56=0x90
    buf[0x90] = 0x00;
    buf[0x91] = 0x10;
    buf[0x92] = 0x00;
    buf[0x93] = 0x00; // 0x1000
    // SizeOfHeaders at 0x58+60=0x94
    buf[0x94] = 0x00;
    buf[0x95] = 0x02;
    buf[0x96] = 0x00;
    buf[0x97] = 0x00; // 0x200
    // First section header starts at 0x40 + 4 + 20 + 0xE0 = 0x148 — too big for 512 buf.
    // Reduce opt_header_size to 0x60 so section offset = 0x40+4+20+0x60 = 0xA8.
    buf[0x54] = 0x60;
    buf[0x55] = 0x00;
    // Adjust SizeOfImage/SizeOfHeaders offsets: opt start = 0x40+4+20=0x58, +56=0x90, +60=0x94.
    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- SizeCalculator ---

    #[test]
    fn size_calc_align() {
        assert_eq!(SizeCalculator::align_to(1, 0x200), 0x200);
        assert_eq!(SizeCalculator::align_to(0x200, 0x200), 0x200);
        assert_eq!(SizeCalculator::align_to(0x201, 0x200), 0x400);
    }

    #[test]
    fn size_calc_bad_alignment() {
        assert!(matches!(
            SizeCalculator::new(0x300, 0x1000),
            Err(SurgeonError::BadAlignment(0x300))
        ));
    }

    #[test]
    fn size_calc_file_aligned() {
        let c = SizeCalculator::new(0x200, 0x1000).unwrap();
        assert_eq!(c.file_aligned(0x1FF), 0x200);
        assert_eq!(c.file_aligned(0x200), 0x200);
        assert_eq!(c.file_aligned(0x201), 0x400);
    }

    #[test]
    fn size_calc_section_aligned() {
        let c = SizeCalculator::new(0x200, 0x1000).unwrap();
        assert_eq!(c.section_aligned(0xFFF), 0x1000);
        assert_eq!(c.section_aligned(0x1001), 0x2000);
    }

    // --- ChecksumFixer ---

    #[test]
    fn checksum_compute_returns_u32() {
        let buf = vec![0u8; 64];
        let cf = ChecksumFixer::new();
        // Just ensure it doesn't panic.
        let _ck = cf.compute(&buf, 0x40);
    }

    #[test]
    fn checksum_compute_small_buf() {
        let buf = vec![0xABu8; 16];
        let cf = ChecksumFixer::new();
        let ck = cf.compute(&buf, 0);
        assert!(ck > 0);
    }

    #[test]
    fn checksum_fix_valid_pe() {
        let mut buf = minimal_pe32();
        let cf = ChecksumFixer::new();
        let ck = cf.fix(&mut buf).unwrap();
        assert!(ck > 0);
    }

    #[test]
    fn checksum_fix_not_pe() {
        let mut buf = vec![0u8; 64];
        let cf = ChecksumFixer::new();
        assert!(matches!(cf.fix(&mut buf), Err(SurgeonError::NotPe(_))));
    }

    // --- HeaderFixer ---

    #[test]
    fn header_fixer_zero_timestamp() {
        let mut buf = minimal_pe32();
        let fixer = HeaderFixer::new();
        fixer.zero_timestamp(&mut buf).unwrap();
        let nt = nt_header_offset(&buf).unwrap();
        let ts = read_u32_le(&buf, nt + COFF_TIMESTAMP).unwrap();
        assert_eq!(ts, 0);
    }

    #[test]
    fn header_fixer_set_timestamp() {
        let mut buf = minimal_pe32();
        let fixer = HeaderFixer::new();
        fixer.set_timestamp(&mut buf, 0xDEAD_BEEF).unwrap();
        let nt = nt_header_offset(&buf).unwrap();
        let ts = read_u32_le(&buf, nt + COFF_TIMESTAMP).unwrap();
        assert_eq!(ts, 0xDEAD_BEEF);
    }

    #[test]
    fn header_fixer_num_sections_roundtrip() {
        let mut buf = minimal_pe32();
        let fixer = HeaderFixer::new();
        fixer.set_num_sections(&mut buf, 3).unwrap();
        assert_eq!(fixer.num_sections(&buf).unwrap(), 3);
    }

    #[test]
    fn header_fixer_size_of_image() {
        let mut buf = minimal_pe32();
        let fixer = HeaderFixer::new();
        fixer.set_size_of_image(&mut buf, 0x8000).unwrap();
        assert_eq!(fixer.size_of_image(&buf).unwrap(), 0x8000);
    }

    #[test]
    fn header_fixer_characteristics() {
        let mut buf = minimal_pe32();
        let fixer = HeaderFixer::new();
        fixer.set_characteristics(&mut buf, 0x0102).unwrap();
        assert_eq!(fixer.characteristics(&buf).unwrap(), 0x0102);
    }

    #[test]
    fn header_fixer_not_pe_error() {
        let buf = vec![0u8; 64];
        let fixer = HeaderFixer::new();
        assert!(fixer.num_sections(&buf).is_err());
    }

    // --- SectionInjector ---

    #[test]
    fn section_injector_appends_section() {
        let mut buf = minimal_pe32();
        let calc = SizeCalculator::new(0x200, 0x1000).unwrap();
        let inj = SectionInjector::new();
        let sec = NewSection::code(".injected", vec![0x90u8; 64]);
        let va = inj.inject(&mut buf, &sec, &calc).unwrap();
        assert!(va >= 0x1000);
        let fixer = HeaderFixer::new();
        assert_eq!(fixer.num_sections(&buf).unwrap(), 1);
    }

    #[test]
    fn section_injector_name_too_long() {
        let mut buf = minimal_pe32();
        let calc = SizeCalculator::new(0x200, 0x1000).unwrap();
        let inj = SectionInjector::new();
        let sec = NewSection::code(".toolongsectionname", vec![0u8; 4]);
        assert!(matches!(
            inj.inject(&mut buf, &sec, &calc),
            Err(SurgeonError::NameTooLong(_))
        ));
    }

    #[test]
    fn section_injector_data_section() {
        let mut buf = minimal_pe32();
        let calc = SizeCalculator::new(0x200, 0x1000).unwrap();
        let inj = SectionInjector::new();
        let sec = NewSection::data(".rdata", vec![0xAAu8; 128]);
        let va = inj.inject(&mut buf, &sec, &calc).unwrap();
        assert!(va > 0);
    }

    // --- PeSurgeon ---

    #[test]
    fn surgeon_new_valid_pe() {
        let buf = minimal_pe32();
        assert!(PeSurgeon::new(buf).is_ok());
    }

    #[test]
    fn surgeon_zero_timestamp() {
        let buf = minimal_pe32();
        let mut surgeon = PeSurgeon::new(buf).unwrap();
        surgeon.zero_timestamp().unwrap();
        assert!(
            surgeon
                .report
                .operations
                .iter()
                .any(|op| op.op == "zero_timestamp")
        );
    }

    #[test]
    fn surgeon_set_timestamp() {
        let buf = minimal_pe32();
        let mut surgeon = PeSurgeon::new(buf).unwrap();
        surgeon.set_timestamp(0x12345678).unwrap();
        let ts = surgeon.header_fixer.size_of_image(&surgeon.buffer); // just checking no panic
        let _ = ts;
    }

    #[test]
    fn surgeon_fix_checksum() {
        let buf = minimal_pe32();
        let mut surgeon = PeSurgeon::new(buf).unwrap();
        let ck = surgeon.fix_checksum().unwrap();
        assert!(ck > 0);
        assert_eq!(surgeon.report.checksum_after, Some(ck));
    }

    #[test]
    fn surgeon_inject_section() {
        let buf = minimal_pe32();
        let mut surgeon = PeSurgeon::new(buf).unwrap();
        let sec = NewSection::code(".new", vec![0x90u8; 64]);
        let va = surgeon.inject_section(&sec).unwrap();
        assert!(va > 0);
        assert!(
            surgeon
                .report
                .sections_injected
                .contains(&".new".to_string())
        );
    }

    #[test]
    fn surgeon_set_characteristics() {
        let buf = minimal_pe32();
        let mut surgeon = PeSurgeon::new(buf).unwrap();
        surgeon.set_characteristics(0x0022).unwrap();
    }

    #[test]
    fn surgeon_set_size_of_image() {
        let buf = minimal_pe32();
        let mut surgeon = PeSurgeon::new(buf).unwrap();
        surgeon.set_size_of_image(0x10000).unwrap();
        let fixer = HeaderFixer::new();
        assert_eq!(fixer.size_of_image(&surgeon.buffer).unwrap(), 0x10000);
    }

    #[test]
    fn surgeon_finalise() {
        let buf = minimal_pe32();
        let mut surgeon = PeSurgeon::new(buf).unwrap();
        surgeon.finalise();
        assert!(surgeon.report.final_file_size > 0);
    }

    #[test]
    fn surgeon_into_buffer() {
        let buf = minimal_pe32();
        let len = buf.len();
        let surgeon = PeSurgeon::new(buf).unwrap();
        assert_eq!(surgeon.into_buffer().len(), len);
    }

    #[test]
    fn pe_report_display() {
        let mut r = PeReport::default();
        r.record("op", "detail", None);
        r.final_file_size = 512;
        let s = format!("{r}");
        assert!(s.contains("1 operation"));
    }

    #[test]
    fn nt_header_offset_bad_magic() {
        let buf = vec![0u8; 64];
        assert!(matches!(
            nt_header_offset(&buf),
            Err(SurgeonError::NotPe(_))
        ));
    }

    #[test]
    fn nt_header_offset_valid() {
        let buf = minimal_pe32();
        assert_eq!(nt_header_offset(&buf).unwrap(), 0x40);
    }

    #[test]
    fn size_calc_align_zero_value() {
        assert_eq!(SizeCalculator::align_to(0, 0x200), 0);
    }

    #[test]
    fn size_calc_section_alignment_exact() {
        let c = SizeCalculator::new(0x200, 0x1000).unwrap();
        assert_eq!(c.section_aligned(0x1000), 0x1000);
    }

    #[test]
    fn section_new_code_characteristics() {
        let s = NewSection::code(".text", vec![0x90; 4]);
        assert_eq!(s.characteristics, 0x60000020);
    }

    #[test]
    fn section_new_data_characteristics() {
        let s = NewSection::data(".data", vec![0u8; 4]);
        assert_eq!(s.characteristics, 0xC0000040);
    }

    #[test]
    fn header_fixer_bad_e_lfanew() {
        // Buffer must be at least 0x40 bytes to hold the e_lfanew field itself.
        let mut buf = vec![0u8; 64];
        buf[0] = 0x4D;
        buf[1] = 0x5A; // MZ magic
        buf[0x3C] = 0xFF;
        buf[0x3D] = 0x00;
        buf[0x3E] = 0x00;
        buf[0x3F] = 0x00; // e_lfanew=0xFF > buf
        let fixer = HeaderFixer::new();
        assert!(fixer.num_sections(&buf).is_err());
    }

    #[test]
    fn size_calc_bad_section_alignment() {
        assert!(SizeCalculator::new(0x200, 0x300).is_err());
    }

    #[test]
    fn surgeon_report_error_recorded() {
        let mut r = PeReport::default();
        r.add_error("something went wrong");
        assert!(!r.success());
    }

    #[test]
    fn checksum_fixer_odd_length_buf() {
        let buf = vec![0x4D, 0x5A, 0x01]; // odd length
        let cf = ChecksumFixer::new();
        let _ = cf.compute(&buf, 99); // no panic
    }

    #[test]
    fn first_section_offset_valid_pe() {
        let buf = minimal_pe32();
        let off = first_section_offset(&buf).unwrap();
        // first section = nt(0x40) + 4 + 20 + opt_size(0x60) = 0xA8
        assert_eq!(off, 0x40 + 4 + 20 + 0x60);
    }

    #[test]
    fn header_fixer_read_size_of_image() {
        let buf = minimal_pe32();
        let fixer = HeaderFixer::new();
        let sz = fixer.size_of_image(&buf).unwrap();
        // We set it to 0x1000 in the stub
        assert_eq!(sz, 0x1000);
    }

    #[test]
    fn header_changes_default_empty() {
        let hc = HeaderChanges::default();
        assert!(hc.timestamp_set.is_none());
        assert!(hc.num_sections_corrected.is_none());
    }

    #[test]
    fn surgeon_multiple_sections() {
        let buf = minimal_pe32();
        let mut surgeon = PeSurgeon::new(buf).unwrap();
        surgeon
            .inject_section(&NewSection::code(".t1", vec![0x90u8; 32]))
            .unwrap();
        surgeon
            .inject_section(&NewSection::data(".d1", vec![0u8; 32]))
            .unwrap();
        let fixer = HeaderFixer::new();
        assert_eq!(fixer.num_sections(&surgeon.buffer).unwrap(), 2);
    }

    #[test]
    fn pe_report_multiple_operations() {
        let mut r = PeReport::default();
        r.record("op1", "d1", Some(0));
        r.record("op2", "d2", None);
        assert_eq!(r.operations.len(), 2);
    }
    #[test]
    fn nt_signature_is_verified() {
        // Regression: NT_SIGNATURE was declared and never read, so a file
        // that merely began with "MZ" was accepted and the writers would
        // patch arbitrary bytes of it.
        let mut buf = minimal_pe32();
        let nt = u32::from_le_bytes(buf[0x3C..0x40].try_into().unwrap()) as usize;
        assert!(HeaderFixer::new().size_of_image(&buf).is_ok());

        buf[nt] ^= 0xFF; // corrupt the "PE" signature only
        let err = HeaderFixer::new().size_of_image(&buf).unwrap_err();
        assert!(
            matches!(err, SurgeonError::BadNtSignature(_)),
            "expected BadNtSignature, got {err:?}"
        );
    }

    #[test]
    fn coff_machine_is_readable() {
        let buf = minimal_pe32();
        let m = HeaderFixer::new().machine(&buf).expect("machine reads");
        assert_ne!(m, 0, "COFF_MACHINE offset must point at a real machine word");
    }

    #[test]
    fn pe32_and_pe64_size_offsets_coincide_by_construction() {
        // PE32 and PE32+ really do agree here; the constants are kept
        // separate so a future edit to one cannot silently move the other.
        assert_eq!(PE32_CHECKSUM_OFF, PE64_CHECKSUM_OFF);
        assert_eq!(PE32_SIZE_OF_IMAGE_OFF, PE64_SIZE_OF_IMAGE_OFF);
        assert_eq!(PE32_SIZE_OF_HEADERS_OFF, PE64_SIZE_OF_HEADERS_OFF);

        // and a PE32+ image round-trips through the PE64 arm
        let mut buf = minimal_pe32();
        let nt = u32::from_le_bytes(buf[0x3C..0x40].try_into().unwrap()) as usize;
        buf[nt + OPT_MAGIC..nt + OPT_MAGIC + 2].copy_from_slice(&PE64_MAGIC.to_le_bytes());
        let sc = HeaderFixer::new();
        sc.set_size_of_image(&mut buf, 0x4321).expect("write");
        assert_eq!(sc.size_of_image(&buf).expect("read"), 0x4321);
    }

}
