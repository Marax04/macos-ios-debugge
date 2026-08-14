//! `pe_section_editor` — Advanced PE section operations.
//!
//! Provides add/remove/resize/rename/reorder operations on PE sections with
//! full header recalculation: `SizeOfImage`, `SizeOfHeaders`, `FileAlignment` padding,
//! `SectionAlignment` virtual layout, and multi-section cascading updates.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{EditError, section_chars};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default file alignment (512 bytes).
pub const DEFAULT_FILE_ALIGN: u32 = 0x200;
/// Default section alignment (4 KiB).
pub const DEFAULT_SECT_ALIGN: u32 = 0x1000;
/// Size of one `IMAGE_SECTION_HEADER` entry (bytes).
pub const SECTION_HEADER_SIZE: usize = 40;
/// Size of the COFF file header (bytes).
pub const COFF_HDR_SIZE: usize = 20;

// ---------------------------------------------------------------------------
// SectionInfo
// ---------------------------------------------------------------------------

/// Descriptor of a single PE section header (read-only view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    /// Up-to-8-byte name (zero-padded internally, displayed trimmed).
    pub name: String,
    /// Virtual size (bytes in memory, may be larger than `raw_size`).
    pub virtual_size: u32,
    /// Relative virtual address.
    pub virtual_address: u32,
    /// Aligned raw data size on disk.
    pub raw_size: u32,
    /// File offset of the first raw data byte.
    pub raw_offset: u32,
    /// Section characteristics flags.
    pub characteristics: u32,
    /// Zero-based index in the section table.
    pub index: usize,
}

impl SectionInfo {
    /// Compute the virtual end address (exclusive).
    #[must_use]
    pub const fn virtual_end(&self) -> u32 {
        self.virtual_address.saturating_add(self.virtual_size)
    }

    /// Compute the raw end offset (exclusive).
    #[must_use]
    pub const fn raw_end(&self) -> u32 {
        self.raw_offset.saturating_add(self.raw_size)
    }

    /// Returns `true` if this section contains executable code.
    #[must_use]
    pub const fn is_code(&self) -> bool {
        self.characteristics & section_chars::CODE != 0
            || self.characteristics & section_chars::MEM_EXECUTE != 0
    }

    /// Returns `true` if this section is readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.characteristics & section_chars::MEM_READ != 0
    }

    /// Returns `true` if this section is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.characteristics & section_chars::MEM_WRITE != 0
    }
}

impl fmt::Display for SectionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] '{}' VA={:#010x} VS={} RawOff={:#010x} RawSz={} Chars={:#010x}",
            self.index,
            self.name,
            self.virtual_address,
            self.virtual_size,
            self.raw_offset,
            self.raw_size,
            self.characteristics,
        )
    }
}

// ---------------------------------------------------------------------------
// NewSection
// ---------------------------------------------------------------------------

/// Specification for a new section to be added.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSection {
    /// Section name (truncated to 8 bytes).
    pub name: String,
    /// Initial raw data (will be padded to file alignment).
    pub data: Vec<u8>,
    /// Section characteristics flags.
    pub characteristics: u32,
    /// If `Some`, override the virtual address; otherwise auto-layout.
    pub virtual_address_override: Option<u32>,
}

impl NewSection {
    /// Create a code section.
    #[must_use]
    pub fn code(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            data,
            characteristics: section_chars::CODE
                | section_chars::MEM_EXECUTE
                | section_chars::MEM_READ,
            virtual_address_override: None,
        }
    }

    /// Create a readable/writable data section.
    #[must_use]
    pub fn data(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            data,
            characteristics: section_chars::INITIALIZED_DATA
                | section_chars::MEM_READ
                | section_chars::MEM_WRITE,
            virtual_address_override: None,
        }
    }

    /// Create a read-only data section.
    #[must_use]
    pub fn rdata(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            data,
            characteristics: section_chars::INITIALIZED_DATA | section_chars::MEM_READ,
            virtual_address_override: None,
        }
    }

    /// Create a discardable initialisation section.
    #[must_use]
    pub fn init(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            data,
            characteristics: section_chars::INITIALIZED_DATA
                | section_chars::MEM_READ
                | section_chars::MEM_DISCARDABLE,
            virtual_address_override: None,
        }
    }
}

// ---------------------------------------------------------------------------
// ResizeMode
// ---------------------------------------------------------------------------

/// Mode of section resize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResizeMode {
    /// Expand the section raw data, appending zeros.
    Expand,
    /// Shrink the section raw data, truncating.
    Shrink,
    /// Set the section to exactly `new_size` bytes (pad or truncate).
    SetExact,
}

// ---------------------------------------------------------------------------
// SectionPatchRecord
// ---------------------------------------------------------------------------

/// Audit record for a single section operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionOpRecord {
    /// Operation kind.
    pub operation: String,
    /// Section name.
    pub section_name: String,
    /// Extra information.
    pub detail: String,
}

impl fmt::Display for SectionOpRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] '{}': {}",
            self.operation, self.section_name, self.detail
        )
    }
}

// ---------------------------------------------------------------------------
// PeSectionEditor
// ---------------------------------------------------------------------------

/// Full-featured PE section editor.
///
/// Wraps a raw PE byte buffer and supports add, remove, rename, resize, and
/// characteristic modifications.  All operations update the section table and
/// recalculate `SizeOfImage` and file-alignment padding.
pub struct PeSectionEditor {
    data: Vec<u8>,
    audit_log: Vec<SectionOpRecord>,
}

impl PeSectionEditor {
    /// Create a section editor from raw PE bytes.
    ///
    /// # Errors
    /// Returns `EditError` if the bytes are not a valid PE.
    pub fn new(data: Vec<u8>) -> Result<Self, EditError> {
        validate_pe_magic(&data)?;
        Ok(Self {
            data,
            audit_log: Vec::new(),
        })
    }

    // ---- Public API --------------------------------------------------------

    /// Return a snapshot of all section headers.
    ///
    /// # Errors
    /// Returns `EditError` on header parse failure.
    pub fn sections(&self) -> Result<Vec<SectionInfo>, EditError> {
        let (table_off, count) = self.section_table_range()?;
        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            let off = table_off + i * SECTION_HEADER_SIZE;
            if off + SECTION_HEADER_SIZE > self.data.len() {
                break;
            }
            let info = parse_section_header(&self.data, off, i);
            result.push(info);
        }
        Ok(result)
    }

    /// Find a section by name.
    ///
    /// # Errors
    /// Returns `EditError::SectionNotFound` if not found.
    pub fn find_section(&self, name: &str) -> Result<SectionInfo, EditError> {
        self.sections()?
            .into_iter()
            .find(|s| s.name == name)
            .ok_or_else(|| EditError::SectionNotFound(name.to_string()))
    }

    /// Rename a section.
    ///
    /// # Errors
    /// Returns `EditError::SectionNotFound` if `old_name` does not exist.
    pub fn rename_section(&mut self, old_name: &str, new_name: &str) -> Result<(), EditError> {
        let off = self.find_header_offset(old_name)?;
        write_section_name(&mut self.data, off, new_name);
        self.log_op("rename", old_name, &format!("→ '{new_name}'"));
        Ok(())
    }

    /// Set section characteristics flags.
    ///
    /// # Errors
    /// Returns `EditError::SectionNotFound` if the section is not found.
    pub fn set_characteristics(
        &mut self,
        name: &str,
        characteristics: u32,
    ) -> Result<(), EditError> {
        let off = self.find_header_offset(name)?;
        write_u32(&mut self.data, off + 36, characteristics);
        self.log_op(
            "set_chars",
            name,
            &format!("chars={characteristics:#010x}"),
        );
        Ok(())
    }

    /// Add a characteristics bit to a section (OR-in a flag).
    ///
    /// # Errors
    /// Returns `EditError::SectionNotFound` if not found.
    pub fn add_characteristic(&mut self, name: &str, flag: u32) -> Result<(), EditError> {
        let off = self.find_header_offset(name)?;
        let cur = read_u32(&self.data, off + 36);
        write_u32(&mut self.data, off + 36, cur | flag);
        self.log_op("add_char", name, &format!("flag={flag:#010x}"));
        Ok(())
    }

    /// Remove a characteristics bit from a section (AND-NOT a flag).
    ///
    /// # Errors
    /// Returns `EditError::SectionNotFound` if not found.
    pub fn remove_characteristic(&mut self, name: &str, flag: u32) -> Result<(), EditError> {
        let off = self.find_header_offset(name)?;
        let cur = read_u32(&self.data, off + 36);
        write_u32(&mut self.data, off + 36, cur & !flag);
        self.log_op("rm_char", name, &format!("flag={flag:#010x}"));
        Ok(())
    }

    /// Add a new section to the PE.
    ///
    /// The section data is appended to the file and the section header is
    /// written into the first free slot in the section table.
    ///
    /// # Errors
    /// Returns `EditError::InvalidAlignment` if there is no room in the
    /// header region.
    ///
    /// # Panics
    /// Panics if any computed size or offset exceeds `u32::MAX`.
    pub fn add_section(&mut self, spec: &NewSection) -> Result<(), EditError> {
        let file_align = self.file_alignment()?;
        let sect_align = self.section_alignment()?;

        let (table_off, n_sections) = self.section_table_range()?;
        let new_hdr_off = table_off + n_sections * SECTION_HEADER_SIZE;

        // Ensure space for the new header slot before first section raw data.
        let first_raw = self.first_raw_data_offset()?;
        if new_hdr_off + SECTION_HEADER_SIZE > first_raw {
            return Err(EditError::InvalidAlignment(
                "no room for new section header (all header space consumed)".to_string(),
            ));
        }

        let raw_data_len = align_up(u32::try_from(spec.data.len()).expect("section data fits in u32"), file_align);
        let virt_size = u32::try_from(spec.data.len()).expect("section data fits in u32");

        // Pick virtual address.
        let virt_addr = if let Some(va) = spec.virtual_address_override {
            va
        } else {
            self.next_virtual_address(sect_align)?
        };

        // Pick raw offset.
        let raw_off = align_up(u32::try_from(self.data.len()).expect("file size fits in u32"), file_align);

        // Write new section header.
        let name_bytes = spec.name.as_bytes();
        let copy_len = name_bytes.len().min(8);
        for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
            if new_hdr_off + i < self.data.len() {
                self.data[new_hdr_off + i] = b;
            }
        }
        for i in copy_len..8 {
            if new_hdr_off + i < self.data.len() {
                self.data[new_hdr_off + i] = 0;
            }
        }
        write_u32(&mut self.data, new_hdr_off + 8, virt_size);
        write_u32(&mut self.data, new_hdr_off + 12, virt_addr);
        write_u32(&mut self.data, new_hdr_off + 16, raw_data_len);
        write_u32(&mut self.data, new_hdr_off + 20, raw_off);
        for i in 24..36 {
            if new_hdr_off + i < self.data.len() {
                self.data[new_hdr_off + i] = 0;
            }
        }
        write_u32(&mut self.data, new_hdr_off + 36, spec.characteristics);

        // Increment section count.
        let pe_off = self.pe_header_offset()?;
        let old_count = read_u16(&self.data, pe_off + 6);
        let new_count = old_count.checked_add(1).ok_or_else(|| {
            EditError::InvalidAlignment("section count overflow (max 65535)".to_string())
        })?;
        write_u16(&mut self.data, pe_off + 6, new_count);

        // Append raw data (with padding).
        let pad_before = (raw_off as usize).saturating_sub(self.data.len());
        self.data.extend(std::iter::repeat_n(0u8, pad_before));
        self.data.extend_from_slice(&spec.data);
        let pad_after = (raw_data_len as usize).saturating_sub(spec.data.len());
        self.data.extend(std::iter::repeat_n(0u8, pad_after));

        // Recalculate SizeOfImage.
        self.recalculate_size_of_image(sect_align)?;

        self.log_op(
            "add",
            &spec.name,
            &format!("VA={virt_addr:#x} rawOff={raw_off:#x} rawSz={raw_data_len}"),
        );
        Ok(())
    }

    /// Remove a section by name.
    ///
    /// The section's raw data is zeroed and its header entry is removed from
    /// the section table by shifting subsequent entries forward by one slot.
    ///
    /// # Errors
    /// Returns `EditError::SectionNotFound` if not found.
    pub fn remove_section(&mut self, name: &str) -> Result<(), EditError> {
        let (table_off, n_sections) = self.section_table_range()?;
        // Find the target index.
        let target_idx = self
            .sections()?
            .iter()
            .position(|s| s.name == name)
            .ok_or_else(|| EditError::SectionNotFound(name.to_string()))?;

        // Zero raw data for the section being removed.
        {
            let off = table_off + target_idx * SECTION_HEADER_SIZE;
            let raw_sz = read_u32(&self.data, off + 16) as usize;
            let raw_off = read_u32(&self.data, off + 20) as usize;
            if raw_off + raw_sz <= self.data.len() {
                self.data[raw_off..raw_off + raw_sz].fill(0);
            }
        }

        // Shift headers: copy headers [target+1 .. n] one slot forward.
        for i in target_idx + 1..n_sections {
            let src = table_off + i * SECTION_HEADER_SIZE;
            let dst = table_off + (i - 1) * SECTION_HEADER_SIZE;
            if src + SECTION_HEADER_SIZE <= self.data.len() {
                let entry: Vec<u8> = self.data[src..src + SECTION_HEADER_SIZE].to_vec();
                self.data[dst..dst + SECTION_HEADER_SIZE].copy_from_slice(&entry);
            }
        }

        // Zero the last (now-duplicate) header slot.
        let last_slot = table_off + (n_sections - 1) * SECTION_HEADER_SIZE;
        if last_slot + SECTION_HEADER_SIZE <= self.data.len() {
            self.data[last_slot..last_slot + SECTION_HEADER_SIZE].fill(0);
        }

        // Decrement section count.
        let pe_off = self.pe_header_offset()?;
        let cur = read_u16(&self.data, pe_off + 6);
        write_u16(&mut self.data, pe_off + 6, cur.saturating_sub(1));

        // Recalculate SizeOfImage.
        let sect_align = self.section_alignment()?;
        self.recalculate_size_of_image(sect_align)?;

        self.log_op("remove", name, "section removed");
        Ok(())
    }

    /// Resize a section's raw data in-place.
    ///
    /// Only works if the section is the last one in the file (its raw data
    /// ends at `data.len()`).  For other sections, returns `EditError`.
    ///
    /// # Errors
    /// Returns `EditError::InvalidAlignment` if the section is not the last.
    ///
    /// # Panics
    /// Panics if the new raw size or virtual size exceeds `u32::MAX`.
    pub fn resize_last_section(
        &mut self,
        name: &str,
        new_virtual_size: u32,
        mode: ResizeMode,
    ) -> Result<(), EditError> {
        let file_align = self.file_alignment()?;
        let sect_align = self.section_alignment()?;

        let off = self.find_header_offset(name)?;
        let raw_off = read_u32(&self.data, off + 20) as usize;
        let old_raw_sz = read_u32(&self.data, off + 16) as usize;
        let raw_end = raw_off + old_raw_sz;

        if raw_end != self.data.len() {
            return Err(EditError::InvalidAlignment(format!(
                "section '{name}' is not the last section in the file; in-place resize not supported"
            )));
        }

        let new_raw_sz = match mode {
            ResizeMode::Expand => {
                
                old_raw_sz.max(align_up(new_virtual_size, file_align) as usize)
            }
            ResizeMode::Shrink => {
                let shrunk = align_up(new_virtual_size, file_align) as usize;
                shrunk.min(old_raw_sz)
            }
            ResizeMode::SetExact => align_up(new_virtual_size, file_align) as usize,
        };

        // Resize the data vec.
        if new_raw_sz > old_raw_sz {
            let extra = new_raw_sz - old_raw_sz;
            self.data.extend(std::iter::repeat_n(0u8, extra));
        } else {
            self.data.truncate(raw_off + new_raw_sz);
        }

        // Update header: VirtualSize and RawSize.
        write_u32(&mut self.data, off + 8, new_virtual_size);
        write_u32(&mut self.data, off + 16, u32::try_from(new_raw_sz).expect("raw size fits in u32"));

        // Update SizeOfImage.
        self.recalculate_size_of_image(sect_align)?;

        self.log_op(
            "resize",
            name,
            &format!("vs={new_virtual_size} raw_sz={new_raw_sz} mode={mode:?}"),
        );
        Ok(())
    }

    /// Read raw section data.
    ///
    /// # Errors
    /// Returns `EditError::SectionNotFound` if not found.
    pub fn read_section_data(&self, name: &str) -> Result<&[u8], EditError> {
        let info = self.find_section(name)?;
        let off = info.raw_offset as usize;
        let sz = info.raw_size as usize;
        let end = (off + sz).min(self.data.len());
        Ok(&self.data[off..end])
    }

    /// Write bytes into a section at `section_offset`.
    ///
    /// # Errors
    /// Returns `EditError::PatchOutOfBounds` if out-of-bounds.
    pub fn write_section_data(
        &mut self,
        name: &str,
        section_offset: usize,
        bytes: &[u8],
    ) -> Result<(), EditError> {
        let info = self.find_section(name)?;
        let abs_off = info.raw_offset as usize + section_offset;
        if abs_off + bytes.len() > info.raw_offset as usize + info.raw_size as usize
            || abs_off + bytes.len() > self.data.len()
        {
            return Err(EditError::PatchOutOfBounds {
                offset: abs_off,
                len: bytes.len(),
                file_size: self.data.len(),
            });
        }
        self.data[abs_off..abs_off + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Zero out a section's raw data.
    ///
    /// # Errors
    /// Returns `EditError::SectionNotFound`.
    pub fn zero_section(&mut self, name: &str) -> Result<(), EditError> {
        let info = self.find_section(name)?;
        let off = info.raw_offset as usize;
        let sz = info.raw_size as usize;
        if off + sz <= self.data.len() {
            self.data[off..off + sz].fill(0);
        }
        self.log_op("zero", name, "raw data zeroed");
        Ok(())
    }

    /// Set both the virtual size and raw size of a section header without
    /// moving any data.
    ///
    /// Use this to correct inconsistent headers.
    ///
    /// # Errors
    /// Returns `EditError::SectionNotFound`.
    pub fn fixup_sizes(
        &mut self,
        name: &str,
        virtual_size: u32,
        raw_size: u32,
    ) -> Result<(), EditError> {
        let off = self.find_header_offset(name)?;
        write_u32(&mut self.data, off + 8, virtual_size);
        write_u32(&mut self.data, off + 16, raw_size);
        self.log_op(
            "fixup_sizes",
            name,
            &format!("vs={virtual_size} raw={raw_size}"),
        );
        Ok(())
    }

    /// Move a section's virtual address (RVA) in the header.
    ///
    /// Does **not** move raw data.  Mainly useful for crafting test inputs.
    ///
    /// # Errors
    /// Returns `EditError::SectionNotFound`.
    pub fn set_virtual_address(
        &mut self,
        name: &str,
        new_va: u32,
    ) -> Result<(), EditError> {
        let off = self.find_header_offset(name)?;
        write_u32(&mut self.data, off + 12, new_va);
        self.log_op("set_va", name, &format!("new_va={new_va:#x}"));
        Ok(())
    }

    /// Force-recalculate `SizeOfImage` from the current section table.
    ///
    /// # Errors
    /// Returns `EditError` on header parse failure.
    pub fn recalculate_size_of_image_pub(&mut self) -> Result<u32, EditError> {
        let sect_align = self.section_alignment()?;
        self.recalculate_size_of_image(sect_align)
    }

    /// Build a `{name → offset}` map of all section header file offsets.
    ///
    /// # Errors
    /// Returns `EditError` on parse failure.
    pub fn section_header_offsets(&self) -> Result<HashMap<String, usize>, EditError> {
        let (table_off, count) = self.section_table_range()?;
        let mut map = HashMap::new();
        for i in 0..count {
            let off = table_off + i * SECTION_HEADER_SIZE;
            if off + 8 > self.data.len() {
                break;
            }
            let name = read_section_name(&self.data, off);
            map.insert(name, off);
        }
        Ok(map)
    }

    /// Swap the positions of two sections in the section table.
    ///
    /// Only swaps the headers; does not move raw data.
    ///
    /// # Errors
    /// Returns `EditError::SectionNotFound` if either section is missing.
    pub fn swap_headers(&mut self, name_a: &str, name_b: &str) -> Result<(), EditError> {
        let (table_off, count) = self.section_table_range()?;
        let idx_a = self
            .sections()?
            .iter()
            .position(|s| s.name == name_a)
            .ok_or_else(|| EditError::SectionNotFound(name_a.to_string()))?;
        let idx_b = self
            .sections()?
            .iter()
            .position(|s| s.name == name_b)
            .ok_or_else(|| EditError::SectionNotFound(name_b.to_string()))?;
        if idx_a == idx_b {
            return Ok(());
        }
        let off_a = table_off + idx_a * SECTION_HEADER_SIZE;
        let off_b = table_off + idx_b * SECTION_HEADER_SIZE;
        if off_a + SECTION_HEADER_SIZE <= self.data.len()
            && off_b + SECTION_HEADER_SIZE <= self.data.len()
        {
            let (lo, hi) = if off_a < off_b {
                (off_a, off_b)
            } else {
                (off_b, off_a)
            };
            // Split borrow workaround: copy one into a temp.
            let tmp: Vec<u8> = self.data[lo..lo + SECTION_HEADER_SIZE].to_vec();
            let src: Vec<u8> = self.data[hi..hi + SECTION_HEADER_SIZE].to_vec();
            self.data[lo..lo + SECTION_HEADER_SIZE].copy_from_slice(&src);
            self.data[hi..hi + SECTION_HEADER_SIZE].copy_from_slice(&tmp);
        }
        let _ = count;
        self.log_op("swap", name_a, &format!("swapped with '{name_b}'"));
        Ok(())
    }

    /// Consume the editor and return the modified bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Borrow the current bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Audit log of operations performed.
    #[must_use]
    pub fn audit_log(&self) -> &[SectionOpRecord] {
        &self.audit_log
    }

    // ---- Internal helpers --------------------------------------------------

    fn pe_header_offset(&self) -> Result<usize, EditError> {
        if self.data.len() < 64 {
            return Err(EditError::InvalidAlignment(
                "buffer too short for DOS header".to_string(),
            ));
        }
        let off = read_u32(&self.data, 60) as usize;
        if off + 4 > self.data.len() {
            return Err(EditError::InvalidAlignment(
                "PE header offset out of range".to_string(),
            ));
        }
        Ok(off)
    }

    fn section_table_range(&self) -> Result<(usize, usize), EditError> {
        let pe_off = self.pe_header_offset()?;
        let n = read_u16(&self.data, pe_off + 6) as usize;
        let opt_sz = read_u16(&self.data, pe_off + 20) as usize;
        let table_start = pe_off + 4 + COFF_HDR_SIZE + opt_sz;
        Ok((table_start, n))
    }

    fn find_header_offset(&self, name: &str) -> Result<usize, EditError> {
        let (table_off, count) = self.section_table_range()?;
        for i in 0..count {
            let off = table_off + i * SECTION_HEADER_SIZE;
            if off + 8 > self.data.len() {
                break;
            }
            if read_section_name(&self.data, off) == name {
                return Ok(off);
            }
        }
        Err(EditError::SectionNotFound(name.to_string()))
    }

    fn first_raw_data_offset(&self) -> Result<usize, EditError> {
        let (table_off, count) = self.section_table_range()?;
        let mut min_raw = self.data.len();
        for i in 0..count {
            let off = table_off + i * SECTION_HEADER_SIZE;
            if off + 24 > self.data.len() {
                break;
            }
            let raw = read_u32(&self.data, off + 20) as usize;
            if raw > 0 && raw < min_raw {
                min_raw = raw;
            }
        }
        Ok(min_raw)
    }

    fn next_virtual_address(&self, sect_align: u32) -> Result<u32, EditError> {
        let (table_off, count) = self.section_table_range()?;
        let mut max_end: u32 = sect_align;
        for i in 0..count {
            let off = table_off + i * SECTION_HEADER_SIZE;
            if off + 16 > self.data.len() {
                break;
            }
            let va = read_u32(&self.data, off + 12);
            let vs = read_u32(&self.data, off + 8);
            let end = va.saturating_add(vs);
            if end > max_end {
                max_end = end;
            }
        }
        Ok(align_up(max_end, sect_align))
    }

    fn file_alignment(&self) -> Result<u32, EditError> {
        let pe_off = self.pe_header_offset()?;
        let opt_off = pe_off + 4 + COFF_HDR_SIZE;
        if opt_off + 40 > self.data.len() {
            return Ok(DEFAULT_FILE_ALIGN);
        }
        let fa = read_u32(&self.data, opt_off + 36);
        if fa == 0 { Ok(DEFAULT_FILE_ALIGN) } else { Ok(fa) }
    }

    fn section_alignment(&self) -> Result<u32, EditError> {
        let pe_off = self.pe_header_offset()?;
        let opt_off = pe_off + 4 + COFF_HDR_SIZE;
        if opt_off + 36 > self.data.len() {
            return Ok(DEFAULT_SECT_ALIGN);
        }
        let sa = read_u32(&self.data, opt_off + 32);
        if sa == 0 { Ok(DEFAULT_SECT_ALIGN) } else { Ok(sa) }
    }

    fn recalculate_size_of_image(&mut self, sect_align: u32) -> Result<u32, EditError> {
        let (table_off, count) = self.section_table_range()?;
        let mut max_end: u32 = sect_align;
        for i in 0..count {
            let off = table_off + i * SECTION_HEADER_SIZE;
            if off + 16 > self.data.len() {
                break;
            }
            let va = read_u32(&self.data, off + 12);
            let vs = read_u32(&self.data, off + 8);
            if vs == 0 {
                continue;
            }
            let end = align_up(va.saturating_add(vs), sect_align);
            if end > max_end {
                max_end = end;
            }
        }

        // Write SizeOfImage.
        let pe_off = self.pe_header_offset()?;
        let opt_off = pe_off + 4 + COFF_HDR_SIZE;
        if opt_off + 60 <= self.data.len() {
            write_u32(&mut self.data, opt_off + 56, max_end);
        }
        Ok(max_end)
    }

    fn log_op(&mut self, operation: &str, section: &str, detail: &str) {
        self.audit_log.push(SectionOpRecord {
            operation: operation.to_string(),
            section_name: section.to_string(),
            detail: detail.to_string(),
        });
    }
}

impl fmt::Debug for PeSectionEditor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeSectionEditor {{ buf={} ops={} }}",
            self.data.len(),
            self.audit_log.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Validate that `data` starts with MZ and has a valid PE signature.
///
/// # Errors
/// Returns [`EditError::InvalidAlignment`] if the buffer is too short or the MZ/PE signatures are missing.
pub fn validate_pe_magic(data: &[u8]) -> Result<(), EditError> {
    if data.len() < 64 {
        return Err(EditError::InvalidAlignment(
            "buffer too short to be a PE file".to_string(),
        ));
    }
    if data[0] != 0x4D || data[1] != 0x5A {
        return Err(EditError::InvalidAlignment("missing MZ magic".to_string()));
    }
    let pe_off = read_u32(data, 60) as usize;
    if pe_off + 4 > data.len() {
        return Err(EditError::InvalidAlignment(
            "PE offset beyond buffer".to_string(),
        ));
    }
    if &data[pe_off..pe_off + 4] != b"PE\x00\x00" {
        return Err(EditError::InvalidAlignment(
            "missing PE\\0\\0 signature".to_string(),
        ));
    }
    Ok(())
}

/// Read a section name from the section header at `off`.
#[must_use]
pub fn read_section_name(data: &[u8], off: usize) -> String {
    if off + 8 > data.len() {
        return String::new();
    }
    let name_bytes = &data[off..off + 8];
    let len = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8_lossy(&name_bytes[..len]).into_owned()
}

/// Write a section name into the section header at `off`.
pub fn write_section_name(data: &mut [u8], off: usize, name: &str) {
    let bytes = name.as_bytes();
    let copy = bytes.len().min(8);
    for i in 0..copy {
        if off + i < data.len() {
            data[off + i] = bytes[i];
        }
    }
    for i in copy..8 {
        if off + i < data.len() {
            data[off + i] = 0;
        }
    }
}

/// Parse one section header into a `SectionInfo`.
#[must_use]
pub fn parse_section_header(data: &[u8], off: usize, index: usize) -> SectionInfo {
    let name = read_section_name(data, off);
    SectionInfo {
        name,
        virtual_size: read_u32(data, off + 8),
        virtual_address: read_u32(data, off + 12),
        raw_size: read_u32(data, off + 16),
        raw_offset: read_u32(data, off + 20),
        characteristics: read_u32(data, off + 36),
        index,
    }
}

/// Align `value` up to the next multiple of `align`.
#[must_use]
pub const fn align_up(value: u32, align: u32) -> u32 {
    if align == 0 {
        return value;
    }
    // saturating_add prevents overflow when value is near u32::MAX.
    value.saturating_add(align - 1) / align * align
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
}

fn write_u32(data: &mut [u8], off: usize, val: u32) {
    if off + 4 <= data.len() {
        data[off..off + 4].copy_from_slice(&val.to_le_bytes());
    }
}

fn read_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn write_u16(data: &mut [u8], off: usize, val: u16) {
    if off + 2 <= data.len() {
        data[off..off + 2].copy_from_slice(&val.to_le_bytes());
    }
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
        assert_eq!(align_up(0x200, 0x200), 0x200);
        assert_eq!(align_up(0x201, 0x200), 0x400);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
    }

    #[test]
    fn section_info_flags() {
        let s = SectionInfo {
            name: ".text".to_string(),
            virtual_size: 0x100,
            virtual_address: 0x1000,
            raw_size: 0x200,
            raw_offset: 0x400,
            characteristics: 0x6000_0020,
            index: 0,
        };
        assert!(s.is_code());
        assert!(!s.is_writable());
    }

    #[test]
    fn new_section_code() {
        let s = NewSection::code(".inject", vec![0x90u8; 16]);
        assert!(s.characteristics & section_chars::CODE != 0);
        assert!(s.characteristics & section_chars::MEM_EXECUTE != 0);
    }

    #[test]
    fn new_section_data() {
        let s = NewSection::data(".extra", vec![0u8; 64]);
        assert!(s.characteristics & section_chars::MEM_WRITE != 0);
        assert!(s.characteristics & section_chars::MEM_EXECUTE == 0);
    }

    #[test]
    fn section_info_display() {
        let s = SectionInfo {
            name: ".rsrc".to_string(),
            virtual_size: 0x100,
            virtual_address: 0x3000,
            raw_size: 0x200,
            raw_offset: 0x800,
            characteristics: 0x4000_0040,
            index: 2,
        };
        let display = s.to_string();
        assert!(display.contains(".rsrc"));
        assert!(display.contains("0x00003000"));
    }

    #[test]
    fn validate_pe_magic_too_short() {
        assert!(validate_pe_magic(&[0x4D, 0x5A]).is_err());
    }

    #[test]
    fn validate_pe_magic_no_mz() {
        let data = vec![0u8; 64];
        assert!(validate_pe_magic(&data).is_err());
    }

    #[test]
    fn section_op_record_display() {
        let rec = SectionOpRecord {
            operation: "add".to_string(),
            section_name: ".text".to_string(),
            detail: "VA=0x1000".to_string(),
        };
        assert!(rec.to_string().contains("add"));
    }
}
