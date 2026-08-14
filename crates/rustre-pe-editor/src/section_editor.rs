//! PE section editor.
//!
//! Add, remove, resize, rename, change flags, and set raw content for PE sections.

pub use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::EditError;

// ─── SectionFlags ────────────────────────────────────────────────────────────

/// Section characteristic flags (PE `IMAGE_SCN`_*).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionFlags(pub u32);

impl SectionFlags {
    pub const CODE: u32 = 0x0000_0020;
    pub const INITIALIZED_DATA: u32 = 0x0000_0040;
    pub const UNINITIALIZED_DATA: u32 = 0x0000_0080;
    pub const LINK_REMOVE: u32 = 0x0000_0800;
    pub const GPREL: u32 = 0x0000_8000;
    pub const ALIGN_1BYTES: u32 = 0x0010_0000;
    pub const ALIGN_16BYTES: u32 = 0x0050_0000;
    pub const LNK_NRELOC_OVFL: u32 = 0x0100_0000;
    pub const MEM_DISCARDABLE: u32 = 0x0200_0000;
    pub const MEM_NOT_CACHED: u32 = 0x0400_0000;
    pub const MEM_NOT_PAGED: u32 = 0x0800_0000;
    pub const MEM_SHARED: u32 = 0x1000_0000;
    pub const MEM_EXECUTE: u32 = 0x2000_0000;
    pub const MEM_READ: u32 = 0x4000_0000;
    pub const MEM_WRITE: u32 = 0x8000_0000;

    /// Return a new flags value with the readable bit set/cleared.
    #[must_use]
    pub const fn with_read(mut self, v: bool) -> Self {
        if v {
            self.0 |= Self::MEM_READ;
        } else {
            self.0 &= !Self::MEM_READ;
        }
        self
    }

    /// Return a new flags value with the writable bit set/cleared.
    #[must_use]
    pub const fn with_write(mut self, v: bool) -> Self {
        if v {
            self.0 |= Self::MEM_WRITE;
        } else {
            self.0 &= !Self::MEM_WRITE;
        }
        self
    }

    /// Return a new flags value with the executable bit set/cleared.
    #[must_use]
    pub const fn with_execute(mut self, v: bool) -> Self {
        if v {
            self.0 |= Self::MEM_EXECUTE;
        } else {
            self.0 &= !Self::MEM_EXECUTE;
        }
        self
    }

    /// Standard .text section flags (readable + executable + code).
    #[must_use]
    pub const fn text() -> Self {
        Self(Self::CODE | Self::MEM_EXECUTE | Self::MEM_READ)
    }

    /// Standard .data section flags (readable + writable + initialized data).
    #[must_use]
    pub const fn data() -> Self {
        Self(Self::INITIALIZED_DATA | Self::MEM_READ | Self::MEM_WRITE)
    }

    /// Standard .rdata section flags (readable + initialized data).
    #[must_use]
    pub const fn rdata() -> Self {
        Self(Self::INITIALIZED_DATA | Self::MEM_READ)
    }

    /// Return true if the readable bit is set.
    #[must_use]
    pub const fn is_readable(self) -> bool {
        self.0 & Self::MEM_READ != 0
    }
    /// Return true if the writable bit is set.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        self.0 & Self::MEM_WRITE != 0
    }
    /// Return true if the executable bit is set.
    #[must_use]
    pub const fn is_executable(self) -> bool {
        self.0 & Self::MEM_EXECUTE != 0
    }
}

// ─── SectionOp ───────────────────────────────────────────────────────────────

/// A single section editing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SectionOp {
    /// Add a new section with the given name, virtual size, and flags.
    Add {
        name: String,
        virtual_size: u32,
        flags: SectionFlags,
        content: Vec<u8>,
    },
    /// Remove a section by name.
    Remove { name: String },
    /// Resize a section's raw data area.
    Resize { name: String, new_raw_size: u32 },
    /// Rename a section.
    Rename { old_name: String, new_name: String },
    /// Change section characteristic flags.
    ChangeFlags {
        name: String,
        new_flags: SectionFlags,
    },
    /// Replace the raw content of a section.
    SetContent { name: String, content: Vec<u8> },
    /// Align the section's raw size to the given boundary.
    AlignRaw { name: String, alignment: u32 },
    /// Set the virtual size of a section.
    SetVirtualSize { name: String, virtual_size: u32 },
}

impl SectionOp {
    /// Return the target section name for this operation.
    #[must_use]
    pub fn section_name(&self) -> &str {
        match self {
            Self::Rename { old_name, .. } => old_name,
            Self::Add { name, .. }
            | Self::Remove { name }
            | Self::Resize { name, .. }
            | Self::ChangeFlags { name, .. }
            | Self::SetContent { name, .. }
            | Self::AlignRaw { name, .. }
            | Self::SetVirtualSize { name, .. } => name,
        }
    }

    /// Return a human-readable description of this operation.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Add {
                name, virtual_size, ..
            } => format!("Add section '{name}' vsize={virtual_size:#x}"),
            Self::Remove { name } => format!("Remove section '{name}'"),
            Self::Resize { name, new_raw_size } => format!("Resize '{name}' raw→{new_raw_size:#x}"),
            Self::Rename { old_name, new_name } => format!("Rename '{old_name}'→'{new_name}'"),
            Self::ChangeFlags { name, new_flags } => {
                format!("Flags '{name}'→{:#010x}", new_flags.0)
            }
            Self::SetContent { name, content } => {
                format!("SetContent '{name}' {} bytes", content.len())
            }
            Self::AlignRaw { name, alignment } => format!("AlignRaw '{name}' to {alignment}"),
            Self::SetVirtualSize { name, virtual_size } => {
                format!("SetVSize '{name}'→{virtual_size:#x}")
            }
        }
    }
}

// ─── EditResult ──────────────────────────────────────────────────────────────

/// Result of a section editing batch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EditResult {
    /// Operations that were applied.
    pub applied: Vec<String>,
    /// Operations that failed, with error messages.
    pub failed: Vec<(String, String)>,
    /// Whether the result should be re-checksummed.
    pub needs_checksum_update: bool,
}

impl EditResult {
    /// Return true if all operations succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.failed.is_empty()
    }

    /// Return the total count of applied operations.
    #[must_use]
    pub const fn applied_count(&self) -> usize {
        self.applied.len()
    }

    /// Return the total count of all operations (applied + failed).
    #[must_use]
    pub const fn total_matches(&self) -> usize {
        self.applied.len() + self.failed.len()
    }
}

// ─── SectionRecord ───────────────────────────────────────────────────────────

/// In-memory representation of a PE section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionRecord {
    /// Section name (max 8 bytes).
    pub name: String,
    /// Virtual size.
    pub virtual_size: u32,
    /// Virtual address (RVA).
    pub virtual_address: u32,
    /// Raw data size (aligned to file alignment).
    pub raw_size: u32,
    /// Raw data file offset.
    pub raw_offset: u32,
    /// Section characteristic flags.
    pub flags: SectionFlags,
    /// Raw bytes of the section.
    pub data: Vec<u8>,
}

impl SectionRecord {
    /// Create a new section with auto-computed `raw_size` from content.
    ///
    /// # Panics
    /// Panics if `content.len()` exceeds `u32::MAX`.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        virtual_address: u32,
        flags: SectionFlags,
        content: Vec<u8>,
    ) -> Self {
        let raw_size = u32::try_from(content.len()).expect("section content fits in u32");
        let virtual_size = raw_size;
        Self {
            name: name.into(),
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset: 0,
            flags,
            data: content,
        }
    }

    /// Return entropy of this section's data.
    #[must_use]
    pub fn entropy(&self) -> f64 {
        if self.data.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for &b in &self.data {
            counts[b as usize] = counts[b as usize].saturating_add(1);
        }
        let len = f64::from(u32::try_from(self.data.len()).unwrap_or(u32::MAX));
        let mut h = 0.0f64;
        for &c in &counts {
            if c > 0 {
                let p = f64::from(c) / len;
                h = p.mul_add(-p.log2(), h);
            }
        }
        h
    }
}

// ─── SectionFlagEditor ───────────────────────────────────────────────────────

/// Convenience type for editing section flags.
pub struct SectionFlagEditor;

impl SectionFlagEditor {
    /// Make a section executable (add `MEM_EXECUTE` + CODE).
    #[must_use]
    pub const fn make_executable(flags: SectionFlags) -> SectionFlags {
        SectionFlags(flags.0 | SectionFlags::MEM_EXECUTE | SectionFlags::CODE)
    }

    /// Remove execute permission.
    #[must_use]
    pub const fn remove_execute(flags: SectionFlags) -> SectionFlags {
        SectionFlags(flags.0 & !(SectionFlags::MEM_EXECUTE | SectionFlags::CODE))
    }

    /// Make a section writable.
    #[must_use]
    pub const fn make_writable(flags: SectionFlags) -> SectionFlags {
        SectionFlags(flags.0 | SectionFlags::MEM_WRITE)
    }

    /// Remove write permission.
    #[must_use]
    pub const fn remove_write(flags: SectionFlags) -> SectionFlags {
        SectionFlags(flags.0 & !SectionFlags::MEM_WRITE)
    }

    /// Make a section read-only.
    #[must_use]
    pub const fn make_readonly(flags: SectionFlags) -> SectionFlags {
        SectionFlags((flags.0 & !SectionFlags::MEM_WRITE) | SectionFlags::MEM_READ)
    }
}

// ─── VirtualSizeEditor ───────────────────────────────────────────────────────

/// Adjusts virtual sizes across a section list.
pub struct VirtualSizeEditor;

impl VirtualSizeEditor {
    /// Recompute virtual addresses for a list of sections using the given
    /// image base, section alignment, and file alignment.
    pub fn rebase_sections(
        sections: &mut [SectionRecord],
        first_section_rva: u32,
        section_alignment: u32,
    ) {
        let align = |v: u32, a: u32| -> u32 { if a == 0 { v } else { (v + a - 1) & !(a - 1) } };
        let mut rva = first_section_rva;
        for sec in sections.iter_mut() {
            sec.virtual_address = rva;
            rva += align(sec.virtual_size.max(sec.raw_size), section_alignment);
        }
    }

    /// Set the virtual size of a named section.
    pub fn set_virtual_size(sections: &mut [SectionRecord], name: &str, new_vsize: u32) -> bool {
        for sec in sections.iter_mut() {
            if sec.name == name {
                sec.virtual_size = new_vsize;
                return true;
            }
        }
        false
    }
}

// ─── RawDataEditor ───────────────────────────────────────────────────────────

/// Edits raw data within a section.
pub struct RawDataEditor;

impl RawDataEditor {
    /// Patch bytes at a given offset within section data.
    ///
    /// # Errors
    /// Returns [`EditError::PatchOutOfBounds`] if `offset + bytes.len() > section.data.len()`.
    pub fn patch(
        section: &mut SectionRecord,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), EditError> {
        if offset + bytes.len() > section.data.len() {
            return Err(EditError::PatchOutOfBounds {
                offset,
                len: bytes.len(),
                file_size: section.data.len(),
            });
        }
        section.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Extend section data to a minimum size, padding with zeros.
    ///
    /// # Panics
    /// Panics if `min_size` exceeds `u32::MAX`.
    pub fn pad_to(section: &mut SectionRecord, min_size: usize) {
        if section.data.len() < min_size {
            section.data.resize(min_size, 0);
            section.raw_size = u32::try_from(section.data.len()).expect("section data fits in u32");
        }
    }

    /// Align raw size of the section data to the given boundary.
    ///
    /// # Panics
    /// Panics if the aligned size exceeds `u32::MAX`.
    pub fn align(section: &mut SectionRecord, alignment: u32) {
        if alignment == 0 {
            return;
        }
        let a = alignment as usize;
        let current = section.data.len();
        let needed = (current + a - 1) & !(a - 1);
        if needed > current {
            section.data.resize(needed, 0);
            section.raw_size = u32::try_from(needed).expect("aligned size fits in u32");
        }
    }
}

// ─── SectionEditor ───────────────────────────────────────────────────────────

/// High-level PE section editor.
///
/// Maintains a list of [`SectionRecord`]s and applies [`SectionOp`] operations.
pub struct SectionEditor {
    sections: Vec<SectionRecord>,
    /// File alignment (default 0x200).
    pub file_alignment: u32,
    /// Section alignment (default 0x1000).
    pub section_alignment: u32,
    /// Description of the most recently applied operation, for diagnostics.
    pub last_op_description: Option<String>,
}

impl SectionEditor {
    /// Create a new editor from an existing section list.
    #[must_use]
    pub const fn new(sections: Vec<SectionRecord>) -> Self {
        Self {
            sections,
            file_alignment: 0x200,
            section_alignment: 0x1000,
            last_op_description: None,
        }
    }

    /// Create an empty editor.
    #[must_use]
    pub const fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Return a reference to the section list.
    #[must_use]
    pub fn sections(&self) -> &[SectionRecord] {
        &self.sections
    }

    /// Return a mutable reference to the section list.
    pub const fn sections_mut(&mut self) -> &mut Vec<SectionRecord> {
        &mut self.sections
    }

    /// Return the number of sections.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.sections.len()
    }

    /// Find a section by name.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&SectionRecord> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Apply a single section operation.
    ///
    /// # Errors
    /// Returns [`EditError`] if the target section is not found or an operation-specific constraint is violated.
    ///
    /// # Panics
    /// Panics if any computed section size exceeds `u32::MAX`.
    pub fn apply(&mut self, op: SectionOp) -> Result<(), EditError> {
        let desc = op.describe();
        self.last_op_description = Some(desc);
        match op {
            SectionOp::Add {
                name,
                virtual_size,
                flags,
                content,
            } => {
                if self.sections.iter().any(|s| s.name == name) {
                    return Err(EditError::SectionNotFound(format!(
                        "section '{name}' already exists"
                    )));
                }
                // Compute RVA: place after last section
                let rva = self
                    .sections
                    .last()
                    .map_or(self.section_alignment, |s| {
                        let end = s.virtual_address + s.virtual_size;
                        let a = self.section_alignment;
                        (end + a - 1) & !(a - 1)
                    });
                let mut sec = SectionRecord::new(&name, rva, flags, content);
                sec.virtual_size = virtual_size;
                self.sections.push(sec);
            }
            SectionOp::Remove { name } => {
                let pos = self
                    .sections
                    .iter()
                    .position(|s| s.name == name)
                    .ok_or_else(|| EditError::SectionNotFound(name.clone()))?;
                self.sections.remove(pos);
            }
            SectionOp::Resize { name, new_raw_size } => {
                let sec = self
                    .sections
                    .iter_mut()
                    .find(|s| s.name == name)
                    .ok_or_else(|| EditError::SectionNotFound(name.clone()))?;
                sec.data.resize(new_raw_size as usize, 0);
                sec.raw_size = new_raw_size;
            }
            SectionOp::Rename { old_name, new_name } => {
                if new_name.len() > 8 {
                    return Err(EditError::InvalidAlignment(
                        "section name too long (max 8 bytes)".to_owned(),
                    ));
                }
                let sec = self
                    .sections
                    .iter_mut()
                    .find(|s| s.name == old_name)
                    .ok_or_else(|| EditError::SectionNotFound(old_name.clone()))?;
                sec.name = new_name;
            }
            SectionOp::ChangeFlags { name, new_flags } => {
                let sec = self
                    .sections
                    .iter_mut()
                    .find(|s| s.name == name)
                    .ok_or_else(|| EditError::SectionNotFound(name.clone()))?;
                sec.flags = new_flags;
            }
            SectionOp::SetContent { name, content } => {
                let sec = self
                    .sections
                    .iter_mut()
                    .find(|s| s.name == name)
                    .ok_or_else(|| EditError::SectionNotFound(name.clone()))?;
                sec.raw_size = u32::try_from(content.len()).expect("content fits in u32");
                sec.virtual_size = sec.raw_size;
                sec.data = content;
            }
            SectionOp::AlignRaw { name, alignment } => {
                let sec = self
                    .sections
                    .iter_mut()
                    .find(|s| s.name == name)
                    .ok_or_else(|| EditError::SectionNotFound(name.clone()))?;
                RawDataEditor::align(sec, alignment);
            }
            SectionOp::SetVirtualSize { name, virtual_size } => {
                let sec = self
                    .sections
                    .iter_mut()
                    .find(|s| s.name == name)
                    .ok_or_else(|| EditError::SectionNotFound(name.clone()))?;
                sec.virtual_size = virtual_size;
            }
        }
        Ok(())
    }

    /// Apply a batch of operations, collecting results.
    pub fn apply_batch(&mut self, ops: Vec<SectionOp>) -> EditResult {
        let mut result = EditResult::default();
        for op in ops {
            let desc = op.describe();
            match self.apply(op) {
                Ok(()) => result.applied.push(desc),
                Err(e) => result.failed.push((desc, e.to_string())),
            }
        }
        result.needs_checksum_update = !result.applied.is_empty();
        result
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn text_section() -> SectionRecord {
        SectionRecord::new(".text", 0x1000, SectionFlags::text(), vec![0x90u8; 256])
    }

    fn data_section() -> SectionRecord {
        SectionRecord::new(".data", 0x2000, SectionFlags::data(), vec![0u8; 128])
    }

    #[test]
    fn test_section_flags_text() {
        let f = SectionFlags::text();
        assert!(f.is_readable());
        assert!(f.is_executable());
        assert!(!f.is_writable());
    }

    #[test]
    fn test_section_flags_data() {
        let f = SectionFlags::data();
        assert!(f.is_readable());
        assert!(f.is_writable());
        assert!(!f.is_executable());
    }

    #[test]
    fn test_section_flags_rdata() {
        let f = SectionFlags::rdata();
        assert!(f.is_readable());
        assert!(!f.is_writable());
        assert!(!f.is_executable());
    }

    #[test]
    fn test_section_flags_with_write() {
        let f = SectionFlags::rdata().with_write(true);
        assert!(f.is_writable());
    }

    #[test]
    fn test_section_flags_remove_execute() {
        let f = SectionFlagEditor::remove_execute(SectionFlags::text());
        assert!(!f.is_executable());
    }

    #[test]
    fn test_section_flag_editor_make_writable() {
        let f = SectionFlagEditor::make_writable(SectionFlags::rdata());
        assert!(f.is_writable());
    }

    #[test]
    fn test_section_flag_editor_make_readonly() {
        let f = SectionFlagEditor::make_readonly(SectionFlags::data());
        assert!(!f.is_writable());
        assert!(f.is_readable());
    }

    #[test]
    fn test_section_editor_add() {
        let mut ed = SectionEditor::empty();
        let op = SectionOp::Add {
            name: ".new".to_owned(),
            virtual_size: 0x1000,
            flags: SectionFlags::text(),
            content: vec![0x90; 64],
        };
        assert!(ed.apply(op).is_ok());
        assert_eq!(ed.count(), 1);
        assert!(ed.find(".new").is_some());
    }

    #[test]
    fn test_section_editor_remove() {
        let mut ed = SectionEditor::new(vec![text_section(), data_section()]);
        ed.apply(SectionOp::Remove {
            name: ".text".to_owned(),
        })
        .unwrap();
        assert_eq!(ed.count(), 1);
        assert!(ed.find(".text").is_none());
    }

    #[test]
    fn test_section_editor_rename() {
        let mut ed = SectionEditor::new(vec![text_section()]);
        ed.apply(SectionOp::Rename {
            old_name: ".text".to_owned(),
            new_name: ".code".to_owned(),
        })
        .unwrap();
        assert!(ed.find(".code").is_some());
        assert!(ed.find(".text").is_none());
    }

    #[test]
    fn test_section_editor_rename_too_long() {
        let mut ed = SectionEditor::new(vec![text_section()]);
        let result = ed.apply(SectionOp::Rename {
            old_name: ".text".to_owned(),
            new_name: ".toolongname".to_owned(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_section_editor_change_flags() {
        let mut ed = SectionEditor::new(vec![text_section()]);
        let new_flags = SectionFlags::data();
        ed.apply(SectionOp::ChangeFlags {
            name: ".text".to_owned(),
            new_flags,
        })
        .unwrap();
        let sec = ed.find(".text").unwrap();
        assert!(sec.flags.is_writable());
    }

    #[test]
    fn test_section_editor_set_content() {
        let mut ed = SectionEditor::new(vec![text_section()]);
        let new_content = vec![0xCCu8; 512];
        ed.apply(SectionOp::SetContent {
            name: ".text".to_owned(),
            content: new_content.clone(),
        })
        .unwrap();
        let sec = ed.find(".text").unwrap();
        assert_eq!(sec.data, new_content);
        assert_eq!(sec.raw_size, 512);
    }

    #[test]
    fn test_section_editor_resize() {
        let mut ed = SectionEditor::new(vec![text_section()]);
        ed.apply(SectionOp::Resize {
            name: ".text".to_owned(),
            new_raw_size: 512,
        })
        .unwrap();
        let sec = ed.find(".text").unwrap();
        assert_eq!(sec.raw_size, 512);
        assert_eq!(sec.data.len(), 512);
    }

    #[test]
    fn test_section_editor_align_raw() {
        let mut ed = SectionEditor::new(vec![SectionRecord::new(
            ".data",
            0x1000,
            SectionFlags::data(),
            vec![0u8; 100],
        )]);
        ed.apply(SectionOp::AlignRaw {
            name: ".data".to_owned(),
            alignment: 512,
        })
        .unwrap();
        let sec = ed.find(".data").unwrap();
        assert_eq!(sec.raw_size % 512, 0);
    }

    #[test]
    fn test_section_editor_set_virtual_size() {
        let mut ed = SectionEditor::new(vec![text_section()]);
        ed.apply(SectionOp::SetVirtualSize {
            name: ".text".to_owned(),
            virtual_size: 0x2000,
        })
        .unwrap();
        assert_eq!(ed.find(".text").unwrap().virtual_size, 0x2000);
    }

    #[test]
    fn test_section_editor_not_found_error() {
        let mut ed = SectionEditor::empty();
        let result = ed.apply(SectionOp::Remove {
            name: ".nonexistent".to_owned(),
        });
        assert!(matches!(result, Err(EditError::SectionNotFound(_))));
    }

    #[test]
    fn test_section_editor_batch() {
        let mut ed = SectionEditor::new(vec![text_section(), data_section()]);
        let ops = vec![
            SectionOp::Rename {
                old_name: ".text".to_owned(),
                new_name: ".code".to_owned(),
            },
            SectionOp::ChangeFlags {
                name: ".data".to_owned(),
                new_flags: SectionFlags::rdata(),
            },
        ];
        let result = ed.apply_batch(ops);
        assert!(result.is_success());
        assert_eq!(result.applied_count(), 2);
    }

    #[test]
    fn test_raw_data_editor_patch() {
        let mut sec = text_section();
        let patch = vec![0xCCu8, 0xCCu8];
        RawDataEditor::patch(&mut sec, 0, &patch).unwrap();
        assert_eq!(sec.data[0], 0xCC);
        assert_eq!(sec.data[1], 0xCC);
    }

    #[test]
    fn test_raw_data_editor_pad_to() {
        let mut sec = SectionRecord::new(".pad", 0x1000, SectionFlags::data(), vec![0u8; 10]);
        RawDataEditor::pad_to(&mut sec, 64);
        assert_eq!(sec.data.len(), 64);
    }

    #[test]
    fn test_section_entropy() {
        let sec = SectionRecord::new(
            ".entropy",
            0x1000,
            SectionFlags::data(),
            (0u8..=255u8).collect(),
        );
        let e = sec.entropy();
        // Uniform distribution over 256 values should have entropy close to 8.0
        assert!((e - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_virtual_size_editor_rebase() {
        let mut sections = vec![
            SectionRecord::new(".text", 0x1000, SectionFlags::text(), vec![0u8; 0x500]),
            SectionRecord::new(".data", 0x2000, SectionFlags::data(), vec![0u8; 0x300]),
        ];
        VirtualSizeEditor::rebase_sections(&mut sections, 0x1000, 0x1000);
        assert_eq!(sections[0].virtual_address, 0x1000);
        assert!(sections[1].virtual_address >= 0x2000);
    }

    #[test]
    fn test_section_flags_mem_shared() {
        let f = SectionFlags(SectionFlags::MEM_SHARED);
        assert_eq!(f.0 & SectionFlags::MEM_SHARED, SectionFlags::MEM_SHARED);
    }

    #[test]
    fn test_section_flags_code() {
        let f = SectionFlags(SectionFlags::CODE);
        assert_eq!(f.0 & SectionFlags::CODE, SectionFlags::CODE);
    }

    #[test]
    fn test_section_flags_not_cached() {
        let f = SectionFlags(SectionFlags::MEM_NOT_CACHED);
        assert_eq!(
            f.0 & SectionFlags::MEM_NOT_CACHED,
            SectionFlags::MEM_NOT_CACHED
        );
    }

    #[test]
    fn test_section_editor_add_multiple() {
        let mut ed = SectionEditor::empty();
        for i in 0..5u32 {
            ed.apply(SectionOp::Add {
                name: format!(".s{i}"),
                virtual_size: 0x1000,
                flags: SectionFlags::data(),
                content: vec![i as u8; 16],
            })
            .unwrap();
        }
        assert_eq!(ed.count(), 5);
    }

    #[test]
    fn test_raw_data_editor_patch_out_of_bounds() {
        let mut sec = SectionRecord::new(".x", 0x1000, SectionFlags::data(), vec![0u8; 8]);
        let result = RawDataEditor::patch(&mut sec, 7, &[0xAA, 0xBB]);
        assert!(matches!(result, Err(EditError::PatchOutOfBounds { .. })));
    }

    #[test]
    fn test_section_editor_remove_not_found() {
        let mut ed = SectionEditor::empty();
        let result = ed.apply(SectionOp::Remove {
            name: ".ghost".to_owned(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_section_record_new_raw_size() {
        let sec = SectionRecord::new(".test", 0x1000, SectionFlags::text(), vec![0u8; 0x200]);
        assert_eq!(sec.raw_size, 0x200);
        assert_eq!(sec.virtual_size, 0x200);
    }

    #[test]
    fn test_virtual_size_editor_set() {
        let mut sections = vec![SectionRecord::new(
            ".bss",
            0x1000,
            SectionFlags::data(),
            vec![],
        )];
        let changed = VirtualSizeEditor::set_virtual_size(&mut sections, ".bss", 0x5000);
        assert!(changed);
        assert_eq!(sections[0].virtual_size, 0x5000);
    }

    #[test]
    fn test_virtual_size_editor_not_found() {
        let mut sections: Vec<SectionRecord> = Vec::new();
        let changed = VirtualSizeEditor::set_virtual_size(&mut sections, ".none", 0x1000);
        assert!(!changed);
    }

    #[test]
    fn test_section_entropy_uniform() {
        let sec = SectionRecord::new(".flat", 0x1000, SectionFlags::data(), vec![0xAA; 256]);
        let e = sec.entropy();
        // All same bytes → entropy = 0
        assert_eq!(e, 0.0);
    }

    #[test]
    fn test_edit_result_failed_count() {
        let result = EditResult {
            applied: vec!["ok".to_owned()],
            failed: vec![("bad".to_owned(), "err".to_owned())],
            needs_checksum_update: false,
        };
        assert!(!result.is_success());
        assert_eq!(result.total_matches(), 2);
    }
}
