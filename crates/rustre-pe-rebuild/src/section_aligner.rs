//! PE section alignment fixer.
//!
//! When a PE is rebuilt from a memory dump or partially corrupt file, raw
//! section sizes and file offsets often violate the `FileAlignment` and
//! `SectionAlignment` constraints documented in the PE specification
//! (Microsoft PE/COFF §3.3).
//!
//! [`SectionAligner`] inspects each section and emits an [`AlignmentFix`] for
//! every section whose raw or virtual size is not properly rounded.

// ── AlignmentFix ─────────────────────────────────────────────────────────────

/// A single alignment correction for one section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlignmentFix {
    /// Zero-based index of the section in the section table.
    pub section_index: usize,
    /// Section name (max 8 chars in PE; may be truncated).
    pub section_name: String,
    /// Old raw (on-disk) size before alignment.
    pub old_raw_size: u32,
    /// New raw (on-disk) size after alignment to `FileAlignment`.
    pub new_raw_size: u32,
    /// Old virtual size before alignment.
    pub old_virtual_size: u32,
    /// New virtual size after alignment to `SectionAlignment`.
    pub new_virtual_size: u32,
    /// Old file offset before adjustment.
    pub old_file_offset: u32,
    /// New file offset after adjustment.
    pub new_file_offset: u32,
}

impl AlignmentFix {
    /// Return `true` if any value actually changed.
    #[must_use]
    pub const fn has_change(&self) -> bool {
        self.old_raw_size != self.new_raw_size
            || self.old_virtual_size != self.new_virtual_size
            || self.old_file_offset != self.new_file_offset
    }
}

// ── AlignmentReport ──────────────────────────────────────────────────────────

/// Summary of all alignment corrections applied to a PE.
#[derive(Debug, Clone, Default)]
pub struct AlignmentReport {
    /// All fixes, including no-op ones (see [`AlignmentFix::has_change`]).
    pub fixes: Vec<AlignmentFix>,
    /// The `FileAlignment` value used.
    pub file_alignment: u32,
    /// The `SectionAlignment` value used.
    pub section_alignment: u32,
}

impl AlignmentReport {
    /// Return only the fixes that actually modified something.
    #[must_use]
    pub fn actual_fixes(&self) -> Vec<&AlignmentFix> {
        self.fixes.iter().filter(|f| f.has_change()).collect()
    }

    /// Return the number of sections that were corrected.
    #[must_use]
    pub fn corrected_count(&self) -> usize {
        self.fixes.iter().filter(|f| f.has_change()).count()
    }

    /// Return `true` if any section needed correction.
    #[must_use]
    pub fn needs_correction(&self) -> bool {
        self.fixes.iter().any(AlignmentFix::has_change)
    }
}

impl std::fmt::Display for AlignmentReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AlignmentReport(file_align=0x{:x}, sect_align=0x{:x}, corrected={}/{})",
            self.file_alignment,
            self.section_alignment,
            self.corrected_count(),
            self.fixes.len(),
        )
    }
}

// ── SectionDescriptor ────────────────────────────────────────────────────────

/// A lightweight description of a PE section, sufficient for alignment analysis.
#[derive(Debug, Clone)]
pub struct SectionDescriptor {
    /// Section name (at most 8 bytes, UTF-8 best-effort).
    pub name: String,
    /// `VirtualSize` — actual bytes used at run time.
    pub virtual_size: u32,
    /// `VirtualAddress` — RVA of the section.
    pub virtual_address: u32,
    /// `SizeOfRawData` — on-disk size.
    pub raw_size: u32,
    /// `PointerToRawData` — file offset of the section data.
    pub raw_offset: u32,
}

impl SectionDescriptor {
    /// Create a new descriptor.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        virtual_size: u32,
        virtual_address: u32,
        raw_size: u32,
        raw_offset: u32,
    ) -> Self {
        Self {
            name: name.into(),
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
        }
    }
}

// ── SectionAligner ────────────────────────────────────────────────────────────

/// Aligns section raw and virtual sizes to `FileAlignment` and `SectionAlignment`.
pub struct SectionAligner {
    /// PE optional header `FileAlignment` (typically 0x200 or 0x1000).
    pub file_alignment: u32,
    /// PE optional header `SectionAlignment` (typically 0x1000).
    pub section_alignment: u32,
}

impl SectionAligner {
    /// Construct with explicit alignment values.
    ///
    /// # Panics
    /// Panics if either alignment is 0.
    #[must_use]
    pub fn new(file_alignment: u32, section_alignment: u32) -> Self {
        assert!(file_alignment > 0, "file_alignment must be > 0");
        assert!(section_alignment > 0, "section_alignment must be > 0");
        Self {
            file_alignment,
            section_alignment,
        }
    }

    /// Create with standard PE defaults (0x200 / 0x1000).
    #[must_use]
    pub fn default_pe() -> Self {
        Self::new(0x200, 0x1000)
    }

    /// Align `value` up to the next multiple of `align`.
    #[must_use]
    pub const fn align_up(value: u32, align: u32) -> u32 {
        if align == 0 {
            return value;
        }
        value.saturating_add(align - 1) & !(align - 1)
    }

    /// Compute the aligned fix for a single section.
    #[must_use]
    pub fn fix_section(&self, index: usize, section: &SectionDescriptor) -> AlignmentFix {
        let new_virtual_size = Self::align_up(section.virtual_size, self.section_alignment);
        let new_raw_size = Self::align_up(section.raw_size, self.file_alignment);
        let new_file_offset = Self::align_up(section.raw_offset, self.file_alignment);
        AlignmentFix {
            section_index: index,
            section_name: section.name.clone(),
            old_raw_size: section.raw_size,
            new_raw_size,
            old_virtual_size: section.virtual_size,
            new_virtual_size,
            old_file_offset: section.raw_offset,
            new_file_offset,
        }
    }

    /// Process all sections and return a complete [`AlignmentReport`].
    #[must_use]
    pub fn align_all(&self, sections: &[SectionDescriptor]) -> AlignmentReport {
        let fixes: Vec<AlignmentFix> = sections
            .iter()
            .enumerate()
            .map(|(i, s)| self.fix_section(i, s))
            .collect();
        AlignmentReport {
            fixes,
            file_alignment: self.file_alignment,
            section_alignment: self.section_alignment,
        }
    }

    /// Repack file offsets so each section immediately follows the previous one,
    /// with each offset aligned to `FileAlignment`.  Returns a new list of
    /// corrected sections.
    #[must_use]
    pub fn repack_offsets(
        &self,
        sections: &[SectionDescriptor],
        headers_size: u32,
    ) -> Vec<SectionDescriptor> {
        let mut out = Vec::with_capacity(sections.len());
        let mut next_offset = Self::align_up(headers_size, self.file_alignment);
        for s in sections {
            let raw_size = Self::align_up(s.raw_size, self.file_alignment);
            out.push(SectionDescriptor::new(
                s.name.clone(),
                s.virtual_size,
                s.virtual_address,
                raw_size,
                next_offset,
            ));
            next_offset += raw_size;
        }
        out
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn text_section(raw_size: u32, raw_offset: u32) -> SectionDescriptor {
        SectionDescriptor::new(".text", raw_size, 0x1000, raw_size, raw_offset)
    }

    #[test]
    fn test_align_up_already_aligned() {
        assert_eq!(SectionAligner::align_up(0x200, 0x200), 0x200);
        assert_eq!(SectionAligner::align_up(0x1000, 0x1000), 0x1000);
    }

    #[test]
    fn test_align_up_rounds_up() {
        assert_eq!(SectionAligner::align_up(0x201, 0x200), 0x400);
        assert_eq!(SectionAligner::align_up(1, 0x200), 0x200);
        assert_eq!(SectionAligner::align_up(0, 0x200), 0);
    }

    #[test]
    fn test_fix_section_already_aligned() {
        let aligner = SectionAligner::default_pe();
        let section = SectionDescriptor::new(".text", 0x1000, 0x1000, 0x200, 0x200);
        let fix = aligner.fix_section(0, &section);
        assert!(!fix.has_change());
    }

    #[test]
    fn test_fix_section_needs_alignment() {
        let aligner = SectionAligner::default_pe();
        let section = text_section(0x150, 0x100); // 0x100 not aligned to 0x200
        let fix = aligner.fix_section(0, &section);
        assert!(fix.has_change());
        assert_eq!(fix.new_raw_size, 0x200);
        assert_eq!(fix.new_file_offset, 0x200);
    }

    #[test]
    fn test_align_all_report() {
        let aligner = SectionAligner::default_pe();
        let sections = vec![
            SectionDescriptor::new(".text", 0x1234, 0x1000, 0x1234, 0x400),
            SectionDescriptor::new(".rdata", 0x500, 0x3000, 0x500, 0x400), // bad offset
        ];
        let report = aligner.align_all(&sections);
        assert_eq!(report.fixes.len(), 2);
        assert!(report.needs_correction());
    }

    #[test]
    fn test_report_corrected_count() {
        let aligner = SectionAligner::default_pe();
        let sections = vec![
            SectionDescriptor::new(".text", 0x1000, 0x1000, 0x200, 0x200), // clean
            SectionDescriptor::new(".data", 0x800, 0x2000, 0x150, 0x100),  // needs fix
        ];
        let report = aligner.align_all(&sections);
        assert_eq!(report.corrected_count(), 1);
    }

    #[test]
    fn test_repack_offsets() {
        let aligner = SectionAligner::default_pe();
        let sections = vec![
            SectionDescriptor::new(".text", 0x1000, 0x1000, 0x150, 0x400),
            SectionDescriptor::new(".data", 0x800, 0x2000, 0x300, 0x800),
        ];
        let repacked = aligner.repack_offsets(&sections, 0x400);
        // first section starts at aligned(0x400, 0x200) = 0x400
        assert_eq!(repacked[0].raw_offset, 0x400);
        // raw_size of first = align_up(0x150, 0x200) = 0x200
        // second section starts at 0x400 + 0x200 = 0x600
        assert_eq!(repacked[1].raw_offset, 0x600);
    }

    #[test]
    fn test_report_display_contains_alignment_values() {
        let aligner = SectionAligner::default_pe();
        let report = aligner.align_all(&[]);
        let s = report.to_string();
        assert!(s.contains("200")); // 0x200 in hex
        assert!(s.contains("1000")); // 0x1000 in hex
    }
}
