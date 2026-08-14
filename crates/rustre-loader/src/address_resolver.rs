//! Address resolution for loaded binaries.
//!
//! Provides [`AddressResolver`] for mapping virtual addresses (VAs) to file
//! offsets and vice-versa. Supports PE relative virtual addresses (RVAs),
//! position-independent executable (PIE) rebasing, and multi-segment binaries.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// SectionEntry
// ─────────────────────────────────────────────────────────────────────────────

/// One entry in a [`SectionMap`] — a contiguous mapping between file bytes and
/// virtual memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionEntry {
    /// Virtual address at which this section begins.
    pub va_start: u64,
    /// Exclusive end of the virtual range (`va_start + virtual_size`).
    pub va_end: u64,
    /// Raw file offset of the first byte of this section.
    pub file_offset: u64,
    /// Size of the section on disk (may be smaller than the virtual size).
    pub file_size: u64,
    /// Human-readable section name, e.g. `.text`.
    pub name: String,
}

impl SectionEntry {
    /// Construct a new [`SectionEntry`].
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        va_start: u64,
        virtual_size: u64,
        file_offset: u64,
        file_size: u64,
    ) -> Self {
        Self {
            name: name.into(),
            va_start,
            va_end: va_start.saturating_add(virtual_size),
            file_offset,
            file_size,
        }
    }

    /// Return `true` if `va` falls within this section's virtual range.
    #[must_use]
    pub const fn contains_va(&self, va: u64) -> bool {
        va >= self.va_start && va < self.va_end
    }

    /// Convert `va` to a file offset.
    ///
    /// Returns `None` when `va` is outside this section or the resulting file
    /// offset would exceed `file_size`.
    #[must_use]
    pub const fn va_to_offset(&self, va: u64) -> Option<u64> {
        if !self.contains_va(va) {
            return None;
        }
        let delta = va - self.va_start;
        if delta >= self.file_size {
            return None;
        }
        Some(self.file_offset + delta)
    }

    /// Convert a file offset to a VA.
    ///
    /// Returns `None` when `offset` is outside this section's file range.
    #[must_use]
    pub const fn offset_to_va(&self, offset: u64) -> Option<u64> {
        if offset < self.file_offset || offset >= self.file_offset + self.file_size {
            return None;
        }
        let delta = offset - self.file_offset;
        Some(self.va_start + delta)
    }

    /// Virtual size of this section.
    #[must_use]
    pub const fn virtual_size(&self) -> u64 {
        self.va_end.saturating_sub(self.va_start)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SectionMap
// ─────────────────────────────────────────────────────────────────────────────

/// A sorted collection of [`SectionEntry`] records that supports O(log n)
/// address-to-offset lookups via binary search.
#[derive(Debug, Clone, Default)]
pub struct SectionMap {
    /// Sorted by `va_start` ascending.
    entries: Vec<SectionEntry>,
}

impl SectionMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a section and maintain the sorted invariant.
    pub fn insert(&mut self, entry: SectionEntry) {
        let pos = self
            .entries
            .partition_point(|e| e.va_start <= entry.va_start);
        self.entries.insert(pos, entry);
    }

    /// Find the section whose virtual range contains `va`.
    #[must_use]
    pub fn find_by_va(&self, va: u64) -> Option<&SectionEntry> {
        // Binary search for the rightmost entry with va_start <= va.
        let idx = self.entries.partition_point(|e| e.va_start <= va);
        if idx == 0 {
            return None;
        }
        let candidate = &self.entries[idx - 1];
        if candidate.contains_va(va) {
            Some(candidate)
        } else {
            None
        }
    }

    /// Find the section whose file range contains `offset`.
    #[must_use]
    pub fn find_by_offset(&self, offset: u64) -> Option<&SectionEntry> {
        self.entries
            .iter()
            .find(|e| offset >= e.file_offset && offset < e.file_offset + e.file_size)
    }

    /// Find a section by name (first match, case-sensitive).
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&SectionEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Convert a VA to a file offset using the section table.
    #[must_use]
    pub fn va_to_offset(&self, va: u64) -> Option<u64> {
        self.find_by_va(va)?.va_to_offset(va)
    }

    /// Convert a file offset to a VA using the section table.
    #[must_use]
    pub fn offset_to_va(&self, offset: u64) -> Option<u64> {
        self.find_by_offset(offset)?.offset_to_va(offset)
    }

    /// Number of sections in the map.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the map contains no sections.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries in VA order.
    pub fn iter(&self) -> impl Iterator<Item = &SectionEntry> {
        self.entries.iter()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SegmentMap
// ─────────────────────────────────────────────────────────────────────────────

/// A segment-level equivalent of [`SectionMap`] for ELF/Mach-O `PT_LOAD` /
/// `LC_SEGMENT` entries.  Segment granularity is coarser and may overlap sections.
#[derive(Debug, Clone, Default)]
pub struct SegmentMap {
    entries: Vec<SectionEntry>,
}

impl SegmentMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a segment.
    pub fn insert(&mut self, entry: SectionEntry) {
        self.entries.push(entry);
        self.entries.sort_by_key(|e| e.va_start);
    }

    /// Translate a virtual address to a file offset via the segment table.
    #[must_use]
    pub fn va_to_offset(&self, va: u64) -> Option<u64> {
        // Prefer the narrowest covering segment.
        self.entries
            .iter()
            .filter(|e| e.contains_va(va))
            .min_by_key(|e| e.virtual_size())
            .and_then(|e| e.va_to_offset(va))
    }

    /// Translate a file offset to a virtual address via the segment table.
    #[must_use]
    pub fn offset_to_va(&self, offset: u64) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| offset >= e.file_offset && offset < e.file_offset + e.file_size)
            .and_then(|e| e.offset_to_va(offset))
    }

    /// Number of segments.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VA2Offset / Offset2VA conversion wrappers
// ─────────────────────────────────────────────────────────────────────────────

/// Directional conversion: virtual address → file offset.
///
/// Wraps a [`SectionMap`] and provides a single-purpose conversion entry-point.
#[derive(Debug, Clone, Default)]
pub struct VA2Offset {
    map: SectionMap,
}

impl VA2Offset {
    /// Create from a [`SectionMap`].
    #[must_use]
    pub const fn new(map: SectionMap) -> Self {
        Self { map }
    }

    /// Convert `va` to a file offset.  Returns `None` when the address is not
    /// covered by any section.
    #[must_use]
    pub fn convert(&self, va: u64) -> Option<u64> {
        self.map.va_to_offset(va)
    }

    /// Borrow the inner [`SectionMap`].
    #[must_use]
    pub const fn section_map(&self) -> &SectionMap {
        &self.map
    }
}

/// Directional conversion: file offset → virtual address.
#[derive(Debug, Clone, Default)]
pub struct Offset2VA {
    map: SectionMap,
}

impl Offset2VA {
    /// Create from a [`SectionMap`].
    #[must_use]
    pub const fn new(map: SectionMap) -> Self {
        Self { map }
    }

    /// Convert `offset` to a virtual address. Returns `None` when the offset
    /// is not covered by any section.
    #[must_use]
    pub fn convert(&self, offset: u64) -> Option<u64> {
        self.map.offset_to_va(offset)
    }

    /// Borrow the inner [`SectionMap`].
    #[must_use]
    pub const fn section_map(&self) -> &SectionMap {
        &self.map
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RebaseMap — PIE binary rebasing
// ─────────────────────────────────────────────────────────────────────────────

/// Rebasing support for position-independent executables.
///
/// A PIE binary has a link-time base address of 0 (or a small canonical value
/// like `0x400000` on some toolchains).  When loaded by the OS a random slide
/// is applied.  `RebaseMap` translates between the link-time address and the
/// run-time (slid) address.
#[derive(Debug, Clone)]
pub struct RebaseMap {
    /// Link-time image base.
    link_base: u64,
    /// Run-time load address.
    load_base: u64,
    /// Precomputed slide: `load_base - link_base`.
    slide: i128,
    /// Underlying section map (with link-time addresses).
    section_map: SectionMap,
}

impl RebaseMap {
    /// Construct a new rebase map.
    ///
    /// * `link_base` – the address the binary was linked at (e.g. `0`).
    /// * `load_base` – the address at which the OS loaded the image.
    /// * `section_map` – section table using *link-time* virtual addresses.
    #[must_use]
    pub fn new(link_base: u64, load_base: u64, section_map: SectionMap) -> Self {
        let slide = i128::from(load_base) - i128::from(link_base);
        Self {
            link_base,
            load_base,
            slide,
            section_map,
        }
    }

    /// Slide a link-time VA to the runtime VA.
    ///
    /// # Panics
    /// Never panics; the slice length is always 8.
    #[must_use]
    pub fn to_runtime(&self, link_va: u64) -> u64 {
        let bytes = (i128::from(link_va) + self.slide).to_le_bytes();
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    }

    /// Unslide a runtime VA back to the link-time VA.
    ///
    /// # Panics
    /// Never panics; the slice length is always 8.
    #[must_use]
    pub fn to_link_time(&self, runtime_va: u64) -> u64 {
        let bytes = (i128::from(runtime_va) - self.slide).to_le_bytes();
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    }

    /// Convert a runtime VA to a file offset.
    #[must_use]
    pub fn runtime_va_to_offset(&self, runtime_va: u64) -> Option<u64> {
        let link_va = self.to_link_time(runtime_va);
        self.section_map.va_to_offset(link_va)
    }

    /// Convert a file offset to a runtime VA.
    #[must_use]
    pub fn offset_to_runtime_va(&self, offset: u64) -> Option<u64> {
        let link_va = self.section_map.offset_to_va(offset)?;
        Some(self.to_runtime(link_va))
    }

    /// The link-time image base.
    #[must_use]
    pub const fn link_base(&self) -> u64 {
        self.link_base
    }

    /// The runtime load base.
    #[must_use]
    pub const fn load_base(&self) -> u64 {
        self.load_base
    }

    /// The ASLR slide value.
    #[must_use]
    pub const fn slide(&self) -> i128 {
        self.slide
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RvaResolver — PE Relative Virtual Addresses
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves PE relative virtual addresses (RVAs) to file offsets and absolute
/// virtual addresses.
///
/// A PE RVA is defined relative to the image base:
/// `VA = ImageBase + RVA`.
#[derive(Debug, Clone)]
pub struct RvaResolver {
    /// The PE image base (e.g. `0x140000000` for 64-bit PE).
    image_base: u64,
    /// Section table.
    section_map: SectionMap,
}

impl RvaResolver {
    /// Create a new resolver.
    ///
    /// * `image_base` – value of the PE header `ImageBase` field.
    /// * `section_map` – section table populated from the PE section headers
    ///   (using *virtual addresses* relative to the image base, i.e. absolute VAs).
    #[must_use]
    pub const fn new(image_base: u64, section_map: SectionMap) -> Self {
        Self {
            image_base,
            section_map,
        }
    }

    /// Convert an RVA to an absolute virtual address.
    #[must_use]
    pub fn rva_to_va(&self, rva: u32) -> u64 {
        self.image_base.wrapping_add(u64::from(rva))
    }

    /// Convert an absolute VA to an RVA.
    ///
    /// Returns `None` when the VA is below the image base.
    ///
    /// # Panics
    /// Never panics; the value is checked to fit before conversion.
    #[must_use]
    pub fn va_to_rva(&self, va: u64) -> Option<u32> {
        if va < self.image_base {
            return None;
        }
        let rva = va - self.image_base;
        if rva > u64::from(u32::MAX) {
            return None;
        }
        Some(u32::try_from(rva).expect("rva already checked <= u32::MAX"))
    }

    /// Convert an RVA to a file offset.
    ///
    /// Returns `None` when no section covers the resulting VA.
    #[must_use]
    pub fn rva_to_offset(&self, rva: u32) -> Option<u64> {
        let va = self.rva_to_va(rva);
        self.section_map.va_to_offset(va)
    }

    /// Convert a file offset to an RVA.
    ///
    /// Returns `None` when no section covers `offset`, or the resulting VA is
    /// below the image base.
    #[must_use]
    pub fn offset_to_rva(&self, offset: u64) -> Option<u32> {
        let va = self.section_map.offset_to_va(offset)?;
        self.va_to_rva(va)
    }

    /// The image base.
    #[must_use]
    pub const fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Borrow the section map.
    #[must_use]
    pub const fn section_map(&self) -> &SectionMap {
        &self.section_map
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AddressResolver — unified façade
// ─────────────────────────────────────────────────────────────────────────────

/// Unified address-resolution engine for a loaded binary.
///
/// Combines a [`SectionMap`] (for VA↔offset translation), an optional
/// [`RebaseMap`] (for PIE ASLR slide), and an optional [`RvaResolver`] (for PE
/// RVAs) into a single object that callers can query without knowing which
/// sub-resolver to use.
#[derive(Debug, Clone)]
pub struct AddressResolver {
    /// Section table.
    sections: SectionMap,
    /// Optional PIE rebase info.
    rebase: Option<RebaseMap>,
    /// Optional PE RVA resolver.
    rva: Option<RvaResolver>,
    /// Cached VA→offset overrides (e.g. from debug symbols).
    overrides: HashMap<u64, u64>,
}

impl AddressResolver {
    /// Create a resolver backed only by a section table.
    #[must_use]
    pub fn new(sections: SectionMap) -> Self {
        Self {
            sections,
            rebase: None,
            rva: None,
            overrides: HashMap::new(),
        }
    }

    /// Attach a [`RebaseMap`] for PIE support.
    #[must_use]
    pub fn with_rebase(mut self, rebase: RebaseMap) -> Self {
        self.rebase = Some(rebase);
        self
    }

    /// Attach an [`RvaResolver`] for PE RVA lookups.
    #[must_use]
    pub fn with_rva_resolver(mut self, rva: RvaResolver) -> Self {
        self.rva = Some(rva);
        self
    }

    /// Add a VA→offset override entry (e.g. from DWARF debug info).
    pub fn add_override(&mut self, va: u64, offset: u64) {
        self.overrides.insert(va, offset);
    }

    /// Translate a virtual address to a file offset.
    ///
    /// Resolution order:
    /// 1. Override table.
    /// 2. Rebase map (runtime VA → link-time VA → offset).
    /// 3. Section map (link-time VA → offset).
    #[must_use]
    pub fn va_to_offset(&self, va: u64) -> Option<u64> {
        if let Some(&off) = self.overrides.get(&va) {
            return Some(off);
        }
        if let Some(rb) = &self.rebase
            && let Some(off) = rb.runtime_va_to_offset(va) {
                return Some(off);
            }
        self.sections.va_to_offset(va)
    }

    /// Translate a file offset to a virtual address.
    #[must_use]
    pub fn offset_to_va(&self, offset: u64) -> Option<u64> {
        if let Some(rb) = &self.rebase
            && let Some(va) = rb.offset_to_runtime_va(offset) {
                return Some(va);
            }
        self.sections.offset_to_va(offset)
    }

    /// Translate a PE RVA to a file offset.
    ///
    /// Returns `None` when no [`RvaResolver`] is configured.
    #[must_use]
    pub fn rva_to_offset(&self, rva: u32) -> Option<u64> {
        self.rva.as_ref()?.rva_to_offset(rva)
    }

    /// Translate a PE RVA to an absolute VA.
    ///
    /// Returns `None` when no [`RvaResolver`] is configured.
    #[must_use]
    pub fn rva_to_va(&self, rva: u32) -> Option<u64> {
        Some(self.rva.as_ref()?.rva_to_va(rva))
    }

    /// Borrow the section map.
    #[must_use]
    pub const fn sections(&self) -> &SectionMap {
        &self.sections
    }

    /// Check whether a VA has an explicit override.
    #[must_use]
    pub fn has_override(&self, va: u64) -> bool {
        self.overrides.contains_key(&va)
    }

    /// Number of VA→offset overrides registered.
    #[must_use]
    pub fn override_count(&self) -> usize {
        self.overrides.len()
    }
}

impl Default for AddressResolver {
    fn default() -> Self {
        Self::new(SectionMap::new())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AddressResolverBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Ergonomic builder for [`AddressResolver`].
#[derive(Debug, Default)]
pub struct AddressResolverBuilder {
    sections: SectionMap,
    rebase: Option<RebaseMap>,
    rva: Option<RvaResolver>,
    overrides: HashMap<u64, u64>,
}

impl AddressResolverBuilder {
    /// Create an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a section entry.
    #[must_use] 
    pub fn section(mut self, entry: SectionEntry) -> Self {
        self.sections.insert(entry);
        self
    }

    /// Add multiple section entries.
    #[must_use]
    pub fn sections(mut self, entries: impl IntoIterator<Item = SectionEntry>) -> Self {
        for e in entries {
            self.sections.insert(e);
        }
        self
    }

    /// Configure PIE rebasing.
    #[must_use] 
    pub fn rebase(mut self, link_base: u64, load_base: u64) -> Self {
        // Clone the section map so the RebaseMap can own it.
        let rb = RebaseMap::new(link_base, load_base, self.sections.clone());
        self.rebase = Some(rb);
        self
    }

    /// Configure a PE RVA resolver.
    #[must_use] 
    pub fn rva_resolver(mut self, image_base: u64) -> Self {
        let rv = RvaResolver::new(image_base, self.sections.clone());
        self.rva = Some(rv);
        self
    }

    /// Add a VA→offset override.
    #[must_use] 
    pub fn add_override(mut self, va: u64, offset: u64) -> Self {
        self.overrides.insert(va, offset);
        self
    }

    /// Build the [`AddressResolver`].
    #[must_use]
    pub fn build(self) -> AddressResolver {
        let mut resolver = AddressResolver::new(self.sections);
        if let Some(rb) = self.rebase {
            resolver = resolver.with_rebase(rb);
        }
        if let Some(rv) = self.rva {
            resolver = resolver.with_rva_resolver(rv);
        }
        for (va, offset) in self.overrides {
            resolver.add_override(va, offset);
        }
        resolver
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_section(name: &str, va: u64, vsz: u64, off: u64, fsz: u64) -> SectionEntry {
        SectionEntry::new(name, va, vsz, off, fsz)
    }

    // ── SectionEntry ──────────────────────────────────────────────────────────

    #[test]
    fn test_entry_contains_va() {
        let e = make_section(".text", 0x1000, 0x500, 0x200, 0x500);
        assert!(e.contains_va(0x1000));
        assert!(e.contains_va(0x14FF));
        assert!(!e.contains_va(0x1500));
        assert!(!e.contains_va(0x0FFF));
    }

    #[test]
    fn test_entry_va_to_offset() {
        let e = make_section(".text", 0x1000, 0x400, 0x200, 0x400);
        assert_eq!(e.va_to_offset(0x1000), Some(0x200));
        assert_eq!(e.va_to_offset(0x1100), Some(0x300));
        assert_eq!(e.va_to_offset(0x1400), None); // outside
    }

    #[test]
    fn test_entry_offset_to_va() {
        let e = make_section(".data", 0x2000, 0x100, 0x600, 0x100);
        assert_eq!(e.offset_to_va(0x600), Some(0x2000));
        assert_eq!(e.offset_to_va(0x650), Some(0x2050));
        assert_eq!(e.offset_to_va(0x700), None);
    }

    #[test]
    fn test_entry_virtual_size() {
        let e = make_section(".bss", 0x3000, 0x200, 0x800, 0x0);
        assert_eq!(e.virtual_size(), 0x200);
    }

    #[test]
    fn test_entry_file_size_smaller_than_virtual() {
        // va_to_offset should return None for bytes in the zero-fill region.
        let e = make_section(".bss", 0x4000, 0x1000, 0xA00, 0x200);
        assert!(e.va_to_offset(0x4000).is_some());
        assert!(e.va_to_offset(0x41FF).is_some());
        assert!(e.va_to_offset(0x4200).is_none()); // past file_size
    }

    // ── SectionMap ────────────────────────────────────────────────────────────

    #[test]
    fn test_section_map_insert_sorted() {
        let mut m = SectionMap::new();
        m.insert(make_section(".data", 0x2000, 0x100, 0x600, 0x100));
        m.insert(make_section(".text", 0x1000, 0x500, 0x200, 0x500));
        assert_eq!(m.entries[0].name, ".text");
        assert_eq!(m.entries[1].name, ".data");
    }

    #[test]
    fn test_section_map_va_to_offset() {
        let mut m = SectionMap::new();
        m.insert(make_section(".text", 0x1000, 0x500, 0x200, 0x500));
        assert_eq!(m.va_to_offset(0x1000), Some(0x200));
        assert_eq!(m.va_to_offset(0x1200), Some(0x400));
        assert_eq!(m.va_to_offset(0x9000), None);
    }

    #[test]
    fn test_section_map_offset_to_va() {
        let mut m = SectionMap::new();
        m.insert(make_section(".text", 0x1000, 0x500, 0x200, 0x500));
        assert_eq!(m.offset_to_va(0x200), Some(0x1000));
        assert_eq!(m.offset_to_va(0x300), Some(0x1100));
        assert_eq!(m.offset_to_va(0x100), None);
    }

    #[test]
    fn test_section_map_find_by_name() {
        let mut m = SectionMap::new();
        m.insert(make_section(".rdata", 0x3000, 0x200, 0xA00, 0x200));
        assert!(m.find_by_name(".rdata").is_some());
        assert!(m.find_by_name(".nonexistent").is_none());
    }

    #[test]
    fn test_section_map_len() {
        let mut m = SectionMap::new();
        assert_eq!(m.len(), 0);
        assert!(m.is_empty());
        m.insert(make_section(".x", 0, 1, 0, 1));
        assert_eq!(m.len(), 1);
        assert!(!m.is_empty());
    }

    #[test]
    fn test_section_map_multiple_sections() {
        let mut m = SectionMap::new();
        m.insert(make_section(".text", 0x1000, 0x1000, 0x400, 0x1000));
        m.insert(make_section(".data", 0x2000, 0x0800, 0x1400, 0x0800));
        m.insert(make_section(".rdata", 0x3000, 0x0400, 0x1C00, 0x0400));
        assert_eq!(m.va_to_offset(0x1500), Some(0x900));
        assert_eq!(m.va_to_offset(0x2100), Some(0x1500));
        assert_eq!(m.va_to_offset(0x3200), Some(0x1E00));
    }

    // ── SegmentMap ────────────────────────────────────────────────────────────

    #[test]
    fn test_segment_map_va_to_offset() {
        let mut sm = SegmentMap::new();
        sm.insert(make_section("LOAD0", 0, 0x10000, 0, 0x10000));
        assert_eq!(sm.va_to_offset(0x500), Some(0x500));
        assert_eq!(sm.va_to_offset(0x10001), None);
    }

    #[test]
    fn test_segment_map_offset_to_va() {
        let mut sm = SegmentMap::new();
        sm.insert(make_section("LOAD0", 0x8000, 0x4000, 0x1000, 0x4000));
        assert_eq!(sm.offset_to_va(0x1000), Some(0x8000));
        assert_eq!(sm.offset_to_va(0x1200), Some(0x8200));
    }

    // ── VA2Offset / Offset2VA ─────────────────────────────────────────────────

    #[test]
    fn test_va2offset_convert() {
        let mut m = SectionMap::new();
        m.insert(make_section(".text", 0x0040_0000, 0x1000, 0x400, 0x1000));
        let conv = VA2Offset::new(m);
        assert_eq!(conv.convert(0x0040_0000), Some(0x400));
        assert_eq!(conv.convert(0x0041_0000), None);
    }

    #[test]
    fn test_offset2va_convert() {
        let mut m = SectionMap::new();
        m.insert(make_section(".text", 0x0040_0000, 0x1000, 0x400, 0x1000));
        let conv = Offset2VA::new(m);
        assert_eq!(conv.convert(0x400), Some(0x0040_0000));
        assert_eq!(conv.convert(0x2000), None);
    }

    // ── RebaseMap ────────────────────────────────────────────────────────────

    #[test]
    fn test_rebase_to_runtime() {
        let map = SectionMap::new();
        let rb = RebaseMap::new(0, 0x7fff0000, map);
        assert_eq!(rb.to_runtime(0x1000), 0x7fff1000);
    }

    #[test]
    fn test_rebase_to_link_time() {
        let map = SectionMap::new();
        let rb = RebaseMap::new(0, 0x7fff0000, map);
        assert_eq!(rb.to_link_time(0x7fff1000), 0x1000);
    }

    #[test]
    fn test_rebase_runtime_va_to_offset() {
        let mut m = SectionMap::new();
        m.insert(make_section(".text", 0x1000, 0x500, 0x200, 0x500));
        let rb = RebaseMap::new(0, 0x7fff0000, m);
        // runtime VA = 0x7fff0000 + 0x1000 = 0x7fff1000 → link-time 0x1000 → offset 0x200
        assert_eq!(rb.runtime_va_to_offset(0x7fff1000), Some(0x200));
    }

    #[test]
    fn test_rebase_offset_to_runtime_va() {
        let mut m = SectionMap::new();
        m.insert(make_section(".text", 0x1000, 0x500, 0x200, 0x500));
        let rb = RebaseMap::new(0, 0x7fff0000, m);
        assert_eq!(rb.offset_to_runtime_va(0x200), Some(0x7fff1000));
    }

    #[test]
    fn test_rebase_slide_accessors() {
        let map = SectionMap::new();
        let rb = RebaseMap::new(0x0040_0000, 0x0050_0000, map);
        assert_eq!(rb.link_base(), 0x0040_0000);
        assert_eq!(rb.load_base(), 0x0050_0000);
        assert_eq!(rb.slide(), 0x0010_0000);
    }

    // ── RvaResolver ──────────────────────────────────────────────────────────

    #[test]
    fn test_rva_to_va() {
        let m = SectionMap::new();
        let rv = RvaResolver::new(0x0001_4000_0000, m);
        assert_eq!(rv.rva_to_va(0x1000), 0x0001_4000_1000);
    }

    #[test]
    fn test_va_to_rva() {
        let m = SectionMap::new();
        let rv = RvaResolver::new(0x0001_4000_0000, m);
        assert_eq!(rv.va_to_rva(0x0001_4000_1000), Some(0x1000));
        assert_eq!(rv.va_to_rva(0x100), None); // below base
    }

    #[test]
    fn test_rva_to_offset() {
        let mut m = SectionMap::new();
        // .text: va_start=0x140001000, vsz=0x2000, file_offset=0x400, fsz=0x2000
        m.insert(make_section(".text", 0x0001_4000_1000, 0x2000, 0x400, 0x2000));
        let rv = RvaResolver::new(0x0001_4000_0000, m);
        assert_eq!(rv.rva_to_offset(0x1000), Some(0x400));
        assert_eq!(rv.rva_to_offset(0x1100), Some(0x500));
        assert_eq!(rv.rva_to_offset(0x9000), None);
    }

    #[test]
    fn test_offset_to_rva() {
        let mut m = SectionMap::new();
        m.insert(make_section(".text", 0x0001_4000_1000, 0x2000, 0x400, 0x2000));
        let rv = RvaResolver::new(0x0001_4000_0000, m);
        assert_eq!(rv.offset_to_rva(0x400), Some(0x1000));
        assert_eq!(rv.offset_to_rva(0x500), Some(0x1100));
        assert_eq!(rv.offset_to_rva(0x200), None);
    }

    // ── AddressResolver ───────────────────────────────────────────────────────

    #[test]
    fn test_resolver_basic_va_to_offset() {
        let mut m = SectionMap::new();
        m.insert(make_section(".text", 0x1000, 0x1000, 0x400, 0x1000));
        let r = AddressResolver::new(m);
        assert_eq!(r.va_to_offset(0x1000), Some(0x400));
    }

    #[test]
    fn test_resolver_override_takes_priority() {
        let mut m = SectionMap::new();
        m.insert(make_section(".text", 0x1000, 0x1000, 0x400, 0x1000));
        let mut r = AddressResolver::new(m);
        r.add_override(0x1000, 0xBEEF);
        assert_eq!(r.va_to_offset(0x1000), Some(0xBEEF));
    }

    #[test]
    fn test_resolver_override_count() {
        let mut r = AddressResolver::default();
        assert_eq!(r.override_count(), 0);
        r.add_override(0x1000, 0x400);
        r.add_override(0x2000, 0x800);
        assert_eq!(r.override_count(), 2);
    }

    #[test]
    fn test_resolver_has_override() {
        let mut r = AddressResolver::default();
        assert!(!r.has_override(0x1000));
        r.add_override(0x1000, 0x400);
        assert!(r.has_override(0x1000));
    }

    #[test]
    fn test_resolver_rva_no_resolver_returns_none() {
        let r = AddressResolver::default();
        assert!(r.rva_to_offset(0x1000).is_none());
        assert!(r.rva_to_va(0x1000).is_none());
    }

    #[test]
    fn test_resolver_rva_to_offset_via_resolver() {
        let mut m = SectionMap::new();
        m.insert(make_section(".text", 0x0001_4000_1000, 0x1000, 0x400, 0x1000));
        let rv = RvaResolver::new(0x0001_4000_0000, m.clone());
        let r = AddressResolver::new(m).with_rva_resolver(rv);
        assert_eq!(r.rva_to_offset(0x1000), Some(0x400));
    }

    // ── AddressResolverBuilder ────────────────────────────────────────────────

    #[test]
    fn test_builder_basic() {
        let r = AddressResolverBuilder::new()
            .section(make_section(".text", 0x1000, 0x500, 0x200, 0x500))
            .build();
        assert_eq!(r.va_to_offset(0x1000), Some(0x200));
    }

    #[test]
    fn test_builder_with_override() {
        let r = AddressResolverBuilder::new()
            .section(make_section(".text", 0x1000, 0x500, 0x200, 0x500))
            .add_override(0x1000, 0xDEAD)
            .build();
        assert_eq!(r.va_to_offset(0x1000), Some(0xDEAD));
    }

    #[test]
    fn test_builder_sections_bulk() {
        let entries = vec![
            make_section(".text", 0x1000, 0x500, 0x200, 0x500),
            make_section(".data", 0x2000, 0x200, 0x700, 0x200),
        ];
        let r = AddressResolverBuilder::new().sections(entries).build();
        assert!(r.va_to_offset(0x1100).is_some());
        assert!(r.va_to_offset(0x2100).is_some());
    }

    // ── Extra edge-case coverage ────────────────────────────────────────────

    #[test]
    fn test_section_entry_contains_va_boundaries() {
        let e = make_section(".t", 0x1000, 0x100, 0x0, 0x100);
        assert!(e.contains_va(0x1000));        // inclusive start
        assert!(e.contains_va(0x10FF));        // last valid byte
        assert!(!e.contains_va(0x1100));       // exclusive end
        assert!(!e.contains_va(0x0FFF));       // before start
    }

    #[test]
    fn test_section_entry_saturating_va_end_no_overflow() {
        // va_start + virtual_size should saturate, not panic.
        let e = SectionEntry::new(".huge", u64::MAX - 4, 100, 0, 100);
        assert_eq!(e.va_end, u64::MAX);
        assert!(e.contains_va(u64::MAX - 1));
    }

    #[test]
    fn test_section_entry_offset_to_va_boundary() {
        let e = make_section(".t", 0x1000, 0x100, 0x200, 0x100);
        assert_eq!(e.offset_to_va(0x200), Some(0x1000));
        assert_eq!(e.offset_to_va(0x2FF), Some(0x10FF));
        assert_eq!(e.offset_to_va(0x300), None); // exclusive end
        assert_eq!(e.offset_to_va(0x1FF), None); // before file_offset
    }

    #[test]
    fn test_section_map_empty_lookups_return_none() {
        let m = SectionMap::new();
        assert_eq!(m.va_to_offset(0x1000), None);
        assert_eq!(m.offset_to_va(0x100), None);
        assert!(m.find_by_va(0).is_none());
        assert!(m.find_by_name(".text").is_none());
    }

    #[test]
    fn test_section_map_va_in_gap_returns_none() {
        let mut m = SectionMap::new();
        m.insert(make_section(".text", 0x1000, 0x100, 0x200, 0x100));
        m.insert(make_section(".data", 0x3000, 0x100, 0x400, 0x100));
        // VA in gap between sections.
        assert_eq!(m.va_to_offset(0x2000), None);
    }

    #[test]
    fn test_resolver_remove_override_via_recreate() {
        let mut m = SectionMap::new();
        m.insert(make_section(".text", 0x1000, 0x1000, 0x400, 0x1000));
        let mut r = AddressResolver::new(m);
        r.add_override(0x1000, 0xBEEF);
        assert_eq!(r.va_to_offset(0x1000), Some(0xBEEF));
        // Adding new override for same VA replaces.
        r.add_override(0x1000, 0xCAFE);
        assert_eq!(r.va_to_offset(0x1000), Some(0xCAFE));
    }

    #[test]
    fn test_rebase_zero_slide_is_identity() {
        let map = SectionMap::new();
        let rb = RebaseMap::new(0x0040_0000, 0x0040_0000, map);
        assert_eq!(rb.slide(), 0i128);
        assert_eq!(rb.to_runtime(0x1000), 0x1000);
        assert_eq!(rb.to_link_time(0x1000), 0x1000);
    }
}
