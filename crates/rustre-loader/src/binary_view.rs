//! `binary_view` — `BinaryView` abstraction for the multi-format loader layer.
//!
//! This module provides [`LoaderBinaryView`], a rich, self-contained
//! description of a loaded binary image.  It carries:
//!
//! * Ordered [`Segment`]s (coarse, runtime-mapped regions).
//! * Detailed [`SectionRecord`]s (named sub-ranges within segments).
//! * A [`SymbolTable`] of named addresses.
//! * A list of entry-point addresses.
//! * Relocation records (see [`crate::relocation_engine`]).
//! * An architecture tag and bitness.
//!
//! # Builder pattern
//!
//! Use [`LoaderBinaryViewBuilder`] to construct a view incrementally, then
//! call [`LoaderBinaryViewBuilder::build`] to obtain the finished
//! [`LoaderBinaryView`].
//!
//! # Constructing from a `RichLoadResult`
//!
//! [`LoaderBinaryView::from_loader_result`] converts a [`crate::RichLoadResult`]
//! (as produced by any [`crate::MultiFormatLoader`]) into a `LoaderBinaryView`.

use std::collections::HashMap;

pub use crate::SymbolInfo;
use crate::{ExportInfo, ImportInfo, RichLoadResult, SectionInfo};

// ─── Permissions ─────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Permission flags for a memory region.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct RegionPermissions: u8 {
        /// Region is readable.
        const READ    = 0b0001;
        /// Region is writable.
        const WRITE   = 0b0010;
        /// Region is executable.
        const EXECUTE = 0b0100;
    }
}

impl std::fmt::Display for RegionPermissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = if self.contains(Self::READ) { 'r' } else { '-' };
        let w = if self.contains(Self::WRITE) { 'w' } else { '-' };
        let x = if self.contains(Self::EXECUTE) {
            'x'
        } else {
            '-'
        };
        write!(f, "{r}{w}{x}")
    }
}

// ─── Segment ─────────────────────────────────────────────────────────────────

/// A coarse memory segment in a loaded binary image (e.g. `PT_LOAD` for ELF,
/// `__TEXT` / `__DATA` for Mach-O, or a PE section group).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Optional name (e.g. `"__TEXT"`, `".text+.rodata"`).
    pub name: String,
    /// Segment virtual address (start of mapped region).
    pub virtual_address: u64,
    /// Virtual size of the segment in bytes.
    pub virtual_size: u64,
    /// Raw file offset for the segment data.
    pub file_offset: u64,
    /// Raw file size of the segment data.
    pub file_size: u64,
    /// Runtime permissions for this segment.
    pub permissions: RegionPermissions,
}

impl Segment {
    /// Construct a new `Segment`.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        virtual_address: u64,
        virtual_size: u64,
        file_offset: u64,
        file_size: u64,
        permissions: RegionPermissions,
    ) -> Self {
        Self {
            name: name.into(),
            virtual_address,
            virtual_size,
            file_offset,
            file_size,
            permissions,
        }
    }

    /// Return `true` if the virtual address `va` lies within this segment.
    #[must_use]
    pub const fn contains_va(&self, va: u64) -> bool {
        va >= self.virtual_address && va < self.virtual_address.saturating_add(self.virtual_size)
    }

    /// Translate a virtual address to a file offset within this segment.
    ///
    /// Returns `None` if `va` is not within the segment, or if the computed
    /// file offset exceeds `file_offset + file_size`.
    #[must_use]
    pub fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        if !self.contains_va(va) {
            return None;
        }
        let delta = va - self.virtual_address;
        let file_off = self.file_offset.checked_add(delta)?;
        let file_end = self.file_offset.checked_add(self.file_size)?;
        if file_off < file_end {
            Some(file_off)
        } else {
            None
        }
    }
}

// ─── SectionRecord ───────────────────────────────────────────────────────────

/// A fine-grained named section within a binary (e.g. `.text`, `.data`,
/// `__objc_methnames`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionRecord {
    /// Section name.
    pub name: String,
    /// Virtual address.
    pub virtual_address: u64,
    /// Virtual size.
    pub virtual_size: u64,
    /// Raw offset in the file.
    pub raw_offset: u64,
    /// Raw size in the file.
    pub raw_size: u64,
    /// Platform-specific flags / characteristics.
    pub flags: u32,
    /// Index of the parent segment in the view's segment list (if known).
    pub segment_index: Option<usize>,
}

impl SectionRecord {
    /// Convert a [`SectionInfo`] (from the multi-format layer) into a
    /// `SectionRecord`.
    #[must_use]
    pub fn from_section_info(si: &SectionInfo, segment_index: Option<usize>) -> Self {
        Self {
            name: si.name.clone(),
            virtual_address: si.virtual_addr,
            virtual_size: si.virtual_size,
            raw_offset: si.raw_offset,
            raw_size: si.raw_size,
            flags: si.flags,
            segment_index,
        }
    }

    /// Return `true` if the virtual address lies within this section.
    #[must_use]
    pub const fn contains_va(&self, va: u64) -> bool {
        va >= self.virtual_address && va < self.virtual_address.saturating_add(self.virtual_size)
    }
}

// ─── Symbol / SymbolTable ────────────────────────────────────────────────────

/// A single symbol entry in a [`SymbolTable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Symbol name (demangled when available).
    pub name: String,
    /// Virtual address.
    pub address: u64,
    /// Kind tag: `"function"`, `"object"`, `"section"`, `"import"`, `"export"`, …
    pub kind: String,
    /// Symbol size in bytes (0 if unknown).
    pub size: u64,
}

impl Symbol {
    /// Construct a `Symbol`.
    #[must_use]
    pub fn new(name: impl Into<String>, address: u64, kind: impl Into<String>, size: u64) -> Self {
        Self {
            name: name.into(),
            address,
            kind: kind.into(),
            size,
        }
    }
}

/// Thread-safe symbol table keyed by name.
#[derive(Debug, Default, Clone)]
pub struct SymbolTable {
    by_name: HashMap<String, Symbol>,
    by_addr: HashMap<u64, Vec<String>>,
}

impl SymbolTable {
    /// Create an empty `SymbolTable`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a symbol.  Overwrites any existing symbol with the same name.
    pub fn insert(&mut self, sym: Symbol) {
        self.by_addr
            .entry(sym.address)
            .or_default()
            .push(sym.name.clone());
        self.by_name.insert(sym.name.clone(), sym);
    }

    /// Look up a symbol by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Symbol> {
        self.by_name.get(name)
    }

    /// Return all symbols at virtual address `addr`.
    #[must_use]
    pub fn at_address(&self, addr: u64) -> Vec<&Symbol> {
        self.by_addr
            .get(&addr)
            .map(|names| {
                names
                    .iter()
                    .filter_map(|n| self.by_name.get(n.as_str()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return the total number of symbols.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Return `true` if the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Iterate over all symbols.
    pub fn iter(&self) -> impl Iterator<Item = &Symbol> {
        self.by_name.values()
    }
}

// ─── LoaderBinaryView ────────────────────────────────────────────────────────

/// A rich, format-agnostic view of a loaded binary image.
///
/// Produced either by [`LoaderBinaryViewBuilder`] (preferred for tests and
/// custom loaders) or by [`LoaderBinaryView::from_loader_result`] (for
/// converting a [`RichLoadResult`]).
#[derive(Debug, Clone)]
pub struct LoaderBinaryView {
    // ── identity ─────────────────────────────────────────────────────────────
    /// Source URI (file path, URL, or synthetic label).
    pub uri: String,
    /// Format string, e.g. `"ELF-64LE"`.
    pub format: String,
    /// Architecture tag, e.g. `"x86_64"`, `"arm64"`, `"wasm32"`.
    pub arch: String,
    /// Pointer / address width in bits.
    pub bits: u8,
    /// Endianness: `"little"` or `"big"`.
    pub endian: String,

    // ── structure ────────────────────────────────────────────────────────────
    /// Coarse memory segments.
    pub segments: Vec<Segment>,
    /// Named sections.
    pub sections: Vec<SectionRecord>,
    /// Symbol table.
    pub symbols: SymbolTable,
    /// Entry-point virtual addresses.
    pub entry_points: Vec<u64>,
    /// Image base address (0 for position-independent objects).
    pub base_address: u64,

    // ── imports / exports ────────────────────────────────────────────────────
    /// Import table.
    pub imports: Vec<ImportInfo>,
    /// Export table.
    pub exports: Vec<ExportInfo>,

    // ── raw bytes ────────────────────────────────────────────────────────────
    /// Raw file bytes (or the mapped image).
    pub data: Vec<u8>,
}

impl LoaderBinaryView {
    /// Convert a [`RichLoadResult`] into a `LoaderBinaryView`.
    ///
    /// Sections from the result are mapped directly; symbols are inserted into
    /// a new [`SymbolTable`]; entry-point from the result (if any) is used.
    #[must_use]
    pub fn from_loader_result(uri: impl Into<String>, result: RichLoadResult) -> Self {
        let mut symbols = SymbolTable::new();
        for sym in &result.symbols {
            symbols.insert(Symbol::new(
                sym.name.clone(),
                sym.addr,
                sym.kind.clone(),
                sym.size,
            ));
        }

        // Build sections (no segment mapping at this layer).
        let sections: Vec<SectionRecord> = result
            .sections
            .iter()
            .map(|s| SectionRecord::from_section_info(s, None))
            .collect();

        let entry_points = result.entry_point.map(|ep| vec![ep]).unwrap_or_default();

        Self {
            uri: uri.into(),
            format: result.format,
            arch: result.arch,
            bits: result.bits,
            endian: result.endian,
            segments: Vec::new(),
            sections,
            symbols,
            entry_points,
            base_address: result.base_address,
            imports: result.imports,
            exports: result.exports,
            data: result.data,
        }
    }

    // ── query helpers ─────────────────────────────────────────────────────────

    /// Find the section containing virtual address `va`, or `None`.
    #[must_use]
    pub fn section_at(&self, va: u64) -> Option<&SectionRecord> {
        self.sections.iter().find(|s| s.contains_va(va))
    }

    /// Find the segment containing virtual address `va`, or `None`.
    #[must_use]
    pub fn segment_at(&self, va: u64) -> Option<&Segment> {
        self.segments.iter().find(|s| s.contains_va(va))
    }

    /// Translate a virtual address to a file offset using segment mapping.
    ///
    /// Falls back to VA - `base_address` if no segment matches.
    #[must_use]
    pub fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        if let Some(seg) = self.segment_at(va) {
            return seg.va_to_file_offset(va);
        }
        // Fallback: try raw offset = va - base
        let offset = va.checked_sub(self.base_address)?;
        if offset < self.data.len() as u64 {
            Some(offset)
        } else {
            None
        }
    }

    /// Read `len` bytes starting at virtual address `va`.
    ///
    /// Returns `None` if the virtual address cannot be mapped, or if the
    /// requested range exceeds the available data.
    #[must_use]
    pub fn read_at_va(&self, va: u64, len: usize) -> Option<&[u8]> {
        let off = usize::try_from(self.va_to_file_offset(va)?).ok()?;
        let end = off.checked_add(len)?;
        self.data.get(off..end)
    }

    /// Return the number of entry points.
    #[must_use]
    pub const fn entry_point_count(&self) -> usize {
        self.entry_points.len()
    }

    /// Return the primary entry point, or `None` if none is defined.
    #[must_use]
    pub fn primary_entry_point(&self) -> Option<u64> {
        self.entry_points.first().copied()
    }

    /// Return `true` if the view is 64-bit.
    #[must_use]
    pub const fn is_64bit(&self) -> bool {
        self.bits == 64
    }

    /// Return `true` if the view is little-endian.
    #[must_use]
    pub fn is_little_endian(&self) -> bool {
        self.endian == "little"
    }

    /// Total virtual address space covered by all sections.
    #[must_use]
    pub fn total_virtual_size(&self) -> u64 {
        self.sections.iter().map(|s| s.virtual_size).sum()
    }
}

// ─── LoaderBinaryViewBuilder ─────────────────────────────────────────────────

/// Builder for [`LoaderBinaryView`].
///
/// # Example
/// ```rust
/// use rustre_loader::binary_view::{LoaderBinaryViewBuilder, RegionPermissions};
///
/// let view = LoaderBinaryViewBuilder::new("test://bin")
///     .arch("x86_64")
///     .bits(64)
///     .endian("little")
///     .format("ELF-64LE")
///     .entry_point(0x401000)
///     .build();
/// assert_eq!(view.arch, "x86_64");
/// ```
#[derive(Debug, Default)]
pub struct LoaderBinaryViewBuilder {
    uri: String,
    format: String,
    arch: String,
    bits: u8,
    endian: String,
    base_address: u64,
    segments: Vec<Segment>,
    sections: Vec<SectionRecord>,
    symbols: SymbolTable,
    entry_points: Vec<u64>,
    imports: Vec<ImportInfo>,
    exports: Vec<ExportInfo>,
    data: Vec<u8>,
}

impl LoaderBinaryViewBuilder {
    /// Create a new builder with the given source URI.
    #[must_use]
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            ..Default::default()
        }
    }

    /// Set the format string.
    #[must_use]
    pub fn format(mut self, format: impl Into<String>) -> Self {
        self.format = format.into();
        self
    }

    /// Set the architecture tag.
    #[must_use]
    pub fn arch(mut self, arch: impl Into<String>) -> Self {
        self.arch = arch.into();
        self
    }

    /// Set the pointer width in bits.
    #[must_use]
    pub const fn bits(mut self, bits: u8) -> Self {
        self.bits = bits;
        self
    }

    /// Set the endianness.
    #[must_use]
    pub fn endian(mut self, endian: impl Into<String>) -> Self {
        self.endian = endian.into();
        self
    }

    /// Set the image base address.
    #[must_use]
    pub const fn base_address(mut self, base: u64) -> Self {
        self.base_address = base;
        self
    }

    /// Add an entry point.
    #[must_use]
    pub fn entry_point(mut self, ep: u64) -> Self {
        self.entry_points.push(ep);
        self
    }

    /// Add a segment.
    #[must_use]
    pub fn segment(mut self, seg: Segment) -> Self {
        self.segments.push(seg);
        self
    }

    /// Add a section.
    #[must_use]
    pub fn section(mut self, sec: SectionRecord) -> Self {
        self.sections.push(sec);
        self
    }

    /// Add a symbol.
    #[must_use]
    pub fn symbol(mut self, sym: Symbol) -> Self {
        self.symbols.insert(sym);
        self
    }

    /// Add an import.
    #[must_use]
    pub fn import(mut self, imp: ImportInfo) -> Self {
        self.imports.push(imp);
        self
    }

    /// Add an export.
    #[must_use]
    pub fn export(mut self, exp: ExportInfo) -> Self {
        self.exports.push(exp);
        self
    }

    /// Set raw data bytes.
    #[must_use]
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// Build the [`LoaderBinaryView`].
    #[must_use]
    pub fn build(self) -> LoaderBinaryView {
        LoaderBinaryView {
            uri: self.uri,
            format: self.format,
            arch: self.arch,
            bits: self.bits,
            endian: self.endian,
            segments: self.segments,
            sections: self.sections,
            symbols: self.symbols,
            entry_points: self.entry_points,
            base_address: self.base_address,
            imports: self.imports,
            exports: self.exports,
            data: self.data,
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExportInfo, ImportInfo, RichLoadResult, SectionInfo};

    fn sample_view() -> LoaderBinaryView {
        let seg = Segment::new(
            "__TEXT",
            0x1000,
            0x2000,
            0x000,
            0x2000,
            RegionPermissions::READ | RegionPermissions::EXECUTE,
        );
        let sec = SectionRecord {
            name: ".text".to_owned(),
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_offset: 0,
            raw_size: 0x1000,
            flags: 0,
            segment_index: Some(0),
        };
        let mut sym_table = SymbolTable::new();
        sym_table.insert(Symbol::new("main", 0x1000, "function", 64));
        sym_table.insert(Symbol::new("helper", 0x1100, "function", 32));

        LoaderBinaryView {
            uri: "test://binary".into(),
            format: "ELF-64LE".into(),
            arch: "x86_64".into(),
            bits: 64,
            endian: "little".into(),
            segments: vec![seg],
            sections: vec![sec],
            symbols: sym_table,
            entry_points: vec![0x1000],
            base_address: 0x1000,
            imports: vec![ImportInfo::named("libc.so", "printf", 0x3000)],
            exports: vec![ExportInfo::named("main", 0x1000, 1)],
            data: vec![0u8; 0x2000],
        }
    }

    #[test]
    fn test_section_at_hit() {
        let view = sample_view();
        let sec = view.section_at(0x1500);
        assert!(sec.is_some());
        assert_eq!(sec.unwrap().name, ".text");
    }

    #[test]
    fn test_section_at_miss() {
        let view = sample_view();
        assert!(view.section_at(0x9999).is_none());
    }

    #[test]
    fn test_segment_at_hit() {
        let view = sample_view();
        let seg = view.segment_at(0x1500);
        assert!(seg.is_some());
        assert_eq!(seg.unwrap().name, "__TEXT");
    }

    #[test]
    fn test_va_to_file_offset_via_segment() {
        let view = sample_view();
        let off = view.va_to_file_offset(0x1200);
        assert_eq!(off, Some(0x200));
    }

    #[test]
    fn test_va_to_file_offset_fallback() {
        // no segments — should fallback to va - base
        let view = LoaderBinaryViewBuilder::new("test://")
            .base_address(0x1000)
            .data(vec![0u8; 0x1000])
            .build();
        let off = view.va_to_file_offset(0x1100);
        assert_eq!(off, Some(0x100));
    }

    #[test]
    fn test_read_at_va() {
        let mut data = vec![0u8; 0x2000];
        data[0x200] = 0xAA;
        data[0x201] = 0xBB;
        let seg = Segment::new("seg", 0x1000, 0x2000, 0, 0x2000, RegionPermissions::READ);
        let view = LoaderBinaryViewBuilder::new("test://")
            .segment(seg)
            .data(data)
            .build();
        let bytes = view.read_at_va(0x1200, 2).unwrap();
        assert_eq!(bytes, &[0xAA, 0xBB]);
    }

    #[test]
    fn test_entry_points() {
        let view = sample_view();
        assert_eq!(view.entry_point_count(), 1);
        assert_eq!(view.primary_entry_point(), Some(0x1000));
    }

    #[test]
    fn test_is_64bit() {
        let view = sample_view();
        assert!(view.is_64bit());
    }

    #[test]
    fn test_is_little_endian() {
        let view = sample_view();
        assert!(view.is_little_endian());
    }

    #[test]
    fn test_total_virtual_size() {
        let view = sample_view();
        assert_eq!(view.total_virtual_size(), 0x1000);
    }

    #[test]
    fn test_symbol_lookup() {
        let view = sample_view();
        let sym = view.symbols.get("main").unwrap();
        assert_eq!(sym.address, 0x1000);
        assert_eq!(sym.kind, "function");
    }

    #[test]
    fn test_symbol_at_address() {
        let view = sample_view();
        let syms = view.symbols.at_address(0x1000);
        assert!(!syms.is_empty());
        assert!(syms.iter().any(|s| s.name == "main"));
    }

    #[test]
    fn test_symbol_table_len() {
        let view = sample_view();
        assert_eq!(view.symbols.len(), 2);
    }

    #[test]
    fn test_from_loader_result() {
        let result = RichLoadResult::new(vec![0u8; 100])
            .with_format("ELF-64LE")
            .with_arch("x86_64")
            .with_bits(64)
            .with_endian("little")
            .with_entry_point(0x4000)
            .with_section(SectionInfo::new(".text", 0x4000, 0x100, 0, 0x100, 0));
        let view = LoaderBinaryView::from_loader_result("file://test.elf", result);
        assert_eq!(view.arch, "x86_64");
        assert_eq!(view.primary_entry_point(), Some(0x4000));
        assert_eq!(view.sections.len(), 1);
    }

    #[test]
    fn test_builder_pattern() {
        let view = LoaderBinaryViewBuilder::new("uri://test")
            .arch("arm64")
            .bits(64)
            .endian("little")
            .format("Mach-O LE64")
            .base_address(0x0001_0000_0000)
            .entry_point(0x0001_0000_4000)
            .build();
        assert_eq!(view.arch, "arm64");
        assert_eq!(view.base_address, 0x0001_0000_0000);
        assert_eq!(view.entry_points, vec![0x0001_0000_4000]);
    }

    #[test]
    fn test_region_permissions_display() {
        let p = RegionPermissions::READ | RegionPermissions::EXECUTE;
        let s = p.to_string();
        assert_eq!(s, "r-x");
    }

    #[test]
    fn test_region_permissions_rwx() {
        let p = RegionPermissions::all();
        assert_eq!(p.to_string(), "rwx");
    }

    #[test]
    fn test_segment_contains_va() {
        let seg = Segment::new("seg", 0x1000, 0x1000, 0, 0x1000, RegionPermissions::READ);
        assert!(seg.contains_va(0x1000));
        assert!(seg.contains_va(0x1fff));
        assert!(!seg.contains_va(0x2000));
        assert!(!seg.contains_va(0x0fff));
    }

    #[test]
    fn test_segment_va_to_file_offset() {
        let seg = Segment::new(
            "seg",
            0x4000,
            0x1000,
            0x200,
            0x1000,
            RegionPermissions::READ,
        );
        assert_eq!(seg.va_to_file_offset(0x4000), Some(0x200));
        assert_eq!(seg.va_to_file_offset(0x4100), Some(0x300));
        assert_eq!(seg.va_to_file_offset(0x5001), None);
    }

    #[test]
    fn test_section_record_from_section_info() {
        let si = SectionInfo::new(".data", 0x6000, 0x200, 0x400, 0x200, 0);
        let sr = SectionRecord::from_section_info(&si, Some(1));
        assert_eq!(sr.name, ".data");
        assert_eq!(sr.segment_index, Some(1));
    }

    #[test]
    fn test_symbol_table_empty() {
        let t = SymbolTable::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn test_symbol_table_iter() {
        let mut t = SymbolTable::new();
        t.insert(Symbol::new("a", 0x100, "function", 0));
        t.insert(Symbol::new("b", 0x200, "object", 0));
        assert_eq!(t.iter().count(), 2);
    }
}
