/// Extended memory-region utilities: `Permissions` bitflags (independent of
/// `rustre-core`'s permissions), `RegionKind`, address-range helpers, and
/// region-set operations used across the memory subsystem.
use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// RegionKind — semantic classification of a mapped region
// ─────────────────────────────────────────────────────────────────────────────

/// High-level semantic classification of a memory region's purpose.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegionKind {
    /// Executable code section (.text, CODE, …).
    Code,
    /// Initialised read/write data (.data, DATA, …).
    Data,
    /// Read-only data (.rodata, CONST, …).
    ReadOnlyData,
    /// Zero-initialised data (.bss, BSS, …).
    Bss,
    /// Import address table / GOT / PLT.
    ImportTable,
    /// Export table.
    ExportTable,
    /// Thread-local storage template.
    ThreadLocalStorage,
    /// Exception-handling / unwind metadata.
    ExceptionHandling,
    /// Debug information (DWARF, PDB CV records, …).
    Debug,
    /// Symbol table (static / dynamic).
    SymbolTable,
    /// String table (.strtab, .dynstr, …).
    StringTable,
    /// Dynamic linker metadata (.dynamic, …).
    DynamicLinker,
    /// Process heap arena.
    Heap,
    /// Thread stack.
    Stack,
    /// Memory-mapped file that is neither a PE/ELF section nor a heap.
    MappedFile,
    /// Kernel-mapped special region (VDSO, VSYSCALL, …).
    KernelSpecial,
    /// Device / MMIO mapped region.
    Device,
    /// Guard page (intentionally inaccessible).
    Guard,
    /// Unknown / unclassified.
    Unknown,
}

impl RegionKind {
    /// Return `true` if the region is likely to contain executable code.
    #[must_use]
    pub const fn is_code(&self) -> bool {
        matches!(
            self,
            Self::Code | Self::ImportTable | Self::ExportTable | Self::KernelSpecial
        )
    }

    /// Return `true` if the region is expected to be read-only.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(
            self,
            Self::ReadOnlyData
                | Self::ExceptionHandling
                | Self::Debug
                | Self::SymbolTable
                | Self::StringTable
                | Self::KernelSpecial
        )
    }

    /// Return a short human-readable tag.
    #[must_use]
    pub const fn short_tag(&self) -> &'static str {
        match self {
            Self::Code => "CODE",
            Self::Data => "DATA",
            Self::ReadOnlyData => "RDAT",
            Self::Bss => "BSS",
            Self::ImportTable => "IAT",
            Self::ExportTable => "EAT",
            Self::ThreadLocalStorage => "TLS",
            Self::ExceptionHandling => "EH",
            Self::Debug => "DBG",
            Self::SymbolTable => "SYM",
            Self::StringTable => "STR",
            Self::DynamicLinker => "DYN",
            Self::Heap => "HEAP",
            Self::Stack => "STK",
            Self::MappedFile => "MMAP",
            Self::KernelSpecial => "KERN",
            Self::Device => "DEV",
            Self::Guard => "GUARD",
            Self::Unknown => "???",
        }
    }
}

impl std::fmt::Display for RegionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.short_tag())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegionAttributes — extended metadata attached to a mapped region
// ─────────────────────────────────────────────────────────────────────────────

/// Rich metadata for a single mapped memory region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionAttributes {
    /// Human-readable name (section name, module path basename, …).
    pub name: Option<String>,
    /// Semantic classification.
    pub kind: RegionKind,
    /// File path if this region is backed by a file.
    pub file_path: Option<PathBuf>,
    /// File offset where this region begins (if file-backed).
    pub file_offset: Option<u64>,
    /// Module that owns this region (for process memory).
    pub module_name: Option<String>,
    /// Process ID that owns this region (for process memory providers).
    pub pid: Option<u32>,
    /// `true` if this region has a RELRO protection applied.
    pub relro: bool,
    /// `true` if the region contains position-independent code.
    pub pic: bool,
    /// `true` if the region is part of the kernel address space.
    pub kernel: bool,
    /// Arbitrary analyst comment.
    pub comment: Option<String>,
}

impl Default for RegionAttributes {
    fn default() -> Self {
        Self {
            name: None,
            kind: RegionKind::Unknown,
            file_path: None,
            file_offset: None,
            module_name: None,
            pid: None,
            relro: false,
            pic: false,
            kernel: false,
            comment: None,
        }
    }
}

impl RegionAttributes {
    /// Create a minimal `RegionAttributes` with only a name.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Default::default()
        }
    }

    /// Attach a kind classification.
    #[must_use]
    pub const fn with_kind(mut self, kind: RegionKind) -> Self {
        self.kind = kind;
        self
    }

    /// Attach a backing file path and offset.
    #[must_use]
    pub fn with_file(mut self, path: impl Into<PathBuf>, offset: u64) -> Self {
        self.file_path = Some(path.into());
        self.file_offset = Some(offset);
        self
    }

    /// Attach a module name.
    #[must_use]
    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module_name = Some(module.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtendedRegion — a region with full attributes
// ─────────────────────────────────────────────────────────────────────────────

/// A memory region enriched with [`RegionAttributes`].
///
/// This is the canonical region type used within the memory-provider pipeline.
/// The lightweight [`crate::memory_provider::MemoryRegion`] is used for the
/// trait API boundary; `ExtendedRegion` is used internally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedRegion {
    /// Virtual-address range `[start, end)`.
    pub range: AddressRange,
    /// Access permissions.
    pub perms: Permissions,
    /// Rich metadata.
    pub attrs: RegionAttributes,
}

impl ExtendedRegion {
    /// Create a minimal region.
    #[must_use]
    pub fn new(range: AddressRange, perms: Permissions) -> Self {
        Self {
            range,
            perms,
            attrs: RegionAttributes::default(),
        }
    }

    /// Attach attributes.
    #[must_use]
    pub fn with_attrs(mut self, attrs: RegionAttributes) -> Self {
        self.attrs = attrs;
        self
    }

    /// Byte size of the region.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.range.len()
    }

    /// Return `true` if `addr` is inside the region.
    #[must_use]
    pub const fn contains(&self, addr: Address) -> bool {
        self.range.contains(addr)
    }

    /// Return `true` if the region is readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.perms.is_readable()
    }

    /// Return `true` if the region is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.perms.is_writable()
    }

    /// Return `true` if the region is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.perms.is_executable()
    }

    /// Permission string in `rwx` format.
    #[must_use]
    pub fn rwx_string(&self) -> String {
        self.perms.as_rwx_string()
    }

    /// Return `true` if the region overlaps with `other`.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.range.overlaps(&other.range)
    }
}

impl std::fmt::Display for ExtendedRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self.attrs.name.as_deref().unwrap_or("<anon>");
        write!(
            f,
            "{} [{}..{}) {} {} {}",
            name,
            self.range.start,
            self.range.end,
            self.rwx_string(),
            self.attrs.kind.short_tag(),
            self.size(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegionSet — sorted, non-overlapping collection of ExtendedRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A sorted, efficiently queryable collection of [`ExtendedRegion`]s.
///
/// Regions are stored sorted by start address. The set does **not** enforce
/// non-overlapping invariants on insertion so that it can represent real
/// process maps where regions may partially overlap (e.g. guard pages adjacent
/// to stack).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegionSet {
    regions: Vec<ExtendedRegion>,
}

impl RegionSet {
    /// Create an empty region set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a region and maintain sort order by start address.
    pub fn insert(&mut self, region: ExtendedRegion) {
        let pos = self
            .regions
            .binary_search_by_key(&region.range.start, |r| r.range.start)
            .unwrap_or_else(|i| i);
        self.regions.insert(pos, region);
    }

    /// Remove the region that starts at exactly `addr`.
    /// Returns `true` if a region was found and removed.
    pub fn remove_at(&mut self, addr: Address) -> bool {
        if let Ok(idx) = self.regions.binary_search_by_key(&addr, |r| r.range.start) {
            self.regions.remove(idx);
            true
        } else {
            false
        }
    }

    /// Find the region that contains `addr` (first match by start order).
    #[must_use]
    pub fn find_containing(&self, addr: Address) -> Option<&ExtendedRegion> {
        // Binary search for the last region whose start <= addr, then check.
        let idx = self
            .regions
            .partition_point(|r| r.range.start.as_u64() <= addr.as_u64());
        // idx points one past the last region with start <= addr.
        // Walk backwards to find one whose end > addr.
        for i in (0..idx).rev() {
            if self.regions[i].range.end.as_u64() > addr.as_u64() {
                return Some(&self.regions[i]);
            }
            // Regions are sorted; if this start is already past addr we can stop.
            if self.regions[i].range.start.as_u64() > addr.as_u64() {
                break;
            }
        }
        None
    }

    /// Return all regions that overlap with `range`.
    #[must_use]
    pub fn find_overlapping(&self, range: &AddressRange) -> Vec<&ExtendedRegion> {
        self.regions
            .iter()
            .filter(|r| r.range.overlaps(range))
            .collect()
    }

    /// Return all regions whose permissions include `perms`.
    #[must_use]
    pub fn filter_by_perms(&self, perms: Permissions) -> Vec<&ExtendedRegion> {
        self.regions
            .iter()
            .filter(|r| r.perms.contains(perms))
            .collect()
    }

    /// Return all regions with the given kind.
    #[must_use]
    pub fn filter_by_kind(&self, kind: &RegionKind) -> Vec<&ExtendedRegion> {
        self.regions
            .iter()
            .filter(|r| &r.attrs.kind == kind)
            .collect()
    }

    /// Iterate over all regions in start-address order.
    pub fn iter(&self) -> impl Iterator<Item = &ExtendedRegion> {
        self.regions.iter()
    }

    /// Number of regions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.regions.len()
    }

    /// Return `true` if the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Total number of bytes covered by all regions.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.regions.iter().map(ExtendedRegion::size).sum()
    }

    /// Compute the contiguous "gaps" between consecutive regions.
    ///
    /// Gaps are address ranges that have no associated region.  The result is
    /// sorted by start address and is empty if the region set is empty or has
    /// only one region.
    #[must_use]
    pub fn gaps(&self) -> Vec<AddressRange> {
        if self.regions.len() < 2 {
            return Vec::new();
        }
        let mut result = Vec::new();
        for window in self.regions.windows(2) {
            let end_of_first = window[0].range.end;
            let start_of_second = window[1].range.start;
            if end_of_first.as_u64() < start_of_second.as_u64() {
                result.push(AddressRange::new(end_of_first, start_of_second));
            }
        }
        result
    }

    /// Merge adjacent regions that have identical permissions and kind.
    ///
    /// Two regions are "adjacent" when the end of one equals the start of the
    /// next.  Merging is useful after live-process map refreshes where the OS
    /// splits logically contiguous memory into multiple entries.
    pub fn merge_adjacent(&mut self) {
        if self.regions.len() < 2 {
            return;
        }
        let mut merged: Vec<ExtendedRegion> = Vec::with_capacity(self.regions.len());
        for region in self.regions.drain(..) {
            if let Some(last) = merged.last_mut() {
                let same_perms = last.perms == region.perms;
                let same_kind = last.attrs.kind == region.attrs.kind;
                let adjacent = last.range.end.as_u64() == region.range.start.as_u64();
                if same_perms && same_kind && adjacent {
                    // Extend the last region.
                    last.range = AddressRange::new(last.range.start, region.range.end);
                    continue;
                }
            }
            merged.push(region);
        }
        self.regions = merged;
    }

    /// Return the executable regions sorted by start address.
    #[must_use]
    pub fn executable_regions(&self) -> Vec<&ExtendedRegion> {
        self.filter_by_perms(Permissions::EXECUTE)
    }

    /// Return the writable regions sorted by start address.
    #[must_use]
    pub fn writable_regions(&self) -> Vec<&ExtendedRegion> {
        self.filter_by_perms(Permissions::WRITE)
    }

    /// Return the readable regions sorted by start address.
    #[must_use]
    pub fn readable_regions(&self) -> Vec<&ExtendedRegion> {
        self.filter_by_perms(Permissions::READ)
    }

    /// Return regions whose name contains `s` (case-sensitive substring match).
    #[must_use]
    pub fn filter_by_name(&self, s: &str) -> Vec<&ExtendedRegion> {
        self.regions
            .iter()
            .filter(|r| r.attrs.name.as_deref().is_some_and(|n| n.contains(s)))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AddressRangeHelper — free functions that extend AddressRange
// ─────────────────────────────────────────────────────────────────────────────

/// Align `addr` up to `page_size` (must be a power of two).
#[must_use]
pub fn page_align_up(addr: Address, page_size: u64) -> Address {
    assert!(
        page_size.is_power_of_two(),
        "page_size must be a power of two"
    );
    addr.align_up(page_size)
}

/// Align `addr` down to `page_size` (must be a power of two).
#[must_use]
pub fn page_align_down(addr: Address, page_size: u64) -> Address {
    assert!(
        page_size.is_power_of_two(),
        "page_size must be a power of two"
    );
    addr.align_down(page_size)
}

/// Compute the page index for `addr` given a `page_size`.
#[must_use]
pub const fn page_index(addr: Address, page_size: u64) -> u64 {
    addr.as_u64() / page_size
}

/// Return the range of pages that cover `range` (inclusive both ends).
/// Returns `(first_page_index, last_page_index)`.
#[must_use]
pub fn page_range_indices(range: &AddressRange, page_size: u64) -> (u64, u64) {
    let first = page_index(range.start, page_size);
    let last = page_index(
        Address::new(range.end.as_u64().saturating_sub(1)),
        page_size,
    );
    (first, last.max(first))
}

/// Build an `AddressRange` that covers the page containing `addr`.
///
/// The end is saturated rather than wrapped. On the final page of the address
/// space `start + page_size` overflows, and `from_len` wrapped it to 0 — so
/// `page_containing(0xFFFF_FFFF_FFFF_F000)` returned the inverted range
/// `[0xFFFF_FFFF_FFFF_F000, 0x0)`, which `contains` reports as holding *no*
/// address at all, not even its own start. Kernel-space addresses land there
/// routinely.
///
/// Note the residual limit: `AddressRange` is half-open, so the very last byte
/// (`u64::MAX`) cannot be covered by any non-inverted range. That is a property
/// of the representation, not something this function can repair.
#[must_use]
pub fn page_containing(addr: Address, page_size: u64) -> AddressRange {
    let start = page_align_down(addr, page_size);
    let end = start.as_u64().saturating_add(page_size);
    AddressRange::new(start, Address::new(end))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_region(start: u64, end: u64, perms: Permissions, kind: RegionKind) -> ExtendedRegion {
        ExtendedRegion {
            range: AddressRange::new(Address::new(start), Address::new(end)),
            perms,
            attrs: RegionAttributes {
                kind,
                ..Default::default()
            },
        }
    }

    #[test]
    fn region_kind_predicates() {
        assert!(RegionKind::Code.is_code());
        assert!(!RegionKind::Heap.is_code());
        assert!(RegionKind::ReadOnlyData.is_read_only());
        assert!(!RegionKind::Data.is_read_only());
    }

    #[test]
    fn extended_region_basic() {
        let r = make_region(
            0x1000,
            0x2000,
            Permissions::READ | Permissions::EXECUTE,
            RegionKind::Code,
        );
        assert_eq!(r.size(), 0x1000);
        assert!(r.contains(Address::new(0x1500)));
        assert!(!r.contains(Address::new(0x2000)));
        assert!(r.is_readable());
        assert!(r.is_executable());
        assert!(!r.is_writable());
    }

    #[test]
    fn region_set_insert_find() {
        let mut rs = RegionSet::new();
        rs.insert(make_region(
            0x1000,
            0x2000,
            Permissions::READ,
            RegionKind::Data,
        ));
        rs.insert(make_region(
            0x3000,
            0x4000,
            Permissions::READ | Permissions::WRITE,
            RegionKind::Heap,
        ));
        rs.insert(make_region(
            0x2000,
            0x3000,
            Permissions::READ | Permissions::EXECUTE,
            RegionKind::Code,
        ));

        assert_eq!(rs.len(), 3);
        // Sorted by start: 0x1000, 0x2000, 0x3000
        let regions: Vec<_> = rs.iter().collect();
        assert_eq!(regions[0].range.start, Address::new(0x1000));
        assert_eq!(regions[1].range.start, Address::new(0x2000));
        assert_eq!(regions[2].range.start, Address::new(0x3000));

        let found = rs.find_containing(Address::new(0x1800)).unwrap();
        assert_eq!(found.range.start, Address::new(0x1000));

        assert!(rs.find_containing(Address::new(0x5000)).is_none());
    }

    #[test]
    fn region_set_total_bytes() {
        let mut rs = RegionSet::new();
        rs.insert(make_region(
            0x0,
            0x1000,
            Permissions::READ,
            RegionKind::Code,
        ));
        rs.insert(make_region(
            0x2000,
            0x4000,
            Permissions::READ,
            RegionKind::Data,
        ));
        assert_eq!(rs.total_bytes(), 0x3000);
    }

    #[test]
    fn region_set_gaps() {
        let mut rs = RegionSet::new();
        rs.insert(make_region(
            0x1000,
            0x2000,
            Permissions::READ,
            RegionKind::Code,
        ));
        rs.insert(make_region(
            0x3000,
            0x4000,
            Permissions::READ,
            RegionKind::Data,
        ));
        let gaps = rs.gaps();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].start, Address::new(0x2000));
        assert_eq!(gaps[0].end, Address::new(0x3000));
    }

    #[test]
    fn region_set_merge_adjacent() {
        let mut rs = RegionSet::new();
        rs.insert(make_region(
            0x0,
            0x1000,
            Permissions::READ,
            RegionKind::Code,
        ));
        rs.insert(make_region(
            0x1000,
            0x2000,
            Permissions::READ,
            RegionKind::Code,
        ));
        rs.insert(make_region(
            0x3000,
            0x4000,
            Permissions::READ,
            RegionKind::Data,
        ));
        rs.merge_adjacent();
        assert_eq!(rs.len(), 2);
        let v: Vec<_> = rs.iter().collect();
        assert_eq!(v[0].range.end, Address::new(0x2000));
    }

    #[test]
    fn region_set_filter_by_kind() {
        let mut rs = RegionSet::new();
        rs.insert(make_region(
            0x1000,
            0x2000,
            Permissions::READ | Permissions::EXECUTE,
            RegionKind::Code,
        ));
        rs.insert(make_region(
            0x2000,
            0x3000,
            Permissions::READ | Permissions::WRITE,
            RegionKind::Data,
        ));
        let code_regions = rs.filter_by_kind(&RegionKind::Code);
        assert_eq!(code_regions.len(), 1);
    }

    #[test]
    fn region_set_remove_at() {
        let mut rs = RegionSet::new();
        rs.insert(make_region(
            0x1000,
            0x2000,
            Permissions::READ,
            RegionKind::Data,
        ));
        rs.insert(make_region(
            0x2000,
            0x3000,
            Permissions::READ,
            RegionKind::Data,
        ));
        let removed = rs.remove_at(Address::new(0x1000));
        assert!(removed);
        assert_eq!(rs.len(), 1);
        assert!(!rs.remove_at(Address::new(0x1000))); // already gone
    }

    #[test]
    fn page_helpers() {
        let addr = Address::new(0x1234);
        assert_eq!(page_align_down(addr, 0x1000), Address::new(0x1000));
        assert_eq!(page_align_up(addr, 0x1000), Address::new(0x2000));
        assert_eq!(page_index(addr, 0x1000), 1);
        let range = AddressRange::new(Address::new(0x1000), Address::new(0x3000));
        let (first, last) = page_range_indices(&range, 0x1000);
        assert_eq!(first, 1);
        assert_eq!(last, 2);
    }

    #[test]
    fn page_containing_test() {
        let addr = Address::new(0x1500);
        let page = page_containing(addr, 0x1000);
        assert_eq!(page.start, Address::new(0x1000));
        assert_eq!(page.end, Address::new(0x2000));
    }
}
