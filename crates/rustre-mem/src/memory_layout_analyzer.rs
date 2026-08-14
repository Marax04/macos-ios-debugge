//! Memory layout analysis utilities.
//!
//! Provides [`MemoryLayoutAnalyzer`], [`MemoryRegion`], [`LayoutReport`], and
//! [`analyze_layout()`] for classifying and summarising the segments that make
//! up a process or binary image.

use std::collections::HashMap;
use std::fmt;

use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;

// ─────────────────────────────────────────────────────────────────────────────
// RegionKind
// ─────────────────────────────────────────────────────────────────────────────

/// Semantic classification of a memory region.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RegionKind {
    /// Executable code section.
    Code,
    /// Read-only data (`.rodata`, `.const`, etc.).
    ReadOnlyData,
    /// Mutable data (`.data`, `.bss`).
    MutableData,
    /// Thread-local storage.
    ThreadLocal,
    /// Stack segment.
    Stack,
    /// Heap / dynamic allocation arena.
    Heap,
    /// Memory-mapped file or anonymous mapping.
    MappedFile(String),
    /// Kernel-managed special region (VDSO, gate, etc.).
    Kernel,
    /// Guard page or unmapped sentinel.
    Guard,
    /// Shared library segment.
    SharedLibrary(String),
    /// Purpose could not be determined.
    Unknown,
}

impl RegionKind {
    #[must_use] 
    pub const fn is_code(&self) -> bool {
        matches!(self, Self::Code)
    }

    #[must_use] 
    pub const fn is_writable_data(&self) -> bool {
        matches!(self, Self::MutableData | Self::Heap | Self::Stack)
    }

    #[must_use] 
    pub const fn label(&self) -> &str {
        match self {
            Self::Code => "code",
            Self::ReadOnlyData => "rodata",
            Self::MutableData => "data",
            Self::ThreadLocal => "tls",
            Self::Stack => "stack",
            Self::Heap => "heap",
            Self::MappedFile(_) => "mmap",
            Self::Kernel => "kernel",
            Self::Guard => "guard",
            Self::SharedLibrary(_) => "shlib",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for RegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MappedFile(path) => write!(f, "mmap:{path}"),
            Self::SharedLibrary(name) => write!(f, "shlib:{name}"),
            other => write!(f, "{}", other.label()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A single classified region in the memory layout.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub range: AddressRange,
    pub perms: Permissions,
    pub kind: RegionKind,
    pub name: Option<String>,
    /// Actual resident bytes (may be empty for large/lazy mappings).
    pub bytes: Vec<u8>,
    /// Entropy of the region's contents (0.0 = all same; 8.0 = random).
    pub entropy: f64,
}

impl MemoryRegion {
    #[must_use] 
    pub const fn new(range: AddressRange, perms: Permissions, kind: RegionKind) -> Self {
        Self {
            range,
            perms,
            kind,
            name: None,
            bytes: Vec::new(),
            entropy: 0.0,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use] 
    pub fn with_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.entropy = shannon_entropy(&bytes);
        self.bytes = bytes;
        self
    }

    #[must_use] 
    pub const fn size(&self) -> u64 {
        self.range.end.0.saturating_sub(self.range.start.0)
    }

    #[must_use] 
    pub const fn contains(&self, addr: Address) -> bool {
        addr.0 >= self.range.start.0 && addr.0 < self.range.end.0
    }

    #[must_use] 
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.range.start.0 < other.range.end.0 && other.range.start.0 < self.range.end.0
    }

    /// One-line summary for display.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "{:#x}..{:#x} {} {:?} (entropy={:.2})",
            self.range.start.0,
            self.range.end.0,
            self.kind,
            self.perms,
            self.entropy,
        )
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

// ─────────────────────────────────────────────────────────────────────────────
// LayoutReport
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated statistics and region list produced by [`analyze_layout()`].
#[derive(Debug)]
pub struct LayoutReport {
    /// All classified regions in address order.
    pub regions: Vec<MemoryRegion>,
    /// Total mapped bytes across all regions.
    pub total_mapped_bytes: u64,
    /// Total bytes that are executable.
    pub executable_bytes: u64,
    /// Total bytes that are writable.
    pub writable_bytes: u64,
    /// Total bytes that are both writable and executable (dangerous).
    pub wx_bytes: u64,
    /// Total bytes classified as code.
    pub code_bytes: u64,
    /// Average Shannon entropy across all non-empty regions.
    pub average_entropy: f64,
    /// Number of regions with entropy > 7.0 (likely encrypted/compressed).
    pub high_entropy_regions: usize,
    /// Gaps (unmapped address ranges) between mapped regions.
    pub gaps: Vec<AddressRange>,
}

impl LayoutReport {
    const fn new() -> Self {
        Self {
            regions: Vec::new(),
            total_mapped_bytes: 0,
            executable_bytes: 0,
            writable_bytes: 0,
            wx_bytes: 0,
            code_bytes: 0,
            average_entropy: 0.0,
            high_entropy_regions: 0,
            gaps: Vec::new(),
        }
    }

    /// Find the region containing `addr`, if any.
    #[must_use] 
    pub fn region_at(&self, addr: Address) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    /// All regions of the given `kind` label.
    #[must_use] 
    pub fn regions_by_kind(&self, kind: &RegionKind) -> Vec<&MemoryRegion> {
        self.regions.iter().filter(|r| &r.kind == kind).collect()
    }

    /// All writable+executable regions (security concern).
    #[must_use] 
    pub fn wx_regions(&self) -> Vec<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.perms.is_writable() && r.perms.is_executable())
            .collect()
    }

    /// Produces a multi-line summary string.
    #[must_use] 
    pub fn format_summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Layout: {} regions, {} MiB mapped, {:.2} avg entropy\n",
            self.regions.len(),
            self.total_mapped_bytes / (1024 * 1024),
            self.average_entropy,
        ));
        if self.wx_bytes > 0 {
            out.push_str(&format!("  WARNING: {} WX byte(s) found\n", self.wx_bytes));
        }
        for r in &self.regions {
            out.push_str(&format!("  {}\n", r.summary()));
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryLayoutAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Analyses a set of raw memory mappings and produces a [`LayoutReport`].
#[derive(Debug, Default)]
pub struct MemoryLayoutAnalyzer {
    /// Hints: address → expected region name / kind label.
    hints: HashMap<u64, String>,
}

impl MemoryLayoutAnalyzer {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Provide an address hint that helps the classifier identify a region.
    ///
    /// For example, `(0x7fff0000, "stack")` causes the region starting at
    /// `0x7fff0000` to be classified as [`RegionKind::Stack`].
    pub fn with_hint(mut self, base: u64, label: impl Into<String>) -> Self {
        self.hints.insert(base, label.into());
        self
    }

    /// Classify a single region based on its permissions and optional hints.
    fn classify(
        &self,
        range: AddressRange,
        perms: Permissions,
        name: Option<&str>,
        bytes: &[u8],
    ) -> MemoryRegion {
        let hint_label = self.hints.get(&range.start.0).map(String::as_str);
        let kind = self.infer_kind(hint_label, name, perms, bytes);
        let mut region = MemoryRegion::new(range, perms, kind);
        if let Some(n) = name {
            region.name = Some(n.to_string());
        }
        if !bytes.is_empty() {
            region.entropy = shannon_entropy(bytes);
            region.bytes = bytes.to_vec();
        }
        region
    }

    fn infer_kind(
        &self,
        hint: Option<&str>,
        name: Option<&str>,
        perms: Permissions,
        bytes: &[u8],
    ) -> RegionKind {
        // Hint takes precedence.
        if let Some(h) = hint {
            return match h.to_ascii_lowercase().as_str() {
                "stack" => RegionKind::Stack,
                "heap" => RegionKind::Heap,
                "code" => RegionKind::Code,
                "rodata" | "readonly" => RegionKind::ReadOnlyData,
                "data" => RegionKind::MutableData,
                "tls" => RegionKind::ThreadLocal,
                "guard" => RegionKind::Guard,
                "kernel" => RegionKind::Kernel,
                other => RegionKind::MappedFile(other.to_string()),
            };
        }

        // Name-based heuristics (e.g. from /proc/maps).
        if let Some(n) = name {
            let lower = n.to_ascii_lowercase();
            if lower.contains("[stack]") {
                return RegionKind::Stack;
            }
            if lower.contains("[heap]") {
                return RegionKind::Heap;
            }
            if lower.contains("[vdso]") || lower.contains("[vsyscall]") {
                return RegionKind::Kernel;
            }
            if lower.contains("[guard]") {
                return RegionKind::Guard;
            }
            if lower.ends_with(".so") || lower.contains(".so.") {
                return RegionKind::SharedLibrary(n.to_string());
            }
            if !n.is_empty() {
                return RegionKind::MappedFile(n.to_string());
            }
        }

        // Permission-based heuristics.
        if perms.is_executable() && !perms.is_writable() {
            if bytes.len() >= 2 && (bytes[0] == 0x4D || bytes[0] == 0x7F) {
                return RegionKind::Code; // MZ or ELF header
            }
            return RegionKind::Code;
        }
        if perms.is_readable() && !perms.is_writable() && !perms.is_executable() {
            return RegionKind::ReadOnlyData;
        }
        if perms.is_writable() && !perms.is_executable() {
            return RegionKind::MutableData;
        }
        if !perms.is_readable() && !perms.is_writable() && !perms.is_executable() {
            return RegionKind::Guard;
        }

        RegionKind::Unknown
    }

    // ── Compute gaps ───────────────────────────────────────────────────────

    fn compute_gaps(regions: &[MemoryRegion]) -> Vec<AddressRange> {
        let mut gaps = Vec::new();
        let mut sorted: Vec<(u64, u64)> =
            regions.iter().map(|r| (r.range.start.0, r.range.end.0)).collect();
        sorted.sort_by_key(|(s, _)| *s);

        for window in sorted.windows(2) {
            let end_prev = window[0].1;
            let start_next = window[1].0;
            if end_prev < start_next {
                gaps.push(AddressRange::new(
                    Address::new(end_prev),
                    Address::new(start_next),
                ));
            }
        }
        gaps
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Input type for the analyser
// ─────────────────────────────────────────────────────────────────────────────

/// Raw mapping descriptor passed to [`analyze_layout()`].
#[derive(Debug, Clone)]
pub struct RawMapping {
    pub base: Address,
    pub size: u64,
    pub perms: Permissions,
    pub name: Option<String>,
    pub bytes: Vec<u8>,
}

impl RawMapping {
    #[must_use] 
    pub const fn new(base: u64, size: u64, perms: Permissions) -> Self {
        Self {
            base: Address::new(base),
            size,
            perms,
            name: None,
            bytes: Vec::new(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use] 
    pub fn with_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.bytes = bytes;
        self
    }

    #[must_use] 
    pub const fn end_address(&self) -> Address {
        Address::new(self.base.0 + self.size)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// analyze_layout — primary entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Analyse a list of raw memory mappings and produce a [`LayoutReport`].
#[must_use] 
pub fn analyze_layout(analyzer: &MemoryLayoutAnalyzer, mappings: &[RawMapping]) -> LayoutReport {
    let mut report = LayoutReport::new();

    let mut entropy_sum = 0.0f64;
    let mut entropy_count = 0usize;

    for mapping in mappings {
        let range =
            AddressRange::new(mapping.base, mapping.end_address());
        let region = analyzer.classify(
            range,
            mapping.perms,
            mapping.name.as_deref(),
            &mapping.bytes,
        );

        let size = region.size();
        report.total_mapped_bytes += size;

        if mapping.perms.is_executable() {
            report.executable_bytes += size;
        }
        if mapping.perms.is_writable() {
            report.writable_bytes += size;
        }
        if mapping.perms.is_writable() && mapping.perms.is_executable() {
            report.wx_bytes += size;
        }
        if region.kind.is_code() {
            report.code_bytes += size;
        }

        if !mapping.bytes.is_empty() {
            entropy_sum += region.entropy;
            entropy_count += 1;
            if region.entropy > 7.0 {
                report.high_entropy_regions += 1;
            }
        }

        report.regions.push(region);
    }

    // Sort regions by start address.
    report.regions.sort_by_key(|r| r.range.start.0);

    report.average_entropy =
        if entropy_count > 0 { entropy_sum / entropy_count as f64 } else { 0.0 };

    report.gaps = MemoryLayoutAnalyzer::compute_gaps(&report.regions);

    report
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rx() -> Permissions {
        Permissions::READ | Permissions::EXECUTE
    }
    fn rw() -> Permissions {
        Permissions::READ | Permissions::WRITE
    }
    fn r() -> Permissions {
        Permissions::READ
    }
    fn rwx() -> Permissions {
        Permissions::READ | Permissions::WRITE | Permissions::EXECUTE
    }

    #[test]
    fn classifies_code_region_by_perms() {
        let analyzer = MemoryLayoutAnalyzer::new();
        let mappings = vec![RawMapping::new(0x1000, 0x1000, rx())];
        let report = analyze_layout(&analyzer, &mappings);
        assert_eq!(report.regions.len(), 1);
        assert_eq!(report.regions[0].kind, RegionKind::Code);
        assert_eq!(report.executable_bytes, 0x1000);
    }

    #[test]
    fn classifies_stack_by_hint() {
        let analyzer = MemoryLayoutAnalyzer::new().with_hint(0x7fff0000, "stack");
        let mappings = vec![RawMapping::new(0x7fff0000, 0x10000, rw())];
        let report = analyze_layout(&analyzer, &mappings);
        assert_eq!(report.regions[0].kind, RegionKind::Stack);
    }

    #[test]
    fn classifies_stack_by_name() {
        let analyzer = MemoryLayoutAnalyzer::new();
        let mappings =
            vec![RawMapping::new(0x7fff0000, 0x1000, rw()).with_name("[stack]")];
        let report = analyze_layout(&analyzer, &mappings);
        assert_eq!(report.regions[0].kind, RegionKind::Stack);
    }

    #[test]
    fn classifies_heap_by_name() {
        let analyzer = MemoryLayoutAnalyzer::new();
        let mappings =
            vec![RawMapping::new(0x10000000, 0x4000, rw()).with_name("[heap]")];
        let report = analyze_layout(&analyzer, &mappings);
        assert_eq!(report.regions[0].kind, RegionKind::Heap);
    }

    #[test]
    fn classifies_shared_library() {
        let analyzer = MemoryLayoutAnalyzer::new();
        let mappings =
            vec![RawMapping::new(0x7f000000, 0x8000, rx()).with_name("libc.so.6")];
        let report = analyze_layout(&analyzer, &mappings);
        assert!(matches!(report.regions[0].kind, RegionKind::SharedLibrary(_)));
    }

    #[test]
    fn detects_wx_region() {
        let analyzer = MemoryLayoutAnalyzer::new();
        let mappings = vec![RawMapping::new(0x2000, 0x1000, rwx())];
        let report = analyze_layout(&analyzer, &mappings);
        assert_eq!(report.wx_bytes, 0x1000);
        assert_eq!(report.wx_regions().len(), 1);
    }

    #[test]
    fn computes_gaps() {
        let analyzer = MemoryLayoutAnalyzer::new();
        let mappings = vec![
            RawMapping::new(0x1000, 0x1000, r()),
            RawMapping::new(0x3000, 0x1000, r()),
        ];
        let report = analyze_layout(&analyzer, &mappings);
        assert_eq!(report.gaps.len(), 1);
        assert_eq!(report.gaps[0].start.0, 0x2000);
        assert_eq!(report.gaps[0].end.0, 0x3000);
    }

    #[test]
    fn no_gaps_when_contiguous() {
        let analyzer = MemoryLayoutAnalyzer::new();
        let mappings = vec![
            RawMapping::new(0x1000, 0x1000, r()),
            RawMapping::new(0x2000, 0x1000, r()),
        ];
        let report = analyze_layout(&analyzer, &mappings);
        assert!(report.gaps.is_empty());
    }

    #[test]
    fn region_at_returns_correct() {
        let analyzer = MemoryLayoutAnalyzer::new();
        let mappings = vec![RawMapping::new(0x4000, 0x2000, rx())];
        let report = analyze_layout(&analyzer, &mappings);
        assert!(report.region_at(Address::new(0x5000)).is_some());
        assert!(report.region_at(Address::new(0x3FFF)).is_none());
        assert!(report.region_at(Address::new(0x6000)).is_none());
    }

    #[test]
    fn entropy_calculation_for_uniform_data() {
        let bytes = vec![0xAAu8; 256];
        let ent = shannon_entropy(&bytes);
        assert!((ent - 0.0).abs() < 1e-9);
    }

    #[test]
    fn entropy_calculation_for_random_data() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let ent = shannon_entropy(&bytes);
        assert!((ent - 8.0).abs() < 0.01);
    }

    #[test]
    fn high_entropy_region_detected() {
        let analyzer = MemoryLayoutAnalyzer::new();
        let bytes: Vec<u8> = (0u8..=255).collect();
        let mappings = vec![
            RawMapping::new(0x1000, bytes.len() as u64, r()).with_bytes(bytes)
        ];
        let report = analyze_layout(&analyzer, &mappings);
        assert_eq!(report.high_entropy_regions, 1);
    }

    #[test]
    fn total_mapped_bytes_sums() {
        let analyzer = MemoryLayoutAnalyzer::new();
        let mappings = vec![
            RawMapping::new(0x1000, 0x100, r()),
            RawMapping::new(0x2000, 0x200, rw()),
        ];
        let report = analyze_layout(&analyzer, &mappings);
        assert_eq!(report.total_mapped_bytes, 0x300);
    }

    #[test]
    fn guard_page_classification() {
        let analyzer = MemoryLayoutAnalyzer::new();
        let none_perms = Permissions::empty();
        let mappings = vec![RawMapping::new(0x5000, 0x1000, none_perms)];
        let report = analyze_layout(&analyzer, &mappings);
        assert_eq!(report.regions[0].kind, RegionKind::Guard);
    }

    #[test]
    fn format_summary_includes_region_count() {
        let analyzer = MemoryLayoutAnalyzer::new();
        let mappings = vec![RawMapping::new(0x1000, 0x1000, r())];
        let report = analyze_layout(&analyzer, &mappings);
        let summary = report.format_summary();
        assert!(summary.contains("1 regions"));
    }
}
