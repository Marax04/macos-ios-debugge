//! Process memory dump analysis for `rustre-forensics-mem`.
//!
//! Provides higher-level analysis of a captured process dump beyond the
//! basic PE/module walking in the parent crate.  Key components:
//!
//! - [`ProcessDumpAnalyzer`]: orchestrates all sub-analyses.
//! - [`InjectedModule`]: detects PE images in unexpected memory regions.
//! - [`HeapSprayDetection`]: looks for heap-spray artefacts.
//! - [`PEBWalker`]: walks the Process Environment Block loader list.
//! - [`VadAnalysis`]: produces a virtual address descriptor summary.
//! - [`KernelObjectAddresses`]: collects kernel object addresses from VAD.
//! - [`HiddenProcess`]: heuristic cross-check for DKOM-hidden processes.
//! - [`MemoryArtifact`]: generic taggable artefact found in a dump.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use crate::casts::{u64_to_f64, usize_to_f64, usize_to_u8};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from process dump analysis.
#[derive(Debug, thiserror::Error)]
pub enum DumpError {
    #[error("short read at 0x{0:016x}")]
    ShortRead(u64),
    #[error("invalid PE at 0x{0:016x}: {1}")]
    InvalidPe(u64, String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("not a process dump")]
    NotProcessDump,
}

// ---------------------------------------------------------------------------
// Lightweight memory region model
// ---------------------------------------------------------------------------

/// Protection flags on a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegionProtect(pub u32);

impl RegionProtect {
    pub const NONE: Self = Self(0x01);
    pub const READ: Self = Self(0x02);
    pub const READWRITE: Self = Self(0x04);
    pub const WRITECOPY: Self = Self(0x08);
    pub const EXECUTE: Self = Self(0x10);
    pub const EXECUTE_READ: Self = Self(0x20);
    pub const EXECUTE_READWRITE: Self = Self(0x40);
    pub const EXECUTE_WRITECOPY: Self = Self(0x80);

    #[must_use]
    pub const fn is_executable(self) -> bool {
        (self.0 & 0xF0) != 0
    }

    #[must_use]
    pub const fn is_writable(self) -> bool {
        matches!(
            self,
            Self::READWRITE | Self::WRITECOPY | Self::EXECUTE_READWRITE | Self::EXECUTE_WRITECOPY
        )
    }
}

impl fmt::Display for RegionProtect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::EXECUTE_READWRITE => write!(f, "RWX"),
            Self::EXECUTE_READ => write!(f, "RX"),
            Self::READWRITE => write!(f, "RW"),
            _ => write!(f, "0x{:02X}", self.0),
        }
    }
}

/// State of a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionState {
    Commit,
    Reserve,
    Free,
}

/// Type of a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionType {
    Private,
    Mapped,
    Image,
    Unknown,
}

/// A virtual address region in the process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualRegion {
    pub base: u64,
    pub size: u64,
    pub protect: RegionProtect,
    pub state: RegionState,
    pub region_type: RegionType,
    pub mapped_file: Option<String>,
    pub data: Vec<u8>,
}

impl VirtualRegion {
    /// End address (exclusive).
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
    }

    /// Returns `true` if the region contains the given address.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }

    /// Read bytes at the given offset within the region.
    #[must_use]
    pub fn read(&self, offset: usize, len: usize) -> Option<&[u8]> {
        if offset + len <= self.data.len() {
            Some(&self.data[offset..offset + len])
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// MemoryArtifact
// ---------------------------------------------------------------------------

/// Severity of an artefact finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        };
        write!(f, "{s}")
    }
}

/// A tagged artefact found during memory dump analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryArtifact {
    /// Virtual address where the artefact was found.
    pub address: u64,
    /// Human-readable name / type.
    pub kind: String,
    /// Brief description.
    pub description: String,
    /// Severity of the finding.
    pub severity: Severity,
    /// Raw bytes associated with the artefact (if small enough to embed).
    pub data: Vec<u8>,
    /// Key-value metadata.
    pub metadata: HashMap<String, String>,
}

impl MemoryArtifact {
    /// Create a new artefact.
    #[must_use]
    pub fn new(
        address: u64,
        kind: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            address,
            kind: kind.into(),
            description: description.into(),
            severity,
            data: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Attach raw bytes.
    #[must_use]
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// Attach a metadata key-value pair.
    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

impl fmt::Display for MemoryArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {:#018x}: {} — {}",
            self.severity, self.address, self.kind, self.description
        )
    }
}

// ---------------------------------------------------------------------------
// InjectedModule
// ---------------------------------------------------------------------------

/// Detected PE image in a memory region that is not in the loader list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectedModule {
    pub base: u64,
    pub size: u64,
    pub region_protect: RegionProtect,
    /// Best-guess name extracted from the PE header (may be empty).
    pub apparent_name: String,
    /// Whether the module is in the loader's module list.
    pub in_loader_list: bool,
    /// Confidence that this is an injected PE (0.0–1.0).
    pub confidence: f32,
    pub pe_header_present: bool,
    pub has_export_directory: bool,
}

impl InjectedModule {
    /// Returns `true` if this is likely an injected PE.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        !self.in_loader_list && self.pe_header_present
    }
}

/// Scans memory regions for PE images that are not in the known loader list.
#[derive(Debug, Default)]
pub struct InjectedModuleScanner {
    pub findings: Vec<InjectedModule>,
}

impl InjectedModuleScanner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `regions` for PE MZ headers and compare against `loaded_modules`.
    pub fn scan(&mut self, regions: &[VirtualRegion], loaded_bases: &[u64]) {
        let loaded_set: std::collections::HashSet<u64> = loaded_bases.iter().copied().collect();
        for region in regions {
            if region.data.len() < 4 {
                continue;
            }
            if &region.data[0..2] != b"MZ" {
                continue;
            }

            let in_loader = loaded_set.contains(&region.base);
            let has_pe = Self::has_pe_signature(&region.data);
            let apparent_name = Self::extract_module_name(&region.data);
            let has_exports = has_pe && Self::has_export_directory(&region.data);
            let confidence = if !in_loader && has_pe {
                0.9
            } else if !in_loader {
                0.5
            } else {
                0.0
            };

            self.findings.push(InjectedModule {
                base: region.base,
                size: region.size,
                region_protect: region.protect,
                apparent_name,
                in_loader_list: in_loader,
                confidence,
                pe_header_present: has_pe,
                has_export_directory: has_exports,
            });
        }
    }

    fn has_pe_signature(data: &[u8]) -> bool {
        if data.len() < 64 {
            return false;
        }
        if &data[0..2] != b"MZ" {
            return false;
        }
        let pe_off = u32::from_le_bytes(data[60..64].try_into().unwrap_or([0; 4])) as usize;
        pe_off + 4 <= data.len() && &data[pe_off..pe_off + 4] == b"PE\0\0"
    }

    fn has_export_directory(data: &[u8]) -> bool {
        // Simplified heuristic: look for "export" in the first 4KB.
        data.windows(6).any(|w| w == b"EXPORT")
    }

    fn extract_module_name(data: &[u8]) -> String {
        // Try to find a null-terminated ASCII string that looks like a DLL name
        // in the first 1KB.
        let scan_len = data.len().min(1024);
        let mut best = String::new();
        let mut i = 0;
        while i < scan_len {
            if data[i].is_ascii_alphanumeric() || data[i] == b'.' {
                let start = i;
                while i < scan_len
                    && (data[i].is_ascii_alphanumeric() || data[i] == b'.' || data[i] == b'_')
                {
                    i += 1;
                }
                let candidate = std::str::from_utf8(&data[start..i])
                    .unwrap_or("")
                    .to_lowercase();
                if (std::path::Path::new(&candidate).extension().is_some_and(|e| e.eq_ignore_ascii_case("dll")) || std::path::Path::new(&candidate).extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")))
                    && candidate.len() > best.len()
                {
                    best = candidate;
                }
            } else {
                i += 1;
            }
        }
        best
    }
}

// ---------------------------------------------------------------------------
// HeapSprayDetection
// ---------------------------------------------------------------------------

/// Detected heap-spray region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapSprayRegion {
    pub base: u64,
    pub size: u64,
    pub pattern_entropy: f64,
    pub dominant_byte: u8,
    pub repetition_score: f64,
    pub suspected_nop_sled: bool,
    pub suspected_shellcode: bool,
}

/// Detects heap-spray patterns: high repetition of a filler byte (often 0x0C
/// or 0x90) followed by shellcode.
#[derive(Debug, Default)]
pub struct HeapSprayDetection {
    pub regions: Vec<HeapSprayRegion>,
    /// Minimum region size to analyze (bytes).
    pub min_size: u64,
    /// Repetition threshold (0.0–1.0): fraction of bytes that equal the
    /// dominant byte to consider a spray.
    pub repetition_threshold: f64,
}

impl HeapSprayDetection {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_size: 4096,
            repetition_threshold: 0.7,
            regions: Vec::new(),
        }
    }

    /// Scan all regions.
    pub fn scan(&mut self, regions: &[VirtualRegion]) {
        for region in regions {
            if region.size < self.min_size {
                continue;
            }
            if region.data.is_empty() {
                continue;
            }
            self.analyze_region(region);
        }
    }

    fn analyze_region(&mut self, region: &VirtualRegion) {
        let data = &region.data;
        // Byte frequency.
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let total = usize_to_f64(data.len());
        let (dominant_byte, dominant_count) = freq
            .iter()
            .enumerate()
            .max_by_key(|&(_, &c)| c)
            .map_or((0, 0), |(i, &c)| (usize_to_u8(i), c));
        let repetition_score = u64_to_f64(dominant_count) / total;
        if repetition_score < self.repetition_threshold {
            return;
        }

        let entropy = Self::shannon_entropy(data);
        let suspected_nop_sled = dominant_byte == 0x90 && repetition_score > 0.8;
        let suspected_shellcode = region.protect.is_executable();

        self.regions.push(HeapSprayRegion {
            base: region.base,
            size: region.size,
            pattern_entropy: entropy,
            dominant_byte,
            repetition_score,
            suspected_nop_sled,
            suspected_shellcode,
        });
    }

    fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let n = usize_to_f64(data.len());
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = u64_to_f64(c) / n;
                -p * p.log2()
            })
            .sum()
    }
}

// ---------------------------------------------------------------------------
// PEBWalker
// ---------------------------------------------------------------------------

/// An entry from the PEB loader list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedModule {
    pub base: u64,
    pub size: u64,
    pub name: String,
    pub full_path: String,
    pub entry_point: u64,
    pub flags: u32,
}

/// Walks the Process Environment Block loader linked list to enumerate modules.
#[derive(Debug, Default)]
pub struct PEBWalker {
    pub modules: Vec<LoadedModule>,
}

impl PEBWalker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulate walking the PEB loader list from known module entries.
    ///
    /// In a real implementation this would follow the `LDR_DATA_TABLE_ENTRY`
    /// doubly-linked list at `PEB.Ldr.InLoadOrderModuleList`.  Here we accept
    /// pre-parsed entries directly.
    pub fn add_module(&mut self, module: LoadedModule) {
        self.modules.push(module);
    }

    /// Find a module by base address.
    #[must_use]
    pub fn find_by_base(&self, base: u64) -> Option<&LoadedModule> {
        self.modules.iter().find(|m| m.base == base)
    }

    /// Find a module by name (case-insensitive).
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&LoadedModule> {
        let lower = name.to_lowercase();
        self.modules.iter().find(|m| m.name.to_lowercase() == lower)
    }

    /// All module base addresses.
    #[must_use]
    pub fn bases(&self) -> Vec<u64> {
        self.modules.iter().map(|m| m.base).collect()
    }
}

// ---------------------------------------------------------------------------
// VadAnalysis
// ---------------------------------------------------------------------------

/// Summary of a VAD node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VadNode {
    pub start: u64,
    pub end: u64,
    pub protect: RegionProtect,
    pub tag: String,
    pub mapped_file: Option<String>,
    pub suspicious: bool,
}

impl VadNode {
    /// Size of the region in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// Summarizes the Virtual Address Descriptor tree for a process.
#[derive(Debug, Default)]
pub struct VadAnalysis {
    pub nodes: Vec<VadNode>,
    pub suspicious_count: usize,
}

impl VadAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a VAD summary from memory regions.
    pub fn build(&mut self, regions: &[VirtualRegion]) {
        self.nodes.clear();
        self.suspicious_count = 0;
        for region in regions {
            let suspicious =
                region.protect.is_executable() && region.region_type == RegionType::Private;
            if suspicious {
                self.suspicious_count += 1;
            }
            self.nodes.push(VadNode {
                start: region.base,
                end: region.end(),
                protect: region.protect,
                tag: format!("{:?}", region.region_type),
                mapped_file: region.mapped_file.clone(),
                suspicious,
            });
        }
    }

    /// Return only suspicious (private + executable) nodes.
    #[must_use]
    pub fn suspicious_nodes(&self) -> Vec<&VadNode> {
        self.nodes.iter().filter(|n| n.suspicious).collect()
    }

    /// Total virtual memory size covered.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.nodes.iter().map(VadNode::size).sum()
    }
}

// ---------------------------------------------------------------------------
// KernelObjectAddresses
// ---------------------------------------------------------------------------

/// Addresses of kernel objects found in the process VAD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelObjectRef {
    pub address: u64,
    pub object_type: String,
    pub handle_value: u64,
}

/// Collects kernel object addresses from VAD metadata.
#[derive(Debug, Default)]
pub struct KernelObjectAddresses {
    pub objects: Vec<KernelObjectRef>,
}

impl KernelObjectAddresses {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a kernel object reference.
    pub fn add(&mut self, address: u64, object_type: impl Into<String>, handle_value: u64) {
        self.objects.push(KernelObjectRef {
            address,
            object_type: object_type.into(),
            handle_value,
        });
    }

    /// Return objects of the given type.
    #[must_use]
    pub fn of_type(&self, ty: &str) -> Vec<&KernelObjectRef> {
        self.objects
            .iter()
            .filter(|o| o.object_type == ty)
            .collect()
    }

    /// Count of objects.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.objects.len()
    }
}

// ---------------------------------------------------------------------------
// HiddenProcess
// ---------------------------------------------------------------------------

/// Evidence that a process may have been hidden via DKOM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiddenProcessIndicator {
    pub pid: u32,
    pub name: String,
    /// How the process was discovered.
    pub discovery_method: String,
    /// Description of the anomaly.
    pub reason: String,
    pub confidence: f32,
}

/// Detects potential DKOM-hidden processes by cross-referencing multiple
/// process enumeration methods.
#[derive(Debug, Default)]
pub struct HiddenProcess {
    pub indicators: Vec<HiddenProcessIndicator>,
}

impl HiddenProcess {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Cross-reference `from_eprocess` (EPROCESS scan) with `from_peb`
    /// (PEB-based enumeration).  Processes in `from_eprocess` but not in
    /// `from_peb` are candidates for DKOM hiding.
    pub fn cross_reference(&mut self, from_eprocess: &[(u32, String)], from_peb: &[(u32, String)]) {
        let peb_pids: std::collections::HashSet<u32> = from_peb.iter().map(|(p, _)| *p).collect();
        for (pid, name) in from_eprocess {
            if !peb_pids.contains(pid) {
                self.indicators.push(HiddenProcessIndicator {
                    pid: *pid,
                    name: name.clone(),
                    discovery_method: "EPROCESS_scan".to_string(),
                    reason: "visible in EPROCESS list but not in PEB loader list".to_string(),
                    confidence: 0.75,
                });
            }
        }
    }

    /// Add a manual indicator.
    pub fn add_indicator(&mut self, indicator: HiddenProcessIndicator) {
        self.indicators.push(indicator);
    }

    /// High-confidence hidden process indicators (confidence ≥ 0.8).
    #[must_use]
    pub fn high_confidence(&self) -> Vec<&HiddenProcessIndicator> {
        self.indicators
            .iter()
            .filter(|i| i.confidence >= 0.8)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ProcessDumpAnalyzer
// ---------------------------------------------------------------------------

/// High-level orchestrator for process dump analysis.
pub struct ProcessDumpAnalyzer {
    pub regions: Vec<VirtualRegion>,
    pub injected_modules: InjectedModuleScanner,
    pub heap_spray: HeapSprayDetection,
    pub peb: PEBWalker,
    pub vad: VadAnalysis,
    pub kernel_objects: KernelObjectAddresses,
    pub hidden_processes: HiddenProcess,
    pub artifacts: Vec<MemoryArtifact>,
}

impl ProcessDumpAnalyzer {
    /// Create an empty analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            injected_modules: InjectedModuleScanner::new(),
            heap_spray: HeapSprayDetection::new(),
            peb: PEBWalker::new(),
            vad: VadAnalysis::new(),
            kernel_objects: KernelObjectAddresses::new(),
            hidden_processes: HiddenProcess::new(),
            artifacts: Vec::new(),
        }
    }

    /// Add a virtual region to be analyzed.
    pub fn add_region(&mut self, region: VirtualRegion) {
        self.regions.push(region);
    }

    /// Run all analysis passes.
    pub fn analyze(&mut self) {
        let loader_bases = self.peb.bases();
        self.injected_modules.scan(&self.regions, &loader_bases);
        self.heap_spray.scan(&self.regions);
        self.vad.build(&self.regions);

        // Promote suspicious injected modules to artifacts.
        for m in &self.injected_modules.findings {
            if m.is_suspicious() {
                self.artifacts.push(
                    MemoryArtifact::new(
                        m.base,
                        "InjectedModule",
                        format!("PE at {:#x} not in loader list", m.base),
                        Severity::High,
                    )
                    .with_meta("name", m.apparent_name.clone())
                    .with_meta("protect", m.region_protect.to_string()),
                );
            }
        }
        for hs in &self.heap_spray.regions {
            self.artifacts.push(MemoryArtifact::new(
                hs.base,
                "HeapSpray",
                format!("repetitive pattern ({:.0}%)", hs.repetition_score * 100.0),
                if hs.suspected_shellcode {
                    Severity::High
                } else {
                    Severity::Medium
                },
            ));
        }
        for vad in self.vad.suspicious_nodes() {
            self.artifacts.push(MemoryArtifact::new(
                vad.start,
                "SuspiciousVad",
                format!("private executable region {:#x}-{:#x}", vad.start, vad.end),
                Severity::Medium,
            ));
        }
    }

    /// Return artifacts sorted by severity (highest first).
    #[must_use]
    pub fn sorted_artifacts(&self) -> Vec<&MemoryArtifact> {
        let mut v: Vec<&MemoryArtifact> = self.artifacts.iter().collect();
        v.sort_by(|a, b| b.severity.cmp(&a.severity));
        v
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "ProcessDumpAnalyzer: {} regions, {} injected, {} heap_spray, {} artifacts",
            self.regions.len(),
            self.injected_modules.findings.len(),
            self.heap_spray.regions.len(),
            self.artifacts.len(),
        )
    }
}

impl Default for ProcessDumpAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_region(
        base: u64,
        data: Vec<u8>,
        protect: RegionProtect,
        rtype: RegionType,
    ) -> VirtualRegion {
        let size = data.len() as u64;
        VirtualRegion {
            base,
            size,
            protect,
            state: RegionState::Commit,
            region_type: rtype,
            mapped_file: None,
            data,
        }
    }

    fn make_pe_data(add_pe_sig: bool) -> Vec<u8> {
        let mut data = vec![0u8; 256];
        data[0] = b'M';
        data[1] = b'Z';
        if add_pe_sig {
            data[60..64].copy_from_slice(&64u32.to_le_bytes());
            data[64..68].copy_from_slice(b"PE\0\0");
        }
        data
    }

    // ── RegionProtect ──────────────────────────────────────────────────────

    #[test]
    fn protect_executable() {
        assert!(RegionProtect::EXECUTE_READ.is_executable());
        assert!(RegionProtect::EXECUTE_READWRITE.is_executable());
        assert!(!RegionProtect::READWRITE.is_executable());
    }

    #[test]
    fn protect_display() {
        assert_eq!(RegionProtect::EXECUTE_READWRITE.to_string(), "RWX");
        assert_eq!(RegionProtect::READWRITE.to_string(), "RW");
    }

    // ── MemoryArtifact ─────────────────────────────────────────────────────

    #[test]
    fn artifact_display() {
        let a = MemoryArtifact::new(0x1000, "Test", "desc", Severity::High);
        let s = a.to_string();
        assert!(s.contains("Test"));
        assert!(s.contains("HIGH"));
        assert!(s.contains("0x0000000000001000"));
    }

    #[test]
    fn artifact_with_meta() {
        let a = MemoryArtifact::new(0, "T", "d", Severity::Low).with_meta("key", "val");
        assert_eq!(a.metadata.get("key").unwrap(), "val");
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Info < Severity::Low);
    }

    // ── InjectedModuleScanner ──────────────────────────────────────────────

    #[test]
    fn injected_module_mz_no_pe_not_suspicious() {
        let mut scanner = InjectedModuleScanner::new();
        let data = {
            let mut d = vec![0u8; 100];
            d[0] = b'M';
            d[1] = b'Z';
            d
        };
        let region = make_region(0x1000, data, RegionProtect::READ, RegionType::Mapped);
        scanner.scan(&[region], &[]);
        // MZ without PE sig → pe_header_present = false → not suspicious
        assert!(!scanner.findings.iter().any(super::InjectedModule::is_suspicious));
    }

    #[test]
    fn injected_module_full_pe_not_in_loader() {
        let mut scanner = InjectedModuleScanner::new();
        let data = make_pe_data(true);
        let region = make_region(
            0x400000,
            data,
            RegionProtect::EXECUTE_READ,
            RegionType::Image,
        );
        scanner.scan(&[region], &[]);
        assert!(scanner.findings.iter().any(super::InjectedModule::is_suspicious));
    }

    #[test]
    fn injected_module_in_loader_list_not_suspicious() {
        let mut scanner = InjectedModuleScanner::new();
        let data = make_pe_data(true);
        let region = make_region(
            0x400000,
            data,
            RegionProtect::EXECUTE_READ,
            RegionType::Image,
        );
        scanner.scan(&[region], &[0x400000]);
        assert!(!scanner.findings.iter().any(super::InjectedModule::is_suspicious));
    }

    // ── HeapSprayDetection ─────────────────────────────────────────────────

    #[test]
    fn heap_spray_detects_nop_sled() {
        let mut hsd = HeapSprayDetection::new();
        hsd.min_size = 100;
        let data = vec![0x90u8; 200]; // all NOPs
        let region = make_region(
            0x2000,
            data,
            RegionProtect::EXECUTE_READ,
            RegionType::Private,
        );
        hsd.scan(&[region]);
        assert!(!hsd.regions.is_empty());
        assert!(hsd.regions[0].suspected_nop_sled);
    }

    #[test]
    fn heap_spray_no_spray_random_data() {
        let mut hsd = HeapSprayDetection::new();
        hsd.min_size = 100;
        let data: Vec<u8> = (0..200u8).collect();
        let region = make_region(0x3000, data, RegionProtect::READ, RegionType::Private);
        hsd.scan(&[region]);
        assert!(hsd.regions.is_empty());
    }

    // ── PEBWalker ─────────────────────────────────────────────────────────

    #[test]
    fn peb_walker_find_by_base() {
        let mut walker = PEBWalker::new();
        walker.add_module(LoadedModule {
            base: 0x7FF00000,
            size: 0x10000,
            name: "ntdll.dll".to_string(),
            full_path: "C:\\Windows\\System32\\ntdll.dll".to_string(),
            entry_point: 0x7FF01000,
            flags: 0,
        });
        let m = walker.find_by_base(0x7FF00000).unwrap();
        assert_eq!(m.name, "ntdll.dll");
    }

    #[test]
    fn peb_walker_find_by_name_case_insensitive() {
        let mut walker = PEBWalker::new();
        walker.add_module(LoadedModule {
            base: 0x1000,
            size: 0x1000,
            name: "Kernel32.dll".to_string(),
            full_path: String::new(),
            entry_point: 0,
            flags: 0,
        });
        assert!(walker.find_by_name("kernel32.dll").is_some());
    }

    #[test]
    fn peb_walker_bases() {
        let mut walker = PEBWalker::new();
        walker.add_module(LoadedModule {
            base: 0x1000,
            size: 0x100,
            name: "a".to_string(),
            full_path: String::new(),
            entry_point: 0,
            flags: 0,
        });
        walker.add_module(LoadedModule {
            base: 0x2000,
            size: 0x100,
            name: "b".to_string(),
            full_path: String::new(),
            entry_point: 0,
            flags: 0,
        });
        let bases = walker.bases();
        assert_eq!(bases.len(), 2);
    }

    // ── VadAnalysis ───────────────────────────────────────────────────────

    #[test]
    fn vad_analysis_empty() {
        let mut vad = VadAnalysis::new();
        vad.build(&[]);
        assert_eq!(vad.nodes.len(), 0);
        assert_eq!(vad.suspicious_count, 0);
    }

    #[test]
    fn vad_analysis_suspicious_private_executable() {
        let mut vad = VadAnalysis::new();
        let region = make_region(
            0x1000,
            vec![0u8; 4096],
            RegionProtect::EXECUTE_READ,
            RegionType::Private,
        );
        vad.build(&[region]);
        assert_eq!(vad.suspicious_count, 1);
        assert_eq!(vad.suspicious_nodes().len(), 1);
    }

    #[test]
    fn vad_analysis_image_not_suspicious() {
        let mut vad = VadAnalysis::new();
        let region = make_region(
            0x1000,
            vec![0u8; 4096],
            RegionProtect::EXECUTE_READ,
            RegionType::Image,
        );
        vad.build(&[region]);
        assert_eq!(vad.suspicious_count, 0);
    }

    // ── KernelObjectAddresses ─────────────────────────────────────────────

    #[test]
    fn kernel_objects_add_and_query() {
        let mut ko = KernelObjectAddresses::new();
        ko.add(0xFFFF_8000_1234_5678, "Process", 0x4);
        ko.add(0xFFFF_8000_ABCD_EF01, "Thread", 0x8);
        assert_eq!(ko.count(), 2);
        assert_eq!(ko.of_type("Process").len(), 1);
        assert_eq!(ko.of_type("Thread").len(), 1);
    }

    // ── HiddenProcess ─────────────────────────────────────────────────────

    #[test]
    fn hidden_process_cross_reference() {
        let mut hp = HiddenProcess::new();
        let from_eprocess = vec![
            (4u32, "System".to_string()),
            (666, "hidden_evil".to_string()),
        ];
        let from_peb = vec![(4u32, "System".to_string())];
        hp.cross_reference(&from_eprocess, &from_peb);
        assert_eq!(hp.indicators.len(), 1);
        assert_eq!(hp.indicators[0].pid, 666);
    }

    #[test]
    fn hidden_process_no_hidden() {
        let mut hp = HiddenProcess::new();
        let procs = vec![(4u32, "System".to_string())];
        hp.cross_reference(&procs, &procs);
        assert!(hp.indicators.is_empty());
    }

    #[test]
    fn hidden_process_high_confidence() {
        let mut hp = HiddenProcess::new();
        hp.add_indicator(HiddenProcessIndicator {
            pid: 1,
            name: "evil".to_string(),
            discovery_method: "test".to_string(),
            reason: "r".to_string(),
            confidence: 0.9,
        });
        hp.add_indicator(HiddenProcessIndicator {
            pid: 2,
            name: "low".to_string(),
            discovery_method: "test".to_string(),
            reason: "r".to_string(),
            confidence: 0.5,
        });
        assert_eq!(hp.high_confidence().len(), 1);
    }

    // ── ProcessDumpAnalyzer ────────────────────────────────────────────────

    #[test]
    fn analyzer_empty_summary() {
        let a = ProcessDumpAnalyzer::new();
        assert!(a.summary().contains("0 regions"));
    }

    #[test]
    fn analyzer_with_regions_analyze() {
        let mut a = ProcessDumpAnalyzer::new();
        a.add_region(make_region(
            0x1000,
            vec![0u8; 4096],
            RegionProtect::READ,
            RegionType::Private,
        ));
        a.analyze();
        let _ = a.summary();
    }

    #[test]
    fn analyzer_sorted_artifacts_critical_first() {
        let mut a = ProcessDumpAnalyzer::new();
        a.artifacts
            .push(MemoryArtifact::new(0, "low", "", Severity::Low));
        a.artifacts
            .push(MemoryArtifact::new(0, "crit", "", Severity::Critical));
        let sorted = a.sorted_artifacts();
        assert_eq!(sorted[0].severity, Severity::Critical);
    }

    // ── VirtualRegion ─────────────────────────────────────────────────────

    #[test]
    fn virtual_region_contains() {
        let r = VirtualRegion {
            base: 0x1000,
            size: 0x1000,
            protect: RegionProtect::READ,
            state: RegionState::Commit,
            region_type: RegionType::Private,
            mapped_file: None,
            data: vec![],
        };
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1FFF));
        assert!(!r.contains(0x2000));
    }

    #[test]
    fn virtual_region_read() {
        let data = vec![1u8, 2, 3, 4];
        let r = VirtualRegion {
            base: 0x1000,
            size: 4,
            protect: RegionProtect::READ,
            state: RegionState::Commit,
            region_type: RegionType::Private,
            mapped_file: None,
            data,
        };
        assert_eq!(r.read(1, 2), Some(&[2u8, 3][..]));
        assert!(r.read(3, 2).is_none());
    }
}
