//! `peid_deep_scan` — Deep PEiD-style scanning with unpacking hints, version
//! detection, multi-layer analysis, and embedded executable discovery.
//!
//! Provides [`PeidDeepScanner`], [`DeepScanResult`], manual unpacking hints,
//! [`PackerVersion`], [`ProtectedCodeRegion`], [`EmbeddedExecutable`],
//! and [`MultiPackLayer`].

use std::fmt;
use serde::{Deserialize, Serialize};

// ─── PackerVersion ────────────────────────────────────────────────────────────

/// Refined packer version extracted during deep scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerVersion {
    /// Canonical packer name (e.g. "UPX").
    pub name: String,
    /// Version string (e.g. "3.96").
    pub version: String,
    /// Detected variant (e.g. "LZMA", "NRV2B").
    pub variant: String,
    /// Target architecture (e.g. "x86", "x64").
    pub arch: String,
    /// Confidence score 0–100.
    pub confidence: u8,
    /// Evidence for this detection.
    pub evidence: String,
}

impl PackerVersion {
    /// Create a packer version record.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        confidence: u8,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            variant: String::new(),
            arch: String::new(),
            confidence,
            evidence: evidence.into(),
        }
    }

    /// Returns `true` if confidence is at least 70.
    #[must_use]
    pub fn is_confident(&self) -> bool {
        self.confidence >= 70
    }
}

impl fmt::Display for PackerVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} v{}", self.name, self.version)?;
        if !self.variant.is_empty() { write!(f, " ({})", self.variant)?; }
        if !self.arch.is_empty() { write!(f, " [{}]", self.arch)?; }
        write!(f, " {}%", self.confidence)
    }
}

// ─── ProtectedCodeRegion ─────────────────────────────────────────────────────

/// A code region that is protected/virtualised.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedCodeRegion {
    /// File offset.
    pub offset: u64,
    /// Size in bytes.
    pub size: usize,
    /// Shannon entropy.
    pub entropy: f32,
    /// Whether this region appears virtualised (VM-based protection).
    pub virtualised: bool,
    /// Section name containing this region.
    pub section_name: String,
    /// Reason this region was flagged.
    pub reason: String,
}

impl ProtectedCodeRegion {
    /// Compute a region descriptor from raw data.
    #[must_use]
    pub fn from_data(offset: u64, data: &[u8], section_name: impl Into<String>) -> Self {
        let e = entropy(data);
        Self {
            offset,
            size: data.len(),
            entropy: e,
            virtualised: e > 7.5,
            section_name: section_name.into(),
            reason: if e > 7.5 { "near-random entropy (virtualised)".to_string() }
                    else { "high entropy (packed/encrypted)".to_string() },
        }
    }

    /// Returns `true` if the region is likely encrypted.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.entropy > 7.5
    }
}

impl fmt::Display for ProtectedCodeRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProtectedRegion[{}] @ 0x{:x} size={} entropy={:.3} vm={}",
            self.section_name, self.offset, self.size, self.entropy, self.virtualised
        )
    }
}

// ─── EmbeddedExecutable ──────────────────────────────────────────────────────

/// An executable found embedded inside the scanned file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedExecutable {
    /// File offset of the embedded executable.
    pub offset: u64,
    /// Estimated size.
    pub estimated_size: u64,
    /// Format of the embedded file.
    pub format: EmbeddedFormat,
    /// Whether the embedded file has a full PE header.
    pub has_full_header: bool,
    /// First 16 bytes of the embedded file.
    pub header_bytes: Vec<u8>,
    /// Shannon entropy of the embedded file.
    pub entropy: f32,
}

/// Format of an embedded executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmbeddedFormat {
    Pe32,
    Pe64,
    Elf,
    MachO,
    ShellCode,
    Unknown,
}

impl fmt::Display for EmbeddedFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl EmbeddedExecutable {
    /// Scan `data` for all embedded executables.
    #[must_use]
    pub fn find_all(data: &[u8]) -> Vec<Self> {
        let mut results = Vec::new();
        // Skip first 2 bytes (the outer MZ header if any)
        for i in 2..data.len().saturating_sub(3) {
            // MZ header
            if data[i] == 0x4D && data[i + 1] == 0x5A {
                let header_bytes: Vec<u8> = data[i..data.len().min(i + 16)].to_vec();
                let has_full = has_pe_header(data, i);
                let fmt = if has_full {
                    if is_pe64(data, i) { EmbeddedFormat::Pe64 } else { EmbeddedFormat::Pe32 }
                } else {
                    EmbeddedFormat::Unknown
                };
                results.push(Self {
                    offset: i as u64,
                    estimated_size: (data.len() - i) as u64,
                    format: fmt,
                    has_full_header: has_full,
                    header_bytes,
                    entropy: entropy(&data[i..]),
                });
            }
            // ELF magic
            if i + 4 <= data.len() && &data[i..i + 4] == b"\x7FELF" {
                let header_bytes: Vec<u8> = data[i..data.len().min(i + 16)].to_vec();
                results.push(Self {
                    offset: i as u64,
                    estimated_size: (data.len() - i) as u64,
                    format: EmbeddedFormat::Elf,
                    has_full_header: true,
                    header_bytes,
                    entropy: entropy(&data[i..]),
                });
            }
        }
        results
    }

    /// Returns the number of embedded executables that have full PE headers.
    pub fn confirmed_count(list: &[Self]) -> usize {
        list.iter().filter(|e| e.has_full_header).count()
    }
}

impl fmt::Display for EmbeddedExecutable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Embedded[{}] @ 0x{:x} size_est={} full_hdr={}",
            self.format, self.offset, self.estimated_size, self.has_full_header
        )
    }
}

fn has_pe_header(data: &[u8], base: usize) -> bool {
    if base.saturating_add(0x40) > data.len() { return false; }
    let pe_off = u32::from_le_bytes([
        data[base + 0x3c], data[base + 0x3d],
        data[base + 0x3e], data[base + 0x3f],
    ]) as usize;
    let abs = match base.checked_add(pe_off) {
        Some(v) => v,
        None => return false,
    };
    abs.saturating_add(4) <= data.len() && &data[abs..abs + 4] == b"PE\x00\x00"
}

fn is_pe64(data: &[u8], base: usize) -> bool {
    if !has_pe_header(data, base) { return false; }
    let pe_off = u32::from_le_bytes([
        data[base + 0x3c], data[base + 0x3d],
        data[base + 0x3e], data[base + 0x3f],
    ]) as usize;
    let opt_off = match base.checked_add(pe_off).and_then(|v| v.checked_add(0x18)) {
        Some(v) => v,
        None => return false,
    };
    if opt_off.saturating_add(2) > data.len() { return false; }
    u16::from_le_bytes([data[opt_off], data[opt_off + 1]]) == 0x020B
}

// ─── MultiPackLayer ───────────────────────────────────────────────────────────

/// A single layer in a multi-layer packing chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackingLayer {
    pub layer_index: usize,
    pub packer: String,
    pub packer_version: String,
    pub entropy: f32,
    pub compressed: bool,
    pub encrypted: bool,
}

impl fmt::Display for PackingLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Layer {}: {} v{} entropy={:.3} compressed={} encrypted={}",
            self.layer_index, self.packer, self.packer_version,
            self.entropy, self.compressed, self.encrypted
        )
    }
}

/// Multi-layer packing analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiPackLayer {
    pub layers: Vec<PackingLayer>,
    pub total_entropy: f32,
}

impl MultiPackLayer {
    /// Build a multi-layer analysis from detected packer matches.
    #[must_use]
    pub fn from_matches(matches: &[(&str, &str)], data: &[u8]) -> Self {
        let e = entropy(data);
        let layers = matches.iter()
            .enumerate()
            .map(|(i, &(name, ver))| PackingLayer {
                layer_index: i,
                packer: name.to_string(),
                packer_version: ver.to_string(),
                entropy: e,
                compressed: e > 6.0 && e <= 7.5,
                encrypted: e > 7.5,
            })
            .collect();
        Self { layers, total_entropy: e }
    }

    /// Returns `true` if more than one layer is present.
    #[must_use]
    pub fn is_multi_packed(&self) -> bool {
        self.layers.len() > 1
    }

    /// Returns the number of layers.
    #[must_use]
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }
}

// ─── UnpackingHint ────────────────────────────────────────────────────────────

/// A hint to assist reverse-engineers in manually unpacking a sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpackingHint {
    pub packer_name: String,
    pub technique: String,
    pub description: String,
    pub tools: Vec<String>,
    pub bp_suggestion: Option<String>,
    pub difficulty: UnpackDifficulty,
}

/// Difficulty of manual unpacking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnpackDifficulty {
    Easy,
    Medium,
    Hard,
    VeryHard,
}

impl fmt::Display for UnpackDifficulty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl UnpackingHint {
    fn for_upx() -> Self {
        Self {
            packer_name: "UPX".to_string(),
            technique: "PUSHAD/POPAD detection".to_string(),
            description: "UPX uses a PUSHAD/POPAD stub. Set a hardware breakpoint on ESP after \
                PUSHAD fires. When POPAD executes, ESP returns to the original value. \
                The OEP follows immediately after the long JMP at the decompression tail.".to_string(),
            tools: vec!["x64dbg".to_string(), "ScyllaHide".to_string(), "upx -d".to_string()],
            bp_suggestion: Some("HW BP on ESP (memory write) → POPAD → JMP".to_string()),
            difficulty: UnpackDifficulty::Easy,
        }
    }

    fn for_vmprotect() -> Self {
        Self {
            packer_name: "VMProtect".to_string(),
            technique: "VM bytecode deobfuscation".to_string(),
            description: "VMProtect converts code into custom VM bytecode. Use NoVmp or \
                devirtualize-vmprotect to reconstruct original instructions. \
                Manual analysis requires tracing the VM interpreter loop.".to_string(),
            tools: vec!["NoVmp".to_string(), "x64dbg + VMPDump".to_string()],
            bp_suggestion: None,
            difficulty: UnpackDifficulty::VeryHard,
        }
    }

    fn for_themida() -> Self {
        Self {
            packer_name: "Themida".to_string(),
            technique: "IAT reconstruction + OEP hunt".to_string(),
            description: "Themida encrypts the original code and IAT. Use Scylla or ImpRec \
                after reaching the OEP. Kernelmode protections require a kernel debugger.".to_string(),
            tools: vec!["x64dbg + Scylla".to_string(), "Cheat Engine (kernel mode)".to_string()],
            bp_suggestion: Some("BP on VirtualAlloc return; then scan for original EP".to_string()),
            difficulty: UnpackDifficulty::Hard,
        }
    }

    fn generic(packer: &str) -> Self {
        Self {
            packer_name: packer.to_string(),
            technique: "Memory dump at OEP".to_string(),
            description: "Run the sample in a debugger. Wait until a new memory region is \
                allocated and execution transfers to it. That is likely the OEP. Dump the \
                process and fix the PE header using Scylla.".to_string(),
            tools: vec!["x64dbg".to_string(), "Scylla".to_string(), "PE-bear".to_string()],
            bp_suggestion: Some("BP on VirtualAlloc; after return scan for JMP to new region".to_string()),
            difficulty: UnpackDifficulty::Medium,
        }
    }

    /// Generate hints for a list of detected packers.
    #[must_use]
    pub fn generate_for(packers: &[&str]) -> Vec<Self> {
        packers.iter().map(|&p| {
            match p {
                "UPX" => Self::for_upx(),
                "VMProtect" => Self::for_vmprotect(),
                "Themida" => Self::for_themida(),
                _ => Self::generic(p),
            }
        }).collect()
    }
}

impl fmt::Display for UnpackingHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}: {} (difficulty: {})",
            self.packer_name, self.technique, self.description, self.difficulty
        )
    }
}

// ─── DeepScanResult ───────────────────────────────────────────────────────────

/// Full result from a deep PEiD scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepScanResult {
    /// File hash.
    pub file_hash: String,
    /// File size.
    pub file_size: usize,
    /// Global entropy.
    pub global_entropy: f32,
    /// Detected packer versions, sorted by confidence.
    pub packer_versions: Vec<PackerVersion>,
    /// Multi-layer packing analysis.
    pub pack_layers: MultiPackLayer,
    /// Protected code regions.
    pub protected_regions: Vec<ProtectedCodeRegion>,
    /// Embedded executables.
    pub embedded_executables: Vec<EmbeddedExecutable>,
    /// Manual unpacking hints.
    pub unpacking_hints: Vec<UnpackingHint>,
    /// Whether the sample is packed.
    pub is_packed: bool,
    /// Whether the sample is multi-packed.
    pub is_multi_packed: bool,
    /// Whether the sample contains embedded executables (dropper).
    pub is_dropper: bool,
    /// Elapsed analysis time in milliseconds.
    pub elapsed_ms: u64,
}

impl DeepScanResult {
    /// Return the highest-confidence packer version.
    #[must_use]
    pub fn best_packer(&self) -> Option<&PackerVersion> {
        self.packer_versions.first()
    }

    /// Serialise to JSON.
    ///
    /// # Errors
    /// Returns a string on failure.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    /// Brief summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "DeepScanResult: packed={} multi={} dropper={} packers={} embedded={} hints={}",
            self.is_packed,
            self.is_multi_packed,
            self.is_dropper,
            self.packer_versions.len(),
            self.embedded_executables.len(),
            self.unpacking_hints.len()
        )
    }
}

impl fmt::Display for DeepScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Deep Scan Result ===")?;
        writeln!(f, "  File size  : {}", self.file_size)?;
        writeln!(f, "  Entropy    : {:.4}", self.global_entropy)?;
        writeln!(f, "  Packed     : {}", self.is_packed)?;
        writeln!(f, "  Multi-pack : {}", self.is_multi_packed)?;
        writeln!(f, "  Dropper    : {}", self.is_dropper)?;
        writeln!(f, "  Packers    : {}", self.packer_versions.len())?;
        for pv in &self.packer_versions {
            writeln!(f, "    {pv}")?;
        }
        writeln!(f, "  Embedded   : {}", self.embedded_executables.len())?;
        writeln!(f, "  Hints      : {}", self.unpacking_hints.len())?;
        Ok(())
    }
}

// ─── PeidDeepScanner ─────────────────────────────────────────────────────────

/// Deep PEiD-style scanner that goes beyond EP signature matching.
pub struct PeidDeepScanner {
    /// Entropy threshold for marking a region as packed.
    pub entropy_threshold: f32,
    /// Block size for entropy analysis.
    pub block_size: usize,
    /// Whether to scan for embedded executables.
    pub scan_embedded: bool,
    /// Minimum confidence threshold (0–100).
    pub min_confidence: u8,
}

impl PeidDeepScanner {
    /// Create a scanner with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entropy_threshold: 7.0,
            block_size: 512,
            scan_embedded: true,
            min_confidence: 60,
        }
    }

    /// Run a deep scan on `data` and return the full result.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> DeepScanResult {
        use std::time::Instant;
        let start = Instant::now();

        let global_entropy = entropy(data);

        // ── Packer detection ──────────────────────────────────────────────────
        let mut packer_versions: Vec<PackerVersion> = Vec::new();

        // UPX
        if data.windows(4).any(|w| w == b"UPX0") {
            let version = self.detect_upx_version(data);
            packer_versions.push(PackerVersion::new("UPX", version, 97, "UPX0/UPX1 section names"));
        }

        // VMProtect
        if data.windows(5).any(|w| w == b".vmp0") {
            packer_versions.push(PackerVersion::new("VMProtect", "2.x", 93, ".vmp0 section name"));
        }
        if data.windows(5).any(|w| w == b".vmp1") {
            packer_versions.push(PackerVersion::new("VMProtect", "3.x", 93, ".vmp1 section name"));
        }

        // Themida
        if data.windows(8).any(|w| w == b".themida") {
            packer_versions.push(PackerVersion::new("Themida", "3.x", 93, ".themida section name"));
        }

        // ASPack
        if data.windows(7).any(|w| w == b".aspack") {
            packer_versions.push(PackerVersion::new("ASPack", "2.x", 91, ".aspack section name"));
        }

        // MPRESS
        if data.windows(8).any(|w| w == b".MPRESS1") {
            packer_versions.push(PackerVersion::new("MPRESS", "2.x", 92, ".MPRESS1 section name"));
        }

        // PECompact
        if data.windows(10).any(|w| w == b"PECompact2") {
            packer_versions.push(PackerVersion::new("PECompact", "2.x", 90, "PECompact2 string"));
        }

        // PyInstaller
        if data.windows(7).any(|w| w.starts_with(b"MEI\x0C\x0B")) {
            packer_versions.push(PackerVersion::new("PyInstaller", "6.x", 95, "MEI magic"));
        }

        // Sort by confidence descending
        packer_versions.sort_by(|a, b| b.confidence.cmp(&a.confidence));

        // Filter by minimum confidence
        packer_versions.retain(|pv| pv.confidence >= self.min_confidence);

        // ── Pack layers ───────────────────────────────────────────────────────
        let pairs: Vec<(&str, &str)> = packer_versions
            .iter()
            .map(|pv| (pv.name.as_str(), pv.version.as_str()))
            .collect();
        let pack_layers = MultiPackLayer::from_matches(&pairs, data);

        // ── Protected regions ─────────────────────────────────────────────────
        let protected_regions = self.find_protected_regions(data);

        // ── Embedded executables ──────────────────────────────────────────────
        let embedded_executables = if self.scan_embedded {
            EmbeddedExecutable::find_all(data)
        } else {
            Vec::new()
        };

        // ── Unpacking hints ───────────────────────────────────────────────────
        let packer_names: Vec<&str> = packer_versions.iter().map(|pv| pv.name.as_str()).collect();
        let unpacking_hints = UnpackingHint::generate_for(&packer_names);

        let is_packed = !packer_versions.is_empty() || global_entropy > self.entropy_threshold;
        let is_multi_packed = pack_layers.is_multi_packed();
        let is_dropper = !embedded_executables.is_empty()
            && embedded_executables.iter().any(|e| e.has_full_header);

        let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        DeepScanResult {
            file_hash: simple_hash(data),
            file_size: data.len(),
            global_entropy,
            packer_versions,
            pack_layers,
            protected_regions,
            embedded_executables,
            unpacking_hints,
            is_packed,
            is_multi_packed,
            is_dropper,
            elapsed_ms,
        }
    }

    /// Detect the precise UPX version from the binary.
    fn detect_upx_version(&self, data: &[u8]) -> &'static str {
        // UPX 4.x started using a different stub alignment
        if data.windows(5).any(|w| w == b"UPX 4") { return "4.x"; }
        // UPX 3.x most common
        if data.windows(5).any(|w| w.starts_with(b"UPX!")) { return "3.x"; }
        "unknown"
    }

    fn find_protected_regions(&self, data: &[u8]) -> Vec<ProtectedCodeRegion> {
        let bs = self.block_size;
        let mut regions = Vec::new();
        for (i, chunk) in data.chunks(bs).enumerate() {
            let e = entropy(chunk);
            if e > self.entropy_threshold {
                regions.push(ProtectedCodeRegion::from_data(
                    (i * bs) as u64,
                    chunk,
                    format!("block_{i}"),
                ));
            }
        }
        regions
    }
}

impl Default for PeidDeepScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PeidDeepScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeidDeepScanner(threshold={:.1} block={})", self.entropy_threshold, self.block_size)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn entropy(data: &[u8]) -> f32 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f32;
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f32 / len; -p * p.log2()
    }).sum::<f32>().clamp(0.0, 8.0)
}

fn simple_hash(data: &[u8]) -> String {
    let mut h: u64 = 0xcbf29ce484222325u64;
    for &b in data { h ^= b as u64; h = h.wrapping_mul(0x100000001b3u64); }
    format!("{:016x}", h)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn upx_sample() -> Vec<u8> {
        let mut v = vec![0x4D, 0x5A, 0x90, 0x00];
        v.extend_from_slice(&[0u8; 60]);
        v.extend_from_slice(b"UPX0");
        v.extend_from_slice(b"UPX1");
        v.extend_from_slice(b"UPX!");
        v
    }

    fn clean_sample() -> Vec<u8> {
        let mut v = vec![0x4D, 0x5A, 0x90, 0x00];
        v.extend_from_slice(&[0u8; 200]);
        v
    }

    fn vmprotect_sample() -> Vec<u8> {
        let mut v = vec![0x4D, 0x5A];
        v.extend_from_slice(&[0u8; 50]);
        v.extend_from_slice(b".vmp0");
        v.extend_from_slice(b".vmp1");
        v
    }

    fn dropper_sample() -> Vec<u8> {
        // Outer MZ + inner MZ with valid PE offset
        let mut outer = vec![0x4D, 0x5A];
        outer.extend_from_slice(&[0u8; 0x3e]);
        outer.push(0x40); // e_lfanew = 0x40
        outer.extend_from_slice(&[0u8; 12]);
        // Inner MZ at offset 0x60
        outer.extend_from_slice(&[0u8; 12]);
        outer.extend_from_slice(b"MZ"); // inner MZ at offset ~0x60
        outer.extend_from_slice(&[0u8; 200]);
        outer
    }

    // ── PackerVersion ─────────────────────────────────────────────────────────

    #[test]
    fn test_packer_version_new() {
        let pv = PackerVersion::new("UPX", "3.x", 97, "UPX0 section");
        assert_eq!(pv.name, "UPX");
        assert!(pv.is_confident());
    }

    #[test]
    fn test_packer_version_not_confident() {
        let pv = PackerVersion::new("X", "1.0", 50, "weak");
        assert!(!pv.is_confident());
    }

    #[test]
    fn test_packer_version_display() {
        let pv = PackerVersion::new("UPX", "3.x", 97, "x");
        assert!(pv.to_string().contains("UPX"));
        assert!(pv.to_string().contains("97%"));
    }

    #[test]
    fn test_packer_version_with_variant() {
        let mut pv = PackerVersion::new("UPX", "3.x", 97, "x");
        pv.variant = "LZMA".to_string();
        assert!(pv.to_string().contains("LZMA"));
    }

    // ── ProtectedCodeRegion ───────────────────────────────────────────────────

    #[test]
    fn test_protected_region_from_data_low_entropy() {
        let r = ProtectedCodeRegion::from_data(0, &[0u8; 64], ".bss");
        assert!(!r.virtualised);
        assert!(!r.is_encrypted());
    }

    #[test]
    fn test_protected_region_from_data_high_entropy() {
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let r = ProtectedCodeRegion::from_data(0, &data, ".vmp0");
        assert!(r.virtualised);
        assert!(r.is_encrypted());
    }

    #[test]
    fn test_protected_region_display() {
        let r = ProtectedCodeRegion {
            offset: 0x1000, size: 512, entropy: 7.8, virtualised: true,
            section_name: ".vmp0".to_string(), reason: "test".to_string(),
        };
        assert!(r.to_string().contains(".vmp0"));
    }

    // ── EmbeddedExecutable ────────────────────────────────────────────────────

    #[test]
    fn test_embedded_exe_find_all_empty() {
        let found = EmbeddedExecutable::find_all(&[0u8; 100]);
        assert!(found.is_empty());
    }

    #[test]
    fn test_embedded_exe_find_inner_mz() {
        let mut data = b"MZ\x00\x00".to_vec();
        data.extend_from_slice(&[0u8; 100]);
        data.extend_from_slice(b"MZinner");
        let found = EmbeddedExecutable::find_all(&data);
        assert!(!found.is_empty(), "the inner MZ must be found");
        // Two magic bytes are not a PE32. `has_pe_header` requires e_lfanew to
        // resolve to a "PE\0\0" signature, and "MZinner" has none — so the
        // honest classification is `Unknown`, with `has_full_header: false`
        // recording why. Expecting Pe32 here would ask the scanner to call any
        // stray "MZ" a portable executable.
        assert_eq!(found[0].format, EmbeddedFormat::Unknown);
        assert!(!found[0].has_full_header);
    }

    #[test]
    fn test_embedded_exe_inner_pe_with_header_is_pe32() {
        // The positive half: an inner MZ whose e_lfanew points at a real
        // "PE\0\0" signature must be classified, or the `Unknown` above would be
        // indistinguishable from a scanner that never recognises anything.
        let mut data = b"MZ\x00\x00".to_vec();
        data.extend_from_slice(&[0u8; 100]);
        let base = data.len();
        data.extend_from_slice(&[0u8; 0x48]);
        data[base] = b'M';
        data[base + 1] = b'Z';
        data[base + 0x3C..base + 0x40].copy_from_slice(&0x40u32.to_le_bytes());
        data[base + 0x40..base + 0x44].copy_from_slice(b"PE\x00\x00");
        let found = EmbeddedExecutable::find_all(&data);
        let inner = found
            .iter()
            .find(|e| e.offset as usize == base)
            .expect("inner PE found");
        assert_eq!(inner.format, EmbeddedFormat::Pe32);
        assert!(inner.has_full_header);
    }

    #[test]
    fn test_embedded_exe_find_elf() {
        let mut data = b"MZ\x00\x00\x00\x00".to_vec();
        data.extend_from_slice(&[0u8; 50]);
        data.extend_from_slice(b"\x7FELF\x02\x01");
        let found = EmbeddedExecutable::find_all(&data);
        let elf = found.iter().find(|e| e.format == EmbeddedFormat::Elf);
        assert!(elf.is_some());
    }

    #[test]
    fn test_embedded_exe_confirmed_count() {
        let found = EmbeddedExecutable::find_all(&[0u8; 50]);
        assert_eq!(EmbeddedExecutable::confirmed_count(&found), 0);
    }

    #[test]
    fn test_embedded_exe_display() {
        let e = EmbeddedExecutable {
            offset: 0x200,
            estimated_size: 1024,
            format: EmbeddedFormat::Pe32,
            has_full_header: true,
            header_bytes: vec![0x4D, 0x5A],
            entropy: 5.5,
        };
        assert!(e.to_string().contains("0x200"));
    }

    // ── MultiPackLayer ────────────────────────────────────────────────────────

    #[test]
    fn test_multi_pack_layer_empty() {
        let ml = MultiPackLayer::from_matches(&[], &[0u8; 100]);
        assert_eq!(ml.layer_count(), 0);
        assert!(!ml.is_multi_packed());
    }

    #[test]
    fn test_multi_pack_layer_single() {
        let ml = MultiPackLayer::from_matches(&[("UPX", "3.x")], &[0u8; 100]);
        assert_eq!(ml.layer_count(), 1);
        assert!(!ml.is_multi_packed());
    }

    #[test]
    fn test_multi_pack_layer_multi() {
        let ml = MultiPackLayer::from_matches(&[("UPX", "3.x"), ("ASPack", "2.x")], &[0u8; 100]);
        assert!(ml.is_multi_packed());
    }

    #[test]
    fn test_packing_layer_display() {
        let l = PackingLayer {
            layer_index: 0, packer: "UPX".to_string(), packer_version: "3.x".to_string(),
            entropy: 7.5, compressed: true, encrypted: false,
        };
        assert!(l.to_string().contains("UPX"));
    }

    // ── UnpackingHint ─────────────────────────────────────────────────────────

    #[test]
    fn test_unpacking_hint_upx() {
        let hints = UnpackingHint::generate_for(&["UPX"]);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].packer_name, "UPX");
        assert_eq!(hints[0].difficulty, UnpackDifficulty::Easy);
    }

    #[test]
    fn test_unpacking_hint_vmprotect() {
        let hints = UnpackingHint::generate_for(&["VMProtect"]);
        assert_eq!(hints[0].difficulty, UnpackDifficulty::VeryHard);
    }

    #[test]
    fn test_unpacking_hint_generic() {
        let hints = UnpackingHint::generate_for(&["UnknownPacker"]);
        assert_eq!(hints[0].difficulty, UnpackDifficulty::Medium);
    }

    #[test]
    fn test_unpacking_hint_display() {
        let h = UnpackingHint::generate_for(&["UPX"]).remove(0);
        assert!(h.to_string().contains("UPX"));
    }

    #[test]
    fn test_unpack_difficulty_display() {
        assert_eq!(UnpackDifficulty::Easy.to_string(), "Easy");
        assert_eq!(UnpackDifficulty::VeryHard.to_string(), "VeryHard");
    }

    // ── PeidDeepScanner ───────────────────────────────────────────────────────

    #[test]
    fn test_deep_scanner_clean() {
        let scanner = PeidDeepScanner::new();
        let result = scanner.scan(&clean_sample());
        assert!(!result.is_packed || result.packer_versions.is_empty());
    }

    #[test]
    fn test_deep_scanner_upx() {
        let scanner = PeidDeepScanner::new();
        let result = scanner.scan(&upx_sample());
        assert!(result.is_packed);
        assert!(result.packer_versions.iter().any(|pv| pv.name == "UPX"));
    }

    #[test]
    fn test_deep_scanner_vmprotect() {
        let scanner = PeidDeepScanner::new();
        let result = scanner.scan(&vmprotect_sample());
        assert!(result.packer_versions.iter().any(|pv| pv.name == "VMProtect"));
    }

    #[test]
    fn test_deep_scanner_generates_hints() {
        let scanner = PeidDeepScanner::new();
        let result = scanner.scan(&upx_sample());
        assert!(!result.unpacking_hints.is_empty());
    }

    #[test]
    fn test_deep_scanner_summary() {
        let scanner = PeidDeepScanner::new();
        let result = scanner.scan(&upx_sample());
        let s = result.summary();
        assert!(s.contains("DeepScanResult"));
    }

    #[test]
    fn test_deep_scanner_display() {
        let scanner = PeidDeepScanner::new();
        let result = scanner.scan(&upx_sample());
        let s = format!("{result}");
        assert!(s.contains("Deep Scan Result"));
    }

    #[test]
    fn test_deep_scanner_json() {
        let scanner = PeidDeepScanner::new();
        let result = scanner.scan(b"test");
        let json = result.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["is_packed"].is_boolean());
    }

    #[test]
    fn test_deep_scanner_best_packer_none() {
        let scanner = PeidDeepScanner::new();
        let result = scanner.scan(&clean_sample());
        // clean sample may or may not find packers; just ensure no panic
        let _ = result.best_packer();
    }

    #[test]
    fn test_deep_scanner_best_packer_upx() {
        let scanner = PeidDeepScanner::new();
        let result = scanner.scan(&upx_sample());
        if let Some(best) = result.best_packer() {
            assert_eq!(best.name, "UPX");
        }
    }

    #[test]
    fn test_deep_scanner_high_entropy() {
        let scanner = PeidDeepScanner::new();
        let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let result = scanner.scan(&data);
        assert!(!result.protected_regions.is_empty());
    }

    #[test]
    fn test_deep_scanner_debug() {
        let scanner = PeidDeepScanner::new();
        let s = format!("{scanner:?}");
        assert!(s.contains("PeidDeepScanner"));
    }

    #[test]
    fn test_deep_scanner_embedded_scan_disabled() {
        let scanner = PeidDeepScanner { scan_embedded: false, ..Default::default() };
        let result = scanner.scan(&dropper_sample());
        assert!(result.embedded_executables.is_empty());
    }

    #[test]
    fn test_entropy_helper() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = entropy(&data);
        assert!((e - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_entropy_zeros() {
        assert_eq!(entropy(&[0u8; 100]), 0.0);
    }

    #[test]
    fn test_simple_hash_deterministic() {
        assert_eq!(simple_hash(b"abc"), simple_hash(b"abc"));
        assert_ne!(simple_hash(b"abc"), simple_hash(b"xyz"));
    }

    #[test]
    fn test_embedded_format_display() {
        assert_eq!(EmbeddedFormat::Pe32.to_string(), "Pe32");
        assert_eq!(EmbeddedFormat::Elf.to_string(), "Elf");
    }
}
