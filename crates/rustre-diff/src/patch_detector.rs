//! Binary patch detector.
//!
//! Scans a binary image (or compares two images) for common patching patterns:
//! hot-patches, NOP sleds, `RET` trampolines, `CALL` redirects, and
//! structural changes to PE import/export tables and section headers.

use ahash::AHashMap;
use std::fmt;

// ────────────────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────────────────

/// Classification of a detected patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchType {
    /// Windows hot-patch trampoline: `MOV EDI, EDI` (8B FF) + `JMP short` at prolog.
    HotPatch,
    /// Long jump patch: `E9 xx xx xx xx` at function start.
    JmpPatch,
    /// NOP sled replacing real code.
    NopPatch,
    /// `RET` (C3 / C2) planted at function start to disable it.
    RetPatch,
    /// A `CALL` target was redirected to a different address.
    CallRedirect,
    /// Data bytes in a read-write section changed.
    DataPatch,
    /// An entirely new section was added.
    SectionAdded,
    /// An import table entry was added, removed, or redirected.
    ImportModified,
    /// An export table entry changed.
    ExportModified,
}

impl fmt::Display for PatchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::HotPatch => "HotPatch",
            Self::JmpPatch => "JmpPatch",
            Self::NopPatch => "NopPatch",
            Self::RetPatch => "RetPatch",
            Self::CallRedirect => "CallRedirect",
            Self::DataPatch => "DataPatch",
            Self::SectionAdded => "SectionAdded",
            Self::ImportModified => "ImportModified",
            Self::ExportModified => "ExportModified",
        };
        f.write_str(s)
    }
}

/// Risk level assigned to a patch report.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => f.write_str("Low"),
            Self::Medium => f.write_str("Medium"),
            Self::High => f.write_str("High"),
        }
    }
}

/// A single detected patch location.
#[derive(Debug, Clone)]
pub struct PatchLocation {
    /// File/image offset where the patch begins.
    pub offset: u64,
    /// Size of the patched region in bytes.
    pub size: u32,
    /// Classification of the patch.
    pub patch_type: PatchType,
    /// Original bytes (from the reference binary), may be empty if unknown.
    pub original_bytes: Vec<u8>,
    /// Patched bytes (from the patched binary).
    pub patched_bytes: Vec<u8>,
    /// Human-readable description.
    pub description: String,
}

impl PatchLocation {
    /// `true` if this patch changes control flow (JMP / RET / CALL redirect / hot-patch).
    #[must_use]
    pub const fn is_control_flow_patch(&self) -> bool {
        matches!(
            self.patch_type,
            PatchType::HotPatch
                | PatchType::JmpPatch
                | PatchType::RetPatch
                | PatchType::CallRedirect
        )
    }
}

impl fmt::Display for PatchLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ {:#x} ({} bytes): {}",
            self.patch_type, self.offset, self.size, self.description
        )
    }
}

/// Aggregated patch report.
#[derive(Debug, Clone)]
pub struct PatchReport {
    /// All detected patch locations.
    pub patches: Vec<PatchLocation>,
    /// Overall risk level (worst of all individual patches).
    pub risk_level: RiskLevel,
    /// Estimated patch date (not always available; derived from PE timestamps if present).
    pub patch_date_estimate: Option<String>,
}

impl PatchReport {
    /// Number of control-flow patches detected.
    #[must_use]
    pub fn control_flow_count(&self) -> usize {
        self.patches.iter().filter(|p| p.is_control_flow_patch()).count()
    }

    /// `true` if any patch was detected.
    #[must_use]
    pub const fn has_patches(&self) -> bool {
        !self.patches.is_empty()
    }
}

impl fmt::Display for PatchReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PatchReport: {} patches, risk={}, cf_patches={}",
            self.patches.len(),
            self.risk_level,
            self.control_flow_count()
        )
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Import / Export table representations
// ────────────────────────────────────────────────────────────────────────────────

/// A single import entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImportEntry {
    /// DLL name (lower-cased).
    pub dll: String,
    /// Function name or ordinal string.
    pub name: String,
    /// IAT address (virtual address in the image).
    pub iat_address: u64,
}

/// A single export entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExportEntry {
    /// Exported symbol name, if named.
    pub name: Option<String>,
    /// Ordinal.
    pub ordinal: u32,
    /// Virtual address.
    pub address: u64,
}

/// Minimal PE section header for comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    /// Section name (e.g. `.text`).
    pub name: String,
    /// Virtual size.
    pub virtual_size: u32,
    /// Virtual address.
    pub virtual_address: u32,
    /// Raw size on disk.
    pub raw_size: u32,
    /// Section characteristics flags.
    pub characteristics: u32,
}

// ────────────────────────────────────────────────────────────────────────────────
// FullReportContext
// ────────────────────────────────────────────────────────────────────────────────

/// Bundles all inputs needed by [`PatchDetector::full_report`].
pub struct FullReportContext<'a> {
    /// Reference (old) binary image.
    pub old_image: &'a [u8],
    /// Patched (new) binary image.
    pub new_image: &'a [u8],
    /// Known function start offsets (file-relative) within the images.
    pub func_starts: &'a [u64],
    /// Import table from the old binary.
    pub old_imports: &'a [ImportEntry],
    /// Import table from the new binary.
    pub new_imports: &'a [ImportEntry],
    /// Export table from the old binary.
    pub old_exports: &'a [ExportEntry],
    /// Export table from the new binary.
    pub new_exports: &'a [ExportEntry],
    /// Section headers from the old binary.
    pub old_sections: &'a [SectionHeader],
    /// Section headers from the new binary.
    pub new_sections: &'a [SectionHeader],
}

// ────────────────────────────────────────────────────────────────────────────────
// PatchDetector
// ────────────────────────────────────────────────────────────────────────────────

/// Configuration for the patch detector.
#[derive(Debug, Clone)]
pub struct PatchDetectorConfig {
    /// Minimum NOP sequence length to report (default 4).
    pub min_nop_len: usize,
    /// Look ahead this many bytes past function starts for prologue patterns.
    pub prologue_scan_len: usize,
}

impl Default for PatchDetectorConfig {
    fn default() -> Self {
        Self {
            min_nop_len: 4,
            prologue_scan_len: 8,
        }
    }
}

/// Main patch detection engine.
pub struct PatchDetector {
    config: PatchDetectorConfig,
}

impl PatchDetector {
    /// Create a detector with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: PatchDetectorConfig::default(),
        }
    }

    /// Create a detector with custom configuration.
    #[must_use]
    pub const fn with_config(config: PatchDetectorConfig) -> Self {
        Self { config }
    }

    // ── Single-image detectors ────────────────────────────────────────────────

    /// Detect Windows-style hot-patch trampolines in a flat binary image.
    ///
    /// A hot-patch consists of:
    /// 1. `8B FF` (`MOV EDI, EDI`) immediately before a function start.
    /// 2. `EB xx` (`JMP short`) at offset 0 of the function start.
    ///
    /// The `func_starts` slice provides the list of known function start offsets.
    #[must_use]
    pub fn detect_jmp_patches(&self, image: &[u8], func_starts: &[u64]) -> Vec<PatchLocation> {
        let mut patches = Vec::new();
        for &start in func_starts {
            let s = usize::try_from(start).unwrap_or(usize::MAX);
            if s >= image.len() {
                continue;
            }
            let remaining = &image[s..];

            // Long JMP: E9 xx xx xx xx
            if remaining.len() >= 5 && remaining[0] == 0xE9 {
                let rel = i32::from_le_bytes([remaining[1], remaining[2], remaining[3], remaining[4]]);
                let target_raw = i64::try_from(start).unwrap_or(i64::MAX).saturating_add(5).saturating_add(i64::from(rel));
                let target = u64::try_from(target_raw).unwrap_or(0);
                patches.push(PatchLocation {
                    offset: start,
                    size: 5,
                    patch_type: PatchType::JmpPatch,
                    original_bytes: Vec::new(),
                    patched_bytes: remaining[..5].to_vec(),
                    description: format!("Long JMP to {target:#x} at function start"),
                });
                continue;
            }

            // Hot-patch pattern: MOV EDI, EDI (8B FF) immediately preceding the
            // function start, followed by a short JMP (EB xx). Must be checked
            // BEFORE the generic short-JMP branch, otherwise we'd classify the
            // jmp half of a hot-patch trampoline as a plain JmpPatch.
            if s >= 2
                && image[s - 2] == 0x8B
                && image[s - 1] == 0xFF
                && remaining.len() >= 2
                && remaining[0] == 0xEB
            {
                patches.push(PatchLocation {
                    offset: start - 2,
                    size: 4,
                    patch_type: PatchType::HotPatch,
                    original_bytes: Vec::new(),
                    patched_bytes: image[s - 2..s + 2].to_vec(),
                    description: format!("Hot-patch trampoline at {:#x}", start - 2),
                });
                continue;
            }

            // Short JMP: EB xx
            if remaining.len() >= 2 && remaining[0] == 0xEB {
                let rel = i8::from_ne_bytes([remaining[1]]);
                let target_raw = (i64::try_from(start).unwrap_or(i64::MAX)).saturating_add(2).saturating_add(i64::from(rel));
                let target = u64::try_from(target_raw).unwrap_or(0);
                patches.push(PatchLocation {
                    offset: start,
                    size: 2,
                    patch_type: PatchType::JmpPatch,
                    original_bytes: Vec::new(),
                    patched_bytes: remaining[..2].to_vec(),
                    description: format!("Short JMP to {target:#x} at function start"),
                });
            }
        }
        patches
    }

    /// Detect NOP sleds in a flat binary image.
    ///
    /// Reports any run of >= `min_nop_len` 0x90 bytes, or any sequence of
    /// multi-byte NOP encodings (66 90, 0F 1F ...).
    #[must_use]
    pub fn detect_nop_patches(&self, image: &[u8]) -> Vec<PatchLocation> {
        let mut patches = Vec::new();
        let mut i = 0;
        while i < image.len() {
            // Single-byte NOP run.
            if image[i] == 0x90 {
                let start = i;
                while i < image.len() && image[i] == 0x90 {
                    i += 1;
                }
                let len = i - start;
                if len >= self.config.min_nop_len {
                    patches.push(PatchLocation {
                        offset: u64::try_from(start).unwrap_or(u64::MAX),
                        size: u32::try_from(len).unwrap_or(u32::MAX),
                        patch_type: PatchType::NopPatch,
                        original_bytes: Vec::new(),
                        patched_bytes: image[start..i].to_vec(),
                        description: format!("{len}-byte NOP sled at {start:#x}"),
                    });
                }
                continue;
            }

            // 2-byte NOP: 66 90.
            if i + 1 < image.len() && image[i] == 0x66 && image[i + 1] == 0x90 {
                let start = i;
                while i + 1 < image.len() && image[i] == 0x66 && image[i + 1] == 0x90 {
                    i += 2;
                }
                let len = i - start;
                if len >= self.config.min_nop_len {
                    patches.push(PatchLocation {
                        offset: u64::try_from(start).unwrap_or(u64::MAX),
                        size: u32::try_from(len).unwrap_or(u32::MAX),
                        patch_type: PatchType::NopPatch,
                        original_bytes: Vec::new(),
                        patched_bytes: image[start..i].to_vec(),
                        description: format!("{len}-byte multi-NOP sled (66 90) at {start:#x}"),
                    });
                }
                continue;
            }

            // 3-byte NOP: 0F 1F 00.
            if i + 2 < image.len() && image[i] == 0x0F && image[i + 1] == 0x1F && image[i + 2] == 0x00 {
                patches.push(PatchLocation {
                    offset: u64::try_from(i).unwrap_or(u64::MAX),
                    size: 3,
                    patch_type: PatchType::NopPatch,
                    original_bytes: Vec::new(),
                    patched_bytes: image[i..i + 3].to_vec(),
                    description: format!("3-byte NOP (0F 1F 00) at {i:#x}"),
                });
                i += 3;
                continue;
            }

            i += 1;
        }
        patches
    }

    /// Detect `RET` patches at function starts.
    ///
    /// A RET (C3) or RET N (C2 xx xx) at the very first byte of a function is
    /// a common technique to disable a function without removing it.
    #[must_use]
    pub fn detect_ret_patches(&self, image: &[u8], func_starts: &[u64]) -> Vec<PatchLocation> {
        let mut patches = Vec::new();
        for &start in func_starts {
            let s = usize::try_from(start).unwrap_or(usize::MAX);
            if s >= image.len() {
                continue;
            }
            let b = image[s];
            if b == 0xC3 {
                patches.push(PatchLocation {
                    offset: start,
                    size: 1,
                    patch_type: PatchType::RetPatch,
                    original_bytes: Vec::new(),
                    patched_bytes: vec![0xC3],
                    description: format!("RET (C3) planted at function start {start:#x}"),
                });
            } else if b == 0xC2 && s + 2 < image.len() {
                let n = u16::from_le_bytes([image[s + 1], image[s + 2]]);
                patches.push(PatchLocation {
                    offset: start,
                    size: 3,
                    patch_type: PatchType::RetPatch,
                    original_bytes: Vec::new(),
                    patched_bytes: image[s..s + 3].to_vec(),
                    description: format!("RET {n} (C2) planted at function start {start:#x}"),
                });
            }
        }
        patches
    }

    /// Detect CALL redirects by comparing call targets between two images.
    ///
    /// Scans `old_image` and `new_image` for `E8` (relative CALL) opcodes at
    /// the same offsets; if the resolved target differs, a redirect is reported.
    #[must_use]
    pub fn detect_call_redirects(&self, old_image: &[u8], new_image: &[u8]) -> Vec<PatchLocation> {
        let mut patches = Vec::new();
        let len = old_image.len().min(new_image.len());
        if len < 5 {
            return patches;
        }
        let mut i = 0;
        while i + 4 < len {
            if old_image[i] == 0xE8 && new_image[i] == 0xE8 {
                let old_rel = i32::from_le_bytes([
                    old_image[i + 1],
                    old_image[i + 2],
                    old_image[i + 3],
                    old_image[i + 4],
                ]);
                let new_rel = i32::from_le_bytes([
                    new_image[i + 1],
                    new_image[i + 2],
                    new_image[i + 3],
                    new_image[i + 4],
                ]);
                if old_rel != new_rel {
                    let i64_i = i64::try_from(i).unwrap_or(i64::MAX);
                    let old_target = u64::try_from(i64_i.saturating_add(5).saturating_add(i64::from(old_rel))).unwrap_or(0);
                    let new_target = u64::try_from(i64_i.saturating_add(5).saturating_add(i64::from(new_rel))).unwrap_or(0);
                    patches.push(PatchLocation {
                        offset: u64::try_from(i).unwrap_or(u64::MAX),
                        size: 5,
                        patch_type: PatchType::CallRedirect,
                        original_bytes: old_image[i..i + 5].to_vec(),
                        patched_bytes: new_image[i..i + 5].to_vec(),
                        description: format!(
                            "CALL redirect at {i:#x}: {old_target:#x} → {new_target:#x}"
                        ),
                    });
                }
                i += 5;
                continue;
            }
            i += 1;
        }
        patches
    }

    // ── Table comparisons ─────────────────────────────────────────────────────

    /// Compare two import tables and report added, removed, or changed entries.
    #[must_use]
    pub fn compare_import_tables(
        &self,
        old_imports: &[ImportEntry],
        new_imports: &[ImportEntry],
    ) -> Vec<PatchLocation> {
        let mut patches = Vec::new();

        // AHashMap: import names come from the binary (attacker-controlled);
        // std HashMap with SipHash would still be vulnerable to hash-collision
        // DoS if an adversary crafts many DLL/name pairs with the same hash.
        let old_map: AHashMap<(&str, &str), &ImportEntry> = old_imports
            .iter()
            .map(|e| ((e.dll.as_str(), e.name.as_str()), e))
            .collect();
        let new_map: AHashMap<(&str, &str), &ImportEntry> = new_imports
            .iter()
            .map(|e| ((e.dll.as_str(), e.name.as_str()), e))
            .collect();

        for (key, old_e) in &old_map {
            if let Some(new_e) = new_map.get(key) {
                if old_e.iat_address != new_e.iat_address {
                    patches.push(PatchLocation {
                        offset: old_e.iat_address,
                        size: 8,
                        patch_type: PatchType::ImportModified,
                        original_bytes: old_e.iat_address.to_le_bytes().to_vec(),
                        patched_bytes: new_e.iat_address.to_le_bytes().to_vec(),
                        description: format!(
                            "Import {}!{} IAT address changed: {:#x} → {:#x}",
                            key.0, key.1, old_e.iat_address, new_e.iat_address
                        ),
                    });
                }
            } else {
                patches.push(PatchLocation {
                    offset: old_e.iat_address,
                    size: 8,
                    patch_type: PatchType::ImportModified,
                    original_bytes: old_e.iat_address.to_le_bytes().to_vec(),
                    patched_bytes: Vec::new(),
                    description: format!("Import {}!{} removed", key.0, key.1),
                });
            }
        }

        for (key, new_e) in &new_map {
            if !old_map.contains_key(key) {
                patches.push(PatchLocation {
                    offset: new_e.iat_address,
                    size: 8,
                    patch_type: PatchType::ImportModified,
                    original_bytes: Vec::new(),
                    patched_bytes: new_e.iat_address.to_le_bytes().to_vec(),
                    description: format!("Import {}!{} added", key.0, key.1),
                });
            }
        }

        patches
    }

    /// Compare two export tables and report changes.
    #[must_use]
    pub fn compare_export_tables(
        &self,
        old_exports: &[ExportEntry],
        new_exports: &[ExportEntry],
    ) -> Vec<PatchLocation> {
        let mut patches = Vec::new();
        let old_map: AHashMap<u32, &ExportEntry> = old_exports.iter().map(|e| (e.ordinal, e)).collect();
        let new_map: AHashMap<u32, &ExportEntry> = new_exports.iter().map(|e| (e.ordinal, e)).collect();

        for (&ord, old_e) in &old_map {
            match new_map.get(&ord) {
                Some(new_e) => {
                    if old_e.address != new_e.address {
                        patches.push(PatchLocation {
                            offset: old_e.address,
                            size: 4,
                            patch_type: PatchType::ExportModified,
                            original_bytes: u32::try_from(old_e.address).unwrap_or(u32::MAX).to_le_bytes().to_vec(),
                            patched_bytes: u32::try_from(new_e.address).unwrap_or(u32::MAX).to_le_bytes().to_vec(),
                            description: format!(
                                "Export #{ord} address changed: {:#x} → {:#x}",
                                old_e.address, new_e.address
                            ),
                        });
                    }
                }
                None => {
                    patches.push(PatchLocation {
                        offset: old_e.address,
                        size: 4,
                        patch_type: PatchType::ExportModified,
                        original_bytes: u32::try_from(old_e.address).unwrap_or(u32::MAX).to_le_bytes().to_vec(),
                        patched_bytes: Vec::new(),
                        description: format!("Export #{ord} removed"),
                    });
                }
            }
        }

        for (&ord, new_e) in &new_map {
            if !old_map.contains_key(&ord) {
                patches.push(PatchLocation {
                    offset: new_e.address,
                    size: 4,
                    patch_type: PatchType::ExportModified,
                    original_bytes: Vec::new(),
                    patched_bytes: u32::try_from(new_e.address).unwrap_or(u32::MAX).to_le_bytes().to_vec(),
                    description: format!("Export #{ord} added"),
                });
            }
        }

        patches
    }

    /// Compare two PE section header lists for structural changes.
    #[must_use]
    pub fn compare_section_headers(
        &self,
        old_sections: &[SectionHeader],
        new_sections: &[SectionHeader],
    ) -> Vec<PatchLocation> {
        let mut patches = Vec::new();
        // Section names originate from the binary being analysed (untrusted);
        // use AHashMap to prevent hash-collision DoS with crafted section names.
        let old_map: AHashMap<&str, &SectionHeader> =
            old_sections.iter().map(|s| (s.name.as_str(), s)).collect();
        let new_map: AHashMap<&str, &SectionHeader> =
            new_sections.iter().map(|s| (s.name.as_str(), s)).collect();

        for (name, new_s) in &new_map {
            if !old_map.contains_key(name) {
                patches.push(PatchLocation {
                    offset: u64::from(new_s.virtual_address),
                    size: new_s.raw_size,
                    patch_type: PatchType::SectionAdded,
                    original_bytes: Vec::new(),
                    patched_bytes: Vec::new(),
                    description: format!("New section '{name}' added at VA {:#x}", new_s.virtual_address),
                });
            }
        }

        for (name, old_s) in &old_map {
            if let Some(new_s) = new_map.get(name) {
                if old_s.characteristics != new_s.characteristics {
                    patches.push(PatchLocation {
                        offset: u64::from(old_s.virtual_address),
                        size: 4,
                        patch_type: PatchType::DataPatch,
                        original_bytes: old_s.characteristics.to_le_bytes().to_vec(),
                        patched_bytes: new_s.characteristics.to_le_bytes().to_vec(),
                        description: format!(
                            "Section '{name}' characteristics changed: {:#x} → {:#x}",
                            old_s.characteristics, new_s.characteristics
                        ),
                    });
                }
                if old_s.raw_size != new_s.raw_size {
                    patches.push(PatchLocation {
                        offset: u64::from(old_s.virtual_address),
                        size: 4,
                        patch_type: PatchType::DataPatch,
                        original_bytes: old_s.raw_size.to_le_bytes().to_vec(),
                        patched_bytes: new_s.raw_size.to_le_bytes().to_vec(),
                        description: format!(
                            "Section '{name}' raw size changed: {} → {}",
                            old_s.raw_size, new_s.raw_size
                        ),
                    });
                }
            }
        }

        patches
    }

        /// Generate a full `PatchReport` by running all detectors.
    ///
    /// `func_starts` must contain known function start offsets inside the images.
    #[must_use]
    pub fn full_report(&self, ctx: &FullReportContext<'_>) -> PatchReport {
        let mut all: Vec<PatchLocation> = Vec::new();

        all.extend(self.detect_jmp_patches(ctx.new_image, ctx.func_starts));
        all.extend(self.detect_nop_patches(ctx.new_image));
        all.extend(self.detect_ret_patches(ctx.new_image, ctx.func_starts));
        all.extend(self.detect_call_redirects(ctx.old_image, ctx.new_image));
        all.extend(self.compare_import_tables(ctx.old_imports, ctx.new_imports));
        all.extend(self.compare_export_tables(ctx.old_exports, ctx.new_exports));
        all.extend(self.compare_section_headers(ctx.old_sections, ctx.new_sections));

        let risk_level = compute_risk(&all);

        PatchReport {
            patches: all,
            risk_level,
            patch_date_estimate: None,
        }
    }
}

impl Default for PatchDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PatchDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PatchDetector")
            .field("min_nop_len", &self.config.min_nop_len)
            .finish_non_exhaustive()
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────────

fn compute_risk(patches: &[PatchLocation]) -> RiskLevel {
    if patches.iter().any(PatchLocation::is_control_flow_patch) {
        RiskLevel::High
    } else if patches.iter().any(|p| {
        matches!(p.patch_type, PatchType::ImportModified | PatchType::ExportModified | PatchType::SectionAdded)
    }) {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> PatchDetector {
        PatchDetector::new()
    }

    // ── detect_jmp_patches ────────────────────────────────────────────────────

    #[test]
    fn test_detect_long_jmp_at_start() {
        let mut image = vec![0x90u8; 64];
        // Place E9 xx xx xx xx at offset 0x10.
        let rel: i32 = 0x20;
        image[0x10] = 0xE9;
        image[0x11..0x15].copy_from_slice(&rel.to_le_bytes());
        let patches = detector().detect_jmp_patches(&image, &[0x10]);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].patch_type, PatchType::JmpPatch);
        assert_eq!(patches[0].offset, 0x10);
    }

    #[test]
    fn test_detect_short_jmp_at_start() {
        let mut image = vec![0x90u8; 32];
        image[0x08] = 0xEB;
        image[0x09] = 0x10;
        let patches = detector().detect_jmp_patches(&image, &[0x08]);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].patch_type, PatchType::JmpPatch);
    }

    #[test]
    fn test_detect_hotpatch_pattern() {
        let mut image = vec![0x90u8; 32];
        // 8B FF at offset 6, EB xx at offset 8.
        image[6] = 0x8B;
        image[7] = 0xFF;
        image[8] = 0xEB;
        image[9] = 0x05;
        let patches = detector().detect_jmp_patches(&image, &[0x08]);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].patch_type, PatchType::HotPatch);
    }

    #[test]
    fn test_no_patches_on_clean_image() {
        let image = vec![0x55u8, 0x8Bu8, 0xECu8, 0xC3u8]; // push ebp; mov ebp,esp; ret
        let patches = detector().detect_jmp_patches(&image, &[0x00]);
        assert!(patches.is_empty());
    }

    // ── detect_nop_patches ────────────────────────────────────────────────────

    #[test]
    fn test_detect_nop_sled() {
        let mut image = vec![0x00u8; 64];
        for b in &mut image[0x10..0x1A] {
            *b = 0x90;
        }
        let patches = detector().detect_nop_patches(&image);
        assert!(!patches.is_empty());
        assert_eq!(patches[0].patch_type, PatchType::NopPatch);
        assert!(patches[0].size >= 4);
    }

    #[test]
    fn test_nop_sled_too_short_not_reported() {
        let mut image = vec![0x00u8; 16];
        image[0] = 0x90;
        image[1] = 0x90;
        // Only 2 bytes, below min_nop_len = 4.
        let patches = detector().detect_nop_patches(&image);
        assert!(patches.is_empty());
    }

    #[test]
    fn test_detect_multibyte_nop() {
        let mut image = vec![0x00u8; 32];
        // Place 3-byte NOP: 0F 1F 00.
        image[4] = 0x0F;
        image[5] = 0x1F;
        image[6] = 0x00;
        let patches = detector().detect_nop_patches(&image);
        assert!(patches.iter().any(|p| p.patch_type == PatchType::NopPatch));
    }

    // ── detect_ret_patches ────────────────────────────────────────────────────

    #[test]
    fn test_detect_ret_patch_c3() {
        let image = vec![0xC3u8; 8];
        let patches = detector().detect_ret_patches(&image, &[0]);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].patch_type, PatchType::RetPatch);
    }

    #[test]
    fn test_detect_ret_n_patch_c2() {
        let mut image = vec![0x90u8; 8];
        image[0] = 0xC2;
        image[1] = 0x08;
        image[2] = 0x00;
        let patches = detector().detect_ret_patches(&image, &[0]);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].patch_type, PatchType::RetPatch);
        assert!(patches[0].description.contains("RET 8"));
    }

    // ── detect_call_redirects ─────────────────────────────────────────────────

    #[test]
    fn test_detect_call_redirect() {
        let mut old = vec![0x00u8; 16];
        let mut new = vec![0x00u8; 16];
        old[0] = 0xE8;
        old[1..5].copy_from_slice(&100i32.to_le_bytes());
        new[0] = 0xE8;
        new[1..5].copy_from_slice(&200i32.to_le_bytes());
        let patches = detector().detect_call_redirects(&old, &new);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].patch_type, PatchType::CallRedirect);
    }

    #[test]
    fn test_no_call_redirect_same_target() {
        let mut image = vec![0x00u8; 16];
        image[0] = 0xE8;
        image[1..5].copy_from_slice(&42i32.to_le_bytes());
        let patches = detector().detect_call_redirects(&image, &image);
        assert!(patches.is_empty());
    }

    // ── compare_import_tables ─────────────────────────────────────────────────

    #[test]
    fn test_import_added() {
        let old: Vec<ImportEntry> = Vec::new();
        let new = vec![ImportEntry {
            dll: "kernel32.dll".into(),
            name: "CreateFile".into(),
            iat_address: 0x1000,
        }];
        let patches = detector().compare_import_tables(&old, &new);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].patch_type, PatchType::ImportModified);
        assert!(patches[0].description.contains("added"));
    }

    #[test]
    fn test_import_removed() {
        let old = vec![ImportEntry {
            dll: "ntdll.dll".into(),
            name: "NtQuerySystemInformation".into(),
            iat_address: 0x2000,
        }];
        let new: Vec<ImportEntry> = Vec::new();
        let patches = detector().compare_import_tables(&old, &new);
        assert_eq!(patches.len(), 1);
        assert!(patches[0].description.contains("removed"));
    }

    // ── compare_export_tables ─────────────────────────────────────────────────

    #[test]
    fn test_export_address_changed() {
        let old = vec![ExportEntry { name: Some("Foo".into()), ordinal: 1, address: 0x5000 }];
        let new = vec![ExportEntry { name: Some("Foo".into()), ordinal: 1, address: 0x6000 }];
        let patches = detector().compare_export_tables(&old, &new);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].patch_type, PatchType::ExportModified);
    }

    // ── compare_section_headers ────────────────────────────────────────────────

    #[test]
    fn test_section_added() {
        let old = vec![SectionHeader {
            name: ".text".into(),
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            raw_size: 0x1000,
            characteristics: 0x60000020,
        }];
        let mut new = old.clone();
        new.push(SectionHeader {
            name: ".malware".into(),
            virtual_size: 0x200,
            virtual_address: 0x5000,
            raw_size: 0x200,
            characteristics: 0xE0000020,
        });
        let patches = detector().compare_section_headers(&old, &new);
        assert!(patches.iter().any(|p| p.patch_type == PatchType::SectionAdded));
    }

    #[test]
    fn test_risk_level_high_on_cf_patch() {
        let p = PatchLocation {
            offset: 0,
            size: 5,
            patch_type: PatchType::JmpPatch,
            original_bytes: Vec::new(),
            patched_bytes: vec![0xE9, 0, 0, 0, 0],
            description: "test".into(),
        };
        assert_eq!(compute_risk(&[p]), RiskLevel::High);
    }

    #[test]
    fn test_risk_level_low_on_empty() {
        assert_eq!(compute_risk(&[]), RiskLevel::Low);
    }
}
