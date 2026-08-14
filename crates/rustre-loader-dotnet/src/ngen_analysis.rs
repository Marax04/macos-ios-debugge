//! `NGen` (Native Image Generator) analysis.
//!
//! Parses `.ni.dll` / `.ni.exe` native image headers, identifies hot/cold
//! section splits, maps native code back to MSIL tokens, and assesses version
//! resilience.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum NgenError {
    #[error("not an NGen image: {0}")]
    NotNgen(String),
    #[error("Truncated data at offset {0:#x}")]
    Truncated(usize),
    #[error("invalid section: {0}")]
    InvalidSection(String),
    #[error("parse error: {0}")]
    Parse(String),
}

// ─── NgenVersion ─────────────────────────────────────────────────────────────

/// CLR / `NGen` format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NgenVersion {
    /// .NET 2.0 / 3.5 `NGen` format.
    V2,
    /// .NET 4.x `NGen` format.
    V4,
    /// .NET 6+ `ReadyToRun` format.
    ReadyToRun,
    /// Unknown / unrecognised.
    Unknown,
}

impl fmt::Display for NgenVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V2 => write!(f, "NGen v2 (.NET 2.0/3.5)"),
            Self::V4 => write!(f, "NGen v4 (.NET 4.x)"),
            Self::ReadyToRun => write!(f, "ReadyToRun (.NET 6+)"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─── NgenHeader ──────────────────────────────────────────────────────────────

/// Parsed `NGen` / `ReadyToRun` header embedded in the PE optional header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NgenHeader {
    /// Detected `NGen` version.
    pub version: NgenVersion,
    /// RVA of the native code manager table.
    pub code_manager_table_rva: u32,
    /// Size of the native code manager table.
    pub code_manager_table_size: u32,
    /// RVA of the vtable fixups directory.
    pub vtable_fixups_rva: u32,
    /// Size of the vtable fixups directory.
    pub vtable_fixups_size: u32,
    /// `NGen` flags (e.g. `IL_ONLY`, `STRONG_NAME_SIGNED`).
    pub flags: u32,
    /// MVID (Module Version ID) of the original IL assembly.
    pub mvid: [u8; 16],
    /// COR20 magic signature (`0x424A5342` = "BSJB").
    pub metadata_magic: u32,
    /// Entry-point metadata token.
    pub entry_point_token: u32,
}

impl NgenHeader {
    /// Parse from a CLR20 header embedded at `offset` in `data`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, NgenError> {
        if offset + 72 > data.len() {
            return Err(NgenError::Truncated(offset));
        }
        let rd32 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap_or([0; 4]));

        let flags = rd32(offset + 16);
        let version = if data[offset..offset + 4] == *b"RTR\0" {
            NgenVersion::ReadyToRun
        } else if flags & 0x0000_0001 != 0 {
            // IL_ONLY = no native code
            NgenVersion::Unknown
        } else {
            // Simple heuristic: presence of code manager table
            let cm_rva = rd32(offset + 32);
            if cm_rva != 0 {
                NgenVersion::V4
            } else {
                NgenVersion::V2
            }
        };

        let mut mvid = [0u8; 16];
        if offset + 56 + 16 <= data.len() {
            mvid.copy_from_slice(&data[offset + 56..offset + 72]);
        }

        Ok(Self {
            version,
            code_manager_table_rva: rd32(offset + 32),
            code_manager_table_size: rd32(offset + 36),
            vtable_fixups_rva: rd32(offset + 40),
            vtable_fixups_size: rd32(offset + 44),
            flags,
            mvid,
            metadata_magic: rd32(offset + 48),
            entry_point_token: rd32(offset + 20),
        })
    }

    /// Returns `true` when this is pure IL (no native code).
    #[must_use]
    pub const fn is_il_only(&self) -> bool {
        self.flags & 0x0000_0001 != 0
    }

    /// Returns `true` when the assembly is strong-name signed.
    #[must_use]
    pub const fn is_strong_name_signed(&self) -> bool {
        self.flags & 0x0000_0008 != 0
    }

    /// Returns `true` when the native code has a code manager table.
    #[must_use]
    pub const fn has_native_code(&self) -> bool {
        self.code_manager_table_rva != 0
    }

    /// Format MVID as a standard GUID string.
    #[must_use]
    pub fn mvid_string(&self) -> String {
        let u = &self.mvid;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
             {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u[0],
            u[1],
            u[2],
            u[3],
            u[4],
            u[5],
            u[6],
            u[7],
            u[8],
            u[9],
            u[10],
            u[11],
            u[12],
            u[13],
            u[14],
            u[15],
        )
    }
}

// ─── HotColdSection ──────────────────────────────────────────────────────────

/// A hot or cold code section split by the `NGen` code layout algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotColdSection {
    /// Section name (e.g. `.text`, `.textbss`, `.cold`).
    pub name: String,
    /// Virtual address.
    pub virtual_address: u64,
    /// Size in bytes.
    pub size: u32,
    /// Whether this is a cold (rarely executed) section.
    pub is_cold: bool,
    /// Whether this section contains data-in-code islands.
    pub has_data_islands: bool,
    /// Approximate method count estimated from the section size.
    pub estimated_method_count: u32,
}

impl HotColdSection {
    /// Estimate the number of methods from code density heuristic.
    #[must_use]
    pub const fn estimate_methods(size: u32) -> u32 {
        // Average native method ~= 64 bytes
        size / 64
    }
}

impl fmt::Display for HotColdSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ {:#x} size={} cold={} methods~{}",
            self.name, self.virtual_address, self.size, self.is_cold, self.estimated_method_count,
        )
    }
}

/// Collection of hot/cold sections in an `NGen` image.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HotColdSections {
    pub sections: Vec<HotColdSection>,
}

impl HotColdSections {
    /// Return only hot sections.
    #[must_use]
    pub fn hot(&self) -> Vec<&HotColdSection> {
        self.sections.iter().filter(|s| !s.is_cold).collect()
    }

    /// Return only cold sections.
    #[must_use]
    pub fn cold(&self) -> Vec<&HotColdSection> {
        self.sections.iter().filter(|s| s.is_cold).collect()
    }

    /// Total estimated method count across all sections.
    #[must_use]
    pub fn total_estimated_methods(&self) -> u32 {
        self.sections.iter().map(|s| s.estimated_method_count).sum()
    }

    /// Cold/hot ratio (fraction of code that is cold-path).
    #[must_use]
    pub fn cold_ratio(&self) -> f64 {
        let total: u32 = self.sections.iter().map(|s| s.size).sum();
        let cold: u32 = self
            .sections
            .iter()
            .filter(|s| s.is_cold)
            .map(|s| s.size)
            .sum();
        if total == 0 {
            0.0
        } else {
            f64::from(cold) / f64::from(total)
        }
    }
}

// ─── NgenImports ─────────────────────────────────────────────────────────────

/// An imported helper from the `NGen` support DLL (`mscorwks`, `clrjit`, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NgenImportEntry {
    /// Name of the helper (e.g. `JIT_New`, `JIT_CheckedWriteBarrier`).
    pub name: String,
    /// Virtual address of the import slot.
    pub address: u64,
    /// Whether this is a GC write barrier helper.
    pub is_write_barrier: bool,
    /// Whether this is a JIT interface helper.
    pub is_jit_helper: bool,
}

impl NgenImportEntry {
    /// Classify from the import name.
    #[must_use]
    pub fn from_name(name: impl Into<String>, address: u64) -> Self {
        let name = name.into();
        let is_write_barrier = name.contains("WriteBarrier") || name.contains("GCWrite");
        let is_jit_helper = name.starts_with("JIT_") || name.starts_with("CORINFO_");
        Self {
            name,
            address,
            is_write_barrier,
            is_jit_helper,
        }
    }
}

/// All NGen-specific imports from the native image.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NgenImports {
    pub entries: Vec<NgenImportEntry>,
}

impl NgenImports {
    /// Return all write-barrier helpers.
    #[must_use]
    pub fn write_barriers(&self) -> Vec<&NgenImportEntry> {
        self.entries.iter().filter(|e| e.is_write_barrier).collect()
    }

    /// Return all JIT helpers.
    #[must_use]
    pub fn jit_helpers(&self) -> Vec<&NgenImportEntry> {
        self.entries.iter().filter(|e| e.is_jit_helper).collect()
    }

    /// Total import count.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.entries.len()
    }
}

// ─── NgenGCInfo ──────────────────────────────────────────────────────────────

/// GC info block associated with a native method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NgenGCInfo {
    /// RVA of the method's code start.
    pub code_rva: u32,
    /// Byte length of the encoded GC info blob.
    pub gc_info_size: u32,
    /// Frame size of the method in bytes.
    pub frame_size: u32,
    /// Whether the method has a GC-safe point epilogue.
    pub has_epilogue: bool,
    /// Number of tracked GC root slots.
    pub tracked_slot_count: u32,
    /// Number of untracked (interior pointer) GC slots.
    pub untracked_count: u32,
}

impl NgenGCInfo {
    /// Rough complexity metric.
    #[must_use]
    pub const fn complexity(&self) -> u32 {
        self.tracked_slot_count + self.untracked_count
    }
}

// ─── SecurityObjects ─────────────────────────────────────────────────────────

/// Security-relevant objects detected in an `NGen` image.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityObjects {
    /// Strong-name signature present.
    pub strong_name_signed: bool,
    /// Whether the assembly was skip-verified (trust override).
    pub skip_verification: bool,
    /// Whether the assembly runs with full trust in the security policy.
    pub full_trust: bool,
    /// Code access security evidence.
    pub cas_evidence_present: bool,
    /// Publisher certificate fingerprint (SHA-1 hex), if found.
    pub publisher_cert_sha1: Option<String>,
}

// ─── NgenToMSIL ──────────────────────────────────────────────────────────────

/// Mapping from native code offset to MSIL metadata token / IL offset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NgenToMsilMapping {
    /// Native code RVA.
    pub native_rva: u32,
    /// MSIL method token (`0x0600xxxx`).
    pub msil_token: u32,
    /// IL offset within the method.
    pub il_offset: u32,
    /// Source line number (0 = unavailable).
    pub source_line: u32,
}

impl NgenToMsilMapping {
    /// Return `true` when source-line info is available.
    #[must_use]
    pub const fn has_debug_info(&self) -> bool {
        self.source_line != 0
    }

    /// Decode the method row index from the token.
    #[must_use]
    pub const fn method_row(&self) -> u32 {
        self.msil_token & 0x00FF_FFFF
    }
}

/// Table of all native→MSIL mappings in the image.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NgenToMsil {
    pub mappings: Vec<NgenToMsilMapping>,
    /// `method_token` → list of native RVAs
    pub method_to_native: HashMap<u32, Vec<u32>>,
}

impl NgenToMsil {
    /// Build the reverse index `method_token → [native_rva]`.
    pub fn build_index(&mut self) {
        self.method_to_native.clear();
        for m in &self.mappings {
            self.method_to_native
                .entry(m.msil_token)
                .or_default()
                .push(m.native_rva);
        }
    }

    /// Resolve a native RVA to its closest MSIL mapping.
    #[must_use]
    pub fn resolve_native(&self, rva: u32) -> Option<&NgenToMsilMapping> {
        // Linear scan; production code would use binary search
        self.mappings
            .iter()
            .filter(|m| m.native_rva <= rva)
            .max_by_key(|m| m.native_rva)
    }

    /// Count of mappings with source-line information.
    #[must_use]
    pub fn mappings_with_debug(&self) -> usize {
        self.mappings.iter().filter(|m| m.has_debug_info()).count()
    }
}

// ─── NgenVersionResilience ────────────────────────────────────────────────────

/// Assessment of how resilient a native image is to version changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NgenVersionResilience {
    /// Whether the `NGen` image encodes the target CLR version.
    pub clr_version_bound: bool,
    /// Whether vtable fixups are needed on load (fragile).
    pub has_vtable_fixups: bool,
    /// Whether the image was generated with `noNgenOpt` flag.
    pub no_optimization: bool,
    /// Whether the image uses generic dictionary cells (version-sensitive).
    pub has_dictionary_cells: bool,
    /// Estimated fragility score (0 = robust, 100 = very fragile).
    pub fragility_score: u32,
    /// Human-readable assessment.
    pub assessment: String,
}

impl NgenVersionResilience {
    /// Compute resilience from header and section data.
    #[must_use]
    pub fn compute(header: &NgenHeader, sections: &HotColdSections) -> Self {
        let has_vtable_fixups = header.vtable_fixups_size > 0;
        let cold_ratio = sections.cold_ratio();

        let mut score: u32 = 0;
        if has_vtable_fixups {
            score += 30;
        }
        if header.is_strong_name_signed() {
            score += 10;
        }
        if cold_ratio < 0.05 {
            score += 10;
        } // no hot/cold split = older NGen

        let assessment = match score {
            0..=20 => "Robust — minimal version sensitivity".to_string(),
            21..=50 => "Moderate — some version-sensitive constructs".to_string(),
            _ => "Fragile — likely to invalidate on CLR update".to_string(),
        };

        Self {
            clr_version_bound: header.version != NgenVersion::Unknown,
            has_vtable_fixups,
            no_optimization: false,
            has_dictionary_cells: false,
            fragility_score: score.min(100),
            assessment,
        }
    }
}

// ─── NgenImage ────────────────────────────────────────────────────────────────

/// Full representation of a parsed `NGen` `.ni.dll` / `.ni.exe` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NgenImage {
    /// NGen-specific header information.
    pub header: NgenHeader,
    /// Hot/cold section layout.
    pub sections: HotColdSections,
    /// `NGen` helper imports.
    pub imports: NgenImports,
    /// Sampled GC info blocks.
    pub gc_infos: Vec<NgenGCInfo>,
    /// Security objects detected.
    pub security: SecurityObjects,
    /// Native ↔ MSIL mapping table.
    pub msil_map: NgenToMsil,
    /// Version resilience assessment.
    pub resilience: NgenVersionResilience,
    /// Original PE image size.
    pub image_size: u64,
    /// Detected CLR runtime version string (e.g. `"v4.0.30319"`).
    pub clr_runtime_version: String,
}

impl NgenImage {
    /// Build a mock `NgenImage` for testing.
    #[must_use]
    pub fn mock() -> Self {
        let header = NgenHeader {
            version: NgenVersion::V4,
            code_manager_table_rva: 0x1000,
            code_manager_table_size: 0x200,
            vtable_fixups_rva: 0x1200,
            vtable_fixups_size: 0x40,
            flags: 0x0008,
            mvid: [
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88,
            ],
            metadata_magic: 0x424A_5342,
            entry_point_token: 0x0600_0001,
        };
        let sections = HotColdSections {
            sections: vec![
                HotColdSection {
                    name: ".text".into(),
                    virtual_address: 0x1000,
                    size: 0x8000,
                    is_cold: false,
                    has_data_islands: false,
                    estimated_method_count: HotColdSection::estimate_methods(0x8000),
                },
                HotColdSection {
                    name: ".cold".into(),
                    virtual_address: 0x9000,
                    size: 0x1000,
                    is_cold: true,
                    has_data_islands: false,
                    estimated_method_count: HotColdSection::estimate_methods(0x1000),
                },
            ],
        };
        let imports = NgenImports {
            entries: vec![
                NgenImportEntry::from_name("JIT_New", 0x4000),
                NgenImportEntry::from_name("JIT_CheckedWriteBarrier", 0x4008),
                NgenImportEntry::from_name("CORINFO_HELP_ARRADDR_ST", 0x4010),
            ],
        };
        let gc_infos = vec![NgenGCInfo {
            code_rva: 0x1010,
            gc_info_size: 24,
            frame_size: 48,
            has_epilogue: true,
            tracked_slot_count: 3,
            untracked_count: 1,
        }];
        let security = SecurityObjects {
            strong_name_signed: true,
            skip_verification: false,
            full_trust: false,
            cas_evidence_present: false,
            publisher_cert_sha1: None,
        };
        let mut msil_map = NgenToMsil {
            mappings: vec![
                NgenToMsilMapping {
                    native_rva: 0x1010,
                    msil_token: 0x0600_0001,
                    il_offset: 0,
                    source_line: 42,
                },
                NgenToMsilMapping {
                    native_rva: 0x1020,
                    msil_token: 0x0600_0001,
                    il_offset: 4,
                    source_line: 43,
                },
            ],
            method_to_native: HashMap::new(),
        };
        msil_map.build_index();
        let resilience = NgenVersionResilience::compute(&header, &sections);
        Self {
            header,
            sections,
            imports,
            gc_infos,
            security,
            msil_map,
            resilience,
            image_size: 0x10_000,
            clr_runtime_version: "v4.0.30319".into(),
        }
    }

    /// Quick summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "NGen {} clr={} methods~{} fragility={}",
            self.header.version,
            self.clr_runtime_version,
            self.sections.total_estimated_methods(),
            self.resilience.fragility_score,
        )
    }
}

impl fmt::Display for NgenImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── NgenVersion ──────────────────────────────────────────────────────────

    #[test]
    fn test_ngen_version_display_v4() {
        assert!(NgenVersion::V4.to_string().contains("4.x"));
    }

    #[test]
    fn test_ngen_version_display_rtr() {
        assert!(NgenVersion::ReadyToRun.to_string().contains("ReadyToRun"));
    }

    #[test]
    fn test_ngen_version_display_unknown() {
        assert_eq!(NgenVersion::Unknown.to_string(), "Unknown");
    }

    // ── NgenHeader ────────────────────────────────────────────────────────────

    #[test]
    fn test_ngen_header_is_il_only_when_flag_set() {
        let h = NgenHeader {
            flags: 0x0001,
            version: NgenVersion::Unknown,
            code_manager_table_rva: 0,
            code_manager_table_size: 0,
            vtable_fixups_rva: 0,
            vtable_fixups_size: 0,
            mvid: [0u8; 16],
            metadata_magic: 0,
            entry_point_token: 0,
        };
        assert!(h.is_il_only());
    }

    #[test]
    fn test_ngen_header_is_strong_name_signed() {
        let h = NgenHeader {
            flags: 0x0008,
            version: NgenVersion::V4,
            code_manager_table_rva: 0,
            code_manager_table_size: 0,
            vtable_fixups_rva: 0,
            vtable_fixups_size: 0,
            mvid: [0u8; 16],
            metadata_magic: 0,
            entry_point_token: 0,
        };
        assert!(h.is_strong_name_signed());
    }

    #[test]
    fn test_ngen_header_has_native_code() {
        let h = NgenHeader {
            code_manager_table_rva: 0x1000,
            flags: 0,
            version: NgenVersion::V4,
            code_manager_table_size: 0,
            vtable_fixups_rva: 0,
            vtable_fixups_size: 0,
            mvid: [0u8; 16],
            metadata_magic: 0,
            entry_point_token: 0,
        };
        assert!(h.has_native_code());
    }

    #[test]
    fn test_ngen_header_mvid_string_length() {
        let img = NgenImage::mock();
        let mvid = img.header.mvid_string();
        assert_eq!(mvid.len(), 36);
    }

    #[test]
    fn test_ngen_header_parse_truncated_returns_error() {
        let data = vec![0u8; 4];
        let r = NgenHeader::parse(&data, 0);
        assert!(r.is_err());
    }

    #[test]
    fn test_ngen_header_parse_zero_buffer() {
        let data = vec![0u8; 128];
        let h = NgenHeader::parse(&data, 0).unwrap();
        // All-zero flags → il_only is false (bit 0 not set)
        assert!(!h.is_il_only());
    }

    // ── HotColdSection ────────────────────────────────────────────────────────

    #[test]
    fn test_hot_cold_section_display() {
        let s = HotColdSection {
            name: ".text".into(),
            virtual_address: 0x1000,
            size: 0x200,
            is_cold: false,
            has_data_islands: false,
            estimated_method_count: 8,
        };
        let d = s.to_string();
        assert!(d.contains(".text"));
    }

    #[test]
    fn test_hot_cold_section_estimate_methods() {
        assert_eq!(HotColdSection::estimate_methods(6400), 100);
    }

    // ── HotColdSections ───────────────────────────────────────────────────────

    #[test]
    fn test_hot_cold_sections_hot_cold_split() {
        let img = NgenImage::mock();
        assert_eq!(img.sections.hot().len(), 1);
        assert_eq!(img.sections.cold().len(), 1);
    }

    #[test]
    fn test_hot_cold_sections_total_methods() {
        let img = NgenImage::mock();
        assert!(img.sections.total_estimated_methods() > 0);
    }

    #[test]
    fn test_hot_cold_sections_cold_ratio() {
        let img = NgenImage::mock();
        let ratio = img.sections.cold_ratio();
        assert!(ratio > 0.0 && ratio < 1.0);
    }

    // ── NgenImports ───────────────────────────────────────────────────────────

    #[test]
    fn test_ngen_imports_write_barriers() {
        let img = NgenImage::mock();
        assert!(!img.imports.write_barriers().is_empty());
    }

    #[test]
    fn test_ngen_imports_jit_helpers() {
        let img = NgenImage::mock();
        assert!(!img.imports.jit_helpers().is_empty());
    }

    #[test]
    fn test_ngen_imports_count() {
        let img = NgenImage::mock();
        assert_eq!(img.imports.count(), 3);
    }

    #[test]
    fn test_ngen_import_entry_classification() {
        let e = NgenImportEntry::from_name("JIT_New", 0);
        assert!(e.is_jit_helper);
        assert!(!e.is_write_barrier);
    }

    #[test]
    fn test_ngen_import_entry_write_barrier() {
        let e = NgenImportEntry::from_name("JIT_CheckedWriteBarrier", 0);
        assert!(e.is_write_barrier);
    }

    // ── NgenGCInfo ────────────────────────────────────────────────────────────

    #[test]
    fn test_gc_info_complexity() {
        let g = NgenGCInfo {
            code_rva: 0,
            gc_info_size: 0,
            frame_size: 0,
            has_epilogue: false,
            tracked_slot_count: 5,
            untracked_count: 2,
        };
        assert_eq!(g.complexity(), 7);
    }

    // ── NgenToMsil ────────────────────────────────────────────────────────────

    #[test]
    fn test_msil_map_resolve_native() {
        let img = NgenImage::mock();
        let m = img.msil_map.resolve_native(0x1015);
        assert!(m.is_some());
        assert_eq!(m.unwrap().msil_token, 0x0600_0001);
    }

    #[test]
    fn test_msil_map_mappings_with_debug() {
        let img = NgenImage::mock();
        assert_eq!(img.msil_map.mappings_with_debug(), 2);
    }

    #[test]
    fn test_msil_mapping_has_debug_info() {
        let m = NgenToMsilMapping {
            native_rva: 0,
            msil_token: 0,
            il_offset: 0,
            source_line: 10,
        };
        assert!(m.has_debug_info());
    }

    #[test]
    fn test_msil_mapping_no_debug_info() {
        let m = NgenToMsilMapping {
            native_rva: 0,
            msil_token: 0,
            il_offset: 0,
            source_line: 0,
        };
        assert!(!m.has_debug_info());
    }

    #[test]
    fn test_msil_mapping_method_row() {
        let m = NgenToMsilMapping {
            native_rva: 0,
            msil_token: 0x0600_00AB,
            il_offset: 0,
            source_line: 0,
        };
        assert_eq!(m.method_row(), 0xAB);
    }

    #[test]
    fn test_msil_map_build_index() {
        let img = NgenImage::mock();
        assert!(img.msil_map.method_to_native.contains_key(&0x0600_0001));
    }

    // ── NgenVersionResilience ─────────────────────────────────────────────────

    #[test]
    fn test_resilience_has_vtable_fixups() {
        let img = NgenImage::mock();
        assert!(img.resilience.has_vtable_fixups);
    }

    #[test]
    fn test_resilience_fragility_score_range() {
        let img = NgenImage::mock();
        assert!(img.resilience.fragility_score <= 100);
    }

    #[test]
    fn test_resilience_clr_version_bound() {
        let img = NgenImage::mock();
        assert!(img.resilience.clr_version_bound);
    }

    // ── NgenImage ─────────────────────────────────────────────────────────────

    #[test]
    fn test_ngen_image_mock_version_v4() {
        let img = NgenImage::mock();
        assert_eq!(img.header.version, NgenVersion::V4);
    }

    #[test]
    fn test_ngen_image_summary_contains_version() {
        let img = NgenImage::mock();
        let s = img.summary();
        assert!(s.contains("v4.0.30319"));
    }

    #[test]
    fn test_ngen_image_display() {
        let img = NgenImage::mock();
        let s = format!("{img}");
        assert!(!s.is_empty());
    }

    #[test]
    fn test_ngen_image_serialization() {
        let img = NgenImage::mock();
        let json = serde_json::to_string(&img).unwrap();
        let back: NgenImage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.clr_runtime_version, img.clr_runtime_version);
    }

    #[test]
    fn test_ngen_image_security_strong_name() {
        let img = NgenImage::mock();
        assert!(img.security.strong_name_signed);
    }

    #[test]
    fn test_ngen_error_display() {
        let e = NgenError::NotNgen("bad magic".into());
        assert!(e.to_string().contains("bad magic"));
    }

    #[test]
    fn test_ngen_error_truncated() {
        let e = NgenError::Truncated(0x100);
        assert!(e.to_string().contains("Truncated"));
    }

    #[test]
    fn test_ngen_version_v2() {
        assert_eq!(NgenVersion::V2.to_string(), "NGen v2 (.NET 2.0/3.5)");
    }
    #[test]
    fn test_ngen_header_mock_vtable_nonzero() {
        let img = NgenImage::mock();
        assert_ne!(img.header.vtable_fixups_rva, 0);
    }
    #[test]
    fn test_ngen_sections_default_empty() {
        let s = HotColdSections::default();
        assert!(s.sections.is_empty());
    }
    #[test]
    fn test_ngen_imports_default_empty() {
        let i = NgenImports::default();
        assert_eq!(i.count(), 0);
    }
    #[test]
    fn test_ngen_gc_info_complexity_zero() {
        let g = NgenGCInfo {
            code_rva: 0,
            gc_info_size: 0,
            frame_size: 0,
            has_epilogue: false,
            tracked_slot_count: 0,
            untracked_count: 0,
        };
        assert_eq!(g.complexity(), 0);
    }
    #[test]
    fn test_msil_mapping_method_row_zero() {
        let m = NgenToMsilMapping {
            native_rva: 0,
            msil_token: 0x0600_0000,
            il_offset: 0,
            source_line: 0,
        };
        assert_eq!(m.method_row(), 0);
    }
    #[test]
    fn test_ngen_image_mock_code_mgr() {
        let img = NgenImage::mock();
        assert_ne!(img.header.code_manager_table_rva, 0);
    }
    #[test]
    fn test_ngen_image_mock_entry_point() {
        let img = NgenImage::mock();
        assert_eq!(img.header.entry_point_token, 0x0600_0001);
    }
    #[test]
    fn test_hot_cold_section_estimate_zero() {
        assert_eq!(HotColdSection::estimate_methods(0), 0);
    }
    #[test]
    fn test_ngen_gc_info_has_epilogue() {
        let img = NgenImage::mock();
        assert!(img.gc_infos[0].has_epilogue);
    }
}
